// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.h
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: enum probe_attach_mode, bpf_program__attach_uprobe, bpf_program__attach_uprobe_opts, resolve_full_path, arch_specific_lib_paths

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// ProbeAttachMode selects how BpfProgramAttachKprobeOpts and
// BpfProgramAttachUprobeOpts create a probe and attach the program to it. A
// mode the kernel cannot provide returns EOPNOTSUPP.
type ProbeAttachMode int

// Kprobe and uprobe attach modes.
const (
	// ProbeAttachModeDefault uses the newest mechanism the kernel has: the
	// kprobe or uprobe perf PMU, or a tracefs probe event on a kernel
	// without it, attached with a BPF perf link, or with
	// PERF_EVENT_IOC_SET_BPF on a kernel without perf links. It is the zero
	// value.
	ProbeAttachModeDefault ProbeAttachMode = 0
	// ProbeAttachModeLegacy creates a tracefs probe event and attaches the
	// program with PERF_EVENT_IOC_SET_BPF. tracefs must be writable, and the
	// mode carries neither a uprobe reference counter, a kprobe on a raw
	// address nor a BPF cookie.
	ProbeAttachModeLegacy ProbeAttachMode = 1
	// ProbeAttachModePerf opens the probe through its perf PMU with
	// perf_event_open and attaches the program with PERF_EVENT_IOC_SET_BPF.
	// It carries a uprobe reference counter but no BPF cookie.
	ProbeAttachModePerf ProbeAttachMode = 2
	// ProbeAttachModeLink opens the probe through its perf PMU and attaches
	// the program with a BPF perf link, which carries a BPF cookie. The
	// kernel must support perf links (Linux 5.15 or newer).
	ProbeAttachModeLink ProbeAttachMode = 3
)

// BpfUprobeOpts are the optional settings of BpfProgramAttachUprobeOpts. The
// zero value attaches a uprobe in ProbeAttachModeDefault.
//
// FuncName resolves to a file offset in the binary and is added to the
// explicit offset. RefCtrOffset is the file offset of a USDT semaphore the
// kernel counts while the uprobe is installed; it needs the uprobe perf PMU.
// BpfCookie is the value the program reads with bpf_get_attach_cookie; it
// needs a BPF perf link. AttachMode selects how the uprobe is created and
// attached.
type BpfUprobeOpts struct {
	Retprobe     bool
	RefCtrOffset uint64
	FuncName     string
	BpfCookie    uint64
	AttachMode   ProbeAttachMode
}

// The directory lists resolveFullPath searches after the environment
// variable, each a colon-separated list like PATH.
var (
	binarySearchPaths  = []string{"/usr/bin:/usr/sbin"}
	librarySearchPaths = []string{"/usr/lib64:/usr/lib", archLibPath(), "/lib64:/lib"}
)

// BpfProgramAttachUprobe attaches a loaded program to binaryPath at offset in
// ProbeAttachModeDefault. pid -1 attaches for every process; pid 0 attaches to
// the calling process. The caller must release the link with BpfLinkDestroy.
func BpfProgramAttachUprobe(prog *BpfProgram, pid int, binaryPath string, offset uint64) (*BpfLink, error) {
	return BpfProgramAttachUprobeOpts(prog, pid, binaryPath, offset, nil)
}

// BpfProgramAttachUprobeOpts attaches a loaded program to binaryPath at offset
// with the given options and returns a link the caller releases with
// BpfLinkDestroy. pid -1 attaches for every process, pid 0 to the calling
// process and a positive pid to that process. FuncName, when set, is resolved
// to a file offset in binaryPath and added to offset.
//
// A binaryPath without a slash is searched for. A name that ends in ".so" or
// contains ".so." must be a readable file in LD_LIBRARY_PATH, /usr/lib64,
// /usr/lib, the architecture's multiarch directory (/lib/x86_64-linux-gnu or
// /lib/aarch64-linux-gnu), /lib64 or /lib; any other name a readable and
// executable file in PATH, /usr/bin or /usr/sbin. The first match is used and
// no match is ENOENT. A path with a slash is used as given.
//
// binaryPath may name an ELF member of a zip archive as "archive!/member",
// the form Android uses for libraries stored uncompressed in an APK. FuncName
// is then resolved inside the member and the probe is placed on the archive
// file at the member's data offset plus the function offset. A compressed
// member returns LIBBPF_ERRNO__FORMAT (4001). Without FuncName the probe uses
// the member path itself.
//
// AttachMode selects the mechanism; see ProbeAttachMode. The kernel has the
// uprobe perf PMU when /sys/bus/event_source/devices/uprobe/type can be read.
// Without it the default mode creates a tracefs uprobe event, and the perf
// and link modes return EOPNOTSUPP; the link mode also returns EOPNOTSUPP on a
// kernel without BPF perf links. Any other mode is EINVAL.
//
// The PMU event carries RefCtrOffset: the kernel increments the 16-bit counter
// at that file offset of the binary in every process the uprobe is installed
// in, and decrements it when the link is destroyed. A RefCtrOffset that does
// not fit in 32 bits, or any nonzero RefCtrOffset on the tracefs path, is
// EINVAL. A uretprobe through a PMU without its retprobe format file is
// ENOENT.
//
// The default and link modes attach the program with a BPF perf link when the
// kernel has one, which carries BpfCookie. Otherwise, and always in the
// legacy and perf modes, the program is attached with PERF_EVENT_IOC_SET_BPF,
// and a nonzero BpfCookie is EOPNOTSUPP. The link owns the perf event and the
// tracefs event, if any; when the attach fails, the call releases both.
func BpfProgramAttachUprobeOpts(prog *BpfProgram, pid int, binaryPath string, offset uint64, opts *BpfUprobeOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_uprobe"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if binaryPath == "" {
		return nil, attachErr(op, unix.EINVAL)
	}
	if opts == nil {
		opts = &BpfUprobeOpts{}
	}

	path, offset, err := uprobeLocation(binaryPath, offset, opts.FuncName)
	if err != nil {
		return nil, attachErr(op, err)
	}
	_, pmuErr := determineUprobePerfType()
	legacy, forceIoctl, err := probeAttachMode(opts.AttachMode, pmuErr != nil, perfLinkSupported)
	if err != nil {
		return nil, attachErr(op, err)
	}

	var event *legacyEvent
	var pfd int
	if legacy {
		event, pfd, err = openLegacyUprobe(opts, path, offset, pid)
	} else {
		pfd, err = perfEventOpenProbe(true, opts.Retprobe, path, offset, pid, opts.RefCtrOffset)
	}
	if err != nil {
		return nil, attachErr(op, err)
	}

	peOpts := &BpfPerfEventOpts{BpfCookie: opts.BpfCookie, ForceIoctlAttach: forceIoctl}
	link, err := attachProbePerfEvent(prog, pfd, event, peOpts)
	if err != nil {
		return nil, attachErr(op, err)
	}
	return link, nil
}

// probeAttachMode applies mode to the kernel's capabilities: noPMU reports a
// kernel without the probe's perf PMU, and perfLink, which only the link mode
// calls, reports BPF perf link support. legacy selects a tracefs event over
// the PMU, and forceIoctl selects PERF_EVENT_IOC_SET_BPF even when the kernel
// has perf links.
func probeAttachMode(mode ProbeAttachMode, noPMU bool, perfLink func() bool) (legacy, forceIoctl bool, err error) {
	switch mode {
	case ProbeAttachModeDefault:
		return noPMU, false, nil
	case ProbeAttachModeLegacy:
		return true, true, nil
	case ProbeAttachModePerf:
		if noPMU {
			return false, false, unix.EOPNOTSUPP
		}
		return false, true, nil
	case ProbeAttachModeLink:
		if noPMU || !perfLink() {
			return false, false, unix.EOPNOTSUPP
		}
		return false, false, nil
	default:
		return false, false, unix.EINVAL
	}
}

// uprobeLocation returns the file and offset a uprobe on binaryPath probes. A
// name without a slash is resolved with resolveFullPath first. With funcName
// the function's offset is added: a function inside "archive!/member" is
// probed on the archive file. Without it a member path probes the member path
// itself.
func uprobeLocation(binaryPath string, offset uint64, funcName string) (string, uint64, error) {
	if !strings.Contains(binaryPath, "/") {
		resolved, err := resolveFullPath(binaryPath)
		if err != nil {
			return "", 0, err
		}
		binaryPath = resolved
	}

	if funcName == "" {
		if _, member, ok := strings.Cut(binaryPath, archiveSep); ok {
			return member, offset, nil
		}
		return binaryPath, offset, nil
	}
	path, funcOffset, err := findUprobeFuncOffset(binaryPath, funcName)
	if err != nil {
		return "", 0, err
	}
	return path, offset + funcOffset, nil
}

// openLegacyUprobe adds a tracefs uprobe event for path at offset and opens
// its perf event for pid. tracefs cannot pass a reference counter, so a
// nonzero RefCtrOffset is EINVAL. The caller owns the event and the perf
// descriptor; on failure the event is removed again.
func openLegacyUprobe(opts *BpfUprobeOpts, path string, offset uint64, pid int) (*legacyEvent, int, error) {
	if opts.RefCtrOffset != 0 {
		return nil, -1, unix.EINVAL
	}

	kind := probeUprobe
	prefix := byte('p')
	if opts.Retprobe {
		kind = probeUretprobe
		prefix = 'r'
	}
	event := &legacyEvent{root: tracefsRoot(), kind: kind, name: probeEventName(uprobeEventLabel(path), offset)}
	line := fmt.Sprintf("%c:%s/%s %s:0x%x", prefix, event.group(), event.name, path, offset)
	pfd, err := event.open(line, pid)
	if err != nil {
		return nil, -1, err
	}
	return event, pfd, nil
}

// uprobeEventLabel returns what libbpf names a tracefs uprobe event on path
// after: the path from its last slash on, the slash included, or the whole
// path when it has no slash. The event name turns the slash into '_'.
func uprobeEventLabel(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i:]
	}
	return path
}

// resolveFullPath returns the path of file, a program or shared library name
// without a slash. A name that ends in ".so" or contains ".so." is a shared
// library: it is searched in LD_LIBRARY_PATH and then librarySearchPaths, and
// must be readable. Any other name is a program: it is searched in PATH and
// then binarySearchPaths, and must be readable and executable. Access is
// checked with the effective IDs, and empty directory entries are skipped.
// The result joins the first matching directory and file with a slash; no
// match is ENOENT.
func resolveFullPath(file string) (string, error) {
	searchPaths := append([]string{os.Getenv("PATH")}, binarySearchPaths...)
	perm := uint32(unix.R_OK | unix.X_OK)
	if strings.HasSuffix(file, ".so") || strings.Contains(file, ".so.") {
		searchPaths = append([]string{os.Getenv("LD_LIBRARY_PATH")}, librarySearchPaths...)
		perm = unix.R_OK
	}

	for _, paths := range searchPaths {
		for _, dir := range strings.Split(paths, ":") {
			if dir == "" {
				continue
			}
			path := dir + "/" + file
			if unix.Faccessat(unix.AT_FDCWD, path, perm, unix.AT_EACCESS) == nil {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s not found in the search path", unix.ENOENT, file)
}

// archLibPath returns the Debian multiarch library directory of the
// architecture the package runs on.
func archLibPath() string {
	switch runtime.GOARCH {
	case "amd64":
		return "/lib/x86_64-linux-gnu"
	case "arm64":
		return "/lib/aarch64-linux-gnu"
	default:
		return ""
	}
}
