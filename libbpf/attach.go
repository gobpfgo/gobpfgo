// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program__attach_tracepoint_opts, bpf_program__attach_perf_event_opts, bpf_program__attach_raw_tracepoint_opts, bpf_program__attach_kprobe_multi_opts, bpf_program__attach_uprobe_multi, bpf_program__attach_trace_opts, bpf_program__attach_lsm, bpf_program__attach

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"debug/elf"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BPF_F_KPROBE_MULTI_RETURN makes a kprobe multi link call the program when
// the probed functions return.
const BPF_F_KPROBE_MULTI_RETURN uint32 = 1

// BpfTracepointOpts are the optional settings of
// BpfProgramAttachTracepointOpts.
type BpfTracepointOpts struct {
	BpfCookie uint64
}

// BpfPerfEventOpts are the optional settings of
// BpfProgramAttachPerfEventOpts.
type BpfPerfEventOpts struct {
	BpfCookie        uint64
	ForceIoctlAttach bool
	DontEnable       bool
}

// BpfRawTracepointOpts are the optional settings of
// BpfProgramAttachRawTracepointOpts.
type BpfRawTracepointOpts struct {
	Cookie uint64
}

// BpfKprobeMultiOpts are the optional settings of
// BpfProgramAttachKprobeMulti. Exactly one of Symbols and Addrs is used;
// Cookies, when present, has one entry per symbol or address.
type BpfKprobeMultiOpts struct {
	Symbols  []string
	Addrs    []uint64
	Cookies  []uint64
	Retprobe bool
}

// BpfUprobeMultiOpts are the optional settings of
// BpfProgramAttachUprobeMulti. Exactly one of Syms and Offsets selects the
// probe locations, and its length is the probe count. Syms are function names
// resolved to file offsets in the binary; Offsets are file offsets used as
// given. RefCtrOffsets and Cookies are optional and, when set, have one entry
// per probe. Retprobe and Session are mutually exclusive.
type BpfUprobeMultiOpts struct {
	Syms          []string
	Offsets       []uint64
	RefCtrOffsets []uint64
	Cookies       []uint64
	Retprobe      bool
	Session       bool
}

// BpfTraceOpts are the optional settings of BpfProgramAttachTraceOpts.
type BpfTraceOpts struct {
	BpfCookie uint64
}

// BpfProgramAttachTracepoint attaches a loaded program to a tracepoint named
// category/name, such as syscalls/sys_enter_openat.
func BpfProgramAttachTracepoint(prog *BpfProgram, category, name string) (*BpfLink, error) {
	return BpfProgramAttachTracepointOpts(prog, category, name, nil)
}

// BpfProgramAttachTracepointOpts attaches a loaded program to a tracepoint
// with the given options. BpfCookie requires a kernel with BPF perf link
// support and returns EOPNOTSUPP on the ioctl fallback.
func BpfProgramAttachTracepointOpts(prog *BpfProgram, category, name string, opts *BpfTracepointOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_tracepoint"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if category == "" || name == "" {
		return nil, attachErr(op, unix.EINVAL)
	}
	if opts == nil {
		opts = &BpfTracepointOpts{}
	}

	id, err := tracepointID(category, name)
	if err != nil {
		return nil, attachErr(op, errnoFromError(err))
	}
	perfFD, err := openTracepointPerf(id, -1, 0)
	if err != nil {
		return nil, attachErr(op, errnoFromError(err))
	}

	perfOpts := &BpfPerfEventOpts{BpfCookie: opts.BpfCookie}
	link, err := BpfProgramAttachPerfEventOpts(prog, perfFD, perfOpts)
	if err != nil {
		unix.Close(perfFD)
		return nil, attachErr(op, errnoFromError(err))
	}
	return link, nil
}

// BpfProgramAttachPerfEvent attaches a loaded program to an already open perf
// event descriptor. On success the link takes ownership of pfd and releases
// it in BpfLinkDestroy; on failure pfd stays open and belongs to the caller.
func BpfProgramAttachPerfEvent(prog *BpfProgram, pfd int) (*BpfLink, error) {
	return BpfProgramAttachPerfEventOpts(prog, pfd, nil)
}

// BpfProgramAttachPerfEventOpts attaches a loaded program to a perf event
// with the given options.
//
// When the kernel supports BPF perf links and ForceIoctlAttach is false, the
// program is attached with BPF_LINK_CREATE, which carries BpfCookie. Otherwise
// the call uses PERF_EVENT_IOC_SET_BPF; a nonzero BpfCookie then returns
// EOPNOTSUPP, matching libbpf's fallback.
func BpfProgramAttachPerfEventOpts(prog *BpfProgram, pfd int, opts *BpfPerfEventOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_perf_event"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if pfd < 0 {
		return nil, attachErr(op, unix.EINVAL)
	}
	if opts == nil {
		opts = &BpfPerfEventOpts{}
	}

	if !opts.ForceIoctlAttach && perfLinkSupported() {
		attr := &sys.LinkCreateAttr{
			ProgFD:          uint32(prog.fd),
			TargetFD:        uint32(pfd),
			AttachType:      uint32(BPF_PERF_EVENT),
			PerfEventCookie: opts.BpfCookie,
		}
		linkFD, err := sys.LinkCreate(attr, nil)
		if err != nil {
			return nil, attachErr(op, errnoFromError(err))
		}
		link := &BpfLink{fd: linkFD, perfFD: pfd}
		if !opts.DontEnable {
			if err := unix.IoctlSetInt(pfd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
				unix.Close(linkFD)
				return nil, attachErr(op, errnoFromError(err))
			}
		}
		return link, nil
	}

	if opts.BpfCookie != 0 {
		return nil, attachErr(op, unix.EOPNOTSUPP)
	}
	link := &BpfLink{fd: pfd, perfFD: pfd}
	if err := unix.IoctlSetInt(pfd, unix.PERF_EVENT_IOC_SET_BPF, prog.fd); err != nil {
		return nil, attachErr(op, errnoFromError(err))
	}
	if !opts.DontEnable {
		if err := unix.IoctlSetInt(pfd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			return nil, attachErr(op, errnoFromError(err))
		}
	}
	return link, nil
}

// attachProbePerfEvent attaches prog to pfd, the perf event of a kprobe or
// uprobe, with opts. On success the link owns pfd and event, the probe's
// tracefs event or nil. On failure the call closes pfd and removes event.
func attachProbePerfEvent(prog *BpfProgram, pfd int, event *legacyEvent, opts *BpfPerfEventOpts) (*BpfLink, error) {
	link, err := BpfProgramAttachPerfEventOpts(prog, pfd, opts)
	if err != nil {
		unix.Close(pfd)
		if event != nil {
			_ = event.remove()
		}
		return nil, err
	}
	link.legacy = event
	return link, nil
}

// BpfProgramAttachRawTracepoint attaches a loaded program to a raw
// tracepoint, such as sys_enter.
func BpfProgramAttachRawTracepoint(prog *BpfProgram, name string) (*BpfLink, error) {
	return BpfProgramAttachRawTracepointOpts(prog, name, nil)
}

// BpfProgramAttachRawTracepointOpts attaches a loaded program to a raw
// tracepoint with the given options. Cookie requires kernel 5.15 or newer.
func BpfProgramAttachRawTracepointOpts(prog *BpfProgram, name string, opts *BpfRawTracepointOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_raw_tracepoint"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, attachErr(op, unix.EINVAL)
	}
	if opts == nil {
		opts = &BpfRawTracepointOpts{}
	}

	fd, err := sys.RawTracepointOpen(name, prog.fd, opts.Cookie)
	if err != nil {
		return nil, attachErr(op, errnoFromError(err))
	}
	return &BpfLink{fd: fd, perfFD: -1}, nil
}

// BpfProgramAttachKprobeMulti attaches a loaded kprobe.multi program to
// several functions in one link. Exactly one of Symbols and Addrs must be
// set. The kernel must support BPF_TRACE_KPROBE_MULTI (5.18 or newer); older
// kernels return EINVAL.
func BpfProgramAttachKprobeMulti(prog *BpfProgram, opts *BpfKprobeMultiOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_kprobe_multi"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if opts == nil || len(opts.Symbols) > 0 && len(opts.Addrs) > 0 || len(opts.Symbols) == 0 && len(opts.Addrs) == 0 {
		return nil, attachErr(op, unix.EINVAL)
	}

	flags := uint32(0)
	if opts.Retprobe {
		flags = BPF_F_KPROBE_MULTI_RETURN
	}
	attr := &sys.LinkCreateAttr{
		ProgFD:     uint32(prog.fd),
		AttachType: uint32(BPF_TRACE_KPROBE_MULTI),
	}
	km := &sys.LinkKprobeMulti{
		Flags:   flags,
		Syms:    opts.Symbols,
		Addrs:   opts.Addrs,
		Cookies: opts.Cookies,
	}
	fd, err := sys.LinkCreate(attr, km)
	if err != nil {
		errno := errnoFromError(err)
		if errors.Is(err, unix.ESRCH) {
			errno = unix.ENOENT
		}
		return nil, &Error{Op: op, Errno: errno}
	}
	return &BpfLink{fd: fd, perfFD: -1}, nil
}

// BpfProgramAttachUprobeMulti attaches a loaded program to several locations
// in binaryPath through one uprobe multi link, and returns a link the caller
// releases with BpfLinkDestroy. The link pins, unpins and detaches like the
// other BPF links.
//
// opts selects the locations with Syms or Offsets and may add one reference
// counter offset and one BPF cookie per location. Retprobe calls the program
// when the functions return; Session calls it on entry and, unless the entry
// run returns nonzero, on return. pid 0 probes the calling process, a
// positive pid probes that process, and a negative pid probes every process.
//
// The kernel must support uprobe multi links (Linux 6.6 or newer, 6.13 for
// Session), and the program must have been loaded with the expected attach
// type BPF_TRACE_UPROBE_MULTI, or BPF_TRACE_UPROBE_SESSION for Session; the
// kernel rejects other programs and older kernels with EINVAL.
//
// funcPattern, the function-name pattern alternative to opts, is not
// supported: a non-empty pattern returns EOPNOTSUPP after the input checks.
// The call returns EINVAL for an unloaded program, an empty binaryPath, a
// pattern combined with Syms, Offsets, RefCtrOffsets or Cookies, no locations
// at all, both Syms and Offsets, RefCtrOffsets or Cookies whose length is not
// the probe count, or both Retprobe and Session. A symbol missing from
// binaryPath returns ENOENT.
func BpfProgramAttachUprobeMulti(prog *BpfProgram, pid int, binaryPath string, funcPattern string, opts *BpfUprobeMultiOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_uprobe_multi"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &BpfUprobeMultiOpts{}
	}
	if err := checkUprobeMultiInputs(binaryPath, funcPattern, opts); err != nil {
		return nil, attachErr(op, err)
	}
	if funcPattern != "" {
		return nil, attachErr(op, unix.EOPNOTSUPP)
	}
	offsets, err := uprobeMultiOffsets(binaryPath, opts)
	if err != nil {
		return nil, attachErr(op, err)
	}

	attachType := BPF_TRACE_UPROBE_MULTI
	if opts.Session {
		attachType = BPF_TRACE_UPROBE_SESSION
	}
	um := &sys.LinkUprobeMulti{
		Path:          binaryPath,
		Offsets:       offsets,
		RefCtrOffsets: opts.RefCtrOffsets,
		Cookies:       opts.Cookies,
	}
	if opts.Retprobe {
		um.Flags = BPF_F_UPROBE_MULTI_RETURN
	}
	if pid == 0 {
		pid = os.Getpid()
	}
	if pid > 0 {
		um.PID = uint32(pid)
	}

	attr := &sys.LinkCreateAttr{
		ProgFD:     uint32(prog.fd),
		AttachType: uint32(attachType),
	}
	fd, err := sys.LinkCreateUprobeMulti(attr, um)
	if err != nil {
		return nil, attachErr(op, err)
	}
	return &BpfLink{fd: fd, perfFD: -1}, nil
}

// checkUprobeMultiInputs applies the uprobe multi input rules: a path is
// required; a pattern excludes every explicit array; without a pattern,
// exactly one of Syms and Offsets is set and the optional arrays match its
// length; Retprobe excludes Session.
func checkUprobeMultiInputs(binaryPath, funcPattern string, opts *BpfUprobeMultiOpts) error {
	cnt := len(opts.Syms)
	if cnt == 0 {
		cnt = len(opts.Offsets)
	}

	if binaryPath == "" {
		return unix.EINVAL
	}
	if funcPattern == "" && cnt == 0 {
		return unix.EINVAL
	}
	if funcPattern != "" {
		if cnt != 0 || len(opts.RefCtrOffsets) != 0 || len(opts.Cookies) != 0 {
			return unix.EINVAL
		}
	} else {
		if len(opts.Syms) != 0 && len(opts.Offsets) != 0 {
			return unix.EINVAL
		}
		if !optionalArrayLen(len(opts.RefCtrOffsets), cnt) || !optionalArrayLen(len(opts.Cookies), cnt) {
			return unix.EINVAL
		}
	}
	if opts.Retprobe && opts.Session {
		return unix.EINVAL
	}
	return nil
}

// optionalArrayLen reports whether an optional per-probe array of length n is
// absent or has one entry per probe.
func optionalArrayLen(n, cnt int) bool {
	return n == 0 || n == cnt
}

// uprobeMultiOffsets returns the probe offsets: Offsets as given, or the file
// offset of each name in Syms, resolved in binaryPath in order.
func uprobeMultiOffsets(binaryPath string, opts *BpfUprobeMultiOpts) ([]uint64, error) {
	if len(opts.Syms) == 0 {
		return opts.Offsets, nil
	}

	f, err := elf.Open(binaryPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	offsets := make([]uint64, len(opts.Syms))
	for i, sym := range opts.Syms {
		offset, err := elfFuncOffset(f, binaryPath, sym)
		if err != nil {
			return nil, err
		}
		offsets[i] = offset
	}
	return offsets, nil
}

// BpfProgramAttachTrace attaches a loaded fentry, fexit, fmod_ret or tp_btf
// program to the function resolved at load time.
func BpfProgramAttachTrace(prog *BpfProgram) (*BpfLink, error) {
	return BpfProgramAttachTraceOpts(prog, nil)
}

// BpfProgramAttachTraceOpts attaches a loaded tracing program with the given
// options. BpfCookie is passed to the program through
// bpf_get_attach_cookie.
func BpfProgramAttachTraceOpts(prog *BpfProgram, opts *BpfTraceOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_trace"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &BpfTraceOpts{}
	}

	attr := &sys.LinkCreateAttr{
		ProgFD:        uint32(prog.fd),
		AttachType:    uint32(prog.expectedAttachType),
		TracingCookie: opts.BpfCookie,
	}
	fd, err := sys.LinkCreate(attr, nil)
	if err != nil {
		// Kernels before 5.15 only attach tracing programs through the
		// raw tracepoint open command with a NULL name; the link is
		// still a tracing link. The raw command has no cookie support.
		if errors.Is(err, unix.EINVAL) && opts.BpfCookie == 0 {
			fd, err = sys.RawTracepointOpenProgram(prog.fd, 0)
		}
		if err != nil {
			return nil, attachErr(op, errnoFromError(err))
		}
	}
	return &BpfLink{fd: fd, perfFD: -1}, nil
}

// BpfProgramAttachLsm attaches a loaded LSM program to the hook resolved at
// load time.
func BpfProgramAttachLsm(prog *BpfProgram) (*BpfLink, error) {
	link, err := BpfProgramAttachTraceOpts(prog, nil)
	if err != nil {
		return nil, &Error{Op: "bpf_program__attach_lsm", Errno: errnoFromError(err)}
	}
	return link, nil
}

// BpfProgramAttach attaches a loaded program using the section name, like the
// library's automatic attach. It supports the sections this package can
// attach: kprobe, kretprobe, kprobe.multi, uprobe, uretprobe, tracepoint, tp,
// raw tracepoint, fentry, fexit, fmod_ret, tp_btf and lsm.
func BpfProgramAttach(prog *BpfProgram) (*BpfLink, error) {
	const op = "bpf_program__attach"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}

	def, ok := secDefFor(prog.sectionName)
	if !ok {
		return nil, attachErr(op, unix.EOPNOTSUPP)
	}
	target := strings.TrimPrefix(prog.sectionName, def.prefix)

	switch def.prefix {
	case "kprobe/", "kretprobe/":
		funcName, offset := splitFuncOffset(target)
		if funcName == "" || def.prefix == "kretprobe/" && offset != 0 {
			return nil, attachErr(op, unix.EINVAL)
		}
		return BpfProgramAttachKprobeOpts(prog, funcName, &BpfKprobeOpts{Retprobe: def.prefix == "kretprobe/", Offset: offset})
	case "kprobe.multi/", "kretprobe.multi/":
		return BpfProgramAttachKprobeMulti(prog, &BpfKprobeMultiOpts{
			Symbols:  []string{target},
			Retprobe: def.prefix == "kretprobe.multi/",
		})
	case "uprobe/", "uretprobe/", "uprobe.s/", "uretprobe.s/":
		sep := strings.LastIndexByte(target, ':')
		if sep < 0 {
			return nil, attachErr(op, unix.EINVAL)
		}
		funcName, offset := splitFuncOffset(target[sep+1:])
		retprobe := strings.HasPrefix(def.prefix, "uretprobe")
		if retprobe && offset != 0 {
			return nil, attachErr(op, unix.EINVAL)
		}
		return BpfProgramAttachUprobeOpts(prog, -1, target[:sep], offset, &BpfUprobeOpts{
			Retprobe: retprobe,
			FuncName: funcName,
		})
	case "tracepoint/", "tp/", "tracepoint.s/", "tp.s/":
		category, name, ok := strings.Cut(target, "/")
		if !ok {
			return nil, attachErr(op, unix.EINVAL)
		}
		return BpfProgramAttachTracepoint(prog, category, name)
	case "raw_tracepoint/", "raw_tp/", "raw_tracepoint.w/", "raw_tp.w/",
		"raw_tracepoint.s/", "raw_tp.s/":
		return BpfProgramAttachRawTracepoint(prog, target)
	case "fentry/", "fexit/", "fmod_ret/", "tp_btf/",
		"fentry.s/", "fexit.s/", "fmod_ret.s/", "tp_btf.s/":
		return BpfProgramAttachTrace(prog)
	case "lsm/", "lsm.s/":
		return BpfProgramAttachLsm(prog)
	default:
		return nil, attachErr(op, unix.EOPNOTSUPP)
	}
}

// checkAttachProgram rejects a nil or unloaded program.
func checkAttachProgram(prog *BpfProgram, op string) error {
	if prog == nil || prog.fd < 0 {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	return nil
}

// splitFuncOffset splits "name+123" into name and 123. A suffix that is not a
// decimal number is part of the name, matching libbpf's section parser.
func splitFuncOffset(spec string) (string, uint64) {
	plus := strings.LastIndexByte(spec, '+')
	if plus < 0 {
		return spec, 0
	}
	offset, err := strconv.ParseUint(spec[plus+1:], 10, 64)
	if err != nil {
		return spec, 0
	}
	return spec[:plus], offset
}

// attachErr wraps a syscall error for an attach operation.
func attachErr(op string, err error) error {
	return &Error{Op: op, Errno: errnoFromError(err)}
}
