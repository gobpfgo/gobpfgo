// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.h
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: struct bpf_kprobe_opts, bpf_program__attach_kprobe, bpf_program__attach_kprobe_opts, add_kprobe_event_legacy, arch_specific_syscall_pfx, probe_kern_syscall_wrapper

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// BpfKprobeOpts are the optional settings of BpfProgramAttachKprobeOpts. The
// zero value attaches a kprobe at the function entry in
// ProbeAttachModeDefault.
//
// Retprobe attaches to the function return instead. Offset is the byte
// offset into the function or, when the function name is empty, the raw
// kernel address to probe. BpfCookie is the value the program reads with
// bpf_get_attach_cookie; it needs a BPF perf link.
//
// AttachMode selects how the kprobe is created and attached. The kernel has
// the kprobe perf PMU when /sys/bus/event_source/devices/kprobe/type can be
// read.
//
//   - ProbeAttachModeDefault opens the kprobe through the PMU, or through a
//     tracefs kprobe event on a kernel without it, and attaches the program
//     with a BPF perf link when the kernel has one and with
//     PERF_EVENT_IOC_SET_BPF otherwise.
//   - ProbeAttachModeLegacy creates a tracefs kprobe event and attaches the
//     program with PERF_EVENT_IOC_SET_BPF.
//   - ProbeAttachModePerf opens the kprobe through the PMU and attaches the
//     program with PERF_EVENT_IOC_SET_BPF.
//   - ProbeAttachModeLink opens the kprobe through the PMU and attaches the
//     program with a BPF perf link (Linux 5.15 or newer).
type BpfKprobeOpts struct {
	Retprobe   bool
	Offset     uint64
	BpfCookie  uint64
	AttachMode ProbeAttachMode
}

// BpfProgramAttachKprobe attaches a loaded program to the entry of the kernel
// function funcName, or to its return when retprobe is set, in
// ProbeAttachModeDefault. The caller must release the link with
// BpfLinkDestroy. See BpfProgramAttachKprobeOpts.
func BpfProgramAttachKprobe(prog *BpfProgram, retprobe bool, funcName string) (*BpfLink, error) {
	return BpfProgramAttachKprobeOpts(prog, funcName, &BpfKprobeOpts{Retprobe: retprobe})
}

// BpfProgramAttachKprobeOpts attaches a loaded program to the kernel function
// funcName with the given options and returns a link the caller releases with
// BpfLinkDestroy. The kprobe fires on every CPU for every process. opts.Offset
// is the byte offset into funcName; an empty funcName probes the raw kernel
// address in opts.Offset instead, which only the PMU can do.
//
// opts.AttachMode selects the mechanism; see BpfKprobeOpts. Without the kprobe
// perf PMU the perf and link modes return EOPNOTSUPP; the link mode also
// returns EOPNOTSUPP on a kernel without BPF perf links. Any other mode is
// EINVAL. An empty funcName on the tracefs path is EOPNOTSUPP. A kretprobe
// through a PMU without its retprobe format file is ENOENT.
//
// The default and link modes attach the program with a BPF perf link when the
// kernel has one, which carries opts.BpfCookie. Otherwise, and always in the
// legacy and perf modes, the program is attached with PERF_EVENT_IOC_SET_BPF,
// and a nonzero BpfCookie is EOPNOTSUPP. The link owns the perf event and the
// tracefs event, if any; when the attach fails, the call releases both.
//
// Opening the perf event needs root or CAP_PERFMON, and the tracefs path also
// needs write access to tracefs.
func BpfProgramAttachKprobeOpts(prog *BpfProgram, funcName string, opts *BpfKprobeOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_kprobe"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &BpfKprobeOpts{}
	}

	_, pmuErr := determineKprobePerfType()
	legacy, forceIoctl, err := probeAttachMode(opts.AttachMode, pmuErr != nil, perfLinkSupported)
	if err != nil {
		return nil, attachErr(op, err)
	}
	if funcName == "" && legacy {
		return nil, attachErr(op, unix.EOPNOTSUPP)
	}

	var event *legacyEvent
	var pfd int
	if legacy {
		event, pfd, err = openLegacyKprobe(opts.Retprobe, funcName, opts.Offset)
	} else {
		pfd, err = perfEventOpenProbe(false, opts.Retprobe, funcName, opts.Offset, -1, 0)
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

// openLegacyKprobe adds a tracefs kprobe or kretprobe event at offset into
// funcName and opens its perf event for every process on CPU 0. The caller
// owns the event and the perf descriptor; on failure the event is removed
// again.
func openLegacyKprobe(retprobe bool, funcName string, offset uint64) (*legacyEvent, int, error) {
	kind := probeKprobe
	if retprobe {
		kind = probeKretprobe
	}
	event := &legacyEvent{root: tracefsRoot(), kind: kind, name: probeEventName(funcName, offset)}
	pfd, err := event.open(kprobeEventLine(event, funcName, offset), -1)
	if err != nil {
		return nil, -1, err
	}
	return event, pfd, nil
}

// kprobeEventLine returns the kprobe_events command that adds event, a
// kprobe or kretprobe at offset into funcName, as libbpf's
// add_kprobe_event_legacy writes it.
func kprobeEventLine(event *legacyEvent, funcName string, offset uint64) string {
	prefix := byte('p')
	if event.kind == probeKretprobe {
		prefix = 'r'
	}
	return fmt.Sprintf("%c:%s/%s %s+0x%x", prefix, event.group(), event.name, funcName, offset)
}

// archSyscallPrefix returns libbpf's arch_specific_syscall_pfx for the
// architecture the package is built for: the infix of the kernel's
// arch-specific syscall entry points, as in __x64_sys_bpf, or "" for an
// architecture without one.
func archSyscallPrefix() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	}
	return ""
}

// probeSyscallWrapper reports whether the kernel enters syscalls through
// arch-specific wrappers, CONFIG_ARCH_HAS_SYSCALL_WRAPPER, by checking that
// a kprobe on __<prefix>_sys_bpf can be created, as libbpf's
// probe_kern_syscall_wrapper does. With the kprobe perf PMU it opens the
// kprobe for the calling process and closes it again. Without the PMU it
// adds a tracefs kprobe event and removes it; libbpf ignores a failed
// removal, and so does the probe. It needs root, or CAP_PERFMON and for the
// tracefs path write access to tracefs; without them, and on an
// architecture without a prefix, the feature is reported missing.
func probeSyscallWrapper() bool {
	prefix := archSyscallPrefix()
	if prefix == "" {
		return false
	}
	name := "__" + prefix + "_sys_bpf"

	if _, err := determineKprobePerfType(); err == nil {
		pfd, err := perfEventOpenProbe(false, false, name, 0, os.Getpid(), 0)
		if err != nil {
			return false
		}
		unix.Close(pfd)
		return true
	}

	event := &legacyEvent{root: tracefsRoot(), kind: probeKprobe, name: probeEventName(name, 0)}
	if err := event.add(kprobeEventLine(event, name, 0)); err != nil {
		return false
	}
	_ = event.remove()
	return true
}
