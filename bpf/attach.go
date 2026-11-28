// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf

import "github.com/gobpfgo/gobpfgo/libbpf"

// The attach methods share one contract. Each takes the parameters and core
// option types of the libbpf.BpfProgramAttach function it names, requires a
// loaded program, and returns a Link the caller owns and must Destroy. After
// the Object is closed they return ErrClosed; a core failure returns the core
// *libbpf.Error unchanged.

// AttachKprobe attaches the program to the kernel function funcName, or to
// its return when retprobe is set. See libbpf.BpfProgramAttachKprobe.
func (p *Program) AttachKprobe(retprobe bool, funcName string) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachKprobe(p.live(), retprobe, funcName))
}

// AttachKprobeOpts attaches the program to the kernel function funcName with
// opts, or to the raw kernel address in opts.Offset when funcName is empty.
// See libbpf.BpfProgramAttachKprobeOpts.
func (p *Program) AttachKprobeOpts(funcName string, opts *libbpf.BpfKprobeOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachKprobeOpts(p.live(), funcName, opts))
}

// AttachUprobe attaches the program to binaryPath at offset for pid, where
// -1 selects every process. See libbpf.BpfProgramAttachUprobe.
func (p *Program) AttachUprobe(pid int, binaryPath string, offset uint64) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachUprobe(p.live(), pid, binaryPath, offset))
}

// AttachUprobeOpts attaches the program to binaryPath at offset for pid with
// opts. See libbpf.BpfProgramAttachUprobeOpts.
func (p *Program) AttachUprobeOpts(pid int, binaryPath string, offset uint64, opts *libbpf.BpfUprobeOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachUprobeOpts(p.live(), pid, binaryPath, offset, opts))
}

// AttachTracepoint attaches the program to the tracepoint category/name. See
// libbpf.BpfProgramAttachTracepoint.
func (p *Program) AttachTracepoint(category, name string) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachTracepoint(p.live(), category, name))
}

// AttachTracepointOpts attaches the program to the tracepoint category/name
// with opts. See libbpf.BpfProgramAttachTracepointOpts.
func (p *Program) AttachTracepointOpts(category, name string, opts *libbpf.BpfTracepointOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachTracepointOpts(p.live(), category, name, opts))
}

// AttachPerfEvent attaches the program to the open perf event pfd. On
// success the Link owns pfd; on any error, including ErrClosed, pfd stays
// with the caller. See libbpf.BpfProgramAttachPerfEvent.
func (p *Program) AttachPerfEvent(pfd int) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachPerfEvent(p.live(), pfd))
}

// AttachPerfEventOpts attaches the program to the open perf event pfd with
// opts, with the ownership of AttachPerfEvent. See
// libbpf.BpfProgramAttachPerfEventOpts.
func (p *Program) AttachPerfEventOpts(pfd int, opts *libbpf.BpfPerfEventOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachPerfEventOpts(p.live(), pfd, opts))
}

// AttachRawTracepoint attaches the program to the raw tracepoint name. See
// libbpf.BpfProgramAttachRawTracepoint.
func (p *Program) AttachRawTracepoint(name string) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachRawTracepoint(p.live(), name))
}

// AttachRawTracepointOpts attaches the program to the raw tracepoint name
// with opts. See libbpf.BpfProgramAttachRawTracepointOpts.
func (p *Program) AttachRawTracepointOpts(name string, opts *libbpf.BpfRawTracepointOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachRawTracepointOpts(p.live(), name, opts))
}

// AttachKprobeMulti attaches the program to the functions opts selects
// through one kprobe multi link. See libbpf.BpfProgramAttachKprobeMulti.
func (p *Program) AttachKprobeMulti(opts *libbpf.BpfKprobeMultiOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachKprobeMulti(p.live(), opts))
}

// AttachUprobeMulti attaches the program to the locations in binaryPath that
// funcPattern or opts selects through one uprobe multi link. See
// libbpf.BpfProgramAttachUprobeMulti.
func (p *Program) AttachUprobeMulti(pid int, binaryPath string, funcPattern string, opts *libbpf.BpfUprobeMultiOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachUprobeMulti(p.live(), pid, binaryPath, funcPattern, opts))
}

// AttachCgroup attaches the program to the cgroup v2 directory cgroupFD with
// its expected attach type. The caller keeps cgroupFD. See
// libbpf.BpfProgramAttachCgroup.
func (p *Program) AttachCgroup(cgroupFD int) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachCgroup(p.live(), cgroupFD))
}

// AttachCgroupOpts attaches the program to the cgroup v2 directory cgroupFD
// with the placement, flags and expected revision in opts. See
// libbpf.BpfProgramAttachCgroupOpts.
func (p *Program) AttachCgroupOpts(cgroupFD int, opts *libbpf.BpfCgroupOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachCgroupOpts(p.live(), cgroupFD, opts))
}

// AttachNetns attaches the program, such as a flow_dissector program, to the
// network namespace netnsFD. The caller keeps netnsFD. See
// libbpf.BpfProgramAttachNetns.
func (p *Program) AttachNetns(netnsFD int) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachNetns(p.live(), netnsFD))
}

// AttachXDP attaches an XDP program to the network interface with index
// ifindex. See libbpf.BpfProgramAttachXDP.
func (p *Program) AttachXDP(ifindex int) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachXDP(p.live(), ifindex))
}

// AttachSockmap attaches the program, such as an sk_msg program, to the
// sockmap or sockhash mapFD. The caller keeps mapFD. See
// libbpf.BpfProgramAttachSockmap.
func (p *Program) AttachSockmap(mapFD int) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachSockmap(p.live(), mapFD))
}

// AttachIter attaches an iterator program, such as an iter/bpf_map program,
// through an iterator link with the link info in opts, which may be nil for
// the default iterator. See libbpf.BpfProgramAttachIter.
func (p *Program) AttachIter(opts *libbpf.BpfIterOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachIter(p.live(), opts))
}

// AttachFreplace attaches a freplace program in place of the function
// attachFuncName of the loaded program targetFD, or, with targetFD 0 and an
// empty attachFuncName, to the function it was loaded against. The caller
// keeps targetFD. See libbpf.BpfProgramAttachFreplace.
func (p *Program) AttachFreplace(targetFD int, attachFuncName string) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachFreplace(p.live(), targetFD, attachFuncName))
}

// AttachUsdt attaches the program to every call site of the USDT probe
// provider:name in binaryPath for pid, where -1 selects every process. The
// object must include libbpf's usdt.bpf.h. The Link has no descriptor: FD
// returns -1 and Pin returns EOPNOTSUPP. See libbpf.BpfProgramAttachUsdt.
func (p *Program) AttachUsdt(pid int, binaryPath, provider, name string, opts *libbpf.BpfUsdtOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachUsdt(p.live(), pid, binaryPath, provider, name, opts))
}

// AttachTrace attaches an fentry, fexit, fmod_ret or tp_btf program to the
// target resolved at load. See libbpf.BpfProgramAttachTrace.
func (p *Program) AttachTrace() (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachTrace(p.live()))
}

// AttachTraceOpts attaches a tracing program with opts. See
// libbpf.BpfProgramAttachTraceOpts.
func (p *Program) AttachTraceOpts(opts *libbpf.BpfTraceOpts) (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachTraceOpts(p.live(), opts))
}

// AttachLsm attaches an LSM program to the hook resolved at load. See
// libbpf.BpfProgramAttachLsm.
func (p *Program) AttachLsm() (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttachLsm(p.live()))
}

// Attach attaches the program to the target its section name describes. See
// libbpf.BpfProgramAttach for the supported sections.
func (p *Program) Attach() (*Link, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return newLink(libbpf.BpfProgramAttach(p.live()))
}
