// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program_attach_fd, bpf_program__attach_cgroup, bpf_program__attach_cgroup_opts, bpf_program__attach_netns, bpf_program__attach_sockmap, bpf_program__attach_xdp

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfCgroupOpts are the optional settings of BpfProgramAttachCgroupOpts.
//
// RelativeFD or RelativeID names the program or link the new program is
// placed next to; at most one of them may be set. Flags carries the link
// attach flags, such as BPF_F_BEFORE, BPF_F_AFTER and BPF_F_LINK; the attach
// adds BPF_F_ID itself when RelativeID is set. ExpectedRevision, when
// nonzero, makes the kernel refuse the attach with ESTALE if the cgroup's
// program list for the attach type changed since that revision.
type BpfCgroupOpts struct {
	Flags            uint32
	RelativeFD       int
	RelativeID       uint32
	ExpectedRevision uint64
}

// BpfProgramAttachCgroup attaches a loaded program to the cgroup v2 directory
// cgroupFD through a BPF link, with the program's expected attach type, such
// as BPF_CGROUP_INET_INGRESS for a cgroup_skb/ingress program. The caller
// keeps cgroupFD and owns the returned link, which BpfLinkDestroy detaches.
// See bpfProgramAttachFD for the errors.
func BpfProgramAttachCgroup(prog *BpfProgram, cgroupFD int) (*BpfLink, error) {
	return bpfProgramAttachFD(prog, cgroupFD, "bpf_program__attach_cgroup", nil)
}

// BpfProgramAttachCgroupOpts attaches a loaded program to the cgroup v2
// directory cgroupFD like BpfProgramAttachCgroup, with the placement, flags
// and expected revision in opts, which may be nil. It returns EINVAL when
// both RelativeFD and RelativeID are set. The kernel refuses relative
// placement and nonzero flags with EINVAL when it predates multi-program
// cgroup attachment, and ignores ExpectedRevision there.
func BpfProgramAttachCgroupOpts(prog *BpfProgram, cgroupFD int, opts *BpfCgroupOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_cgroup_opts"

	attr, err := cgroupOptsAttr(opts)
	if err != nil {
		return nil, attachErr(op, err)
	}
	return bpfProgramAttachFD(prog, cgroupFD, op, attr)
}

// cgroupOptsAttr returns the link flags and cgroup fields of opts, or nil for
// nil opts. It returns EINVAL when both RelativeFD and RelativeID are set.
func cgroupOptsAttr(opts *BpfCgroupOpts) (*sys.LinkCreateAttr, error) {
	if opts == nil {
		return nil, nil
	}
	if opts.RelativeFD != 0 && opts.RelativeID != 0 {
		return nil, unix.EINVAL
	}
	return &sys.LinkCreateAttr{
		Flags:                  opts.Flags,
		CgroupRelativeFD:       uint32(opts.RelativeFD),
		CgroupRelativeID:       opts.RelativeID,
		CgroupExpectedRevision: opts.ExpectedRevision,
	}, nil
}

// BpfProgramAttachNetns attaches a loaded program, such as a flow_dissector
// program, to the network namespace netnsFD, an open /proc/<pid>/ns/net,
// through a BPF link with the program's expected attach type. The caller
// keeps netnsFD and owns the returned link. See bpfProgramAttachFD for the
// errors.
func BpfProgramAttachNetns(prog *BpfProgram, netnsFD int) (*BpfLink, error) {
	return bpfProgramAttachFD(prog, netnsFD, "bpf_program__attach_netns", nil)
}

// BpfProgramAttachXDP attaches a loaded XDP program to the network interface
// with index ifindex through a BPF link with the program's expected attach
// type, BPF_XDP for an xdp section. The kernel picks the attach mode. It
// returns EEXIST or EBUSY from the kernel when the interface already has an
// XDP program. See bpfProgramAttachFD for the other errors.
func BpfProgramAttachXDP(prog *BpfProgram, ifindex int) (*BpfLink, error) {
	return bpfProgramAttachFD(prog, ifindex, "bpf_program__attach_xdp", nil)
}

// BpfProgramAttachSockmap attaches a loaded program, such as an sk_msg
// program, to the sockmap or sockhash mapFD through a BPF link with the
// program's expected attach type. The caller keeps mapFD and owns the
// returned link. Sockmap links need Linux 6.10 or newer; older kernels
// return EINVAL. See bpfProgramAttachFD for the other errors.
func BpfProgramAttachSockmap(prog *BpfProgram, mapFD int) (*BpfLink, error) {
	return bpfProgramAttachFD(prog, mapFD, "bpf_program__attach_sockmap", nil)
}

// bpfProgramAttachFD creates a BPF link from the loaded prog to targetFD, a
// descriptor or, for XDP, an interface index, with the program's expected
// attach type. attr, which may be nil, carries the flags and union fields of
// the link; the call fills in the program, target and attach type. It
// returns EINVAL for a nil or unloaded program or for attr fields the attach
// type does not take, and the kernel errno when the link is refused.
func bpfProgramAttachFD(prog *BpfProgram, targetFD int, op string, attr *sys.LinkCreateAttr) (*BpfLink, error) {
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}

	fd, err := sys.LinkCreate(attachFDAttr(prog, targetFD, attr), nil)
	if err != nil {
		return nil, attachErr(op, err)
	}
	return &BpfLink{fd: fd, perfFD: -1}, nil
}

// attachFDAttr returns a copy of attr, or a zero attribute when attr is nil,
// with the loaded prog's descriptor, targetFD and the program's expected
// attach type.
func attachFDAttr(prog *BpfProgram, targetFD int, attr *sys.LinkCreateAttr) *sys.LinkCreateAttr {
	out := &sys.LinkCreateAttr{}
	if attr != nil {
		*out = *attr
	}
	out.ProgFD = uint32(prog.fd)
	out.TargetFD = uint32(targetFD)
	out.AttachType = uint32(prog.expectedAttachType)
	return out
}
