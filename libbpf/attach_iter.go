// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program__attach_iter

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfIterOpts are the optional settings of BpfProgramAttachIter.
//
// LinkInfo is the raw union bpf_iter_link_info the iterator target takes,
// such as the map descriptor of a bpf_map_elem iterator, in native byte
// order. nil selects the target's default iterator. The attach passes the
// bytes to the kernel, which reads them during the call; a non-nil empty
// LinkInfo is refused with EINVAL, as the kernel refuses an info pointer
// without a length.
type BpfIterOpts struct {
	LinkInfo []byte
}

// BpfProgramAttachIter attaches a loaded iterator program, such as an
// iter/bpf_map program, through a BPF_TRACE_ITER link with no target
// descriptor and the link info in opts, which may be nil. The link does not
// run the program: reading an iterator descriptor that BPF_ITER_CREATE makes
// from the link does, and this package does not wrap that yet. It returns
// EINVAL for a nil or unloaded program and a non-nil empty LinkInfo, and the
// kernel errno when the link is refused.
func BpfProgramAttachIter(prog *BpfProgram, opts *BpfIterOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_iter"

	var info []byte
	if opts != nil {
		if opts.LinkInfo != nil && len(opts.LinkInfo) == 0 {
			return nil, &Error{Op: op, Errno: unix.EINVAL}
		}
		info = opts.LinkInfo
	}
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}

	fd, err := sys.LinkCreateIter(iterAttr(prog), info)
	if err != nil {
		return nil, attachErr(op, err)
	}
	return &BpfLink{fd: fd, perfFD: -1}, nil
}

// iterAttr returns the BPF_LINK_CREATE attribute of an iterator link for the
// loaded prog: the program, target descriptor 0 and BPF_TRACE_ITER.
// sys.LinkCreateIter points it at the link info.
func iterAttr(prog *BpfProgram) *sys.LinkCreateAttr {
	return &sys.LinkCreateAttr{
		ProgFD:     uint32(prog.fd),
		AttachType: sys.BPF_TRACE_ITER,
	}
}
