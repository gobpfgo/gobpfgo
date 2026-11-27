// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf

import "github.com/gobpfgo/gobpfgo/libbpf"

// Program is one program of an Object.
//
// A Program keeps its Object but owns nothing: the Object owns the core
// program and its descriptor. After the Object is closed, every Program
// method with an error result returns ErrClosed and the accessors return a
// zero value, -1 for FD. A Link returned by an attach method is independent of
// the Program and the Object.
type Program struct {
	prog *libbpf.BpfProgram
	obj  *Object
}

// live returns the core program, or nil for a nil Program or a closed
// Object. The core accessors return their zero value for nil.
func (p *Program) live() *libbpf.BpfProgram {
	if p == nil || p.obj.closed {
		return nil
	}
	return p.prog
}

// isClosed reports whether the Program's Object is closed. A nil Program is
// not closed; its methods pass nil to the core, which rejects it.
func (p *Program) isClosed() bool {
	return p != nil && p.obj.closed
}

// Name returns the program's function name.
func (p *Program) Name() string {
	return libbpf.BpfProgramName(p.live())
}

// Type returns the program type the section name selects.
func (p *Program) Type() libbpf.BpfProgType {
	return libbpf.BpfProgramTypeOf(p.live())
}

// ExpectedAttachType returns the expected attach type the section name
// selects, or BPF_ATTACH_TYPE_UNSPEC when the section needs none.
func (p *Program) ExpectedAttachType() libbpf.BpfAttachType {
	return libbpf.BpfProgramExpectedAttachType(p.live())
}

// SectionName returns the ELF section name, such as "kprobe/do_sys_openat2".
func (p *Program) SectionName() string {
	return libbpf.BpfProgramSectionName(p.live())
}

// InsnCnt returns the number of 8-byte instructions Insns returns.
func (p *Program) InsnCnt() int {
	return libbpf.BpfProgramInsnCnt(p.live())
}

// Insns returns the program's instruction bytes: its own function before
// Load, and the final code the kernel received after a successful Load. The
// slice belongs to the Object; do not modify it or use it after Close.
func (p *Program) Insns() []byte {
	return libbpf.BpfProgramInsns(p.live())
}

// FD returns the loaded program descriptor, or -1 before Load and after the
// Object is closed. The descriptor belongs to the Object.
func (p *Program) FD() int {
	return libbpf.BpfProgramFD(p.live())
}

// Info returns the kernel metadata of the loaded program, including the line
// info libbpf.BpfProgLineInfoNew takes. It returns ErrClosed after the Object
// is closed and the core *libbpf.Error otherwise, with EINVAL before Load.
// See libbpf.BpfProgramInfo.
func (p *Program) Info() (*libbpf.BpfProgInfo, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	return libbpf.BpfProgramInfo(p.live())
}

// Pin pins the loaded program at path on bpffs, creating a missing parent
// directory. It returns ErrClosed after the Object is closed and the core
// *libbpf.Error otherwise.
func (p *Program) Pin(path string) error {
	if p.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfProgramPin(p.live(), path)
}

// Unpin removes the program's pin at path. The program descriptor stays
// open. It returns ErrClosed after the Object is closed and the core
// *libbpf.Error otherwise.
func (p *Program) Unpin(path string) error {
	if p.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfProgramUnpin(p.live(), path)
}
