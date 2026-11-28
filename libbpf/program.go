// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program__name, bpf_program__type, bpf_program__expected_attach_type, bpf_program__section_name, bpf_program__insn_cnt, bpf_program__insns, bpf_program__fd

package libbpf

import "github.com/gobpfgo/gobpfgo/internal/elf"

// BpfProgram is a program parsed from an object. It carries the section, type,
// attach type and instruction bytes; the load step adds the kernel descriptor.
//
// A program is one function of an executable section. A function in .text is
// a subprogram: the load appends it to every program that calls it and never
// loads it on its own.
type BpfProgram struct {
	// obj is the object the program belongs to. USDT attachment keeps its
	// spec ID state there.
	obj                *BpfObject
	name               string
	progType           BpfProgType
	expectedAttachType BpfAttachType
	progFlags          uint32
	usdt               bool
	sectionName        string
	attachBTF          bool
	attachTarget       string
	attachBTFID        uint32
	attachBTFObjFD     int
	insns              []byte
	relocs             []elf.Reloc
	fd                 int
	id                 uint32
	xlatedInsnCnt      int
	jitedLen           uint32
	// secIdx is the index of the section that holds the program's
	// function, and secInsnOff and secInsnCnt are the function's first
	// instruction and length in it. relocs cover only that function, with
	// relocation offsets from its first instruction, and so does insns
	// until a load replaces a main program's insns with its final code.
	// symGlobal is set for a global or weak function, and markBtfStatic
	// when that function also has hidden or internal visibility, so the
	// load gives a subprogram's BTF FUNC static linkage.
	secIdx        int
	secInsnOff    int
	secInsnCnt    int
	symGlobal     bool
	markBtfStatic bool
	// exceptionCbIdx is the index in the object's programs of a main
	// program's exception callback, which the load appends to the
	// program's code, or -1. The load sets it.
	exceptionCbIdx int
}

// BpfProgramName returns the function name of the program.
func BpfProgramName(p *BpfProgram) string {
	if p == nil {
		return ""
	}
	return p.name
}

// BpfProgramTypeOf returns the program type from the SEC table.
//
// The accessor has the Of suffix because BpfProgType is the Go type name. The
// value is the enum bpf_prog_type from linux/bpf.h.
func BpfProgramTypeOf(p *BpfProgram) BpfProgType {
	if p == nil {
		return 0
	}
	return p.progType
}

// BpfProgramExpectedAttachType returns the expected attach type from the SEC
// table, or BPF_ATTACH_TYPE_UNSPEC when the section does not need one. A USDT
// program loaded on a kernel with uprobe multi links reports
// BPF_TRACE_UPROBE_MULTI after the load.
func BpfProgramExpectedAttachType(p *BpfProgram) BpfAttachType {
	if p == nil {
		return 0
	}
	return p.expectedAttachType
}

// BpfProgramSectionName returns the ELF section name, such as
// "kprobe/do_sys_open" or "tracepoint/syscalls/sys_enter_openat".
func BpfProgramSectionName(p *BpfProgram) string {
	if p == nil {
		return ""
	}
	return p.sectionName
}

// BpfProgramInsnCnt returns the number of 8-byte BPF instructions that
// BpfProgramInsns returns: the program's own function before BpfObjectLoad,
// and after a successful load the final code, which includes the appended
// subprograms. A subprogram's count stays its own function's.
func BpfProgramInsnCnt(p *BpfProgram) int {
	if p == nil {
		return 0
	}
	return len(p.insns) / 8
}

// BpfProgramInsns returns the program's instruction bytes. Before
// BpfObjectLoad they are the program's own function as the object file holds
// it. A successful load replaces them with a copy of the final code the
// kernel received: CO-RE relocated, with a copy of every .text subprogram
// the program reaches appended in the order the load first reaches each, the
// calls pointing at those copies, and the map descriptors, global variable
// offsets and extern values patched in. A subprogram, which the program
// iteration skips, gets its own function after CO-RE instead, with every
// load of a subprogram address marked BPF_PSEUDO_FUNC, as libbpf leaves it:
// its calls, map loads and extern references stay as the object file has
// them, because they are relocated only in each copy appended to a main
// program. A failed load leaves every program as it was. The object file's
// section data is never changed.
//
// The slice belongs to the program. Do not modify it and do not use it
// after BpfObjectClose.
func BpfProgramInsns(p *BpfProgram) []byte {
	if p == nil {
		return nil
	}
	return p.insns
}

// BpfProgramFD returns the loaded program descriptor, or -1 before
// BpfObjectLoad and after BpfObjectClose. A subprogram is never loaded on its
// own, so it always returns -1.
func BpfProgramFD(p *BpfProgram) int {
	if p == nil {
		return -1
	}
	return p.fd
}
