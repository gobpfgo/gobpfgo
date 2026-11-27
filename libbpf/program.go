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
	// instruction and length in it. insns and relocs cover only that
	// function, with relocation offsets from its first instruction.
	// symGlobal is set for a global or weak function.
	secIdx     int
	secInsnOff int
	secInsnCnt int
	symGlobal  bool
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

// BpfProgramInsnCnt returns the number of 8-byte BPF instructions of the
// program's own function. The subprograms that the load appends are not
// counted.
func BpfProgramInsnCnt(p *BpfProgram) int {
	if p == nil {
		return 0
	}
	return len(p.insns) / 8
}

// BpfProgramInsns returns the raw instruction bytes of the program's own
// function, as the object file holds them. The load relocates and appends
// subprograms on a copy, so the bytes do not change.
//
// The slice aliases the object. Do not modify it and do not use it after
// BpfObjectClose.
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
