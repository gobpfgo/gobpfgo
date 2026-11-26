// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program__name, bpf_program__type, bpf_program__expected_attach_type, bpf_program__section_name, bpf_program__insn_cnt, bpf_program__insns

package libbpf

import "github.com/golbpfgo/golbpfgo/internal/elf"

// BpfProgram is a program parsed from an object. It carries the section, type,
// attach type and instruction bytes; the load step adds the kernel descriptor.
type BpfProgram struct {
	name               string
	progType           BpfProgType
	expectedAttachType BpfAttachType
	sectionName        string
	insns              []byte
	relocs             []elf.Reloc
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
// table, or BPF_ATTACH_TYPE_UNSPEC when the section does not need one.
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

// BpfProgramInsnCnt returns the number of 8-byte BPF instructions.
func BpfProgramInsnCnt(p *BpfProgram) int {
	if p == nil {
		return 0
	}
	return len(p.insns) / 8
}

// BpfProgramInsns returns the raw instruction bytes.
//
// The slice aliases the object. Do not modify it and do not use it after
// BpfObjectClose.
func BpfProgramInsns(p *BpfProgram) []byte {
	if p == nil {
		return nil
	}
	return p.insns
}
