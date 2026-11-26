// SPDX-License-Identifier: LGPL-2.1-only
// Ported from libbpf src/libbpf.c at 4f05fb0.

package libbpf

import "github.com/golbpfgo/golbpfgo/internal/elf"

// BpfProgram is a program opened from an object. It mirrors struct bpf_program.
type BpfProgram struct {
	name               string
	progType           BpfProgType
	expectedAttachType BpfAttachType
	sectionName        string
	insns              []byte
	relocs             []elf.Reloc
}

// BpfProgramName mirrors bpf_program__name().
func BpfProgramName(p *BpfProgram) string {
	if p == nil {
		return ""
	}
	return p.name
}

// BpfProgramType mirrors bpf_program__type().
func BpfProgramTypeOf(p *BpfProgram) BpfProgType {
	if p == nil {
		return 0
	}
	return p.progType
}

// BpfProgramExpectedAttachType mirrors bpf_program__expected_attach_type().
func BpfProgramExpectedAttachType(p *BpfProgram) BpfAttachType {
	if p == nil {
		return 0
	}
	return p.expectedAttachType
}

// BpfProgramSectionName mirrors bpf_program__section_name().
func BpfProgramSectionName(p *BpfProgram) string {
	if p == nil {
		return ""
	}
	return p.sectionName
}

// BpfProgramInsnCnt mirrors bpf_program__insn_cnt().
func BpfProgramInsnCnt(p *BpfProgram) int {
	if p == nil {
		return 0
	}
	return len(p.insns) / 8
}

// BpfProgramInsns returns the raw instruction bytes. The slice must not be
// modified.
func BpfProgramInsns(p *BpfProgram) []byte {
	if p == nil {
		return nil
	}
	return p.insns
}
