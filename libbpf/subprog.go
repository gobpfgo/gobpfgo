// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__add_programs, bpf_object__init_prog, cmp_progs, prog_is_subprog, sym_is_subprog, prog_contains_insn, find_prog_by_sec_insn, bpf_object__collect_prog_relos

package libbpf

import (
	"cmp"
	"debug/elf"
	"fmt"
	"slices"
	"strings"

	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// textSec is the section of the subprograms: the functions that are not
// programs of their own and that programs call.
const textSec = ".text"

// parsePrograms creates the programs of the executable sections, one per
// function symbol, sorted by section index and then by offset in the
// section. Every function in .text is a subprogram. A section whose name is
// not in the SEC table has no programs. Each program gets the relocations of
// its own instructions. It also returns the index of the .text section, or 0
// when the object has none.
func parsePrograms(e *objelf.Object) ([]*BpfProgram, int, error) {
	var programs []*BpfProgram
	textShndx := 0
	var sections []objelf.Program

	for _, sec := range e.Programs {
		if sec.Name == textSec {
			textShndx = sec.SectionIndex
		}
		def, ok := secDefFor(sec.Name)
		if !ok && sec.Name != textSec {
			continue
		}
		progs, err := addPrograms(e, sec, textShndx, def)
		if err != nil {
			return nil, 0, err
		}
		programs = append(programs, progs...)
		sections = append(sections, sec)
	}

	slices.SortFunc(programs, cmpProgs)
	for _, sec := range sections {
		if err := collectProgRelos(e, programs, sec); err != nil {
			return nil, 0, err
		}
	}
	return programs, textShndx, nil
}

// addPrograms creates one program for each function symbol of the executable
// section sec, in symbol table order, with def's program type. Outside .text
// a static function is rejected with ENOTSUP, because a program must be a
// global function.
func addPrograms(e *objelf.Object, sec objelf.Program, textShndx int, def secDef) ([]*BpfProgram, error) {
	var programs []*BpfProgram
	for _, sym := range e.Symbols {
		if int(sym.SectionIndex) != sec.SectionIndex || sym.Type != elf.STT_FUNC {
			continue
		}

		off, size := sym.Value, sym.Size
		if off+size > uint64(len(sec.Insns)) || off+size < off {
			return nil, fmt.Errorf("sec '%s': program at offset %d crosses section boundary", sec.Name, off)
		}
		if sec.SectionIndex != textShndx && sym.Bind == elf.STB_LOCAL {
			return nil, &Error{
				Op:    "bpf_object__open",
				Errno: unix.ENOTSUP,
				Log:   fmt.Sprintf("sec '%s': program '%s' is static and not supported", sec.Name, sym.Name),
			}
		}
		if size == 0 || size%bpfInsnSize != 0 || off%bpfInsnSize != 0 {
			return nil, fmt.Errorf("sec '%s': corrupted program '%s', offset %d, size %d", sec.Name, sym.Name, off, size)
		}

		programs = append(programs, newProgram(sec, sym, def))
	}
	return programs, nil
}

// newProgram builds the program for the function sym of section sec. A
// subprogram in .text has no SEC entry and keeps the zero program type.
func newProgram(sec objelf.Program, sym objelf.Symbol, def secDef) *BpfProgram {
	end := sym.Value + sym.Size
	prog := &BpfProgram{
		name:               sym.Name,
		progType:           def.progType,
		expectedAttachType: def.attachType,
		progFlags:          def.progFlags,
		usdt:               def.flags&secUSDT != 0,
		sectionName:        sec.Name,
		secIdx:             sec.SectionIndex,
		secInsnOff:         int(sym.Value / bpfInsnSize),
		secInsnCnt:         int(sym.Size / bpfInsnSize),
		symGlobal:          sym.Bind != elf.STB_LOCAL,
		insns:              sec.Insns[sym.Value:end:end],
		fd:                 -1,
	}
	if def.flags&secAttachBTF != 0 {
		prog.attachBTF = true
		prog.attachTarget = strings.TrimPrefix(sec.Name, def.prefix)
	}
	return prog
}

// cmpProgs orders programs by section index and then by first instruction,
// the order findProgBySecInsn searches.
func cmpProgs(a, b *BpfProgram) int {
	if a.secIdx != b.secIdx {
		return cmp.Compare(a.secIdx, b.secIdx)
	}
	return cmp.Compare(a.secInsnOff, b.secInsnOff)
}

// collectProgRelos gives each program of section sec the relocations of its
// own instructions, with offsets from the program's first instruction. A
// relocation outside every program, such as one in a weak function another
// object overrode, is dropped.
func collectProgRelos(e *objelf.Object, programs []*BpfProgram, sec objelf.Program) error {
	for i, rel := range sec.Relocs {
		if int(rel.SymbolIndex) >= len(e.Symbols) {
			return fmt.Errorf("sec '%s': symbol #%d not found for relo #%d", sec.Name, rel.SymbolIndex, i)
		}
		sym := e.Symbols[rel.SymbolIndex]
		if int(sym.SectionIndex) >= len(e.Sections) {
			return fmt.Errorf("sec '%s': corrupted symbol #%d pointing to invalid section #%d for relo #%d",
				sec.Name, rel.SymbolIndex, sym.SectionIndex, i)
		}
		if rel.Offset%bpfInsnSize != 0 || rel.Offset >= uint64(len(sec.Insns)) {
			return fmt.Errorf("sec '%s': invalid offset 0x%x for relo #%d", sec.Name, rel.Offset, i)
		}

		prog := findProgBySecInsn(programs, sec.SectionIndex, int(rel.Offset/bpfInsnSize))
		if prog == nil {
			continue
		}
		rel.Offset -= uint64(prog.secInsnOff * bpfInsnSize)
		prog.relocs = append(prog.relocs, rel)
	}
	return nil
}

// findProgBySecInsn returns the program of section secIdx that contains
// instruction insnIdx of the section, or nil. programs must be sorted with
// cmpProgs.
func findProgBySecInsn(programs []*BpfProgram, secIdx, insnIdx int) *BpfProgram {
	if len(programs) == 0 {
		return nil
	}

	l, r := 0, len(programs)-1
	for l < r {
		m := l + (r-l+1)/2
		p := programs[m]
		if p.secIdx < secIdx || (p.secIdx == secIdx && p.secInsnOff <= insnIdx) {
			l = m
		} else {
			r = m - 1
		}
	}

	if p := programs[l]; p.secIdx == secIdx && progContainsInsn(p, insnIdx) {
		return p
	}
	return nil
}

// progContainsInsn reports whether section instruction insnIdx is inside p.
func progContainsInsn(p *BpfProgram, insnIdx int) bool {
	return insnIdx >= p.secInsnOff && insnIdx < p.secInsnOff+p.secInsnCnt
}

// progIsSubprog reports whether p is a subprogram: a function in .text that
// is only loaded as part of the programs that call it.
func progIsSubprog(obj *BpfObject, p *BpfProgram) bool {
	return p.secIdx == obj.textShndx
}

// symIsSubprog reports whether a relocation against sym refers to a .text
// function: a static one through the section symbol, or a global or weak one
// through its own symbol.
func symIsSubprog(sym objelf.Symbol, textShndx int) bool {
	if int(sym.SectionIndex) != textShndx {
		return false
	}
	if sym.Bind == elf.STB_LOCAL && sym.Type == elf.STT_SECTION {
		return true
	}
	return (sym.Bind == elf.STB_GLOBAL || sym.Bind == elf.STB_WEAK) && sym.Type == elf.STT_FUNC
}
