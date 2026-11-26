// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/linker.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: add_dst_sec, init_sec, find_dst_sec_by_name, secs_match, sec_content_is_same, extend_sec, is_data_sec, is_relo_sec, linker_append_sec_data, linker_append_elf_relos

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// bpfJmpCall is the opcode of a BPF call instruction, BPF_JMP | BPF_CALL.
const bpfJmpCall = 0x85

// linkerSec is one output section: its header, its contents, its section
// symbol, its DATASEC variables and its .BTF.ext records. data holds the
// bytes of a code, data or relocation section; size is the section size for
// every type, including SHT_NOBITS. info is the relocated section's ELF index
// for a relocation section.
type linkerSec struct {
	name      string
	typ       elf.SectionType
	flags     elf.SectionFlag
	addralign uint64
	entsize   uint64
	info      uint32
	data      []byte
	size      uint64
	secSymIdx uint32

	hasBTF   bool
	vars     []btf.VarSecInfo
	funcInfo linkerExtRecs
	lineInfo linkerExtRecs
	coreRelo linkerExtRecs
}

// linkerExtRecs is a section's .BTF.ext records of one kind. recSize is 0
// until the first record arrives.
type linkerExtRecs struct {
	recSize int
	records []byte
}

func (r *linkerExtRecs) count() int {
	if r.recSize == 0 {
		return 0
	}
	return len(r.records) / r.recSize
}

// newLinkerSec starts an empty output section with the header of src.
func newLinkerSec(src *objelf.Section) *linkerSec {
	return &linkerSec{
		name:      src.Name,
		typ:       src.Type,
		flags:     src.Flags,
		addralign: src.Addralign,
		entsize:   src.Entsize,
	}
}

// addSec appends s and returns its ELF index.
func (out *linkerOutput) addSec(s *linkerSec) int {
	out.secs = append(out.secs, s)
	return len(out.secs)
}

// sec returns the output section with ELF index idx.
func (out *linkerOutput) sec(idx int) *linkerSec {
	return out.secs[idx-1]
}

// findSec returns the ELF index of the output section named name, or 0.
func (out *linkerOutput) findSec(name string) int {
	for i, s := range out.secs {
		if s.name == name {
			return i + 1
		}
	}
	return 0
}

// mismatch names the header field that keeps src from merging into s, or
// returns "" when the two sections are compatible. The alignment may differ:
// the merged section takes the larger one.
func (s *linkerSec) mismatch(src *objelf.Section) string {
	switch {
	case s.typ != src.Type:
		return "type"
	case s.flags != src.Flags:
		return "flags"
	case s.entsize != src.Entsize:
		return "entsize"
	}
	return ""
}

// extend appends the contents of src at the larger of the two alignments,
// padding with zeros, and returns the offset src landed at. A SHT_NOBITS
// section only grows.
func (s *linkerSec) extend(src *objelf.Section) uint64 {
	align := max(s.addralign, 1, src.Addralign)
	off := (s.size + align - 1) / align * align

	if src.Type != elf.SHT_NOBITS {
		s.data = append(s.data, make([]byte, off-uint64(len(s.data)))...)
		s.data = append(s.data, src.Data...)
	}
	s.size = off + src.Size
	s.addralign = align
	return off
}

// output returns the section for the ELF writer. Relocation entries are
// decoded back from the bytes they were merged as.
func (s *linkerSec) output() objelf.OutputSection {
	o := objelf.OutputSection{
		Name:      s.name,
		Type:      s.typ,
		Flags:     s.flags,
		Addralign: s.addralign,
		Entsize:   s.entsize,
		Info:      s.info,
	}
	switch s.typ {
	case elf.SHT_PROGBITS:
		o.Data = s.data
	case elf.SHT_NOBITS:
		o.Size = s.size
	case elf.SHT_REL:
		for _, r := range decodeRelos(s.data) {
			o.Relocs = append(o.Relocs, objelf.OutputReloc{Offset: r.offset, Symbol: r.sym, Type: r.typ})
		}
	}
	return o
}

// appendSecData merges the code and data sections of in into the output
// sections of the same name. license and version are kept once, and their
// contents must be identical in every object.
func (out *linkerOutput) appendSecData(in *linkerInput) error {
	for i := 1; i < len(in.elf.Sections); i++ {
		s := &in.elf.Sections[i]
		src := &in.secs[i]
		if src.skipped || (s.Type != elf.SHT_PROGBITS && s.Type != elf.SHT_NOBITS) {
			continue
		}

		idx := out.findSec(s.Name)
		if idx == 0 {
			idx = out.addSec(newLinkerSec(s))
		} else {
			if err := out.checkMerge(idx, s); err != nil {
				return err
			}
			if s.Name == "license" || s.Name == "version" {
				if !bytes.Equal(out.sec(idx).data, s.Data) {
					return linkerErrorf(unix.EINVAL, "non-identical contents of section '%s' are not supported", s.Name)
				}
				src.skipped = true
				src.dst = idx
				continue
			}
		}

		src.dst = idx
		src.dstOff = out.sec(idx).extend(s)
	}
	return nil
}

// checkMerge rejects merging s into the output section idx when their types,
// flags or entry sizes differ.
func (out *linkerOutput) checkMerge(idx int, s *objelf.Section) error {
	if what := out.sec(idx).mismatch(s); what != "" {
		return linkerErrorf(unix.EINVAL, "ELF sections %s are incompatible: %s mismatch", s.Name, what)
	}
	return nil
}

// appendRelos merges the relocation sections whose target is kept into the
// output relocation sections of the same name, then rewrites the copied
// entries for the output: the offset moves with the target section and the
// symbol becomes its output index.
func (out *linkerOutput) appendRelos(in *linkerInput) error {
	for i := 1; i < len(in.elf.Sections); i++ {
		s := &in.elf.Sections[i]
		src := &in.secs[i]
		if src.skipped || s.Type != elf.SHT_REL || in.secs[s.Info].skipped {
			continue
		}

		idx := out.findSec(s.Name)
		if idx == 0 {
			idx = out.addSec(newLinkerSec(s))
		} else if err := out.checkMerge(idx, s); err != nil {
			return err
		}

		dst := out.sec(idx)
		dst.info = uint32(in.secs[s.Info].dst)
		src.dst = idx
		src.dstOff = dst.extend(s)
		if err := out.rewriteRelos(in, s, dst.data[src.dstOff:][:s.Size]); err != nil {
			return err
		}
	}
	return nil
}

// rewriteRelos rewrites the entries of relocation section s after they were
// copied to entries.
func (out *linkerOutput) rewriteRelos(in *linkerInput, s *objelf.Section, entries []byte) error {
	linked := &in.secs[s.Info]
	target := out.sec(linked.dst)
	targetExec := in.elf.Sections[s.Info].Flags&elf.SHF_EXECINSTR != 0
	le := binary.LittleEndian

	for off := 0; off+elfRelSize <= len(entries); off += elfRelSize {
		entry := entries[off:]
		rOffset := le.Uint64(entry) + linked.dstOff
		info := le.Uint64(entry[8:])
		symIdx, typ := uint32(info>>32), uint32(info)

		le.PutUint64(entry, rOffset)
		le.PutUint64(entry[8:], uint64(in.symMap[symIdx])<<32|uint64(typ))

		sym := &in.elf.Symbols[symIdx]
		if sym.Type != elf.STT_SECTION {
			continue
		}
		if err := fixupSectionReloc(in, target, rOffset, targetExec, sym, typ); err != nil {
			return err
		}
	}
	return nil
}

// fixupSectionReloc handles a relocation against a section symbol. A section
// symbol stands for offset 0 of its section, so after merging the reference
// must also move by the offset the referenced section landed at: in code,
// the instruction immediate grows by that offset, counted in instructions
// for a call; in data, only an R_BPF_64_ABS64 pointer to code is allowed and
// the stored pointer grows by the offset.
func fixupSectionReloc(in *linkerInput, target *linkerSec, off uint64, targetExec bool, sym *objelf.Symbol, typ uint32) error {
	if int(sym.SectionIndex) >= len(in.secs) {
		return linkerErrorf(unix.EINVAL, "relocation against missing section #%d", sym.SectionIndex)
	}
	refOff := in.secs[sym.SectionIndex].dstOff
	refExec := in.elf.Sections[sym.SectionIndex].Flags&elf.SHF_EXECINSTR != 0
	le := binary.LittleEndian

	switch {
	case targetExec:
		if off+bpfInsnSize > uint64(len(target.data)) {
			return linkerErrorf(unix.EINVAL, "relocation at %#x is outside section %s", off, target.name)
		}
		insn := target.data[off:]
		delta := int32(refOff)
		if insn[0] == bpfJmpCall {
			delta = int32(refOff / bpfInsnSize)
		}
		le.PutUint32(insn[4:], uint32(int32(le.Uint32(insn[4:]))+delta))
	case typ == objelf.R_BPF_64_ABS64 && refExec:
		if off+8 > uint64(len(target.data)) {
			return linkerErrorf(unix.EINVAL, "relocation at %#x is outside section %s", off, target.name)
		}
		le.PutUint64(target.data[off:], le.Uint64(target.data[off:])+refOff)
	default:
		return linkerErrorf(unix.EINVAL, "relocation against STT_SECTION in non-exec section is not supported")
	}
	return nil
}
