// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/linker.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: linker_load_obj_file, add_src_sec, is_dwarf_sec_name, is_ignored_sec, linker_sanity_check_elf, linker_sanity_check_elf_symtab, linker_sanity_check_elf_relos, linker_sanity_check_btf, linker_sanity_check_btf_ext, check_btf_type_id, check_btf_str_off, find_src_sec_by_name, find_sym_by_name, linker_fixup_btf, btf_is_non_static, find_glob_sym_btf

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math/bits"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// ELF record sizes and section names the linker checks.
const (
	elfSymSize     = 24
	elfRelSize     = 16
	bpfInsnSize    = 8
	btfSecName     = ".BTF"
	btfExtSecName  = ".BTF.ext"
	btfExternSec   = ".extern"
	jumptablesSec  = ".jumptables"
	dwarfSecPrefix = ".debug_"
	relSecPrefix   = ".rel"
)

// linkerInput is one input object being added. secs[i] describes ELF
// section i, and the ephemeral sections of the DATASECs that have no ELF
// section, such as .kconfig and .ksyms, follow the ELF ones.
type linkerInput struct {
	name      string
	elf       *objelf.Object
	secs      []linkerInputSec
	symtab    int
	btfIdx    int
	btfExtIdx int
	btf       *btf.Spec
	btfExt    *btf.ExtRaw

	// symMap maps an input symbol index to its output index. Symbols in
	// skipped sections map to 0.
	symMap []uint32
	// btfTypeMap maps an input BTF type ID to its output ID. Skipped VARs
	// and FUNCs and every DATASEC map to 0.
	btfTypeMap []uint32
}

// linkerInputSec records how an input section reaches the output. An
// ephemeral section stands for a DATASEC of externs the loader resolves and
// has no ELF section or contents. dst is the position of the output section,
// or 0 when the section has none, and dstOff is the offset of the section's
// contents inside it. btfTypeID is the section's DATASEC, or 0.
type linkerInputSec struct {
	name      string
	skipped   bool
	ephemeral bool
	dst       int
	dstOff    uint64
	btfTypeID uint32
}

// linkerLoadObj parses data as a relocatable BPF object, classifies its
// sections, validates it and fixes its BTF DATASEC sizes and offsets.
func linkerLoadObj(name string, data []byte) (*linkerInput, error) {
	e, err := objelf.OpenBytes(data)
	if err != nil {
		return nil, linkerErrorf(unix.EINVAL, "failed to parse ELF file '%s': %v", name, err)
	}
	if e.ByteOrder != binary.LittleEndian {
		return nil, linkerErrorf(unix.EOPNOTSUPP, "big-endian ELF file %s is not supported yet", name)
	}
	if e.Type != elf.ET_REL || e.Machine != elf.EM_BPF || e.Class != elf.ELFCLASS64 {
		return nil, linkerErrorf(unix.EOPNOTSUPP, "unsupported kind of ELF file %s", name)
	}

	in := &linkerInput{name: name, elf: e, secs: make([]linkerInputSec, len(e.Sections))}
	for i := range e.Sections {
		in.secs[i].name = e.Sections[i].Name
	}
	if err := in.classifySections(); err != nil {
		return nil, err
	}
	if err := in.sanityCheckELF(); err != nil {
		return nil, err
	}
	if err := in.parseBTF(); err != nil {
		return nil, err
	}
	if err := in.fixupBTF(); err != nil {
		return nil, err
	}
	return in, nil
}

// classifySections marks the sections the output does not carry and finds
// the symbol table. .BTF and .BTF.ext are skipped here and emitted again when
// the output is finalized.
func (in *linkerInput) classifySections() error {
	for i := 1; i < len(in.elf.Sections); i++ {
		s := &in.elf.Sections[i]
		if isIgnoredSec(s) {
			in.secs[i].skipped = true
			continue
		}

		switch s.Type {
		case elf.SHT_SYMTAB:
			if in.symtab != 0 {
				return linkerErrorf(unix.EOPNOTSUPP, "multiple SYMTAB sections found, not supported")
			}
			in.symtab = i
		case elf.SHT_PROGBITS:
			switch s.Name {
			case btfSecName:
				in.btfIdx = i
				in.secs[i].skipped = true
			case btfExtSecName:
				in.btfExtIdx = i
				in.secs[i].skipped = true
			}
		case elf.SHT_NOBITS, elf.SHT_REL:
		default:
			return linkerErrorf(unix.EINVAL, "unrecognized section #%d (%s) in %s", i, s.Name, in.name)
		}
	}
	return nil
}

func isDwarfSecName(name string) bool {
	return strings.HasPrefix(name, dwarfSecPrefix)
}

// isIgnoredSec reports whether a section never reaches the output: string
// tables, the LLVM address-significance table, an empty .text, DWARF and its
// relocations, and the .BTF and .BTF.ext relocations.
func isIgnoredSec(s *objelf.Section) bool {
	switch {
	case s.Type == elf.SHT_STRTAB, s.Type == objelf.SHT_LLVM_ADDRSIG:
		return true
	case s.Type == elf.SHT_PROGBITS && s.Size == 0 && s.Name == ".text":
		return true
	case isDwarfSecName(s.Name):
		return true
	}

	target, ok := strings.CutPrefix(s.Name, relSecPrefix)
	if !ok {
		return false
	}
	return isDwarfSecName(target) || target == btfSecName || target == btfExtSecName
}

// sanityCheckELF validates every section that is not DWARF, including the
// skipped ones, the way libbpf does before it links anything.
func (in *linkerInput) sanityCheckELF() error {
	if in.symtab == 0 {
		return linkerErrorf(unix.EINVAL, "ELF is missing SYMTAB section in %s", in.name)
	}

	for i := 1; i < len(in.elf.Sections); i++ {
		s := &in.elf.Sections[i]
		if s.Name == "" {
			return linkerErrorf(unix.EINVAL, "ELF section #%d has empty name in %s", i, in.name)
		}
		if isDwarfSecName(s.Name) {
			continue
		}
		if s.Addralign != 0 && bits.OnesCount64(s.Addralign) != 1 {
			return linkerErrorf(unix.EINVAL, "ELF section #%d alignment %d is non pow-of-2 alignment in %s", i, s.Addralign, in.name)
		}

		var err error
		switch s.Type {
		case elf.SHT_SYMTAB:
			err = in.sanityCheckSymtab(i)
		case elf.SHT_REL:
			err = in.sanityCheckRelos(i)
		case elf.SHT_PROGBITS:
			if s.Flags&elf.SHF_EXECINSTR != 0 && s.Size%bpfInsnSize != 0 {
				err = linkerErrorf(unix.EINVAL, "ELF section #%d has unexpected size alignment %d in %s", i, s.Size, in.name)
			}
		case elf.SHT_STRTAB, elf.SHT_NOBITS, objelf.SHT_LLVM_ADDRSIG:
		default:
			err = linkerErrorf(unix.EINVAL, "ELF section #%d (%s) has unrecognized type %d in %s", i, s.Name, s.Type, in.name)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// sanityCheckSymtab validates the symbol table geometry, its string table and
// every symbol's binding, visibility and section.
func (in *linkerInput) sanityCheckSymtab(idx int) error {
	s := &in.elf.Sections[idx]
	if s.Entsize != elfSymSize || s.Size%elfSymSize != 0 {
		return linkerErrorf(unix.EINVAL, "ELF SYMTAB section #%d has invalid geometry in %s", idx, in.name)
	}
	if s.Link == 0 || int(s.Link) >= len(in.elf.Sections) || in.elf.Sections[s.Link].Type != elf.SHT_STRTAB {
		return linkerErrorf(unix.EINVAL, "ELF SYMTAB section #%d points to invalid STRTAB section #%d in %s", idx, s.Link, in.name)
	}
	if len(s.Data) < elfSymSize || !bytes.Equal(s.Data[:elfSymSize], make([]byte, elfSymSize)) {
		return linkerErrorf(unix.EINVAL, "ELF sym #0 is invalid in %s", in.name)
	}
	if uint64(len(in.elf.Symbols)) != s.Size/elfSymSize {
		return linkerErrorf(unix.EINVAL, "ELF SYMTAB section #%d has %d entries, read %d in %s", idx, s.Size/elfSymSize, len(in.elf.Symbols), in.name)
	}

	for i := 1; i < len(in.elf.Symbols); i++ {
		if err := in.sanityCheckSym(i); err != nil {
			return err
		}
	}
	return nil
}

func (in *linkerInput) sanityCheckSym(i int) error {
	sym := &in.elf.Symbols[i]
	vis := elf.SymVis(sym.Other & 0x3)

	if sym.Bind != elf.STB_LOCAL && sym.Bind != elf.STB_GLOBAL && sym.Bind != elf.STB_WEAK {
		return linkerErrorf(unix.EINVAL, "ELF sym #%d has unsupported symbol binding %d", i, sym.Bind)
	}
	if vis != elf.STV_DEFAULT && vis != elf.STV_HIDDEN {
		return linkerErrorf(unix.EINVAL, "ELF sym #%d has unsupported symbol visibility %d", i, vis)
	}
	if sym.SectionIndex == elf.SHN_UNDEF {
		if sym.Type != elf.STT_NOTYPE || sym.Bind == elf.STB_LOCAL || sym.Value != 0 || sym.Size != 0 {
			return linkerErrorf(unix.EINVAL, "ELF sym #%d is invalid extern symbol in %s", i, in.name)
		}
		return nil
	}
	if sym.SectionIndex < elf.SHN_LORESERVE && int(sym.SectionIndex) >= len(in.elf.Sections) {
		return linkerErrorf(unix.EINVAL, "ELF sym #%d points to missing section #%d in %s", i, sym.SectionIndex, in.name)
	}
	if sym.Type == elf.STT_SECTION && sym.Value != 0 {
		return linkerErrorf(unix.EINVAL, "ELF sym #%d is a section symbol with a nonzero value in %s", i, in.name)
	}
	return nil
}

// sanityCheckRelos validates a relocation section's links and name, and,
// unless its target is skipped, every relocation type, symbol and offset.
func (in *linkerInput) sanityCheckRelos(idx int) error {
	s := &in.elf.Sections[idx]
	if s.Entsize != elfRelSize || s.Size%elfRelSize != 0 {
		return linkerErrorf(unix.EINVAL, "ELF relo section #%d has invalid geometry in %s", idx, in.name)
	}
	if int(s.Link) != in.symtab {
		return linkerErrorf(unix.EINVAL, "ELF relo section #%d points to invalid SYMTAB section #%d in %s", idx, s.Link, in.name)
	}
	if s.Info == 0 || int(s.Info) >= len(in.elf.Sections) {
		return linkerErrorf(unix.EINVAL, "ELF relo section #%d points to missing section #%d in %s", idx, s.Info, in.name)
	}

	target := &in.elf.Sections[s.Info]
	if s.Name != relSecPrefix+target.Name {
		return linkerErrorf(unix.EINVAL, "ELF relo section #%d name has invalid name in %s", idx, in.name)
	}
	if in.secs[s.Info].skipped {
		return nil
	}
	if target.Type != elf.SHT_PROGBITS && target.Type != elf.SHT_NOBITS {
		return linkerErrorf(unix.EINVAL, "ELF relo section #%d points to invalid section #%d in %s", idx, s.Info, in.name)
	}

	symCnt := in.elf.Sections[in.symtab].Size / elfSymSize
	for j, r := range decodeRelos(s.Data) {
		switch r.typ {
		case objelf.R_BPF_64_64, objelf.R_BPF_64_32, objelf.R_BPF_64_ABS64, objelf.R_BPF_64_ABS32:
		default:
			return linkerErrorf(unix.EINVAL, "ELF relo #%d in section #%d has unexpected type %d in %s", j, idx, r.typ, in.name)
		}
		if r.sym == 0 || uint64(r.sym) >= symCnt {
			return linkerErrorf(unix.EINVAL, "ELF relo #%d in section #%d points to invalid symbol #%d in %s", j, idx, r.sym, in.name)
		}
		if target.Flags&elf.SHF_EXECINSTR != 0 && r.offset%bpfInsnSize != 0 {
			return linkerErrorf(unix.EINVAL, "ELF relo #%d in section #%d points to missing symbol #%d in %s", j, idx, r.sym, in.name)
		}
	}
	return nil
}

// elfRel is one decoded Elf64_Rel entry.
type elfRel struct {
	offset uint64
	sym    uint32
	typ    uint32
}

// decodeRelos decodes the little-endian Elf64_Rel entries of a relocation
// section. A trailing partial entry is ignored; the sanity check rejects it.
func decodeRelos(data []byte) []elfRel {
	relos := make([]elfRel, 0, len(data)/elfRelSize)
	for off := 0; off+elfRelSize <= len(data); off += elfRelSize {
		info := binary.LittleEndian.Uint64(data[off+8:])
		relos = append(relos, elfRel{
			offset: binary.LittleEndian.Uint64(data[off:]),
			sym:    uint32(info >> 32),
			typ:    uint32(info),
		})
	}
	return relos
}

// parseBTF parses and checks the .BTF and .BTF.ext sections. A .BTF.ext
// without .BTF is invalid.
func (in *linkerInput) parseBTF() error {
	if in.btfIdx != 0 {
		spec, err := btf.Parse(in.elf.Sections[in.btfIdx].Data, in.elf.ByteOrder)
		if err != nil {
			return linkerErrorf(unix.EINVAL, "failed to parse .BTF from %s: %v", in.name, err)
		}
		in.btf = spec
		if err := in.sanityCheckBTF(); err != nil {
			return err
		}
	}
	if in.btfExtIdx == 0 {
		return nil
	}
	if in.btf == nil {
		return linkerErrorf(unix.EINVAL, ".BTF.ext without .BTF in %s", in.name)
	}

	ext, err := btf.ParseExtRaw(in.elf.Sections[in.btfExtIdx].Data, in.btf, in.elf.ByteOrder)
	if err != nil {
		return linkerErrorf(unix.EINVAL, "failed to parse .BTF.ext from '%s': %v", in.name, err)
	}
	in.btfExt = ext
	return in.sanityCheckBTFExt()
}

// sanityCheckBTF rejects a type that refers to a type ID past the end of the
// table. Parse already checked the string offsets.
func (in *linkerInput) sanityCheckBTF() error {
	n := uint32(len(in.btf.Types))
	for i := 1; i < len(in.btf.Types); i++ {
		err := in.btf.Types[i].VisitTypeIDs(func(id *uint32) error {
			if *id >= n {
				return linkerErrorf(unix.EINVAL, "BTF type #%d in %s refers to missing type #%d", i, in.name, *id)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Field offsets inside the .BTF.ext records: every record starts with the
// instruction offset; function and CO-RE records then hold a type ID, line
// records the file and line string offsets, and CO-RE records the access
// string offset after the type ID.
const (
	extRecTypeID    = 4
	extRecFileName  = 4
	extRecLine      = 8
	extRecAccessStr = 8
)

// sanityCheckBTFExt checks that every .BTF.ext type ID is in the BTF type
// table and every string offset resolves.
func (in *linkerInput) sanityCheckBTFExt() error {
	n := uint32(len(in.btf.Types))
	checkType := func(rec []byte, off int) error {
		if id := binary.LittleEndian.Uint32(rec[off:]); id >= n {
			return linkerErrorf(unix.EINVAL, ".BTF.ext in %s refers to missing type #%d", in.name, id)
		}
		return nil
	}
	checkStr := func(rec []byte, off int) error {
		if _, err := in.btf.String(binary.LittleEndian.Uint32(rec[off:])); err != nil {
			return linkerErrorf(unix.EINVAL, ".BTF.ext in %s: %v", in.name, err)
		}
		return nil
	}

	err := forEachExtRecord(in.btfExt.FuncInfo, func(rec []byte) error { return checkType(rec, extRecTypeID) })
	if err == nil {
		err = forEachExtRecord(in.btfExt.LineInfo, func(rec []byte) error {
			if err := checkStr(rec, extRecFileName); err != nil {
				return err
			}
			return checkStr(rec, extRecLine)
		})
	}
	if err == nil {
		err = forEachExtRecord(in.btfExt.CoreRelo, func(rec []byte) error {
			if err := checkType(rec, extRecTypeID); err != nil {
				return err
			}
			return checkStr(rec, extRecAccessStr)
		})
	}
	return err
}

// forEachExtRecord calls fn with each record of each block.
func forEachExtRecord(blocks []btf.ExtRecords, fn func(rec []byte) error) error {
	for _, b := range blocks {
		for off := 0; off+b.RecSize <= len(b.Records); off += b.RecSize {
			if err := fn(b.Records[off : off+b.RecSize]); err != nil {
				return err
			}
		}
	}
	return nil
}

// findSecByName returns the index of the first section named name, ELF or
// ephemeral, or 0.
func (in *linkerInput) findSecByName(name string) int {
	for i := 1; i < len(in.secs); i++ {
		if in.secs[i].name == name {
			return i
		}
	}
	return 0
}

// addEphemeralSec adds an ephemeral section named name and returns its index.
func (in *linkerInput) addEphemeralSec(name string) int {
	in.secs = append(in.secs, linkerInputSec{name: name, ephemeral: true})
	return len(in.secs) - 1
}

// elfIndex returns the ELF index of section i, or 0, SHN_UNDEF, for an
// ephemeral section.
func (in *linkerInput) elfIndex(i int) int {
	if in.secs[i].ephemeral {
		return 0
	}
	return i
}

// findSymByName returns the first symbol of type typ named name in section
// secIdx, or nil.
func (in *linkerInput) findSymByName(secIdx int, typ elf.SymType, name string) *objelf.Symbol {
	for i := range in.elf.Symbols {
		sym := &in.elf.Symbols[i]
		if int(sym.SectionIndex) == secIdx && sym.Type == typ && sym.Name == name {
			return sym
		}
	}
	return nil
}

// fixupBTF sets each DATASEC size to its ELF section size and each allocated
// global variable's offset to its ELF symbol value, and records each
// section's DATASEC. .extern is left alone: its externs are resolved by
// symbol, and the DATASEC itself is not carried to the output. Any other
// DATASEC without an ELF section, such as .kconfig or .ksyms, holds externs
// the loader resolves; it gets an ephemeral section, keeps its size, and
// reaches the output with its externs still undefined.
func (in *linkerInput) fixupBTF() error {
	if in.btf == nil {
		return nil
	}

	for id := 1; id < len(in.btf.Types); id++ {
		t := &in.btf.Types[id]
		if t.Kind != btf.KindDatasec {
			continue
		}

		secIdx := in.findSecByName(t.Name)
		if secIdx == 0 {
			if t.Name == btfExternSec {
				continue
			}
			secIdx = in.addEphemeralSec(t.Name)
		} else if !in.secs[secIdx].ephemeral {
			if err := in.btf.SetDatasecSize(t.ID, uint32(in.elf.Sections[secIdx].Size)); err != nil {
				return linkerErrorf(unix.EINVAL, "%v", err)
			}
		}

		in.secs[secIdx].btfTypeID = t.ID
		if err := in.fixupDatasecVars(t, in.elfIndex(secIdx)); err != nil {
			return err
		}
	}
	return nil
}

// fixupDatasecVars writes the offsets of the allocated global variables of
// the DATASEC t, whose ELF section is secIdx. An ephemeral section's index is
// SHN_UNDEF, which defines no variable, so an allocated variable in its
// DATASEC is not found.
func (in *linkerInput) fixupDatasecVars(t *btf.Type, secIdx int) error {
	for j, vi := range t.DataSec {
		vt, err := in.btf.TypeByID(vi.Type)
		if err != nil {
			return linkerErrorf(unix.EINVAL, "%v", err)
		}
		if vt.Kind != btf.KindVar || vt.Var == nil || vt.Var.Linkage != btf.VarGlobalAllocated {
			continue
		}

		sym := in.findSymByName(secIdx, elf.STT_OBJECT, vt.Name)
		if sym == nil {
			return linkerErrorf(unix.ENOENT, "failed to find symbol for variable '%s' in section '%s'", vt.Name, t.Name)
		}
		if err := in.btf.SetDatasecVarOffset(t.ID, j, uint32(sym.Value)); err != nil {
			return linkerErrorf(unix.EINVAL, "%v", err)
		}
	}
	return nil
}

// btfIsNonStatic reports whether t is a VAR or FUNC with global or extern
// linkage. A FUNC's linkage is its vlen.
func btfIsNonStatic(t *btf.Type) bool {
	switch t.Kind {
	case btf.KindVar:
		return t.Var != nil && t.Var.Linkage != btf.VarStatic
	case btf.KindFunc:
		return t.Vlen != btfFuncStatic
	}
	return false
}

// btfIsStatic reports whether t is a VAR or FUNC with static linkage.
func btfIsStatic(t *btf.Type) bool {
	switch t.Kind {
	case btf.KindVar:
		return t.Var != nil && t.Var.Linkage == btf.VarStatic
	case btf.KindFunc:
		return t.Vlen == btfFuncStatic
	}
	return false
}

// BTF_FUNC_STATIC from linux/btf.h.
const btfFuncStatic = 0

// findGlobSymBTF returns the DATASEC and the VAR or FUNC type that describe
// the global or extern symbol name. secID is 0 for a free-floating FUNC or
// extern. It fails when the object has no BTF, when two types match, or when
// none does.
func (in *linkerInput) findGlobSymBTF(name string) (secID, btfID uint32, err error) {
	if in.btf == nil {
		return 0, 0, linkerErrorf(unix.EINVAL, "failed to find BTF info for object '%s'", in.name)
	}

	for id := 1; id < len(in.btf.Types); id++ {
		t := &in.btf.Types[id]
		if btfIsNonStatic(t) {
			if t.Name == name {
				btfID = uint32(id)
			}
			continue
		}
		if t.Kind != btf.KindDatasec {
			continue
		}

		for _, vi := range t.DataSec {
			vt, err := in.btf.TypeByID(vi.Type)
			if err != nil || vt.Name != name || btfIsStatic(vt) {
				continue
			}
			if btfID != 0 && btfID != vi.Type {
				return 0, 0, linkerErrorf(unix.EINVAL, "global/extern '%s' BTF is ambiguous: both types #%d and #%d match", name, btfID, vi.Type)
			}
			return uint32(id), vi.Type, nil
		}
	}

	if btfID != 0 {
		return 0, btfID, nil
	}
	return 0, 0, linkerErrorf(unix.ENOENT, "failed to find BTF info for global/extern symbol '%s'", name)
}
