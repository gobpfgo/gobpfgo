// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/linker.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: get_sym_by_idx, find_glob_sym, add_glob_sym, glob_sym_btf_matches, map_defs_match, glob_map_defs_match, glob_syms_match, sym_update_bind, sym_update_type, sym_update_visibility, linker_append_elf_syms, linker_append_elf_sym

package libbpf

import (
	"debug/elf"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// stVisibilityMask selects the visibility bits of st_other.
const stVisibilityMask = 0x3

// linkerGlobSym is a global or weak symbol of the output, known by name
// across the inputs. Externs never get here: they are rejected until extern
// resolution is ported.
type linkerGlobSym struct {
	name   string
	symIdx uint32
	// secIdx is the output section ELF index, or 0 for a symbol outside a
	// section.
	secIdx int
	// btfID is the output BTF VAR or FUNC, or 0 until the BTF of the object
	// that defined the symbol is merged.
	btfID uint32
	// underlyingBtfID is the type the VAR or FUNC refers to. As in libbpf,
	// a negative value is an input type ID still to be remapped, and 0 asks
	// the next BTF merge to point the VAR or FUNC at the type of a new
	// strong definition.
	underlyingBtfID int64
	// varIdx is the symbol's entry among its section's DATASEC variables,
	// or -1.
	varIdx int
	isWeak bool
}

// findGlobSym returns the global symbol named name, or nil.
func (out *linkerOutput) findGlobSym(name string) *linkerGlobSym {
	i, ok := out.globIdx[name]
	if !ok {
		return nil
	}
	return &out.globSyms[i]
}

// addGlobSym records g. The first symbol of a name keeps the index.
func (out *linkerOutput) addGlobSym(g linkerGlobSym) {
	if _, ok := out.globIdx[g.name]; !ok {
		out.globIdx[g.name] = len(out.globSyms)
	}
	out.globSyms = append(out.globSyms, g)
}

// appendSyms appends or resolves the input symbols in order and records
// their output indices.
func (out *linkerOutput) appendSyms(in *linkerInput) error {
	in.symMap = make([]uint32, len(in.elf.Symbols))
	for i := 1; i < len(in.elf.Symbols); i++ {
		if err := out.appendSym(in, i); err != nil {
			return err
		}
	}
	return nil
}

// appendSym adds input symbol i to the output. A symbol in a skipped section
// is dropped, and each output section keeps one STT_SECTION symbol. A local
// symbol is always added. A global or weak symbol needs a BTF description,
// except in .jumptables, and is resolved against an earlier symbol of the
// same name.
func (out *linkerOutput) appendSym(in *linkerInput, i int) error {
	sym := &in.elf.Symbols[i]
	if sym.SectionIndex == elf.SHN_UNDEF {
		if in.btf == nil {
			return linkerErrorf(unix.ENOTSUP, "externs without BTF info are not supported")
		}
		return linkerErrorf(unix.EOPNOTSUPP, "extern symbol '%s' in %s: extern resolution is not supported yet", sym.Name, in.name)
	}

	resolve := sym.Bind != elf.STB_LOCAL
	if sym.SectionIndex < elf.SHN_LORESERVE {
		src := &in.secs[sym.SectionIndex]
		if src.skipped {
			return nil
		}
		if sym.Type == elf.STT_SECTION && src.dst != 0 && out.sec(src.dst).secSymIdx != 0 {
			in.symMap[i] = out.sec(src.dst).secSymIdx
			return nil
		}
		if in.elf.Sections[sym.SectionIndex].Name == jumptablesSec {
			resolve = false
		}
	}

	if resolve {
		_, btfID, err := in.findGlobSymBTF(sym.Name)
		if err != nil {
			return err
		}
		if g := out.findGlobSym(sym.Name); g != nil {
			return out.resolveGlobSym(in, i, g, btfID)
		}
	}

	idx := out.addInputSym(in, i)
	if sym.Bind != elf.STB_LOCAL {
		out.addGlobSym(linkerGlobSym{
			name:   sym.Name,
			symIdx: idx,
			secIdx: outputSecIdx(in, sym),
			varIdx: -1,
			isWeak: sym.Bind == elf.STB_WEAK,
		})
	}
	return nil
}

// outputSecIdx returns the ELF index of the output section that holds an
// input symbol, or 0 for a symbol outside a section.
func outputSecIdx(in *linkerInput, sym *objelf.Symbol) int {
	if sym.SectionIndex == elf.SHN_UNDEF || sym.SectionIndex >= elf.SHN_LORESERVE {
		return 0
	}
	return in.secs[sym.SectionIndex].dst
}

// placeSym returns the output section index and value of an input symbol. A
// symbol in a section moves with the section's contents; a reserved index
// such as SHN_ABS is kept.
func placeSym(in *linkerInput, sym *objelf.Symbol) (elf.SectionIndex, uint64) {
	if sym.SectionIndex == elf.SHN_UNDEF || sym.SectionIndex >= elf.SHN_LORESERVE {
		return sym.SectionIndex, sym.Value
	}
	src := &in.secs[sym.SectionIndex]
	return elf.SectionIndex(src.dst), src.dstOff + sym.Value
}

// addInputSym appends input symbol i as a new output symbol and returns its
// index. A section symbol becomes its output section's symbol, at value 0.
func (out *linkerOutput) addInputSym(in *linkerInput, i int) uint32 {
	sym := &in.elf.Symbols[i]
	o := objelf.OutputSymbol{Name: sym.Name, Info: sym.Info, Other: sym.Other, Size: sym.Size}
	o.Section, o.Value = placeSym(in, sym)

	sectionSym := sym.Type == elf.STT_SECTION && o.Section != 0 && sym.SectionIndex < elf.SHN_LORESERVE
	if sectionSym {
		o.Value = 0
	}

	idx := out.addSym(o)
	in.symMap[i] = idx
	if sectionSym {
		out.sec(int(o.Section)).secSymIdx = idx
	}
	return idx
}

// resolveGlobSym merges input symbol i into the earlier global g of the same
// name. Two strong definitions conflict, and the two BTF types must match.
// A strong binding and a stricter visibility win. A strong definition then
// replaces a weak one, while a weak definition leaves g as it is.
func (out *linkerOutput) resolveGlobSym(in *linkerInput, i int, g *linkerGlobSym, btfID uint32) error {
	sym := &in.elf.Symbols[i]
	in.symMap[i] = g.symIdx

	if !g.isWeak && sym.Bind != elf.STB_WEAK {
		return linkerErrorf(unix.EINVAL, "conflicting non-weak symbol #%d (%s) definition in '%s'", i, sym.Name, in.name)
	}
	if err := out.globSymsMatch(in, g, sym.Name, btfID); err != nil {
		return err
	}

	dst := out.sym(g.symIdx)
	if sym.Bind == elf.STB_GLOBAL {
		dst.Info = elf.ST_INFO(elf.STB_GLOBAL, elf.ST_TYPE(dst.Info))
		g.isWeak = false
	}
	if vis := sym.Other & stVisibilityMask; vis > dst.Other&stVisibilityMask {
		dst.Other = dst.Other&^stVisibilityMask | vis
	}
	if sym.Bind == elf.STB_WEAK {
		return nil
	}

	dst.Info = elf.ST_INFO(elf.ST_BIND(dst.Info), sym.Type)
	dst.Section, dst.Value = placeSym(in, sym)
	dst.Size = sym.Size
	g.secIdx = outputSecIdx(in, sym)

	if err := out.btf.completeExternInfo(g.btfID, in.btf, btfID); err != nil {
		return err
	}
	g.underlyingBtfID = 0
	return nil
}

// globSymsMatch checks that input symbol name, described by btfID, can merge
// into g: both must have a BTF VAR or FUNC, map definitions in .maps must
// agree, and the other types must match exactly.
func (out *linkerOutput) globSymsMatch(in *linkerInput, g *linkerGlobSym, name string, btfID uint32) error {
	if g.btfID == 0 || btfID == 0 {
		return linkerErrorf(unix.EINVAL, "BTF info is missing for global symbol '%s'", name)
	}

	srcT := &in.btf.Types[btfID]
	if srcT.Kind != btf.KindVar && srcT.Kind != btf.KindFunc {
		return linkerErrorf(unix.EINVAL, "only extern variables and functions are supported, but got '%s' for '%s'", srcT.Kind, name)
	}
	if g.secIdx != 0 && out.sec(g.secIdx).name == mapsSecName {
		return globMapDefsMatch(name, out.btf.spec, g.btfID, in.btf, btfID)
	}
	return globSymBTFMatches(name, true, out.btf.spec, g.btfID, in.btf, btfID)
}

// mapsSecName is the ELF section of BTF-defined maps.
const mapsSecName = ".maps"

// globMapDefsMatch parses both map definitions and compares them. The
// definition of an earlier map must match the new one exactly.
func globMapDefsMatch(name string, dstSpec *btf.Spec, dstID uint32, srcSpec *btf.Spec, srcID uint32) error {
	src, err := linkerMapDef(srcSpec, srcID)
	if err != nil {
		return linkerErrorf(unix.EINVAL, "global '%s': invalid map definition: %v", name, err)
	}
	dst, err := linkerMapDef(dstSpec, dstID)
	if err != nil {
		return linkerErrorf(unix.EINVAL, "global '%s': invalid dst map definition: %v", name, err)
	}
	return mapDefsMatch(name, dstSpec, dst, srcSpec, src)
}

// linkerMapDef parses the map definition of the VAR id.
func linkerMapDef(spec *btf.Spec, id uint32) (*BpfMap, error) {
	v, err := spec.TypeByID(id)
	if err != nil {
		return nil, err
	}
	if v.Kind != btf.KindVar {
		return nil, linkerErrorf(unix.EINVAL, "invalid map definition type [%d]", id)
	}
	st, _ := skipModsAndTypedefs(spec, v.SizeOrType)
	if st == nil || st.Kind != btf.KindStruct {
		return nil, linkerErrorf(unix.EINVAL, "map definition [%d] is not a struct", id)
	}

	m := &BpfMap{}
	if err := fillMapDef(spec, st, m); err != nil {
		return nil, err
	}
	return m, nil
}

// mapDefsMatch compares the map type, key and value sizes and BTF types,
// max_entries and map_flags of two definitions. The parser does not read
// numa_node, pinning or inner maps, so they are not compared.
func mapDefsMatch(name string, mainSpec *btf.Spec, main *BpfMap, extraSpec *btf.Spec, extra *BpfMap) error {
	reason := ""
	switch {
	case main.mapType != extra.mapType:
		reason = "type"
	case main.keySize != extra.keySize:
		reason = "key_size"
	case (main.btfKeyTypeID != 0) != (extra.btfKeyTypeID != 0):
		reason = "key type"
	case main.btfKeyTypeID != 0 && globSymBTFMatches(name, true, mainSpec, main.btfKeyTypeID, extraSpec, extra.btfKeyTypeID) != nil:
		reason = "key type"
	case main.valueSize != extra.valueSize:
		reason = "value_size"
	case (main.btfValueTypeID != 0) != (extra.btfValueTypeID != 0):
		reason = "value type"
	case main.btfValueTypeID != 0 && globSymBTFMatches(name, true, mainSpec, main.btfValueTypeID, extraSpec, extra.btfValueTypeID) != nil:
		reason = "value type"
	case main.maxEntries != extra.maxEntries:
		reason = "max_entries"
	case main.mapFlags != extra.mapFlags:
		reason = "map_flags"
	default:
		return nil
	}
	return linkerErrorf(unix.EINVAL, "global '%s': map %s mismatch", name, reason)
}

// skipModsAndTypedefs follows modifiers, type tags and typedefs from id and
// returns the first other type with its ID, or nil for a bad ID or a cycle.
func skipModsAndTypedefs(spec *btf.Spec, id uint32) (*btf.Type, uint32) {
	for range spec.Types {
		t, err := spec.TypeByID(id)
		if err != nil {
			return nil, id
		}
		switch t.Kind {
		case btf.KindTypedef, btf.KindVolatile, btf.KindConst, btf.KindRestrict, btf.KindTypeTag:
			id = t.SizeOrType
		default:
			return t, id
		}
	}
	return nil, id
}

// globSymBTFMatches reports, as an error, whether type id1 of spec1 and id2
// of spec2 are incompatible descriptions of global name. Modifiers and
// typedefs are skipped. Names, sizes, linkage and shapes must agree; struct
// and union members are compared only while exact holds, which a pointer
// turns off, and outside exact a forward declaration matches a struct or
// union of the same name.
func globSymBTFMatches(name string, exact bool, spec1 *btf.Spec, id1 uint32, spec2 *btf.Spec, id2 uint32) error {
	mismatch := func(format string, args ...any) error {
		return linkerErrorf(unix.EINVAL, "global '%s': "+format, append([]any{name}, args...)...)
	}

	for {
		t1, _ := skipModsAndTypedefs(spec1, id1)
		t2, _ := skipModsAndTypedefs(spec2, id2)
		if t1 == nil || t2 == nil {
			return mismatch("invalid BTF type")
		}
		if !exact && (t1.Kind == btf.KindFwd) != (t2.Kind == btf.KindFwd) {
			return fwdMatches(name, t1, t2)
		}
		if t1.Kind != t2.Kind {
			return mismatch("incompatible BTF kinds %s and %s", t1.Kind, t2.Kind)
		}
		if namedKind(t1.Kind) && t1.Name != t2.Name {
			return mismatch("incompatible %s names '%s' and '%s'", t1.Kind, t1.Name, t2.Name)
		}

		switch t1.Kind {
		case btf.KindVoid, btf.KindFwd:
			return nil
		case btf.KindInt, btf.KindFloat, btf.KindEnum, btf.KindEnum64:
			if t1.SizeOrType != t2.SizeOrType {
				return mismatch("incompatible %s '%s' size %d and %d", t1.Kind, t1.Name, t1.SizeOrType, t2.SizeOrType)
			}
			return nil
		case btf.KindPtr:
			exact = false
			id1, id2 = t1.SizeOrType, t2.SizeOrType
		case btf.KindArray:
			id1, id2 = t1.Array.Type, t2.Array.Type
		case btf.KindFunc, btf.KindVar:
			if btfIsStatic(t1) != btfIsStatic(t2) {
				return mismatch("incompatible %s '%s' linkage", t1.Kind, t1.Name)
			}
			id1, id2 = t1.SizeOrType, t2.SizeOrType
		case btf.KindStruct, btf.KindUnion:
			if !exact {
				return nil
			}
			return membersMatch(name, spec1, t1, spec2, t2)
		case btf.KindFuncProto:
			if err := paramsMatch(name, exact, spec1, t1, spec2, t2); err != nil {
				return err
			}
			id1, id2 = t1.SizeOrType, t2.SizeOrType
		default:
			return mismatch("unsupported BTF kind %s", t1.Kind)
		}
	}
}

// namedKind reports whether two types of kind k must have the same name.
func namedKind(k btf.Kind) bool {
	switch k {
	case btf.KindStruct, btf.KindUnion, btf.KindEnum, btf.KindEnum64, btf.KindFwd, btf.KindFunc, btf.KindVar:
		return true
	}
	return false
}

// fwdMatches compares a forward declaration with a concrete type: the names
// must agree, and a union forward declaration needs a union, a struct one a
// struct.
func fwdMatches(name string, t1, t2 *btf.Type) error {
	if t1.Name != t2.Name {
		return linkerErrorf(unix.EINVAL, "global '%s': incompatible forward declaration names '%s' and '%s'", name, t1.Name, t2.Name)
	}

	fwd, concrete := t1, t2
	if t1.Kind != btf.KindFwd {
		fwd, concrete = t2, t1
	}
	if (fwd.KindFlag && concrete.Kind == btf.KindUnion) || (!fwd.KindFlag && concrete.Kind == btf.KindStruct) {
		return nil
	}

	kind := "struct"
	if fwd.KindFlag {
		kind = "union"
	}
	return linkerErrorf(unix.EINVAL, "global '%s': incompatible %s forward declaration and concrete kind %s", name, kind, concrete.Kind)
}

// membersMatch compares struct or union members by name, offset and type.
func membersMatch(name string, spec1 *btf.Spec, t1 *btf.Type, spec2 *btf.Spec, t2 *btf.Type) error {
	if len(t1.Members) != len(t2.Members) {
		return linkerErrorf(unix.EINVAL, "global '%s': incompatible number of %s fields %d and %d", name, t1.Kind, len(t1.Members), len(t2.Members))
	}
	for i := range t1.Members {
		m1, m2 := &t1.Members[i], &t2.Members[i]
		if m1.Name != m2.Name {
			return linkerErrorf(unix.EINVAL, "global '%s': incompatible field #%d names '%s' and '%s'", name, i, m1.Name, m2.Name)
		}
		if m1.Offset != m2.Offset || m1.BitfieldSize != m2.BitfieldSize {
			return linkerErrorf(unix.EINVAL, "global '%s': incompatible field #%d ('%s') offsets", name, i, m1.Name)
		}
		if err := globSymBTFMatches(name, true, spec1, m1.Type, spec2, m2.Type); err != nil {
			return err
		}
	}
	return nil
}

// paramsMatch compares function prototype parameter types; names are
// ignored.
func paramsMatch(name string, exact bool, spec1 *btf.Spec, t1 *btf.Type, spec2 *btf.Spec, t2 *btf.Type) error {
	if len(t1.Params) != len(t2.Params) {
		return linkerErrorf(unix.EINVAL, "global '%s': incompatible number of %s params %d and %d", name, t1.Kind, len(t1.Params), len(t2.Params))
	}
	for i := range t1.Params {
		if err := globSymBTFMatches(name, exact, spec1, t1.Params[i].Type, spec2, t2.Params[i].Type); err != nil {
			return err
		}
	}
	return nil
}
