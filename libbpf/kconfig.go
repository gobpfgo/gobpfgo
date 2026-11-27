// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__collect_externs, sym_is_extern, find_extern_btf_id, find_extern_sec_btf_id, find_kcfg_type, cmp_externs, find_extern_by_name, bpf_object__init_kconfig_map

package libbpf

import (
	"debug/elf"
	"fmt"
	"sort"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// externType is the kind of an extern. Externs sort by it, so the .kconfig
// externs come before the .ksyms ones.
type externType int

const (
	extUnknown externType = iota
	extKcfg
	extKsym
)

// kcfgType says how a .kconfig extern's value is written into the map.
type kcfgType int

const (
	kcfgUnknown kcfgType = iota
	kcfgChar
	kcfgBool
	kcfgInt
	kcfgTristate
	kcfgCharArr
)

// BTF_INT_ENCODING flags, kept in bits 24 to 27 of an INT type's encoding.
const (
	btfIntSigned = 1 << 0
	btfIntBool   = 1 << 2
)

// BTF_FUNC_EXTERN from linux/btf.h.
const btfFuncExtern = 2

// libbpfTristateName is the BTF name of the enum a tristate extern must use.
const libbpfTristateName = "libbpf_tristate"

// kcfgExtern is the .kconfig part of an extern: the value's type, size,
// alignment and signedness, and its offset in the .kconfig map value.
type kcfgExtern struct {
	typ      kcfgType
	sz       int
	align    int
	dataOff  int
	isSigned bool
}

// externDesc is one extern of the object: an undefined global or weak ELF
// symbol whose BTF VAR or FUNC sits in an extern DATASEC. symIdx is the ELF
// symbol index the relocations use; isSet records that the loader gave it a
// value. essentName is the name without a ___flavor suffix, or "" when the
// name has none; a kernel function is looked up by it.
type externDesc struct {
	typ        externType
	symIdx     int
	btfID      uint32
	secBtfID   uint32
	name       string
	essentName string
	isSet      bool
	isWeak     bool
	kcfg       kcfgExtern
	ksym       ksymExtern
}

// externError reports an extern that cannot be collected at open time.
func externError(errno syscall.Errno, format string, args ...any) error {
	return &Error{Op: "bpf_object__collect_externs", Errno: errno, Log: fmt.Sprintf(format, args...)}
}

// symIsExtern reports whether sym is an extern: an untyped global or weak
// symbol with no section.
func symIsExtern(sym objelf.Symbol) bool {
	return sym.SectionIndex == elf.SHN_UNDEF &&
		(sym.Bind == elf.STB_GLOBAL || sym.Bind == elf.STB_WEAK) &&
		sym.Type == elf.STT_NOTYPE
}

// collectExterns returns the externs of the object, sorted, and lays out the
// .kconfig and .ksyms DATASECs for the kernel.
//
// Every named extern ELF symbol needs a BTF VAR or FUNC with extern linkage
// and a DATASEC that holds it. A .kconfig extern must be a variable of a
// supported kconfig type; a .ksyms extern is a kernel variable or function
// the loader resolves; any other section returns ENOTSUP.
//
// The externs sort by kind and then, for .kconfig, by descending alignment,
// ascending size and name. The .ksyms DATASEC becomes 4-byte allocated
// integer slots, with the functions replaced by a dummy_ksym VAR, because
// the kernel accepts neither extern variables nor functions there. Each
// .kconfig extern takes the next offset rounded up to its alignment. The
// .kconfig DATASEC gets that layout: its size, the variable offsets, and
// allocated linkage, which the kernel requires.
func collectExterns(e *objelf.Object, spec *btf.Spec) ([]externDesc, error) {
	dummyID, err := addDummyKsymVar(spec)
	if err != nil {
		return nil, err
	}

	var (
		externs   []externDesc
		kcfgSecID uint32
		ksymSecID uint32
	)
	for i, sym := range e.Symbols {
		if !symIsExtern(sym) || sym.Name == "" {
			continue
		}
		ext, err := newExtern(spec, sym, i)
		if err != nil {
			return nil, err
		}
		switch ext.typ {
		case extKcfg:
			kcfgSecID = ext.secBtfID
		case extKsym:
			ksymSecID = ext.secBtfID
		}
		externs = append(externs, ext)
	}
	if len(externs) == 0 {
		return nil, nil
	}

	sort.SliceStable(externs, func(a, b int) bool {
		return externLess(&externs[a], &externs[b])
	})

	if ksymSecID != 0 {
		if err := layoutKsyms(spec, ksymSecID, dummyID, externs); err != nil {
			return nil, err
		}
	}
	if kcfgSecID != 0 {
		if err := layoutKconfig(spec, kcfgSecID, externs); err != nil {
			return nil, err
		}
	}
	return externs, nil
}

// newExtern describes the extern ELF symbol sym at index symIdx from its BTF
// VAR or FUNC and the DATASEC that holds it.
func newExtern(spec *btf.Spec, sym objelf.Symbol, symIdx int) (externDesc, error) {
	btfID, errno := findExternBtfID(spec, sym.Name)
	if errno != 0 {
		return externDesc{}, externError(errno, "failed to find BTF for extern '%s': %v", sym.Name, errno)
	}
	t := &spec.Types[btfID]
	ext := externDesc{
		symIdx:     symIdx,
		btfID:      btfID,
		name:       t.Name,
		essentName: essentialName(t.Name),
		isWeak:     sym.Bind == elf.STB_WEAK,
	}

	ext.secBtfID, errno = findExternSecBtfID(spec, btfID)
	if errno != 0 {
		return externDesc{}, externError(errno, "failed to find BTF for extern '%s' [%d] section: %v", sym.Name, btfID, errno)
	}
	sec := &spec.Types[ext.secBtfID]

	switch sec.Name {
	case btf.KconfigSec:
		if t.Kind == btf.KindFunc {
			return externDesc{}, externError(unix.ENOTSUP, "extern function %s is unsupported under %s section", ext.name, btf.KconfigSec)
		}
		ext.typ = extKcfg
		kcfg, err := newKcfgExtern(spec, t.SizeOrType, sym.Name)
		if err != nil {
			return externDesc{}, err
		}
		ext.kcfg = kcfg
	case btf.KsymsSec:
		ext.typ = extKsym
		ext.ksym = newKsymExtern(spec, t)
	default:
		return externDesc{}, externError(unix.ENOTSUP, "unrecognized extern section '%s'", sec.Name)
	}
	return ext, nil
}

// newKcfgExtern returns the size, alignment and kconfig type of the .kconfig
// extern name, whose VAR has type id.
//
// libbpf stops collecting and reports success for a zero-sized extern, which
// then fails later; this port rejects it here with EINVAL.
func newKcfgExtern(spec *btf.Spec, id uint32, name string) (kcfgExtern, error) {
	sz, err := spec.SizeOf(id)
	if err != nil || sz == 0 {
		return kcfgExtern{}, externError(unix.EINVAL, "failed to resolve size of extern (kcfg) '%s'", name)
	}
	align, err := spec.AlignOf(id)
	if err != nil || align <= 0 {
		return kcfgExtern{}, externError(unix.EINVAL, "failed to determine alignment of extern (kcfg) '%s'", name)
	}
	typ, signed := findKcfgType(spec, id)
	if typ == kcfgUnknown {
		return kcfgExtern{}, externError(unix.ENOTSUP, "extern (kcfg) '%s': type is unsupported", name)
	}
	return kcfgExtern{typ: typ, sz: int(sz), align: align, isSigned: signed}, nil
}

// findExternBtfID returns the first BTF VAR or FUNC named name. It returns
// EINVAL when that type does not have extern linkage and ENOENT when there is
// none.
func findExternBtfID(spec *btf.Spec, name string) (uint32, syscall.Errno) {
	for id := 1; id < len(spec.Types); id++ {
		t := &spec.Types[id]
		if (t.Kind != btf.KindVar && t.Kind != btf.KindFunc) || t.Name != name {
			continue
		}
		if t.Kind == btf.KindVar && (t.Var == nil || t.Var.Linkage != btf.VarGlobalExtern) {
			return 0, unix.EINVAL
		}
		if t.Kind == btf.KindFunc && t.Vlen != btfFuncExtern {
			return 0, unix.EINVAL
		}
		return uint32(id), 0
	}
	return 0, unix.ENOENT
}

// findExternSecBtfID returns the first DATASEC with a variable of type extID,
// or ENOENT.
func findExternSecBtfID(spec *btf.Spec, extID uint32) (uint32, syscall.Errno) {
	for id := 1; id < len(spec.Types); id++ {
		t := &spec.Types[id]
		if t.Kind != btf.KindDatasec {
			continue
		}
		for _, vsi := range t.DataSec {
			if vsi.Type == extID {
				return uint32(id), 0
			}
		}
	}
	return 0, unix.ENOENT
}

// findKcfgType classifies type id, after modifiers and typedefs, as a kconfig
// value type and reports whether an integer is signed.
//
// A one-byte bool is kcfgBool and any other one-byte integer kcfgChar. An
// integer of 2, 4 or 8 bytes is kcfgInt. The libbpf_tristate enum, 4 bytes
// or enum64, is kcfgTristate, and a non-empty array of kcfgChar is
// kcfgCharArr. Everything else is kcfgUnknown.
func findKcfgType(spec *btf.Spec, id uint32) (kcfgType, bool) {
	t, _ := skipModsAndTypedefs(spec, id)
	if t == nil {
		return kcfgUnknown, false
	}

	switch t.Kind {
	case btf.KindInt:
		enc := btfIntEncoding(t)
		if enc&btfIntBool != 0 {
			if t.SizeOrType == 1 {
				return kcfgBool, false
			}
			return kcfgUnknown, false
		}
		signed := enc&btfIntSigned != 0
		size := t.SizeOrType
		if size == 1 {
			return kcfgChar, signed
		}
		if size < 1 || size > 8 || size&(size-1) != 0 {
			return kcfgUnknown, signed
		}
		return kcfgInt, signed
	case btf.KindEnum:
		if t.SizeOrType != 4 || t.Name != libbpfTristateName {
			return kcfgUnknown, false
		}
		return kcfgTristate, false
	case btf.KindEnum64:
		if t.Name != libbpfTristateName {
			return kcfgUnknown, false
		}
		return kcfgTristate, false
	case btf.KindArray:
		if t.Array == nil || t.Array.Nelems == 0 {
			return kcfgUnknown, false
		}
		if elem, _ := findKcfgType(spec, t.Array.Type); elem != kcfgChar {
			return kcfgUnknown, false
		}
		return kcfgCharArr, false
	}
	return kcfgUnknown, false
}

// btfIntEncoding returns the BTF_INT_ENCODING flags of an INT type.
func btfIntEncoding(t *btf.Type) uint32 {
	if t.Int == nil {
		return 0
	}
	return (t.Int.Encoding >> 24) & 0x0f
}

// externLess orders externs by kind, then .kconfig externs by descending
// alignment and ascending size, and finally by name.
func externLess(a, b *externDesc) bool {
	if a.typ != b.typ {
		return a.typ < b.typ
	}
	if a.typ == extKcfg {
		if a.kcfg.align != b.kcfg.align {
			return a.kcfg.align > b.kcfg.align
		}
		if a.kcfg.sz != b.kcfg.sz {
			return a.kcfg.sz < b.kcfg.sz
		}
	}
	return a.name < b.name
}

// layoutKconfig assigns each sorted .kconfig extern its offset in the map
// value and rewrites the .kconfig DATASEC secID to match: the size becomes
// the end of the last extern, and each variable gets its extern's offset and
// allocated linkage. A variable without an extern returns ESRCH.
func layoutKconfig(spec *btf.Spec, secID uint32, externs []externDesc) error {
	off := 0
	for i := range externs {
		ext := &externs[i]
		if ext.typ != extKcfg {
			continue
		}
		ext.kcfg.dataOff = roundup(off, ext.kcfg.align)
		off = ext.kcfg.dataOff + ext.kcfg.sz
	}
	if err := spec.SetDatasecSize(secID, uint32(off)); err != nil {
		return externError(unix.EINVAL, "%v", err)
	}

	sec := &spec.Types[secID]
	for j, vsi := range sec.DataSec {
		vt, err := spec.TypeByID(vsi.Type)
		if err != nil {
			return externError(unix.EINVAL, "%v", err)
		}
		ext := findExternByName(externs, vt.Name)
		if ext == nil {
			return externError(unix.ESRCH, "failed to find extern definition for BTF var '%s'", vt.Name)
		}
		if err := spec.SetVarLinkage(vt.ID, btf.VarGlobalAllocated); err != nil {
			return externError(unix.EINVAL, "%v", err)
		}
		if err := spec.SetDatasecVarOffset(secID, j, uint32(ext.kcfg.dataOff)); err != nil {
			return externError(unix.EINVAL, "%v", err)
		}
	}
	return nil
}

// findExternByName returns the extern named name, or nil.
func findExternByName(externs []externDesc, name string) *externDesc {
	for i := range externs {
		if externs[i].name == name {
			return &externs[i]
		}
	}
	return nil
}

// findExternIdxBySymIdx returns the index of the extern of ELF symbol
// symIdx, or -1.
func findExternIdxBySymIdx(externs []externDesc, symIdx int) int {
	for i := range externs {
		if externs[i].symIdx == symIdx {
			return i
		}
	}
	return -1
}

// initKconfigMap returns the internal .kconfig map, or nil when the object
// has no .kconfig externs. Its value ends with the last .kconfig extern, so
// the value size is that extern's offset plus its size. The map is read-only
// for programs and starts zeroed; the loader writes the extern values into it
// before creating it. symtabIdx is the ELF symbol table index, which stands
// in for the map's section.
func initKconfigMap(spec *btf.Spec, objName string, externs []externDesc, symtabIdx int) *BpfMap {
	var last *externDesc
	for i := range externs {
		if externs[i].typ == extKcfg {
			last = &externs[i]
		}
	}
	if last == nil {
		return nil
	}

	size := last.kcfg.dataOff + last.kcfg.sz
	return initInternalMap(spec, objName, libbpfMapKconfig, btf.KconfigSec, symtabIdx, nil, uint32(size))
}

// symtabIndex returns the index of the ELF symbol table section, or 0.
func symtabIndex(e *objelf.Object) int {
	for _, s := range e.Sections {
		if s.Type == elf.SHT_SYMTAB {
			return s.Index
		}
	}
	return 0
}
