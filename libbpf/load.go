// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__load, bpf_object_load, bpf_object__create_map, bpf_object__populate_internal_map, bpf_map_create, bpf_prog_load, adjust_prog_btf_ext_info, bpf_program__record_reloc, bpf_object__relocate_data

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// Source register values of a relocated ld_imm64 instruction.
const (
	bpfPseudoMapFD    = 1
	bpfPseudoMapValue = 2
)

// mapTakesBTF reports whether BPF_MAP_CREATE accepts the object BTF and the
// key and value type ids for a map type. The kernel rejects them for maps that
// store descriptors or raw values instead of BTF-described elements.
func mapTakesBTF(mapType BpfMapType) bool {
	switch mapType {
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		BPF_MAP_TYPE_CGROUP_ARRAY,
		BPF_MAP_TYPE_STACK_TRACE,
		BPF_MAP_TYPE_ARRAY_OF_MAPS,
		BPF_MAP_TYPE_HASH_OF_MAPS,
		BPF_MAP_TYPE_DEVMAP,
		BPF_MAP_TYPE_DEVMAP_HASH,
		BPF_MAP_TYPE_CPUMAP,
		BPF_MAP_TYPE_XSKMAP,
		BPF_MAP_TYPE_SOCKMAP,
		BPF_MAP_TYPE_SOCKHASH,
		BPF_MAP_TYPE_QUEUE,
		BPF_MAP_TYPE_STACK,
		BPF_MAP_TYPE_ARENA:
		return false
	}
	return true
}

// BpfObjectLoad loads the object into the kernel. It first resolves the
// .kconfig externs into the .kconfig map's initial value, from the open
// options' Kconfig text and the system kernel config. It then validates and
// loads the BTF, creates the maps with their BTF type ids, writes the initial
// contents of the internal maps, relocates the map, global variable and
// extern references in each program and loads the programs. The .rodata and
// .kconfig maps are frozen after their contents are written, so user space
// can read but not change them.
//
// The descriptors stay in the object and are closed by BpfObjectClose. The
// caller must have opened the object with BpfObjectOpenFile or
// BpfObjectOpenMem. A second load returns EINVAL. On failure the object is left
// unloaded and the error carries the verifier log when the kernel produced one.
func BpfObjectLoad(obj *BpfObject) error {
	if obj == nil {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL}
	}
	if obj.closed {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL, Log: "object is closed"}
	}
	if obj.loaded {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL, Log: "object already loaded"}
	}
	if obj.btf == nil {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL, Log: "object has no BTF"}
	}
	if err := resolveExterns(obj); err != nil {
		return err
	}

	logBuf := make([]byte, 64*1024)
	btfFD, err := sys.BtfLoad(obj.btf.Raw(), logBuf, 1)
	if err != nil {
		return &Error{
			Op:    "bpf_btf_load",
			Errno: errnoFromError(err),
			Log:   strings.TrimRight(string(logBuf), "\x00"),
		}
	}
	obj.btfFD = btfFD

	ext, kernelBTFs, err := objectCoreRelocations(obj)
	if err != nil {
		obj.closeLoadFDs()
		return &Error{
			Op:    "bpf_object__relocate_core",
			Errno: errnoFromError(err),
			Log:   err.Error(),
		}
	}

	for _, m := range obj.maps {
		if err := createMap(m, btfFD); err != nil {
			obj.closeLoadFDs()
			return err
		}
	}

	license := append([]byte(obj.license), 0)
	for _, p := range obj.programs {
		insns := append([]byte(nil), p.insns...)
		if len(kernelBTFs) > 0 {
			if err := relocateCore(p, insns, ext, obj.btf, kernelBTFs); err != nil {
				obj.closeLoadFDs()
				return &Error{
					Op:    "bpf_object__relocate_core",
					Errno: unix.EINVAL,
					Log:   err.Error(),
				}
			}
		}
		if err := relocateProgram(obj, p, insns); err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_prog_load",
				Errno: unix.EINVAL,
				Log:   err.Error(),
			}
		}
		if err := resolveAttachBTFID(p); err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_object__load",
				Errno: errnoFromError(err),
				Log:   err.Error(),
			}
		}

		// A USDT program is loaded for the uprobe multi link when the
		// kernel has one, so its attach can use the link.
		if p.usdt && featUprobeMultiLink.supported() {
			p.expectedAttachType = BPF_TRACE_UPROBE_MULTI
		}

		funcInfo := programFuncInfo(ext, p)
		lineInfo := programLineInfo(ext, p)
		attr := &sys.ProgLoadAttr{
			ProgType:           uint32(p.progType),
			InsnCnt:            uint32(len(insns) / 8),
			LogLevel:           1,
			ProgFlags:          p.progFlags,
			ExpectedAttachType: uint32(p.expectedAttachType),
			ProgBtfFD:          uint32(btfFD),
			AttachBtfID:        p.attachBTFID,
			AttachBtfObjFD:     int32(p.attachBTFObjFD),
			FuncInfoRecSize:    8,
			FuncInfoCnt:        uint32(len(funcInfo) / 8),
			LineInfoRecSize:    btf.LineInfoMinSize,
			LineInfoCnt:        uint32(len(lineInfo) / btf.LineInfoMinSize),
		}
		if len(funcInfo) == 0 {
			attr.FuncInfoRecSize = 0
		}
		if len(lineInfo) == 0 {
			attr.LineInfoRecSize = 0
		}
		attr.SetProgName(p.name)

		fd, err := sys.ProgLoad(attr, insns, license, logBuf, funcInfo, lineInfo)
		if err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_prog_load",
				Errno: errnoFromError(err),
				Log:   p.name + ": " + strings.TrimRight(string(logBuf), "\x00"),
			}
		}
		p.fd = fd

		info, err := sys.ProgInfoByFD(fd)
		if err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_obj_get_info_by_fd",
				Errno: errnoFromError(err),
				Log:   p.name,
			}
		}
		p.id = info.ID
		p.xlatedInsnCnt = int(info.XlatedProgLen / 8)
		p.jitedLen = info.JitedProgLen
	}

	obj.loaded = true
	return nil
}

// createMap creates m with the object BTF and records its descriptor and id.
// A reused map keeps its descriptor and only gets the id. A global data map
// gets its initial contents after creation.
func createMap(m *BpfMap, btfFD int) error {
	if !m.reused {
		attr := &sys.MapCreateAttr{
			MapType:        uint32(m.mapType),
			KeySize:        m.keySize,
			ValueSize:      m.valueSize,
			MaxEntries:     m.maxEntries,
			MapFlags:       m.mapFlags,
			BtfFD:          uint32(btfFD),
			BtfKeyTypeID:   m.btfKeyTypeID,
			BtfValueTypeID: m.btfValueTypeID,
		}
		if !mapTakesBTF(m.mapType) {
			attr.BtfFD = 0
			attr.BtfKeyTypeID = 0
			attr.BtfValueTypeID = 0
			m.btfKeyTypeID = 0
			m.btfValueTypeID = 0
		}
		attr.SetMapName(m.name)

		fd, err := sys.MapCreate(attr, nil)
		if err != nil {
			return &Error{Op: "bpf_map_create", Errno: errnoFromError(err), Log: m.name}
		}
		m.fd = fd

		if m.libbpfType != libbpfMapUnspec {
			if err := populateInternalMap(m); err != nil {
				return err
			}
		}
	}

	info, err := sys.MapInfoByFD(m.fd)
	if err != nil {
		return &Error{Op: "bpf_obj_get_info_by_fd", Errno: errnoFromError(err), Log: m.name}
	}
	m.id = info.ID
	return nil
}

// populateInternalMap writes the initial value into the only element of an
// internal map with one BPF_MAP_UPDATE_ELEM, then freezes a read-only data or
// .kconfig map so user space cannot change it.
func populateInternalMap(m *BpfMap) error {
	key := make([]byte, internalMapKeySize)
	if err := sys.MapUpdateElem(m.fd, key, m.initialValue, 0); err != nil {
		return &Error{
			Op:    "bpf_map_update_elem",
			Errno: errnoFromError(err),
			Log:   fmt.Sprintf("map '%s': failed to set initial contents", BpfMapName(m)),
		}
	}

	if m.libbpfType == libbpfMapRodata || m.libbpfType == libbpfMapKconfig {
		if err := sys.MapFreeze(m.fd); err != nil {
			return &Error{
				Op:    "bpf_map_freeze",
				Errno: errnoFromError(err),
				Log:   fmt.Sprintf("map '%s': failed to freeze as read-only", BpfMapName(m)),
			}
		}
	}
	return nil
}

// programFuncInfo encodes the .BTF.ext function records of p's section in the
// struct bpf_func_info layout BPF_PROG_LOAD expects. Records past the program's
// instructions are ignored.
func programFuncInfo(ext *btf.ExtSpec, p *BpfProgram) []byte {
	if ext == nil {
		return nil
	}

	insnCnt := len(p.insns) / 8
	for _, section := range ext.FuncInfos {
		if section.Section != p.sectionName {
			continue
		}
		var buf []byte
		for _, info := range section.Records {
			if int(info.InsnOff) >= insnCnt {
				continue
			}
			rec := make([]byte, 8)
			binary.NativeEndian.PutUint32(rec, info.InsnOff)
			binary.NativeEndian.PutUint32(rec[4:], info.TypeID)
			buf = append(buf, rec...)
		}
		return buf
	}
	return nil
}

// programLineInfo encodes the .BTF.ext line records of p's section in the
// struct bpf_line_info layout BPF_PROG_LOAD expects. Clang records byte
// offsets from the section start and the kernel takes instruction indexes,
// so each offset is divided by the instruction size. The records are sorted,
// and the copy stops at the first one past the program's instructions.
func programLineInfo(ext *btf.ExtSpec, p *BpfProgram) []byte {
	if ext == nil {
		return nil
	}

	insnCnt := uint32(len(p.insns) / bpfInsnSize)
	for _, section := range ext.LineInfos {
		if section.Section != p.sectionName {
			continue
		}
		var buf []byte
		for _, info := range section.Records {
			insnOff := info.InsnOff / bpfInsnSize
			if insnOff >= insnCnt {
				break
			}
			rec := make([]byte, btf.LineInfoMinSize)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffInsnOff:], insnOff)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffFileNameOff:], info.FileNameOff)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffLineOff:], info.LineOff)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffLineCol:], info.LineCol)
			buf = append(buf, rec...)
		}
		return buf
	}
	return nil
}

// relocateProgram patches the map, global variable and extern references in a
// private copy of the program instructions. A map reference becomes a
// BPF_PSEUDO_MAP_FD load of the map descriptor. A global variable or .kconfig
// extern reference becomes a BPF_PSEUDO_MAP_VALUE load: the first immediate
// holds the map descriptor and the second the variable's offset in the map
// value.
func relocateProgram(obj *BpfObject, p *BpfProgram, insns []byte) error {
	for _, rel := range p.relocs {
		if rel.Type != elf.R_BPF_64_64 {
			return fmt.Errorf("unsupported relocation type %d for %s", rel.Type, rel.Symbol)
		}

		r, err := recordReloc(obj, p, rel, insns)
		if err != nil {
			return err
		}
		if r.m.fd < 0 {
			return fmt.Errorf("map %s has no descriptor", BpfMapName(r.m))
		}
		patchReloc(insns, r)
	}
	return nil
}

// patchReloc rewrites the ld_imm64 pair at r.insnOff. The source register is
// the high nibble of the second byte on the little-endian targets.
func patchReloc(insns []byte, r progReloc) {
	insn := insns[r.insnOff:]
	switch r.kind {
	case relocLD64:
		insn[1] = (insn[1] & 0x0f) | (bpfPseudoMapFD << 4)
		binary.NativeEndian.PutUint32(insn[4:], uint32(r.m.fd))
		binary.NativeEndian.PutUint32(insn[12:], 0)
	case relocData:
		imm := binary.NativeEndian.Uint32(insn[4:])
		binary.NativeEndian.PutUint32(insn[12:], imm+r.symOff)
		insn[1] = (insn[1] & 0x0f) | (bpfPseudoMapValue << 4)
		binary.NativeEndian.PutUint32(insn[4:], uint32(r.m.fd))
	case relocExternLD64:
		// The extern offset replaces the instruction immediate; it is
		// not added to it as for a global variable.
		binary.NativeEndian.PutUint32(insn[12:], r.symOff)
		insn[1] = (insn[1] & 0x0f) | (bpfPseudoMapValue << 4)
		binary.NativeEndian.PutUint32(insn[4:], uint32(r.m.fd))
	}
}

// relocKind is what a program relocation patches.
type relocKind int

const (
	// relocLD64 loads a map descriptor.
	relocLD64 relocKind = iota
	// relocData loads the address of a global variable inside its map.
	relocData
	// relocExternLD64 loads the address of a .kconfig extern inside the
	// .kconfig map.
	relocExternLD64
)

// progReloc is one resolved program relocation. insnOff is the byte offset of
// the ld_imm64 instruction; symOff is the symbol value added to the
// instruction's own immediate for a global data relocation, or the extern's
// offset in the .kconfig map value.
type progReloc struct {
	kind    relocKind
	insnOff int
	m       *BpfMap
	symOff  uint32
}

// recordReloc resolves one ELF relocation of program p against obj's maps.
//
// An extern symbol refers to an extern variable; a .kconfig extern lives in
// the .kconfig map at its extern offset. A symbol in .maps names a map. A
// symbol in a data section refers to that section's internal map; the symbol
// value, zero for a section symbol, is the variable offset, and the
// instruction immediate carries any extra offset.
func recordReloc(obj *BpfObject, p *BpfProgram, rel elf.Reloc, insns []byte) (progReloc, error) {
	off := int(rel.Offset)
	if off < 0 || off%bpfInsnLength != 0 || off+2*bpfInsnLength > len(insns) {
		return progReloc{}, fmt.Errorf("prog '%s': relocation at %d is out of range", p.name, off)
	}
	if insns[off] != bpfLD|bpfImm|bpfSizeDW {
		return progReloc{}, fmt.Errorf("prog '%s': invalid relo against '%s' for insns[%d].code 0x%x",
			p.name, rel.Symbol, off/bpfInsnLength, insns[off])
	}
	if obj.elf == nil || int(rel.SymbolIndex) >= len(obj.elf.Symbols) {
		return progReloc{}, fmt.Errorf("prog '%s': symbol #%d not found", p.name, rel.SymbolIndex)
	}

	sym := obj.elf.Symbols[rel.SymbolIndex]
	if symIsExtern(sym) {
		return recordExternReloc(obj, p, rel, off)
	}
	symName := sym.Name
	if sym.Type == elf.STT_SECTION && symName == "" {
		symName = sym.Section
	}
	shndx := int(sym.SectionIndex)
	if shndx == 0 || sym.SectionIndex >= elf.SHN_LORESERVE || shndx >= len(obj.elf.Sections) {
		return progReloc{}, fmt.Errorf("prog '%s': invalid relo against '%s' in special section 0x%x; forgot to initialize global var?..",
			p.name, symName, shndx)
	}

	sec := &obj.elf.Sections[shndx]
	typ := dataSectionType(sec)
	if typ == libbpfMapUnspec {
		if sec.Name != mapsSec {
			return progReloc{}, fmt.Errorf("prog '%s': bad map relo against '%s' in section '%s'", p.name, symName, sec.Name)
		}
		m := findMapBySymbol(obj, rel.Symbol)
		if m == nil {
			return progReloc{}, fmt.Errorf("map %s not found", rel.Symbol)
		}
		return progReloc{kind: relocLD64, insnOff: off, m: m}, nil
	}

	for _, m := range obj.maps {
		if m.libbpfType == typ && m.secIdx == shndx {
			return progReloc{kind: relocData, insnOff: off, m: m, symOff: uint32(sym.Value)}, nil
		}
	}
	return progReloc{}, fmt.Errorf("prog '%s': data relo failed to find map for section '%s'", p.name, sec.Name)
}

// recordExternReloc resolves a relocation against the extern ELF symbol of
// rel. Only .kconfig externs are supported; they load from the .kconfig map.
func recordExternReloc(obj *BpfObject, p *BpfProgram, rel elf.Reloc, insnOff int) (progReloc, error) {
	ext := findExternBySymIdx(obj.externs, int(rel.SymbolIndex))
	if ext == nil {
		return progReloc{}, fmt.Errorf("prog '%s': extern relo failed to find extern for '%s' (%d)",
			p.name, rel.Symbol, rel.SymbolIndex)
	}
	if ext.typ != extKcfg {
		return progReloc{}, fmt.Errorf("prog '%s': extern '%s' is not a .kconfig extern", p.name, ext.name)
	}
	if obj.kconfigMap == nil {
		return progReloc{}, fmt.Errorf("prog '%s': extern '%s' has no .kconfig map", p.name, ext.name)
	}
	return progReloc{kind: relocExternLD64, insnOff: insnOff, m: obj.kconfigMap, symOff: uint32(ext.kcfg.dataOff)}, nil
}
