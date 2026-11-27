// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__load, bpf_object_load, bpf_object__load_progs, bpf_object_load_prog, bpf_object__create_map, bpf_object__populate_internal_map, bpf_map_create, bpf_prog_load, adjust_prog_btf_ext_info, bpf_program__record_reloc, bpf_object__relocate_data, poison_kfunc_call

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
	bpfPseudoBtfID    = 3
)

// bpfPseudoKfuncCall is the source register of a call to a kernel function.
const bpfPseudoKfuncCall = 2

// poisonCallKfuncBase is the helper ID a call to an unresolved weak kernel
// function gets, plus the extern's index. The verifier rejects the call with
// that ID only if it is reachable.
const poisonCallKfuncBase = 2002000000

// Field offsets of struct bpf_func_info, the function record of
// BPF_PROG_LOAD.
const (
	bpfFuncInfoOffInsnOff = 0
	bpfFuncInfoOffTypeID  = 4
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
// options' Kconfig text and the system kernel config, and the .ksyms
// externs: a typeless variable to its /proc/kallsyms address, a typed
// variable or kernel function to its ID in the running kernel's BTF or in a
// module BTF. Program references to them become constants, BPF_PSEUDO_BTF_ID
// loads and kfunc calls; a call to a missing weak kernel function is
// replaced with one the verifier rejects only when it is reachable. The
// kernel and module BTFs are released when the load returns. It then
// validates and loads the BTF, creates the maps with their BTF type ids,
// writes the initial contents of the internal maps and relocates each
// program. A program gets a copy of every .text subprogram it calls,
// directly or through another subprogram, appended to its own code, with
// the calls, the function and line records and the map, global variable and
// extern references relocated. Only the programs are loaded; a subprogram is
// loaded only as part of the programs that call it and has no descriptor.
// The .rodata and .kconfig maps are frozen after their contents are
// written, so user space can read but not change them.
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
	defer obj.closeModuleBTFs()
	if err := loadVmlinuxBTF(obj); err != nil {
		return err
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

	codes, err := relocateObject(obj, ext, kernelBTFs)
	if err != nil {
		obj.closeLoadFDs()
		return err
	}

	license := append([]byte(obj.license), 0)
	for _, code := range codes {
		if err := loadProgram(obj, code, license, logBuf); err != nil {
			obj.closeLoadFDs()
			return err
		}
	}

	obj.loaded = true
	return nil
}

// loadProgram loads the relocated code of one main program and records its
// descriptor, id and loaded lengths in the program. The code carries the
// subprograms the program calls and their function and line records.
func loadProgram(obj *BpfObject, code *progCode, license, logBuf []byte) error {
	p := code.prog
	if err := resolveAttachBTFID(p); err != nil {
		return &Error{
			Op:    "bpf_object__load",
			Errno: errnoFromError(err),
			Log:   err.Error(),
		}
	}

	// A USDT program is loaded for the uprobe multi link when the kernel
	// has one, so its attach can use the link.
	if p.usdt && featUprobeMultiLink.supported() {
		p.expectedAttachType = BPF_TRACE_UPROBE_MULTI
	}

	attr := &sys.ProgLoadAttr{
		ProgType:           uint32(p.progType),
		InsnCnt:            uint32(len(code.insns) / bpfInsnLength),
		LogLevel:           1,
		ProgFlags:          p.progFlags,
		ExpectedAttachType: uint32(p.expectedAttachType),
		ProgBtfFD:          uint32(obj.btfFD),
		AttachBtfID:        p.attachBTFID,
		AttachBtfObjFD:     int32(p.attachBTFObjFD),
		FuncInfoRecSize:    btf.FuncInfoMinSize,
		FuncInfoCnt:        uint32(len(code.funcInfo) / btf.FuncInfoMinSize),
		LineInfoRecSize:    btf.LineInfoMinSize,
		LineInfoCnt:        uint32(len(code.lineInfo) / btf.LineInfoMinSize),
	}
	if len(code.funcInfo) == 0 {
		attr.FuncInfoRecSize = 0
	}
	if len(code.lineInfo) == 0 {
		attr.LineInfoRecSize = 0
	}
	attr.SetProgName(p.name)

	fd, err := sys.ProgLoad(attr, code.insns, license, logBuf, code.funcInfo, code.lineInfo, fdArrayBytes(obj))
	if err != nil {
		return &Error{
			Op:    "bpf_prog_load",
			Errno: errnoFromError(err),
			Log:   p.name + ": " + strings.TrimRight(string(logBuf), "\x00"),
		}
	}
	p.fd = fd

	info, err := sys.ProgInfoByFD(fd)
	if err != nil {
		return &Error{
			Op:    "bpf_obj_get_info_by_fd",
			Errno: errnoFromError(err),
			Log:   p.name,
		}
	}
	p.id = info.ID
	p.xlatedInsnCnt = int(info.XlatedProgLen / bpfInsnLength)
	p.jitedLen = info.JitedProgLen
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

// programFuncInfo encodes the .BTF.ext function records of prog's own
// instructions in the struct bpf_func_info layout BPF_PROG_LOAD expects.
// Clang records byte offsets from the section start and the kernel takes
// instruction indexes from the start of the loaded code, so each offset is
// divided by the instruction size and moved from prog's start in its section
// to subInsnOff, where prog's copy starts in the loaded code. The records are
// sorted; only the first section with prog's name is read, and the copy stops
// at the first record past prog. It returns nil when no record is inside
// prog.
func programFuncInfo(ext *btf.ExtSpec, prog *BpfProgram, subInsnOff int) []byte {
	for _, section := range ext.FuncInfos {
		if section.Section != prog.sectionName {
			continue
		}
		first, last := progExtRecords(prog, len(section.Records), func(i int) uint32 {
			return section.Records[i].InsnOff
		})
		var buf []byte
		for _, info := range section.Records[first:last] {
			rec := make([]byte, btf.FuncInfoMinSize)
			binary.NativeEndian.PutUint32(rec[bpfFuncInfoOffInsnOff:], progExtInsnOff(prog, info.InsnOff, subInsnOff))
			binary.NativeEndian.PutUint32(rec[bpfFuncInfoOffTypeID:], info.TypeID)
			buf = append(buf, rec...)
		}
		return buf
	}
	return nil
}

// programLineInfo encodes the .BTF.ext line records of prog's own
// instructions in the struct bpf_line_info layout BPF_PROG_LOAD expects, with
// the instruction offsets moved like programFuncInfo moves them. It returns
// nil when no record is inside prog.
func programLineInfo(ext *btf.ExtSpec, prog *BpfProgram, subInsnOff int) []byte {
	for _, section := range ext.LineInfos {
		if section.Section != prog.sectionName {
			continue
		}
		first, last := progExtRecords(prog, len(section.Records), func(i int) uint32 {
			return section.Records[i].InsnOff
		})
		var buf []byte
		for _, info := range section.Records[first:last] {
			rec := make([]byte, btf.LineInfoMinSize)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffInsnOff:], progExtInsnOff(prog, info.InsnOff, subInsnOff))
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffFileNameOff:], info.FileNameOff)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffLineOff:], info.LineOff)
			binary.NativeEndian.PutUint32(rec[bpfLineInfoOffLineCol:], info.LineCol)
			buf = append(buf, rec...)
		}
		return buf
	}
	return nil
}

// progExtRecords returns the range [first, last) of the sorted .BTF.ext
// records whose instruction is inside prog. byteOff returns record i's byte
// offset from the section start. The range is empty when no record is inside.
func progExtRecords(prog *BpfProgram, count int, byteOff func(int) uint32) (first, last int) {
	first = -1
	for i := 0; i < count; i++ {
		insnOff := int(byteOff(i) / bpfInsnLength)
		if insnOff < prog.secInsnOff {
			continue
		}
		if insnOff >= prog.secInsnOff+prog.secInsnCnt {
			break
		}
		if first < 0 {
			first = i
		}
		last = i + 1
	}
	if first < 0 {
		return 0, 0
	}
	return first, last
}

// progExtInsnOff turns a .BTF.ext record's byte offset in prog's section into
// the instruction index of the same instruction in the loaded code, where
// prog's copy starts at subInsnOff.
func progExtInsnOff(prog *BpfProgram, byteOff uint32, subInsnOff int) uint32 {
	return uint32(int(byteOff/bpfInsnLength) + subInsnOff - prog.secInsnOff)
}

// relocateData patches the map, global variable and extern references of
// code, whose relocations are at their offset in the loaded code. A map
// reference becomes a BPF_PSEUDO_MAP_FD load of the map descriptor. A global
// variable or .kconfig extern reference becomes a BPF_PSEUDO_MAP_VALUE load:
// the first immediate holds the map descriptor and the second the variable's
// offset in the map value. A .ksyms reference and a kernel function call
// take what the extern resolved to, as patchKsymLD64 and patchExternCall
// describe. The calls and the subprogram address loads were patched when the
// subprograms were appended; an address load must still carry
// BPF_PSEUDO_FUNC.
func relocateData(code *progCode) error {
	externs := code.prog.obj.externs
	for i, r := range code.relocs {
		switch {
		case r.kind == relocCall:
		case r.kind == relocSubprogAddr:
			if decodeBpfInsn(code.insns[r.insnOff:]).Src != bpfPseudoFunc {
				return fmt.Errorf("prog '%s': relo #%d: bad insn", code.prog.name, i)
			}
		case r.kind == relocExternCall:
			patchExternCall(code.insns[r.insnOff:], r.extIdx, &externs[r.extIdx])
		case r.kind == relocExternLD64 && externs[r.extIdx].typ == extKsym:
			patchKsymLD64(code.insns[r.insnOff:], &externs[r.extIdx])
		default:
			if r.m.fd < 0 {
				return fmt.Errorf("map %s has no descriptor", BpfMapName(r.m))
			}
			patchReloc(code.insns, r)
		}
	}
	return nil
}

// patchKsymLD64 rewrites the ld_imm64 pair insn that loads the .ksyms
// extern ext. A resolved typed extern becomes a BPF_PSEUDO_BTF_ID load of
// the kernel BTF ID, with the module BTF descriptor, or 0 for vmlinux, in
// the second immediate. A typeless extern, or an unresolved weak typed one,
// loads its kallsyms address as a 64-bit constant, 0 when it has none.
func patchKsymLD64(insn []byte, ext *externDesc) {
	if ext.ksym.typeID != 0 && ext.isSet {
		insn[1] = (insn[1] & 0x0f) | (bpfPseudoBtfID << 4)
		binary.NativeEndian.PutUint32(insn[4:], ext.ksym.kernelBtfID)
		binary.NativeEndian.PutUint32(insn[12:], uint32(ext.ksym.kernelBtfObjFD))
		return
	}
	binary.NativeEndian.PutUint32(insn[4:], uint32(ext.ksym.addr))
	binary.NativeEndian.PutUint32(insn[12:], uint32(ext.ksym.addr>>32))
}

// patchExternCall rewrites the call insn to the kernel function ext, the
// extern at index extIdx. A resolved call becomes a BPF_PSEUDO_KFUNC_CALL
// with the kernel BTF ID as the immediate and the module's fd array slot, 0
// for vmlinux, as the offset. An unresolved weak function is poisoned
// instead: the call becomes a helper call with ID poisonCallKfuncBase plus
// extIdx, which the verifier rejects only if the call is reachable.
func patchExternCall(insn []byte, extIdx int, ext *externDesc) {
	call := decodeBpfInsn(insn)
	call.Src = bpfPseudoKfuncCall
	if ext.isSet {
		call.Imm = int32(ext.ksym.kernelBtfID)
		call.Off = ext.ksym.btfFdIdx
	} else {
		call = bpfInsn{Code: bpfJMP | bpfCall, Imm: int32(poisonCallKfuncBase + extIdx)}
	}
	encodeBpfInsn(insn, call)
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
	// .kconfig map, or what a .ksyms extern resolved to.
	relocExternLD64
	// relocExternCall calls a kernel function, a .ksyms extern.
	relocExternCall
	// relocCall calls a .text subprogram.
	relocCall
	// relocSubprogAddr loads the address of a .text subprogram, such as a
	// callback passed to a helper.
	relocSubprogAddr
)

// progReloc is one resolved program relocation. insnOff is the byte offset of
// the call or ld_imm64 instruction; symOff is the symbol value added to the
// instruction's own immediate for a global data relocation, the extern's
// offset in the .kconfig map value, or the symbol value of a subprogram call
// or address load. extIdx is the index of an extern relocation's extern in
// the object's sorted externs.
type progReloc struct {
	kind    relocKind
	insnOff int
	m       *BpfMap
	symOff  uint32
	extIdx  int
}

// recordReloc resolves one ELF relocation of program p against obj's maps and
// subprograms. The relocated instruction must be a call or an ld_imm64.
//
// An extern symbol refers to an extern: a call to a kernel function, or a
// load of an extern variable or function address; a .kconfig extern lives
// in the .kconfig map at its extern offset. A call refers to a .text
// subprogram, and so does an ld_imm64 against a .text function or the .text
// section symbol. A symbol in .maps names a map. A symbol in a data section
// refers to that section's internal map; the symbol value, zero for a section
// symbol, is the variable offset, and the instruction immediate carries any
// extra offset.
func recordReloc(obj *BpfObject, p *BpfProgram, rel elf.Reloc, insns []byte) (progReloc, error) {
	off := int(rel.Offset)
	if off < 0 || off%bpfInsnLength != 0 || off+bpfInsnLength > len(insns) {
		return progReloc{}, fmt.Errorf("prog '%s': relocation at %d is out of range", p.name, off)
	}
	insn := decodeBpfInsn(insns[off:])
	isCall := isCallInsn(insn)
	if !isCall && insn.Code != bpfLD|bpfImm|bpfSizeDW {
		return progReloc{}, fmt.Errorf("prog '%s': invalid relo against '%s' for insns[%d].code 0x%x",
			p.name, rel.Symbol, off/bpfInsnLength, insn.Code)
	}
	if !isCall && off+2*bpfInsnLength > len(insns) {
		return progReloc{}, fmt.Errorf("prog '%s': relocation at %d is out of range", p.name, off)
	}
	if obj.elf == nil || int(rel.SymbolIndex) >= len(obj.elf.Symbols) {
		return progReloc{}, fmt.Errorf("prog '%s': symbol #%d not found", p.name, rel.SymbolIndex)
	}

	sym := obj.elf.Symbols[rel.SymbolIndex]
	if symIsExtern(sym) {
		return recordExternReloc(obj, p, rel, isCall, off)
	}
	symName := sym.Name
	if sym.Type == elf.STT_SECTION && symName == "" {
		symName = sym.Section
	}
	if isCall {
		return recordCallReloc(obj, p, insn, sym, symName, off)
	}
	shndx := int(sym.SectionIndex)
	if shndx == 0 || sym.SectionIndex >= elf.SHN_LORESERVE || shndx >= len(obj.elf.Sections) {
		return progReloc{}, fmt.Errorf("prog '%s': invalid relo against '%s' in special section 0x%x; forgot to initialize global var?..",
			p.name, symName, shndx)
	}
	if symIsSubprog(sym, obj.textShndx) {
		return recordSubprogAddrReloc(p, insn, sym, symName, off)
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

// recordCallReloc resolves the relocation of a BPF_PSEUDO_CALL instruction.
// The target must be a function in .text at an instruction boundary: a
// global function through its own symbol, or a static one through the
// section symbol with the function offset in the instruction immediate.
func recordCallReloc(obj *BpfObject, p *BpfProgram, insn bpfInsn, sym elf.Symbol, symName string, insnOff int) (progReloc, error) {
	if insn.Src != bpfPseudoCall {
		return progReloc{}, fmt.Errorf("prog '%s': incorrect bpf_call opcode", p.name)
	}
	shndx := int(sym.SectionIndex)
	if shndx == 0 || shndx != obj.textShndx {
		secName := ""
		if shndx < len(obj.elf.Sections) {
			secName = obj.elf.Sections[shndx].Name
		}
		return progReloc{}, fmt.Errorf("prog '%s': bad call relo against '%s' in section '%s'", p.name, symName, secName)
	}
	if sym.Value%bpfInsnLength != 0 {
		return progReloc{}, fmt.Errorf("prog '%s': bad call relo against '%s' at offset %d", p.name, symName, sym.Value)
	}
	return progReloc{kind: relocCall, insnOff: insnOff, symOff: uint32(sym.Value)}, nil
}

// recordSubprogAddrReloc resolves an ld_imm64 that loads the address of a
// .text function. A global function's symbol value is its offset and the
// immediate is 0; a static function's relocation is against the section
// symbol and the immediate is its offset.
func recordSubprogAddrReloc(p *BpfProgram, insn bpfInsn, sym elf.Symbol, symName string, insnOff int) (progReloc, error) {
	if sym.Value%bpfInsnLength != 0 || insn.Imm%bpfInsnLength != 0 {
		return progReloc{}, fmt.Errorf("prog '%s': bad subprog addr relo against '%s' at offset %d+%d",
			p.name, symName, sym.Value, insn.Imm)
	}
	return progReloc{kind: relocSubprogAddr, insnOff: insnOff, symOff: uint32(sym.Value)}, nil
}

// recordExternReloc resolves a relocation against the extern ELF symbol of
// rel. A call is a kernel function call; any other reference is an ld_imm64
// of the extern, which for a .kconfig extern loads from the .kconfig map.
func recordExternReloc(obj *BpfObject, p *BpfProgram, rel elf.Reloc, isCall bool, insnOff int) (progReloc, error) {
	extIdx := findExternIdxBySymIdx(obj.externs, int(rel.SymbolIndex))
	if extIdx < 0 {
		return progReloc{}, fmt.Errorf("prog '%s': extern relo failed to find extern for '%s' (%d)",
			p.name, rel.Symbol, rel.SymbolIndex)
	}
	r := progReloc{kind: relocExternLD64, insnOff: insnOff, extIdx: extIdx}
	if isCall {
		r.kind = relocExternCall
		return r, nil
	}

	ext := &obj.externs[extIdx]
	if ext.typ == extKcfg {
		if obj.kconfigMap == nil {
			return progReloc{}, fmt.Errorf("prog '%s': extern '%s' has no .kconfig map", p.name, ext.name)
		}
		r.m = obj.kconfigMap
		r.symOff = uint32(ext.kcfg.dataOff)
	}
	return r, nil
}
