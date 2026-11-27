// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__init_global_data_maps, bpf_object__init_internal_map, internal_map_name, map_fill_btf_type_info, map_is_mmapable, map_uses_real_name, bpf_object__section_to_libbpf_map_type, bpf_object__shndx_is_data, btf_fixup_datasec, find_elf_var_sym

package libbpf

import (
	"debug/elf"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// Global data section names. A section is also a data section when its name
// starts with one of them followed by a dot, such as ".rodata.str1.1".
const (
	dataSec      = ".data"
	rodataSec    = ".rodata"
	bssSec       = ".bss"
	dataRelRoSec = ".data.rel.ro"
	percpuSec    = ".percpu"
	mapsSec      = ".maps"
)

// libbpfMapType tells an internal map, one of the global data maps, the
// .kconfig map or a per-CPU data map, from a map defined in the .maps section,
// which is libbpfMapUnspec.
type libbpfMapType int

const (
	libbpfMapUnspec libbpfMapType = iota
	libbpfMapData
	libbpfMapBss
	libbpfMapRodata
	libbpfMapKconfig
	libbpfMapPercpu
)

// internalMapKeySize is the key size of every global data map: one int index.
const internalMapKeySize = 4

// secNameIs reports whether name is base or base followed by a dotted suffix.
func secNameIs(name, base string) bool {
	return name == base || strings.HasPrefix(name, base+".")
}

// dataSectionType classifies an ELF section as a global data section. Data,
// read-only data and per-CPU data must be non-empty, non-executable PROGBITS
// sections; the .data.rel.ro constants are read-only data. Zero-initialized
// data must be a NOBITS section.
func dataSectionType(s *objelf.Section) libbpfMapType {
	switch {
	case s.Type == elf.SHT_PROGBITS && s.Size > 0 && s.Flags&elf.SHF_EXECINSTR == 0:
		switch {
		case secNameIs(s.Name, dataRelRoSec):
			return libbpfMapRodata
		case secNameIs(s.Name, dataSec):
			return libbpfMapData
		case secNameIs(s.Name, rodataSec):
			return libbpfMapRodata
		case secNameIs(s.Name, percpuSec):
			return libbpfMapPercpu
		}
	case s.Type == elf.SHT_NOBITS && secNameIs(s.Name, bssSec):
		return libbpfMapBss
	}
	return libbpfMapUnspec
}

// initGlobalDataMaps returns one internal map per non-empty data, read-only
// data, zero-initialized data and per-CPU data section, in ELF section order.
// objName is the object name used as the map name prefix.
func initGlobalDataMaps(e *objelf.Object, spec *btf.Spec, objName string) []*BpfMap {
	var maps []*BpfMap
	for i := 1; i < len(e.Sections); i++ {
		s := &e.Sections[i]
		typ := dataSectionType(s)
		if typ == libbpfMapUnspec || s.Size == 0 {
			continue
		}
		maps = append(maps, newInternalMap(spec, objName, typ, s))
	}
	return maps
}

// newInternalMap builds the internal map that holds section s. The value is
// the whole section, so variables keep their section offsets. The initial
// value is the section bytes, or zeroes for a NOBITS section.
func newInternalMap(spec *btf.Spec, objName string, typ libbpfMapType, s *objelf.Section) *BpfMap {
	var data []byte
	if typ != libbpfMapBss {
		data = s.Data
	}
	return initInternalMap(spec, objName, typ, s.Name, s.Index, data, uint32(s.Size))
}

// initInternalMap builds a single-entry array map of size bytes for the
// internal map realName at ELF section secIdx. A per-CPU data map is a per-CPU
// array, so each CPU has its own copy of the value. Read-only data and
// .kconfig maps are read-only for programs. The BTF value type is the DATASEC
// named realName, when there is one, and a map other than a per-CPU one with a
// variable visible outside the object is mmapable. The initial value is data
// padded with zeroes to size; a per-CPU map starts with it on every CPU.
func initInternalMap(spec *btf.Spec, objName string, typ libbpfMapType, realName string, secIdx int, data []byte, size uint32) *BpfMap {
	m := &BpfMap{
		name:       internalMapName(objName, realName, typ),
		realName:   realName,
		libbpfType: typ,
		secIdx:     secIdx,
		mapType:    BPF_MAP_TYPE_ARRAY,
		keySize:    internalMapKeySize,
		valueSize:  size,
		maxEntries: 1,
		autocreate: true,
		fd:         -1,
	}
	if typ == libbpfMapPercpu {
		m.mapType = BPF_MAP_TYPE_PERCPU_ARRAY
	}
	if typ == libbpfMapRodata || typ == libbpfMapKconfig {
		m.mapFlags = unix.BPF_F_RDONLY_PROG
	}

	// A section without a DATASEC, such as .rodata.str1.1, has no BTF
	// value type and is created without one.
	mapFillBtfTypeInfo(spec, m)
	if mapIsMmapable(spec, m) {
		m.mapFlags |= unix.BPF_F_MMAPABLE
	}

	m.initialValue = make([]byte, size)
	copy(m.initialValue, data)
	return m
}

// internalMapName returns the kernel name of the internal map of type typ for
// section realName.
//
// The name keeps as much of the object name as fits in front of the section
// name, reserving at least seven characters for the section, so object
// "my_object_name" gives "my_objec.rodata" and "my_objec.bss". A section name
// with a second dot, such as ".rodata.custom", and a per-CPU data section,
// such as ".percpu", are used alone. The result is cut to the kernel's 15
// characters and every character the kernel rejects becomes '_'.
func internalMapName(objName, realName string, typ libbpfMapType) string {
	const maxLen = sys.BPF_OBJ_NAME_LEN - 1

	sfxLen := min(max(7, len(realName)), maxLen)
	pfxLen := 0
	if !strings.Contains(realName[min(1, len(realName)):], ".") && typ != libbpfMapPercpu {
		pfxLen = min(maxLen-sfxLen, len(objName))
	}

	name := []byte(objName[:pfxLen] + realName[:min(sfxLen, len(realName))])
	for i, c := range name {
		if !isMapNameChar(c) {
			name[i] = '_'
		}
	}
	return string(name)
}

// isMapNameChar reports whether the kernel accepts c in a map name.
func isMapNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.'
}

// mapFillBtfTypeInfo sets the BTF value type of an internal map to the first
// BTF type named like its section, the section's DATASEC. The key has no BTF
// type. Without a match the map keeps zero ids.
func mapFillBtfTypeInfo(spec *btf.Spec, m *BpfMap) {
	if spec == nil {
		return
	}
	for id := 1; id < len(spec.Types); id++ {
		if spec.Types[id].Name == m.realName {
			m.btfKeyTypeID = 0
			m.btfValueTypeID = uint32(id)
			return
		}
	}
}

// mapIsMmapable reports whether an internal map exposes a variable outside the
// object: its value type is a DATASEC with at least one non-static VAR. Global
// variables with hidden or internal visibility count as static. A per-CPU data
// map is never mmapable, because the kernel cannot map a per-CPU array.
func mapIsMmapable(spec *btf.Spec, m *BpfMap) bool {
	if spec == nil || m.btfValueTypeID == 0 {
		return false
	}
	if m.libbpfType == libbpfMapPercpu {
		return false
	}
	t, err := spec.TypeByID(m.btfValueTypeID)
	if err != nil || t.Kind != btf.KindDatasec {
		return false
	}
	for _, vsi := range t.DataSec {
		vt, err := spec.TypeByID(vsi.Type)
		if err != nil || vt.Kind != btf.KindVar || vt.Var == nil {
			continue
		}
		if vt.Var.Linkage != btf.VarStatic {
			return true
		}
	}
	return false
}

// mapUsesRealName reports whether the user-visible map name is the section
// name instead of the kernel name. That is the case for custom data sections
// such as ".data.custom" and for every per-CPU data section, whose kernel name
// may be truncated.
func mapUsesRealName(m *BpfMap) bool {
	switch m.libbpfType {
	case libbpfMapData:
		return m.realName != dataSec
	case libbpfMapRodata:
		return m.realName != rodataSec
	case libbpfMapPercpu:
		return true
	}
	return false
}

// varSymbols returns, for each name, the first global or weak object symbol
// with that name. It is the ELF symbol the BTF DATASEC fixups match a
// variable with.
func varSymbols(e *objelf.Object) map[string]objelf.Symbol {
	syms := make(map[string]objelf.Symbol)
	for _, sym := range e.Symbols {
		if sym.Name == "" || sym.Type != elf.STT_OBJECT {
			continue
		}
		if sym.Bind != elf.STB_GLOBAL && sym.Bind != elf.STB_WEAK {
			continue
		}
		if _, ok := syms[sym.Name]; !ok {
			syms[sym.Name] = sym
		}
	}
	return syms
}

// hiddenVariables returns the names of the global variables whose ELF symbol
// has hidden or internal visibility.
func hiddenVariables(syms map[string]objelf.Symbol) map[string]bool {
	hidden := make(map[string]bool)
	for name, sym := range syms {
		vis := elf.ST_VISIBILITY(sym.Other)
		if vis == elf.STV_HIDDEN || vis == elf.STV_INTERNAL {
			hidden[name] = true
		}
	}
	return hidden
}
