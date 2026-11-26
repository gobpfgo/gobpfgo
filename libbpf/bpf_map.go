// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__name, bpf_map__type, bpf_map__key_size, bpf_map__value_size, bpf_map__max_entries, bpf_map__map_flags, bpf_map__btf_key_type_id, bpf_map__btf_value_type_id, bpf_map__pin_path, bpf_map__fd

package libbpf

// BpfMap is a map parsed from an object. It carries the definition metadata
// from the ELF and BTF sections; the load step adds the kernel descriptor.
type BpfMap struct {
	name           string
	mapType        BpfMapType
	keySize        uint32
	valueSize      uint32
	maxEntries     uint32
	mapFlags       uint32
	btfKeyTypeID   uint32
	btfValueTypeID uint32
	pinPath        string
	fd             int
}

// BpfMapName returns the name declared in the map definition, or an empty
// string when the map is unnamed.
func BpfMapName(m *BpfMap) string {
	if m == nil {
		return ""
	}
	return m.name
}

// BpfMapTypeOf returns the map type declared in the definition.
//
// The accessor has the Of suffix because BpfMapType is the Go type name. The
// value is the enum bpf_map_type from linux/bpf.h.
func BpfMapTypeOf(m *BpfMap) BpfMapType {
	if m == nil {
		return 0
	}
	return m.mapType
}

// BpfMapKeySize returns the key size in bytes.
func BpfMapKeySize(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.keySize
}

// BpfMapValueSize returns the value size in bytes.
func BpfMapValueSize(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.valueSize
}

// BpfMapMaxEntries returns the maximum number of entries.
func BpfMapMaxEntries(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.maxEntries
}

// BpfMapMapFlags returns the BPF_F_* flags from the map definition.
func BpfMapMapFlags(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.mapFlags
}

// BpfMapBtfKeyTypeID returns the BTF type ID of the map key, or zero when the
// definition has no BTF key type.
func BpfMapBtfKeyTypeID(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.btfKeyTypeID
}

// BpfMapBtfValueTypeID returns the BTF type ID of the map value, or zero when
// the definition has no BTF value type.
func BpfMapBtfValueTypeID(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.btfValueTypeID
}

// BpfMapFD returns the loaded map descriptor, or -1 before BpfObjectLoad and
// after BpfObjectClose.
func BpfMapFD(m *BpfMap) int {
	if m == nil {
		return -1
	}
	return m.fd
}

// BpfMapPinPath returns the pin path set on the map, or an empty string. The
// path is empty at open time unless the map definition or the caller set it.
func BpfMapPinPath(m *BpfMap) string {
	if m == nil {
		return ""
	}
	return m.pinPath
}
