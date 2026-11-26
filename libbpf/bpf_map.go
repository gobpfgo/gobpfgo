// SPDX-License-Identifier: LGPL-2.1-only
// Ported from libbpf src/libbpf.c at 4f05fb0.

package libbpf

// BpfMap is a map opened from an object. It mirrors struct bpf_map.
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
}

// BpfMapName mirrors bpf_map__name().
func BpfMapName(m *BpfMap) string {
	if m == nil {
		return ""
	}
	return m.name
}

// BpfMapType returns bpf_map__type().
func BpfMapTypeOf(m *BpfMap) BpfMapType {
	if m == nil {
		return 0
	}
	return m.mapType
}

// BpfMapKeySize mirrors bpf_map__key_size().
func BpfMapKeySize(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.keySize
}

// BpfMapValueSize mirrors bpf_map__value_size().
func BpfMapValueSize(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.valueSize
}

// BpfMapMaxEntries mirrors bpf_map__max_entries().
func BpfMapMaxEntries(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.maxEntries
}

// BpfMapMapFlags mirrors bpf_map__map_flags().
func BpfMapMapFlags(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.mapFlags
}

// BpfMapBtfKeyTypeID mirrors bpf_map__btf_key_type_id().
func BpfMapBtfKeyTypeID(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.btfKeyTypeID
}

// BpfMapBtfValueTypeID mirrors bpf_map__btf_value_type_id().
func BpfMapBtfValueTypeID(m *BpfMap) uint32 {
	if m == nil {
		return 0
	}
	return m.btfValueTypeID
}

// BpfMapPinPath mirrors bpf_map__pin_path().
func BpfMapPinPath(m *BpfMap) string {
	if m == nil {
		return ""
	}
	return m.pinPath
}
