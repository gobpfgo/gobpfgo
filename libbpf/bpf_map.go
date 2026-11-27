// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__name, bpf_map__is_internal, bpf_map__type, bpf_map__key_size, bpf_map__value_size, bpf_map__max_entries, bpf_map__map_flags, bpf_map__btf_key_type_id, bpf_map__btf_value_type_id, bpf_map__pin_path, bpf_map__fd, bpf_map__lookup_elem

package libbpf

import (
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfMap is a map parsed from an object. It carries the definition metadata
// from the ELF and BTF sections; the load step adds the kernel descriptor.
type BpfMap struct {
	name       string
	symbolName string

	// An internal map records its section name and ELF index, and the
	// initial value written into the map after creation: the section image,
	// or the extern values for .kconfig.
	realName     string
	libbpfType   libbpfMapType
	secIdx       int
	initialValue []byte

	mapType        BpfMapType
	keySize        uint32
	valueSize      uint32
	maxEntries     uint32
	mapFlags       uint32
	btfKeyTypeID   uint32
	btfValueTypeID uint32
	pinPath        string
	pinned         bool
	reused         bool
	fd             int
	id             uint32
}

// BpfMapName returns the name declared in the map definition, or an empty
// string when the map is unnamed.
//
// A global data map is named after its object and section, such as
// "my_objec.data", which is also its kernel name. A custom data section such
// as ".data.custom" uses the section name, because the kernel name may be cut
// to 15 characters.
func BpfMapName(m *BpfMap) string {
	if m == nil {
		return ""
	}
	if mapUsesRealName(m) {
		return m.realName
	}
	return m.name
}

// BpfMapIsInternal reports whether m is an internal map that the object
// created for a .data, .rodata or .bss section or for the .kconfig externs,
// rather than a map defined in the .maps section.
func BpfMapIsInternal(m *BpfMap) bool {
	if m == nil {
		return false
	}
	return m.libbpfType != libbpfMapUnspec
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

// BpfMapLookupElem reads the value for key from a loaded map and copies it
// into value.
//
// key and value must match the map key and value sizes. A different length is
// rejected with EINVAL, because the kernel would otherwise copy the map value
// size past the end of the value slice. flags is passed to the kernel
// unchanged; BPF_F_LOCK is the flag element lookups use today.
//
// The caller must load the map with BpfObjectLoad first. A failed lookup
// returns an *Error with the kernel errno, for example ENOENT when the key is
// absent.
func BpfMapLookupElem(m *BpfMap, key, value []byte, flags uint64) error {
	if m == nil {
		return &Error{Op: "bpf_map__lookup_elem", Errno: unix.EINVAL}
	}
	if m.fd < 0 {
		return &Error{Op: "bpf_map__lookup_elem", Errno: unix.EBADF}
	}
	if len(key) != int(m.keySize) || len(value) != int(m.valueSize) {
		return &Error{Op: "bpf_map__lookup_elem", Errno: unix.EINVAL}
	}

	if err := sys.MapLookupElem(m.fd, key, value, flags); err != nil {
		return &Error{Op: "bpf_map__lookup_elem", Errno: errnoFromError(err)}
	}
	return nil
}
