// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__name, bpf_map__is_internal, bpf_map__type, bpf_map__key_size, bpf_map__value_size, bpf_map__max_entries, bpf_map__map_flags, bpf_map__btf_key_type_id, bpf_map__btf_value_type_id, bpf_map__pin_path, bpf_map__fd, bpf_map__lookup_elem, validate_map_op

package libbpf

import (
	"fmt"

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

	// autocreate is set when the load creates the map. The load clears it
	// for a map the kernel cannot use, which then keeps descriptor -1.
	autocreate bool
	fd         int
	id         uint32

	// funcPtrs are the pointers to .text functions in a read-only data
	// map's section, a slice of the object's, sorted by offset. A program
	// with callx that loads the map gets its own copy, with the offsets of
	// the functions in that program.
	funcPtrs []funcPtr
}

// BpfMapName returns the name declared in the map definition, or an empty
// string when the map is unnamed.
//
// A global data map is named after its object and section, such as
// "my_objec.data", which is also its kernel name. A custom data section such
// as ".data.custom" and a per-CPU data section such as ".percpu" use the
// section name, because the kernel name may be cut to 15 characters.
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
// created for a .data, .rodata, .bss or .percpu section or for the .kconfig
// externs, rather than a map defined in the .maps section.
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

// BpfMapFD returns the loaded map descriptor, or -1 before BpfObjectLoad,
// after BpfObjectClose, and for a map the load did not create: a per-CPU data
// map on a kernel without global per-CPU data.
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
// key must match the map key size and value the size the kernel copies out,
// or the call fails with EINVAL before the kernel could write past the end
// of value. For most maps that is the map value size. A per-CPU map
// (BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_PERCPU_HASH,
// BPF_MAP_TYPE_LRU_PERCPU_HASH or BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE) returns
// one value per possible CPU, each padded to a multiple of 8 bytes, so value
// must hold LibbpfNumPossibleCpus times the padded value size. With BPF_F_CPU
// or BPF_F_ALL_CPUS in flags it returns a single value of the map value size
// instead; setting both is EINVAL. flags is otherwise passed to the kernel
// unchanged.
//
// The caller must load the map with BpfObjectLoad first; before that the call
// fails with EBADF. A failed lookup returns an *Error with the kernel errno,
// for example ENOENT when the key is absent, or EINVAL for BPF_F_CPU and
// BPF_F_ALL_CPUS on a kernel that does not have them.
func BpfMapLookupElem(m *BpfMap, key, value []byte, flags uint64) error {
	const op = "bpf_map__lookup_elem"

	if m == nil {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if m.fd < 0 {
		return &Error{Op: op, Errno: unix.EBADF}
	}
	if err := validateMapOp(m, len(key), len(value), flags); err != nil {
		return &Error{Op: op, Errno: unix.EINVAL, Log: err.Error()}
	}

	if err := sys.MapLookupElem(m.fd, key, value, flags); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// validateMapOp checks the key and value buffer sizes of an element operation
// on m with flags. A per-CPU map takes one value per possible CPU at an 8-byte
// aligned stride, unless flags selects one CPU or all CPUs, which take a
// single value; BPF_F_CPU and BPF_F_ALL_CPUS together are rejected. Every
// other map takes exactly its value size.
func validateMapOp(m *BpfMap, keySize, valueSize int, flags uint64) error {
	if keySize != int(m.keySize) {
		return fmt.Errorf("map '%s': unexpected key size %d provided, expected %d", m.name, keySize, m.keySize)
	}
	if !isPercpuMapType(m.mapType) {
		if valueSize != int(m.valueSize) {
			return fmt.Errorf("map '%s': unexpected value size %d provided, expected %d", m.name, valueSize, m.valueSize)
		}
		return nil
	}

	if flags&(BPF_F_CPU|BPF_F_ALL_CPUS) != 0 {
		if flags&BPF_F_CPU != 0 && flags&BPF_F_ALL_CPUS != 0 {
			return fmt.Errorf("map '%s': BPF_F_CPU and BPF_F_ALL_CPUS are mutually exclusive", m.name)
		}
		if valueSize != int(m.valueSize) {
			return fmt.Errorf("map '%s': unexpected value size %d provided for either BPF_F_CPU or BPF_F_ALL_CPUS, expected %d",
				m.name, valueSize, m.valueSize)
		}
		return nil
	}

	numCPU := libbpfNumPossibleCPUs()
	if want := percpuValueSize(m.valueSize, numCPU); numCPU < 0 || valueSize != want {
		return fmt.Errorf("map '%s': unexpected value size %d provided for per-CPU map, expected %d * %d = %d",
			m.name, valueSize, numCPU, roundup(int(m.valueSize), 8), want)
	}
	return nil
}

// isPercpuMapType reports whether a map of type t keeps one value per
// possible CPU in each element.
func isPercpuMapType(t BpfMapType) bool {
	switch t {
	case BPF_MAP_TYPE_PERCPU_ARRAY,
		BPF_MAP_TYPE_PERCPU_HASH,
		BPF_MAP_TYPE_LRU_PERCPU_HASH,
		BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		return true
	}
	return false
}

// percpuValueSize returns the size of the element value of a per-CPU map with
// value size valueSize on numCPU possible CPUs: the kernel copies each CPU's
// value at a stride rounded up to 8 bytes.
func percpuValueSize(valueSize uint32, numCPU int) int {
	return numCPU * roundup(int(valueSize), 8)
}
