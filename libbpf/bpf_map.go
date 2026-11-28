// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__name, bpf_map__is_internal, bpf_map__type, bpf_map__key_size, bpf_map__value_size, bpf_map__max_entries, bpf_map__map_flags, bpf_map__btf_key_type_id, bpf_map__btf_value_type_id, bpf_map__pin_path, bpf_map__fd, bpf_map__lookup_elem, bpf_map__update_elem, bpf_map__delete_elem, bpf_map__lookup_and_delete_elem, bpf_map__get_next_key, bpf_map__initial_value, bpf_map__set_initial_value, validate_map_op, map_is_created

package libbpf

import (
	"fmt"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfMap is a map parsed from an object. It carries the definition metadata
// from the ELF and BTF sections; the load step adds the kernel descriptor.
type BpfMap struct {
	// obj is the object that opened the map. Its load state decides
	// whether the map counts as created.
	obj *BpfObject

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
// after a failed load or BpfObjectClose, and for a map the load did not
// create: a per-CPU data map on a kernel without global per-CPU data. A map
// given a descriptor with BpfMapReuseFD returns it before the load too.
func BpfMapFD(m *BpfMap) int {
	if m == nil || !mapIsCreated(m) {
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
// unchanged. A map with key size 0, such as a queue or stack, takes an empty
// key.
//
// Before BpfObjectLoad the call fails with ENOENT, unless BpfMapReuseFD gave
// the map a descriptor. Once a load has run, successfully or not, a map
// without a descriptor fails with EINVAL after the key size check: a map the
// load did not create, such as a per-CPU data map on a kernel without global
// per-CPU data, and every map after a failed load or BpfObjectClose. A failed
// lookup returns an *Error with the kernel errno, for example ENOENT when the
// key is absent, or EINVAL for BPF_F_CPU and BPF_F_ALL_CPUS on a kernel that
// does not have them.
func BpfMapLookupElem(m *BpfMap, key, value []byte, flags uint64) error {
	const op = "bpf_map__lookup_elem"

	if err := validateMapOp(op, m, len(key), len(value), true, flags); err != nil {
		return err
	}
	if err := sys.MapLookupElem(m.fd, key, value, flags); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// BpfMapUpdateElem writes value for key into a loaded map.
//
// key and value follow the size rules of BpfMapLookupElem: a per-CPU map
// takes one 8-byte aligned value per possible CPU, or a single value with
// BPF_F_CPU or BPF_F_ALL_CPUS in flags. flags is BPF_ANY, BPF_NOEXIST or
// BPF_EXIST, possibly with other BPF_F_* bits, and is passed to the kernel
// unchanged. A queue or stack map takes an empty key and pushes value.
//
// The call fails with EINVAL for a buffer of the wrong size, and before the
// load or for a map without a descriptor as BpfMapLookupElem describes. A
// failed update returns an *Error with the kernel errno, for example EEXIST
// for BPF_NOEXIST on an existing key, E2BIG for a full hash map, or EPERM for
// a frozen map.
func BpfMapUpdateElem(m *BpfMap, key, value []byte, flags uint64) error {
	const op = "bpf_map__update_elem"

	if err := validateMapOp(op, m, len(key), len(value), true, flags); err != nil {
		return err
	}
	if err := sys.MapUpdateElem(m.fd, key, value, flags); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// BpfMapDeleteElem removes key from a loaded map.
//
// key must match the map key size; no value is involved. flags is passed to
// the kernel unchanged. The call fails with EINVAL for a key of the wrong
// size, and before the load or for a map without a descriptor as
// BpfMapLookupElem describes. A failed delete returns an *Error with the
// kernel errno, for example ENOENT when the key is absent,
// or EINVAL for an array map, whose elements cannot be deleted.
func BpfMapDeleteElem(m *BpfMap, key []byte, flags uint64) error {
	const op = "bpf_map__delete_elem"

	if err := validateMapOp(op, m, len(key), 0, false, flags); err != nil {
		return err
	}
	if err := sys.MapDeleteElem(m.fd, key, flags); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// BpfMapLookupAndDeleteElem copies the value for key into value and removes
// the element from a loaded map in one step.
//
// key and value follow the size rules of BpfMapLookupElem. A queue or stack
// map takes an empty key and pops its next element. flags is passed to the
// kernel unchanged. The call fails with EINVAL for a buffer of the wrong
// size, and before the load or for a map without a descriptor as
// BpfMapLookupElem describes. A failed call returns an *Error with the kernel
// errno, for example ENOENT when the key is absent; a kernel
// older than 5.14 supports the command only for queue and stack maps and
// returns ENOTSUPP (524) for the others.
func BpfMapLookupAndDeleteElem(m *BpfMap, key, value []byte, flags uint64) error {
	const op = "bpf_map__lookup_and_delete_elem"

	if err := validateMapOp(op, m, len(key), len(value), true, flags); err != nil {
		return err
	}
	if err := sys.MapLookupAndDeleteElem(m.fd, key, value, flags); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// BpfMapGetNextKey copies the key that follows curKey in a loaded map into
// nextKey. An empty curKey asks for the first key, so a caller walks the map
// by starting with nil and passing each returned key back in.
//
// nextKey must match the map key size, and so must curKey when it is not
// empty. The call fails with EINVAL for a buffer of the wrong size, and
// before the load or for a map without a descriptor as BpfMapLookupElem
// describes. After the last key the kernel returns ENOENT.
func BpfMapGetNextKey(m *BpfMap, curKey, nextKey []byte) error {
	const op = "bpf_map__get_next_key"

	if err := validateMapOp(op, m, len(nextKey), 0, false, 0); err != nil {
		return err
	}
	if len(curKey) != 0 && len(curKey) != int(m.keySize) {
		return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf(
			"map '%s': unexpected current key size %d provided, expected %d", m.name, len(curKey), m.keySize)}
	}
	if err := sys.MapGetNextKey(m.fd, curKey, nextKey); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// BpfMapInitialValue returns the initial value of an internal map: the
// section image of a .data, .rodata, .bss or per-CPU data map, or the
// extern values of the .kconfig map. It returns nil for a map defined in the
// .maps section, which has no initial value, and for a nil map.
//
// The slice aliases the object's buffer and is BpfMapValueSize bytes long.
// Before BpfObjectLoad, changing its bytes changes what the load writes into
// the map, as BpfMapSetInitialValue does. The load writes the resolved extern
// values into the .kconfig map's buffer. After the load the slice keeps the
// bytes the load wrote and is not the kernel map's memory, so changing it no
// longer affects the map; use BpfMapLookupElem and BpfMapUpdateElem instead.
// BpfObjectClose releases the buffer, and the call returns nil from then on;
// a failed BpfObjectLoad keeps it.
func BpfMapInitialValue(m *BpfMap) []byte {
	if m == nil {
		return nil
	}
	return m.initialValue
}

// BpfMapSetInitialValue replaces the initial value of an internal map with a
// copy of data, so BpfObjectLoad writes data into the map instead of the
// section image. A per-CPU data map starts with data on every possible CPU.
//
// data must be exactly the map value size. The call fails with EBUSY once
// the map counts as created: after BpfMapReuseFD, and once BpfObjectLoad has
// run on the object, even when the load failed or did not create this map. It
// fails with EINVAL for a nil map, a map without an initial value, such as
// one defined in the .maps section, the .kconfig map, whose values the load
// resolves, or data of another size. After BpfObjectClose, which released
// the initial value, it fails with EINVAL whatever the map's state was.
func BpfMapSetInitialValue(m *BpfMap, data []byte) error {
	const op = "bpf_map__set_initial_value"

	if m == nil || (m.obj != nil && m.obj.closed) {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if mapIsCreated(m) {
		return &Error{Op: op, Errno: unix.EBUSY}
	}
	if m.initialValue == nil || m.libbpfType == libbpfMapKconfig {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if len(data) != int(m.valueSize) {
		return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf(
			"map '%s': initial value size %d, expected %d", m.name, len(data), m.valueSize)}
	}

	copy(m.initialValue, data)
	return nil
}

// mapIsCreated reports whether m is past the point where its definition can
// change: the caller gave it a descriptor with BpfMapReuseFD, or a load of
// its object has run, successfully or not. A created map may still have no
// descriptor, when the load skipped it or failed.
func mapIsCreated(m *BpfMap) bool {
	return m.reused || (m.obj != nil && m.obj.attempted)
}

// validateMapOp checks an element operation op on m with keySize and
// valueSize byte buffers and flags. A nil map is EINVAL, and a map that is
// not created yet is ENOENT. A key of another size than the map's is EINVAL,
// and so is a created map without a descriptor. When
// checkValueSize is set, the value size is checked too: a per-CPU map takes
// one value per possible CPU at an 8-byte aligned stride, unless flags
// selects one CPU or all CPUs, which take a single value; BPF_F_CPU and
// BPF_F_ALL_CPUS together are rejected. Every other map takes exactly its
// value size. A failed check is EINVAL with the reason in the log.
func validateMapOp(op string, m *BpfMap, keySize, valueSize int, checkValueSize bool, flags uint64) error {
	if m == nil {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if !mapIsCreated(m) {
		return &Error{Op: op, Errno: unix.ENOENT}
	}

	invalid := func(format string, args ...any) error {
		return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf(format, args...)}
	}
	if keySize != int(m.keySize) {
		return invalid("map '%s': unexpected key size %d provided, expected %d", m.name, keySize, m.keySize)
	}
	if m.fd < 0 {
		return invalid("map '%s': can't use BPF map without FD (was it created?)", m.name)
	}
	if !checkValueSize {
		return nil
	}

	if !isPercpuMapType(m.mapType) {
		if valueSize != int(m.valueSize) {
			return invalid("map '%s': unexpected value size %d provided, expected %d", m.name, valueSize, m.valueSize)
		}
		return nil
	}

	if flags&(BPF_F_CPU|BPF_F_ALL_CPUS) != 0 {
		if flags&BPF_F_CPU != 0 && flags&BPF_F_ALL_CPUS != 0 {
			return invalid("map '%s': BPF_F_CPU and BPF_F_ALL_CPUS are mutually exclusive", m.name)
		}
		if valueSize != int(m.valueSize) {
			return invalid("map '%s': unexpected value size %d provided for either BPF_F_CPU or BPF_F_ALL_CPUS, expected %d",
				m.name, valueSize, m.valueSize)
		}
		return nil
	}

	numCPU := libbpfNumPossibleCPUs()
	if want := percpuValueSize(m.valueSize, numCPU); numCPU < 0 || valueSize != want {
		return invalid("map '%s': unexpected value size %d provided for per-CPU map, expected %d * %d = %d",
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
