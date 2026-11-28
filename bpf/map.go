// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf

import "github.com/gobpfgo/gobpfgo/libbpf"

// Map is one map of an Object.
//
// A Map keeps its Object but owns nothing: the Object owns the core map and
// its descriptor. After the Object is closed, every Map method with an error
// result returns ErrClosed and the accessors return a zero value, -1 for FD
// and false for IsPinned. Pins on bpffs outlive the Object.
type Map struct {
	m   *libbpf.BpfMap
	obj *Object
}

// live returns the core map, or nil for a nil Map or a closed Object. The
// core accessors return their zero value for nil.
func (m *Map) live() *libbpf.BpfMap {
	if m == nil || m.obj.closed {
		return nil
	}
	return m.m
}

// isClosed reports whether the Map's Object is closed. A nil Map is not
// closed; its methods pass nil to the core, which rejects it.
func (m *Map) isClosed() bool {
	return m != nil && m.obj.closed
}

// Name returns the map name. See libbpf.BpfMapName for the names of the
// internal data maps.
func (m *Map) Name() string {
	return libbpf.BpfMapName(m.live())
}

// Type returns the map type.
func (m *Map) Type() libbpf.BpfMapType {
	return libbpf.BpfMapTypeOf(m.live())
}

// KeySize returns the key size in bytes.
func (m *Map) KeySize() uint32 {
	return libbpf.BpfMapKeySize(m.live())
}

// ValueSize returns the value size in bytes.
func (m *Map) ValueSize() uint32 {
	return libbpf.BpfMapValueSize(m.live())
}

// MaxEntries returns the maximum number of entries.
func (m *Map) MaxEntries() uint32 {
	return libbpf.BpfMapMaxEntries(m.live())
}

// Flags returns the BPF_F_* map flags.
func (m *Map) Flags() uint32 {
	return libbpf.BpfMapMapFlags(m.live())
}

// BtfKeyTypeID returns the BTF type ID of the key, or zero without one.
func (m *Map) BtfKeyTypeID() uint32 {
	return libbpf.BpfMapBtfKeyTypeID(m.live())
}

// BtfValueTypeID returns the BTF type ID of the value, or zero without one.
func (m *Map) BtfValueTypeID() uint32 {
	return libbpf.BpfMapBtfValueTypeID(m.live())
}

// IsInternal reports whether the map is an internal map the object created
// for a .data, .rodata, .bss or .percpu section or for the .kconfig externs,
// rather than a .maps definition.
func (m *Map) IsInternal() bool {
	return libbpf.BpfMapIsInternal(m.live())
}

// FD returns the loaded map descriptor, or -1 before Load, after the Object
// is closed and for a map the load did not create. The descriptor belongs to
// the Object.
func (m *Map) FD() int {
	return libbpf.BpfMapFD(m.live())
}

// Lookup copies the value stored for key into value. key must be KeySize
// bytes; value must be ValueSize bytes, or one 8-byte aligned slot per
// possible CPU for a per-CPU map without a CPU flag. It returns ErrClosed
// after the Object is closed and the core *libbpf.Error otherwise. Before
// Load that is ENOENT, unless ReuseFD gave the map a descriptor. Once Load
// has run, a map without a descriptor, because the Load did not create it
// or failed, is EINVAL, and so is a buffer of the wrong size. A missing key
// is the kernel's ENOENT. See libbpf.BpfMapLookupElem.
func (m *Map) Lookup(key, value []byte, flags uint64) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapLookupElem(m.live(), key, value, flags)
}

// Update stores value for key. key and value follow the sizes of Lookup, and
// flags is BPF_ANY, BPF_NOEXIST or BPF_EXIST, possibly with other BPF_F_*
// bits. A queue or stack map takes an empty key and pushes value. It returns
// ErrClosed after the Object is closed and the core *libbpf.Error otherwise,
// with the errors of Lookup for the map state and the kernel errno of a
// failed update, such as EEXIST for BPF_NOEXIST on an existing key or EPERM
// for a frozen map. See libbpf.BpfMapUpdateElem.
func (m *Map) Update(key, value []byte, flags uint64) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapUpdateElem(m.live(), key, value, flags)
}

// Delete removes key, which must be KeySize bytes. It returns ErrClosed
// after the Object is closed and the core *libbpf.Error otherwise, with the
// errors of Lookup for the map state and the kernel errno of a failed
// delete, such as ENOENT for a missing key or EINVAL for an array map. See
// libbpf.BpfMapDeleteElem.
func (m *Map) Delete(key []byte, flags uint64) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapDeleteElem(m.live(), key, flags)
}

// LookupAndDelete copies the value stored for key into value and removes
// the element in one step. key and value follow the sizes of Lookup; a queue
// or stack map takes an empty key and pops its next element. It returns
// ErrClosed after the Object is closed and the core *libbpf.Error otherwise,
// with the errors of Lookup; a kernel older than 5.14 returns ENOTSUPP (524)
// for a map other than a queue or stack. See
// libbpf.BpfMapLookupAndDeleteElem.
func (m *Map) LookupAndDelete(key, value []byte, flags uint64) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapLookupAndDeleteElem(m.live(), key, value, flags)
}

// NextKey copies the key that follows curKey into nextKey; an empty curKey
// asks for the first key. Both are KeySize bytes, curKey unless it is empty.
// After the last key it returns the core ENOENT error. It returns ErrClosed
// after the Object is closed and the core *libbpf.Error otherwise, with the
// errors of Lookup for the map state. See libbpf.BpfMapGetNextKey.
func (m *Map) NextKey(curKey, nextKey []byte) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapGetNextKey(m.live(), curKey, nextKey)
}

// InitialValue returns the initial value of an internal data or .kconfig
// map, ValueSize bytes that alias the Object's buffer, or nil for a .maps
// definition and after the Object is closed. Before Load, changing the bytes
// changes what Load writes into the map; after Load they no longer affect
// the map. See libbpf.BpfMapInitialValue.
func (m *Map) InitialValue() []byte {
	return libbpf.BpfMapInitialValue(m.live())
}

// SetInitialValue replaces the initial value of an internal data map with a
// copy of data, which must be ValueSize bytes, so Load writes it into the
// map. It returns ErrClosed after the Object is closed and the core
// *libbpf.Error otherwise: EBUSY after ReuseFD or once Load has run, even a
// failed one, and EINVAL for a .maps definition, the .kconfig map or data of
// another size. See libbpf.BpfMapSetInitialValue.
func (m *Map) SetInitialValue(data []byte) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapSetInitialValue(m.live(), data)
}

// SetPinPath stores the path Pin and Unpin use when called with nil; a nil
// path clears it. It does not touch bpffs. It returns ErrClosed after the
// Object is closed.
func (m *Map) SetPinPath(path *string) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapSetPinPath(m.live(), path)
}

// PinPath returns the stored pin path, set by SetPinPath or by a Pin with a
// path, or an empty string. Unpin keeps it.
func (m *Map) PinPath() string {
	return libbpf.BpfMapPinPath(m.live())
}

// Pin pins the loaded map on bpffs at path, or at the stored pin path when
// path is nil. It returns ErrClosed after the Object is closed and the core
// *libbpf.Error otherwise. See libbpf.BpfMapPin.
func (m *Map) Pin(path *string) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapPin(m.live(), path)
}

// Unpin removes the map's pin at path, or at the stored pin path when path
// is nil. The map descriptor stays open. It returns ErrClosed after the
// Object is closed and the core *libbpf.Error otherwise.
func (m *Map) Unpin(path *string) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapUnpin(m.live(), path)
}

// IsPinned reports whether Pin pinned the map. It returns false after the
// Object is closed, even though the bpffs pin remains.
func (m *Map) IsPinned() bool {
	return libbpf.BpfMapIsPinned(m.live())
}

// ReuseFD makes Load use the existing kernel map fd instead of creating
// this map. The Object keeps a duplicate of fd and the caller keeps fd. Call
// it before Load. It returns ErrClosed after the Object is closed and the core
// *libbpf.Error otherwise. See libbpf.BpfMapReuseFD.
func (m *Map) ReuseFD(fd int) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapReuseFD(m.live(), fd)
}
