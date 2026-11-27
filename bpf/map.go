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
// after the Object is closed and the core *libbpf.Error otherwise, with
// EBADF before Load and ENOENT for a missing key. See
// libbpf.BpfMapLookupElem.
func (m *Map) Lookup(key, value []byte, flags uint64) error {
	if m.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfMapLookupElem(m.live(), key, value, flags)
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
