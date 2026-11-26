// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map_create

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"reflect"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfMapCreateOpts controls optional attributes of a new map.
//
// Zero is the default for every field. Sz must be zero or the size returned by
// NewBpfMapCreateOpts; a mismatched size makes BpfMapCreate return EINVAL.
// The libbpf LogOpts field is not ported yet.
type BpfMapCreateOpts struct {
	// Sz is the layout size for forward compatibility. Set it with
	// NewBpfMapCreateOpts; zero means the current layout.
	Sz uintptr

	// BtfFD is the BTF object that describes the key and value types.
	BtfFD uint32
	// BtfKeyTypeID is the BTF type ID of the key.
	BtfKeyTypeID uint32
	// BtfValueTypeID is the BTF type ID of the value.
	BtfValueTypeID uint32
	// BtfVmlinuxValueTypeID is the BTF type ID of a kernel struct stored as
	// the map value.
	BtfVmlinuxValueTypeID uint32

	// InnerMapFD is the inner map template for map-in-map types.
	InnerMapFD uint32
	// MapFlags are the BPF_F_* flags from linux/bpf.h.
	MapFlags uint32
	// MapExtra is the per-map-type extra value.
	MapExtra uint64

	// NumaNode is the NUMA node when BPF_F_NUMA_NODE is set.
	NumaNode uint32
	// MapIfindex is the netdev index for offloaded maps.
	MapIfindex uint32
	// ValueTypeBtfObjFD is the BTF object fd for a value type that lives in
	// another BTF object.
	ValueTypeBtfObjFD int32

	// TokenFD is the BPF token fd, when the kernel and privileges allow it.
	TokenFD uint32

	// ExclProgHash is the program hash for exclusive map ownership. The
	// slice supplies both the pointer and the length.
	ExclProgHash []byte
}

var bpfMapCreateOptsSize = reflect.TypeOf(BpfMapCreateOpts{}).Size()

// NewBpfMapCreateOpts returns options with Sz set to the current layout.
//
// Use it whenever any field is set; BpfMapCreate rejects a non-zero Sz that
// does not match the current layout.
func NewBpfMapCreateOpts() *BpfMapCreateOpts {
	return &BpfMapCreateOpts{Sz: bpfMapCreateOptsSize}
}

// BpfMapCreate creates a BPF map and returns its file descriptor.
//
// mapType, keySize, valueSize and maxEntries describe the map. name is the
// optional object name; it is truncated to 15 bytes and NUL-terminated like
// the kernel's object names. The kernel accepts letters, digits, '_' and '.'
// in the name; other characters make the call fail with EINVAL. opts may be
// nil.
//
// The caller owns the descriptor and must close it with unix.Close. A failed
// call returns a negative descriptor and an *Error with the kernel errno.
func BpfMapCreate(mapType BpfMapType, name string, keySize, valueSize, maxEntries uint32, opts *BpfMapCreateOpts) (int, error) {
	if opts != nil && opts.Sz != 0 && opts.Sz != bpfMapCreateOptsSize {
		return -1, &Error{Op: "bpf_map_create", Errno: unix.EINVAL}
	}

	attr := &sys.MapCreateAttr{
		MapType:    uint32(mapType),
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
	attr.SetMapName(name)

	var exclHash []byte
	if opts != nil {
		attr.BtfFD = opts.BtfFD
		attr.BtfKeyTypeID = opts.BtfKeyTypeID
		attr.BtfValueTypeID = opts.BtfValueTypeID
		attr.BtfVmlinuxValueTypeID = opts.BtfVmlinuxValueTypeID
		attr.InnerMapFD = opts.InnerMapFD
		attr.MapFlags = opts.MapFlags
		attr.MapExtra = opts.MapExtra
		attr.NumaNode = opts.NumaNode
		attr.MapIfindex = opts.MapIfindex
		attr.ValueTypeBtfObjFD = opts.ValueTypeBtfObjFD
		attr.MapTokenFD = int32(opts.TokenFD)
		exclHash = opts.ExclProgHash
	}

	fd, err := sys.MapCreate(attr, exclHash)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			return -1, &Error{Op: "bpf_map_create", Errno: errno}
		}
		return -1, err
	}
	return fd, nil
}
