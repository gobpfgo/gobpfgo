// SPDX-License-Identifier: LGPL-2.1-only
// Ported from libbpf src/bpf.c at 4f05fb0.

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"reflect"
	"syscall"

	"github.com/golbpfgo/golbpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfMapCreateOpts mirrors struct bpf_map_create_opts.
//
// Sz must be zero or the size returned by NewBpfMapCreateOpts. The LogOpts
// field is not ported yet.
type BpfMapCreateOpts struct {
	Sz uintptr

	BtfFD                 uint32
	BtfKeyTypeID          uint32
	BtfValueTypeID        uint32
	BtfVmlinuxValueTypeID uint32

	InnerMapFD uint32
	MapFlags   uint32
	MapExtra   uint64

	NumaNode          uint32
	MapIfindex        uint32
	ValueTypeBtfObjFD int32

	TokenFD uint32

	ExclProgHash []byte
}

var bpfMapCreateOptsSize = reflect.TypeOf(BpfMapCreateOpts{}).Size()

// NewBpfMapCreateOpts returns options with Sz set to the current size.
func NewBpfMapCreateOpts() *BpfMapCreateOpts {
	return &BpfMapCreateOpts{Sz: bpfMapCreateOptsSize}
}

// BpfMapCreate creates a BPF map, mirroring bpf_map_create() in libbpf
// src/bpf.c. It returns the new map file descriptor; the caller closes it.
//
// opts may be nil. When non-nil, Sz must be zero or the current
// BpfMapCreateOpts size.
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
