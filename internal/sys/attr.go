// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/bpf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: union bpf_attr

//go:build linux && (amd64 || arm64)

package sys

import "encoding/binary"

// MapCreateAttrSize is offsetofend(union bpf_attr, excl_prog_hash_size) on
// 64-bit Linux. It is the size libbpf passes to BPF_MAP_CREATE.
const MapCreateAttrSize = 92

// Offsets inside union bpf_attr for the BPF_MAP_CREATE command, from
// offsetof(union bpf_attr, field) on 64-bit Linux.
const (
	mapCreateOffMapType               = 0
	mapCreateOffKeySize               = 4
	mapCreateOffValueSize             = 8
	mapCreateOffMaxEntries            = 12
	mapCreateOffMapFlags              = 16
	mapCreateOffInnerMapFD            = 20
	mapCreateOffNumaNode              = 24
	mapCreateOffMapName               = 28
	mapCreateOffMapIfindex            = 44
	mapCreateOffBtfFD                 = 48
	mapCreateOffBtfKeyTypeID          = 52
	mapCreateOffBtfValueTypeID        = 56
	mapCreateOffBtfVmlinuxValueTypeID = 60
	mapCreateOffMapExtra              = 64
	mapCreateOffValueTypeBtfObjFD     = 72
	mapCreateOffMapTokenFD            = 76
	mapCreateOffExclProgHash          = 80
	mapCreateOffExclProgHashSize      = 88
)

// MapCreateAttr is the BPF_MAP_CREATE view of union bpf_attr. Marshal writes
// the fields at the offsets in the layout table; fields left zero stay zero.
type MapCreateAttr struct {
	MapType               uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	InnerMapFD            uint32
	NumaNode              uint32
	MapName               [BPF_OBJ_NAME_LEN]byte
	MapIfindex            uint32
	BtfFD                 uint32
	BtfKeyTypeID          uint32
	BtfValueTypeID        uint32
	BtfVmlinuxValueTypeID uint32
	MapExtra              uint64
	ValueTypeBtfObjFD     int32
	MapTokenFD            int32
	ExclProgHash          uint64
	ExclProgHashSize      uint32
}

// SetMapName copies name into the 16-byte map_name field the way libbpf's
// libbpf_strlcpy does: truncate to 15 bytes and NUL-terminate.
func (a *MapCreateAttr) SetMapName(name string) {
	a.MapName = [BPF_OBJ_NAME_LEN]byte{}
	if len(name) > BPF_OBJ_NAME_LEN-1 {
		name = name[:BPF_OBJ_NAME_LEN-1]
	}
	copy(a.MapName[:], name)
}

// Marshal returns the bytes passed to bpf(BPF_MAP_CREATE, ...).
func (a *MapCreateAttr) Marshal() []byte {
	buf := make([]byte, MapCreateAttrSize)

	binary.NativeEndian.PutUint32(buf[mapCreateOffMapType:], a.MapType)
	binary.NativeEndian.PutUint32(buf[mapCreateOffKeySize:], a.KeySize)
	binary.NativeEndian.PutUint32(buf[mapCreateOffValueSize:], a.ValueSize)
	binary.NativeEndian.PutUint32(buf[mapCreateOffMaxEntries:], a.MaxEntries)
	binary.NativeEndian.PutUint32(buf[mapCreateOffMapFlags:], a.MapFlags)
	binary.NativeEndian.PutUint32(buf[mapCreateOffInnerMapFD:], a.InnerMapFD)
	binary.NativeEndian.PutUint32(buf[mapCreateOffNumaNode:], a.NumaNode)
	copy(buf[mapCreateOffMapName:mapCreateOffMapName+BPF_OBJ_NAME_LEN], a.MapName[:])
	binary.NativeEndian.PutUint32(buf[mapCreateOffMapIfindex:], a.MapIfindex)
	binary.NativeEndian.PutUint32(buf[mapCreateOffBtfFD:], a.BtfFD)
	binary.NativeEndian.PutUint32(buf[mapCreateOffBtfKeyTypeID:], a.BtfKeyTypeID)
	binary.NativeEndian.PutUint32(buf[mapCreateOffBtfValueTypeID:], a.BtfValueTypeID)
	binary.NativeEndian.PutUint32(buf[mapCreateOffBtfVmlinuxValueTypeID:], a.BtfVmlinuxValueTypeID)
	binary.NativeEndian.PutUint64(buf[mapCreateOffMapExtra:], a.MapExtra)
	binary.NativeEndian.PutUint32(buf[mapCreateOffValueTypeBtfObjFD:], uint32(a.ValueTypeBtfObjFD))
	binary.NativeEndian.PutUint32(buf[mapCreateOffMapTokenFD:], uint32(a.MapTokenFD))
	binary.NativeEndian.PutUint64(buf[mapCreateOffExclProgHash:], a.ExclProgHash)
	binary.NativeEndian.PutUint32(buf[mapCreateOffExclProgHashSize:], a.ExclProgHashSize)

	return buf
}

type fieldLayout struct {
	Name   string
	Offset int
	Size   int
}

// mapCreateFieldLayout is the Go claim about the C layout. The layout test
// compares it with the oracle output.
func mapCreateFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"map_type", mapCreateOffMapType, 4},
		{"key_size", mapCreateOffKeySize, 4},
		{"value_size", mapCreateOffValueSize, 4},
		{"max_entries", mapCreateOffMaxEntries, 4},
		{"map_flags", mapCreateOffMapFlags, 4},
		{"inner_map_fd", mapCreateOffInnerMapFD, 4},
		{"numa_node", mapCreateOffNumaNode, 4},
		{"map_name", mapCreateOffMapName, BPF_OBJ_NAME_LEN},
		{"map_ifindex", mapCreateOffMapIfindex, 4},
		{"btf_fd", mapCreateOffBtfFD, 4},
		{"btf_key_type_id", mapCreateOffBtfKeyTypeID, 4},
		{"btf_value_type_id", mapCreateOffBtfValueTypeID, 4},
		{"btf_vmlinux_value_type_id", mapCreateOffBtfVmlinuxValueTypeID, 4},
		{"map_extra", mapCreateOffMapExtra, 8},
		{"value_type_btf_obj_fd", mapCreateOffValueTypeBtfObjFD, 4},
		{"map_token_fd", mapCreateOffMapTokenFD, 4},
		{"excl_prog_hash", mapCreateOffExclProgHash, 8},
		{"excl_prog_hash_size", mapCreateOffExclProgHashSize, 4},
	}
}
