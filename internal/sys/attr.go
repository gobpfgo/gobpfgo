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

// MapElemAttrSize is offsetofend(union bpf_attr, flags) on 64-bit Linux. It is
// the size libbpf passes to the BPF_MAP_*_ELEM commands.
const MapElemAttrSize = 32

// Offsets inside union bpf_attr for the BPF_MAP_LOOKUP_ELEM command, from
// offsetof(union bpf_attr, field) on 64-bit Linux.
const (
	mapElemOffMapFD = 0
	mapElemOffKey   = 8
	mapElemOffValue = 16
	mapElemOffFlags = 24
)

// MapElemAttr is the BPF_MAP_*_ELEM view of union bpf_attr. Key and Value are
// the addresses of the caller's buffers; MapLookupElem fills the value in and
// MapUpdateElem reads both.
type MapElemAttr struct {
	MapFD uint32
	Key   uint64
	Value uint64
	Flags uint64
}

// Marshal returns the bytes passed to bpf(BPF_MAP_LOOKUP_ELEM, ...).
func (a *MapElemAttr) Marshal() []byte {
	buf := make([]byte, MapElemAttrSize)

	binary.NativeEndian.PutUint32(buf[mapElemOffMapFD:], a.MapFD)
	binary.NativeEndian.PutUint64(buf[mapElemOffKey:], a.Key)
	binary.NativeEndian.PutUint64(buf[mapElemOffValue:], a.Value)
	binary.NativeEndian.PutUint64(buf[mapElemOffFlags:], a.Flags)

	return buf
}

// MapFreezeAttrSize is offsetofend(union bpf_attr, map_fd) on 64-bit Linux. It
// is the size libbpf passes to BPF_MAP_FREEZE, which reads only the map fd of
// the BPF_MAP_*_ELEM view.
const MapFreezeAttrSize = 4

// MapFreezeAttr is the BPF_MAP_FREEZE view of union bpf_attr.
type MapFreezeAttr struct {
	MapFD uint32
}

// Marshal returns the bytes passed to bpf(BPF_MAP_FREEZE, ...).
func (a *MapFreezeAttr) Marshal() []byte {
	buf := make([]byte, MapFreezeAttrSize)
	binary.NativeEndian.PutUint32(buf[mapElemOffMapFD:], a.MapFD)
	return buf
}

// ObjPinAttrSize is offsetofend(union bpf_attr, path_fd) on 64-bit Linux. It
// is the size libbpf passes to BPF_OBJ_PIN and BPF_OBJ_GET.
const ObjPinAttrSize = 20

// Offsets inside union bpf_attr for the BPF_OBJ_* commands, from
// offsetof(union bpf_attr, field) on 64-bit Linux.
const (
	objPinOffPathname  = 0
	objPinOffBPFFD     = 8
	objPinOffFileFlags = 12
	objPinOffPathFD    = 16
)

// ObjPinAttr is the BPF_OBJ_PIN view of union bpf_attr. Pathname is the
// address of a NUL-terminated path on bpffs; ObjPin fills it in.
type ObjPinAttr struct {
	Pathname  uint64
	BPFFD     uint32
	FileFlags uint32
	PathFD    int32
}

// Marshal returns the bytes passed to bpf(BPF_OBJ_PIN, ...).
func (a *ObjPinAttr) Marshal() []byte {
	buf := make([]byte, ObjPinAttrSize)

	binary.NativeEndian.PutUint64(buf[objPinOffPathname:], a.Pathname)
	binary.NativeEndian.PutUint32(buf[objPinOffBPFFD:], a.BPFFD)
	binary.NativeEndian.PutUint32(buf[objPinOffFileFlags:], a.FileFlags)
	binary.NativeEndian.PutUint32(buf[objPinOffPathFD:], uint32(a.PathFD))

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

// mapElemFieldLayout is the Go claim about the C layout of the element
// command fields. The layout test compares it with the oracle output.
func mapElemFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"map_fd", mapElemOffMapFD, 4},
		{"key", mapElemOffKey, 8},
		{"value", mapElemOffValue, 8},
		{"flags", mapElemOffFlags, 8},
	}
}

// objPinFieldLayout is the Go claim about the C layout of the BPF_OBJ_PIN
// fields. The layout test compares it with the oracle output.
func objPinFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"pathname", objPinOffPathname, 8},
		{"bpf_fd", objPinOffBPFFD, 4},
		{"file_flags", objPinOffFileFlags, 4},
		{"path_fd", objPinOffPathFD, 4},
	}
}
