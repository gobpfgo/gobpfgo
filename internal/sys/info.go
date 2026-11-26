// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_obj_get_info_by_fd, bpf_map_get_info_by_fd, bpf_prog_get_info_by_fd

//go:build linux && (amd64 || arm64)

package sys

import (
	"bytes"
	"encoding/binary"
	"runtime"
)

// ObjInfoAttrSize is offsetofend(union bpf_attr, info) on 64-bit Linux.
const ObjInfoAttrSize = 16

// Offsets inside union bpf_attr for BPF_OBJ_GET_INFO_BY_FD.
const (
	objInfoOffBpfFD   = 0
	objInfoOffInfoLen = 4
	objInfoOffInfo    = 8
)

// ObjInfoAttr is the BPF_OBJ_GET_INFO_BY_FD view of union bpf_attr.
type ObjInfoAttr struct {
	BpfFD   uint32
	InfoLen uint32
	Info    uint64
}

// Marshal returns the bytes for bpf(BPF_OBJ_GET_INFO_BY_FD, ...).
func (a *ObjInfoAttr) Marshal() []byte {
	buf := make([]byte, ObjInfoAttrSize)

	binary.NativeEndian.PutUint32(buf[objInfoOffBpfFD:], a.BpfFD)
	binary.NativeEndian.PutUint32(buf[objInfoOffInfoLen:], a.InfoLen)
	binary.NativeEndian.PutUint64(buf[objInfoOffInfo:], a.Info)

	return buf
}

func objInfoFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"bpf_fd", objInfoOffBpfFD, 4},
		{"info_len", objInfoOffInfoLen, 4},
		{"info", objInfoOffInfo, 8},
	}
}

// MapInfoSize is sizeof(struct bpf_map_info).
const MapInfoSize = 104

// Offsets in struct bpf_map_info for the fields this port reads.
const (
	mapInfoOffType           = 0
	mapInfoOffID             = 4
	mapInfoOffKeySize        = 8
	mapInfoOffValueSize      = 12
	mapInfoOffMaxEntries     = 16
	mapInfoOffMapFlags       = 20
	mapInfoOffName           = 24
	mapInfoOffBtfKeyTypeID   = 68
	mapInfoOffBtfValueTypeID = 72
)

// MapInfo is the map metadata returned by BPF_OBJ_GET_INFO_BY_FD.
type MapInfo struct {
	Type           uint32
	ID             uint32
	KeySize        uint32
	ValueSize      uint32
	MaxEntries     uint32
	MapFlags       uint32
	Name           string
	BtfKeyTypeID   uint32
	BtfValueTypeID uint32
}

func mapInfoFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"type", mapInfoOffType, 4},
		{"id", mapInfoOffID, 4},
		{"key_size", mapInfoOffKeySize, 4},
		{"value_size", mapInfoOffValueSize, 4},
		{"max_entries", mapInfoOffMaxEntries, 4},
		{"map_flags", mapInfoOffMapFlags, 4},
		{"name", mapInfoOffName, BPF_OBJ_NAME_LEN},
		{"btf_key_type_id", mapInfoOffBtfKeyTypeID, 4},
		{"btf_value_type_id", mapInfoOffBtfValueTypeID, 4},
	}
}

// ProgInfoSize is sizeof(struct bpf_prog_info).
const ProgInfoSize = 232

// Offsets in struct bpf_prog_info for the fields this port reads.
const (
	progInfoOffType          = 0
	progInfoOffID            = 4
	progInfoOffJitedProgLen  = 16
	progInfoOffXlatedProgLen = 20
	progInfoOffName          = 64
)

// ProgInfo is the program metadata returned by BPF_OBJ_GET_INFO_BY_FD.
type ProgInfo struct {
	Type          uint32
	ID            uint32
	JitedProgLen  uint32
	XlatedProgLen uint32
	Name          string
}

func progInfoFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"type", progInfoOffType, 4},
		{"id", progInfoOffID, 4},
		{"jited_prog_len", progInfoOffJitedProgLen, 4},
		{"xlated_prog_len", progInfoOffXlatedProgLen, 4},
		{"name", progInfoOffName, BPF_OBJ_NAME_LEN},
	}
}

// MapInfoByFD returns the kernel metadata for a map descriptor.
func MapInfoByFD(fd int) (*MapInfo, error) {
	buf := make([]byte, MapInfoSize)
	attr := &ObjInfoAttr{
		BpfFD:   uint32(fd),
		InfoLen: uint32(len(buf)),
		Info:    uint64(addr(buf)),
	}

	if _, err := bpf(BPF_OBJ_GET_INFO_BY_FD, attr.Marshal()); err != nil {
		return nil, err
	}
	runtime.KeepAlive(buf)

	return &MapInfo{
		Type:           binary.NativeEndian.Uint32(buf[mapInfoOffType:]),
		ID:             binary.NativeEndian.Uint32(buf[mapInfoOffID:]),
		KeySize:        binary.NativeEndian.Uint32(buf[mapInfoOffKeySize:]),
		ValueSize:      binary.NativeEndian.Uint32(buf[mapInfoOffValueSize:]),
		MaxEntries:     binary.NativeEndian.Uint32(buf[mapInfoOffMaxEntries:]),
		MapFlags:       binary.NativeEndian.Uint32(buf[mapInfoOffMapFlags:]),
		Name:           cString(buf, mapInfoOffName, BPF_OBJ_NAME_LEN),
		BtfKeyTypeID:   binary.NativeEndian.Uint32(buf[mapInfoOffBtfKeyTypeID:]),
		BtfValueTypeID: binary.NativeEndian.Uint32(buf[mapInfoOffBtfValueTypeID:]),
	}, nil
}

// ProgInfoByFD returns the kernel metadata for a program descriptor.
func ProgInfoByFD(fd int) (*ProgInfo, error) {
	buf := make([]byte, ProgInfoSize)
	attr := &ObjInfoAttr{
		BpfFD:   uint32(fd),
		InfoLen: uint32(len(buf)),
		Info:    uint64(addr(buf)),
	}

	if _, err := bpf(BPF_OBJ_GET_INFO_BY_FD, attr.Marshal()); err != nil {
		return nil, err
	}
	runtime.KeepAlive(buf)

	return &ProgInfo{
		Type:          binary.NativeEndian.Uint32(buf[progInfoOffType:]),
		ID:            binary.NativeEndian.Uint32(buf[progInfoOffID:]),
		JitedProgLen:  binary.NativeEndian.Uint32(buf[progInfoOffJitedProgLen:]),
		XlatedProgLen: binary.NativeEndian.Uint32(buf[progInfoOffXlatedProgLen:]),
		Name:          cString(buf, progInfoOffName, BPF_OBJ_NAME_LEN),
	}, nil
}

func cString(buf []byte, off, size int) string {
	b := buf[off : off+size]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
