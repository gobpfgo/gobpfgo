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
	progInfoOffType                 = 0
	progInfoOffID                   = 4
	progInfoOffJitedProgLen         = 16
	progInfoOffXlatedProgLen        = 20
	progInfoOffName                 = 64
	progInfoOffNrJitedKsyms         = 104
	progInfoOffNrJitedFuncLens      = 108
	progInfoOffJitedKsyms           = 112
	progInfoOffJitedFuncLens        = 120
	progInfoOffBtfID                = 128
	progInfoOffNrLineInfo           = 148
	progInfoOffLineInfo             = 152
	progInfoOffJitedLineInfo        = 160
	progInfoOffNrJitedLineInfo      = 168
	progInfoOffLineInfoRecSize      = 172
	progInfoOffJitedLineInfoRecSize = 176
)

// ProgInfo is the program metadata returned by BPF_OBJ_GET_INFO_BY_FD.
//
// BtfID is the id of the program's BTF object, or 0 for a program loaded
// without BTF.
//
// LineInfo holds NrLineInfo records of LineInfoRecSize bytes in the struct
// bpf_line_info layout. JitedLineInfo holds NrJitedLineInfo records of
// JitedLineInfoRecSize bytes, each starting with the jited address of the
// matching line record. JitedKsyms and JitedFuncLens hold the start address
// and the length of each jited function. An array is nil when its count is
// zero or the kernel did not copy it.
type ProgInfo struct {
	Type                 uint32
	ID                   uint32
	JitedProgLen         uint32
	XlatedProgLen        uint32
	BtfID                uint32
	Name                 string
	NrJitedKsyms         uint32
	NrJitedFuncLens      uint32
	JitedKsyms           []uint64
	JitedFuncLens        []uint32
	NrLineInfo           uint32
	LineInfo             []byte
	JitedLineInfo        []byte
	NrJitedLineInfo      uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
}

func progInfoFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"type", progInfoOffType, 4},
		{"id", progInfoOffID, 4},
		{"jited_prog_len", progInfoOffJitedProgLen, 4},
		{"xlated_prog_len", progInfoOffXlatedProgLen, 4},
		{"name", progInfoOffName, BPF_OBJ_NAME_LEN},
		{"nr_jited_ksyms", progInfoOffNrJitedKsyms, 4},
		{"nr_jited_func_lens", progInfoOffNrJitedFuncLens, 4},
		{"jited_ksyms", progInfoOffJitedKsyms, 8},
		{"jited_func_lens", progInfoOffJitedFuncLens, 8},
		{"btf_id", progInfoOffBtfID, 4},
		{"nr_line_info", progInfoOffNrLineInfo, 4},
		{"line_info", progInfoOffLineInfo, 8},
		{"jited_line_info", progInfoOffJitedLineInfo, 8},
		{"nr_jited_line_info", progInfoOffNrJitedLineInfo, 4},
		{"line_info_rec_size", progInfoOffLineInfoRecSize, 4},
		{"jited_line_info_rec_size", progInfoOffJitedLineInfoRecSize, 4},
	}
}

// progInfoArray is one variable-length array of struct bpf_prog_info: the
// offsets of its element count and user pointer, and either the offset of its
// record size or a fixed element size.
type progInfoArray struct {
	countOff   int
	ptrOff     int
	recSizeOff int
	elemSize   uint32
}

// The arrays ProgInfoByFD asks the kernel to fill.
var (
	progInfoJitedKsyms    = progInfoArray{countOff: progInfoOffNrJitedKsyms, ptrOff: progInfoOffJitedKsyms, elemSize: 8}
	progInfoJitedFuncLens = progInfoArray{countOff: progInfoOffNrJitedFuncLens, ptrOff: progInfoOffJitedFuncLens, elemSize: 4}
	progInfoLineInfo      = progInfoArray{countOff: progInfoOffNrLineInfo, ptrOff: progInfoOffLineInfo, recSizeOff: progInfoOffLineInfoRecSize}
	progInfoJitedLineInfo = progInfoArray{countOff: progInfoOffNrJitedLineInfo, ptrOff: progInfoOffJitedLineInfo, recSizeOff: progInfoOffJitedLineInfoRecSize}
)

func (a progInfoArray) recSize(info []byte) uint32 {
	if a.elemSize != 0 {
		return a.elemSize
	}
	return binary.NativeEndian.Uint32(info[a.recSizeOff:])
}

// request allocates the array the kernel reported in first and points req at
// it. It returns nil and leaves req untouched when the array is empty.
func (a progInfoArray) request(first, req []byte) []byte {
	count := binary.NativeEndian.Uint32(first[a.countOff:])
	recSize := a.recSize(first)
	if count == 0 || recSize == 0 {
		return nil
	}

	buf := make([]byte, int(count)*int(recSize))
	binary.NativeEndian.PutUint32(req[a.countOff:], count)
	if a.elemSize == 0 {
		binary.NativeEndian.PutUint32(req[a.recSizeOff:], recSize)
	}
	binary.NativeEndian.PutUint64(req[a.ptrOff:], uint64(addr(buf)))
	return buf
}

// result returns the part of buf the kernel filled. It returns nil when the
// array was not requested or the kernel cleared the pointer instead of
// copying, which it does for the jited arrays when the caller may not read
// kernel addresses.
func (a progInfoArray) result(info, buf []byte) []byte {
	if buf == nil || binary.NativeEndian.Uint64(info[a.ptrOff:]) == 0 {
		return nil
	}
	n := uint64(binary.NativeEndian.Uint32(info[a.countOff:])) * uint64(a.recSize(info))
	if n < uint64(len(buf)) {
		buf = buf[:n]
	}
	return buf
}

// progInfoBufs holds the arrays of the second BPF_OBJ_GET_INFO_BY_FD call.
type progInfoBufs struct {
	jitedKsyms    []byte
	jitedFuncLens []byte
	lineInfo      []byte
	jitedLineInfo []byte
}

// newProgInfoRequest builds the second call from the counts and record sizes
// the kernel reported in first. Every other field is zero, so the kernel
// copies only these arrays.
func newProgInfoRequest(first []byte) ([]byte, *progInfoBufs) {
	req := make([]byte, ProgInfoSize)
	bufs := &progInfoBufs{
		jitedKsyms:    progInfoJitedKsyms.request(first, req),
		jitedFuncLens: progInfoJitedFuncLens.request(first, req),
		lineInfo:      progInfoLineInfo.request(first, req),
		jitedLineInfo: progInfoJitedLineInfo.request(first, req),
	}
	return req, bufs
}

// decodeProgInfo decodes a filled struct bpf_prog_info and the arrays the
// kernel copied into bufs.
func decodeProgInfo(info []byte, bufs *progInfoBufs) *ProgInfo {
	return &ProgInfo{
		Type:                 binary.NativeEndian.Uint32(info[progInfoOffType:]),
		ID:                   binary.NativeEndian.Uint32(info[progInfoOffID:]),
		JitedProgLen:         binary.NativeEndian.Uint32(info[progInfoOffJitedProgLen:]),
		XlatedProgLen:        binary.NativeEndian.Uint32(info[progInfoOffXlatedProgLen:]),
		BtfID:                binary.NativeEndian.Uint32(info[progInfoOffBtfID:]),
		Name:                 cString(info, progInfoOffName, BPF_OBJ_NAME_LEN),
		NrJitedKsyms:         binary.NativeEndian.Uint32(info[progInfoOffNrJitedKsyms:]),
		NrJitedFuncLens:      binary.NativeEndian.Uint32(info[progInfoOffNrJitedFuncLens:]),
		JitedKsyms:           uint64s(progInfoJitedKsyms.result(info, bufs.jitedKsyms)),
		JitedFuncLens:        uint32s(progInfoJitedFuncLens.result(info, bufs.jitedFuncLens)),
		NrLineInfo:           binary.NativeEndian.Uint32(info[progInfoOffNrLineInfo:]),
		LineInfo:             progInfoLineInfo.result(info, bufs.lineInfo),
		JitedLineInfo:        progInfoJitedLineInfo.result(info, bufs.jitedLineInfo),
		NrJitedLineInfo:      binary.NativeEndian.Uint32(info[progInfoOffNrJitedLineInfo:]),
		LineInfoRecSize:      binary.NativeEndian.Uint32(info[progInfoOffLineInfoRecSize:]),
		JitedLineInfoRecSize: binary.NativeEndian.Uint32(info[progInfoOffJitedLineInfoRecSize:]),
	}
}

// MapInfoByFD returns the kernel metadata for a map descriptor.
func MapInfoByFD(fd int) (*MapInfo, error) {
	buf := make([]byte, MapInfoSize)
	if err := objInfoByFD(fd, buf); err != nil {
		return nil, err
	}

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

// ProgInfoByFD returns the kernel metadata for a program descriptor,
// including its line info, jited line info, jited function addresses and
// jited function lengths.
//
// It calls BPF_OBJ_GET_INFO_BY_FD twice. The first call has no array pointers
// and returns the counts and record sizes; the second passes buffers of those
// sizes. The kernel withholds the jited arrays from a caller that may not
// read kernel addresses: their counts are still set, but the arrays are nil.
func ProgInfoByFD(fd int) (*ProgInfo, error) {
	first := make([]byte, ProgInfoSize)
	if err := objInfoByFD(fd, first); err != nil {
		return nil, err
	}

	req, bufs := newProgInfoRequest(first)
	err := objInfoByFD(fd, req)
	runtime.KeepAlive(bufs)
	if err != nil {
		return nil, err
	}
	return decodeProgInfo(req, bufs), nil
}

// objInfoByFD fills info with BPF_OBJ_GET_INFO_BY_FD for a descriptor.
func objInfoByFD(fd int, info []byte) error {
	attr := &ObjInfoAttr{
		BpfFD:   uint32(fd),
		InfoLen: uint32(len(info)),
		Info:    uint64(addr(info)),
	}

	_, err := bpf(BPF_OBJ_GET_INFO_BY_FD, attr.Marshal())
	runtime.KeepAlive(info)
	return err
}

func cString(buf []byte, off, size int) string {
	b := buf[off : off+size]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func uint64s(buf []byte) []uint64 {
	if buf == nil {
		return nil
	}
	out := make([]uint64, len(buf)/8)
	for i := range out {
		out[i] = binary.NativeEndian.Uint64(buf[i*8:])
	}
	return out
}

func uint32s(buf []byte) []uint32 {
	if buf == nil {
		return nil
	}
	out := make([]uint32, len(buf)/4)
	for i := range out {
		out[i] = binary.NativeEndian.Uint32(buf[i*4:])
	}
	return out
}
