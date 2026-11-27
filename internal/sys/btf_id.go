// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_obj_get_next_id, bpf_btf_get_next_id, bpf_btf_get_fd_by_id, bpf_btf_get_fd_by_id_opts, bpf_btf_get_info_by_fd

//go:build linux && (amd64 || arm64)

package sys

import (
	"encoding/binary"
	"runtime"
)

// GetNextIDAttrSize is offsetofend(union bpf_attr, open_flags) on 64-bit
// Linux. It is the size libbpf passes to the *_GET_NEXT_ID commands.
const GetNextIDAttrSize = 12

// Offsets inside union bpf_attr for the *_GET_NEXT_ID commands.
const (
	getNextIDOffStartID   = 0
	getNextIDOffNextID    = 4
	getNextIDOffOpenFlags = 8
)

// GetNextIDAttr is the *_GET_NEXT_ID view of union bpf_attr. The kernel
// writes the ID after StartID into NextID.
type GetNextIDAttr struct {
	StartID   uint32
	NextID    uint32
	OpenFlags uint32
}

// Marshal returns the bytes for bpf(BPF_BTF_GET_NEXT_ID, ...).
func (a *GetNextIDAttr) Marshal() []byte {
	buf := make([]byte, GetNextIDAttrSize)

	binary.NativeEndian.PutUint32(buf[getNextIDOffStartID:], a.StartID)
	binary.NativeEndian.PutUint32(buf[getNextIDOffNextID:], a.NextID)
	binary.NativeEndian.PutUint32(buf[getNextIDOffOpenFlags:], a.OpenFlags)

	return buf
}

func getNextIDFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"start_id", getNextIDOffStartID, 4},
		{"next_id", getNextIDOffNextID, 4},
		{"open_flags", getNextIDOffOpenFlags, 4},
	}
}

// BtfGetFDByIDAttrSize is offsetofend(union bpf_attr, fd_by_id_token_fd) on
// 64-bit Linux. It is the size libbpf passes to BPF_BTF_GET_FD_BY_ID.
const BtfGetFDByIDAttrSize = 16

// Offsets inside union bpf_attr for BPF_BTF_GET_FD_BY_ID.
const (
	btfGetFDByIDOffBtfID         = 0
	btfGetFDByIDOffOpenFlags     = 8
	btfGetFDByIDOffFdByIDTokenFD = 12
)

// BtfGetFDByIDAttr is the BPF_BTF_GET_FD_BY_ID view of union bpf_attr.
type BtfGetFDByIDAttr struct {
	BtfID         uint32
	OpenFlags     uint32
	FdByIDTokenFD int32
}

// Marshal returns the bytes for bpf(BPF_BTF_GET_FD_BY_ID, ...).
func (a *BtfGetFDByIDAttr) Marshal() []byte {
	buf := make([]byte, BtfGetFDByIDAttrSize)

	binary.NativeEndian.PutUint32(buf[btfGetFDByIDOffBtfID:], a.BtfID)
	binary.NativeEndian.PutUint32(buf[btfGetFDByIDOffOpenFlags:], a.OpenFlags)
	binary.NativeEndian.PutUint32(buf[btfGetFDByIDOffFdByIDTokenFD:], uint32(a.FdByIDTokenFD))

	return buf
}

func btfGetFDByIDFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"btf_id", btfGetFDByIDOffBtfID, 4},
		{"open_flags", btfGetFDByIDOffOpenFlags, 4},
		{"fd_by_id_token_fd", btfGetFDByIDOffFdByIDTokenFD, 4},
	}
}

// BtfInfoSize is sizeof(struct bpf_btf_info).
const BtfInfoSize = 32

// Offsets in struct bpf_btf_info.
const (
	btfInfoOffBtf       = 0
	btfInfoOffBtfSize   = 8
	btfInfoOffID        = 12
	btfInfoOffName      = 16
	btfInfoOffNameLen   = 24
	btfInfoOffKernelBtf = 28
)

func btfInfoFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"btf", btfInfoOffBtf, 8},
		{"btf_size", btfInfoOffBtfSize, 4},
		{"id", btfInfoOffID, 4},
		{"name", btfInfoOffName, 8},
		{"name_len", btfInfoOffNameLen, 4},
		{"kernel_btf", btfInfoOffKernelBtf, 4},
	}
}

// BtfInfo is the kernel metadata of a BTF object. BtfSize is the size of the
// raw BTF, which may exceed the buffer the caller passed. Name is empty for
// BTF loaded by user space; a kernel BTF is named vmlinux or after its module.
type BtfInfo struct {
	BtfSize   uint32
	ID        uint32
	Name      string
	KernelBtf bool
}

// BtfGetNextID returns the ID of the first loaded BTF object after startID.
// The kernel returns ENOENT after the last one and EPERM to a caller without
// CAP_SYS_ADMIN.
func BtfGetNextID(startID uint32) (uint32, error) {
	attr := &GetNextIDAttr{StartID: startID}
	buf := attr.Marshal()
	if _, err := bpf(BPF_BTF_GET_NEXT_ID, buf); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint32(buf[getNextIDOffNextID:]), nil
}

// BtfGetFDByID opens the BTF object with id and returns a new descriptor,
// which the caller must close with unix.Close. A BTF that was unloaded
// meanwhile returns ENOENT.
func BtfGetFDByID(id uint32) (int, error) {
	attr := &BtfGetFDByIDAttr{BtfID: id}
	fd, err := bpf(BPF_BTF_GET_FD_BY_ID, attr.Marshal())
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}

// BtfInfoByFD returns the metadata of the BTF descriptor fd. When data is
// not empty the kernel copies up to len(data) bytes of the raw BTF into it;
// when name is not empty it copies the NUL-terminated name into it, which
// the returned Name holds without the NUL. A kernel without name support
// rejects a name buffer with EINVAL.
func BtfInfoByFD(fd int, data, name []byte) (*BtfInfo, error) {
	info := make([]byte, BtfInfoSize)
	if len(data) > 0 {
		binary.NativeEndian.PutUint64(info[btfInfoOffBtf:], uint64(addr(data)))
		binary.NativeEndian.PutUint32(info[btfInfoOffBtfSize:], uint32(len(data)))
	}
	if len(name) > 0 {
		binary.NativeEndian.PutUint64(info[btfInfoOffName:], uint64(addr(name)))
		binary.NativeEndian.PutUint32(info[btfInfoOffNameLen:], uint32(len(name)))
	}

	err := objInfoByFD(fd, info)
	runtime.KeepAlive(data)
	runtime.KeepAlive(name)
	if err != nil {
		return nil, err
	}
	out := &BtfInfo{
		BtfSize:   binary.NativeEndian.Uint32(info[btfInfoOffBtfSize:]),
		ID:        binary.NativeEndian.Uint32(info[btfInfoOffID:]),
		KernelBtf: binary.NativeEndian.Uint32(info[btfInfoOffKernelBtf:]) != 0,
	}
	if len(name) > 0 {
		out.Name = cString(name, 0, len(name))
	}
	return out, nil
}
