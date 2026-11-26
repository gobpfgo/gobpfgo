// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_prog_load

//go:build linux && (amd64 || arm64)

package sys

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/sys/unix"
)

// ProgLoadAttrSize is offsetofend(union bpf_attr, keyring_id) on 64-bit Linux.
// It is the size libbpf passes to BPF_PROG_LOAD.
const ProgLoadAttrSize = 168

// Offsets inside union bpf_attr for the BPF_PROG_LOAD command.
const (
	progLoadOffProgType           = 0
	progLoadOffInsnCnt            = 4
	progLoadOffInsns              = 8
	progLoadOffLicense            = 16
	progLoadOffLogLevel           = 24
	progLoadOffLogSize            = 28
	progLoadOffLogBuf             = 32
	progLoadOffProgFlags          = 44
	progLoadOffProgName           = 48
	progLoadOffProgIfindex        = 64
	progLoadOffExpectedAttachType = 68
	progLoadOffProgBtfFD          = 72
	progLoadOffFuncInfoRecSize    = 76
	progLoadOffFuncInfo           = 80
	progLoadOffFuncInfoCnt        = 88
	progLoadOffLineInfoRecSize    = 92
	progLoadOffLineInfo           = 96
	progLoadOffLineInfoCnt        = 104
	progLoadOffAttachBtfID        = 108
	progLoadOffAttachBtfObjFD     = 112
)

// ProgLoadAttr is the BPF_PROG_LOAD view of union bpf_attr. Insns, License
// and LogBuf are addresses written by ProgLoad; the remaining fields are
// scalar and default to zero.
type ProgLoadAttr struct {
	ProgType           uint32
	InsnCnt            uint32
	Insns              uint64
	License            uint64
	LogLevel           uint32
	LogSize            uint32
	LogBuf             uint64
	ProgFlags          uint32
	ProgName           [BPF_OBJ_NAME_LEN]byte
	ProgIfindex        uint32
	ExpectedAttachType uint32
	ProgBtfFD          uint32
	FuncInfoRecSize    uint32
	FuncInfo           uint64
	FuncInfoCnt        uint32
	LineInfoRecSize    uint32
	LineInfo           uint64
	LineInfoCnt        uint32
	AttachBtfID        uint32
	AttachBtfObjFD     int32
}

// SetProgName copies name into the 16-byte prog_name field, truncating to 15
// bytes and NUL-terminating like the kernel object name.
func (a *ProgLoadAttr) SetProgName(name string) {
	a.ProgName = [BPF_OBJ_NAME_LEN]byte{}
	if len(name) > BPF_OBJ_NAME_LEN-1 {
		name = name[:BPF_OBJ_NAME_LEN-1]
	}
	copy(a.ProgName[:], name)
}

// Marshal returns the bytes for bpf(BPF_PROG_LOAD, ...).
func (a *ProgLoadAttr) Marshal() []byte {
	buf := make([]byte, ProgLoadAttrSize)

	binary.NativeEndian.PutUint32(buf[progLoadOffProgType:], a.ProgType)
	binary.NativeEndian.PutUint32(buf[progLoadOffInsnCnt:], a.InsnCnt)
	binary.NativeEndian.PutUint64(buf[progLoadOffInsns:], a.Insns)
	binary.NativeEndian.PutUint64(buf[progLoadOffLicense:], a.License)
	binary.NativeEndian.PutUint32(buf[progLoadOffLogLevel:], a.LogLevel)
	binary.NativeEndian.PutUint32(buf[progLoadOffLogSize:], a.LogSize)
	binary.NativeEndian.PutUint64(buf[progLoadOffLogBuf:], a.LogBuf)
	binary.NativeEndian.PutUint32(buf[progLoadOffProgFlags:], a.ProgFlags)
	copy(buf[progLoadOffProgName:progLoadOffProgName+BPF_OBJ_NAME_LEN], a.ProgName[:])
	binary.NativeEndian.PutUint32(buf[progLoadOffProgIfindex:], a.ProgIfindex)
	binary.NativeEndian.PutUint32(buf[progLoadOffExpectedAttachType:], a.ExpectedAttachType)
	binary.NativeEndian.PutUint32(buf[progLoadOffProgBtfFD:], a.ProgBtfFD)
	binary.NativeEndian.PutUint32(buf[progLoadOffFuncInfoRecSize:], a.FuncInfoRecSize)
	binary.NativeEndian.PutUint64(buf[progLoadOffFuncInfo:], a.FuncInfo)
	binary.NativeEndian.PutUint32(buf[progLoadOffFuncInfoCnt:], a.FuncInfoCnt)
	binary.NativeEndian.PutUint32(buf[progLoadOffLineInfoRecSize:], a.LineInfoRecSize)
	binary.NativeEndian.PutUint64(buf[progLoadOffLineInfo:], a.LineInfo)
	binary.NativeEndian.PutUint32(buf[progLoadOffLineInfoCnt:], a.LineInfoCnt)
	binary.NativeEndian.PutUint32(buf[progLoadOffAttachBtfID:], a.AttachBtfID)
	binary.NativeEndian.PutUint32(buf[progLoadOffAttachBtfObjFD:], uint32(a.AttachBtfObjFD))

	return buf
}

func progLoadFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"prog_type", progLoadOffProgType, 4},
		{"insn_cnt", progLoadOffInsnCnt, 4},
		{"insns", progLoadOffInsns, 8},
		{"license", progLoadOffLicense, 8},
		{"log_level", progLoadOffLogLevel, 4},
		{"log_size", progLoadOffLogSize, 4},
		{"log_buf", progLoadOffLogBuf, 8},
		{"prog_flags", progLoadOffProgFlags, 4},
		{"prog_name", progLoadOffProgName, BPF_OBJ_NAME_LEN},
		{"prog_ifindex", progLoadOffProgIfindex, 4},
		{"expected_attach_type", progLoadOffExpectedAttachType, 4},
		{"prog_btf_fd", progLoadOffProgBtfFD, 4},
		{"func_info_rec_size", progLoadOffFuncInfoRecSize, 4},
		{"func_info", progLoadOffFuncInfo, 8},
		{"func_info_cnt", progLoadOffFuncInfoCnt, 4},
		{"line_info_rec_size", progLoadOffLineInfoRecSize, 4},
		{"line_info", progLoadOffLineInfo, 8},
		{"line_info_cnt", progLoadOffLineInfoCnt, 4},
		{"attach_btf_id", progLoadOffAttachBtfID, 4},
		{"attach_btf_obj_fd", progLoadOffAttachBtfObjFD, 4},
	}
}

// ProgLoad loads a BPF program into the kernel and returns its file
// descriptor. insns and license are copied by the kernel during the call;
// logBuf may be nil or a buffer for the verifier log.
//
// The caller sets ProgType, InsnCnt, ProgFlags, ExpectedAttachType and
// ProgBtfFD before calling. The caller owns the descriptor and must close it
// with unix.Close.
func ProgLoad(attr *ProgLoadAttr, insns []byte, license []byte, logBuf []byte, funcInfo []byte) (int, error) {
	if len(insns) == 0 || len(license) == 0 {
		return -1, unix.EINVAL
	}

	attr.Insns = uint64(addr(insns))
	attr.License = uint64(addr(license))
	if len(logBuf) > 0 {
		attr.LogBuf = uint64(addr(logBuf))
		attr.LogSize = uint32(len(logBuf))
	}
	if len(funcInfo) > 0 {
		attr.FuncInfo = uint64(addr(funcInfo))
	}

	fd, err := bpf(BPF_PROG_LOAD, attr.Marshal())
	runtime.KeepAlive(insns)
	runtime.KeepAlive(license)
	runtime.KeepAlive(logBuf)
	runtime.KeepAlive(funcInfo)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}
