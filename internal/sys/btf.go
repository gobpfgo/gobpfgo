// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_btf_load

//go:build linux && (amd64 || arm64)

package sys

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/sys/unix"
)

// BtfLoadAttrSize is offsetofend(union bpf_attr, btf_token_fd) on 64-bit
// Linux. It is the size libbpf passes to BPF_BTF_LOAD.
const BtfLoadAttrSize = 40

// Offsets inside union bpf_attr for the BPF_BTF_LOAD command.
const (
	btfLoadOffBtf            = 0
	btfLoadOffBtfLogBuf      = 8
	btfLoadOffBtfSize        = 16
	btfLoadOffBtfLogSize     = 20
	btfLoadOffBtfLogLevel    = 24
	btfLoadOffBtfLogTrueSize = 28
	btfLoadOffBtfFlags       = 32
	btfLoadOffBtfTokenFD     = 36
)

// BtfLoadAttr is the BPF_BTF_LOAD view of union bpf_attr. Btf and BtfLogBuf
// are addresses written by BtfLoad; the remaining fields are scalar.
type BtfLoadAttr struct {
	Btf            uint64
	BtfLogBuf      uint64
	BtfSize        uint32
	BtfLogSize     uint32
	BtfLogLevel    uint32
	BtfLogTrueSize uint32
	BtfFlags       uint32
	BtfTokenFD     int32
}

// Marshal returns the bytes for bpf(BPF_BTF_LOAD, ...).
func (a *BtfLoadAttr) Marshal() []byte {
	buf := make([]byte, BtfLoadAttrSize)

	binary.NativeEndian.PutUint64(buf[btfLoadOffBtf:], a.Btf)
	binary.NativeEndian.PutUint64(buf[btfLoadOffBtfLogBuf:], a.BtfLogBuf)
	binary.NativeEndian.PutUint32(buf[btfLoadOffBtfSize:], a.BtfSize)
	binary.NativeEndian.PutUint32(buf[btfLoadOffBtfLogSize:], a.BtfLogSize)
	binary.NativeEndian.PutUint32(buf[btfLoadOffBtfLogLevel:], a.BtfLogLevel)
	binary.NativeEndian.PutUint32(buf[btfLoadOffBtfLogTrueSize:], a.BtfLogTrueSize)
	binary.NativeEndian.PutUint32(buf[btfLoadOffBtfFlags:], a.BtfFlags)
	binary.NativeEndian.PutUint32(buf[btfLoadOffBtfTokenFD:], uint32(a.BtfTokenFD))

	return buf
}

func btfLoadFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"btf", btfLoadOffBtf, 8},
		{"btf_log_buf", btfLoadOffBtfLogBuf, 8},
		{"btf_size", btfLoadOffBtfSize, 4},
		{"btf_log_size", btfLoadOffBtfLogSize, 4},
		{"btf_log_level", btfLoadOffBtfLogLevel, 4},
		{"btf_log_true_size", btfLoadOffBtfLogTrueSize, 4},
		{"btf_flags", btfLoadOffBtfFlags, 4},
		{"btf_token_fd", btfLoadOffBtfTokenFD, 4},
	}
}

// BtfLoad validates and loads BTF metadata into the kernel and returns its file
// descriptor. logBuf and logLevel request verification logs; either may be
// zero.
//
// The caller owns the descriptor and must close it with unix.Close. A failed
// call returns a negative descriptor and the kernel errno.
func BtfLoad(btf []byte, logBuf []byte, logLevel uint32) (int, error) {
	if len(btf) == 0 {
		return -1, unix.EINVAL
	}

	attr := &BtfLoadAttr{
		Btf:     uint64(addr(btf)),
		BtfSize: uint32(len(btf)),
	}
	if len(logBuf) > 0 {
		attr.BtfLogBuf = uint64(addr(logBuf))
		attr.BtfLogSize = uint32(len(logBuf))
		attr.BtfLogLevel = logLevel
	}

	fd, err := bpf(BPF_BTF_LOAD, attr.Marshal())
	runtime.KeepAlive(btf)
	runtime.KeepAlive(logBuf)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}
