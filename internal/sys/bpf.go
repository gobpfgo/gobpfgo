// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original bpf() wrapper
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: sys_bpf, bpf_map_create

//go:build linux && (amd64 || arm64)

package sys

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// bpf issues one bpf() syscall and returns its first return value.
func bpf(cmd uint32, attr []byte) (uintptr, error) {
	if len(attr) == 0 {
		return 0, unix.EINVAL
	}

	r1, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), addr(attr), uintptr(len(attr)))
	runtime.KeepAlive(attr)
	if errno != 0 {
		return 0, errno
	}
	return r1, nil
}

// BPF issues one bpf() syscall and discards its return value. The kernel errno
// is returned unchanged.
func BPF(cmd uint32, attr []byte) error {
	_, err := bpf(cmd, attr)
	return err
}

// MapCreate calls BPF_MAP_CREATE and returns the new map file descriptor.
//
// When exclHash is non-empty, its address and length are passed as the
// exclusive program hash and the slice is kept alive for the syscall.
func MapCreate(attr *MapCreateAttr, exclHash []byte) (int, error) {
	if len(exclHash) > 0 {
		attr.ExclProgHash = uint64(addr(exclHash))
		attr.ExclProgHashSize = uint32(len(exclHash))
	}

	fd, err := bpf(BPF_MAP_CREATE, attr.Marshal())
	runtime.KeepAlive(exclHash)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}
