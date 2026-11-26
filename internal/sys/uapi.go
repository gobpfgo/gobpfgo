// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/bpf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: enum bpf_cmd, enum bpf_map_type, BPF_OBJ_NAME_LEN

//go:build linux && (amd64 || arm64)

// Package sys contains the Linux UAPI layouts and the bpf() syscall wrapper.
//
// Attribute structs are serialized into []byte with encoding/binary at offsets
// checked against the oracle fixtures. The bpf() wrapper is the only place a
// Go slice address is converted for the syscall.
package sys

// UAPI values from linux/bpf.h used by the first slices.
const (
	BPF_MAP_CREATE     = 0
	BPF_PROG_LOAD      = 5
	BPF_BTF_LOAD       = 18
	BPF_MAP_TYPE_ARRAY = 2
	BPF_OBJ_NAME_LEN   = 16
)
