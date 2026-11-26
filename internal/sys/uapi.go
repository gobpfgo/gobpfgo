// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

//go:build linux && (amd64 || arm64)

// Package sys contains the Linux UAPI layouts and the bpf() syscall wrapper.
package sys

const (
	BPF_MAP_CREATE     = 0
	BPF_MAP_TYPE_ARRAY = 2
	BPF_OBJ_NAME_LEN   = 16
)
