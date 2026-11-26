// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

//go:build linux && (amd64 || arm64)

package sys

import "reflect"

// addr returns the address of the first byte in b without importing unsafe.
// The caller must keep the backing slice alive until the syscall returns.
func addr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return reflect.ValueOf(b).Pointer()
}
