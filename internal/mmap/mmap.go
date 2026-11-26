// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

// Package mmap wraps the shared mappings used by the ring and perf buffers.
// The mappings are returned as byte slices, so callers never convert a
// pointer.
package mmap

import "golang.org/x/sys/unix"

// Map maps length bytes of fd starting at offset. The slice owns the mapping
// and must be released with Unmap.
func Map(fd int, offset int64, length, prot, flags int) ([]byte, error) {
	return unix.Mmap(fd, offset, length, prot, flags)
}

// Unmap releases a mapping returned by Map.
func Unmap(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munmap(b)
}
