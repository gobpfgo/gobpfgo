// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAtomic64(t *testing.T) {
	page, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer unix.Munmap(page)

	const value = 0x1122334455667788
	StoreRelease64(page, value)
	if got := LoadAcquire64(page); got != value {
		t.Fatalf("LoadAcquire64 = %#x, want %#x", got, uint64(value))
	}

	if got := LoadAcquire64(nil); got != 0 {
		t.Fatalf("LoadAcquire64(nil) = %#x, want 0", got)
	}
	StoreRelease64(nil, value)
}
