// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original
// libbpf-source: src/ringbuf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: smp_load_acquire, smp_store_release

//go:build linux && (amd64 || arm64)

package sys

// Implemented in atomic_amd64.s and atomic_arm64.s.
func loadAcquire64(ptr uintptr) uint64
func storeRelease64(ptr uintptr, val uint64)

// LoadAcquire64 loads the first 64-bit word of b with acquire semantics. b
// must be at least 8 bytes and 8-byte aligned, as the ring pages are.
func LoadAcquire64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return loadAcquire64(addr(b))
}

// StoreRelease64 stores v in the first 64-bit word of b with release
// semantics. b must be at least 8 bytes and 8-byte aligned.
func StoreRelease64(b []byte, v uint64) {
	if len(b) < 8 {
		return
	}
	storeRelease64(addr(b), v)
}
