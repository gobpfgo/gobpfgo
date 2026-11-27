// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestUpdatePercpuMap checks the two population forms: a kernel that takes
// BPF_F_ALL_CPUS gets the single image, and a kernel that rejects the flag
// with EINVAL gets the image repeated in every CPU's padded slot. Other
// errors are returned without a fallback, and a negative CPU count fails the
// fallback before a second update.
func TestUpdatePercpuMap(t *testing.T) {
	image := []byte{1, 2, 3, 4, 5}
	slot := []byte{1, 2, 3, 4, 5, 0, 0, 0}
	legacy := bytes.Join([][]byte{slot, slot, slot}, nil)

	t.Run("all cpus", func(t *testing.T) {
		var calls int
		err := updatePercpuMap(func(value []byte, flags uint64) error {
			calls++
			if flags != BPF_F_ALL_CPUS || !bytes.Equal(value, image) {
				t.Fatalf("update %d: flags %#x, value %x", calls, flags, value)
			}
			return nil
		}, image, 3)
		if err != nil || calls != 1 {
			t.Fatalf("update = %v after %d calls, want one success", err, calls)
		}
	})

	t.Run("legacy fallback", func(t *testing.T) {
		var calls int
		err := updatePercpuMap(func(value []byte, flags uint64) error {
			calls++
			switch flags {
			case BPF_F_ALL_CPUS:
				return unix.EINVAL
			case 0:
				if !bytes.Equal(value, legacy) {
					t.Fatalf("fallback value = %x, want %x", value, legacy)
				}
				return nil
			}
			t.Fatalf("unexpected flags %#x", flags)
			return nil
		}, image, 3)
		if err != nil || calls != 2 {
			t.Fatalf("update = %v after %d calls, want fallback success", err, calls)
		}
	})

	t.Run("other error", func(t *testing.T) {
		var calls int
		err := updatePercpuMap(func([]byte, uint64) error {
			calls++
			return unix.EPERM
		}, image, 3)
		if !errors.Is(err, unix.EPERM) || calls != 1 {
			t.Fatalf("update = %v after %d calls, want EPERM once", err, calls)
		}
	})

	t.Run("no cpu count", func(t *testing.T) {
		var calls int
		err := updatePercpuMap(func([]byte, uint64) error {
			calls++
			return unix.EINVAL
		}, image, -12)
		if !errors.Is(err, unix.ENOMEM) || calls != 1 {
			t.Fatalf("update = %v after %d calls, want ENOMEM once", err, calls)
		}
	})
}
