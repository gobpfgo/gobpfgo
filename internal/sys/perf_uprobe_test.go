// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPerfEventOpenUprobeInvalid checks the inputs PerfEventOpenUprobe
// rejects before it calls the kernel, and that it leaves the attribute as it
// was.
func TestPerfEventOpenUprobeInvalid(t *testing.T) {
	if fd, err := PerfEventOpenUprobe(nil, "/bin/true", -1, 0); fd != -1 || !errors.Is(err, unix.EINVAL) {
		t.Errorf("nil attr: %d, %v, want EINVAL", fd, err)
	}

	for _, path := range []string{"", "/bin/\x00true"} {
		attr := unix.PerfEventAttr{Type: 9, Config: 0x3000 << 32, Ext2: 0x1024}
		want := attr
		fd, err := PerfEventOpenUprobe(&attr, path, -1, 0)
		if fd != -1 || !errors.Is(err, unix.EINVAL) {
			t.Errorf("path %q: %d, %v, want EINVAL", path, fd, err)
		}
		if attr != want {
			t.Errorf("path %q: attr = %+v, want %+v", path, attr, want)
		}
	}
}
