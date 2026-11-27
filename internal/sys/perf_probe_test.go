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

// TestPerfEventOpenKprobeInvalid checks the inputs PerfEventOpenKprobe
// rejects before it calls the kernel: a nil attribute and a function name
// with a NUL byte, which leaves the attribute as it was. An empty name is a
// raw address, not an error.
func TestPerfEventOpenKprobeInvalid(t *testing.T) {
	if fd, err := PerfEventOpenKprobe(nil, "do_sys_openat2", -1, 0); fd != -1 || !errors.Is(err, unix.EINVAL) {
		t.Errorf("nil attr: %d, %v, want EINVAL", fd, err)
	}

	attr := unix.PerfEventAttr{Type: 6, Config: 1, Ext2: 0x10}
	want := attr
	fd, err := PerfEventOpenKprobe(&attr, "do_sys\x00openat2", -1, 0)
	if fd != -1 || !errors.Is(err, unix.EINVAL) {
		t.Errorf("name with NUL: %d, %v, want EINVAL", fd, err)
	}
	if attr != want {
		t.Errorf("name with NUL: attr = %+v, want %+v", attr, want)
	}
}

// TestSetProbeName checks config1 of a probe event: a function name or path
// is a pointer to its NUL-terminated copy, and an empty name, a kprobe on a
// raw address, is 0 even when the attribute held a stale pointer. The other
// fields are left alone.
func TestSetProbeName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"do_sys_openat2", "do_sys_openat2\x00"},
		{"/usr/lib/libc.so.6", "/usr/lib/libc.so.6\x00"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := unix.PerfEventAttr{Type: 6, Config: 1, Ext1: 0xdead, Ext2: 0xffffffff81000000}
			attr := before
			nameBytes, err := setProbeName(&attr, tt.name)
			if err != nil {
				t.Fatalf("setProbeName: %v", err)
			}
			if string(nameBytes) != tt.want {
				t.Errorf("name bytes = %q, want %q", nameBytes, tt.want)
			}

			wantConfig1 := uint64(0)
			if tt.name != "" {
				wantConfig1 = uint64(addr(nameBytes))
			}
			if attr.Ext1 != wantConfig1 {
				t.Errorf("config1 = %#x, want %#x", attr.Ext1, wantConfig1)
			}
			attr.Ext1, before.Ext1 = 0, 0
			if attr != before {
				t.Errorf("attr = %+v, want only config1 changed from %+v", attr, before)
			}
		})
	}
}

// TestPerfEventOpenKprobeClearsName opens a kprobe event the kernel cannot
// create, on a PMU type no kernel has, and checks that config1 is cleared
// after the call whatever the kernel returns.
func TestPerfEventOpenKprobeClearsName(t *testing.T) {
	for _, name := range []string{"do_sys_openat2", ""} {
		attr := unix.PerfEventAttr{Type: ^uint32(0), Size: unix.PERF_ATTR_SIZE_VER0, Ext2: 0x10}
		want := attr
		fd, err := PerfEventOpenKprobe(&attr, name, -1, 0)
		if err == nil {
			unix.Close(fd)
			t.Fatalf("name %q: opened an event on PMU type %#x", name, attr.Type)
		}
		if attr != want {
			t.Errorf("name %q: attr = %+v, want %+v", name, attr, want)
		}
	}
}
