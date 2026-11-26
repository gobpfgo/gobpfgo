// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetUprobeMulti checks that each uprobe multi pointer field points at a
// kept buffer holding the NUL-terminated path or the native-endian array.
func TestSetUprobeMulti(t *testing.T) {
	um := &LinkUprobeMulti{
		Path:          "/usr/bin/true",
		Offsets:       []uint64{0x1000, 0x2000},
		RefCtrOffsets: []uint64{0x30, 0x40},
		Cookies:       []uint64{7, 8},
		Flags:         1,
		PID:           4242,
	}
	attr := &LinkCreateAttr{ProgFD: 3, AttachType: 48}

	keeps, err := setUprobeMulti(attr, um)
	if err != nil {
		t.Fatalf("setUprobeMulti: %v", err)
	}

	if attr.UprobeMultiCnt != 2 || attr.UprobeMultiFlags != 1 || attr.UprobeMultiPID != 4242 {
		t.Fatalf("cnt/flags/pid = %d/%d/%d, want 2/1/4242", attr.UprobeMultiCnt, attr.UprobeMultiFlags, attr.UprobeMultiPID)
	}
	checkKeptBuffer(t, keeps, "path", attr.UprobeMultiPath, []byte("/usr/bin/true\x00"))
	checkKeptBuffer(t, keeps, "offsets", attr.UprobeMultiOffsets, u64Bytes(um.Offsets))
	checkKeptBuffer(t, keeps, "ref_ctr_offsets", attr.UprobeMultiRefCtrOffsets, u64Bytes(um.RefCtrOffsets))
	checkKeptBuffer(t, keeps, "cookies", attr.UprobeMultiCookies, u64Bytes(um.Cookies))
}

// TestSetUprobeMultiOptionalArrays checks that absent reference counter
// offsets and cookies leave their pointers NULL.
func TestSetUprobeMultiOptionalArrays(t *testing.T) {
	attr := &LinkCreateAttr{}
	keeps, err := setUprobeMulti(attr, &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10}})
	if err != nil {
		t.Fatalf("setUprobeMulti: %v", err)
	}
	if len(keeps) != 2 {
		t.Fatalf("kept %d buffers, want the path and the offsets", len(keeps))
	}
	if attr.UprobeMultiRefCtrOffsets != 0 || attr.UprobeMultiCookies != 0 {
		t.Fatalf("ref_ctr_offsets/cookies = %#x/%#x, want NULL", attr.UprobeMultiRefCtrOffsets, attr.UprobeMultiCookies)
	}
}

func TestSetUprobeMultiInvalid(t *testing.T) {
	valid := func() *LinkUprobeMulti {
		return &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10, 0x20}}
	}
	tests := []struct {
		name string
		attr *LinkCreateAttr
		um   *LinkUprobeMulti
	}{
		{"nil attr", nil, valid()},
		{"nil arrays", &LinkCreateAttr{}, nil},
		{"empty path", &LinkCreateAttr{}, &LinkUprobeMulti{Offsets: []uint64{0x10}}},
		{"path with NUL", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin\x00/sh", Offsets: []uint64{0x10}}},
		{"no offsets", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin/sh"}},
		{"short ref_ctr_offsets", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10, 0x20}, RefCtrOffsets: []uint64{0x30}}},
		{"long cookies", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10}, Cookies: []uint64{1, 2}}},
		{"target btf id set", &LinkCreateAttr{TargetBTFID: 1}, valid()},
		{"perf event cookie set", &LinkCreateAttr{PerfEventCookie: 1}, valid()},
		{"tracing cookie set", &LinkCreateAttr{TracingCookie: 1}, valid()},
		{"kprobe multi set", &LinkCreateAttr{KprobeMultiCnt: 1}, valid()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := setUprobeMulti(tt.attr, tt.um); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("setUprobeMulti = %v, want EINVAL", err)
			}
		})
	}
}

// checkKeptBuffer finds the kept buffer whose address is ptr and compares its
// contents with want.
func checkKeptBuffer(t *testing.T, keeps [][]byte, name string, ptr uint64, want []byte) {
	t.Helper()

	if ptr == 0 {
		t.Fatalf("%s pointer is NULL", name)
	}
	for _, buf := range keeps {
		if uint64(addr(buf)) != ptr {
			continue
		}
		if !bytes.Equal(buf, want) {
			t.Fatalf("%s buffer = %x, want %x", name, buf, want)
		}
		return
	}
	t.Fatalf("%s pointer %#x is not a kept buffer", name, ptr)
}
