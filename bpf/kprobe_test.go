// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf_test

import (
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/bpf"
)

// TestKprobeAttach runs the kprobe flow through the object layer: it loads
// kprobe.bpf.o, attaches handle_open to do_sys_openat2, opens a file, and
// requires counts to have counted the open. It then destroys the link and
// closes the object. It needs root and skips when the kernel refuses bpf()
// or the kprobe with EPERM or EACCES.
func TestKprobeAttach(t *testing.T) {
	obj, err := bpf.OpenFile(kprobeObject, nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer obj.Close()

	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		t.Fatalf("Load: %v", err)
	}
	prog := obj.Program("handle_open")
	counts := obj.Map("counts")
	if prog.FD() < 0 || counts.FD() < 0 {
		t.Fatalf("after Load: program FD %d, map FD %d", prog.FD(), counts.FD())
	}

	link, err := prog.AttachKprobe(false, "do_sys_openat2")
	if err != nil {
		skipIfNotPermitted(t, "kprobe attach", err)
		t.Fatalf("AttachKprobe: %v", err)
	}
	defer link.Destroy()
	if link.FD() < 0 {
		t.Fatalf("link FD = %d", link.FD())
	}

	triggerOpen(t)
	if got := counter(t, counts); got == 0 {
		t.Fatal("handle_open did not count the open")
	}

	link.Destroy()
	if link.FD() != -1 {
		t.Errorf("link FD after Destroy = %d, want -1", link.FD())
	}
	if err := obj.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if prog.FD() != -1 || counts.FD() != -1 {
		t.Errorf("after Close: program FD %d, map FD %d, want -1", prog.FD(), counts.FD())
	}
}

// skipIfNotPermitted skips the test when err is EPERM or EACCES.
func skipIfNotPermitted(t *testing.T, what string, err error) {
	t.Helper()

	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("%s not permitted: %v", what, err)
	}
}

// triggerOpen opens and closes /dev/null, which reaches do_sys_openat2.
func triggerOpen(t *testing.T) {
	t.Helper()

	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	_ = file.Close()
}

// counter reads the 64-bit value at key 0 of an array map.
func counter(t *testing.T, m *bpf.Map) uint64 {
	t.Helper()

	if m.ValueSize() < 8 {
		t.Fatalf("map %s value size = %d, want at least 8", m.Name(), m.ValueSize())
	}
	key := make([]byte, m.KeySize())
	value := make([]byte, m.ValueSize())
	if err := m.Lookup(key, value, 0); err != nil {
		t.Fatalf("Lookup %s: %v", m.Name(), err)
	}
	return binary.NativeEndian.Uint64(value)
}
