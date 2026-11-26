// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckBpfFS(t *testing.T) {
	if err := checkBpfFS("/tmp/gobpfgo-pin"); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("checkBpfFS(/tmp) = %v, want EINVAL", err)
	}
}

func TestBpfMapAndProgramPin(t *testing.T) {
	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}
	defer BpfObjectClose(obj)

	m := BpfObjectFindMapByName(obj, "counts")
	p := BpfObjectFindProgramByName(obj, "handle_open")
	if m == nil || p == nil {
		t.Fatalf("map counts or program handle_open not found")
	}

	dir, err := os.MkdirTemp("/sys/fs/bpf", "gobpfgo-test-")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("bpffs unavailable: %v", err)
		}
		t.Fatalf("create bpffs directory: %v", err)
	}
	mapPin := filepath.Join(dir, "counts")
	programPin := filepath.Join(dir, "handle_open")
	defer func() {
		if BpfMapIsPinned(m) {
			_ = BpfMapUnpin(m, nil)
		}
		_ = BpfProgramUnpin(p, programPin)
		_ = os.Remove(dir)
	}()

	if err := BpfMapSetPinPath(m, &mapPin); err != nil {
		t.Fatalf("BpfMapSetPinPath: %v", err)
	}
	if got := BpfMapPinPath(m); got != mapPin {
		t.Fatalf("BpfMapPinPath = %q, want %q", got, mapPin)
	}
	if err := BpfMapPin(m, nil); err != nil {
		t.Fatalf("BpfMapPin: %v", err)
	}
	if !BpfMapIsPinned(m) {
		t.Fatal("map is not pinned")
	}
	if _, err := os.Stat(mapPin); err != nil {
		t.Fatalf("stat pinned map: %v", err)
	}

	if err := BpfMapPin(m, nil); err != nil {
		t.Fatalf("second BpfMapPin: %v", err)
	}
	other := filepath.Join(dir, "other")
	if err := BpfMapPin(m, &other); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfMapPin with a different path = %v, want EINVAL", err)
	}

	if err := BpfProgramPin(p, programPin); err != nil {
		t.Fatalf("BpfProgramPin: %v", err)
	}
	if _, err := os.Stat(programPin); err != nil {
		t.Fatalf("stat pinned program: %v", err)
	}

	if err := BpfProgramUnpin(p, programPin); err != nil {
		t.Fatalf("BpfProgramUnpin: %v", err)
	}
	if _, err := os.Stat(programPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pinned program still exists: %v", err)
	}
	if err := BpfMapUnpin(m, nil); err != nil {
		t.Fatalf("BpfMapUnpin: %v", err)
	}
	if BpfMapIsPinned(m) {
		t.Fatal("map still reports pinned")
	}
	if _, err := os.Stat(mapPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pinned map still exists: %v", err)
	}
	if err := BpfMapSetPinPath(m, nil); err != nil {
		t.Fatalf("clear pin path: %v", err)
	}
	if got := BpfMapPinPath(m); got != "" {
		t.Fatalf("BpfMapPinPath after clear = %q", got)
	}
}
