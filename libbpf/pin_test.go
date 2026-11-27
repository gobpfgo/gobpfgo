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

// bpffsTempDir creates a directory with prefix on /sys/fs/bpf and skips the
// test when bpffs is not mounted or not writable. The caller removes it.
func bpffsTempDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp("/sys/fs/bpf", prefix)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("bpffs unavailable: %v", err)
		}
		t.Fatalf("create bpffs directory: %v", err)
	}
	return dir
}

func TestCheckBpfFS(t *testing.T) {
	if err := checkBpfFS("/tmp/gobpfgo-pin"); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("checkBpfFS(/tmp) = %v, want EINVAL", err)
	}
}

// TestObjectPinMapsSkipsUncreated pins an object whose only map has
// autocreate cleared and a stored pin path, as a per-CPU data map has after a
// load on a kernel without global per-CPU data. The map has no descriptor, so
// the precondition must not count it and the pin must not try it; a created
// map is still required to have a descriptor.
func TestObjectPinMapsSkipsUncreated(t *testing.T) {
	skipped := &BpfMap{name: ".percpu", fd: -1, pinPath: "/sys/fs/bpf/gobpfgo-uncreated"}
	obj := &BpfObject{maps: []*BpfMap{skipped}}

	if !objectMapsLoaded(obj) {
		t.Fatal("objectMapsLoaded = false with only an autocreate-cleared map")
	}
	if err := BpfObjectPinMaps(obj, nil); err != nil {
		t.Fatalf("BpfObjectPinMaps: %v", err)
	}
	if BpfMapIsPinned(skipped) {
		t.Error("autocreate-cleared map reports pinned")
	}

	obj.maps = append(obj.maps, &BpfMap{name: ".bss", fd: -1, autocreate: true})
	if objectMapsLoaded(obj) {
		t.Error("objectMapsLoaded = true with an uncreated autocreate map")
	}
	if err := BpfObjectPinMaps(obj, nil); !errors.Is(err, unix.ENOENT) {
		t.Errorf("BpfObjectPinMaps = %v, want ENOENT", err)
	}
}

func TestBpfObjectPin(t *testing.T) {
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

	dir := bpffsTempDir(t, "gobpfgo-object-")
	defer func() {
		_ = BpfObjectUnpin(obj, dir)
		_ = os.Remove(dir)
	}()

	mapPin := filepath.Join(dir, "counts")
	programPin := filepath.Join(dir, "handle_open")

	if err := BpfObjectPinMaps(obj, &dir); err != nil {
		t.Fatalf("BpfObjectPinMaps: %v", err)
	}
	if _, err := os.Stat(mapPin); err != nil {
		t.Fatalf("stat pinned map: %v", err)
	}
	if _, err := os.Stat(programPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("program pinned before BpfObjectPinPrograms: %v", err)
	}

	if err := BpfObjectPinPrograms(obj, dir); err != nil {
		t.Fatalf("BpfObjectPinPrograms: %v", err)
	}
	if _, err := os.Stat(programPin); err != nil {
		t.Fatalf("stat pinned program: %v", err)
	}

	// A nil path uses the map pin path stored by BpfObjectPinMaps.
	if err := BpfObjectUnpinMaps(obj, nil); err != nil {
		t.Fatalf("BpfObjectUnpinMaps: %v", err)
	}
	if _, err := os.Stat(mapPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pinned map still exists: %v", err)
	}
	if _, err := os.Stat(programPin); err != nil {
		t.Fatalf("program was unpinned with the map: %v", err)
	}
	if err := BpfObjectUnpinPrograms(obj, dir); err != nil {
		t.Fatalf("BpfObjectUnpinPrograms: %v", err)
	}

	if err := BpfObjectPin(obj, dir); err != nil {
		t.Fatalf("BpfObjectPin: %v", err)
	}
	if _, err := os.Stat(mapPin); err != nil {
		t.Fatalf("stat object map: %v", err)
	}
	if _, err := os.Stat(programPin); err != nil {
		t.Fatalf("stat object program: %v", err)
	}
	if err := BpfObjectUnpin(obj, dir); err != nil {
		t.Fatalf("BpfObjectUnpin: %v", err)
	}
	if _, err := os.Stat(mapPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object map still exists: %v", err)
	}
	if _, err := os.Stat(programPin); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("object program still exists: %v", err)
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

	dir := bpffsTempDir(t, "gobpfgo-test-")
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
