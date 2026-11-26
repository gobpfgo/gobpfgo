// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

func TestBpfMapReuseFD(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "gobpfgo_reuse", 4, 8, 16, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfMapCreate: %v", err)
	}
	defer unix.Close(fd)

	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	m := BpfObjectFindMapByName(obj, "counts")
	p := BpfObjectFindProgramByName(obj, "handle_open")
	if m == nil || p == nil {
		t.Fatal("map counts or program handle_open not found")
	}

	if err := BpfMapReuseFD(m, fd); err != nil {
		t.Fatalf("BpfMapReuseFD: %v", err)
	}
	if got := BpfMapName(m); got != "gobpfgo_reuse" {
		t.Fatalf("map name = %q, want gobpfgo_reuse", got)
	}
	if got := BpfMapMaxEntries(m); got != 16 {
		t.Fatalf("max entries = %d, want 16", got)
	}
	if BpfMapFD(m) == fd {
		t.Fatal("reuse kept the caller's fd instead of duplicating it")
	}

	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}

	reused, err := sys.MapInfoByFD(BpfMapFD(m))
	if err != nil {
		t.Fatalf("MapInfoByFD reused: %v", err)
	}
	original, err := sys.MapInfoByFD(fd)
	if err != nil {
		t.Fatalf("MapInfoByFD original: %v", err)
	}
	if reused.ID != original.ID {
		t.Fatalf("reused map id = %d, original id = %d", reused.ID, original.ID)
	}
	if reused.Name != "gobpfgo_reuse" || reused.MaxEntries != 16 {
		t.Fatalf("reused map info = %+v", reused)
	}

	link, err := BpfProgramAttachKprobe(p, false, "do_sys_openat2")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("BpfProgramAttachKprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	_ = file.Close()

	key := make([]byte, BpfMapKeySize(m))
	value := make([]byte, BpfMapValueSize(m))
	if err := BpfMapLookupElem(m, key, value, 0); err != nil {
		t.Fatalf("BpfMapLookupElem: %v", err)
	}
	if binary.NativeEndian.Uint64(value) == 0 {
		t.Fatal("program did not increment the reused map")
	}
}
