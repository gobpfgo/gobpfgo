// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

type attachFixture struct {
	ObjectName string `json:"object_name"`
	Program    string `json:"program"`
	Function   string `json:"function"`
	Triggered  bool   `json:"triggered"`
}

func loadAttachFixture(t *testing.T) attachFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/attach.json")
	if err != nil {
		t.Fatalf("read attach fixture: %v", err)
	}
	var f attachFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse attach fixture: %v", err)
	}
	return f
}

func TestPerfEventAttrSize(t *testing.T) {
	if got := int(reflect.TypeOf(unix.PerfEventAttr{}).Size()); got != perfEventAttrSize {
		t.Fatalf("sizeof(perf_event_attr) = %d, want %d", got, perfEventAttrSize)
	}
}

func TestBpfProgramAttachKprobe(t *testing.T) {
	f := loadAttachFixture(t)
	if !f.Triggered {
		t.Fatal("attach fixture is not triggered")
	}

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

	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Fatalf("object name = %q, want %q", got, f.ObjectName)
	}

	prog := BpfObjectFindProgramByName(obj, f.Program)
	if prog == nil {
		t.Fatalf("program %q not found", f.Program)
	}

	link, err := BpfProgramAttachKprobe(prog, false, f.Function)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("BpfProgramAttachKprobe: %v", err)
	}
	if fd := BpfLinkFD(link); fd < 0 {
		t.Fatalf("link fd = %d", fd)
	}

	// The program counts do_sys_openat2 calls, so one open must show up in
	// the map before the link is detached.
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	_ = file.Close()

	if got := mapCount(t, obj, "counts"); got == 0 {
		t.Fatal("kprobe did not increment counts")
	}

	if err := BpfLinkDetach(link); err != nil {
		t.Fatalf("BpfLinkDetach: %v", err)
	}
	if got := BpfLinkFD(link); got != -1 {
		t.Fatalf("link fd after detach = %d, want -1", got)
	}
	if err := BpfLinkDetach(link); err != nil {
		t.Fatalf("second BpfLinkDetach: %v", err)
	}

	BpfLinkDestroy(link)
	BpfLinkDestroy(link)
}

func mapCount(t *testing.T, obj *BpfObject, name string) uint64 {
	t.Helper()

	m := BpfObjectFindMapByName(obj, name)
	if m == nil {
		t.Fatalf("map %q not found", name)
	}
	if BpfMapValueSize(m) < 8 {
		t.Fatalf("map %q value size = %d, want at least 8", name, BpfMapValueSize(m))
	}

	key := make([]byte, BpfMapKeySize(m))
	value := make([]byte, BpfMapValueSize(m))
	if err := BpfMapLookupElem(m, key, value, 0); err != nil {
		t.Fatalf("BpfMapLookupElem %s: %v", name, err)
	}
	return binary.NativeEndian.Uint64(value)
}
