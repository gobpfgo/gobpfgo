// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

type ringbufFixture struct {
	ObjectName string   `json:"object_name"`
	Program    string   `json:"program"`
	Map        string   `json:"map"`
	Samples    []uint32 `json:"samples"`
}

func loadRingbufFixture(t *testing.T) ringbufFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/ringbuf.json")
	if err != nil {
		t.Fatalf("read ringbuf fixture: %v", err)
	}
	var f ringbufFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse ringbuf fixture: %v", err)
	}
	if len(f.Samples) == 0 {
		t.Fatal("ringbuf fixture has no samples")
	}
	return f
}

func TestRingBuffer(t *testing.T) {
	f := loadRingbufFixture(t)

	obj := loadTestObject(t, "../testdata/progs/ringbuf.bpf.o")
	defer BpfObjectClose(obj)
	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Fatalf("object name = %q, want %q", got, f.ObjectName)
	}

	prog := BpfObjectFindProgramByName(obj, f.Program)
	ringMap := BpfObjectFindMapByName(obj, f.Map)
	if prog == nil || ringMap == nil {
		t.Fatal("program or ring buffer map not found")
	}
	secondFD, err := BpfMapCreate(BPF_MAP_TYPE_RINGBUF, "events2", 0, 0, 4096, nil)
	if err != nil {
		t.Fatalf("create second ring buffer: %v", err)
	}
	defer unix.Close(secondFD)

	link, err := BpfProgramAttachKprobe(prog, false, "do_sys_openat2")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("attach kprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	var first, second []uint32
	sampleFn := func(dst *[]uint32) RingBufferSampleFunc {
		return func(_ any, data []byte) int {
			if len(data) != 4 {
				return -int(unix.EINVAL)
			}
			*dst = append(*dst, binary.NativeEndian.Uint32(data))
			return 0
		}
	}

	rb, err := RingBufferNew(BpfMapFD(ringMap), sampleFn(&first), nil, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("ring buffer not permitted: %v", err)
		}
		t.Fatalf("RingBufferNew: %v", err)
	}
	defer RingBufferFree(rb)

	if err := RingBufferAdd(rb, secondFD, sampleFn(&second), nil); err != nil {
		t.Fatalf("RingBufferAdd: %v", err)
	}
	if fd := RingBufferEpollFD(rb); fd < 0 {
		t.Fatalf("epoll fd = %d", fd)
	}

	triggerOpen(t)
	count, err := RingBufferPoll(rb, 1000)
	if err != nil {
		t.Fatalf("RingBufferPoll: %v", err)
	}
	if count < 1 || len(first) == 0 {
		t.Fatalf("poll consumed %d records, first ring has %d", count, len(first))
	}
	if first[0] != f.Samples[0] {
		t.Fatalf("first sample = %#x, want %#x", first[0], f.Samples[0])
	}
	if len(second) != 0 {
		t.Fatalf("second ring has unexpected samples: %v", second)
	}

	triggerOpen(t)
	if count, err = RingBufferConsume(rb); err != nil {
		t.Fatalf("RingBufferConsume: %v", err)
	}
	if count != 1 {
		t.Fatalf("consume count = %d, want 1", count)
	}

	triggerOpen(t)
	if count, err = RingBufferConsumeN(rb, 1); err != nil {
		t.Fatalf("RingBufferConsumeN: %v", err)
	}
	if count != 1 {
		t.Fatalf("consume_n count = %d, want 1", count)
	}

	RingBufferFree(rb)
	RingBufferFree(rb)
	if fd := RingBufferEpollFD(rb); fd != -1 {
		t.Fatalf("epoll fd after free = %d, want -1", fd)
	}
}
