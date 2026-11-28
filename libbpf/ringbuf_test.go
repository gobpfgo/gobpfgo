// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

type ringbufFixture struct {
	ObjectName string   `json:"object_name"`
	Program    string   `json:"program"`
	Map        string   `json:"map"`
	Map2       string   `json:"map2"`
	Samples    []uint32 `json:"samples"`
	Samples2   []uint32 `json:"samples2"`
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
	if len(f.Samples) == 0 || len(f.Samples2) == 0 {
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
	ringMap2 := BpfObjectFindMapByName(obj, f.Map2)
	data := BpfObjectFindMapByName(obj, ".data")
	if prog == nil || ringMap == nil || ringMap2 == nil || data == nil {
		t.Fatal("program, ring buffer or .data maps not found")
	}
	// Only this process's opens produce records, so other processes cannot
	// add any between the trigger and the reads.
	if err := BpfMapUpdateElem(data, u32Key(0), u32Key(uint32(os.Getpid())), BPF_ANY); err != nil {
		t.Fatalf("set target_tgid: %v", err)
	}

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

	if err := RingBufferAdd(rb, BpfMapFD(ringMap2), sampleFn(&second), nil); err != nil {
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
	if count != 2 || !slices.Equal(first, f.Samples) || !slices.Equal(second, f.Samples2) {
		t.Fatalf("poll consumed %d records, samples %#x and %#x, want 2, %#x and %#x",
			count, first, second, f.Samples, f.Samples2)
	}

	triggerOpen(t)
	if count, err = RingBufferConsume(rb); err != nil {
		t.Fatalf("RingBufferConsume: %v", err)
	}
	if count != 2 {
		t.Fatalf("consume count = %d, want 2", count)
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
