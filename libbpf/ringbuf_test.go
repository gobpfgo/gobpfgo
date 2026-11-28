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
	"strings"
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
	// Only the opens of processes with this test's command name produce
	// records, so other processes cannot add any between the trigger and the
	// reads, and the filter holds inside a PID namespace too. Start with a
	// name no process has, so the negative case below proves the filter
	// drops the trigger's own opens.
	wrongComm := make([]byte, taskCommLen)
	copy(wrongComm, "gobpfgo-none")
	if err := BpfMapUpdateElem(data, u32Key(0), wrongComm, BPF_ANY); err != nil {
		t.Fatalf("set wrong target_comm: %v", err)
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
	if count, err := RingBufferPoll(rb, 100); err != nil {
		t.Fatalf("RingBufferPoll with the wrong comm: %v", err)
	} else if count != 0 || len(first) != 0 || len(second) != 0 {
		t.Fatalf("wrong comm consumed %d records, samples %#x and %#x, want none", count, first, second)
	}

	if err := BpfMapUpdateElem(data, u32Key(0), selfComm(t), BPF_ANY); err != nil {
		t.Fatalf("set target_comm: %v", err)
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

// taskCommLen is the kernel's TASK_COMM_LEN, the size of target_comm.
const taskCommLen = 16

// selfComm returns the command name of this process as bpf_get_current_comm
// returns it: the 16-byte kernel comm, NUL-padded. The name comes from
// /proc/self/comm, so unlike a PID it is the same in every PID namespace.
func selfComm(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatalf("read /proc/self/comm: %v", err)
	}
	name := strings.TrimSuffix(string(data), "\n")
	if name == "" {
		t.Fatal("/proc/self/comm is empty")
	}
	comm := make([]byte, taskCommLen)
	copy(comm[:taskCommLen-1], name)
	return comm
}
