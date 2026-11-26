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

type perfbufFixture struct {
	ObjectName string   `json:"object_name"`
	Program    string   `json:"program"`
	Map        string   `json:"map"`
	BufferCnt  int      `json:"buffer_cnt"`
	Samples    []uint32 `json:"samples"`
	Lost       uint64   `json:"lost"`
}

func loadPerfbufFixture(t *testing.T) perfbufFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/perfbuf.json")
	if err != nil {
		t.Fatalf("read perfbuf fixture: %v", err)
	}
	var f perfbufFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse perfbuf fixture: %v", err)
	}
	if len(f.Samples) == 0 {
		t.Fatal("perfbuf fixture has no samples")
	}
	return f
}

func TestPerfBuffer(t *testing.T) {
	f := loadPerfbufFixture(t)

	obj := loadTestObject(t, "../testdata/progs/perfbuf.bpf.o")
	defer BpfObjectClose(obj)
	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Fatalf("object name = %q, want %q", got, f.ObjectName)
	}

	prog := BpfObjectFindProgramByName(obj, f.Program)
	perfMap := BpfObjectFindMapByName(obj, f.Map)
	if prog == nil || perfMap == nil {
		t.Fatal("program or perf event map not found")
	}

	link, err := BpfProgramAttachKprobe(prog, false, "do_sys_openat2")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("attach kprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	var samples []uint32
	var lost uint64
	sampleFn := func(_ any, _ int, data []byte) {
		if len(data) != 4 {
			return
		}
		samples = append(samples, binary.NativeEndian.Uint32(data))
	}
	lostFn := func(_ any, _ int, count uint64) {
		lost += count
	}

	pb, err := PerfBufferNew(BpfMapFD(perfMap), 8, sampleFn, lostFn, nil, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("perf buffer not permitted: %v", err)
		}
		t.Fatalf("PerfBufferNew: %v", err)
	}
	defer PerfBufferFree(pb)

	if count := PerfBufferBufferCnt(pb); count < 1 {
		t.Fatalf("buffer count = %d, want at least 1", count)
	}
	if fd := PerfBufferEpollFD(pb); fd < 0 {
		t.Fatalf("epoll fd = %d", fd)
	}
	if fd, err := PerfBufferBufferFD(pb, 0); err != nil || fd < 0 {
		t.Fatalf("buffer fd = %d, %v", fd, err)
	}
	base, size, err := PerfBufferBuffer(pb, 0)
	if err != nil {
		t.Fatalf("PerfBufferBuffer: %v", err)
	}
	if len(base) != size+unix.Getpagesize() {
		t.Fatalf("mapping length = %d, want %d", len(base), size+unix.Getpagesize())
	}

	triggerOpen(t)
	count, err := PerfBufferPoll(pb, 1000)
	if err != nil {
		t.Fatalf("PerfBufferPoll: %v", err)
	}
	if count < 1 || len(samples) == 0 {
		t.Fatalf("poll returned %d, collected %d samples", count, len(samples))
	}
	if samples[0] != f.Samples[0] {
		t.Fatalf("first sample = %#x, want %#x", samples[0], f.Samples[0])
	}
	if lost != 0 {
		t.Fatalf("lost = %d, want 0", lost)
	}

	triggerOpen(t)
	if err := PerfBufferConsume(pb); err != nil {
		t.Fatalf("PerfBufferConsume: %v", err)
	}
	if len(samples) < 2 {
		t.Fatalf("consume collected %d samples, want at least 2", len(samples))
	}

	triggerOpen(t)
	if err := PerfBufferConsumeBuffer(pb, 0); err != nil {
		t.Fatalf("PerfBufferConsumeBuffer: %v", err)
	}
	if err := PerfBufferConsume(pb); err != nil {
		t.Fatalf("PerfBufferConsume after buffer: %v", err)
	}
	if len(samples) < 3 {
		t.Fatalf("consume buffer collected %d samples, want at least 3", len(samples))
	}

	if _, err := PerfBufferBufferFD(pb, 1000); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("out of range buffer fd error = %v, want EINVAL", err)
	}
	if err := PerfBufferConsumeBuffer(pb, 1000); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("out of range consume buffer error = %v, want EINVAL", err)
	}

	PerfBufferFree(pb)
	PerfBufferFree(pb)
	if fd := PerfBufferEpollFD(pb); fd != -1 {
		t.Fatalf("epoll fd after free = %d, want -1", fd)
	}
	if count := PerfBufferBufferCnt(pb); count != 0 {
		t.Fatalf("buffer count after free = %d, want 0", count)
	}
}

func TestParseCPUMask(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []bool
	}{
		{"range", "0-3\n", []bool{true, true, true, true}},
		{"list", "0,2-3\n", []bool{true, false, true, true}},
		{"single", "1\n", []bool{false, true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCPUMask(tt.in)
			if err != nil {
				t.Fatalf("parseCPUMask(%q): %v", tt.in, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("mask length = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("mask[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}

	for _, in := range []string{"", "3-1", "x", "0-1-2"} {
		if _, err := parseCPUMask(in); err == nil {
			t.Errorf("parseCPUMask(%q) succeeded, want error", in)
		}
	}
}
