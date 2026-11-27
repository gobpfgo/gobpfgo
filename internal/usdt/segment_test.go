// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package usdt

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// loopTargetPath is the x86-64 static PIE the attach tests run. It fires
// gobpfgo:loop at two call sites.
const loopTargetPath = "../../testdata/progs/usdt_loop_target"

// testSegments are two PT_LOAD headers whose addresses and offsets differ,
// like a data segment after the text: text at file offset 0x1000 and address
// 0x401000, data at offset 0x2e00 and address 0x403e00.
var testSegments = []Segment{
	{Start: 0x401000, End: 0x402000, Offset: 0x1000, Exec: true},
	{Start: 0x403e00, End: 0x404100, Offset: 0x2e00},
}

func TestLocationOffset(t *testing.T) {
	tests := []struct {
		name     string
		baseAddr uint64
		segs     []Segment
		note     Note
		addr     uint64
		offset   uint64
		err      bool
	}{
		{name: "text", segs: testSegments, note: Note{Location: 0x401234}, addr: 0x401234, offset: 0x1234},
		{name: "segment start", segs: testSegments, note: Note{Location: 0x401000}, addr: 0x401000, offset: 0x1000},
		{name: "prelinked", baseAddr: 0x500100, segs: testSegments, note: Note{Location: 0x301234, Base: 0x400100}, addr: 0x401234, offset: 0x1234},
		{name: "prelinked down", baseAddr: 0x400100, segs: testSegments, note: Note{Location: 0x501234, Base: 0x500100}, addr: 0x401234, offset: 0x1234},
		{name: "no note base", baseAddr: 0x500100, segs: testSegments, note: Note{Location: 0x401234}, addr: 0x401234, offset: 0x1234},
		{name: "no file base", segs: testSegments, note: Note{Location: 0x401234, Base: 0x400100}, addr: 0x401234, offset: 0x1234},
		{name: "segment end", segs: testSegments, note: Note{Location: 0x402000}, addr: 0x402000, err: true},
		{name: "data", segs: testSegments, note: Note{Location: 0x403f00}, addr: 0x403f00, err: true},
		{name: "no segments", note: Note{Location: 0x401234}, addr: 0x401234, err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &File{BaseAddr: tt.baseAddr, Segments: tt.segs}
			if got := f.Address(tt.note); got != tt.addr {
				t.Errorf("Address = %#x, want %#x", got, tt.addr)
			}
			offset, err := f.LocationOffset(tt.note)
			if tt.err {
				checkError(t, err, ErrNoSegment, unix.ESRCH)
				return
			}
			if err != nil || offset != tt.offset {
				t.Fatalf("LocationOffset = %#x, %v, want %#x", offset, err, tt.offset)
			}
		})
	}
}

func TestSemaphoreOffset(t *testing.T) {
	// The semaphore address is not moved by the .stapsdt.base difference.
	f := &File{BaseAddr: 0x500100, Segments: testSegments}
	offset, err := f.SemaphoreOffset(Note{Semaphore: 0x403f00, Base: 0x400100})
	if err != nil || offset != 0x2f00 {
		t.Fatalf("SemaphoreOffset = %#x, %v, want 0x2f00", offset, err)
	}

	for _, sema := range []uint64{0x401100, 0x405000} {
		_, err := f.SemaphoreOffset(Note{Semaphore: sema})
		checkError(t, err, ErrNoSegment, unix.ESRCH)
	}
}

// sectionOffset converts addr to a file offset through the section that holds
// it, the second derivation the package documentation gives.
func sectionOffset(t *testing.T, f *elf.File, addr uint64) uint64 {
	t.Helper()

	for _, s := range f.Sections {
		if s.Flags&elf.SHF_ALLOC != 0 && s.Type != elf.SHT_NOBITS && s.Addr <= addr && addr < s.Addr+s.Size {
			return addr - s.Addr + s.Offset
		}
	}
	t.Fatalf("no section holds %#x", addr)
	return 0
}

// TestFixtureOffsets checks the segment-based offsets of the fixtures' probes
// and semaphore against the section-based ones.
func TestFixtureOffsets(t *testing.T) {
	for _, path := range []string{fixturePath, loopTargetPath} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			ef, err := elf.Open(path)
			if err != nil {
				t.Fatalf("elf.Open: %v", err)
			}
			defer ef.Close()

			notes, err := f.Notes()
			if err != nil || len(notes) == 0 {
				t.Fatalf("Notes = %d notes, %v", len(notes), err)
			}
			for _, note := range notes {
				offset, err := f.LocationOffset(note)
				if want := sectionOffset(t, ef, f.Address(note)); err != nil || offset != want {
					t.Errorf("%s:%s at %#x: offset %#x, %v, want %#x", note.Provider, note.Name, note.Location, offset, err, want)
				}
				if note.Semaphore == 0 {
					continue
				}
				offset, err = f.SemaphoreOffset(note)
				if want := sectionOffset(t, ef, note.Semaphore); err != nil || offset != want {
					t.Errorf("%s:%s semaphore: offset %#x, %v, want %#x", note.Provider, note.Name, offset, err, want)
				}
			}
		})
	}
}

func TestParseMaps(t *testing.T) {
	const maps = `55d0c0a00000-55d0c0a01000 r--p 00000000 103:02 1234                      /opt/my app/bin
55d0c0a01000-55d0c0a02000 r-xp 00001000 103:02 1234                      /opt/my app/bin
55d0c0a03000-55d0c0a04000 rw-p 00002000 103:02 1234                      /opt/my app/bin
7f0000000000-7f0000001000 r-xp 00000000 103:02 99                        /usr/lib/libc.so.6
7f0000002000-7f0000003000 rw-p 00000000 00:00 0
7f0000003000-7f0000005000 r-xp 00004000 103:02 1234                      /opt/my app/bin
7f0000006000-7f0000007000 r-xp 00000000 103:02 1235                      /opt/my app/bin (deleted)
7ffd00000000-7ffd00001000 r-xp 00000000 00:00 0                          [vdso]
malformed line
7f0000008000-7f0000009000 r-xp 00008000 103:02 1234                      /opt/my app/bin
`
	segs, err := parseMaps(strings.NewReader(maps), "/opt/my app/bin")
	if err != nil {
		t.Fatalf("parseMaps: %v", err)
	}
	want := []Segment{
		{Start: 0x55d0c0a01000, End: 0x55d0c0a02000, Offset: 0x1000, Exec: true},
		{Start: 0x7f0000003000, End: 0x7f0000005000, Offset: 0x4000, Exec: true},
	}
	if len(segs) != len(want) {
		t.Fatalf("segments = %+v, want %+v", segs, want)
	}
	for i := range want {
		if segs[i] != want[i] {
			t.Errorf("segment %d = %+v, want %+v", i, segs[i], want[i])
		}
	}

	seg, ok := FindMappedSegment(segs, 0x4abc)
	if !ok || seg != want[1] {
		t.Errorf("FindMappedSegment(0x4abc) = %+v, %v, want %+v", seg, ok, want[1])
	}
	if seg, ok := FindMappedSegment(segs, 0x6000); ok {
		t.Errorf("FindMappedSegment(0x6000) = %+v, want none", seg)
	}
}

func TestProcRootPath(t *testing.T) {
	tests := []struct {
		pid  int
		path string
		want string
		ok   bool
	}{
		{42, "/proc/42/root/usr/bin/app", "/usr/bin/app", true},
		{42, "/proc/43/root/usr/bin/app", "", false},
		{42, "/proc/42/cwd/app", "", false},
		{42, "/proc/42/root", "", false},
		{42, "/usr/bin/app", "", false},
	}
	for _, tt := range tests {
		got, ok := procRootPath(tt.pid, tt.path)
		if got != tt.want || ok != tt.ok {
			t.Errorf("procRootPath(%d, %q) = %q, %v, want %q, %v", tt.pid, tt.path, got, ok, tt.want, tt.ok)
		}
	}
}

// startLoopTarget runs the loop target until the test ends and waits until it
// is ready, so its mappings exist.
func startLoopTarget(t *testing.T, path string) *exec.Cmd {
	t.Helper()

	cmd := exec.Command(path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", path, err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Wait()
	})

	if f, ok := stdout.(*os.File); ok {
		_ = f.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("target said %q, %v, want ready", line, err)
	}
	return cmd
}

// TestProcessSegments starts the loop target, finds its executable mapping
// and checks that the runtime address of each probe holds the instruction
// bytes at the probe's file offset.
func TestProcessSegments(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the loop target is an x86-64 binary")
	}
	path, err := filepath.Abs(loopTargetPath)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	probes, err := f.Find("gobpfgo", "loop")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}

	cmd := startLoopTarget(t, path)
	pid := cmd.Process.Pid
	segs, err := ProcessSegments(pid, path)
	if err != nil {
		t.Fatalf("ProcessSegments: %v", err)
	}
	mem, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "mem"))
	if err != nil {
		t.Skipf("open target memory: %v", err)
	}
	defer mem.Close()

	for _, p := range probes {
		offset, err := f.LocationOffset(p.Note)
		if err != nil {
			t.Fatalf("LocationOffset: %v", err)
		}
		seg, ok := FindMappedSegment(segs, offset)
		if !ok {
			t.Fatalf("offset %#x is not in %+v", offset, segs)
		}
		ip := seg.Start - seg.Offset + offset

		got := make([]byte, 4)
		if _, err := mem.ReadAt(got, int64(ip)); err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EIO) {
				t.Skipf("read target memory: %v", err)
			}
			t.Fatalf("read target memory at %#x: %v", ip, err)
		}
		if want := file[offset : offset+4]; !bytes.Equal(got, want) {
			t.Errorf("probe at offset %#x: memory at %#x holds % x, file % x", offset, ip, got, want)
		}
	}

	_, err = ProcessSegments(pid, filepath.Join(t.TempDir(), "unmapped"))
	checkError(t, err, ErrNoSegment, unix.ESRCH)
}
