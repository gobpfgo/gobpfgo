// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeLoadedProgram is a program that passes the loaded check. Its
// descriptor is a number no process has open, so the tests fail before they
// could attach it to anything.
func fakeLoadedProgram() *BpfProgram {
	return &BpfProgram{fd: 1 << 30}
}

// fakeUprobePMU points the uprobe PMU directory at a temporary directory
// holding files, a map from path inside the directory to its contents, for
// the rest of the test.
func fakeUprobePMU(t *testing.T, files map[string]string) {
	t.Helper()

	dir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	saved := uprobePMUDir
	uprobePMUDir = dir
	t.Cleanup(func() { uprobePMUDir = saved })
}

// fakeTracefs points the tracefs root at a temporary directory with empty
// probe control files for the rest of the test, and returns the path of its
// uprobe_events file. The tracefs uprobe path appends its commands there and
// then fails with ENOENT, because the directory has no event IDs.
func fakeTracefs(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for _, name := range []string{"kprobe_events", "uprobe_events"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	saved := tracefsRoots
	tracefsRoots = []string{root}
	t.Cleanup(func() { tracefsRoots = saved })
	return filepath.Join(root, "uprobe_events")
}

// TestUprobePerfEventAttr checks the attribute of a uprobe PMU event for a
// PMU type and retprobe bit given by the test: the type and size, the
// reference counter offset in the upper half of config, the retprobe bit only
// for a uretprobe, and the probe offset in config2.
func TestUprobePerfEventAttr(t *testing.T) {
	tests := []struct {
		name         string
		perfType     uint32
		retprobe     bool
		retprobeBit  uint32
		offset       uint64
		refCtrOffset uint64
		wantConfig   uint64
	}{
		{"uprobe", 9, false, 0, 0x1024, 0x3000, 0x0000_3000_0000_0000},
		{"uretprobe", 9, true, 0, 0x1024, 0x3000, 0x0000_3000_0000_0001},
		{"bit unused for a uprobe", 7, false, 5, 0x24, 0x2, 0x0000_0002_0000_0000},
		{"other retprobe bit", 7, true, 5, 0x24, 0x2, 0x0000_0002_0000_0020},
		{"largest counter", 9, false, 0, 0x1000, math.MaxUint32, 0xffff_ffff_0000_0000},
		{"no counter", 9, true, 0, 0x10, 0, 0x0000_0000_0000_0001},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uprobePerfEventAttr(tt.perfType, tt.retprobe, tt.retprobeBit, tt.offset, tt.refCtrOffset)
			want := unix.PerfEventAttr{
				Type:   tt.perfType,
				Size:   perfEventAttrSize,
				Config: tt.wantConfig,
				Ext2:   tt.offset,
			}
			if got != want {
				t.Errorf("attr = %+v, want %+v", got, want)
			}
		})
	}
}

// TestPerfEventOpenUprobeRefCtrLimit checks that a reference counter offset
// past 32 bits is EINVAL before the PMU is looked up: the PMU directory is
// empty, so the largest valid offset reaches the lookup and gets EOPNOTSUPP.
func TestPerfEventOpenUprobeRefCtrLimit(t *testing.T) {
	fakeUprobePMU(t, nil)

	tests := []struct {
		refCtrOffset uint64
		want         syscall.Errno
	}{
		{math.MaxUint32, unix.EOPNOTSUPP},
		{1 << 32, unix.EINVAL},
		{math.MaxUint64, unix.EINVAL},
	}
	for _, tt := range tests {
		fd, err := perfEventOpenUprobe(false, "/bin/true", 0x1000, -1, tt.refCtrOffset)
		if fd != -1 || !errors.Is(err, tt.want) {
			t.Errorf("refCtrOffset %#x: %d, %v, want %v", tt.refCtrOffset, fd, err, tt.want)
		}
	}
}

// TestPerfEventOpenUprobeNoPMU covers kernels without the uprobe PMU files:
// no PMU type at all, and a PMU without the retprobe format bit, which only
// a uretprobe needs. Both are EOPNOTSUPP and neither reaches the kernel.
func TestPerfEventOpenUprobeNoPMU(t *testing.T) {
	t.Run("no type", func(t *testing.T) {
		fakeUprobePMU(t, nil)
		if _, err := determineUprobePerfType(); !errors.Is(err, unix.EOPNOTSUPP) {
			t.Errorf("perf type: %v, want EOPNOTSUPP", err)
		}
		fd, err := perfEventOpenUprobe(false, "/bin/true", 0x1000, -1, 0x3000)
		if fd != -1 || !errors.Is(err, unix.EOPNOTSUPP) {
			t.Errorf("open: %d, %v, want EOPNOTSUPP", fd, err)
		}
	})

	t.Run("no retprobe bit", func(t *testing.T) {
		fakeUprobePMU(t, map[string]string{"type": "9\n"})
		if _, err := determineUprobeRetprobeBit(); !errors.Is(err, unix.EOPNOTSUPP) {
			t.Errorf("retprobe bit: %v, want EOPNOTSUPP", err)
		}
		fd, err := perfEventOpenUprobe(true, "/bin/true", 0x1000, -1, 0x3000)
		if fd != -1 || !errors.Is(err, unix.EOPNOTSUPP) {
			t.Errorf("open: %d, %v, want EOPNOTSUPP", fd, err)
		}
	})
}

// TestUprobePMUFiles reads the PMU type and the retprobe bit in the kernel's
// sysfs formats. Like the C library's scanf, the number may follow white
// space and ends at the first other byte; a file without one is EIO.
func TestUprobePMUFiles(t *testing.T) {
	const typeFile, bitFile = "type", "format/retprobe"
	readers := map[string]func() (uint32, error){
		typeFile: determineUprobePerfType,
		bitFile:  determineUprobeRetprobeBit,
	}

	tests := []struct {
		name string
		file string
		data string
		want uint32
		err  syscall.Errno
	}{
		{"type", typeFile, "9\n", 9, 0},
		{"type without newline", typeFile, "7", 7, 0},
		{"type after spaces", typeFile, " 12\n", 12, 0},
		{"type with trailing text", typeFile, "9 uprobe\n", 9, 0},
		{"type not a number", typeFile, "uprobe\n", 0, unix.EIO},
		{"type negative", typeFile, "-1\n", 0, unix.EIO},
		{"type past 31 bits", typeFile, "2147483648\n", 0, unix.EIO},
		{"type empty", typeFile, "", 0, unix.EIO},
		{"bit", bitFile, "config:0\n", 0, 0},
		{"other bit", bitFile, "config:12", 12, 0},
		{"bit range", bitFile, "config:3-4\n", 3, 0},
		{"bit without prefix", bitFile, "0\n", 0, unix.EIO},
		{"bit of another field", bitFile, "config1:0\n", 0, unix.EIO},
		{"bit negative", bitFile, "config:-1\n", 0, unix.EIO},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeUprobePMU(t, map[string]string{tt.file: tt.data})
			got, err := readers[tt.file]()
			if tt.err != 0 {
				if !errors.Is(err, tt.err) {
					t.Fatalf("read %s %q = %d, %v, want %v", tt.file, tt.data, got, err, tt.err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("read %s %q = %d, %v, want %d", tt.file, tt.data, got, err, tt.want)
			}
		})
	}
}

// TestBpfProgramAttachUprobeRefCtrPath checks which path a uprobe attach
// takes without a kernel: tracefs is a temporary directory and the uprobe PMU
// directory is empty. Without a reference counter the attach writes its
// tracefs event and fails with ENOENT on the missing event ID; with one it
// goes to the PMU instead, which is EOPNOTSUPP here, or EINVAL for an offset
// past 32 bits, and leaves tracefs alone. A BPF cookie is EOPNOTSUPP on both.
func TestBpfProgramAttachUprobeRefCtrPath(t *testing.T) {
	events := fakeTracefs(t)
	fakeUprobePMU(t, nil)
	const target = "/nonexistent/usdt_sema_target"

	tests := []struct {
		name       string
		opts       *BpfUprobeOpts
		want       syscall.Errno
		wantEvents bool
	}{
		{"no counter", &BpfUprobeOpts{}, unix.ENOENT, true},
		{"counter", &BpfUprobeOpts{RefCtrOffset: 0x3000}, unix.EOPNOTSUPP, false},
		{"counter past 32 bits", &BpfUprobeOpts{RefCtrOffset: 1 << 32}, unix.EINVAL, false},
		{"retprobe counter", &BpfUprobeOpts{Retprobe: true, RefCtrOffset: 0x3000}, unix.EOPNOTSUPP, false},
		{"cookie", &BpfUprobeOpts{BpfCookie: 1}, unix.EOPNOTSUPP, false},
		{"cookie and counter", &BpfUprobeOpts{BpfCookie: 1, RefCtrOffset: 0x3000}, unix.EOPNOTSUPP, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Truncate(events, 0); err != nil {
				t.Fatal(err)
			}

			link, err := BpfProgramAttachUprobeOpts(fakeLoadedProgram(), -1, target, 0x1024, tt.opts)
			if link != nil {
				BpfLinkDestroy(link)
				t.Fatal("attach returned a link")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("attach error = %v, want %v", err, tt.want)
			}

			commands := string(readTestFile(t, events))
			if !tt.wantEvents {
				if commands != "" {
					t.Fatalf("uprobe_events got %q, want nothing", commands)
				}
				return
			}
			lines := strings.Split(strings.TrimSuffix(commands, "\n"), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "p:uprobes/gobpfgo_") ||
				!strings.HasSuffix(lines[0], " "+target+":0x1024") || !strings.HasPrefix(lines[1], "-:uprobes/gobpfgo_") {
				t.Fatalf("uprobe_events got %q, want the event added and removed", commands)
			}
		})
	}
}
