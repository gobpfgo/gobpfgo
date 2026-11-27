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
		{"plain uprobe", 9, false, 0, 0x1024, 0, 0},
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
// empty, so the largest valid offset reaches the lookup and gets ENOENT.
func TestPerfEventOpenUprobeRefCtrLimit(t *testing.T) {
	fakeUprobePMU(t, nil)

	tests := []struct {
		refCtrOffset uint64
		want         syscall.Errno
	}{
		{math.MaxUint32, unix.ENOENT},
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
// no PMU type at all, and a PMU without the retprobe format file, which only
// a uretprobe needs. Both are ENOENT, the error of the missing file, and
// neither reaches the kernel.
func TestPerfEventOpenUprobeNoPMU(t *testing.T) {
	t.Run("no type", func(t *testing.T) {
		fakeUprobePMU(t, nil)
		if _, err := determineUprobePerfType(); !errors.Is(err, unix.ENOENT) {
			t.Errorf("perf type: %v, want ENOENT", err)
		}
		fd, err := perfEventOpenUprobe(false, "/bin/true", 0x1000, -1, 0x3000)
		if fd != -1 || !errors.Is(err, unix.ENOENT) {
			t.Errorf("open: %d, %v, want ENOENT", fd, err)
		}
	})

	t.Run("no retprobe bit", func(t *testing.T) {
		fakeUprobePMU(t, map[string]string{"type": "9\n"})
		if _, err := determineUprobeRetprobeBit(); !errors.Is(err, unix.ENOENT) {
			t.Errorf("retprobe bit: %v, want ENOENT", err)
		}
		fd, err := perfEventOpenUprobe(true, "/bin/true", 0x1000, -1, 0x3000)
		if fd != -1 || !errors.Is(err, unix.ENOENT) {
			t.Errorf("open: %d, %v, want ENOENT", fd, err)
		}
	})
}

// TestProbePidCPU checks the perf_event_open pid and cpu of a uprobe: every
// process on CPU 0, or one process on every CPU.
func TestProbePidCPU(t *testing.T) {
	tests := []struct {
		pid, wantPid, wantCPU int
	}{
		{-1, -1, 0},
		{0, 0, -1},
		{4242, 4242, -1},
		{-2, -1, -1},
	}
	for _, tt := range tests {
		if pid, cpu := probePidCPU(tt.pid); pid != tt.wantPid || cpu != tt.wantCPU {
			t.Errorf("probePidCPU(%d) = %d, %d, want %d, %d", tt.pid, pid, cpu, tt.wantPid, tt.wantCPU)
		}
	}
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

// uprobeRoute is one attach of TestBpfProgramAttachUprobeRouting: the uprobe
// PMU files the kernel has, the options, the expected error and the tracefs
// commands the attach must leave, "" for none.
type uprobeRoute struct {
	name   string
	pmu    map[string]string
	opts   BpfUprobeOpts
	want   syscall.Errno
	events string
}

// TestBpfProgramAttachUprobeRouting checks which path a uprobe attach takes
// without a kernel: tracefs is a temporary directory and the uprobe PMU
// directory holds the case's files. A tracefs attach writes its event and
// fails with ENOENT on the missing event ID, which removes the event again; a
// PMU attach stops at the missing retprobe bit or the 32-bit counter limit and
// leaves tracefs alone. Without the PMU type the default mode takes tracefs,
// the perf and link modes are EOPNOTSUPP and a reference counter is EINVAL.
// A BPF cookie is not refused before the attach.
func TestBpfProgramAttachUprobeRouting(t *testing.T) {
	events := fakeTracefs(t)
	const target = "/nonexistent/usdt_sema_target"
	pmu := map[string]string{"type": "9\n"}

	tests := []uprobeRoute{
		{"default without PMU", nil, BpfUprobeOpts{}, unix.ENOENT, "uprobes"},
		{"uretprobe without PMU", nil, BpfUprobeOpts{Retprobe: true}, unix.ENOENT, "uretprobes"},
		{"cookie without PMU", nil, BpfUprobeOpts{BpfCookie: 1}, unix.ENOENT, "uprobes"},
		{"counter without PMU", nil, BpfUprobeOpts{RefCtrOffset: 0x3000}, unix.EINVAL, ""},
		{"counter past 32 bits without PMU", nil, BpfUprobeOpts{RefCtrOffset: 1 << 32}, unix.EINVAL, ""},
		{"legacy without PMU", nil, BpfUprobeOpts{AttachMode: ProbeAttachModeLegacy}, unix.ENOENT, "uprobes"},
		{"perf without PMU", nil, BpfUprobeOpts{AttachMode: ProbeAttachModePerf}, unix.EOPNOTSUPP, ""},
		{"link without PMU", nil, BpfUprobeOpts{AttachMode: ProbeAttachModeLink}, unix.EOPNOTSUPP, ""},
		{"unknown mode", nil, BpfUprobeOpts{AttachMode: ProbeAttachModeLink + 1}, unix.EINVAL, ""},
		{"negative mode", pmu, BpfUprobeOpts{AttachMode: -1}, unix.EINVAL, ""},
		{"uretprobe without retprobe bit", pmu, BpfUprobeOpts{Retprobe: true}, unix.ENOENT, ""},
		{"perf uretprobe without retprobe bit", pmu, BpfUprobeOpts{Retprobe: true, AttachMode: ProbeAttachModePerf}, unix.ENOENT, ""},
		{"counter past 32 bits", pmu, BpfUprobeOpts{RefCtrOffset: 1 << 32}, unix.EINVAL, ""},
		{"legacy with PMU", pmu, BpfUprobeOpts{AttachMode: ProbeAttachModeLegacy}, unix.ENOENT, "uprobes"},
		{"legacy uretprobe with PMU", pmu, BpfUprobeOpts{Retprobe: true, AttachMode: ProbeAttachModeLegacy}, unix.ENOENT, "uretprobes"},
		{"legacy counter with PMU", pmu, BpfUprobeOpts{RefCtrOffset: 0x3000, AttachMode: ProbeAttachModeLegacy}, unix.EINVAL, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeUprobePMU(t, tt.pmu)
			if err := os.Truncate(events, 0); err != nil {
				t.Fatal(err)
			}

			link, err := BpfProgramAttachUprobeOpts(fakeLoadedProgram(), -1, target, 0x1024, &tt.opts)
			if link != nil {
				BpfLinkDestroy(link)
				t.Fatal("attach returned a link")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("attach error = %v, want %v", err, tt.want)
			}
			checkUprobeEventCommands(t, string(readTestFile(t, events)), tt.events, target+":0x1024")
		})
	}
}

// checkUprobeEventCommands requires the tracefs commands to add an event to
// group for location and remove it again, or, when group is "", to be empty.
func checkUprobeEventCommands(t *testing.T, commands, group, location string) {
	t.Helper()

	if group == "" {
		if commands != "" {
			t.Fatalf("uprobe_events got %q, want nothing", commands)
		}
		return
	}
	prefix := "p:"
	if group == "uretprobes" {
		prefix = "r:"
	}
	lines := strings.Split(strings.TrimSuffix(commands, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], prefix+group+"/gobpfgo_") ||
		!strings.HasSuffix(lines[0], " "+location) || !strings.HasPrefix(lines[1], "-:"+group+"/gobpfgo_") {
		t.Fatalf("uprobe_events got %q, want a %s event added and removed", commands, group)
	}
}
