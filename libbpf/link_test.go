// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type attachCase struct {
	Kind        string `json:"kind"`
	Object      string `json:"object"`
	Program     string `json:"program"`
	Category    string `json:"category"`
	Target      string `json:"target"`
	Retprobe    bool   `json:"retprobe"`
	Cookie      bool   `json:"cookie"`
	CookieValue uint64 `json:"cookie_value"`
	Supported   bool   `json:"supported"`
	Triggered   bool   `json:"triggered"`
}

type attachFixture struct {
	Cases []attachCase `json:"cases"`
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
	if len(f.Cases) == 0 {
		t.Fatal("attach fixture has no cases")
	}
	return f
}

func TestPerfEventAttrSize(t *testing.T) {
	if got := int(reflect.TypeOf(unix.PerfEventAttr{}).Size()); got != perfEventAttrSize {
		t.Fatalf("sizeof(perf_event_attr) = %d, want %d", got, perfEventAttrSize)
	}
}

func TestBpfProgramAttachTypes(t *testing.T) {
	f := loadAttachFixture(t)

	for _, c := range f.Cases {
		t.Run(c.Kind, func(t *testing.T) {
			if !c.Supported {
				t.Skip("libbpf reported the attach type as unsupported")
			}
			if c.Kind == "lsm" && !bpfLsmActive() {
				t.Skip("BPF LSM is not active in this kernel")
			}

			obj := loadTestObject(t, "../testdata/progs/"+c.Object)
			defer BpfObjectClose(obj)

			prog := BpfObjectFindProgramByName(obj, c.Program)
			if prog == nil {
				t.Fatalf("program %q not found", c.Program)
			}
			link, err := attachCaseProgram(t, prog, c)
			if err != nil {
				if isAttachUnsupported(err) {
					t.Skipf("attach type is not supported by this kernel: %v", err)
				}
				t.Fatalf("attach: %v", err)
			}
			if fd := BpfLinkFD(link); fd < 0 {
				t.Fatalf("link fd = %d", fd)
			}

			triggerAttachCase(t, c)

			mapName := "counts"
			if c.Cookie {
				mapName = "cookies"
			}
			got := mapValue(t, obj, mapName)
			if c.Cookie && got != c.CookieValue {
				t.Fatalf("%s value = %d, want cookie %d", mapName, got, c.CookieValue)
			}
			if !c.Cookie && got == 0 {
				t.Fatalf("%s value = 0, want a nonzero count", mapName)
			}

			if err := BpfLinkDetach(link); err != nil {
				t.Fatalf("detach: %v", err)
			}
			if fd := BpfLinkFD(link); fd != -1 {
				t.Fatalf("link fd after detach = %d, want -1", fd)
			}
			if err := BpfLinkDetach(link); err != nil {
				t.Fatalf("second detach: %v", err)
			}
			BpfLinkDestroy(link)
			BpfLinkDestroy(link)
		})
	}
}

func TestBpfProgramAttachPerfEventIoctl(t *testing.T) {
	obj := loadTestObject(t, "../testdata/progs/tracepoint.bpf.o")
	defer BpfObjectClose(obj)
	prog := BpfObjectFindProgramByName(obj, "handle_tracepoint")
	if prog == nil {
		t.Fatal("program handle_tracepoint not found")
	}

	id, err := tracepointID("syscalls", "sys_enter_openat")
	if err != nil {
		t.Fatalf("tracepoint id: %v", err)
	}
	perfFD, err := openTracepointPerf(id, -1, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("perf_event_open not permitted: %v", err)
		}
		t.Fatalf("perf_event_open: %v", err)
	}

	link, err := BpfProgramAttachPerfEventOpts(prog, perfFD, &BpfPerfEventOpts{ForceIoctlAttach: true})
	if err != nil {
		unix.Close(perfFD)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("perf event attach not permitted: %v", err)
		}
		t.Fatalf("attach perf event: %v", err)
	}
	defer BpfLinkDestroy(link)

	triggerOpen(t)
	if got := mapValue(t, obj, "counts"); got == 0 {
		t.Fatal("perf event attach did not increment counts")
	}
}

func TestBpfProgramAttachAuto(t *testing.T) {
	for _, path := range []string{"kprobe.bpf.o", "fentry.bpf.o"} {
		t.Run(path, func(t *testing.T) {
			obj := loadTestObject(t, "../testdata/progs/"+path)
			defer BpfObjectClose(obj)

			prog := BpfObjectFindProgramByName(obj, programNameForObject(path))
			if prog == nil {
				t.Fatalf("program not found in %s", path)
			}
			link, err := BpfProgramAttach(prog)
			if err != nil {
				if isAttachUnsupported(err) {
					t.Skipf("auto attach is not supported: %v", err)
				}
				t.Fatalf("auto attach: %v", err)
			}
			defer BpfLinkDestroy(link)

			triggerOpen(t)
			if got := mapValue(t, obj, "counts"); got == 0 {
				t.Fatal("auto attach did not increment counts")
			}
		})
	}
}

func TestBpfLinkPin(t *testing.T) {
	obj := loadTestObject(t, "../testdata/progs/fentry.bpf.o")
	defer BpfObjectClose(obj)
	prog := BpfObjectFindProgramByName(obj, "handle_fentry")
	if prog == nil {
		t.Fatal("program handle_fentry not found")
	}

	link, err := BpfProgramAttachTrace(prog)
	if err != nil {
		if isAttachUnsupported(err) {
			t.Skipf("fentry attach is not supported: %v", err)
		}
		t.Fatalf("attach trace: %v", err)
	}

	path := fmt.Sprintf("/sys/fs/bpf/gobpfgo-test-%d-link", os.Getpid())
	_ = os.Remove(path)
	if err := BpfLinkPin(link, path); err != nil {
		BpfLinkDestroy(link)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EINVAL) {
			t.Skipf("link pinning is not available: %v", err)
		}
		t.Fatalf("pin: %v", err)
	}
	if got := BpfLinkPinPath(link); got != path {
		t.Fatalf("pin path = %q, want %q", got, path)
	}
	if err := BpfLinkPin(link, path); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("second pin = %v, want EBUSY", err)
	}

	triggerOpen(t)
	if got := mapValue(t, obj, "counts"); got == 0 {
		t.Fatal("pinned link did not increment counts")
	}

	// Destroy only closes the descriptor; the pinned link stays attached.
	BpfLinkDestroy(link)
	opened, err := BpfLinkOpen(path)
	if err != nil {
		t.Fatalf("open pinned link: %v", err)
	}
	if fd := BpfLinkFD(opened); fd < 0 {
		t.Fatalf("opened link fd = %d", fd)
	}
	if got := BpfLinkPinPath(opened); got != path {
		t.Fatalf("opened pin path = %q, want %q", got, path)
	}

	triggerOpen(t)
	if got := mapValue(t, obj, "counts"); got < 2 {
		t.Fatalf("reopened link count = %d, want at least 2", got)
	}

	if err := BpfLinkUnpin(opened); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	BpfLinkDestroy(opened)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pin path still exists: %v", err)
	}
	if err := BpfLinkUnpin(opened); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("unpin without a path = %v, want EINVAL", err)
	}
}

func TestBpfLinkUpdateProgram(t *testing.T) {
	first := loadTestObject(t, "../testdata/progs/tracepoint.bpf.o")
	defer BpfObjectClose(first)
	second := loadTestObject(t, "../testdata/progs/tracepoint_alt.bpf.o")
	defer BpfObjectClose(second)

	prog := BpfObjectFindProgramByName(first, "handle_tracepoint")
	alt := BpfObjectFindProgramByName(second, "handle_alt")
	if prog == nil || alt == nil {
		t.Fatal("tracepoint programs not found")
	}

	link, err := BpfProgramAttachTracepoint(prog, "syscalls", "sys_enter_openat")
	if err != nil {
		if isAttachUnsupported(err) {
			t.Skipf("tracepoint attach is not supported: %v", err)
		}
		t.Fatalf("attach tracepoint: %v", err)
	}
	defer BpfLinkDestroy(link)

	triggerOpen(t)
	if got := mapValue(t, first, "counts"); got == 0 {
		t.Fatal("first program did not run")
	}

	if err := BpfLinkUpdateProgram(link, alt); err != nil {
		if isAttachUnsupported(err) {
			t.Skipf("link update is not supported by this kernel: %v", err)
		}
		t.Fatalf("update program: %v", err)
	}

	triggerOpen(t)
	if got := mapValue(t, second, "alt"); got != 0x99 {
		t.Fatalf("updated program value = %#x, want 0x99", got)
	}
}

func TestBpfLinkUpdateUnloadedProgram(t *testing.T) {
	link := &BpfLink{fd: -1, perfFD: -1}
	if err := BpfLinkUpdateProgram(link, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("update unloaded = %v, want EINVAL", err)
	}
}

// uprobeTarget is the function the uprobe cases attach to. The noinline
// directive keeps a symbol the ELF lookup can find.
//
//go:noinline
func uprobeTarget() {
	uprobeTargetCalls++
}

var uprobeTargetCalls int

// uprobeTargetOffset returns the file offset of uprobeTarget in the running
// test binary. The go test runner strips the binary, so the offset comes from
// the runtime entry address and the executable section headers instead of the
// symbol table.
func uprobeTargetOffset(t *testing.T) uint64 {
	t.Helper()

	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatalf("open self: %v", err)
	}
	defer f.Close()

	entry := uint64(runtime.FuncForPC(reflect.ValueOf(uprobeTarget).Pointer()).Entry())
	base := uint64(0)
	if f.Type == elf.ET_DYN {
		base = executableBase(t)
	}
	for _, section := range f.Sections {
		if section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		start := base + section.Addr
		if entry >= start && entry < start+section.Size {
			return entry - base - section.Addr + section.Offset
		}
	}

	t.Fatalf("function entry %#x is not in an executable section", entry)
	return 0
}

// executableBase returns the load address of the first executable mapping of
// the running binary. It is only needed for position-independent binaries.
func executableBase(t *testing.T) uint64 {
	t.Helper()

	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatalf("readlink self: %v", err)
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read maps: %v", err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[5] != exe || fields[2] != "00000000" {
			continue
		}
		start := strings.SplitN(fields[0], "-", 2)[0]
		addr, err := strconv.ParseUint(start, 16, 64)
		if err != nil {
			t.Fatalf("parse map start %q: %v", start, err)
		}
		return addr
	}

	t.Fatalf("no mapping for %s", exe)
	return 0
}

func attachCaseProgram(t *testing.T, prog *BpfProgram, c attachCase) (*BpfLink, error) {
	t.Helper()

	switch c.Kind {
	case "kprobe", "kretprobe":
		return BpfProgramAttachKprobe(prog, c.Retprobe, c.Target)
	case "tracepoint":
		return BpfProgramAttachTracepoint(prog, c.Category, c.Target)
	case "uprobe", "uretprobe":
		return BpfProgramAttachUprobeOpts(prog, 0, "/proc/self/exe", uprobeTargetOffset(t), &BpfUprobeOpts{
			Retprobe: c.Retprobe,
		})
	case "fentry", "fexit":
		return BpfProgramAttachTrace(prog)
	case "lsm":
		return BpfProgramAttachLsm(prog)
	case "raw_tracepoint":
		return BpfProgramAttachRawTracepoint(prog, c.Target)
	case "kprobe_multi", "kretprobe_multi":
		return BpfProgramAttachKprobeMulti(prog, &BpfKprobeMultiOpts{
			Symbols:  []string{c.Target},
			Retprobe: c.Retprobe,
		})
	case "cookie":
		return BpfProgramAttachTracepointOpts(prog, c.Category, c.Target, &BpfTracepointOpts{
			BpfCookie: c.CookieValue,
		})
	default:
		return nil, fmt.Errorf("unknown attach case %q", c.Kind)
	}
}

func triggerAttachCase(t *testing.T, c attachCase) {
	t.Helper()

	if strings.HasPrefix(c.Kind, "uprobe") || strings.HasPrefix(c.Kind, "uretprobe") {
		uprobeTarget()
		return
	}
	triggerOpen(t)
}

func triggerOpen(t *testing.T) {
	t.Helper()

	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	_ = file.Close()
}

func loadTestObject(t *testing.T, path string) *BpfObject {
	t.Helper()

	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("load %s: %v", path, err)
	}
	return obj
}

// bpfLsmActive reports whether the kernel has the BPF LSM enabled. Without
// it an LSM program attaches but its hook never runs.
func bpfLsmActive() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, name := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if name == "bpf" {
			return true
		}
	}
	return false
}

func isAttachUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTSUP)
}

func programNameForObject(path string) string {
	switch path {
	case "kprobe.bpf.o":
		return "handle_open"
	case "fentry.bpf.o":
		return "handle_fentry"
	default:
		return ""
	}
}

func mapValue(t *testing.T, obj *BpfObject, name string) uint64 {
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
		t.Fatalf("lookup %s: %v", name, err)
	}
	return binary.NativeEndian.Uint64(value)
}
