// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The kprobe the mode cases attach to, which the counting program in
// kprobe.bpf.o targets, and the cookie the cookie cases expect it to read.
const (
	kprobeModeTarget = "do_sys_openat2"
	kprobeModeCookie = 0x0bad_cafe_f00d_0002
)

// fakeKprobePMU fakes the kprobe PMU directory with files; see fakeProbePMU.
func fakeKprobePMU(t *testing.T, files map[string]string) {
	t.Helper()
	fakeProbePMU(t, &kprobePMUDir, files)
}

// TestKprobePerfEventAttr checks the attribute of a kprobe PMU event for a
// PMU type and retprobe bit given by the test: the type and size, the
// retprobe bit in config only for a kretprobe, and in config2 the offset into
// the function or the raw address. A kprobe has no reference counter, so the
// upper half of config stays clear; config1, the function name, is set by
// the internal/sys open call.
func TestKprobePerfEventAttr(t *testing.T) {
	tests := []struct {
		name        string
		perfType    uint32
		retprobe    bool
		retprobeBit uint32
		offset      uint64
		wantConfig  uint64
	}{
		{"kprobe", 6, false, 0, 0, 0},
		{"kprobe at an offset", 6, false, 0, 0x10, 0},
		{"kretprobe", 6, true, 0, 0, 1},
		{"bit unused for a kprobe", 8, false, 3, 0x24, 0},
		{"other retprobe bit", 8, true, 3, 0, 0x8},
		{"raw address", 6, false, 0, 0xffff_ffff_8123_4560, 0},
		{"raw kretprobe", 6, true, 0, 0xffff_ffff_8123_4560, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probePerfEventAttr(tt.perfType, tt.retprobe, tt.retprobeBit, tt.offset, 0)
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

// TestPerfEventOpenKprobeNoPMU covers kernels without the kprobe PMU files:
// no PMU type at all, and a PMU without the retprobe format file, which only
// a kretprobe needs. Both are ENOENT, the error of the missing file, and
// neither reaches the kernel. A complete uprobe PMU must not stand in for the
// kprobe one.
func TestPerfEventOpenKprobeNoPMU(t *testing.T) {
	fakeUprobePMU(t, map[string]string{"type": "7\n", "format/retprobe": "config:0\n"})

	t.Run("no type", func(t *testing.T) {
		fakeKprobePMU(t, nil)
		if _, err := determineKprobePerfType(); !errors.Is(err, unix.ENOENT) {
			t.Errorf("perf type: %v, want ENOENT", err)
		}
		fd, err := perfEventOpenProbe(false, false, kprobeModeTarget, 0, -1, 0)
		if fd != -1 || !errors.Is(err, unix.ENOENT) {
			t.Errorf("open: %d, %v, want ENOENT", fd, err)
		}
	})

	t.Run("no retprobe bit", func(t *testing.T) {
		fakeKprobePMU(t, map[string]string{"type": "6\n"})
		if _, err := determineKprobeRetprobeBit(); !errors.Is(err, unix.ENOENT) {
			t.Errorf("retprobe bit: %v, want ENOENT", err)
		}
		fd, err := perfEventOpenProbe(false, true, kprobeModeTarget, 0, -1, 0)
		if fd != -1 || !errors.Is(err, unix.ENOENT) {
			t.Errorf("open: %d, %v, want ENOENT", fd, err)
		}
	})
}

// kprobeRoute is one attach of TestBpfProgramAttachKprobeRouting: the kprobe
// PMU files the kernel has, the function name and options, the expected error
// and the tracefs group the attach must add and remove an event in, "" for
// none.
type kprobeRoute struct {
	name     string
	pmu      map[string]string
	funcName string
	opts     BpfKprobeOpts
	want     syscall.Errno
	events   string
}

// TestBpfProgramAttachKprobeRouting checks which path a kprobe attach takes
// without a kernel: tracefs is a temporary directory and the kprobe PMU
// directory holds the case's files, while the uprobe PMU is complete. A
// tracefs attach writes its event and fails with ENOENT on the missing event
// ID, which removes the event again; a PMU attach stops at the missing
// retprobe bit and leaves tracefs alone. Without the PMU type the default
// mode takes tracefs and the perf and link modes are EOPNOTSUPP. An empty
// function name, a raw address, is EOPNOTSUPP on the tracefs path and goes to
// the PMU otherwise. A BPF cookie is not refused before the attach. The
// tracefs event is named as libbpf names it, after the function and offset.
func TestBpfProgramAttachKprobeRouting(t *testing.T) {
	events := filepath.Join(fakeTracefs(t), kprobeEventsFile)
	fakeUprobePMU(t, map[string]string{"type": "7\n", "format/retprobe": "config:0\n"})
	pmu := map[string]string{"type": "6\n"}
	const fn, raw = kprobeModeTarget, ""
	const addr = 0xffff_ffff_8123_4560

	tests := []kprobeRoute{
		{"default without PMU", nil, fn, BpfKprobeOpts{Offset: 0x10}, unix.ENOENT, "kprobes"},
		{"kretprobe without PMU", nil, fn, BpfKprobeOpts{Retprobe: true}, unix.ENOENT, "kretprobes"},
		{"cookie without PMU", nil, fn, BpfKprobeOpts{BpfCookie: 1}, unix.ENOENT, "kprobes"},
		{"raw address without PMU", nil, raw, BpfKprobeOpts{Offset: addr}, unix.EOPNOTSUPP, ""},
		{"legacy without PMU", nil, fn, BpfKprobeOpts{AttachMode: ProbeAttachModeLegacy}, unix.ENOENT, "kprobes"},
		{"perf without PMU", nil, fn, BpfKprobeOpts{AttachMode: ProbeAttachModePerf}, unix.EOPNOTSUPP, ""},
		{"link without PMU", nil, fn, BpfKprobeOpts{AttachMode: ProbeAttachModeLink}, unix.EOPNOTSUPP, ""},
		{"perf raw address without PMU", nil, raw, BpfKprobeOpts{Offset: addr, AttachMode: ProbeAttachModePerf}, unix.EOPNOTSUPP, ""},
		{"unknown mode", nil, fn, BpfKprobeOpts{AttachMode: ProbeAttachModeLink + 1}, unix.EINVAL, ""},
		{"negative mode", pmu, fn, BpfKprobeOpts{AttachMode: -1}, unix.EINVAL, ""},
		{"kretprobe without retprobe bit", pmu, fn, BpfKprobeOpts{Retprobe: true}, unix.ENOENT, ""},
		{"raw kretprobe without retprobe bit", pmu, raw, BpfKprobeOpts{Retprobe: true, Offset: addr}, unix.ENOENT, ""},
		{"perf kretprobe without retprobe bit", pmu, fn, BpfKprobeOpts{Retprobe: true, AttachMode: ProbeAttachModePerf}, unix.ENOENT, ""},
		{"legacy with PMU", pmu, fn, BpfKprobeOpts{Offset: 0x10, AttachMode: ProbeAttachModeLegacy}, unix.ENOENT, "kprobes"},
		{"legacy kretprobe with PMU", pmu, fn, BpfKprobeOpts{Retprobe: true, AttachMode: ProbeAttachModeLegacy}, unix.ENOENT, "kretprobes"},
		{"legacy raw address with PMU", pmu, raw, BpfKprobeOpts{Offset: addr, AttachMode: ProbeAttachModeLegacy}, unix.EOPNOTSUPP, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKprobePMU(t, tt.pmu)
			if err := os.Truncate(events, 0); err != nil {
				t.Fatal(err)
			}

			seq := attachSeq.Load()
			link, err := BpfProgramAttachKprobeOpts(fakeLoadedProgram(), tt.funcName, &tt.opts)
			if link != nil {
				BpfLinkDestroy(link)
				t.Fatal("attach returned a link")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("attach error = %v, want %v", err, tt.want)
			}
			name := fmt.Sprintf("libbpf_%d_%d_%s_0x%x", os.Getpid(), seq, tt.funcName, tt.opts.Offset)
			location := fmt.Sprintf("%s+0x%x", tt.funcName, tt.opts.Offset)
			checkProbeEventCommands(t, string(readTestFile(t, events)), tt.events, name, location)
			checkProbeEventSeq(t, seq, tt.events != "")
		})
	}
}

// TestAttachProbePerfEventFailure checks that a failed probe attach closes
// the perf descriptor and removes the tracefs event. A cookie on the ioctl
// path is EOPNOTSUPP before the kernel is asked, and the ioctl on a pipe,
// which is not a perf event, fails in the kernel with ENOTTY.
func TestAttachProbePerfEventFailure(t *testing.T) {
	root := fakeTracefs(t)
	events := filepath.Join(root, kprobeEventsFile)

	tests := []struct {
		name string
		opts BpfPerfEventOpts
		want syscall.Errno
	}{
		{"cookie on the ioctl path", BpfPerfEventOpts{BpfCookie: kprobeModeCookie, ForceIoctlAttach: true}, unix.EOPNOTSUPP},
		{"ioctl on a pipe", BpfPerfEventOpts{ForceIoctlAttach: true}, unix.ENOTTY},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Truncate(events, 0); err != nil {
				t.Fatal(err)
			}
			const name = "libbpf_1_0_do_sys_openat2_0x0"
			event := &legacyEvent{root: root, kind: probeKprobe, name: name}
			if err := event.add("p:kprobes/" + name + " do_sys_openat2+0x0"); err != nil {
				t.Fatal(err)
			}
			pfd := pipeReadEnd(t)

			link, err := attachProbePerfEvent(fakeLoadedProgram(), pfd, event, &tt.opts)
			if link != nil || !errors.Is(err, tt.want) {
				BpfLinkDestroy(link)
				t.Fatalf("attach = %v, %v, want %v", link, err, tt.want)
			}
			if _, err := unix.FcntlInt(uintptr(pfd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				t.Errorf("perf descriptor %d still open: %v", pfd, err)
			}
			checkProbeEventCommands(t, string(readTestFile(t, events)), "kprobes", name, "do_sys_openat2+0x0")
		})
	}
}

// pipeReadEnd returns the read end of a new pipe, whose write end is already
// closed. The caller owns the descriptor.
func pipeReadEnd(t *testing.T) int {
	t.Helper()

	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	unix.Close(fds[1])
	return fds[0]
}

// TestBpfProgramAttachKprobeSectionName checks that automatic attach refuses
// a kprobe section without a function name, and a kretprobe section with an
// offset, with EINVAL before it reaches the kernel.
func TestBpfProgramAttachKprobeSectionName(t *testing.T) {
	for _, section := range []string{"kprobe/", "kretprobe/", "kprobe/+16", "kretprobe/do_sys_openat2+16"} {
		prog := fakeLoadedProgram()
		prog.sectionName = section
		link, err := BpfProgramAttach(prog)
		if link != nil || !errors.Is(err, unix.EINVAL) {
			BpfLinkDestroy(link)
			t.Errorf("section %q: %v, %v, want EINVAL", section, link, err)
		}
	}
}

// kprobeModeCase is one attach of a kprobe at kprobeModeTarget for
// TestBpfProgramAttachKprobeModes. A raw case probes the target's address
// from /proc/kallsyms with an empty function name; a cookie case passes
// kprobeModeCookie. want is the error the attach must return on the running
// kernel, 0 when it must succeed.
type kprobeModeCase struct {
	name     string
	mode     ProbeAttachMode
	retprobe bool
	raw      bool
	cookie   bool
	want     syscall.Errno
}

// TestBpfProgramAttachKprobeModes attaches a kprobe to kprobeModeTarget in
// every mode, fires it by opening a file, and destroys it. On 6.18 the default
// and link modes use the kprobe PMU and a BPF perf link, which carries the
// cookie; on 5.10 the default mode uses the PMU with the ioctl, and the link
// mode and every cookie are EOPNOTSUPP. The perf mode always uses the ioctl
// and refuses a cookie, and the legacy mode creates a tracefs event and
// refuses a cookie and a raw address. A failed attach leaves no descriptor
// and no tracefs event behind.
func TestBpfProgramAttachKprobeModes(t *testing.T) {
	_, pmuErr := determineKprobePerfType()
	pmu := pmuErr == nil
	cookies := featBpfCookie.supported()
	links := pmu && perfLinkSupported()

	cases := []kprobeModeCase{
		{name: "default", mode: ProbeAttachModeDefault},
		{name: "default kretprobe", mode: ProbeAttachModeDefault, retprobe: true},
		{name: "default raw address", mode: ProbeAttachModeDefault, raw: true, want: errnoUnless(pmu, unix.EOPNOTSUPP)},
		{name: "default cookie", mode: ProbeAttachModeDefault, cookie: true, want: errnoUnless(cookies, unix.EOPNOTSUPP)},
		{name: "link", mode: ProbeAttachModeLink, want: errnoUnless(links, unix.EOPNOTSUPP)},
		{name: "link raw address", mode: ProbeAttachModeLink, raw: true, want: errnoUnless(links, unix.EOPNOTSUPP)},
		{name: "link cookie", mode: ProbeAttachModeLink, cookie: true, want: errnoUnless(links && cookies, unix.EOPNOTSUPP)},
		{name: "perf", mode: ProbeAttachModePerf, want: errnoUnless(pmu, unix.EOPNOTSUPP)},
		{name: "perf raw address", mode: ProbeAttachModePerf, raw: true, want: errnoUnless(pmu, unix.EOPNOTSUPP)},
		{name: "perf cookie", mode: ProbeAttachModePerf, cookie: true, want: unix.EOPNOTSUPP},
		{name: "legacy", mode: ProbeAttachModeLegacy},
		{name: "legacy kretprobe", mode: ProbeAttachModeLegacy, retprobe: true},
		{name: "legacy cookie", mode: ProbeAttachModeLegacy, cookie: true, want: unix.EOPNOTSUPP},
		{name: "legacy raw address", mode: ProbeAttachModeLegacy, raw: true, want: unix.EOPNOTSUPP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runKprobeModeCase(t, c)
		})
	}
}

// runKprobeModeCase attaches, fires and destroys one mode case. A cookie case
// attaches the cookie program where the kernel has BPF cookies; elsewhere the
// verifier rejects bpf_get_attach_cookie, so it attaches the counting program
// and only checks the attach error.
func runKprobeModeCase(t *testing.T, c kprobeModeCase) {
	readsCookie := c.cookie && featBpfCookie.supported()
	obj, prog, mapName := loadProbeModeProgram(t, readsCookie, "../testdata/progs/kprobe.bpf.o", "handle_open")
	defer BpfObjectClose(obj)

	funcName := kprobeModeTarget
	opts := &BpfKprobeOpts{AttachMode: c.mode, Retprobe: c.retprobe}
	if c.raw {
		funcName, opts.Offset = "", kallsymsAddress(t, kprobeModeTarget)
	}
	if c.cookie {
		opts.BpfCookie = kprobeModeCookie
	}
	events, fds := probeEvents(t, kprobeEventsFile), openDescriptors(t)

	seq := attachSeq.Load()
	link, err := BpfProgramAttachKprobeOpts(prog, funcName, opts)
	if c.want != 0 {
		if link != nil || !errors.Is(err, c.want) {
			BpfLinkDestroy(link)
			t.Fatalf("attach = %v, %v, want %v", link, err, c.want)
		}
		checkNothingLeft(t, kprobeEventsFile, events, fds)
		return
	}
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	_, pmuErr := determineKprobePerfType()
	checkProbeModeLink(t, link, c.mode, pmuErr != nil)
	checkLegacyEventName(t, link, fmt.Sprintf("libbpf_%d_%d_%s_0x0", os.Getpid(), seq, kprobeModeTarget))
	checkKprobeModeEvent(t, link, c.retprobe, events)

	triggerOpen(t)
	checkProbeModeValue(t, obj, mapName, readsCookie, kprobeModeCookie)

	BpfLinkDestroy(link)
	checkNothingLeft(t, kprobeEventsFile, events, fds)
}

// checkKprobeModeEvent requires a tracefs link to have its event listed in
// kprobe_events, as the kernel prints it, and a PMU link to have left the
// file as it was. The attach writes a kretprobe as "r:", but the kernel
// prints it with its maxactive after the r, which register_kretprobe fills
// in when the event was added without one: "r64:" for max(10, 2 * possible
// CPUs) on 32 CPUs. So a kretprobe line may carry any count there, and a
// kprobe line none.
func checkKprobeModeEvent(t *testing.T, link *BpfLink, retprobe bool, events string) {
	t.Helper()

	got := probeEvents(t, kprobeEventsFile)
	if link.legacy == nil {
		if got != events {
			t.Errorf("a PMU attach changed kprobe_events:\n%s", got)
		}
		return
	}
	prefix := "p"
	if retprobe {
		prefix = "r"
	}
	rest := fmt.Sprintf(":%s/%s %s\n", link.legacy.group(), link.legacy.name, kprobeModeTarget)
	if !containsProbeLine(got, prefix, rest, retprobe) {
		t.Errorf("kprobe_events has no %q:\n%s", prefix+rest, got)
	}
}

// containsProbeLine reports whether text has a line, ending in a newline,
// that is prefix and rest with nothing between them or, when counted, with a
// decimal count between them, as the kernel prints a kretprobe's maxactive.
func containsProbeLine(text, prefix, rest string, counted bool) bool {
	return slices.ContainsFunc(strings.SplitAfter(text, "\n"), func(line string) bool {
		count, ok := strings.CutPrefix(line, prefix)
		if !ok {
			return false
		}
		count, ok = strings.CutSuffix(count, rest)
		if !ok || count == "" {
			return ok
		}
		return counted && strings.Trim(count, "0123456789") == ""
	})
}

// kallsymsAddress returns the address /proc/kallsyms lists for the kernel
// symbol name. It skips the test when the symbol is missing or the file hides
// the addresses, as it does for a caller without CAP_SYSLOG.
func kallsymsAddress(t *testing.T, name string) uint64 {
	t.Helper()

	f, err := os.Open(kallsymsPath)
	if err != nil {
		t.Fatalf("open %s: %v", kallsymsPath, err)
	}
	defer f.Close()

	var addr uint64
	err = kallsymsParse(f, func(symAddr uint64, _ byte, symName string) error {
		if symName == name && addr == 0 {
			addr = symAddr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("parse %s: %v", kallsymsPath, err)
	}
	if addr == 0 {
		t.Skipf("%s has no address for %s", kallsymsPath, name)
	}
	return addr
}
