// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// Kernel versions, as KERNEL_VERSION values, that introduced the uprobe multi
// link and its session attach type.
const (
	uprobeMultiKernel   = 6<<16 | 6<<8
	uprobeSessionKernel = 6<<16 | 13<<8
)

// uprobeMultiCookie is the cookie the cookie case expects the program to read.
const uprobeMultiCookie = 0x5eed_c0de_0bad_f00d

// usdtCTargetPath is the USDT parser target, a dynamically linked C program
// with a static and a dynamic symbol table.
const usdtCTargetPath = "../testdata/progs/usdt_target"

func TestCheckUprobeMultiInputs(t *testing.T) {
	const path = "/bin/true"
	tests := []struct {
		name    string
		path    string
		pattern string
		opts    BpfUprobeMultiOpts
		want    error
	}{
		{"offsets", path, "", BpfUprobeMultiOpts{Offsets: []uint64{0x10, 0x20}}, nil},
		{"syms with optional arrays", path, "", BpfUprobeMultiOpts{
			Syms:          []string{"a", "b"},
			RefCtrOffsets: []uint64{1, 2},
			Cookies:       []uint64{3, 4},
		}, nil},
		{"retprobe", path, "", BpfUprobeMultiOpts{Offsets: []uint64{0x10}, Retprobe: true}, nil},
		{"session", path, "", BpfUprobeMultiOpts{Offsets: []uint64{0x10}, Session: true}, nil},
		{"pattern alone", path, "main*", BpfUprobeMultiOpts{}, nil},
		{"empty path", "", "", BpfUprobeMultiOpts{Offsets: []uint64{0x10}}, unix.EINVAL},
		{"empty path with pattern", "", "main*", BpfUprobeMultiOpts{}, unix.EINVAL},
		{"no locations", path, "", BpfUprobeMultiOpts{}, unix.EINVAL},
		{"only cookies", path, "", BpfUprobeMultiOpts{Cookies: []uint64{1}}, unix.EINVAL},
		{"only ref_ctr_offsets", path, "", BpfUprobeMultiOpts{RefCtrOffsets: []uint64{1}}, unix.EINVAL},
		{"syms and offsets", path, "", BpfUprobeMultiOpts{Syms: []string{"a"}, Offsets: []uint64{0x10}}, unix.EINVAL},
		{"pattern and syms", path, "main*", BpfUprobeMultiOpts{Syms: []string{"a"}}, unix.EINVAL},
		{"pattern and offsets", path, "main*", BpfUprobeMultiOpts{Offsets: []uint64{0x10}}, unix.EINVAL},
		{"pattern and ref_ctr_offsets", path, "main*", BpfUprobeMultiOpts{RefCtrOffsets: []uint64{1}}, unix.EINVAL},
		{"pattern and cookies", path, "main*", BpfUprobeMultiOpts{Cookies: []uint64{1}}, unix.EINVAL},
		{"short ref_ctr_offsets", path, "", BpfUprobeMultiOpts{Offsets: []uint64{0x10, 0x20}, RefCtrOffsets: []uint64{1}}, unix.EINVAL},
		{"long cookies", path, "", BpfUprobeMultiOpts{Syms: []string{"a"}, Cookies: []uint64{1, 2}}, unix.EINVAL},
		{"retprobe and session", path, "", BpfUprobeMultiOpts{Offsets: []uint64{0x10}, Retprobe: true, Session: true}, unix.EINVAL},
		{"pattern with retprobe and session", path, "main*", BpfUprobeMultiOpts{Retprobe: true, Session: true}, unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkUprobeMultiInputs(tt.path, tt.pattern, &tt.opts)
			if tt.want == nil && err != nil {
				t.Fatalf("checkUprobeMultiInputs = %v, want nil", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("checkUprobeMultiInputs = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestBpfProgramAttachUprobeMultiErrors covers the errors returned before the
// kernel is called. The program descriptor is a number no process has open,
// so a case that wrongly reached BPF_LINK_CREATE would fail with EBADF or
// EPERM instead of the expected errno.
func TestBpfProgramAttachUprobeMultiErrors(t *testing.T) {
	loaded := &BpfProgram{name: "fake", fd: 1 << 30}
	missing := filepath.Join(t.TempDir(), "missing")
	notELF := writeTestFile(t, "not-elf", "#!/bin/sh\n")
	tests := []struct {
		name    string
		prog    *BpfProgram
		path    string
		pattern string
		opts    *BpfUprobeMultiOpts
		want    syscall.Errno
	}{
		{"nil program", nil, funcTestObject, "", &BpfUprobeMultiOpts{Offsets: []uint64{0x10}}, unix.EINVAL},
		{"unloaded program", &BpfProgram{name: "fake", fd: -1}, funcTestObject, "", &BpfUprobeMultiOpts{Offsets: []uint64{0x10}}, unix.EINVAL},
		{"nil options", loaded, funcTestObject, "", nil, unix.EINVAL},
		{"pattern without a match", loaded, funcTestObject, "no_such_*", nil, unix.ENOENT},
		{"pattern with retprobe without a match", loaded, funcTestObject, "no_such_*", &BpfUprobeMultiOpts{Retprobe: true}, unix.ENOENT},
		{"pattern on a missing binary", loaded, missing, "handle_*", nil, unix.ENOENT},
		{"pattern on a binary not in the search path", loaded, "gobpfgo-no-such-binary", "handle_*", nil, unix.ENOENT},
		{"pattern on a file that is not ELF", loaded, notELF, "handle_*", nil, unix.EINVAL},
		{"invalid options before pattern", loaded, funcTestObject, "handle_*", &BpfUprobeMultiOpts{Cookies: []uint64{1}}, unix.EINVAL},
		{"missing symbol", loaded, funcTestObject, "", &BpfUprobeMultiOpts{Syms: []string{funcTestName, "no_such_function"}}, unix.ENOENT},
		{"missing binary", loaded, missing, "", &BpfUprobeMultiOpts{Syms: []string{funcTestName}}, unix.ENOENT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link, err := BpfProgramAttachUprobeMulti(tt.prog, 0, tt.path, tt.pattern, tt.opts)
			if link != nil {
				BpfLinkDestroy(link)
				t.Fatal("attach returned a link")
			}
			var libErr *Error
			if !errors.As(err, &libErr) || libErr.Op != "bpf_program__attach_uprobe_multi" {
				t.Fatalf("attach error = %v, want a bpf_program__attach_uprobe_multi error", err)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("attach error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestUprobeMultiOffsets(t *testing.T) {
	want, err := findFuncOffset(funcTestObject, funcTestName)
	if err != nil {
		t.Fatalf("findFuncOffset: %v", err)
	}

	path, got, err := uprobeMultiOffsets(funcTestObject, "", &BpfUprobeMultiOpts{Syms: []string{funcTestName, funcTestName}})
	if err != nil {
		t.Fatalf("uprobeMultiOffsets(syms): %v", err)
	}
	if path != funcTestObject || len(got) != 2 || got[0] != want || got[1] != want {
		t.Fatalf("symbol offsets = %s %#x, want %s [%#x %#x]", path, got, funcTestObject, want, want)
	}

	explicit := []uint64{0x10, 0x20, 0x30}
	path, got, err = uprobeMultiOffsets(funcTestObject, "", &BpfUprobeMultiOpts{Offsets: explicit})
	if err != nil {
		t.Fatalf("uprobeMultiOffsets(offsets): %v", err)
	}
	if path != funcTestObject || !slices.Equal(got, explicit) {
		t.Fatalf("explicit offsets = %s %#x, want %s %#x", path, got, funcTestObject, explicit)
	}
}

// TestElfResolvePatternOffsets resolves patterns in the checked-in binaries
// and compares the offsets, in symbol table order, with the single-name
// lookup. usdt_target has both tables: its static table stores the versioned
// names of the undefined C library functions, its dynamic table the bare
// ones, so a bare name is found only through the fallback.
func TestElfResolvePatternOffsets(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	notELF := writeTestFile(t, "not-elf", "#!/bin/sh\n")
	tests := []struct {
		name    string
		path    string
		pattern string
		want    []uint64
		err     error
	}{
		{"single character", usdtTargetPath, "loop_site_?", funcOffsets(t, usdtTargetPath, "loop_site_a", "loop_site_b"), nil},
		{"star in table order", usdtTargetPath, "loop_*", funcOffsets(t, usdtTargetPath, "loop_site_a", "loop_site_b", "loop_fill.constprop.0"), nil},
		{"every function", usdtTargetPath, "*", funcOffsets(t, usdtTargetPath, "run", "loop_site_a", "loop_site_b", "loop_fill.constprop.0"), nil},
		{"literal", usdtTargetPath, "run", funcOffsets(t, usdtTargetPath, "run"), nil},
		{"static table only, undefined skipped", usdtCTargetPath, "__*",
			funcOffsets(t, usdtCTargetPath, "__do_global_dtors_aux"), nil},
		{"dynamic table undefined", usdtCTargetPath, "__cxa_finalize", nil, unix.ENOENT},
		{"relocatable object", funcTestObject, "handle_*", funcOffsets(t, funcTestObject, funcTestName), nil},
		{"no match", usdtTargetPath, "no_such_*", nil, unix.ENOENT},
		{"empty pattern", usdtTargetPath, "", nil, unix.ENOENT},
		{"missing file", missing, "*", nil, unix.ENOENT},
		{"not ELF", notELF, "*", nil, unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := elfResolvePatternOffsets(tt.path, tt.pattern)
			checkAddrs(t, got, err, tt.want, tt.err)
		})
	}
}

// TestUprobeMultiLinkPattern checks the attribute a pattern attach sends: the
// resolved offsets in symbol table order, the path the link names, which is
// the searched path for a name without a slash, and the attach type and
// flags of the options.
func TestUprobeMultiLinkPattern(t *testing.T) {
	loopOffsets := funcOffsets(t, usdtTargetPath, "loop_site_a", "loop_site_b", "loop_fill.constprop.0")
	searched := checkedInUsdtTarget(t, usdtTargetPath)
	tests := []struct {
		name       string
		path       string
		opts       *BpfUprobeMultiOpts
		wantPath   string
		attachType uint32
		flags      uint32
	}{
		{"uprobe", usdtTargetPath, nil, usdtTargetPath, sys.BPF_TRACE_UPROBE_MULTI, 0},
		{"uretprobe", usdtTargetPath, &BpfUprobeMultiOpts{Retprobe: true}, usdtTargetPath, sys.BPF_TRACE_UPROBE_MULTI, BPF_F_UPROBE_MULTI_RETURN},
		{"session", usdtTargetPath, &BpfUprobeMultiOpts{Session: true}, usdtTargetPath, sys.BPF_TRACE_UPROBE_SESSION, 0},
		{"searched path", filepath.Base(usdtTargetPath), nil, searched, sys.BPF_TRACE_UPROBE_MULTI, 0},
	}
	t.Setenv("PATH", filepath.Dir(searched))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, um, err := uprobeMultiLink(&BpfProgram{fd: 5}, -1, tt.path, "loop_*", tt.opts)
			if err != nil {
				t.Fatalf("uprobeMultiLink: %v", err)
			}
			if want := (sys.LinkCreateAttr{ProgFD: 5, AttachType: tt.attachType}); *attr != want {
				t.Errorf("attribute %+v, want %+v", *attr, want)
			}
			if um.Path != tt.wantPath || !slices.Equal(um.Offsets, loopOffsets) || um.Flags != tt.flags || um.PID != 0 {
				t.Errorf("link %s %#x flags %#x pid %d, want %s %#x flags %#x pid 0", um.Path, um.Offsets, um.Flags, um.PID, tt.wantPath, loopOffsets, tt.flags)
			}
			if um.RefCtrOffsets != nil || um.Cookies != nil {
				t.Errorf("reference counters %v and cookies %v, want none", um.RefCtrOffsets, um.Cookies)
			}
		})
	}
}

// TestBpfProgramAttachUprobeMultiPattern attaches a uprobe multi link to
// loop_site_? in a running usdt_loop_target, filtered to its PID, and
// requires one run for each of the two functions per round, and none after
// the link is destroyed.
func TestBpfProgramAttachUprobeMultiPattern(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the USDT target is an x86-64 binary")
	}
	if version := getKernelVersion(); version < uprobeMultiKernel {
		t.Skipf("kernel version %#x predates the link type (%#x)", version, uprobeMultiKernel)
	}
	obj, prog := loadKprobeRetypedObject(t, "../testdata/progs/uprobe.bpf.o", "handle_uprobe", BPF_TRACE_UPROBE_MULTI)
	defer BpfObjectClose(obj)

	path := checkedInUsdtTarget(t, usdtTargetPath)
	target := startUsdtTarget(t, path)
	link, err := BpfProgramAttachUprobeMulti(prog, target.pid, path, "loop_site_?", nil)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("uprobe multi links are not supported by this kernel: %v", err)
		}
		t.Fatalf("attach: %v", err)
	}
	checkLinkFdinfo(t, link, prog, "uprobe_multi", nil)

	target.trigger(t)
	if got := mapValue(t, obj, "counts"); got != 2 {
		t.Fatalf("one round counted %d runs, want 2: loop_site_a and loop_site_b", got)
	}
	destroyLink(t, link)

	target.trigger(t)
	if got := mapValue(t, obj, "counts"); got != 2 {
		t.Fatalf("a round after destroy left %d runs, want 2", got)
	}
	target.stop(t)
}

// funcOffsets returns the file offset of each named function in the ELF file
// at path, found by the single-name lookup.
func funcOffsets(t *testing.T, path string, names ...string) []uint64 {
	t.Helper()

	offsets := make([]uint64, len(names))
	for i, name := range names {
		offset, err := findFuncOffset(path, name)
		if err != nil {
			t.Fatalf("offset of %s in %s: %v", name, path, err)
		}
		offsets[i] = offset
	}
	return offsets
}

// uprobeMultiCase is one root attach case. The program is retyped as a
// uprobe multi program before the load, attached at uprobeTarget's offset in
// the test binary, and must leave want in the map, or any nonzero count when
// want is zero.
type uprobeMultiCase struct {
	name       string
	object     string
	program    string
	attachType BpfAttachType
	minKernel  uint32
	opts       BpfUprobeMultiOpts
	mapName    string
	want       uint64
}

func TestBpfProgramAttachUprobeMulti(t *testing.T) {
	cases := []uprobeMultiCase{
		{name: "uprobe", object: "uprobe.bpf.o", program: "handle_uprobe", attachType: BPF_TRACE_UPROBE_MULTI, minKernel: uprobeMultiKernel, mapName: "counts"},
		{name: "uretprobe", object: "uprobe.bpf.o", program: "handle_uretprobe", attachType: BPF_TRACE_UPROBE_MULTI, minKernel: uprobeMultiKernel,
			opts: BpfUprobeMultiOpts{Retprobe: true}, mapName: "counts"},
		{name: "session", object: "uprobe.bpf.o", program: "handle_uprobe", attachType: BPF_TRACE_UPROBE_SESSION, minKernel: uprobeSessionKernel,
			opts: BpfUprobeMultiOpts{Session: true}, mapName: "counts"},
		{name: "cookie", object: "cookie.bpf.o", program: "handle_cookie", attachType: BPF_TRACE_UPROBE_MULTI, minKernel: uprobeMultiKernel,
			opts: BpfUprobeMultiOpts{Cookies: []uint64{uprobeMultiCookie}}, mapName: "cookies", want: uprobeMultiCookie},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runUprobeMultiCase(t, c)
		})
	}
}

// runUprobeMultiCase skips before the load on kernels older than the case
// needs: they reject the attach type with EINVAL, and before 5.15 the
// verifier also rejects the cookie helper. A newer kernel built without
// uprobes rejects the link with EOPNOTSUPP, which also skips; any other error,
// EINVAL included, means the attribute is wrong and fails.
func runUprobeMultiCase(t *testing.T, c uprobeMultiCase) {
	if version := getKernelVersion(); version < c.minKernel {
		t.Skipf("kernel version %#x predates the link type (%#x)", version, c.minKernel)
	}
	obj, prog := loadKprobeRetypedObject(t, "../testdata/progs/"+c.object, c.program, c.attachType)
	defer BpfObjectClose(obj)

	opts := c.opts
	opts.Offsets = []uint64{uprobeTargetOffset(t)}
	link, err := BpfProgramAttachUprobeMulti(prog, 0, "/proc/self/exe", "", &opts)
	if err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("uprobe multi links are not supported by this kernel: %v", err)
		}
		t.Fatalf("attach: %v", err)
	}
	if fd := BpfLinkFD(link); fd < 0 {
		t.Fatalf("link fd = %d", fd)
	}

	uprobeTarget()

	got := mapValue(t, obj, c.mapName)
	if c.want != 0 && got != c.want {
		t.Fatalf("%s value = %#x, want %#x", c.mapName, got, c.want)
	}
	if c.want == 0 && got == 0 {
		t.Fatalf("%s value = 0, want a nonzero count", c.mapName)
	}

	if err := BpfLinkDetach(link); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if fd := BpfLinkFD(link); fd != -1 {
		t.Fatalf("link fd after detach = %d, want -1", fd)
	}
	BpfLinkDestroy(link)
}

// loadKprobeRetypedObject opens path, retypes the program name as a kprobe
// program with the expected attach type attachType, and loads the object. The
// kernel creates uprobe multi links only for kprobe programs with the multi
// attach types, and attaches a single uprobe only to a kprobe program, while
// the cookie fixture is a tracepoint program. The package has no program type
// setters yet, so the test sets the fields the way bpf_program__set_type and
// bpf_program__set_expected_attach_type would before the load.
func loadKprobeRetypedObject(t *testing.T, path, name string, attachType BpfAttachType) (*BpfObject, *BpfProgram) {
	t.Helper()

	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	prog := BpfObjectFindProgramByName(obj, name)
	if prog == nil {
		BpfObjectClose(obj)
		t.Fatalf("program %q not found in %s", name, path)
	}
	prog.progType = BPF_PROG_TYPE_KPROBE
	prog.expectedAttachType = attachType

	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("load %s: %v", path, err)
	}
	return obj, prog
}
