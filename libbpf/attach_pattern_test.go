// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// kprobeSessionPattern matches do_sys_openat2, which every open reaches, and
// do_sys_open where the kernel has it.
const kprobeSessionPattern = "do_sys_open*"

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		str, pat string
		want     bool
	}{
		{"do_sys_openat2", "do_sys_openat2", true},
		{"do_sys_openat2", "do_sys_open", false},
		{"do_sys_open", "do_sys_openat2", false},
		{"", "", true},
		{"a", "", false},
		{"", "*", true},
		{"", "**", true},
		{"anything", "*", true},
		{"do_sys_open", "do_sys_open*", true},
		{"do_sys_openat2", "do_sys_open*", true},
		{"do_sys_openat2", "*openat2", true},
		{"do_sys_openat2", "*open*", true},
		{"do_sys_openat2", "do_*_open*2", true},
		{"do_sys_openat2", "do_**_open***", true},
		{"do_sys_openat2", "do_*_close*", false},
		{"abcbc", "a*bc", true},
		{"abcbd", "a*bc", false},
		{"a", "?", true},
		{"", "?", false},
		{"ab", "?", false},
		{"abc", "a?c", true},
		{"ac", "a?c", false},
		{"abc", "*?", true},
		{"abc", "?*?*?", true},
		{"ab", "?*?*?", false},
		{"a[b]c", "a[b]c", true},
		{"abc", "a[b]c", false},
		{`a\bc`, `a\*c`, true},
		{"abc", `a\*c`, false},
	}
	for _, tt := range tests {
		if got := globMatch(tt.str, tt.pat); got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.str, tt.pat, got, tt.want)
		}
	}
}

// TestParseAvailableKprobes parses synthetic available_filter_functions_addrs
// tables. The inputs and outcomes are the ones the C library's fscanf loop
// gives for the same bytes.
func TestParseAvailableKprobes(t *testing.T) {
	const (
		open    = 0xffffffff81000000
		openat2 = 0xffffffff81000100
		vfsOpen = 0xffffffff81000200
		modOpen = 0xffffffffc0001000
	)
	table := "ffffffff81000000 do_sys_open\n" +
		"ffffffff81000100 do_sys_openat2\n" +
		"ffffffff81000200 vfs_open\n" +
		"ffffffffc0001000 do_sys_open_mod\t[testmod]\n"

	tests := []struct {
		name    string
		input   string
		pattern string
		want    []uint64
		err     error
	}{
		{"wildcard in file order", table, "do_sys_open*", []uint64{open, openat2, modOpen}, nil},
		{"single character", table, "do_sys_ope?", []uint64{open}, nil},
		{"literal", table, "vfs_open", []uint64{vfsOpen}, nil},
		{"every function", table, "*", []uint64{open, openat2, vfsOpen, modOpen}, nil},
		{"no match", table, "no_such_*", nil, unix.ENOENT},
		{"empty table", "", "*", nil, unix.ENOENT},
		{"blank lines", "\n\nffffffff81000000 a\n\n", "*", []uint64{open}, nil},
		{"no final newline", "ffffffff81000000 a", "*", []uint64{open}, nil},
		{"0x prefix", "0xffffffff81000000 a\n", "*", []uint64{open}, nil},
		{"trailing blanks", "ffffffff81000000 a   \nffffffff81000100 b\n", "*", []uint64{open, openat2}, nil},
		{"carriage returns", "ffffffff81000000 a\r\nffffffff81000100 b\r\n", "*", []uint64{open, openat2}, nil},
		{"bad address", "ffffffff81000000 a\nzz b\n", "*", nil, unix.EINVAL},
		{"address without name", "ffffffff81000000 a\nffffffff81000100\n", "*", nil, unix.EINVAL},
		{"malformed after a match", "ffffffff81000000 do_sys_open\nzz b\n", "do_sys_open", nil, unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAvailableKprobes(strings.NewReader(tt.input), tt.pattern)
			checkAddrs(t, got, err, tt.want, tt.err)
		})
	}
}

// TestReadAvailableKallsyms resolves through synthetic
// available_filter_functions and kallsyms files: names come from the first,
// addresses and their order from the second.
func TestReadAvailableKallsyms(t *testing.T) {
	const funcs = "do_sys_open\ndo_sys_openat2\nvfs_open\ndo_sys_open_mod [testmod]\n"
	const kallsyms = "ffffffff81000000 T do_sys_openat2\n" +
		"ffffffff81000100 T do_sys_open\n" +
		"ffffffff81000200 t do_sys_open_notrace\n" +
		"ffffffff81000300 t do_sys_open.llvm.1234567890\n" +
		"ffffffff81000400 T vfs_open\n" +
		"ffffffffc0001000 t do_sys_open_mod\t[testmod]\n"

	tests := []struct {
		name     string
		funcs    string
		kallsyms string
		pattern  string
		want     []uint64
		err      error
	}{
		{"kallsyms order and llvm suffix", funcs, kallsyms, "do_sys_open*",
			[]uint64{0xffffffff81000000, 0xffffffff81000100, 0xffffffff81000300, 0xffffffffc0001000}, nil},
		{"literal", funcs, kallsyms, "vfs_open", []uint64{0xffffffff81000400}, nil},
		{"not traceable", funcs, kallsyms, "do_sys_open_notrace", nil, unix.ENOENT},
		{"no traceable match", funcs, kallsyms, "no_such_*", nil, unix.ENOENT},
		{"no kallsyms address", "only_in_tracefs\n", kallsyms, "only_*", nil, unix.ENOENT},
		{"malformed kallsyms keeps earlier matches", funcs,
			"ffffffff81000000 T do_sys_openat2\nzz T x\nffffffff81000100 T do_sys_open\n",
			"do_sys_open*", []uint64{0xffffffff81000000}, nil},
		{"malformed first kallsyms entry", funcs, "zz T x\nffffffff81000000 T do_sys_openat2\n", "do_sys_open*", nil, unix.ENOENT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			funcsPath, kallsymsFile := writeTestFile(t, "funcs", tt.funcs), writeTestFile(t, "kallsyms", tt.kallsyms)
			got, err := readAvailableKallsyms(funcsPath, kallsymsFile, tt.pattern)
			checkAddrs(t, got, err, tt.want, tt.err)
		})
	}
}

// TestReadAvailableTracefsMissing checks that a tracefs file that cannot be
// opened fails with its errno, and that a missing kallsyms file is the same
// ENOENT as no match.
func TestReadAvailableTracefsMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	funcs := writeTestFile(t, "funcs", "do_sys_open\n")

	if _, err := readAvailableKprobes(missing, "*"); !errors.Is(err, unix.ENOENT) {
		t.Errorf("missing addrs file = %v, want ENOENT", err)
	}
	if _, err := readAvailableKallsyms(missing, kallsymsPath, "*"); !errors.Is(err, unix.ENOENT) {
		t.Errorf("missing functions file = %v, want ENOENT", err)
	}
	if _, err := readAvailableKallsyms(funcs, missing, "*"); !errors.Is(err, unix.ENOENT) {
		t.Errorf("missing kallsyms file = %v, want ENOENT", err)
	}
}

// TestKprobeMultiLinkPattern checks how a Pattern reaches the link: without a
// wildcard as the one symbol and without a resolver call, with one as the
// resolved addresses, and with the resolver error ahead of the Retprobe and
// Session check.
func TestKprobeMultiLinkPattern(t *testing.T) {
	resolved := []uint64{0xffffffff81000000, 0xffffffff81000100}
	tests := []struct {
		name       string
		opts       BpfKprobeMultiOpts
		resolve    func(t *testing.T) kprobePatternResolver
		attachType uint32
		flags      uint32
		syms       []string
		addrs      []uint64
		err        error
	}{
		{"exact name", BpfKprobeMultiOpts{Pattern: "do_sys_openat2"}, unexpectedKprobeResolve,
			sys.BPF_TRACE_KPROBE_MULTI, 0, []string{"do_sys_openat2"}, nil, nil},
		{"exact name session", BpfKprobeMultiOpts{Pattern: "do_sys_openat2", Session: true}, unexpectedKprobeResolve,
			sys.BPF_TRACE_KPROBE_SESSION, 0, []string{"do_sys_openat2"}, nil, nil},
		{"offset suffix stays literal", BpfKprobeMultiOpts{Pattern: "do_sys_openat2+16"}, unexpectedKprobeResolve,
			sys.BPF_TRACE_KPROBE_MULTI, 0, []string{"do_sys_openat2+16"}, nil, nil},
		{"star", BpfKprobeMultiOpts{Pattern: "do_sys_open*"}, fixedKprobeResolve("do_sys_open*", resolved, nil),
			sys.BPF_TRACE_KPROBE_MULTI, 0, nil, resolved, nil},
		{"question mark retprobe", BpfKprobeMultiOpts{Pattern: "do_sys_ope?", Retprobe: true}, fixedKprobeResolve("do_sys_ope?", resolved, nil),
			sys.BPF_TRACE_KPROBE_MULTI, BPF_F_KPROBE_MULTI_RETURN, nil, resolved, nil},
		{"wildcard session", BpfKprobeMultiOpts{Pattern: "do_sys_open*", Session: true}, fixedKprobeResolve("do_sys_open*", resolved, nil),
			sys.BPF_TRACE_KPROBE_SESSION, 0, nil, resolved, nil},
		{"no match", BpfKprobeMultiOpts{Pattern: "no_such_*"}, fixedKprobeResolve("no_such_*", nil, unix.ENOENT),
			0, 0, nil, nil, unix.ENOENT},
		{"malformed table", BpfKprobeMultiOpts{Pattern: "do_*"}, fixedKprobeResolve("do_*", nil, unix.EINVAL),
			0, 0, nil, nil, unix.EINVAL},
		{"pattern and symbols", BpfKprobeMultiOpts{Pattern: "do_*", Symbols: []string{"vfs_open"}}, unexpectedKprobeResolve,
			0, 0, nil, nil, unix.EINVAL},
		{"pattern and addresses", BpfKprobeMultiOpts{Pattern: "do_*", Addrs: []uint64{1}}, unexpectedKprobeResolve,
			0, 0, nil, nil, unix.EINVAL},
		{"pattern and cookies", BpfKprobeMultiOpts{Pattern: "do_*", Cookies: []uint64{1}}, unexpectedKprobeResolve,
			0, 0, nil, nil, unix.EINVAL},
		{"exact name retprobe and session", BpfKprobeMultiOpts{Pattern: "do_sys_openat2", Retprobe: true, Session: true}, unexpectedKprobeResolve,
			0, 0, nil, nil, unix.EINVAL},
		{"resolved retprobe and session", BpfKprobeMultiOpts{Pattern: "do_*", Retprobe: true, Session: true}, fixedKprobeResolve("do_*", resolved, nil),
			0, 0, nil, nil, unix.EINVAL},
		{"resolution before retprobe and session", BpfKprobeMultiOpts{Pattern: "no_*", Retprobe: true, Session: true}, fixedKprobeResolve("no_*", nil, unix.ENOENT),
			0, 0, nil, nil, unix.ENOENT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, km, err := kprobeMultiLink(&BpfProgram{fd: 5}, &tt.opts, tt.resolve(t))
			if !errors.Is(err, tt.err) || err != nil && tt.err == nil {
				t.Fatalf("kprobeMultiLink error = %v, want %v", err, tt.err)
			}
			if err != nil {
				return
			}
			want := sys.LinkCreateAttr{ProgFD: 5, AttachType: tt.attachType}
			if *attr != want || km.Flags != tt.flags {
				t.Errorf("attribute %+v and flags %#x, want %+v and %#x", *attr, km.Flags, want, tt.flags)
			}
			if !slices.Equal(km.Syms, tt.syms) || !slices.Equal(km.Addrs, tt.addrs) || km.Cookies != nil {
				t.Errorf("arrays %q/%#x/%v, want %q/%#x and no cookies", km.Syms, km.Addrs, km.Cookies, tt.syms, tt.addrs)
			}
		})
	}
}

// TestKprobeMultiSectionOpts checks that the multi and session sections pass
// their whole target as the pattern.
func TestKprobeMultiSectionOpts(t *testing.T) {
	tests := []struct {
		section string
		want    BpfKprobeMultiOpts
	}{
		{"kprobe.multi/do_sys_openat2", BpfKprobeMultiOpts{Pattern: "do_sys_openat2"}},
		{"kprobe.multi/do_sys_open*", BpfKprobeMultiOpts{Pattern: "do_sys_open*"}},
		{"kretprobe.multi/vfs_*", BpfKprobeMultiOpts{Pattern: "vfs_*", Retprobe: true}},
		{"kprobe.session/do_sys_ope?", BpfKprobeMultiOpts{Pattern: "do_sys_ope?", Session: true}},
		{"kprobe.multi/do_sys_openat2+16", BpfKprobeMultiOpts{Pattern: "do_sys_openat2+16"}},
		{"kprobe.multi/", BpfKprobeMultiOpts{}},
	}
	for _, tt := range tests {
		def, ok := secDefFor(tt.section)
		if !ok {
			t.Fatalf("no section definition for %s", tt.section)
		}
		got := kprobeMultiSectionOpts(def.prefix, strings.TrimPrefix(tt.section, def.prefix))
		if !kprobeMultiOptsEqual(got, &tt.want) {
			t.Errorf("%s: options %+v, want %+v", tt.section, *got, tt.want)
		}
	}
}

// TestBpfProgramAttachEmptyKprobeMultiSection checks that a multi section
// without a function fails with EINVAL before tracefs or the kernel is used.
func TestBpfProgramAttachEmptyKprobeMultiSection(t *testing.T) {
	for _, section := range []string{"kprobe.multi/", "kretprobe.multi/", "kprobe.session/"} {
		prog := &BpfProgram{fd: fakeLoadedFD, sectionName: section}
		link, err := BpfProgramAttach(prog)
		checkAttachError(t, link, err, "bpf_program__attach_kprobe_multi", unix.EINVAL)
	}
}

// TestBpfProgramAttachKprobeSessionPattern attaches the kprobe.session
// program of kprobe_session.bpf.o to every do_sys_open* function, through the
// options and through a wildcard section name, opens a file from a locked
// thread and requires an entry and a return run for each function the open
// reached. Where the kernel shows kprobe_cnt in the link fdinfo, the link
// must cover every resolved function. Kernels without kprobe sessions skip.
func TestBpfProgramAttachKprobeSessionPattern(t *testing.T) {
	obj := loadKprobeSessionObject(t)
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "handle_session")

	addrs, err := resolveKprobePattern(kprobeSessionPattern)
	if err != nil {
		t.Fatalf("resolve %s: %v", kprobeSessionPattern, err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	setMapU32(t, obj, "target_tid", uint32(unix.Gettid()))

	attaches := []struct {
		name   string
		attach func() (*BpfLink, error)
	}{
		{"opts", func() (*BpfLink, error) {
			return BpfProgramAttachKprobeMulti(prog, &BpfKprobeMultiOpts{Pattern: kprobeSessionPattern, Session: true})
		}},
		{"section", func() (*BpfLink, error) {
			prog.sectionName = "kprobe.session/" + kprobeSessionPattern
			return BpfProgramAttach(prog)
		}},
	}
	for _, a := range attaches {
		link, err := a.attach()
		if err != nil {
			skipIfKernelLacksKprobeSession(t, err)
			t.Fatalf("%s attach: %v", a.name, err)
		}
		checkLinkFdinfo(t, link, prog, "kprobe_multi", nil)
		if cnt, ok := fdinfo(t, BpfLinkFD(link))["kprobe_cnt"]; ok && cnt != strconv.Itoa(len(addrs)) {
			t.Errorf("%s: kprobe_cnt = %s, want %d resolved functions", a.name, cnt, len(addrs))
		}

		start := mapValue(t, obj, "counts")
		triggerOpen(t)
		if got := mapValue(t, obj, "counts") - start; got < 2 || got%2 != 0 {
			t.Errorf("%s: one open counted %d runs, want an entry and a return run per function", a.name, got)
		}
		destroyLink(t, link)
	}
}

// unexpectedKprobeResolve returns a resolver that fails the test when called.
func unexpectedKprobeResolve(t *testing.T) kprobePatternResolver {
	return func(pattern string) ([]uint64, error) {
		t.Errorf("resolver called with %q", pattern)
		return nil, unix.ENOSYS
	}
}

// fixedKprobeResolve returns a resolver factory whose resolver requires the
// pattern want and returns addrs and err.
func fixedKprobeResolve(want string, addrs []uint64, err error) func(t *testing.T) kprobePatternResolver {
	return func(t *testing.T) kprobePatternResolver {
		return func(pattern string) ([]uint64, error) {
			if pattern != want {
				t.Errorf("resolver called with %q, want %q", pattern, want)
			}
			return addrs, err
		}
	}
}

// kprobeMultiOptsEqual reports whether two options select the same functions
// the same way.
func kprobeMultiOptsEqual(a, b *BpfKprobeMultiOpts) bool {
	return a.Pattern == b.Pattern && a.Retprobe == b.Retprobe && a.Session == b.Session &&
		slices.Equal(a.Symbols, b.Symbols) && slices.Equal(a.Addrs, b.Addrs) && slices.Equal(a.Cookies, b.Cookies)
}

// checkAddrs requires the resolved addresses want, or the error wantErr.
func checkAddrs(t *testing.T, got []uint64, err error, want []uint64, wantErr error) {
	t.Helper()

	if wantErr != nil {
		if !errors.Is(err, wantErr) || got != nil {
			t.Fatalf("addresses %#x, error %v, want %v", got, err, wantErr)
		}
		return
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("addresses %#x, error %v, want %#x", got, err, want)
	}
}

// writeTestFile writes content to the file name in the test's temporary
// directory and returns its path.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
