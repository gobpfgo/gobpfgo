// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// uprobeModeCookie is the cookie the uprobe mode cases expect the program to
// read.
const uprobeModeCookie = 0x0bad_cafe_f00d_0001

// TestUprobeAttachMode checks the mode table on every combination of the two
// kernel capabilities: the default mode follows the kernel, the legacy mode
// always uses tracefs and the ioctl, the perf mode needs the PMU and forces
// the ioctl, and the link mode needs the PMU and perf links. Only the link
// mode asks for perf link support.
func TestUprobeAttachMode(t *testing.T) {
	tests := []struct {
		mode           ProbeAttachMode
		noPMU          bool
		perfLink       bool
		wantLegacy     bool
		wantForceIoctl bool
		want           syscall.Errno
	}{
		{ProbeAttachModeDefault, false, true, false, false, 0},
		{ProbeAttachModeDefault, false, false, false, false, 0},
		{ProbeAttachModeDefault, true, true, true, false, 0},
		{ProbeAttachModeDefault, true, false, true, false, 0},
		{ProbeAttachModeLegacy, false, true, true, true, 0},
		{ProbeAttachModeLegacy, true, false, true, true, 0},
		{ProbeAttachModePerf, false, true, false, true, 0},
		{ProbeAttachModePerf, false, false, false, true, 0},
		{ProbeAttachModePerf, true, true, false, false, unix.EOPNOTSUPP},
		{ProbeAttachModeLink, false, true, false, false, 0},
		{ProbeAttachModeLink, false, false, false, false, unix.EOPNOTSUPP},
		{ProbeAttachModeLink, true, true, false, false, unix.EOPNOTSUPP},
		{ProbeAttachModeLink + 1, false, true, false, false, unix.EINVAL},
		{-1, true, false, false, false, unix.EINVAL},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("mode %d, no PMU %v, perf link %v", tt.mode, tt.noPMU, tt.perfLink)
		t.Run(name, func(t *testing.T) {
			asked := false
			perfLink := func() bool {
				asked = true
				return tt.perfLink
			}

			legacy, forceIoctl, err := uprobeAttachMode(tt.mode, tt.noPMU, perfLink)
			if tt.want != 0 && !errors.Is(err, tt.want) || tt.want == 0 && err != nil {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if legacy != tt.wantLegacy || forceIoctl != tt.wantForceIoctl {
				t.Errorf("legacy %v, force ioctl %v, want %v, %v", legacy, forceIoctl, tt.wantLegacy, tt.wantForceIoctl)
			}
			if wantAsked := tt.mode == ProbeAttachModeLink && !tt.noPMU; asked != wantAsked {
				t.Errorf("perf link support asked %v, want %v", asked, wantAsked)
			}
		})
	}
}

// searchTree is a temporary directory tree for the path resolution tests. Its
// files are created with the given modes under the directory names.
type searchTree struct {
	root string
}

func newSearchTree(t *testing.T) searchTree {
	t.Helper()
	return searchTree{root: t.TempDir()}
}

// dir returns the path of the tree directory name.
func (tree searchTree) dir(name string) string {
	return filepath.Join(tree.root, name)
}

// file creates the file dir/name with mode.
func (tree searchTree) file(t *testing.T, dir, name string, mode os.FileMode) {
	t.Helper()

	path := filepath.Join(tree.dir(dir), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// fakeSearchPaths replaces the fixed search directories with the tree's
// directories for the rest of the test.
func fakeSearchPaths(t *testing.T, binaries, libraries []string) {
	t.Helper()

	savedBinaries, savedLibraries := binarySearchPaths, librarySearchPaths
	binarySearchPaths, librarySearchPaths = binaries, libraries
	t.Cleanup(func() {
		binarySearchPaths, librarySearchPaths = savedBinaries, savedLibraries
	})
}

// TestResolveFullPath searches a temporary tree. PATH has empty entries and a
// directory whose copy of the program is not executable; PATH has a library
// and LD_LIBRARY_PATH a program that the other rule must not find; the fixed
// lists come after the environment and may have empty entries too.
func TestResolveFullPath(t *testing.T) {
	tree := newSearchTree(t)
	tree.file(t, "path1", "tool", 0o644)
	tree.file(t, "path1", "libfoo.so", 0o644)
	tree.file(t, "path2", "tool", 0o755)
	tree.file(t, "path2", "libfoo.so.1", 0o644)
	tree.file(t, "lib1", "libfoo.so.1", 0o644)
	tree.file(t, "lib1", "libonly", 0o755)
	tree.file(t, "sysbin", "systool", 0o755)
	tree.file(t, "sysbin", "tool", 0o755)
	tree.file(t, "syslib", "libsys.so", 0o644)
	tree.file(t, "arch", "libarch.so", 0o644)
	tree.file(t, "arch", "libsys.so", 0o644)

	t.Setenv("PATH", ":"+tree.dir("path1")+"::"+tree.dir("path2")+":")
	t.Setenv("LD_LIBRARY_PATH", tree.dir("lib1")+":"+tree.dir("missing"))
	fakeSearchPaths(t, []string{tree.dir("sysbin")}, []string{tree.dir("syslib"), "", tree.dir("arch")})

	tests := []struct {
		file string
		want string
	}{
		{"tool", tree.dir("path2") + "/tool"},
		{"systool", tree.dir("sysbin") + "/systool"},
		{"libfoo.so.1", tree.dir("lib1") + "/libfoo.so.1"},
		{"libsys.so", tree.dir("syslib") + "/libsys.so"},
		{"libarch.so", tree.dir("arch") + "/libarch.so"},
		{"libfoo.so", ""},
		{"libonly", ""},
		{"missing", ""},
		{"missing.so", ""},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := resolveFullPath(tt.file)
			if tt.want == "" {
				if !errors.Is(err, unix.ENOENT) {
					t.Fatalf("resolveFullPath = %q, %v, want ENOENT", got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolveFullPath = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

// TestResolveFullPathLibraryPath checks that LD_LIBRARY_PATH comes before the
// fixed library directories and that an unset variable is skipped.
func TestResolveFullPathLibraryPath(t *testing.T) {
	tree := newSearchTree(t)
	tree.file(t, "env", "libfoo.so", 0o644)
	tree.file(t, "sys", "libfoo.so", 0o644)
	fakeSearchPaths(t, nil, []string{tree.dir("sys")})

	t.Setenv("LD_LIBRARY_PATH", tree.dir("env"))
	if got, err := resolveFullPath("libfoo.so"); err != nil || got != tree.dir("env")+"/libfoo.so" {
		t.Errorf("with LD_LIBRARY_PATH: %q, %v", got, err)
	}
	os.Unsetenv("LD_LIBRARY_PATH")
	if got, err := resolveFullPath("libfoo.so"); err != nil || got != tree.dir("sys")+"/libfoo.so" {
		t.Errorf("without LD_LIBRARY_PATH: %q, %v", got, err)
	}
}

// TestArchLibPath checks the default library directories, which include the
// multiarch directory of the running architecture.
func TestArchLibPath(t *testing.T) {
	want := map[string]string{"amd64": "/lib/x86_64-linux-gnu", "arm64": "/lib/aarch64-linux-gnu"}
	if got := archLibPath(); got != want[runtime.GOARCH] {
		t.Errorf("archLibPath = %q, want %q", got, want[runtime.GOARCH])
	}
	wantPaths := []string{"/usr/lib64:/usr/lib", archLibPath(), "/lib64:/lib"}
	if fmt.Sprint(librarySearchPaths) != fmt.Sprint(wantPaths) {
		t.Errorf("library search paths = %q, want %q", librarySearchPaths, wantPaths)
	}
	if want := []string{"/usr/bin:/usr/sbin"}; fmt.Sprint(binarySearchPaths) != fmt.Sprint(want) {
		t.Errorf("binary search paths = %q, want %q", binarySearchPaths, want)
	}
}

// TestUprobeLocation checks the probed file and offset: a path with a slash
// is used as given, a bare name is resolved, FuncName adds its offset, and an
// archive member is probed as the member path without FuncName and on the
// archive with it.
func TestUprobeLocation(t *testing.T) {
	tree := newSearchTree(t)
	tree.file(t, "bin", "tool", 0o755)
	t.Setenv("PATH", tree.dir("bin"))
	fakeSearchPaths(t, nil, nil)

	symOffset, err := findFuncOffset(funcTestObject, funcTestName)
	if err != nil {
		t.Fatalf("findFuncOffset: %v", err)
	}
	archivePath := objectArchive(t, zip.Store)
	member := archivePath + archiveSep + funcTestMember
	memberOffset := memberDataOffset(t, archivePath, funcTestMember) + symOffset

	tests := []struct {
		name       string
		path       string
		funcName   string
		wantPath   string
		wantOffset uint64
		want       syscall.Errno
	}{
		{"absolute path", "/nonexistent/tool", "", "/nonexistent/tool", 0x10, 0},
		{"relative path", "nonexistent/tool", "", "nonexistent/tool", 0x10, 0},
		{"bare name", "tool", "", tree.dir("bin") + "/tool", 0x10, 0},
		{"missing bare name", "gobpfgo-no-such-tool", "", "", 0, unix.ENOENT},
		{"function", funcTestObject, funcTestName, funcTestObject, symOffset + 0x10, 0},
		{"member", member, "", funcTestMember, 0x10, 0},
		{"function in member", member, funcTestName, archivePath, memberOffset + 0x10, 0},
		{"missing function", funcTestObject, "no_such_function", "", 0, unix.ENOENT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, offset, err := uprobeLocation(tt.path, 0x10, tt.funcName)
			if tt.want != 0 {
				if !errors.Is(err, tt.want) {
					t.Fatalf("uprobeLocation = %q, %#x, %v, want %v", path, offset, err, tt.want)
				}
				return
			}
			if err != nil || path != tt.wantPath || offset != tt.wantOffset {
				t.Fatalf("uprobeLocation = %q, %#x, %v, want %q, %#x", path, offset, err, tt.wantPath, tt.wantOffset)
			}
		})
	}
}

// uprobeModeCase is one attach of a uprobe at uprobeTarget in the test binary
// for TestBpfProgramAttachUprobeModes. A cookie case passes uprobeModeCookie;
// want is the error the attach must return on the running kernel, 0 when it
// must succeed.
type uprobeModeCase struct {
	name   string
	mode   ProbeAttachMode
	cookie bool
	refCtr uint64
	want   syscall.Errno
}

// errnoUnless returns 0 when the kernel has the capability the case needs,
// and errno otherwise.
func errnoUnless(ok bool, errno syscall.Errno) syscall.Errno {
	if ok {
		return 0
	}
	return errno
}

// TestBpfProgramAttachUprobeModes attaches a uprobe to uprobeTarget in every
// mode and fires it. On 6.18 the default and link modes use the uprobe PMU
// and a BPF perf link, which carries the cookie; on 5.10 the default mode
// uses the PMU with the ioctl, and the link mode and every cookie are
// EOPNOTSUPP. The perf mode always uses the ioctl and refuses a cookie, and
// the legacy mode creates a tracefs event and refuses a cookie and a
// reference counter. A failed attach leaves no descriptor and no tracefs
// event behind.
func TestBpfProgramAttachUprobeModes(t *testing.T) {
	cookies := featBpfCookie.supported()
	cases := []uprobeModeCase{
		{name: "default", mode: ProbeAttachModeDefault},
		{name: "default cookie", mode: ProbeAttachModeDefault, cookie: true, want: errnoUnless(cookies, unix.EOPNOTSUPP)},
		{name: "link", mode: ProbeAttachModeLink, want: errnoUnless(perfLinkSupported(), unix.EOPNOTSUPP)},
		{name: "link cookie", mode: ProbeAttachModeLink, cookie: true, want: errnoUnless(cookies, unix.EOPNOTSUPP)},
		{name: "perf", mode: ProbeAttachModePerf},
		{name: "perf cookie", mode: ProbeAttachModePerf, cookie: true, want: unix.EOPNOTSUPP},
		{name: "legacy", mode: ProbeAttachModeLegacy},
		{name: "legacy cookie", mode: ProbeAttachModeLegacy, cookie: true, want: unix.EOPNOTSUPP},
		{name: "legacy ref counter", mode: ProbeAttachModeLegacy, refCtr: 0x10, want: unix.EINVAL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runUprobeModeCase(t, c)
		})
	}
}

// runUprobeModeCase attaches, fires and destroys one mode case. A cookie case
// attaches the cookie program where the kernel has BPF cookies; elsewhere the
// verifier rejects bpf_get_attach_cookie, so it attaches the counting program
// and only checks the attach error.
func runUprobeModeCase(t *testing.T, c uprobeModeCase) {
	readsCookie := c.cookie && featBpfCookie.supported()
	obj, prog, mapName := loadUprobeModeProgram(t, readsCookie)
	defer BpfObjectClose(obj)

	opts := &BpfUprobeOpts{AttachMode: c.mode, RefCtrOffset: c.refCtr}
	if c.cookie {
		opts.BpfCookie = uprobeModeCookie
	}
	offset := uprobeTargetOffset(t)
	events, fds := uprobeEvents(t), openDescriptors(t)

	link, err := BpfProgramAttachUprobeOpts(prog, 0, "/proc/self/exe", offset, opts)
	if c.want != 0 {
		if link != nil || !errors.Is(err, c.want) {
			BpfLinkDestroy(link)
			t.Fatalf("attach = %v, %v, want %v", link, err, c.want)
		}
		checkNothingLeft(t, events, fds)
		return
	}
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	checkUprobeModeLink(t, link, c.mode)
	if link.legacy != nil {
		line := fmt.Sprintf("p:%s/%s /proc/self/exe:0x%016x", link.legacy.group(), link.legacy.name, offset)
		if got := uprobeEvents(t); !strings.Contains(got, line) {
			t.Errorf("uprobe_events has no %q:\n%s", line, got)
		}
	} else if got := uprobeEvents(t); got != events {
		t.Errorf("a PMU attach changed uprobe_events:\n%s", got)
	}

	uprobeTarget()
	got := mapValue(t, obj, mapName)
	if readsCookie && got != uprobeModeCookie {
		t.Errorf("cookie = %#x, want %#x", got, uprobeModeCookie)
	}
	if !readsCookie && got == 0 {
		t.Error("count = 0, want the uprobe to fire")
	}

	BpfLinkDestroy(link)
	checkNothingLeft(t, events, fds)
}

// loadUprobeModeProgram loads the counting uprobe program, or the cookie
// program retyped as a kprobe program, which a uprobe needs, and returns the
// object, the program and the map it writes.
func loadUprobeModeProgram(t *testing.T, readsCookie bool) (*BpfObject, *BpfProgram, string) {
	t.Helper()

	if readsCookie {
		obj, prog := loadKprobeRetypedObject(t, "../testdata/progs/cookie.bpf.o", "handle_cookie", BPF_ATTACH_TYPE_UNSPEC)
		return obj, prog, "cookies"
	}
	obj := loadTestObject(t, "../testdata/progs/uprobe.bpf.o")
	prog := BpfObjectFindProgramByName(obj, "handle_uprobe")
	if prog == nil {
		BpfObjectClose(obj)
		t.Fatal("program handle_uprobe not found")
	}
	return obj, prog, "counts"
}

// checkUprobeModeLink checks what the attach created: a tracefs event only
// in the legacy mode or, in the default mode, without the uprobe PMU; and a
// BPF perf link, whose descriptor differs from the perf event's, in the link
// mode and, when the kernel has perf links, in the default mode.
func checkUprobeModeLink(t *testing.T, link *BpfLink, mode ProbeAttachMode) {
	t.Helper()

	_, pmuErr := determineUprobePerfType()
	wantLegacy := mode == ProbeAttachModeLegacy || mode == ProbeAttachModeDefault && pmuErr != nil
	wantPerfLink := mode == ProbeAttachModeLink || mode == ProbeAttachModeDefault && perfLinkSupported()

	if fd := BpfLinkFD(link); fd < 0 || link.perfFD < 0 {
		t.Fatalf("link descriptor %d, perf event %d", fd, link.perfFD)
	}
	if gotLegacy := link.legacy != nil; gotLegacy != wantLegacy {
		t.Errorf("tracefs event %v, want %v", gotLegacy, wantLegacy)
	}
	if gotPerfLink := link.fd != link.perfFD; gotPerfLink != wantPerfLink {
		t.Errorf("perf link %v, want %v", gotPerfLink, wantPerfLink)
	}
}

// uprobeEvents returns the tracefs uprobe_events file, or "" without tracefs.
func uprobeEvents(t *testing.T) string {
	t.Helper()

	root, err := tracefsRoot()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(root, "uprobe_events"))
	if err != nil {
		t.Fatalf("read uprobe_events: %v", err)
	}
	return string(data)
}

// openDescriptors returns the number of descriptors the process has open.
func openDescriptors(t *testing.T) int {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// checkNothingLeft requires the tracefs uprobe events and the number of open
// descriptors to be what they were before the attach.
func checkNothingLeft(t *testing.T, events string, fds int) {
	t.Helper()

	if got := uprobeEvents(t); got != events {
		t.Errorf("uprobe_events changed:\n%s\nwas:\n%s", got, events)
	}
	if got := openDescriptors(t); got != fds {
		t.Errorf("%d descriptors open, want %d", got, fds)
	}
}
