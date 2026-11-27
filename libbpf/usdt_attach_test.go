// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/gobpfgo/gobpfgo/internal/usdt"
	"golang.org/x/sys/unix"
)

const (
	usdtObjectPath     = "../testdata/progs/usdt_attach.bpf.o"
	usdtTargetPath     = "../testdata/progs/usdt_loop_target"
	usdtSemaTargetPath = "../testdata/progs/usdt_sema_target"

	usdtProvider = "gobpfgo"
	usdtName     = "loop"
	usdtSemaName = "sema"

	// usdtSemaSymbol is the semaphore of gobpfgo:sema in usdt_sema_target.
	usdtSemaSymbol = "gobpfgo_sema_semaphore"

	// usdtTestCookie is the USDT cookie the program must read back.
	usdtTestCookie = 0xc0ff_ee00_1234_5678
)

// openUsdtObject opens the USDT fixture without loading it.
func openUsdtObject(t *testing.T) *BpfObject {
	t.Helper()

	obj, err := BpfObjectOpenFile(usdtObjectPath, nil)
	if err != nil {
		t.Fatalf("open %s: %v", usdtObjectPath, err)
	}
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// TestUsdtObjectOpen checks the SEC("usdt") program and the usdt.bpf.h maps
// of the fixture.
func TestUsdtObjectOpen(t *testing.T) {
	obj := openUsdtObject(t)

	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	if prog == nil {
		t.Fatal("program handle_loop not found")
	}
	if prog.obj != obj || !prog.usdt || BpfProgramTypeOf(prog) != BPF_PROG_TYPE_KPROBE ||
		BpfProgramExpectedAttachType(prog) != BPF_ATTACH_TYPE_UNSPEC || BpfProgramSectionName(prog) != "usdt" {
		t.Errorf("handle_loop: usdt %v, type %d, attach type %d, section %q", prog.usdt,
			BpfProgramTypeOf(prog), BpfProgramExpectedAttachType(prog), BpfProgramSectionName(prog))
	}

	maps := []struct {
		name               string
		mapType            BpfMapType
		keySize, valueSize uint32
		maxEntries         uint32
	}{
		{usdtSpecsMapName, BPF_MAP_TYPE_ARRAY, usdtSpecIDSize, usdt.SpecSize, 256},
		{usdtIPMapName, BPF_MAP_TYPE_HASH, usdtIPSize, usdtSpecIDSize, 1024},
	}
	for _, want := range maps {
		m := BpfObjectFindMapByName(obj, want.name)
		if m == nil {
			t.Errorf("map %s not found", want.name)
			continue
		}
		if BpfMapTypeOf(m) != want.mapType || BpfMapKeySize(m) != want.keySize ||
			BpfMapValueSize(m) != want.valueSize || BpfMapMaxEntries(m) != want.maxEntries {
			t.Errorf("map %s: type %d, key %d, value %d, entries %d", want.name,
				BpfMapTypeOf(m), BpfMapKeySize(m), BpfMapValueSize(m), BpfMapMaxEntries(m))
		}
	}
}

// TestUsdtObjectPrepare resolves the fixture's LINUX_HAS_BPF_COOKIE extern
// and its program relocations without a kernel: every relocation must name
// one of the maps usdt.bpf.h and the fixture use, or the .kconfig map.
func TestUsdtObjectPrepare(t *testing.T) {
	obj := openUsdtObject(t)
	if err := resolveExterns(obj); err != nil {
		t.Fatalf("resolveExterns: %v", err)
	}
	if got, want := obj.kconfigMap.initialValue[0] != 0, featBpfCookie.supported(); got != want {
		t.Errorf("LINUX_HAS_BPF_COOKIE = %v, feature probe %v", got, want)
	}

	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	insns := slices.Clone(prog.insns)
	used := map[string]bool{}
	for _, rel := range prog.relocs {
		r, err := recordReloc(obj, prog, rel, insns)
		if err != nil {
			t.Fatalf("relocation %s: %v", rel.Symbol, err)
		}
		used[BpfMapName(r.m)] = true
	}
	for _, name := range []string{"records", usdtSpecsMapName, usdtIPMapName, BpfMapName(obj.kconfigMap)} {
		if !used[name] {
			t.Errorf("no relocation uses map %s; used %v", name, used)
		}
	}
	if len(used) != 4 {
		t.Errorf("relocations use maps %v, want 4", used)
	}
}

func TestSecDefUsdt(t *testing.T) {
	for _, tt := range []struct {
		section string
		flags   uint32
	}{
		{"usdt", 0},
		{"usdt/bin:provider:name", 0},
		{"usdt.s", BPF_F_SLEEPABLE},
		{"usdt.s/bin:provider:name", BPF_F_SLEEPABLE},
	} {
		def, ok := secDefFor(tt.section)
		if !ok || def.flags&secUSDT == 0 || def.progType != BPF_PROG_TYPE_KPROBE || def.progFlags != tt.flags {
			t.Errorf("secDefFor(%q) = %+v, %v", tt.section, def, ok)
		}
	}
}

func TestNewUsdtManager(t *testing.T) {
	man, err := newUsdtManager(openUsdtObject(t))
	if err != nil {
		t.Fatalf("newUsdtManager: %v", err)
	}
	if man.specsMap == nil || man.ipMap == nil || man.nextFreeSpecID != 0 || len(man.freeSpecIDs) != 0 {
		t.Errorf("manager = %+v", man)
	}
	if man.hasBpfCookie != featBpfCookie.supported() || man.hasUprobeMulti != featUprobeMultiLink.supported() {
		t.Errorf("manager features: cookie %v, uprobe multi %v", man.hasBpfCookie, man.hasUprobeMulti)
	}

	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("open kprobe.bpf.o: %v", err)
	}
	defer BpfObjectClose(obj)
	if _, err := newUsdtManager(obj); !errors.Is(err, unix.ESRCH) {
		t.Errorf("object without the USDT maps: %v, want ESRCH", err)
	}

	resized := openUsdtObject(t)
	BpfObjectFindMapByName(resized, usdtSpecsMapName).valueSize = 208
	if _, err := newUsdtManager(resized); !errors.Is(err, unix.EINVAL) {
		t.Errorf("spec map of another layout: %v, want EINVAL", err)
	}
}

// TestUsdtSpecIDs walks the spec ID bookkeeping: sharing within one
// attachment, fresh IDs across attachments, the map size limit, and reuse of
// released IDs, newest first.
func TestUsdtSpecIDs(t *testing.T) {
	man := &usdtManager{specsMap: &BpfMap{maxEntries: 3}}
	alloc := func(ids map[string]int32, ul *usdtLink, spec string, wantID int32, wantNew bool) {
		t.Helper()
		id, isNew, err := man.allocateSpecID(ids, ul, spec)
		if err != nil || id != wantID || isNew != wantNew {
			t.Fatalf("allocateSpecID(%q) = %d, %v, %v, want %d, %v", spec, id, isNew, err, wantID, wantNew)
		}
	}

	a, aIDs := &usdtLink{man: man}, map[string]int32{}
	alloc(aIDs, a, "-4@%edi", 0, true)
	alloc(aIDs, a, "8@%rax", 1, true)
	alloc(aIDs, a, "-4@%edi", 0, false)

	b, bIDs := &usdtLink{man: man}, map[string]int32{}
	alloc(bIDs, b, "-4@%edi", 2, true)
	if _, _, err := man.allocateSpecID(bIDs, b, "8@%rbx"); !errors.Is(err, unix.E2BIG) {
		t.Fatalf("allocation past the map size: %v, want E2BIG", err)
	}

	a.detach()
	if !slices.Equal(man.freeSpecIDs, []int32{0, 1}) || a.specIDs != nil {
		t.Fatalf("after detach: free %v, link %v", man.freeSpecIDs, a.specIDs)
	}

	c, cIDs := &usdtLink{man: man}, map[string]int32{}
	alloc(cIDs, c, "8@%rbx", 1, true)
	alloc(cIDs, c, "8@%rcx", 0, true)
	if !slices.Equal(c.specIDs, []int32{1, 0}) || len(man.freeSpecIDs) != 0 || man.nextFreeSpecID != 3 {
		t.Fatalf("link c IDs %v, free %v, next %d", c.specIDs, man.freeSpecIDs, man.nextFreeSpecID)
	}
}

// TestUsdtLink checks the link surface without a kernel: no descriptor, no
// pin, and a destroy that releases the spec IDs and IP entries once.
func TestUsdtLink(t *testing.T) {
	man := &usdtManager{specsMap: &BpfMap{maxEntries: 8, fd: -1}, ipMap: &BpfMap{fd: -1}}
	ul := &usdtLink{man: man, specIDs: []int32{4, 5}, ips: []uint64{0x1000, 0x2000}}
	link := &BpfLink{fd: -1, perfFD: -1, usdt: ul}

	if fd := BpfLinkFD(link); fd != -1 {
		t.Errorf("BpfLinkFD = %d, want -1", fd)
	}
	if err := BpfLinkPin(link, "/sys/fs/bpf/usdt"); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Errorf("BpfLinkPin = %v, want EOPNOTSUPP", err)
	}

	BpfLinkDestroy(link)
	BpfLinkDestroy(link)
	if !slices.Equal(man.freeSpecIDs, []int32{4, 5}) || ul.ips != nil || ul.specIDs != nil {
		t.Errorf("after destroy: free %v, ips %v, ids %v", man.freeSpecIDs, ul.ips, ul.specIDs)
	}
}

// TestBpfProgramAttachUsdtErrors covers the failures before the kernel is
// involved. The program descriptor is a number no process has open; the
// manager is created from the unloaded fixture and set to the no-cookie path.
func TestBpfProgramAttachUsdtErrors(t *testing.T) {
	obj := openUsdtObject(t)
	man, err := newUsdtManager(obj)
	if err != nil {
		t.Fatalf("newUsdtManager: %v", err)
	}
	man.hasBpfCookie, man.hasUprobeMulti = false, false
	obj.usdtMan = man
	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	prog.fd = 1 << 30

	noMaps := &BpfProgram{fd: 1 << 30, obj: &BpfObject{}}
	notELF := filepath.Join(t.TempDir(), "not-elf")
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		prog     *BpfProgram
		pid      int
		path     string
		provider string
		probe    string
		want     syscall.Errno
	}{
		{"nil program", nil, -1, usdtTargetPath, usdtProvider, usdtName, unix.EINVAL},
		{"unloaded program", &BpfProgram{fd: -1}, -1, usdtTargetPath, usdtProvider, usdtName, unix.EINVAL},
		{"empty path", prog, -1, "", usdtProvider, usdtName, unix.EINVAL},
		{"no USDT maps", noMaps, -1, usdtTargetPath, usdtProvider, usdtName, unix.ESRCH},
		{"missing binary", prog, -1, filepath.Join(t.TempDir(), "missing"), usdtProvider, usdtName, unix.ENOENT},
		{"not ELF", prog, -1, notELF, usdtProvider, usdtName, unix.EBADF},
		{"relocatable object", prog, -1, usdtObjectPath, usdtProvider, usdtName, unix.EBADF},
		{"missing probe", prog, -1, usdtTargetPath, usdtProvider, "missing", unix.ENOENT},
		{"library without PID or cookies", prog, -1, usdtTargetPath, usdtProvider, usdtName, unix.EOPNOTSUPP},
		{"PID without the mapping", prog, os.Getpid(), usdtTargetPath, usdtProvider, usdtName, unix.ESRCH},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link, err := BpfProgramAttachUsdt(tt.prog, tt.pid, tt.path, tt.provider, tt.probe, nil)
			if link != nil {
				BpfLinkDestroy(link)
				t.Fatal("attach returned a link")
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("attach error = %v, want %v", err, tt.want)
			}
		})
	}
	if man.nextFreeSpecID != 0 {
		t.Errorf("failed attaches allocated %d spec IDs", man.nextFreeSpecID)
	}
}

// TestBpfProgramAttachUsdtRollback fails the first spec map write, because
// the fixture is not loaded, and checks that the spec ID returns to the free
// list.
func TestBpfProgramAttachUsdtRollback(t *testing.T) {
	obj := openUsdtObject(t)
	man, err := newUsdtManager(obj)
	if err != nil {
		t.Fatalf("newUsdtManager: %v", err)
	}
	man.hasBpfCookie, man.hasUprobeMulti = true, true
	obj.usdtMan = man
	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	prog.fd = 1 << 30

	link, err := BpfProgramAttachUsdt(prog, -1, usdtTargetPath, usdtProvider, usdtName, nil)
	if link != nil || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("attach = %v, %v, want EINVAL from the spec map write", link, err)
	}
	if !slices.Equal(man.freeSpecIDs, []int32{0}) || man.nextFreeSpecID != 1 {
		t.Errorf("after rollback: free %v, next %d", man.freeSpecIDs, man.nextFreeSpecID)
	}
}

// TestBpfProgramAttachUsdtCookieWithoutMulti covers a kernel with BPF cookies
// but no uprobe multi link: the attach fails before it reads the binary or
// allocates a spec ID.
func TestBpfProgramAttachUsdtCookieWithoutMulti(t *testing.T) {
	obj := openUsdtObject(t)
	man, err := newUsdtManager(obj)
	if err != nil {
		t.Fatalf("newUsdtManager: %v", err)
	}
	man.hasBpfCookie, man.hasUprobeMulti = true, false
	obj.usdtMan = man
	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	prog.fd = 1 << 30

	link, err := BpfProgramAttachUsdt(prog, -1, usdtTargetPath, usdtProvider, usdtName, nil)
	if link != nil || !errors.Is(err, unix.EOPNOTSUPP) {
		t.Fatalf("attach = %v, %v, want EOPNOTSUPP", link, err)
	}
	if man.nextFreeSpecID != 0 {
		t.Errorf("the rejected attach allocated %d spec IDs", man.nextFreeSpecID)
	}
}

// usdtLoopTarget is a running usdt_loop_target or usdt_sema_target. trigger
// fires both call sites once and waits until the target has done so.
type usdtLoopTarget struct {
	path   string
	pid    int
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

// checkedInUsdtTarget returns the absolute path of a checked-in target.
func checkedInUsdtTarget(t *testing.T, target string) string {
	t.Helper()

	path, err := filepath.Abs(target)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return path
}

// privateUsdtTarget copies a target into the test's temporary directory. A
// uprobe without a PID filter traps every process that maps its file, so a
// test attaching without a PID uses its own copy and cannot place breakpoints
// in a target another test is running.
func privateUsdtTarget(t *testing.T, target string) string {
	t.Helper()

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(target))
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatalf("copy target: %v", err)
	}
	return path
}

// startUsdtTarget runs the loop target at path until the test ends and waits
// until it is ready to be traced. A path that cannot be executed, such as a
// copy on a noexec temporary directory, skips the test.
func startUsdtTarget(t *testing.T, path string) *usdtLoopTarget {
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
		if errors.Is(err, unix.EACCES) {
			t.Skipf("cannot run %s: %v", path, err)
		}
		t.Fatalf("start %s: %v", path, err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Wait()
	})
	if f, ok := stdout.(*os.File); ok {
		_ = f.SetReadDeadline(time.Now().Add(30 * time.Second))
	}

	target := &usdtLoopTarget{path: path, pid: cmd.Process.Pid, stdin: stdin, stdout: bufio.NewReader(stdout)}
	target.expect(t, "ready\n")
	return target
}

// TestUsdtLoopTarget drives a private copy of the target without tracing it,
// so the root tests' start, trigger and stop protocol is checked everywhere.
func TestUsdtLoopTarget(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the USDT target is an x86-64 binary")
	}
	target := startUsdtTarget(t, privateUsdtTarget(t, usdtTargetPath))
	target.trigger(t)
	target.trigger(t)
	target.stop(t)
}

// TestUsdtSemaTarget does the same for the semaphore target, which reports a
// zero semaphore when nothing traces it.
func TestUsdtSemaTarget(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the USDT target is an x86-64 binary")
	}
	target := startUsdtTarget(t, privateUsdtTarget(t, usdtSemaTargetPath))
	target.triggerSemaphore(t, 0)
	target.triggerSemaphore(t, 0)
	target.stop(t)
}

func (target *usdtLoopTarget) trigger(t *testing.T) {
	t.Helper()

	if _, err := target.stdin.Write([]byte{'x'}); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	target.expect(t, "fired\n")
}

// triggerSemaphore fires the semaphore target's call sites once and requires
// the semaphore value it prints afterwards to be want.
func (target *usdtLoopTarget) triggerSemaphore(t *testing.T, want int) {
	t.Helper()

	target.trigger(t)
	target.expect(t, fmt.Sprintf("semaphore %d\n", want))
}

// stop closes the target's input and requires it to exit without saying more.
func (target *usdtLoopTarget) stop(t *testing.T) {
	t.Helper()

	if err := target.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if line, err := target.stdout.ReadString('\n'); err != io.EOF || line != "" {
		t.Fatalf("after stdin closed the target said %q, %v, want EOF", line, err)
	}
}

func (target *usdtLoopTarget) expect(t *testing.T, want string) {
	t.Helper()

	line, err := target.stdout.ReadString('\n')
	if err != nil || line != want {
		t.Fatalf("target said %q, %v, want %q", line, err, want)
	}
}

// loopRecord is struct loop_record of usdt_attach.bpf.c.
type loopRecord struct {
	args   [4]int64
	argCnt int64
	cookie uint64
	hits   int64
}

func readLoopRecord(t *testing.T, obj *BpfObject, site uint32) loopRecord {
	t.Helper()

	m := BpfObjectFindMapByName(obj, "records")
	key := binary.NativeEndian.AppendUint32(nil, site)
	value := make([]byte, BpfMapValueSize(m))
	if err := BpfMapLookupElem(m, key, value, 0); err != nil {
		t.Fatalf("lookup records[%d]: %v", site, err)
	}
	var rec loopRecord
	for i := range rec.args {
		rec.args[i] = int64(binary.NativeEndian.Uint64(value[i*8:]))
	}
	rec.argCnt = int64(binary.NativeEndian.Uint64(value[32:]))
	rec.cookie = binary.NativeEndian.Uint64(value[40:])
	rec.hits = int64(binary.NativeEndian.Uint64(value[48:]))
	return rec
}

// checkLoopRecords requires each call site's record to hold the arguments of
// the given round (the site number, the round, the site's stack slot, 102 or
// 103, and the negated round), an argument count of 4, the USDT cookie and
// the given hit count.
func checkLoopRecords(t *testing.T, obj *BpfObject, round, hits int64) {
	t.Helper()

	for site := int64(1); site <= 2; site++ {
		want := loopRecord{
			args:   [4]int64{site, round, 100 + site + 1, -round},
			argCnt: 4,
			cookie: usdtTestCookie,
			hits:   hits,
		}
		if got := readLoopRecord(t, obj, uint32(site)); got != want {
			t.Errorf("site %d record = %+v, want %+v", site, got, want)
		}
	}
}

// loadUsdtObject loads the fixture, skipping without privileges, and returns
// its program.
func loadUsdtObject(t *testing.T) (*BpfObject, *BpfProgram) {
	t.Helper()

	if runtime.GOARCH != "amd64" {
		t.Skip("the USDT target is an x86-64 binary")
	}
	obj := loadTestObject(t, usdtObjectPath)
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj, BpfObjectFindProgramByName(obj, "handle_loop")
}

// attachUsdtOrSkip attaches the program to the target's gobpfgo probe name.
// A kernel with BPF cookies but no uprobe multi link needs a cookie on each
// single uprobe, which that path cannot carry: the attach must fail with
// EOPNOTSUPP and the test skips.
func attachUsdtOrSkip(t *testing.T, obj *BpfObject, prog *BpfProgram, pid int, path, name string) *BpfLink {
	t.Helper()

	link, err := BpfProgramAttachUsdt(prog, pid, path, usdtProvider, name, &BpfUsdtOpts{UsdtCookie: usdtTestCookie})
	if man := obj.usdtMan; man != nil && man.hasBpfCookie && !man.hasUprobeMulti {
		if link != nil || !errors.Is(err, unix.EOPNOTSUPP) {
			t.Fatalf("attach = %v, %v, want EOPNOTSUPP on the single-uprobe cookie path", link, err)
		}
		t.Skip("BPF cookies without uprobe multi links need cookies on tracefs uprobes")
	}
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	t.Cleanup(func() { BpfLinkDestroy(link) })
	return link
}

// checkUsdtLoad checks what the load chose: the program's expected attach
// type and the LINUX_HAS_BPF_COOKIE value the program sees.
func checkUsdtLoad(t *testing.T, obj *BpfObject, prog *BpfProgram) {
	t.Helper()

	wantType := BPF_ATTACH_TYPE_UNSPEC
	if featUprobeMultiLink.supported() {
		wantType = BPF_TRACE_UPROBE_MULTI
	}
	if got := BpfProgramExpectedAttachType(prog); got != wantType {
		t.Errorf("expected attach type = %d, want %d", got, wantType)
	}

	cookie := obj.kconfigMap.initialValue[0] != 0
	if cookie != featBpfCookie.supported() {
		t.Errorf("LINUX_HAS_BPF_COOKIE = %v, feature probe %v", cookie, featBpfCookie.supported())
	}
}

// checkUsdtMaps checks the spec map entries against the parsed probes, and
// that the IP map maps every runtime address the link added to a spec ID of
// the link.
func checkUsdtMaps(t *testing.T, obj *BpfObject, ul *usdtLink, path string) {
	t.Helper()

	f, err := usdt.Open(path)
	if err != nil {
		t.Fatalf("usdt.Open: %v", err)
	}
	probes, err := f.Find(usdtProvider, usdtName)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(probes) != 2 || len(ul.specIDs) != 2 {
		t.Fatalf("%d probes and %d spec IDs, want 2 of each", len(probes), len(ul.specIDs))
	}

	for i, id := range ul.specIDs {
		want, err := usdt.MarshalSpec(probes[i].Spec, usdtTestCookie)
		if err != nil {
			t.Fatalf("MarshalSpec: %v", err)
		}
		got := make([]byte, usdt.SpecSize)
		key := binary.NativeEndian.AppendUint32(nil, uint32(id))
		if err := BpfMapLookupElem(obj.usdtMan.specsMap, key, got, 0); err != nil {
			t.Fatalf("lookup spec %d: %v", id, err)
		}
		if string(got) != string(want) {
			t.Errorf("spec %d = % x, want % x", id, got, want)
		}
	}

	if obj.usdtMan.hasBpfCookie {
		if len(ul.ips) != 0 {
			t.Errorf("the cookie path added IP entries %#x", ul.ips)
		}
		return
	}
	if len(ul.ips) != len(probes) {
		t.Fatalf("%d IP entries, want %d", len(ul.ips), len(probes))
	}
	for i, ip := range ul.ips {
		id, err := lookupUsdtIP(obj, ip)
		if err != nil || id != ul.specIDs[i] {
			t.Errorf("IP %#x maps to %d, %v, want spec %d", ip, id, err, ul.specIDs[i])
		}
	}
}

func lookupUsdtIP(obj *BpfObject, ip uint64) (int32, error) {
	value := make([]byte, usdtSpecIDSize)
	if err := BpfMapLookupElem(obj.usdtMan.ipMap, usdtIPKey(ip), value, 0); err != nil {
		return 0, err
	}
	return int32(binary.NativeEndian.Uint32(value)), nil
}

// TestBpfProgramAttachUsdt attaches to the running target's two call sites,
// fires them, checks the arguments, cookie and counts the program recorded,
// destroys the link, and attaches again with the released spec IDs. On a
// kernel with uprobe multi links the call sites share one link and find their
// specs by BPF cookie; without cookies each has a tracefs uprobe and the IP
// map holds its runtime address.
func TestBpfProgramAttachUsdt(t *testing.T) {
	obj, prog := loadUsdtObject(t)
	checkUsdtLoad(t, obj, prog)
	target := startUsdtTarget(t, checkedInUsdtTarget(t, usdtTargetPath))

	link := attachUsdtOrSkip(t, obj, prog, target.pid, target.path, usdtName)
	man := obj.usdtMan
	t.Logf("BPF cookie %v, uprobe multi %v", man.hasBpfCookie, man.hasUprobeMulti)
	if fd := BpfLinkFD(link); fd != -1 {
		t.Errorf("BpfLinkFD = %d, want -1", fd)
	}
	if err := BpfLinkPin(link, "/sys/fs/bpf/gobpfgo_usdt"); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Errorf("BpfLinkPin = %v, want EOPNOTSUPP", err)
	}
	checkUsdtMaps(t, obj, link.usdt, target.path)

	target.trigger(t)
	checkLoopRecords(t, obj, 1, 1)
	target.trigger(t)
	checkLoopRecords(t, obj, 2, 2)

	ids, ips := slices.Clone(link.usdt.specIDs), slices.Clone(link.usdt.ips)
	BpfLinkDestroy(link)
	target.trigger(t)
	checkLoopRecords(t, obj, 2, 2)
	if !slices.Equal(man.freeSpecIDs, ids) {
		t.Errorf("free spec IDs = %v, want %v", man.freeSpecIDs, ids)
	}
	for _, ip := range ips {
		if _, err := lookupUsdtIP(obj, ip); !errors.Is(err, unix.ENOENT) {
			t.Errorf("IP %#x after destroy: %v, want ENOENT", ip, err)
		}
	}

	again := attachUsdtOrSkip(t, obj, prog, target.pid, target.path, usdtName)
	slices.Reverse(ids)
	if !slices.Equal(again.usdt.specIDs, ids) || man.nextFreeSpecID != 2 {
		t.Errorf("second attach spec IDs = %v, next %d, want %v and 2", again.usdt.specIDs, man.nextFreeSpecID, ids)
	}
	checkUsdtMaps(t, obj, again.usdt, target.path)
	target.trigger(t)
	checkLoopRecords(t, obj, 4, 3)
}

// TestBpfProgramAttachUsdtAnyProcess attaches without a PID, to a private
// copy of the target. The target is a position-independent executable, so
// without BPF cookies the runtime addresses are unknown and the attach fails
// with EOPNOTSUPP.
func TestBpfProgramAttachUsdtAnyProcess(t *testing.T) {
	obj, prog := loadUsdtObject(t)
	target := startUsdtTarget(t, privateUsdtTarget(t, usdtTargetPath))

	if !featBpfCookie.supported() {
		link, err := BpfProgramAttachUsdt(prog, -1, target.path, usdtProvider, usdtName, nil)
		if link != nil || !errors.Is(err, unix.EOPNOTSUPP) {
			t.Fatalf("attach = %v, %v, want EOPNOTSUPP without BPF cookies", link, err)
		}
		return
	}

	attachUsdtOrSkip(t, obj, prog, -1, target.path, usdtName)
	target.trigger(t)
	checkLoopRecords(t, obj, 1, 1)
}

// TestUsdtSemaphoreTargets collects the call sites of gobpfgo:sema without a
// kernel. The first has no semaphore and gets reference counter offset 0; the
// second gets the file offset of the semaphore, which the kernel can only
// count in a writable, file-backed part of the executable. A kernel that does
// not count semaphores rejects the probe with EOPNOTSUPP.
func TestUsdtSemaphoreTargets(t *testing.T) {
	f, err := usdt.Open(usdtSemaTargetPath)
	if err != nil {
		t.Fatalf("usdt.Open: %v", err)
	}
	man := &usdtManager{hasBpfCookie: true, hasSemaRefcnt: true}

	targets, err := man.collectTargets(f, usdtSemaTargetPath, -1, usdtProvider, usdtSemaName, 0)
	if err != nil {
		t.Fatalf("collectTargets: %v", err)
	}
	var got []uint64
	for _, target := range targets {
		got = append(got, target.semaOff)
	}
	if want := []uint64{0, usdtSemaphoreOffset(t)}; !slices.Equal(got, want) {
		t.Errorf("semaphore offsets = %#x, want %#x", got, want)
	}

	man.hasSemaRefcnt = false
	if _, err := man.collectTargets(f, usdtSemaTargetPath, -1, usdtProvider, usdtSemaName, 0); !errors.Is(err, unix.EOPNOTSUPP) {
		t.Errorf("without semaphore counting: %v, want EOPNOTSUPP", err)
	}
}

// usdtSemaphoreOffset returns the file offset of the semaphore symbol of the
// semaphore target, from the ELF symbol table rather than the USDT note. The
// symbol must lie in the file-backed part of a writable segment.
func usdtSemaphoreOffset(t *testing.T) uint64 {
	t.Helper()

	f, err := elf.Open(usdtSemaTargetPath)
	if err != nil {
		t.Fatalf("open %s: %v", usdtSemaTargetPath, err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("symbols: %v", err)
	}
	i := slices.IndexFunc(syms, func(sym elf.Symbol) bool { return sym.Name == usdtSemaSymbol })
	if i < 0 {
		t.Fatalf("no symbol %s", usdtSemaSymbol)
	}
	sym := syms[i]

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_W != 0 &&
			sym.Value >= prog.Vaddr && sym.Value+sym.Size <= prog.Vaddr+prog.Filesz {
			return sym.Value - prog.Vaddr + prog.Off
		}
	}
	t.Fatalf("%s at %#x is not in the file-backed part of a writable segment", usdtSemaSymbol, sym.Value)
	return 0
}

// checkUsdtSemaphoreLinks checks how the two call sites of gobpfgo:sema were
// attached: through one uprobe multi link when the kernel has it, otherwise
// with a tracefs uprobe for the call site without a semaphore and a uprobe
// PMU event, which owns its perf event descriptor, for the one with it.
func checkUsdtSemaphoreLinks(t *testing.T, ul *usdtLink) {
	t.Helper()

	if ul.man.hasUprobeMulti {
		if ul.multiLink == nil || len(ul.uprobes) != 0 {
			t.Errorf("multi link %v and %d uprobes, want one multi link", ul.multiLink, len(ul.uprobes))
		}
		return
	}
	if ul.multiLink != nil || len(ul.uprobes) != 2 {
		t.Fatalf("multi link %v and %d uprobes, want 2 uprobes", ul.multiLink, len(ul.uprobes))
	}
	if plain := ul.uprobes[0]; plain.legacy == nil {
		t.Errorf("call site without a semaphore: no tracefs event")
	}
	if sema := ul.uprobes[1]; sema.legacy != nil || sema.perfFD < 0 || sema.fd != sema.perfFD {
		t.Errorf("call site with a semaphore: tracefs event %v, descriptors %d and %d, want a PMU event", sema.legacy, sema.fd, sema.perfFD)
	}
}

// TestBpfProgramAttachUsdtSemaphore attaches handle_loop to gobpfgo:sema in
// the running semaphore target. One of its two call sites has a semaphore, so
// the attachment passes one zero and one real reference counter offset. The
// target prints the semaphore after every round: 0 before the attach, 1 while
// the link exists and 0 again after the link is destroyed, and the program
// records the arguments of both call sites only in the attached round. On a
// kernel with uprobe multi links the call sites share one link; without
// them, as on 5.10, the call site with the semaphore goes through the uprobe
// PMU and the other through tracefs.
func TestBpfProgramAttachUsdtSemaphore(t *testing.T) {
	obj, prog := loadUsdtObject(t)
	target := startUsdtTarget(t, checkedInUsdtTarget(t, usdtSemaTargetPath))
	target.triggerSemaphore(t, 0)

	link := attachUsdtOrSkip(t, obj, prog, target.pid, target.path, usdtSemaName)
	man := obj.usdtMan
	t.Logf("BPF cookie %v, uprobe multi %v", man.hasBpfCookie, man.hasUprobeMulti)
	checkUsdtSemaphoreLinks(t, link.usdt)

	target.triggerSemaphore(t, 1)
	checkLoopRecords(t, obj, 2, 1)

	BpfLinkDestroy(link)
	target.triggerSemaphore(t, 0)
	checkLoopRecords(t, obj, 2, 1)
}
