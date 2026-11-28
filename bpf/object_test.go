// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/bpf"
	"github.com/gobpfgo/gobpfgo/libbpf"
)

const (
	progsDir         = "../testdata/progs"
	oracleDir        = "../testdata/oracle"
	kprobeObject     = progsDir + "/kprobe.bpf.o"
	globalDataObject = progsDir + "/global_data.bpf.o"

	// dataMagic is the initial value of global_data.bpf.c's data_magic, the
	// first .data variable.
	dataMagic = 0xfeedfacecafebeef
)

// openFixture is the part of an open oracle fixture the layer exposes: the
// object name and libbpf's maps and programs, in libbpf's order.
type openFixture struct {
	ObjectName string        `json:"object_name"`
	Maps       []mapMeta     `json:"maps"`
	Programs   []programMeta `json:"programs"`
}

type mapMeta struct {
	Name           string `json:"name"`
	Type           uint32 `json:"type"`
	KeySize        uint32 `json:"key_size"`
	ValueSize      uint32 `json:"value_size"`
	MaxEntries     uint32 `json:"max_entries"`
	MapFlags       uint32 `json:"map_flags"`
	BtfKeyTypeID   uint32 `json:"btf_key_type_id"`
	BtfValueTypeID uint32 `json:"btf_value_type_id"`
}

type programMeta struct {
	Name               string `json:"name"`
	Type               uint32 `json:"type"`
	ExpectedAttachType uint32 `json:"expected_attach_type"`
	Section            string `json:"section"`
	InsnCnt            int    `json:"insn_cnt"`
}

func loadOpenFixture(t *testing.T, name string) openFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(oracleDir, name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f openFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return f
}

// openObject opens path through the layer and closes it when the test ends.
func openObject(t *testing.T, path string) *bpf.Object {
	t.Helper()

	obj, err := bpf.OpenFile(path, nil)
	if err != nil {
		t.Fatalf("OpenFile %s: %v", path, err)
	}
	t.Cleanup(func() { obj.Close() })
	return obj
}

func mapMetaOf(m *bpf.Map) mapMeta {
	return mapMeta{
		Name:           m.Name(),
		Type:           uint32(m.Type()),
		KeySize:        m.KeySize(),
		ValueSize:      m.ValueSize(),
		MaxEntries:     m.MaxEntries(),
		MapFlags:       m.Flags(),
		BtfKeyTypeID:   m.BtfKeyTypeID(),
		BtfValueTypeID: m.BtfValueTypeID(),
	}
}

func programMetaOf(p *bpf.Program) programMeta {
	return programMeta{
		Name:               p.Name(),
		Type:               uint32(p.Type()),
		ExpectedAttachType: uint32(p.ExpectedAttachType()),
		Section:            p.SectionName(),
		InsnCnt:            p.InsnCnt(),
	}
}

// TestObjectMatchesOpenFixture opens each object through the layer and
// compares the name, the map and program order and their metadata with the
// libbpf open oracle. It also checks that Programs and Maps return the same
// wrappers on every call and that Program and Map find them by name.
func TestObjectMatchesOpenFixture(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ object, fixture string }{
		{"kprobe.bpf.o", "open.json"},
		{"global_data.bpf.o", "open-global-data.json"},
		{"kconfig.bpf.o", "open-kconfig.json"},
		{"percpu.bpf.o", "open-percpu.json"},
		{"subprog_arg_ctx.bpf.o", "open-subprog-arg-ctx.json"},
	} {
		t.Run(tc.object, func(t *testing.T) {
			t.Parallel()

			f := loadOpenFixture(t, tc.fixture)
			obj := openObject(t, filepath.Join(progsDir, tc.object))

			if got := obj.Name(); got != f.ObjectName {
				t.Errorf("Name = %q, want %q", got, f.ObjectName)
			}
			checkMaps(t, obj, f.Maps)
			checkPrograms(t, obj, f.Programs)
		})
	}
}

func checkMaps(t *testing.T, obj *bpf.Object, want []mapMeta) {
	t.Helper()

	maps := obj.Maps()
	var got []mapMeta
	for _, m := range maps {
		got = append(got, mapMetaOf(m))
		if found := obj.Map(m.Name()); found != m {
			t.Errorf("Map(%q) = %p, want %p", m.Name(), found, m)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("maps = %+v, want %+v", got, want)
	}
	if again := obj.Maps(); !slices.Equal(again, maps) {
		t.Error("a second Maps call returned different wrappers")
	}
}

func checkPrograms(t *testing.T, obj *bpf.Object, want []programMeta) {
	t.Helper()

	progs := obj.Programs()
	var got []programMeta
	for _, p := range progs {
		got = append(got, programMetaOf(p))
		if found := obj.Program(p.Name()); found != p {
			t.Errorf("Program(%q) = %p, want %p", p.Name(), found, p)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("programs = %+v, want %+v", got, want)
	}
	if again := obj.Programs(); !slices.Equal(again, progs) {
		t.Error("a second Programs call returned different wrappers")
	}
}

// TestKprobeObjectOpen checks the kprobe object before Load: the lookups by
// name, the unloaded descriptors and instructions, and the map element
// operations, which the core rejects with its own ENOENT.
func TestKprobeObjectOpen(t *testing.T) {
	t.Parallel()

	obj := openObject(t, kprobeObject)
	prog := obj.Program("handle_open")
	counts := obj.Map("counts")
	if prog == nil || counts == nil {
		t.Fatalf("Program(handle_open) = %v, Map(counts) = %v", prog, counts)
	}
	if obj.Program("missing") != nil || obj.Map("missing") != nil {
		t.Error("a missing name returned a wrapper")
	}

	if prog.FD() != -1 || counts.FD() != -1 {
		t.Errorf("FDs before Load = %d, %d, want -1", prog.FD(), counts.FD())
	}
	if got, want := len(prog.Insns()), 8*prog.InsnCnt(); got != want || got == 0 {
		t.Errorf("Insns length = %d, want %d and nonzero", got, want)
	}
	if counts.IsPinned() {
		t.Error("counts is pinned before Load")
	}
	if obj.BTF() == nil {
		t.Error("BTF = nil for an object with BTF")
	}

	key := make([]byte, counts.KeySize())
	value := make([]byte, counts.ValueSize())
	for name, err := range map[string]error{
		"Lookup":          counts.Lookup(key, value, 0),
		"Update":          counts.Update(key, value, 0),
		"Delete":          counts.Delete(key, 0),
		"LookupAndDelete": counts.LookupAndDelete(key, value, 0),
		"NextKey":         counts.NextKey(nil, key),
	} {
		var coreErr *libbpf.Error
		if !errors.As(err, &coreErr) || coreErr.Errno != syscall.ENOENT {
			t.Errorf("%s before Load = %v, want the core ENOENT error", name, err)
		}
	}
}

// TestMapInitialValueOpen checks the initial value of global_data.bpf.o's
// .data map through the layer before Load: it is the core's buffer, a copy
// set with SetInitialValue shows in it, and the core rejects a value of
// another size and a .maps definition with EINVAL. After Close it is nil and
// SetInitialValue returns ErrClosed.
func TestMapInitialValueOpen(t *testing.T) {
	t.Parallel()

	obj, err := bpf.OpenFile(globalDataObject, nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	data := obj.Map(".data")
	if data == nil {
		t.Fatal("no .data map")
	}
	initial := data.InitialValue()
	if len(initial) != int(data.ValueSize()) || binary.NativeEndian.Uint64(initial) != dataMagic {
		t.Fatalf(".data initial value = %x, want %d bytes starting with data_magic", initial, data.ValueSize())
	}

	value := bytes.Repeat([]byte{0x5a}, len(initial))
	if err := data.SetInitialValue(value); err != nil {
		t.Fatalf("SetInitialValue: %v", err)
	}
	if !bytes.Equal(data.InitialValue(), value) {
		t.Errorf(".data initial value = %x after the set, want %x", data.InitialValue(), value)
	}
	checkCoreErrno(t, "SetInitialValue with a short value", data.SetInitialValue(value[1:]), syscall.EINVAL)

	obj.Close()
	if data.InitialValue() != nil {
		t.Error("InitialValue after Close is not nil")
	}
	if err := data.SetInitialValue(value); !errors.Is(err, bpf.ErrClosed) {
		t.Errorf("SetInitialValue after Close = %v, want ErrClosed", err)
	}
}

// checkCoreErrno fails the test unless err is the core *libbpf.Error with
// errno.
func checkCoreErrno(t *testing.T, what string, err error, errno syscall.Errno) {
	t.Helper()

	var coreErr *libbpf.Error
	if !errors.As(err, &coreErr) || coreErr.Errno != errno {
		t.Errorf("%s = %v, want the core %v error", what, err, errno)
	}
}

// TestMapInternalAndPinPath checks IsInternal on a .maps definition and an
// internal map, and that PinPath follows SetPinPath without touching bpffs.
func TestMapInternalAndPinPath(t *testing.T) {
	t.Parallel()

	obj := openObject(t, filepath.Join(progsDir, "kconfig.bpf.o"))
	values, kconfig := obj.Map("values"), obj.Map(".kconfig")
	if values == nil || kconfig == nil {
		t.Fatalf("Map(values) = %v, Map(.kconfig) = %v", values, kconfig)
	}
	if values.IsInternal() || !kconfig.IsInternal() {
		t.Errorf("IsInternal: values %v, .kconfig %v, want false, true", values.IsInternal(), kconfig.IsInternal())
	}

	if got := values.PinPath(); got != "" {
		t.Errorf("PinPath at open = %q, want empty", got)
	}
	path := "/sys/fs/bpf/gobpfgo_values"
	if err := values.SetPinPath(&path); err != nil {
		t.Fatalf("SetPinPath: %v", err)
	}
	if got := values.PinPath(); got != path {
		t.Errorf("PinPath = %q, want %q", got, path)
	}
	if err := values.SetPinPath(nil); err != nil {
		t.Fatalf("SetPinPath(nil): %v", err)
	}
	if got := values.PinPath(); got != "" {
		t.Errorf("PinPath after clear = %q, want empty", got)
	}
}

// TestOpenLinkError checks that an OpenLink failure is the core error.
func TestOpenLinkError(t *testing.T) {
	t.Parallel()

	link, err := bpf.OpenLink("")
	var coreErr *libbpf.Error
	if link != nil || !errors.As(err, &coreErr) || coreErr.Errno != syscall.EINVAL {
		t.Fatalf("OpenLink(\"\") = %v, %v, want nil and the core EINVAL error", link, err)
	}
}

// TestOpenMem opens the kprobe object from memory, with the default and an
// explicit object name.
func TestOpenMem(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(kprobeObject)
	if err != nil {
		t.Fatalf("read %s: %v", kprobeObject, err)
	}
	name := "kprobe_mem"
	opts := libbpf.NewBpfObjectOpenOpts()
	opts.ObjectName = &name

	for _, tc := range []struct {
		opts *libbpf.BpfObjectOpenOpts
		want string
	}{
		{nil, "mem"},
		{opts, name},
	} {
		obj, err := bpf.OpenMem(data, tc.opts)
		if err != nil {
			t.Fatalf("OpenMem: %v", err)
		}
		if got := obj.Name(); got != tc.want {
			t.Errorf("Name = %q, want %q", got, tc.want)
		}
		if obj.Program("handle_open") == nil || obj.Map("counts") == nil {
			t.Error("OpenMem object is missing handle_open or counts")
		}
		obj.Close()
	}
}

// TestOpenFileError checks that an open failure is the core error.
func TestOpenFileError(t *testing.T) {
	t.Parallel()

	obj, err := bpf.OpenFile(filepath.Join(progsDir, "missing.bpf.o"), nil)
	var coreErr *libbpf.Error
	if obj != nil || !errors.As(err, &coreErr) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("OpenFile missing = %v, %v, want nil and the core ENOENT error", obj, err)
	}
}

// TestObjectClose checks that Close is idempotent and that afterwards every
// method with an error result returns ErrClosed and the accessors return
// zero values.
func TestObjectClose(t *testing.T) {
	t.Parallel()

	obj, err := bpf.OpenFile(kprobeObject, nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	prog := obj.Program("handle_open")
	counts := obj.Map("counts")
	pinPath := "/sys/fs/bpf/gobpfgo_counts"
	if err := counts.SetPinPath(&pinPath); err != nil {
		t.Fatalf("SetPinPath: %v", err)
	}

	for range 2 {
		if err := obj.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}

	for _, c := range errorMethods(obj, prog, counts) {
		if err := c.call(); !errors.Is(err, bpf.ErrClosed) {
			t.Errorf("%s after Close = %v, want ErrClosed", c.name, err)
		}
	}
	checkClosedAccessors(t, obj, prog, counts)
}

type methodCall struct {
	name string
	call func() error
}

// errorMethods returns a call of every Object, Program and Map method that
// has an error result, plus Link.UpdateProgram with prog. An attach method
// that returns a Link reports an error for it.
func errorMethods(obj *bpf.Object, prog *bpf.Program, counts *bpf.Map) []methodCall {
	path := "/sys/fs/bpf/gobpfgo_closed"
	buf := make([]byte, 8)
	attach := func(l *bpf.Link, err error) error {
		if l != nil {
			l.Destroy()
			return errors.New("returned a Link")
		}
		return err
	}
	return []methodCall{
		{"Object.Load", obj.Load},
		{"Object.Pin", func() error { return obj.Pin(path) }},
		{"Object.Unpin", func() error { return obj.Unpin(path) }},
		{"Program.Pin", func() error { return prog.Pin(path) }},
		{"Program.Unpin", func() error { return prog.Unpin(path) }},
		{"Program.Info", func() error { _, err := prog.Info(); return err }},
		{"Program.SetAttachTarget", func() error { return prog.SetAttachTarget(3, "xdp_pass") }},
		{"Program.AttachKprobe", func() error { return attach(prog.AttachKprobe(false, "do_sys_openat2")) }},
		{"Program.AttachKprobeOpts", func() error { return attach(prog.AttachKprobeOpts("do_sys_openat2", nil)) }},
		{"Program.AttachUprobe", func() error { return attach(prog.AttachUprobe(-1, "/bin/true", 0)) }},
		{"Program.AttachUprobeOpts", func() error { return attach(prog.AttachUprobeOpts(-1, "/bin/true", 0, nil)) }},
		{"Program.AttachTracepoint", func() error { return attach(prog.AttachTracepoint("syscalls", "sys_enter_openat")) }},
		{"Program.AttachTracepointOpts", func() error {
			return attach(prog.AttachTracepointOpts("syscalls", "sys_enter_openat", nil))
		}},
		{"Program.AttachPerfEvent", func() error { return attach(prog.AttachPerfEvent(-1)) }},
		{"Program.AttachPerfEventOpts", func() error { return attach(prog.AttachPerfEventOpts(-1, nil)) }},
		{"Program.AttachRawTracepoint", func() error { return attach(prog.AttachRawTracepoint("sys_enter")) }},
		{"Program.AttachRawTracepointOpts", func() error { return attach(prog.AttachRawTracepointOpts("sys_enter", nil)) }},
		{"Program.AttachKprobeMulti", func() error { return attach(prog.AttachKprobeMulti(nil)) }},
		{"Program.AttachUprobeMulti", func() error { return attach(prog.AttachUprobeMulti(-1, "/bin/true", "", nil)) }},
		{"Program.AttachUsdt", func() error { return attach(prog.AttachUsdt(-1, "/bin/true", "provider", "name", nil)) }},
		{"Program.AttachCgroup", func() error { return attach(prog.AttachCgroup(0)) }},
		{"Program.AttachCgroupOpts", func() error { return attach(prog.AttachCgroupOpts(0, nil)) }},
		{"Program.AttachNetns", func() error { return attach(prog.AttachNetns(0)) }},
		{"Program.AttachXDP", func() error { return attach(prog.AttachXDP(1)) }},
		{"Program.AttachSockmap", func() error { return attach(prog.AttachSockmap(0)) }},
		{"Program.AttachIter", func() error { return attach(prog.AttachIter(nil)) }},
		{"Program.AttachFreplace", func() error { return attach(prog.AttachFreplace(3, "xdp_pass")) }},
		{"Program.AttachTrace", func() error { return attach(prog.AttachTrace()) }},
		{"Program.AttachTraceOpts", func() error { return attach(prog.AttachTraceOpts(nil)) }},
		{"Program.AttachLsm", func() error { return attach(prog.AttachLsm()) }},
		{"Program.Attach", func() error { return attach(prog.Attach()) }},
		{"Map.Lookup", func() error { return counts.Lookup(buf[:4], buf, 0) }},
		{"Map.Update", func() error { return counts.Update(buf[:4], buf, 0) }},
		{"Map.Delete", func() error { return counts.Delete(buf[:4], 0) }},
		{"Map.LookupAndDelete", func() error { return counts.LookupAndDelete(buf[:4], buf, 0) }},
		{"Map.NextKey", func() error { return counts.NextKey(nil, buf[:4]) }},
		{"Map.SetInitialValue", func() error { return counts.SetInitialValue(buf) }},
		{"Map.SetPinPath", func() error { return counts.SetPinPath(&path) }},
		{"Map.Pin", func() error { return counts.Pin(&path) }},
		{"Map.Unpin", func() error { return counts.Unpin(&path) }},
		{"Map.ReuseFD", func() error { return counts.ReuseFD(0) }},
		{"Link.UpdateProgram", func() error { return (*bpf.Link)(nil).UpdateProgram(prog) }},
	}
}

func checkClosedAccessors(t *testing.T, obj *bpf.Object, prog *bpf.Program, counts *bpf.Map) {
	t.Helper()

	if obj.Name() != "" || obj.Programs() != nil || obj.Maps() != nil {
		t.Errorf("Object after Close: Name %q, Programs %v, Maps %v", obj.Name(), obj.Programs(), obj.Maps())
	}
	if obj.Program("handle_open") != nil || obj.Map("counts") != nil {
		t.Error("lookup by name after Close returned a wrapper")
	}
	if obj.BTF() != nil {
		t.Error("BTF after Close is not nil")
	}
	if got := programMetaOf(prog); got != (programMeta{}) || prog.FD() != -1 || prog.Insns() != nil {
		t.Errorf("Program after Close = %+v, FD %d, %d insn bytes", got, prog.FD(), len(prog.Insns()))
	}
	if got := mapMetaOf(counts); got != (mapMeta{}) || counts.FD() != -1 || counts.IsPinned() ||
		counts.IsInternal() || counts.PinPath() != "" || counts.InitialValue() != nil {
		t.Errorf("Map after Close = %+v, FD %d, pinned %v, internal %v, pin path %q",
			got, counts.FD(), counts.IsPinned(), counts.IsInternal(), counts.PinPath())
	}
}

// TestNilReceivers checks that nil wrappers do not panic: Close, Disconnect
// and Destroy are no-ops, accessors return zero values, and the other methods pass nil
// to the core, which rejects it with its own error.
func TestNilReceivers(t *testing.T) {
	t.Parallel()

	var (
		obj  *bpf.Object
		prog *bpf.Program
		m    *bpf.Map
		link *bpf.Link
	)
	if err := obj.Close(); err != nil {
		t.Errorf("nil Object Close = %v", err)
	}
	link.Disconnect()
	link.Destroy()
	if obj.Name() != "" || obj.Programs() != nil || obj.Program("x") != nil || obj.BTF() != nil ||
		prog.FD() != -1 || m.FD() != -1 || m.PinPath() != "" || m.IsInternal() || m.InitialValue() != nil ||
		link.FD() != -1 || link.PinPath() != "" {
		t.Error("a nil wrapper accessor returned a non-zero value")
	}

	for name, err := range map[string]error{
		"Object.Load":          obj.Load(),
		"Program.Pin":          prog.Pin("/sys/fs/bpf/x"),
		"Map.Lookup":           m.Lookup(nil, nil, 0),
		"Map.Update":           m.Update(nil, nil, 0),
		"Map.Delete":           m.Delete(nil, 0),
		"Map.LookupAndDelete":  m.LookupAndDelete(nil, nil, 0),
		"Map.NextKey":          m.NextKey(nil, nil),
		"Map.SetInitialValue":  m.SetInitialValue(nil),
		"Link.UpdateProgram":   link.UpdateProgram(prog),
		"Program.AttachKprobe": func() error { _, err := prog.AttachKprobe(false, "x"); return err }(),
		"Program.AttachCgroup": func() error { _, err := prog.AttachCgroup(0); return err }(),
		"Program.AttachXDP":    func() error { _, err := prog.AttachXDP(1); return err }(),
		"Program.AttachIter":   func() error { _, err := prog.AttachIter(nil); return err }(),
		"Program.AttachFreplace": func() error {
			_, err := prog.AttachFreplace(3, "xdp_pass")
			return err
		}(),
		"Program.SetAttachTarget": prog.SetAttachTarget(3, "xdp_pass"),
	} {
		var coreErr *libbpf.Error
		if !errors.As(err, &coreErr) || coreErr.Errno != syscall.EINVAL {
			t.Errorf("%s = %v, want the core EINVAL error", name, err)
		}
	}
}
