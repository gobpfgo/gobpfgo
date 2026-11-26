// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/golbpfgo/golbpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

type openFixture struct {
	ObjectName string `json:"object_name"`
	Maps       []struct {
		Name           string `json:"name"`
		Type           uint32 `json:"type"`
		KeySize        uint32 `json:"key_size"`
		ValueSize      uint32 `json:"value_size"`
		MaxEntries     uint32 `json:"max_entries"`
		MapFlags       uint32 `json:"map_flags"`
		BtfKeyTypeID   uint32 `json:"btf_key_type_id"`
		BtfValueTypeID uint32 `json:"btf_value_type_id"`
		PinPath        string `json:"pin_path"`
	} `json:"maps"`
	Programs []struct {
		Name               string `json:"name"`
		Type               uint32 `json:"type"`
		ExpectedAttachType uint32 `json:"expected_attach_type"`
		Section            string `json:"section"`
		InsnCnt            int    `json:"insn_cnt"`
	} `json:"programs"`
}

func loadOpenFixture(t *testing.T) openFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/open.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f openFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

type loadFixture struct {
	ObjectName string `json:"object_name"`
	Maps       []struct {
		Name           string `json:"name"`
		Type           uint32 `json:"type"`
		ID             uint32 `json:"id"`
		KeySize        uint32 `json:"key_size"`
		ValueSize      uint32 `json:"value_size"`
		MaxEntries     uint32 `json:"max_entries"`
		MapFlags       uint32 `json:"map_flags"`
		BtfKeyTypeID   uint32 `json:"btf_key_type_id"`
		BtfValueTypeID uint32 `json:"btf_value_type_id"`
	} `json:"maps"`
	Programs []struct {
		Name          string `json:"name"`
		Type          uint32 `json:"type"`
		ID            uint32 `json:"id"`
		Section       string `json:"section"`
		InsnCnt       int    `json:"insn_cnt"`
		XlatedInsnCnt int    `json:"xlated_insn_cnt"`
		JitedProgLen  uint32 `json:"jited_prog_len"`
	} `json:"programs"`
}

func loadLoadFixture(t *testing.T) loadFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/load.json")
	if err != nil {
		t.Fatalf("read load fixture: %v", err)
	}
	var f loadFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse load fixture: %v", err)
	}
	return f
}

func TestBpfObjectOpenKprobe(t *testing.T) {
	f := loadOpenFixture(t)

	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Fatalf("object name = %q, want %q", got, f.ObjectName)
	}
	if len(f.Maps) != 1 {
		t.Fatalf("fixture has %d maps, want 1", len(f.Maps))
	}
	if len(f.Programs) != 1 {
		t.Fatalf("fixture has %d programs, want 1", len(f.Programs))
	}

	m := BpfObjectNextMap(obj, nil)
	if m == nil {
		t.Fatal("no map in object")
	}
	wantMap := f.Maps[0]
	if got := BpfMapName(m); got != wantMap.Name {
		t.Fatalf("map name = %q, want %q", got, wantMap.Name)
	}
	if got := uint32(BpfMapTypeOf(m)); got != wantMap.Type {
		t.Fatalf("map type = %d, want %d", got, wantMap.Type)
	}
	if got := BpfMapKeySize(m); got != wantMap.KeySize {
		t.Fatalf("key size = %d, want %d", got, wantMap.KeySize)
	}
	if got := BpfMapValueSize(m); got != wantMap.ValueSize {
		t.Fatalf("value size = %d, want %d", got, wantMap.ValueSize)
	}
	if got := BpfMapMaxEntries(m); got != wantMap.MaxEntries {
		t.Fatalf("max entries = %d, want %d", got, wantMap.MaxEntries)
	}
	if got := BpfMapMapFlags(m); got != wantMap.MapFlags {
		t.Fatalf("map flags = %d, want %d", got, wantMap.MapFlags)
	}
	if got := BpfMapBtfKeyTypeID(m); got != wantMap.BtfKeyTypeID {
		t.Fatalf("btf key type id = %d, want %d", got, wantMap.BtfKeyTypeID)
	}
	if got := BpfMapBtfValueTypeID(m); got != wantMap.BtfValueTypeID {
		t.Fatalf("btf value type id = %d, want %d", got, wantMap.BtfValueTypeID)
	}
	if got := BpfMapPinPath(m); got != wantMap.PinPath {
		t.Fatalf("pin path = %q, want %q", got, wantMap.PinPath)
	}
	if BpfObjectNextMap(obj, m) != nil {
		t.Fatal("extra map in object")
	}
	if BpfObjectFindMapByName(obj, wantMap.Name) != m {
		t.Fatal("FindMapByName did not return the map")
	}

	p := BpfObjectNextProgram(obj, nil)
	if p == nil {
		t.Fatal("no program in object")
	}
	wantProg := f.Programs[0]
	if got := BpfProgramName(p); got != wantProg.Name {
		t.Fatalf("program name = %q, want %q", got, wantProg.Name)
	}
	if got := uint32(BpfProgramTypeOf(p)); got != wantProg.Type {
		t.Fatalf("program type = %d, want %d", got, wantProg.Type)
	}
	if got := uint32(BpfProgramExpectedAttachType(p)); got != wantProg.ExpectedAttachType {
		t.Fatalf("expected attach type = %d, want %d", got, wantProg.ExpectedAttachType)
	}
	if got := BpfProgramSectionName(p); got != wantProg.Section {
		t.Fatalf("section = %q, want %q", got, wantProg.Section)
	}
	if got := BpfProgramInsnCnt(p); got != wantProg.InsnCnt {
		t.Fatalf("insn count = %d, want %d", got, wantProg.InsnCnt)
	}
	if BpfObjectNextProgram(obj, p) != nil {
		t.Fatal("extra program in object")
	}
	if BpfObjectFindProgramByName(obj, wantProg.Name) != p {
		t.Fatal("FindProgramByName did not return the program")
	}
}

func TestBpfObjectLoad(t *testing.T) {
	f := loadLoadFixture(t)

	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}
	defer BpfObjectClose(obj)

	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Fatalf("object name = %q, want %q", got, f.ObjectName)
	}
	if len(f.Maps) != 1 || len(f.Programs) != 1 {
		t.Fatalf("fixture has %d maps and %d programs", len(f.Maps), len(f.Programs))
	}

	m := BpfObjectNextMap(obj, nil)
	if m == nil || BpfMapFD(m) < 0 {
		t.Fatalf("map fd = %d", BpfMapFD(m))
	}
	wantMap := f.Maps[0]
	mi, err := sys.MapInfoByFD(BpfMapFD(m))
	if err != nil {
		t.Fatalf("MapInfoByFD: %v", err)
	}
	if mi.Name != wantMap.Name || mi.Type != wantMap.Type {
		t.Fatalf("map info = %+v, want name %q type %d", mi, wantMap.Name, wantMap.Type)
	}
	if mi.KeySize != wantMap.KeySize || mi.ValueSize != wantMap.ValueSize ||
		mi.MaxEntries != wantMap.MaxEntries || mi.MapFlags != wantMap.MapFlags {
		t.Fatalf("map geometry = %+v, want %+v", mi, wantMap)
	}
	if mi.BtfKeyTypeID != wantMap.BtfKeyTypeID || mi.BtfValueTypeID != wantMap.BtfValueTypeID {
		t.Fatalf("map BTF ids = %d/%d, want %d/%d",
			mi.BtfKeyTypeID, mi.BtfValueTypeID, wantMap.BtfKeyTypeID, wantMap.BtfValueTypeID)
	}
	if mi.ID == 0 || m.id != mi.ID {
		t.Fatalf("map id = %d, info id = %d", m.id, mi.ID)
	}

	p := BpfObjectNextProgram(obj, nil)
	if p == nil || BpfProgramFD(p) < 0 {
		t.Fatalf("program fd = %d", BpfProgramFD(p))
	}
	wantProg := f.Programs[0]
	if got := BpfProgramSectionName(p); got != wantProg.Section {
		t.Fatalf("section = %q, want %q", got, wantProg.Section)
	}
	if got := BpfProgramInsnCnt(p); got != wantProg.InsnCnt {
		t.Fatalf("insn count = %d, want %d", got, wantProg.InsnCnt)
	}
	pi, err := sys.ProgInfoByFD(BpfProgramFD(p))
	if err != nil {
		t.Fatalf("ProgInfoByFD: %v", err)
	}
	if pi.Name != wantProg.Name || pi.Type != wantProg.Type {
		t.Fatalf("program info = %+v, want name %q type %d", pi, wantProg.Name, wantProg.Type)
	}
	if got := int(pi.XlatedProgLen / 8); got != wantProg.XlatedInsnCnt {
		t.Fatalf("xlated insn count = %d, want %d", got, wantProg.XlatedInsnCnt)
	}
	if pi.JitedProgLen != wantProg.JitedProgLen {
		t.Fatalf("jited length = %d, want %d", pi.JitedProgLen, wantProg.JitedProgLen)
	}
	if pi.ID == 0 || p.id != pi.ID || p.xlatedInsnCnt != int(pi.XlatedProgLen/8) || p.jitedLen != pi.JitedProgLen {
		t.Fatalf("program id/lengths = %d/%d/%d, info = %d/%d/%d",
			p.id, p.xlatedInsnCnt, p.jitedLen, pi.ID, pi.XlatedProgLen/8, pi.JitedProgLen)
	}

	if err := BpfObjectLoad(obj); err == nil {
		t.Fatal("second load succeeded")
	}
}

func TestBpfObjectOpenMem(t *testing.T) {
	data, err := os.ReadFile("../testdata/progs/kprobe.bpf.o")
	if err != nil {
		t.Fatalf("read object: %v", err)
	}
	name := "kprobe"
	obj, err := BpfObjectOpenMem(data, &BpfObjectOpenOpts{ObjectName: &name})
	if err != nil {
		t.Fatalf("BpfObjectOpenMem: %v", err)
	}
	defer BpfObjectClose(obj)

	if got := BpfObjectName(obj); got != name {
		t.Fatalf("object name = %q, want %q", got, name)
	}
}

func TestBpfObjectOpenMissing(t *testing.T) {
	_, err := BpfObjectOpenFile("../testdata/progs/missing.bpf.o", nil)
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("got %v, want ENOENT", err)
	}
}

func TestBpfObjectOpenInvalid(t *testing.T) {
	_, err := BpfObjectOpenMem([]byte{1, 2, 3}, nil)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("got %v, want EINVAL", err)
	}

	bad := NewBpfObjectOpenOpts()
	bad.Sz = 1
	_, err = BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", bad)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("got %v, want EINVAL for bad opts", err)
	}
}
