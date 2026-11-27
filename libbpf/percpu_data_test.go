// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const (
	percpuObject       = "../testdata/progs/percpu.bpf.o"
	percpuUnusedObject = "../testdata/progs/percpu_unused.bpf.o"
)

// Values of the initializers in percpu.bpf.c.
const (
	percpuCounterInit = 100
	percpuLastInit    = 0x5eed
	percpuCustomInit  = 0xc0ffee
)

// Values of the .percpu initializers in percpu_unused.bpf.c.
const (
	percpuUnusedCounterInit = 7
	percpuUnusedLastInit    = 0xfeed
)

// percpuSections lists the per-CPU data sections of percpu.bpf.o in ELF order.
var percpuSections = []string{".percpu", ".percpu.custom"}

// percpuRefs are the global variable references of handle_percpu in
// percpu.bpf.o, in instruction order. The program reaches all of them.
var percpuRefs = []dataRef{
	{1, ".bss", "target_tid"},
	{9, ".percpu", "percpu_last"},
	{12, ".percpu", "percpu_counter"},
}

// percpuImage returns the initial value of the per-CPU data map of section:
// the section bytes, which are not a multiple of 8 long.
func percpuImage(section string) []byte {
	if section == ".percpu.custom" {
		custom := make([]byte, 4)
		binary.NativeEndian.PutUint32(custom, percpuCustomInit)
		return custom
	}
	percpu := make([]byte, 12)
	binary.NativeEndian.PutUint64(percpu[0:], percpuCounterInit)
	binary.NativeEndian.PutUint32(percpu[8:], percpuLastInit)
	return percpu
}

// percpuUnusedImage returns the initial value of the .percpu map of
// percpu_unused.bpf.o.
func percpuUnusedImage() []byte {
	image := make([]byte, 12)
	binary.NativeEndian.PutUint64(image[0:], percpuUnusedCounterInit)
	binary.NativeEndian.PutUint32(image[8:], percpuUnusedLastInit)
	return image
}

// percpuSlot returns image zero-padded to the kernel's 8-byte per-CPU stride,
// the value each CPU's slot holds after the initial update.
func percpuSlot(image []byte) []byte {
	slot := make([]byte, roundup(len(image), 8))
	copy(slot, image)
	return slot
}

// percpuSlots splits a per-CPU element value of a map with value size
// valueSize into one slot per CPU.
func percpuSlots(t *testing.T, value []byte, valueSize uint32) [][]byte {
	t.Helper()

	stride := roundup(int(valueSize), 8)
	if len(value)%stride != 0 {
		t.Fatalf("per-CPU value of %d bytes is not a multiple of the %d-byte stride", len(value), stride)
	}
	var slots [][]byte
	for off := 0; off < len(value); off += stride {
		slots = append(slots, value[off:off+stride])
	}
	return slots
}

// checkPercpuSlots requires every CPU slot of value to hold image, padded to
// the stride.
func checkPercpuSlots(t *testing.T, section string, value, image []byte) {
	t.Helper()

	want := percpuSlot(image)
	for cpu, slot := range percpuSlots(t, value, uint32(len(image))) {
		if !bytes.Equal(slot, want) {
			t.Errorf("%s CPU %d = %x, want %x", section, cpu, slot, want)
		}
	}
}

// openPercpu opens the per-CPU data fixture at path and closes it when the
// test ends.
func openPercpu(t *testing.T, path string) *BpfObject {
	t.Helper()

	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// testPossibleCPUs returns the number of possible CPUs, the slot count of a
// per-CPU element value.
func testPossibleCPUs(t *testing.T) int {
	t.Helper()

	n, err := LibbpfNumPossibleCpus()
	if err != nil {
		t.Fatalf("LibbpfNumPossibleCpus: %v", err)
	}
	return n
}

// lookupPercpu reads every possible CPU's value of the only element of a
// loaded per-CPU data map.
func lookupPercpu(t *testing.T, m *BpfMap) []byte {
	t.Helper()

	value := make([]byte, percpuValueSize(BpfMapValueSize(m), testPossibleCPUs(t)))
	if err := BpfMapLookupElem(m, make([]byte, internalMapKeySize), value, 0); err != nil {
		t.Fatalf("lookup %s: %v", BpfMapName(m), err)
	}
	return value
}

// TestPercpuDataOpen compares the maps, the program and the BTF with what
// libbpf reports after opening the same object, then checks what the fixture
// does not show: each per-CPU data map is internal, keeps its section name as
// both the user-visible and the kernel name, has the section's DATASEC as its
// value type, is not mmapable, starts with the section image and is set to be
// created by the load.
func TestPercpuDataOpen(t *testing.T) {
	obj := openPercpu(t, percpuObject)
	checkOpenFixture(t, obj, loadOpenFixture(t, "open-percpu.json"))

	for _, section := range percpuSections {
		m := globalDataMap(t, obj, section)
		ds := obj.btf.Find(section, btf.KindDatasec)
		if ds == nil {
			t.Fatalf("no DATASEC %s", section)
		}

		if !BpfMapIsInternal(m) || m.libbpfType != libbpfMapPercpu {
			t.Errorf("%s: internal %v, type %d, want a per-CPU data map", section, BpfMapIsInternal(m), m.libbpfType)
		}
		if m.name != section || m.realName != section || BpfMapName(m) != section {
			t.Errorf("%s: kernel name %q, real name %q, BpfMapName %q", section, m.name, m.realName, BpfMapName(m))
		}
		if BpfMapTypeOf(m) != BPF_MAP_TYPE_PERCPU_ARRAY || BpfMapKeySize(m) != internalMapKeySize ||
			BpfMapValueSize(m) != ds.SizeOrType || BpfMapMaxEntries(m) != 1 || BpfMapMapFlags(m) != 0 {
			t.Errorf("%s: type %d key %d value %d entries %d flags %#x, want a one-entry per-CPU array of %d bytes without flags",
				section, BpfMapTypeOf(m), BpfMapKeySize(m), BpfMapValueSize(m), BpfMapMaxEntries(m), BpfMapMapFlags(m), ds.SizeOrType)
		}
		if BpfMapBtfKeyTypeID(m) != 0 || BpfMapBtfValueTypeID(m) != ds.ID {
			t.Errorf("%s: BTF key %d value %d, want 0 and DATASEC %d", section, BpfMapBtfKeyTypeID(m), BpfMapBtfValueTypeID(m), ds.ID)
		}
		if mapIsMmapable(obj.btf, m) {
			t.Errorf("%s is mmapable", section)
		}
		if want := percpuImage(section); !bytes.Equal(m.initialValue, want) {
			t.Errorf("%s initial value = %x, want %x", section, m.initialValue, want)
		}
		if BpfObjectFindMapByName(obj, section) != m {
			t.Errorf("FindMapByName(%q) did not return the %s map", section, section)
		}
		if !m.autocreate {
			t.Errorf("%s: autocreate is clear after open", section)
		}
	}
}

// TestPercpuDataDatasec checks the per-CPU DATASEC sizes and the variable
// offsets taken from the ELF symbols.
func TestPercpuDataDatasec(t *testing.T) {
	obj := openPercpu(t, percpuObject)

	for _, v := range []struct {
		section  string
		variable string
		offset   uint32
	}{
		{".percpu", "percpu_counter", 0},
		{".percpu", "percpu_last", 8},
		{".percpu.custom", "percpu_custom", 0},
	} {
		if got := datasecVarOffset(t, obj.btf, v.section, v.variable); got != v.offset {
			t.Errorf("%s %s offset = %d, want %d", v.section, v.variable, got, v.offset)
		}
	}
	for _, section := range percpuSections {
		ds := obj.btf.Find(section, btf.KindDatasec)
		if size := uint32(len(percpuImage(section))); ds == nil || ds.SizeOrType != size {
			t.Errorf("DATASEC %s = %+v, want size %d", section, ds, size)
		}
	}
}

// TestPercpuDataRelocation checks that the program's per-CPU variable
// references load the .percpu map value at the variable offset, like a .data
// variable, and that the .bss reference still loads the .bss map.
func TestPercpuDataRelocation(t *testing.T) {
	obj := openPercpu(t, percpuObject)
	checkDataRelocations(t, obj, "handle_percpu", percpuRefs)
}

// TestPercpuInitialValue checks the element value that sets every CPU of a
// per-CPU data map: one copy of the section image per CPU, each zero-padded
// to the 8-byte stride, for the fixture's 12- and 4-byte sections.
func TestPercpuInitialValue(t *testing.T) {
	obj := openPercpu(t, percpuObject)

	for _, section := range percpuSections {
		m := globalDataMap(t, obj, section)
		for _, numCPU := range []int{1, 3, testPossibleCPUs(t)} {
			value := percpuInitialValue(m.initialValue, numCPU)
			if want := numCPU * roundup(int(BpfMapValueSize(m)), 8); len(value) != want {
				t.Fatalf("%s on %d CPUs: %d bytes, want %d", section, numCPU, len(value), want)
			}
			checkPercpuSlots(t, section, value, percpuImage(section))
		}
	}
}

// TestValidateMapOp checks the key and value buffer sizes an element
// operation accepts: the value size for most maps, and for a per-CPU map one
// padded value per possible CPU, or a single value with BPF_F_CPU or
// BPF_F_ALL_CPUS but not both.
func TestValidateMapOp(t *testing.T) {
	numCPU := testPossibleCPUs(t)
	array := &BpfMap{name: "array", mapType: BPF_MAP_TYPE_ARRAY, keySize: 4, valueSize: 12}
	percpu := &BpfMap{name: "percpu", mapType: BPF_MAP_TYPE_PERCPU_ARRAY, keySize: 4, valueSize: 12}
	hash := &BpfMap{name: "hash", mapType: BPF_MAP_TYPE_PERCPU_HASH, keySize: 8, valueSize: 8}
	const cpu1 = BPF_F_CPU | 1<<32

	for _, tc := range []struct {
		name      string
		m         *BpfMap
		keySize   int
		valueSize int
		flags     uint64
		ok        bool
	}{
		{"array value", array, 4, 12, 0, true},
		{"array padded value", array, 4, 16, 0, false},
		{"array per-CPU value", array, 4, numCPU * 16, 0, numCPU*16 == 12},
		{"array key", array, 8, 12, 0, false},
		{"per-CPU all values", percpu, 4, numCPU * 16, 0, true},
		{"per-CPU unpadded values", percpu, 4, numCPU * 12, 0, false},
		{"per-CPU single value without flags", percpu, 4, 12, 0, false},
		{"per-CPU key", percpu, 8, numCPU * 16, 0, false},
		{"per-CPU lock flag", percpu, 4, numCPU * 16, unix.BPF_F_LOCK, true},
		{"per-CPU one CPU", percpu, 4, 12, cpu1, true},
		{"per-CPU one CPU all values", percpu, 4, numCPU * 16, cpu1, false},
		{"per-CPU all CPUs", percpu, 4, 12, BPF_F_ALL_CPUS, true},
		{"per-CPU all CPUs padded value", percpu, 4, 16, BPF_F_ALL_CPUS, false},
		{"per-CPU both flags", percpu, 4, 12, BPF_F_CPU | BPF_F_ALL_CPUS, false},
		{"per-CPU hash all values", hash, 8, numCPU * 8, 0, true},
		{"per-CPU hash single value", hash, 8, 8, 0, false},
	} {
		err := validateMapOp(tc.m, tc.keySize, tc.valueSize, tc.flags)
		if (err == nil) != tc.ok {
			t.Errorf("%s: validateMapOp(key %d, value %d, flags %#x) = %v, want ok %v",
				tc.name, tc.keySize, tc.valueSize, tc.flags, err, tc.ok)
		}
	}
}

// TestPercpuDataPopulate creates each per-CPU data map of the fixture with the
// loader's create step, which writes the initial value, and reads every
// possible CPU's value back. The maps are created without BTF: a kernel
// without global per-CPU data rejects a per-CPU array whose BTF has no key
// type. That kernel never creates the maps in BpfObjectLoad, so this is the
// test that runs the population there. The maps must stay writable, because
// the loader does not freeze them. It needs root or CAP_BPF and skips with
// EPERM or EACCES.
func TestPercpuDataPopulate(t *testing.T) {
	obj := openPercpu(t, percpuObject)

	for _, section := range percpuSections {
		m := globalDataMap(t, obj, section)
		m.btfKeyTypeID, m.btfValueTypeID = 0, 0
		if err := createMap(m, 0); err != nil {
			skipIfNotPermitted(t, err)
			t.Fatalf("create %s: %v", section, err)
		}

		info, err := sys.MapInfoByFD(BpfMapFD(m))
		if err != nil {
			t.Fatalf("MapInfoByFD(%s): %v", section, err)
		}
		if info.Name != section || info.Type != uint32(BPF_MAP_TYPE_PERCPU_ARRAY) || info.KeySize != internalMapKeySize ||
			info.ValueSize != BpfMapValueSize(m) || info.MaxEntries != 1 || info.MapFlags != 0 {
			t.Errorf("%s map info = %+v", section, info)
		}

		image := percpuImage(section)
		checkPercpuSlots(t, section, lookupPercpu(t, m), image)

		update := percpuInitialValue(image, testPossibleCPUs(t))
		if err := sys.MapUpdateElem(BpfMapFD(m), make([]byte, internalMapKeySize), update, 0); err != nil {
			t.Errorf("update %s after populate: %v, want a writable map", section, err)
		}
	}
}

// skipIfNotPermitted skips the test when err is the kernel refusing bpf() to
// an unprivileged caller with EPERM or EACCES.
func skipIfNotPermitted(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("bpf() not permitted: %v", err)
	}
}

// TestPercpuDataProbeInsns checks the program of the per-CPU data feature
// probe byte for byte: the ld_imm64 of the map value at offset 0 into r1,
// the 64-bit load from r1 into r0, and exit.
func TestPercpuDataProbeInsns(t *testing.T) {
	want := []byte{
		0x18, 0x21, 0, 0, 0x34, 0x12, 0, 0, // r1 = map_value(fd 0x1234) ll
		0, 0, 0, 0, 0, 0, 0, 0, // second half, offset 0
		0x79, 0x10, 0, 0, 0, 0, 0, 0, // r0 = *(u64 *)(r1 + 0)
		0x95, 0, 0, 0, 0, 0, 0, 0, // exit
	}
	if got := percpuDataProbeInsns(0x1234); !bytes.Equal(got, want) {
		t.Errorf("probe program = %x, want %x", got, want)
	}
}

// TestPoisonMapLdimm64 checks the poisoned map reference: both halves of the
// ld_imm64 become the same helper call, with no registers or offset and the
// helper ID 2001000000 plus the map index, and the next instruction stays.
func TestPoisonMapLdimm64(t *testing.T) {
	insns := bytes.Repeat([]byte{0xff}, 3*bpfInsnLength)
	poisonMapLdimm64(insns, 3)

	call := []byte{0x85, 0, 0, 0, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(call[4:], 2001000003)
	want := slices.Concat(call, call, bytes.Repeat([]byte{0xff}, bpfInsnLength))
	if !bytes.Equal(insns, want) {
		t.Errorf("poisoned insns = %x, want %x", insns, want)
	}
}

// TestCreateMapsSkipsPercpuData checks the load's map gate on percpu.bpf.o.
// Without global per-CPU data the per-CPU data maps lose their autocreate
// flag and the .bss map keeps it; with the feature every map keeps it. The
// feature is asked about once per per-CPU data map and never for the other
// maps. createMaps then makes no bpf() call for a skipped map, which keeps
// descriptor -1.
func TestCreateMapsSkipsPercpuData(t *testing.T) {
	for _, supported := range []bool{false, true} {
		obj := openPercpu(t, percpuObject)
		asked := 0
		percpuData := func() bool {
			asked++
			return supported
		}

		for _, m := range obj.maps {
			gateMapAutocreate(m, percpuData)
			if want := supported || m.libbpfType != libbpfMapPercpu; m.autocreate != want {
				t.Errorf("percpu data %v: %s autocreate = %v, want %v", supported, BpfMapName(m), m.autocreate, want)
			}
		}
		if asked != len(percpuSections) {
			t.Errorf("percpu data %v: feature asked %d times, want %d", supported, asked, len(percpuSections))
		}
	}

	obj := openPercpu(t, percpuObject)
	percpuOnly := &BpfObject{maps: []*BpfMap{globalDataMap(t, obj, ".percpu"), globalDataMap(t, obj, ".percpu.custom")}}
	if err := createMaps(percpuOnly, -1, func() bool { return false }); err != nil {
		t.Fatalf("createMaps of the skipped maps: %v", err)
	}
	for _, m := range percpuOnly.maps {
		if m.autocreate || BpfMapFD(m) != -1 {
			t.Errorf("%s: autocreate %v, fd %d, want a skipped map with fd -1", BpfMapName(m), m.autocreate, BpfMapFD(m))
		}
	}
}

// TestPercpuDataPoison gates the maps of percpu.bpf.o as on a kernel without
// global per-CPU data and relocates handle_percpu with a stand-in descriptor
// for the .bss map. Both .percpu references become the poisoned calls of map
// 0, the .percpu map, and the .bss reference is still a map value load. A map
// that the load meant to create but that has no descriptor is still an
// error.
func TestPercpuDataPoison(t *testing.T) {
	obj := openPercpu(t, percpuObject)
	for _, m := range obj.maps {
		gateMapAutocreate(m, func() bool { return false })
	}
	bss := globalDataMap(t, obj, ".bss")
	bss.fd = 100

	p := BpfObjectFindProgramByName(obj, "handle_percpu")
	insns := slices.Clone(p.insns)
	if err := relocateProgram(obj, p, insns); err != nil {
		t.Fatalf("relocateProgram: %v", err)
	}

	poison := bpfInsn{Code: bpfJMP | bpfCall, Imm: 2001000000}
	for _, ref := range percpuRefs {
		off := ref.insn * bpfInsnLength
		first, second := decodeBpfInsn(insns[off:]), decodeBpfInsn(insns[off+bpfInsnLength:])
		if ref.section != ".percpu" {
			if first.Src != bpfPseudoMapValue || first.Imm != int32(bss.fd) {
				t.Errorf("%s: insn %d = %+v, want a value load of the .bss map", ref.variable, ref.insn, first)
			}
			continue
		}
		if first != poison || second != poison {
			t.Errorf("%s: insns %d and %d = %+v %+v, want two %+v", ref.variable, ref.insn, ref.insn+1, first, second, poison)
		}
	}

	bss.fd = -1
	err := relocateProgram(obj, p, slices.Clone(p.insns))
	if err == nil || !strings.Contains(err.Error(), "has no descriptor") {
		t.Errorf("relocate with an uncreated .bss map: %v, want a missing descriptor error", err)
	}
}

// TestMapCreateRetryAttr checks the attributes of the retry without BTF. A
// failed creation is retried when it sent a key or value type id. The retry
// sends no BTF descriptor or type ids and keeps every other field, and the
// map reports no BTF types afterwards.
func TestMapCreateRetryAttr(t *testing.T) {
	newAttr := func(key, value uint32) *sys.MapCreateAttr {
		attr := &sys.MapCreateAttr{
			MapType:        uint32(BPF_MAP_TYPE_PERCPU_ARRAY),
			KeySize:        4,
			ValueSize:      12,
			MaxEntries:     1,
			MapFlags:       unix.BPF_F_RDONLY_PROG,
			BtfFD:          7,
			BtfKeyTypeID:   key,
			BtfValueTypeID: value,
		}
		attr.SetMapName(".percpu")
		return attr
	}

	for _, tc := range []struct {
		key, value uint32
		retry      bool
	}{
		{0, 18, true},
		{1, 0, true},
		{1, 18, true},
		{0, 0, false},
	} {
		if got := mapCreateSendsBTF(newAttr(tc.key, tc.value)); got != tc.retry {
			t.Errorf("key %d value %d: retry %v, want %v", tc.key, tc.value, got, tc.retry)
		}
	}

	attr := newAttr(1, 18)
	want := *attr
	want.BtfFD, want.BtfKeyTypeID, want.BtfValueTypeID = 0, 0, 0
	m := &BpfMap{btfKeyTypeID: 1, btfValueTypeID: 18}
	clearMapBTF(attr, m)
	if *attr != want {
		t.Errorf("retry attr = %+v, want %+v", *attr, want)
	}
	if BpfMapBtfKeyTypeID(m) != 0 || BpfMapBtfValueTypeID(m) != 0 {
		t.Errorf("map BTF ids after the reset = %d/%d, want 0/0", BpfMapBtfKeyTypeID(m), BpfMapBtfValueTypeID(m))
	}
	if mapCreateSendsBTF(attr) {
		t.Error("the retry attr still sends BTF type ids")
	}
}
