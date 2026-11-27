// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const globalDataObject = "../testdata/progs/global_data.bpf.o"

// Values of the initializers in global_data.bpf.c.
const (
	globalDataMagic   = 0xfeedfacecafebeef
	globalDataCounter = 100
	globalDataStatic  = 7
	globalRodataPad   = 0x11111111
	globalRodataValue = 0x0123456789abcdef
)

// globalDataImages returns the expected initial value of each global data
// map, keyed by section: the section bytes, or zeroes for .bss.
func globalDataImages() map[string][]byte {
	data := make([]byte, 24)
	binary.NativeEndian.PutUint64(data[0:], globalDataMagic)
	binary.NativeEndian.PutUint64(data[8:], globalDataCounter)
	binary.NativeEndian.PutUint64(data[16:], globalDataStatic)

	rodata := make([]byte, 16)
	binary.NativeEndian.PutUint32(rodata[0:], globalRodataPad)
	binary.NativeEndian.PutUint64(rodata[8:], globalRodataValue)

	return map[string][]byte{
		".data":   data,
		".rodata": rodata,
		".bss":    make([]byte, 16),
	}
}

// globalDataVars lists every variable of the object with its section and the
// offset its declaration order and alignment give it.
var globalDataVars = []struct {
	section  string
	variable string
	offset   uint32
}{
	{".data", "data_magic", 0},
	{".data", "data_counter", 8},
	{".data", "data_static", 16},
	{".rodata", "rodata_pad", 0},
	{".rodata", "rodata_value", 8},
	{".bss", "bss_counter", 0},
	{".bss", "bss_seen", 8},
}

func openGlobalData(t *testing.T) *BpfObject {
	t.Helper()

	obj, err := BpfObjectOpenFile(globalDataObject, nil)
	if err != nil {
		t.Fatalf("open %s: %v", globalDataObject, err)
	}
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// globalDataMap returns the global data map of section, found by section name.
func globalDataMap(t *testing.T, obj *BpfObject, section string) *BpfMap {
	t.Helper()

	m := BpfObjectFindMapByName(obj, section)
	if m == nil {
		t.Fatalf("no map for section %s", section)
	}
	return m
}

// datasecVarOffset returns the offset of variable in the section's DATASEC.
func datasecVarOffset(t *testing.T, spec *btf.Spec, section, variable string) uint32 {
	t.Helper()

	ds := spec.Find(section, btf.KindDatasec)
	if ds == nil {
		t.Fatalf("no DATASEC %s", section)
	}
	for _, vsi := range ds.DataSec {
		v, err := spec.TypeByID(vsi.Type)
		if err != nil {
			t.Fatalf("DATASEC %s: %v", section, err)
		}
		if v.Name == variable {
			return vsi.Offset
		}
	}
	t.Fatalf("DATASEC %s has no variable %s", section, variable)
	return 0
}

// TestGlobalDataOpen compares the internal maps and the program with what
// libbpf reports after opening the same object.
func TestGlobalDataOpen(t *testing.T) {
	f := loadOpenFixture(t, "open-global-data.json")
	obj := openGlobalData(t)

	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Fatalf("object name = %q, want %q", got, f.ObjectName)
	}

	m := BpfObjectNextMap(obj, nil)
	for i, want := range f.Maps {
		if m == nil {
			t.Fatalf("object has %d maps, want %d", i, len(f.Maps))
		}
		got := openFixtureMap{
			Name:           BpfMapName(m),
			Type:           uint32(BpfMapTypeOf(m)),
			KeySize:        BpfMapKeySize(m),
			ValueSize:      BpfMapValueSize(m),
			MaxEntries:     BpfMapMaxEntries(m),
			MapFlags:       BpfMapMapFlags(m),
			BtfKeyTypeID:   BpfMapBtfKeyTypeID(m),
			BtfValueTypeID: BpfMapBtfValueTypeID(m),
			PinPath:        BpfMapPinPath(m),
		}
		if got != want {
			t.Errorf("map %d = %+v, want %+v", i, got, want)
		}
		if !BpfMapIsInternal(m) {
			t.Errorf("map %s is not internal", want.Name)
		}
		if BpfObjectFindMapByName(obj, want.Name) != m {
			t.Errorf("FindMapByName(%q) did not return map %d", want.Name, i)
		}
		m = BpfObjectNextMap(obj, m)
	}
	if m != nil {
		t.Fatalf("extra map %s", BpfMapName(m))
	}

	p := BpfObjectNextProgram(obj, nil)
	if len(f.Programs) != 1 || p == nil {
		t.Fatalf("fixture has %d programs, object first program %v", len(f.Programs), p)
	}
	want := f.Programs[0]
	if BpfProgramName(p) != want.Name || BpfProgramSectionName(p) != want.Section ||
		uint32(BpfProgramTypeOf(p)) != want.Type || BpfProgramInsnCnt(p) != want.InsnCnt {
		t.Fatalf("program = %s %s type %d insns %d, want %+v", BpfProgramName(p),
			BpfProgramSectionName(p), BpfProgramTypeOf(p), BpfProgramInsnCnt(p), want)
	}
	checkOpenBTF(t, obj, f)
}

// TestGlobalDataFindBySection finds each internal map by its section name and
// by its kernel name, and leaves unknown sections unmatched.
func TestGlobalDataFindBySection(t *testing.T) {
	obj := openGlobalData(t)

	for _, tc := range []struct{ section, name string }{
		{".data", "global_d.data"},
		{".rodata", "global_d.rodata"},
		{".bss", "global_d.bss"},
	} {
		m := globalDataMap(t, obj, tc.section)
		if got := BpfMapName(m); got != tc.name {
			t.Errorf("%s map name = %q, want %q", tc.section, got, tc.name)
		}
		if BpfObjectFindMapByName(obj, tc.name) != m {
			t.Errorf("FindMapByName(%q) did not return the %s map", tc.name, tc.section)
		}
	}
	for _, name := range []string{".maps", ".kconfig", "data", "license"} {
		if m := BpfObjectFindMapByName(obj, name); m != nil {
			t.Errorf("FindMapByName(%q) = %s, want nil", name, BpfMapName(m))
		}
	}
}

// TestGlobalDataInitialValue checks that each map starts with its section
// bytes, and .bss with zeroes, sized to the map value.
func TestGlobalDataInitialValue(t *testing.T) {
	obj := openGlobalData(t)

	for section, want := range globalDataImages() {
		m := globalDataMap(t, obj, section)
		if len(m.initialValue) != int(BpfMapValueSize(m)) {
			t.Errorf("%s initial value has %d bytes, value size %d", section, len(m.initialValue), BpfMapValueSize(m))
		}
		if !bytes.Equal(m.initialValue, want) {
			t.Errorf("%s initial value = %x, want %x", section, m.initialValue, want)
		}
	}
}

// TestGlobalDataDatasecOffsets checks the DATASEC sizes and variable offsets
// after open: each DATASEC is as large as its section and map value, each
// variable sits at its section offset, and the offsets are sorted.
func TestGlobalDataDatasecOffsets(t *testing.T) {
	obj := openGlobalData(t)

	for _, v := range globalDataVars {
		if got := datasecVarOffset(t, obj.btf, v.section, v.variable); got != v.offset {
			t.Errorf("%s %s offset = %d, want %d", v.section, v.variable, got, v.offset)
		}
	}

	for _, s := range obj.elf.Sections {
		if dataSectionType(&s) == libbpfMapUnspec {
			continue
		}
		ds := obj.btf.Find(s.Name, btf.KindDatasec)
		m := globalDataMap(t, obj, s.Name)
		if ds == nil || uint64(ds.SizeOrType) != s.Size || BpfMapValueSize(m) != ds.SizeOrType {
			t.Errorf("%s: DATASEC %+v, section size %d, value size %d", s.Name, ds, s.Size, BpfMapValueSize(m))
			continue
		}
		if BpfMapBtfValueTypeID(m) != ds.ID {
			t.Errorf("%s: value type id %d, want DATASEC %d", s.Name, BpfMapBtfValueTypeID(m), ds.ID)
		}
		for i := 1; i < len(ds.DataSec); i++ {
			if ds.DataSec[i].Offset < ds.DataSec[i-1].Offset {
				t.Errorf("%s: variables not sorted by offset: %+v", s.Name, ds.DataSec)
			}
		}
	}

	// The global variables take their offsets from their ELF symbols.
	for _, sym := range obj.elf.Symbols {
		if sym.Type != elf.STT_OBJECT || sym.Bind != elf.STB_GLOBAL || sym.Section == "license" {
			continue
		}
		if got := datasecVarOffset(t, obj.btf, sym.Section, sym.Name); uint64(got) != sym.Value {
			t.Errorf("%s offset = %d, symbol value %d", sym.Name, got, sym.Value)
		}
	}
}

// TestGlobalDataRelocation relocates handle_global with stand-in descriptors
// and checks every ld_imm64 that references a variable: it loads the map value
// of the variable's section, with the variable offset in the second immediate.
// The data_static reference goes through the .data section symbol and carries
// its offset in the instruction immediate.
func TestGlobalDataRelocation(t *testing.T) {
	obj := openGlobalData(t)
	for i, m := range obj.maps {
		m.fd = 100 + i
	}
	p := BpfObjectFindProgramByName(obj, "handle_global")
	if p == nil {
		t.Fatal("program handle_global not found")
	}

	insns := append([]byte(nil), p.insns...)
	if err := relocateProgram(obj, p, insns); err != nil {
		t.Fatalf("relocateProgram: %v", err)
	}

	want := []struct {
		insn     int
		section  string
		variable string
	}{
		{1, ".data", "data_counter"},
		{5, ".bss", "bss_counter"},
		{8, ".data", "data_static"},
		{13, ".rodata", "rodata_value"},
		{16, ".bss", "bss_seen"},
	}
	if len(p.relocs) != len(want) {
		t.Fatalf("program has %d relocations, want %d", len(p.relocs), len(want))
	}

	for i, w := range want {
		off := w.insn * bpfInsnLength
		if int(p.relocs[i].Offset) != off {
			t.Fatalf("relocation %d at %d, want %d", i, p.relocs[i].Offset, off)
		}

		orig := decodeBpfInsn(p.insns[off:])
		got := decodeBpfInsn(insns[off:])
		next := decodeBpfInsn(insns[off+bpfInsnLength:])
		m := globalDataMap(t, obj, w.section)
		wantOff := datasecVarOffset(t, obj.btf, w.section, w.variable)

		if got.Code != bpfLD|bpfImm|bpfSizeDW || got.Dst != orig.Dst || got.Src != bpfPseudoMapValue {
			t.Errorf("%s: insn %+v, want ld_imm64 r%d with BPF_PSEUDO_MAP_VALUE", w.variable, got, orig.Dst)
		}
		if got.Imm != int32(m.fd) || next.Imm != int32(wantOff) {
			t.Errorf("%s: imm = %d/%d, want fd %d and offset %d", w.variable, got.Imm, next.Imm, m.fd, wantOff)
		}
	}

	// The static variable reference is the section symbol plus the
	// instruction immediate.
	rel := p.relocs[2]
	sym := obj.elf.Symbols[rel.SymbolIndex]
	if sym.Type != elf.STT_SECTION || sym.Section != ".data" || sym.Value != 0 {
		t.Fatalf("data_static relocation symbol = %+v, want the .data section symbol", sym)
	}
	if imm := decodeBpfInsn(p.insns[rel.Offset:]).Imm; uint32(imm) != datasecVarOffset(t, obj.btf, ".data", "data_static") {
		t.Fatalf("data_static instruction immediate = %d", imm)
	}
}

// TestMapRelocation checks that a .maps reference still becomes a
// BPF_PSEUDO_MAP_FD load of the map descriptor.
func TestMapRelocation(t *testing.T) {
	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer BpfObjectClose(obj)

	m := BpfObjectFindMapByName(obj, "counts")
	p := BpfObjectFindProgramByName(obj, "handle_open")
	if m == nil || p == nil || len(p.relocs) != 1 {
		t.Fatalf("map %v, program %v", m, p)
	}
	m.fd = 42

	insns := append([]byte(nil), p.insns...)
	if err := relocateProgram(obj, p, insns); err != nil {
		t.Fatalf("relocateProgram: %v", err)
	}
	off := int(p.relocs[0].Offset)
	got := decodeBpfInsn(insns[off:])
	next := decodeBpfInsn(insns[off+bpfInsnLength:])
	if got.Src != bpfPseudoMapFD || got.Imm != 42 || next.Imm != 0 {
		t.Fatalf("insn %+v next %+v, want BPF_PSEUDO_MAP_FD with fd 42", got, next)
	}
}

// TestGlobalDataRelocationErrors rejects a data reference without its map and
// a relocation that does not point at an ld_imm64 instruction.
func TestGlobalDataRelocationErrors(t *testing.T) {
	obj := openGlobalData(t)
	p := BpfObjectFindProgramByName(obj, "handle_global")
	insns := append([]byte(nil), p.insns...)

	maps := obj.maps
	obj.maps = nil
	err := relocateProgram(obj, p, insns)
	if err == nil || !strings.Contains(err.Error(), "data relo failed to find map") {
		t.Fatalf("relocate without maps: %v", err)
	}
	obj.maps = maps

	for i, m := range obj.maps {
		m.fd = 100 + i
	}
	insns[p.relocs[0].Offset] = bpfALU64
	err = relocateProgram(obj, p, insns)
	if err == nil || !strings.Contains(err.Error(), "invalid relo") {
		t.Fatalf("relocate a non-ld_imm64 instruction: %v", err)
	}
}

func TestInternalMapName(t *testing.T) {
	for _, tc := range []struct{ obj, section, want string }{
		{"global_data", ".data", "global_d.data"},
		{"global_data", ".rodata", "global_d.rodata"},
		{"global_data", ".bss", "global_d.bss"},
		{"my_object_name", ".rodata", "my_objec.rodata"},
		{"my_object_name", ".kconfig", "my_obje.kconfig"},
		{"obj", ".data", "obj.data"},
		{"my-obj", ".bss", "my_obj.bss"},
		{"obj", ".rodata.abracadabra", ".rodata.abracad"},
		{"obj", ".data.custom", ".data.custom"},
		{"obj", ".rodata.str1.1", ".rodata.str1.1"},
	} {
		if got := internalMapName(tc.obj, tc.section); got != tc.want {
			t.Errorf("internalMapName(%q, %q) = %q, want %q", tc.obj, tc.section, got, tc.want)
		}
	}
}

// TestBpfMapNameCustomSection checks that a custom data section map is named
// after its whole section name, which its kernel name may cut, while the
// standard sections use the kernel name.
func TestBpfMapNameCustomSection(t *testing.T) {
	for _, tc := range []struct {
		typ     libbpfMapType
		section string
		want    string
	}{
		{libbpfMapData, ".data", "obj.data"},
		{libbpfMapRodata, ".rodata", "obj.rodata"},
		{libbpfMapBss, ".bss", "obj.bss"},
		{libbpfMapData, ".data.custom", ".data.custom"},
		{libbpfMapRodata, ".rodata.abracadabra", ".rodata.abracadabra"},
		{libbpfMapRodata, ".data.rel.ro", ".data.rel.ro"},
	} {
		m := &BpfMap{name: internalMapName("obj", tc.section), realName: tc.section, libbpfType: tc.typ}
		if got := BpfMapName(m); got != tc.want {
			t.Errorf("BpfMapName(%s) = %q, want %q", tc.section, got, tc.want)
		}
	}
}

func TestDataSectionType(t *testing.T) {
	const (
		progbits = elf.SHT_PROGBITS
		nobits   = elf.SHT_NOBITS
		wa       = elf.SHF_WRITE | elf.SHF_ALLOC
		ax       = elf.SHF_ALLOC | elf.SHF_EXECINSTR
	)
	for _, tc := range []struct {
		name  string
		typ   elf.SectionType
		flags elf.SectionFlag
		size  uint64
		want  libbpfMapType
	}{
		{".data", progbits, wa, 8, libbpfMapData},
		{".data.custom", progbits, wa, 8, libbpfMapData},
		{".data.rel.ro", progbits, wa, 8, libbpfMapRodata},
		{".data.rel.ro.local", progbits, wa, 8, libbpfMapRodata},
		{".rodata", progbits, elf.SHF_ALLOC, 8, libbpfMapRodata},
		{".rodata.str1.1", progbits, elf.SHF_ALLOC, 8, libbpfMapRodata},
		{".bss", nobits, wa, 8, libbpfMapBss},
		{".bss.custom", nobits, wa, 8, libbpfMapBss},
		{".data", progbits, wa, 0, libbpfMapUnspec},
		{".data", progbits, ax, 8, libbpfMapUnspec},
		{".datax", progbits, wa, 8, libbpfMapUnspec},
		{".rodata", nobits, elf.SHF_ALLOC, 8, libbpfMapUnspec},
		{".bss", progbits, wa, 8, libbpfMapUnspec},
		{".maps", progbits, wa, 8, libbpfMapUnspec},
	} {
		s := &objelf.Section{Name: tc.name, Type: tc.typ, Flags: tc.flags, Size: tc.size}
		if got := dataSectionType(s); got != tc.want {
			t.Errorf("dataSectionType(%s %v %v size %d) = %d, want %d", tc.name, tc.typ, tc.flags, tc.size, got, tc.want)
		}
	}
}

// TestGlobalDataMmapable checks that a global data map is mmapable only while
// its DATASEC has a variable visible outside the object.
func TestGlobalDataMmapable(t *testing.T) {
	obj := openGlobalData(t)
	m := globalDataMap(t, obj, ".rodata")
	if !mapIsMmapable(obj.btf, m) {
		t.Fatal(".rodata with global variables is not mmapable")
	}

	if err := obj.btf.FixupDatasecHiddenVars(map[string]bool{"rodata_pad": true, "rodata_value": true}); err != nil {
		t.Fatalf("FixupDatasecHiddenVars: %v", err)
	}
	if mapIsMmapable(obj.btf, m) {
		t.Fatal(".rodata with only hidden variables is mmapable")
	}
	if mapIsMmapable(obj.btf, &BpfMap{realName: ".data"}) {
		t.Fatal("map without a BTF value type is mmapable")
	}
}

// lookupGlobal reads the only element of a loaded global data map.
func lookupGlobal(t *testing.T, m *BpfMap) []byte {
	t.Helper()

	value := make([]byte, BpfMapValueSize(m))
	if err := BpfMapLookupElem(m, make([]byte, internalMapKeySize), value, 0); err != nil {
		t.Fatalf("lookup %s: %v", BpfMapName(m), err)
	}
	return value
}

// TestGlobalDataLoad loads the object, checks the kernel maps against the
// libbpf open fixture and their initial contents, checks that .rodata is
// frozen, then attaches handle_global to do_sys_openat2, opens a file and
// reads back what the program wrote. It needs root or CAP_BPF and skips with
// EPERM or EACCES.
func TestGlobalDataLoad(t *testing.T) {
	f := loadOpenFixture(t, "open-global-data.json")
	obj := loadTestObject(t, globalDataObject)
	defer BpfObjectClose(obj)

	images := globalDataImages()
	for _, want := range f.Maps {
		m := BpfObjectFindMapByName(obj, want.Name)
		if m == nil || BpfMapFD(m) < 0 {
			t.Fatalf("map %s not loaded", want.Name)
		}
		info, err := sys.MapInfoByFD(BpfMapFD(m))
		if err != nil {
			t.Fatalf("MapInfoByFD(%s): %v", want.Name, err)
		}
		if info.Name != want.Name || info.Type != want.Type || info.KeySize != want.KeySize ||
			info.ValueSize != want.ValueSize || info.MaxEntries != want.MaxEntries || info.MapFlags != want.MapFlags ||
			info.BtfKeyTypeID != want.BtfKeyTypeID || info.BtfValueTypeID != want.BtfValueTypeID {
			t.Errorf("map info = %+v, want %+v", info, want)
		}
		if got := lookupGlobal(t, m); !bytes.Equal(got, images[m.realName]) {
			t.Errorf("%s initial contents = %x, want %x", m.realName, got, images[m.realName])
		}
	}

	rodata := globalDataMap(t, obj, ".rodata")
	err := sys.MapUpdateElem(BpfMapFD(rodata), make([]byte, internalMapKeySize), images[".rodata"], 0)
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("update frozen .rodata: %v, want EPERM", err)
	}

	prog := BpfObjectFindProgramByName(obj, "handle_global")
	link, err := BpfProgramAttachKprobe(prog, false, "do_sys_openat2")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("attach kprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	triggerOpen(t)

	data := lookupGlobal(t, globalDataMap(t, obj, ".data"))
	bss := lookupGlobal(t, globalDataMap(t, obj, ".bss"))
	u64 := binary.NativeEndian.Uint64

	if got := u64(data[0:]); got != globalDataMagic {
		t.Errorf("data_magic = %#x, want %#x", got, uint64(globalDataMagic))
	}
	if got := u64(data[8:]); got <= globalDataCounter {
		t.Errorf("data_counter = %d, want more than %d", got, globalDataCounter)
	}
	if got := u64(data[16:]); got <= globalDataStatic {
		t.Errorf("data_static = %d, want more than %d", got, globalDataStatic)
	}
	if got := u64(bss[0:]); got == 0 {
		t.Error("bss_counter = 0, want the program to count the open")
	}
	if got := u64(bss[8:]); got != globalRodataValue {
		t.Errorf("bss_seen = %#x, want the .rodata value %#x", got, uint64(globalRodataValue))
	}
	if got := lookupGlobal(t, rodata); !bytes.Equal(got, images[".rodata"]) {
		t.Errorf(".rodata = %x, want %x", got, images[".rodata"])
	}
}
