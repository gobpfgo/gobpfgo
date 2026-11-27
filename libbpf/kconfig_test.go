// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const (
	kconfigObject      = "../testdata/progs/kconfig.bpf.o"
	kconfigTypesObject = "../testdata/progs/kconfig_types.bpf.o"

	// kconfigTest is the CONFIG_TEST value the tests pass at open.
	kconfigTest       = 42
	kconfigTestConfig = "CONFIG_TEST=42\n"
)

// kconfigOffsets are the .kconfig offsets of kconfig.bpf.o's externs: the
// 8-byte extern first, the 4-byte ones by name, the bool last.
var kconfigOffsets = map[string]int{
	"LINUX_GOBPFGO_UNKNOWN": 0,
	"CONFIG_TEST":           8,
	"LINUX_KERNEL_VERSION":  12,
	"LINUX_GOBPFGO_FLAG":    16,
}

// kconfigImage returns the .kconfig value libbpf builds for kconfig.bpf.o with
// CONFIG_TEST=42 on the running kernel. The weak unknown externs stay zero.
func kconfigImage() []byte {
	image := make([]byte, 17)
	binary.NativeEndian.PutUint32(image[kconfigOffsets["CONFIG_TEST"]:], kconfigTest)
	binary.NativeEndian.PutUint32(image[kconfigOffsets["LINUX_KERNEL_VERSION"]:], getKernelVersion())
	return image
}

// openKconfig opens path with kconfig as the extra config text, or with none
// when kconfig is nil.
func openKconfig(t *testing.T, path string, kconfig *string) *BpfObject {
	t.Helper()

	opts := NewBpfObjectOpenOpts()
	opts.Kconfig = kconfig
	obj, err := BpfObjectOpenFile(path, opts)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// kconfigMap returns the object's .kconfig map.
func kconfigMap(t *testing.T, obj *BpfObject) *BpfMap {
	t.Helper()

	m := BpfObjectFindMapByName(obj, ".kconfig")
	if m == nil || m != obj.kconfigMap {
		t.Fatalf(".kconfig map = %v, object map %v", m, obj.kconfigMap)
	}
	return m
}

// checkOpenFixture compares the maps, the programs and the .kconfig DATASEC
// layout of obj with what libbpf reports after opening the same object.
func checkOpenFixture(t *testing.T, obj *BpfObject, f openFixture) {
	t.Helper()

	if got := BpfObjectName(obj); got != f.ObjectName {
		t.Errorf("object name = %q, want %q", got, f.ObjectName)
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
		m = BpfObjectNextMap(obj, m)
	}
	if m != nil {
		t.Errorf("extra map %s", BpfMapName(m))
	}

	p := BpfObjectNextProgram(obj, nil)
	for _, want := range f.Programs {
		if p == nil {
			t.Fatalf("missing program %s", want.Name)
		}
		if BpfProgramName(p) != want.Name || BpfProgramSectionName(p) != want.Section ||
			uint32(BpfProgramTypeOf(p)) != want.Type || BpfProgramInsnCnt(p) != want.InsnCnt {
			t.Errorf("program = %s %s type %d insns %d, want %+v", BpfProgramName(p),
				BpfProgramSectionName(p), BpfProgramTypeOf(p), BpfProgramInsnCnt(p), want)
		}
		p = BpfObjectNextProgram(obj, p)
	}

	if f.Kconfig != nil {
		checkKconfigDatasec(t, obj.btf, f.Kconfig)
	}
}

// checkKconfigDatasec compares the .kconfig DATASEC size and its variables,
// in BTF order, with the fixture.
func checkKconfigDatasec(t *testing.T, spec *btf.Spec, want *openFixtureKconfig) {
	t.Helper()

	ds := spec.Find(btf.KconfigSec, btf.KindDatasec)
	if ds == nil {
		t.Fatal("no .kconfig DATASEC")
	}
	if ds.SizeOrType != want.Size || len(ds.DataSec) != len(want.Vars) {
		t.Fatalf(".kconfig DATASEC size %d with %d vars, want %d with %d", ds.SizeOrType, len(ds.DataSec), want.Size, len(want.Vars))
	}
	for i, vsi := range ds.DataSec {
		v, err := spec.TypeByID(vsi.Type)
		if err != nil || v.Var == nil {
			t.Fatalf(".kconfig var %d: %v", i, err)
		}
		w := want.Vars[i]
		if v.Name != w.Name || vsi.Offset != w.Offset || vsi.Size != w.Size || v.Var.Linkage != w.Linkage {
			t.Errorf(".kconfig var %d = %s offset %d size %d linkage %d, want %+v",
				i, v.Name, vsi.Offset, vsi.Size, v.Var.Linkage, w)
		}
	}
}

// TestKconfigOpen opens kconfig.bpf.o with CONFIG_TEST=42 and compares the
// maps and the .kconfig layout with libbpf. The .kconfig map starts zeroed;
// resolving the externs writes CONFIG_TEST and the kernel version into it.
func TestKconfigOpen(t *testing.T) {
	obj := openKconfig(t, kconfigObject, new(kconfigTestConfig))
	checkOpenFixture(t, obj, loadOpenFixture(t, "open-kconfig.json"))

	m := kconfigMap(t, obj)
	if !BpfMapIsInternal(m) || BpfObjectFindMapByName(obj, "kconfig.kconfig") != m {
		t.Errorf("map %s: internal %v, found by kernel name %v", BpfMapName(m), BpfMapIsInternal(m),
			BpfObjectFindMapByName(obj, "kconfig.kconfig") == m)
	}
	if ds := obj.btf.Find(btf.KconfigSec, btf.KindDatasec); ds == nil || BpfMapBtfValueTypeID(m) != ds.ID {
		t.Errorf("value type id %d, want the .kconfig DATASEC %+v", BpfMapBtfValueTypeID(m), ds)
	}
	for _, ext := range obj.externs {
		if want, ok := kconfigOffsets[ext.name]; !ok || ext.kcfg.dataOff != want {
			t.Errorf("extern %s at %d, want %d", ext.name, ext.kcfg.dataOff, want)
		}
	}
	if !bytes.Equal(m.initialValue, make([]byte, BpfMapValueSize(m))) {
		t.Fatalf("initial value before load = %x, want zeroes", m.initialValue)
	}

	if err := resolveExterns(obj); err != nil {
		t.Fatalf("resolveExterns: %v", err)
	}
	if want := kconfigImage(); !bytes.Equal(m.initialValue, want) {
		t.Fatalf("initial value = %x, want %x", m.initialValue, want)
	}
	for _, ext := range obj.externs {
		if !ext.isSet {
			t.Errorf("extern %s is not set", ext.name)
		}
	}
}

// TestKconfigTypesOpen compares the .kconfig layout of one extern per kconfig
// type with libbpf: alignment first, then size, then name.
func TestKconfigTypesOpen(t *testing.T) {
	obj := openKconfig(t, kconfigTypesObject, nil)
	checkOpenFixture(t, obj, loadOpenFixture(t, "open-kconfig-types.json"))

	want := map[string]kcfgType{
		"CONFIG_GOBPFGO_BOOL":     kcfgBool,
		"CONFIG_GOBPFGO_CHAR":     kcfgChar,
		"CONFIG_GOBPFGO_U8":       kcfgChar,
		"CONFIG_GOBPFGO_S16":      kcfgInt,
		"CONFIG_GOBPFGO_S32":      kcfgInt,
		"CONFIG_GOBPFGO_U32":      kcfgInt,
		"CONFIG_GOBPFGO_S64":      kcfgInt,
		"CONFIG_GOBPFGO_U64":      kcfgInt,
		"CONFIG_GOBPFGO_TRISTATE": kcfgTristate,
		"CONFIG_GOBPFGO_STR":      kcfgCharArr,
		"CONFIG_GOBPFGO_STRONG":   kcfgInt,
		"LINUX_GOBPFGO_UNKNOWN":   kcfgInt,
	}
	signed := map[string]bool{
		"CONFIG_GOBPFGO_CHAR": true, "CONFIG_GOBPFGO_S16": true, "CONFIG_GOBPFGO_S32": true,
		"CONFIG_GOBPFGO_S64": true, "CONFIG_GOBPFGO_STRONG": true, "LINUX_GOBPFGO_UNKNOWN": true,
	}
	for _, ext := range obj.externs {
		if ext.typ != extKcfg || ext.kcfg.typ != want[ext.name] || ext.kcfg.isSigned != signed[ext.name] {
			t.Errorf("extern %s: kind %d type %d signed %v, want kcfg type %d signed %v",
				ext.name, ext.typ, ext.kcfg.typ, ext.kcfg.isSigned, want[ext.name], signed[ext.name])
		}
		if ext.isWeak != (ext.name != "CONFIG_GOBPFGO_STRONG") {
			t.Errorf("extern %s: weak %v", ext.name, ext.isWeak)
		}
	}
}

// kconfigFixture is the kconfig scenario: a base config and, per case, the
// lines put in front of it, the load errno and the .kconfig value libbpf
// leaves.
type kconfigFixture struct {
	Base  string `json:"base"`
	Cases []struct {
		Name    string `json:"name"`
		Kconfig string `json:"kconfig"`
		Errno   int32  `json:"errno"`
		Value   string `json:"value"`
	} `json:"cases"`
}

// TestKconfigOracle resolves kconfig_types.bpf.o with every config of the
// kconfig fixture and compares the errno and the .kconfig bytes with libbpf.
func TestKconfigOracle(t *testing.T) {
	data, err := os.ReadFile("../testdata/oracle/kconfig.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f kconfigFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}

	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			obj := openKconfig(t, kconfigTypesObject, new(c.Kconfig+f.Base))
			err := resolveExterns(obj)

			var got int32
			if err != nil {
				got = -int32(errnoFromError(err))
			}
			if got != c.Errno {
				t.Errorf("errno = %d, want %d (%v)", got, c.Errno, err)
			}
			if value := hex.EncodeToString(kconfigMap(t, obj).initialValue); value != c.Value {
				t.Errorf("value = %s, want %s", value, c.Value)
			}
		})
	}
}

// TestKconfigRelocation relocates handle_kconfig with stand-in descriptors:
// every extern load becomes a BPF_PSEUDO_MAP_VALUE load of the .kconfig map
// at the extern's offset.
func TestKconfigRelocation(t *testing.T) {
	obj := openKconfig(t, kconfigObject, new(kconfigTestConfig))
	for i, m := range obj.maps {
		m.fd = 100 + i
	}
	p := BpfObjectFindProgramByName(obj, "handle_kconfig")
	if p == nil {
		t.Fatal("program handle_kconfig not found")
	}

	insns := append([]byte(nil), p.insns...)
	if err := relocateProgram(obj, p, insns); err != nil {
		t.Fatalf("relocateProgram: %v", err)
	}

	m := kconfigMap(t, obj)
	externs := 0
	for _, rel := range p.relocs {
		want, ok := kconfigOffsets[rel.Symbol]
		if !ok {
			continue
		}
		externs++
		got := decodeBpfInsn(insns[rel.Offset:])
		next := decodeBpfInsn(insns[rel.Offset+bpfInsnLength:])
		if got.Src != bpfPseudoMapValue || got.Imm != int32(m.fd) || next.Imm != int32(want) {
			t.Errorf("%s: src %d imm %d/%d, want BPF_PSEUDO_MAP_VALUE fd %d offset %d",
				rel.Symbol, got.Src, got.Imm, next.Imm, m.fd, want)
		}
	}
	if externs != len(kconfigOffsets) {
		t.Fatalf("relocated %d extern loads, want %d", externs, len(kconfigOffsets))
	}

	// Without its extern the relocation has nothing to resolve.
	obj.externs = nil
	if err := relocateProgram(obj, p, append([]byte(nil), p.insns...)); err == nil ||
		!strings.Contains(err.Error(), "failed to find extern") {
		t.Fatalf("relocate without externs: %v", err)
	}
}

// TestKconfigOpenErrors changes the parsed BTF of kconfig.bpf.o to reach the
// extern errors: no extern linkage, no DATASEC, an unknown section and an
// unsupported type.
func TestKconfigOpenErrors(t *testing.T) {
	obj := openKconfig(t, kconfigObject, nil)
	spec, err := btf.Parse(obj.elf.BTF, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("parse BTF: %v", err)
	}
	varID := spec.Find("CONFIG_TEST", btf.KindVar).ID
	secID := spec.Find(btf.KconfigSec, btf.KindDatasec).ID
	structID := spec.Find("", btf.KindStruct).ID

	for _, tc := range []struct {
		name   string
		mutate func(s *btf.Spec)
		errno  syscall.Errno
		log    string
	}{
		{"allocated", func(s *btf.Spec) { s.Types[varID].Var.Linkage = btf.VarGlobalAllocated }, unix.EINVAL, "failed to find BTF for extern"},
		{"renamed", func(s *btf.Spec) { s.Types[varID].Name = "OTHER" }, unix.ENOENT, "failed to find BTF for extern"},
		{"no section", func(s *btf.Spec) { s.Types[secID].DataSec[0].Type = 0 }, unix.ENOENT, "section"},
		{"other section", func(s *btf.Spec) { s.Types[secID].Name = ".extern" }, unix.ENOTSUP, "unrecognized extern section '.extern'"},
		{"struct", func(s *btf.Spec) { s.Types[varID].SizeOrType = structID }, unix.ENOTSUP, "type is unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := btf.Parse(obj.elf.BTF, obj.elf.ByteOrder)
			if err != nil {
				t.Fatalf("parse BTF: %v", err)
			}
			tc.mutate(s)
			_, err = collectExterns(obj.elf, s)
			if !errors.Is(err, tc.errno) || !strings.Contains(err.Error(), tc.log) {
				t.Fatalf("collectExterns = %v, want %v with %q", err, tc.errno, tc.log)
			}
		})
	}
}

// TestFindKcfgType classifies the BTF types a .kconfig extern may have.
func TestFindKcfgType(t *testing.T) {
	const signed, boolean = 1 << 24, 4 << 24
	intType := func(size, enc uint32) btf.Type {
		return btf.Type{Kind: btf.KindInt, SizeOrType: size, Int: &btf.Int{Encoding: enc | size*8}}
	}
	array := func(elem, n uint32) btf.Type {
		return btf.Type{Kind: btf.KindArray, Array: &btf.Array{Type: elem, Nelems: n}}
	}
	types := []btf.Type{
		{Kind: btf.KindVoid},
		intType(1, signed),  // 1: char
		intType(1, boolean), // 2: bool
		intType(2, boolean), // 3: 2-byte bool
		intType(4, signed),  // 4: int
		intType(8, 0),       // 5: u64
		intType(3, 0),       // 6: 3-byte int
		intType(16, 0),      // 7: 16-byte int
		{Kind: btf.KindEnum, Name: libbpfTristateName, SizeOrType: 4},   // 8
		{Kind: btf.KindEnum, Name: libbpfTristateName, SizeOrType: 8},   // 9
		{Kind: btf.KindEnum, Name: "other", SizeOrType: 4},              // 10
		{Kind: btf.KindEnum64, Name: libbpfTristateName, SizeOrType: 8}, // 11
		array(1, 8),                           // 12: char[8]
		array(1, 0),                           // 13: char[0]
		array(4, 2),                           // 14: int[2]
		{Kind: btf.KindConst, SizeOrType: 16}, // 15: const typedef int
		{Kind: btf.KindTypedef, Name: "t", SizeOrType: 4}, // 16
		{Kind: btf.KindStruct, SizeOrType: 4},             // 17
		{Kind: btf.KindFloat, SizeOrType: 8},              // 18
		{Kind: btf.KindPtr, SizeOrType: 1},                // 19
	}
	for i := range types {
		types[i].ID = uint32(i)
	}
	spec := &btf.Spec{Types: types}

	for _, tc := range []struct {
		id     uint32
		want   kcfgType
		signed bool
	}{
		{1, kcfgChar, true}, {2, kcfgBool, false}, {3, kcfgUnknown, false},
		{4, kcfgInt, true}, {5, kcfgInt, false}, {6, kcfgUnknown, false}, {7, kcfgUnknown, false},
		{8, kcfgTristate, false}, {9, kcfgUnknown, false}, {10, kcfgUnknown, false}, {11, kcfgTristate, false},
		{12, kcfgCharArr, false}, {13, kcfgUnknown, false}, {14, kcfgUnknown, false},
		{15, kcfgInt, true}, {17, kcfgUnknown, false}, {18, kcfgUnknown, false}, {19, kcfgUnknown, false},
	} {
		typ, signed := findKcfgType(spec, tc.id)
		if typ != tc.want || (typ != kcfgUnknown && signed != tc.signed) {
			t.Errorf("findKcfgType(%d) = %d signed %v, want %d signed %v", tc.id, typ, signed, tc.want, tc.signed)
		}
	}
}

// TestExternLess sorts .kconfig externs by descending alignment, ascending
// size and name, after the kind.
func TestExternLess(t *testing.T) {
	kcfg := func(name string, align, sz int) externDesc {
		return externDesc{typ: extKcfg, name: name, kcfg: kcfgExtern{align: align, sz: sz}}
	}
	sorted := []externDesc{
		kcfg("Z_U64", 8, 8),
		kcfg("A_INT", 4, 4),
		kcfg("B_INT", 4, 4),
		kcfg("A_CHAR", 1, 1),
		kcfg("A_STR", 1, 16),
		{typ: extKsym, name: "A_KSYM"},
	}
	for i := range sorted {
		for j := range sorted {
			if got := externLess(&sorted[i], &sorted[j]); got != (i < j) {
				t.Errorf("externLess(%s, %s) = %v, want %v", sorted[i].name, sorted[j].name, got, i < j)
			}
		}
	}
}

// kconfigExterns returns synthetic .kconfig externs laid out back to back
// and a zeroed value buffer for them.
func kconfigExterns(externs ...externDesc) ([]externDesc, []byte) {
	off := 0
	for i := range externs {
		externs[i].typ = extKcfg
		externs[i].kcfg.dataOff = roundup(off, externs[i].kcfg.align)
		off = externs[i].kcfg.dataOff + externs[i].kcfg.sz
	}
	return externs, make([]byte, off)
}

// TestResolveVirtualExterns resolves the LINUX_ externs: the kernel version,
// the BPF cookie probe result, the unported syscall wrapper extern as zero,
// weak unknown ones as zero, and errors for strong unknown ones and other
// names.
func TestResolveVirtualExterns(t *testing.T) {
	u32 := func(name string, weak bool) externDesc {
		return externDesc{name: name, isWeak: weak, kcfg: kcfgExtern{typ: kcfgInt, sz: 4, align: 4}}
	}
	resolve := func(externs ...externDesc) (*BpfObject, error) {
		externs, data := kconfigExterns(externs...)
		obj := &BpfObject{externs: externs, kconfigMap: &BpfMap{initialValue: data}}
		return obj, resolveExterns(obj)
	}

	obj, err := resolve(u32("LINUX_KERNEL_VERSION", false), u32("LINUX_HAS_BPF_COOKIE", false),
		u32("LINUX_HAS_SYSCALL_WRAPPER", true), u32("LINUX_GOBPFGO_UNKNOWN", true))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := make([]byte, 16)
	binary.NativeEndian.PutUint32(want, getKernelVersion())
	if featBpfCookie.supported() {
		binary.NativeEndian.PutUint32(want[4:], 1)
	}
	if got := obj.kconfigMap.initialValue; !bytes.Equal(got, want) {
		t.Errorf("value = %x, want %x", got, want)
	}

	for _, tc := range []struct {
		name  string
		ext   externDesc
		errno syscall.Errno
	}{
		{"strong unknown", u32("LINUX_GOBPFGO_UNKNOWN", false), unix.EINVAL},
		{"other prefix", u32("GOBPFGO_UNKNOWN", true), unix.EINVAL},
		{"version range", externDesc{name: "LINUX_KERNEL_VERSION", kcfg: kcfgExtern{typ: kcfgChar, sz: 1, align: 1}}, unix.ERANGE},
		{"version type", externDesc{name: "LINUX_KERNEL_VERSION", kcfg: kcfgExtern{typ: kcfgCharArr, sz: 8, align: 1}}, unix.EINVAL},
	} {
		if _, err := resolve(tc.ext); !errors.Is(err, tc.errno) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.errno)
		}
	}

	if err := resolveExterns(&BpfObject{}); err != nil {
		t.Errorf("no externs: %v", err)
	}
}

// systemKconfigAvailable reports whether the system config the loader falls
// back to can be opened.
func systemKconfigAvailable() bool {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return false
	}
	if _, err := readKconfigSource(bootKconfigPrefix + unix.ByteSliceToString(uts.Release[:])); err == nil {
		return true
	}
	_, err := readKconfigSource(procKconfigPath)
	return err == nil
}

// TestKconfigSystemConfig resolves kconfig.bpf.o without extra config text:
// the loader reads the system config, which has no CONFIG_TEST, so the strong
// extern is ESRCH. Without a system config the read itself fails with EINVAL,
// even though every other extern is resolved.
func TestKconfigSystemConfig(t *testing.T) {
	want := unix.ESRCH
	if !systemKconfigAvailable() {
		want = unix.EINVAL
	}

	obj := openKconfig(t, kconfigObject, nil)
	if err := resolveExterns(obj); !errors.Is(err, want) {
		t.Fatalf("resolveExterns = %v, want %v", err, want)
	}

	// A config that sets every CONFIG_ extern skips the system config.
	obj = openKconfig(t, kconfigObject, new("# comment\n"+kconfigTestConfig))
	if err := resolveExterns(obj); err != nil {
		t.Fatalf("resolveExterns with CONFIG_TEST: %v", err)
	}
}

// TestKconfigLines splits config text like the C line reader: after each
// newline, after 4095 bytes, and at a NUL byte within a piece.
func TestKconfigLines(t *testing.T) {
	long := "CONFIG_A=\"" + strings.Repeat("a", kconfigLineMax) + "\"\n"
	for _, tc := range []struct {
		name string
		text string
		want []string
	}{
		{"empty", "", nil},
		{"last line", "A\nB", []string{"A\n", "B"}},
		{"blank", "\n\n", []string{"\n", "\n"}},
		{"crlf", "A\r\n", []string{"A\r\n"}},
		{"nul", "A\x00B\nC", []string{"A", "C"}},
		{"long", long, []string{long[:kconfigLineMax-1], long[kconfigLineMax-1:]}},
	} {
		got := kconfigLines([]byte(tc.text))
		if strings.Join(got, "|") != strings.Join(tc.want, "|") || len(got) != len(tc.want) {
			t.Errorf("%s: kconfigLines = %q, want %q", tc.name, got, tc.want)
		}
	}

	// The in-memory config ends at its first NUL byte.
	externs, data := kconfigExterns(externDesc{name: "CONFIG_A", kcfg: kcfgExtern{typ: kcfgInt, sz: 4, align: 4}})
	if err := readKconfigMem(externs, "CONFIG_X=1\n\x00CONFIG_A=1\n", data); err != nil || externs[0].isSet {
		t.Errorf("readKconfigMem past NUL: err %v, set %v", err, externs[0].isSet)
	}
}

// TestReadKconfigSource reads plain and gzip config files, keeps what a
// corrupt gzip stream decoded, and fails only for a file it cannot open.
func TestReadKconfigSource(t *testing.T) {
	const text = "CONFIG_A=y\nCONFIG_B=2\n"
	dir := t.TempDir()

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(text)); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}

	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"plain", []byte(text), text},
		{"gzip", gz.Bytes(), text},
		{"bad header", []byte{0x1f, 0x8b, 0, 0}, ""},
		{"truncated", gz.Bytes()[:gz.Len()-8], text},
	} {
		path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_"))
		if err := os.WriteFile(path, tc.data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		got, err := readKconfigSource(path)
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: readKconfigSource = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}

	if _, err := readKconfigSource(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file: no error")
	}
}

// TestKconfigLoad loads kconfig.bpf.o with CONFIG_TEST=42, checks the .kconfig
// map against libbpf's geometry, its contents and its freeze, then attaches
// handle_kconfig to do_sys_openat2, opens a file and reads what the program
// saw. It needs root or CAP_BPF and skips with EPERM or EACCES.
func TestKconfigLoad(t *testing.T) {
	f := loadOpenFixture(t, "open-kconfig.json")
	opts := NewBpfObjectOpenOpts()
	opts.Kconfig = new(kconfigTestConfig)
	obj := loadTestObjectOpts(t, kconfigObject, opts)
	defer BpfObjectClose(obj)

	m := kconfigMap(t, obj)
	want := f.Maps[len(f.Maps)-1]
	info, err := sys.MapInfoByFD(BpfMapFD(m))
	if err != nil {
		t.Fatalf("MapInfoByFD: %v", err)
	}
	if info.Name != want.Name || info.Type != want.Type || info.KeySize != want.KeySize ||
		info.ValueSize != want.ValueSize || info.MaxEntries != want.MaxEntries || info.MapFlags != want.MapFlags ||
		info.BtfKeyTypeID != want.BtfKeyTypeID || info.BtfValueTypeID != want.BtfValueTypeID {
		t.Errorf("map info = %+v, want %+v", info, want)
	}

	image := kconfigImage()
	if got := lookupGlobal(t, m); !bytes.Equal(got, image) {
		t.Errorf(".kconfig contents = %x, want %x", got, image)
	}
	err = sys.MapUpdateElem(BpfMapFD(m), make([]byte, internalMapKeySize), image, 0)
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("update frozen .kconfig: %v, want EPERM", err)
	}

	prog := BpfObjectFindProgramByName(obj, "handle_kconfig")
	link, err := BpfProgramAttachKprobe(prog, false, "do_sys_openat2")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("attach kprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	triggerOpen(t)

	values := BpfObjectFindMapByName(obj, "values")
	for key, want := range []uint64{kconfigTest, uint64(getKernelVersion()), 0, 0} {
		keyBuf := make([]byte, 4)
		binary.NativeEndian.PutUint32(keyBuf, uint32(key))
		value := make([]byte, 8)
		if err := BpfMapLookupElem(values, keyBuf, value, 0); err != nil {
			t.Fatalf("lookup values[%d]: %v", key, err)
		}
		if got := binary.NativeEndian.Uint64(value); got != want {
			t.Errorf("values[%d] = %#x, want %#x", key, got, want)
		}
	}
}
