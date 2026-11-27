// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// The .extern fixtures: link_extern_a.bpf.o declares ext_counter and ext_add
// in the .extern DATASEC and calls them from handle_extern;
// link_extern_b.bpf.o defines both. link_extern_weak.bpf.o declares a weak
// ext_counter, which link_extern_b.bpf.o resolves, and the weak ext_missing
// and ext_missing_add, which nothing defines.
const (
	externUse  = "link_extern_a.bpf.o"
	externDef  = "link_extern_b.bpf.o"
	externWeak = "link_extern_weak.bpf.o"
)

// TestBpfLinkerExternOracle links the .extern fixtures and compares the
// result with libbpf's linker: symbols, relocations and every section,
// including the .BTF and .BTF.ext bytes, plus the maps and programs after
// open, or the open errno when libbpf rejects the linked object because an
// extern stayed unresolved.
func TestBpfLinkerExternOracle(t *testing.T) {
	fixtures := []string{
		"linker-extern.json",
		"linker-extern-reverse.json",
		"linker-extern-weak.json",
		"linker-extern-unresolved.json",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			want := loadLinkerFixture(t, fixture)
			compareLinked(t, want, linkObjects(t, want.Objects...))
		})
	}
}

// externSym is the part of a linked symbol that resolution decides.
type externSym struct {
	Type    uint32
	Bind    uint32
	Section string
	Value   uint64
}

var (
	externObject = externSym{uint32(elf.STT_OBJECT), uint32(elf.STB_GLOBAL), ".data", 0}
	externFunc   = externSym{uint32(elf.STT_FUNC), uint32(elf.STB_GLOBAL), ".text", 0}
)

func weakSym(s externSym) externSym {
	s.Bind = uint32(elf.STB_WEAK)
	return s
}

func undefSym(bind elf.SymBind) externSym {
	return externSym{uint32(elf.STT_NOTYPE), uint32(bind), "UND", 0}
}

// TestBpfLinkerExternPrecedence links the extern fixtures, and a copy of
// link_extern_b.bpf.o whose definitions are weak, in different orders and
// checks how ext_counter and ext_add resolve. A strong binding from either
// side wins, an extern never replaces a definition, a weak definition
// resolves an extern but does not replace a strong definition, and an
// unresolved extern stays undefined. After a strong extern takes a weak
// definition, a strong definition conflicts. The expected symbols are what
// libbpf's linker writes for the same inputs.
func TestBpfLinkerExternPrecedence(t *testing.T) {
	use := readProg(t, externUse)
	def := readProg(t, externDef)
	weak := readProg(t, externWeak)
	weakDef := withSymbolBind(t, def, elf.STB_WEAK, "ext_counter", "ext_add")

	tests := []struct {
		name    string
		objects [][]byte
		counter externSym
		add     externSym
	}{
		{"strong extern then strong definition", [][]byte{use, def}, externObject, externFunc},
		{"strong definition then strong extern", [][]byte{def, use}, externObject, externFunc},
		{"weak extern then strong definition", [][]byte{weak, def}, externObject, externFunc},
		{"strong extern then weak definition", [][]byte{use, weakDef}, externObject, externFunc},
		{"weak definition then strong extern", [][]byte{weakDef, use}, externObject, externFunc},
		{"weak extern then weak definition", [][]byte{weak, weakDef}, weakSym(externObject), weakSym(externFunc)},
		{"weak definition then strong definition", [][]byte{weakDef, def},
			externSym{uint32(elf.STT_OBJECT), uint32(elf.STB_GLOBAL), ".data", 8},
			externSym{uint32(elf.STT_FUNC), uint32(elf.STB_GLOBAL), ".text", 24}},
		{"strong definition then weak definition", [][]byte{def, weakDef}, externObject, externFunc},
		{"unresolved strong extern", [][]byte{use}, undefSym(elf.STB_GLOBAL), undefSym(elf.STB_GLOBAL)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syms := externSymbols(t, linkBufs(t, tt.objects...))
			if got := syms["ext_counter"]; got != tt.counter {
				t.Errorf("ext_counter = %+v, want %+v", got, tt.counter)
			}
			if got := syms["ext_add"]; got != tt.add {
				t.Errorf("ext_add = %+v, want %+v", got, tt.add)
			}
		})
	}

	t.Run("unresolved weak extern", func(t *testing.T) {
		syms := externSymbols(t, linkBufs(t, weak))
		for _, name := range []string{"ext_counter", "ext_missing", "ext_missing_add"} {
			if got, want := syms[name], undefSym(elf.STB_WEAK); got != want {
				t.Errorf("%s = %+v, want %+v", name, got, want)
			}
		}
	})

	t.Run("strong extern, weak definition, strong definition", func(t *testing.T) {
		err := addBufs(t, use, weakDef, def)
		if !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), "conflicting non-weak symbol") {
			t.Fatalf("third add = %v, want a conflicting symbol EINVAL", err)
		}
	})
}

// readProg reads a fixture object from testdata/progs.
func readProg(t *testing.T, name string) []byte {
	t.Helper()
	return readTestFile(t, filepath.Join(progsDir, name))
}

// withSymbolBind returns a copy of the object data with the named symbols
// bound as bind.
func withSymbolBind(t *testing.T, data []byte, bind elf.SymBind, names ...string) []byte {
	t.Helper()

	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	symtab := f.Section(".symtab")
	syms := elfSymbols(t, f)

	out := bytes.Clone(data)
	for _, name := range names {
		i := slices.IndexFunc(syms, func(s elf.Symbol) bool { return s.Name == name })
		if i < 0 {
			t.Fatalf("no symbol %s", name)
		}
		info := &out[symtab.Offset+uint64(i)*elfSymSize+4]
		*info = elf.ST_INFO(bind, elf.ST_TYPE(*info))
	}
	return out
}

// addBufs adds the objects to a new linker in order and returns the first
// error.
func addBufs(t *testing.T, objects ...[]byte) error {
	t.Helper()

	l, err := BpfLinkerNew(filepath.Join(t.TempDir(), "linked.bpf.o"), nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)

	for _, obj := range objects {
		if err := BpfLinkerAddBuf(l, obj, nil); err != nil {
			return err
		}
	}
	return nil
}

// externSymbols returns the linked symbols by name. Each name must appear
// once: a resolved extern shares one symbol with its definition.
func externSymbols(t *testing.T, path string) map[string]externSym {
	t.Helper()

	syms := make(map[string]externSym)
	for _, s := range linkedSymbols(t, openLinkedELF(t, path)) {
		if s.Type == uint32(elf.STT_SECTION) || s.Type == uint32(elf.STT_FILE) {
			continue
		}
		if _, dup := syms[s.Name]; dup {
			t.Fatalf("symbol %s appears twice", s.Name)
		}
		syms[s.Name] = externSym{s.Type, s.Bind, s.Section, s.Value}
	}
	return syms
}

// TestBpfLinkerExternRelocations checks that handle_extern's relocations
// against ext_counter and ext_add reach the definitions in both link orders:
// the extern comes first and its symbol is defined in place, or the
// definition comes first and the extern maps to it. Linked alone, the
// relocations point at the undefined externs.
func TestBpfLinkerExternRelocations(t *testing.T) {
	tests := []struct {
		name    string
		objects []string
		want    map[string]string
	}{
		{"extern first", []string{externUse, externDef}, map[string]string{"ext_counter": ".data", "ext_add": ".text", "ext_seen": ".bss"}},
		{"definition first", []string{externDef, externUse}, map[string]string{"ext_counter": ".data", "ext_add": ".text", "ext_seen": ".bss"}},
		{"unresolved", []string{externUse}, map[string]string{"ext_counter": "UND", "ext_add": "UND", "ext_seen": ".bss"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := openLinkedELF(t, linkObjects(t, tt.objects...))
			syms := elfSymbols(t, f)
			got := make(map[string]string)
			for _, r := range relocSymbols(t, f, ".relkprobe/do_sys_openat2") {
				got[r.Name] = symbolSection(f, &syms[r.index])
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("relocation targets = %v, want %v", got, tt.want)
			}
		})
	}
}

// relocSymbol is the symbol a relocation entry refers to, by index.
type relocSymbol struct {
	Name  string
	index int
}

func relocSymbols(t *testing.T, f *elf.File, section string) []relocSymbol {
	t.Helper()

	s := f.Section(section)
	if s == nil {
		t.Fatalf("no section %s", section)
	}
	syms := elfSymbols(t, f)
	data := sectionData(t, s)
	var out []relocSymbol
	for off := 0; off+elfRelSize <= len(data); off += elfRelSize {
		idx := int(elf.R_SYM64(binary.LittleEndian.Uint64(data[off+8:])))
		if idx >= len(syms) {
			t.Fatalf("%s: relocation symbol %d out of range", section, idx)
		}
		out = append(out, relocSymbol{Name: syms[idx].Name, index: idx})
	}
	return out
}

// TestBpfLinkerExternBTF checks the linked BTF. Resolved, ext_counter is an
// allocated VAR in the .data DATASEC at its symbol offset, ext_add is a
// global FUNC whose prototype has the definition's parameter names, no
// .extern DATASEC is left and dedup leaves no duplicate. Unresolved, both keep
// their extern linkage and unnamed parameters and no DATASEC lists them.
func TestBpfLinkerExternBTF(t *testing.T) {
	for _, names := range [][]string{{externUse, externDef}, {externDef, externUse}} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			path := linkObjects(t, names...)
			spec := parseFileBTF(t, path)

			if dups := duplicateTypes(t, spec); len(dups) != 0 {
				t.Fatalf("duplicate types: %v", dups)
			}
			checkExternBTF(t, spec, btf.VarGlobalAllocated, btfFuncGlobal, []string{"value", "delta"})
			if got, want := datasecVarOffset(t, spec, ".data", "ext_counter"), symbolValues(t, path)["ext_counter"]; uint64(got) != want {
				t.Fatalf("ext_counter DATASEC offset = %d, want %d", got, want)
			}
		})
	}

	t.Run("unresolved", func(t *testing.T) {
		spec := parseFileBTF(t, linkObjects(t, externUse))
		checkExternBTF(t, spec, btf.VarGlobalExtern, btfFuncExtern, []string{"", ""})
		for _, name := range []string{"ext_counter", "ext_add"} {
			if sec := datasecOf(spec, name); sec != "" {
				t.Errorf("%s is in DATASEC %s, want none", name, sec)
			}
		}
	})
}

// checkExternBTF checks the linkage of the ext_counter VAR and the ext_add
// FUNC, the parameter names of ext_add's prototype, and that there is no
// .extern DATASEC.
func checkExternBTF(t *testing.T, spec *btf.Spec, varLinkage, funcLinkage uint32, params []string) {
	t.Helper()

	if spec.Find(btfExternSec, btf.KindDatasec) != nil {
		t.Errorf("linked BTF has a %s DATASEC", btfExternSec)
	}
	v := spec.Find("ext_counter", btf.KindVar)
	if v == nil || v.Var == nil || v.Var.Linkage != varLinkage {
		t.Errorf("ext_counter VAR = %+v, want linkage %d", v, varLinkage)
	}
	fn := spec.Find("ext_add", btf.KindFunc)
	if fn == nil || fn.Vlen != funcLinkage {
		t.Fatalf("ext_add FUNC = %+v, want linkage %d", fn, funcLinkage)
	}
	proto, err := spec.TypeByID(fn.SizeOrType)
	if err != nil {
		t.Fatalf("ext_add prototype: %v", err)
	}
	var got []string
	for _, p := range proto.Params {
		got = append(got, p.Name)
	}
	if !reflect.DeepEqual(got, params) {
		t.Errorf("ext_add parameters = %q, want %q", got, params)
	}
}

// datasecOf returns the DATASEC that lists the VAR or FUNC name, or "".
func datasecOf(spec *btf.Spec, name string) string {
	for i := range spec.Types {
		ds := &spec.Types[i]
		if ds.Kind != btf.KindDatasec {
			continue
		}
		for _, v := range ds.DataSec {
			if vt, err := spec.TypeByID(v.Type); err == nil && vt.Name == name {
				return ds.Name
			}
		}
	}
	return ""
}

// TestBpfLinkerExternOpenUnresolved checks that linking an unresolved extern,
// strong or weak, succeeds, and that opening the result fails with ENOENT
// because the extern is in no DATASEC, as libbpf does.
func TestBpfLinkerExternOpenUnresolved(t *testing.T) {
	for _, names := range [][]string{{externUse}, {externWeak, externDef}} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			obj, err := BpfObjectOpenFile(linkObjects(t, names...), nil)
			if err == nil {
				BpfObjectClose(obj)
			}
			if !errors.Is(err, unix.ENOENT) || !strings.Contains(err.Error(), "failed to find BTF for extern") {
				t.Fatalf("BpfObjectOpenFile = %v, want ENOENT for the unresolved extern", err)
			}
		})
	}
}

// TestBpfLinkerExternDeterministic links the weak externs, two of them
// unresolved, from files and from memory, and twice, and expects the same
// bytes each time: the unresolved externs keep their input order.
func TestBpfLinkerExternDeterministic(t *testing.T) {
	names := []string{externWeak, externDef}
	want := readTestFile(t, linkObjects(t, names...))
	if got := readTestFile(t, linkBufs(t, readProg(t, names[0]), readProg(t, names[1]))); !bytes.Equal(got, want) {
		t.Fatal("linking from memory gave different bytes")
	}
	if again := readTestFile(t, linkObjects(t, names...)); !bytes.Equal(again, want) {
		t.Fatal("linking twice gave different bytes")
	}
}

// TestBpfLinkerKconfigExtern links an object with .kconfig externs, which the
// linker does not pass through yet.
func TestBpfLinkerKconfigExtern(t *testing.T) {
	err := addBufs(t, readProg(t, "kconfig.bpf.o"))
	if !errors.Is(err, unix.EOPNOTSUPP) || !strings.Contains(err.Error(), "extern section '.kconfig'") {
		t.Fatalf("add = %v, want EOPNOTSUPP for the .kconfig section", err)
	}
}

// externMatchBTF builds the BTF of the matching and completion tests. Its
// type IDs are the match constants, and its names are in its string table.
func externMatchBTF() *linkerBTF {
	variable := func(typ, linkage uint32) btf.Type {
		return btf.Type{Kind: btf.KindVar, Name: "ext", SizeOrType: typ, Var: &btf.Var{Linkage: linkage}}
	}
	proto := func(names ...string) btf.Type {
		p := btf.Type{Kind: btf.KindFuncProto, SizeOrType: matchU64}
		for _, name := range names {
			p.Params = append(p.Params, btf.Param{Name: name, Type: matchU64})
		}
		return p
	}
	fn := func(typ, linkage uint32) btf.Type {
		return btf.Type{Kind: btf.KindFunc, Name: "ext_add", SizeOrType: typ, Vlen: linkage}
	}

	b := newLinkerBTF()
	for _, ty := range []btf.Type{
		{Kind: btf.KindInt, Name: "u64", SizeOrType: 8, Int: &btf.Int{Encoding: 64}},
		{Kind: btf.KindInt, Name: "u32", SizeOrType: 4, Int: &btf.Int{Encoding: 32}},
		variable(matchU64, btf.VarGlobalExtern),
		variable(matchU64, btf.VarGlobalAllocated),
		variable(matchU32, btf.VarGlobalAllocated),
		variable(matchU64, btf.VarStatic),
		proto("", ""),
		proto("value", "delta"),
		proto("value"),
		proto("value", ""),
		fn(matchProtoAnon, btfFuncExtern),
		fn(matchProtoNamed, btfFuncGlobal),
		fn(matchProtoShort, btfFuncGlobal),
		fn(matchProtoNamed, btfFuncStatic),
		fn(matchProtoPartial, btfFuncGlobal),
	} {
		b.addType(&ty)
	}
	return b
}

const (
	matchU64 = iota + 1
	matchU32
	matchVarExtern
	matchVarU64
	matchVarU32
	matchVarStatic
	matchProtoAnon
	matchProtoNamed
	matchProtoShort
	matchProtoPartial
	matchFuncExtern
	matchFuncGlobal
	matchFuncShort
	matchFuncStatic
	matchFuncPartial
)

// TestGlobSymsMatchExtern matches extern VARs and FUNCs against definitions:
// extern and global linkage agree, parameter names are ignored, and sizes,
// kinds, static linkage and parameter counts must agree. A symbol whose BTF
// is missing or is not a VAR or FUNC is rejected.
func TestGlobSymsMatchExtern(t *testing.T) {
	out := newLinkerOutput()
	out.btf = externMatchBTF()
	in := &linkerInput{name: "in.bpf.o", btf: out.btf.spec}

	tests := []struct {
		name     string
		globID   uint32
		srcID    uint32
		errorMsg string
	}{
		{"extern and allocated variable", matchVarExtern, matchVarU64, ""},
		{"allocated and extern variable", matchVarU64, matchVarExtern, ""},
		{"variable size", matchVarExtern, matchVarU32, "incompatible int 'u64' size 8 and 4"},
		{"static variable", matchVarExtern, matchVarStatic, "incompatible var 'ext' linkage"},
		{"extern and global function", matchFuncExtern, matchFuncGlobal, ""},
		{"parameter count", matchFuncExtern, matchFuncShort, "incompatible number of func_proto params 2 and 1"},
		{"static function", matchFuncExtern, matchFuncStatic, "incompatible func 'ext_add' linkage"},
		{"variable and function", matchVarExtern, matchFuncGlobal, "incompatible BTF kinds var and func"},
		{"not a variable or function", matchVarExtern, matchU64, "only extern variables and functions are supported"},
		{"no BTF", matchVarExtern, 0, "BTF info is missing"},
		{"no output BTF", 0, matchVarU64, "BTF info is missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &linkerGlobSym{name: "ext", btfID: tt.globID, varIdx: -1, isExtern: true}
			err := out.globSymsMatch(in, g, "ext", tt.srcID)
			if tt.errorMsg == "" {
				if err != nil {
					t.Fatalf("globSymsMatch = %v, want a match", err)
				}
				return
			}
			if !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), tt.errorMsg) {
				t.Fatalf("globSymsMatch = %v, want EINVAL with %q", err, tt.errorMsg)
			}
		})
	}
}

// TestCompleteExternInfo completes an extern VAR and FUNC from their
// definitions: the VAR becomes allocated, and the FUNC becomes global, loses
// its kind flag and takes each parameter name the definition has, while a
// parameter the definition leaves unnamed stays unnamed.
func TestCompleteExternInfo(t *testing.T) {
	src := externMatchBTF().spec
	dst := externMatchBTF()
	dst.spec.Types[matchFuncExtern].KindFlag = true

	if err := dst.completeExternInfo(matchVarExtern, src, matchVarU64); err != nil {
		t.Fatalf("complete VAR: %v", err)
	}
	if got := dst.spec.Types[matchVarExtern].Var.Linkage; got != btf.VarGlobalAllocated {
		t.Errorf("VAR linkage = %d, want %d", got, btf.VarGlobalAllocated)
	}

	if err := dst.completeExternInfo(matchFuncExtern, src, matchFuncPartial); err != nil {
		t.Fatalf("complete FUNC: %v", err)
	}
	fn := &dst.spec.Types[matchFuncExtern]
	if fn.Vlen != btfFuncGlobal || fn.KindFlag {
		t.Errorf("FUNC linkage %d kind flag %v, want %d and false", fn.Vlen, fn.KindFlag, btfFuncGlobal)
	}
	params := dst.spec.Types[matchProtoAnon].Params
	if params[0].Name != "value" || params[0].NameOff != dst.strOffs["value"] {
		t.Errorf("parameter 0 = %q at %d, want %q at %d", params[0].Name, params[0].NameOff, "value", dst.strOffs["value"])
	}
	if params[1].Name != "" || params[1].NameOff != 0 {
		t.Errorf("parameter 1 = %q at %d, want unnamed", params[1].Name, params[1].NameOff)
	}
}

// TestBpfLinkerExternLoad links link_extern_a.bpf.o and link_extern_b.bpf.o
// in both orders, loads the result and runs it. handle_extern increments the
// extern ext_counter, which must land in link_extern_b.bpf.o's .data
// definition above its initial 100, and stores what the extern ext_add, the
// global function in .text, returns for 0x1200 and 0x34. It needs root or
// CAP_BPF and skips otherwise.
func TestBpfLinkerExternLoad(t *testing.T) {
	for _, names := range [][]string{{externUse, externDef}, {externDef, externUse}} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			path := linkObjects(t, names...)
			spec := parseFileBTF(t, path)
			obj := loadTestObject(t, path)
			defer BpfObjectClose(obj)

			attachKprobes(t, obj, map[string]string{"handle_extern": "do_sys_openat2"})
			triggerOpen(t)

			counter := globalVar(t, obj, spec, ".data", "ext_counter")
			if counter <= 100 {
				t.Errorf("ext_counter = %d, want the open counted above 100", counter)
			}
			if seen := globalVar(t, obj, spec, ".bss", "ext_seen"); seen != 0x1234 {
				t.Errorf("ext_seen = %#x, want 0x1234", seen)
			}
		})
	}
}

// globalVar reads the 64-bit global variable name from the internal map of
// section, at its offset in the linked BTF.
func globalVar(t *testing.T, obj *BpfObject, spec *btf.Spec, section, name string) uint64 {
	t.Helper()

	off := datasecVarOffset(t, spec, section, name)
	value := lookupGlobal(t, globalDataMap(t, obj, section))
	if int(off)+8 > len(value) {
		t.Fatalf("%s at %d is outside the %d-byte %s map", name, off, len(value), section)
	}
	return binary.NativeEndian.Uint64(value[off:])
}
