// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// The .ksyms fixtures. link_ksyms.bpf.o has a typed per-CPU variable and two
// kernel functions, link_ksyms_addr.bpf.o two typeless variables, and
// link_ksyms_weak.bpf.o weak externs the kernel lacks next to one it has.
const (
	ksymsAddrProg = "link_ksyms_addr.bpf.o"
	ksymsWeakProg = "link_ksyms_weak.bpf.o"
)

// TestKsymsOpenOracle opens each .ksyms fixture and compares the maps, the
// programs and the whole object BTF after open with libbpf. Open rewrites the
// .ksyms DATASEC for the kernel, so the bytes cover the integer slots, the
// function linkage, the parameter names and the dummy_ksym variable.
func TestKsymsOpenOracle(t *testing.T) {
	for prog, fixture := range map[string]string{
		ksymsProg:     "open-ksyms.json",
		ksymsAddrProg: "open-ksyms-addr.json",
		ksymsWeakProg: "open-ksyms-weak.json",
	} {
		t.Run(prog, func(t *testing.T) {
			obj := openProg(t, prog)
			f := loadOpenFixture(t, fixture)
			checkOpenFixture(t, obj, f)
		})
	}
}

// openProg opens the named object from testdata/progs until the test ends.
func openProg(t *testing.T, name string) *BpfObject {
	t.Helper()
	return openProgOpts(t, name, nil)
}

// openProgOpts opens the named object from testdata/progs with opts until
// the test ends. opts may be nil.
func openProgOpts(t *testing.T, name string, opts *BpfObjectOpenOpts) *BpfObject {
	t.Helper()

	obj, err := BpfObjectOpenFile(progsDir+"/"+name, opts)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// ksymWant is what open records for one .ksyms extern.
type ksymWant struct {
	weak     bool
	typeKind btf.Kind
	essent   string
}

// TestKsymsCollect checks the .ksyms extern descriptors after open: the
// kind, the weak flag, and the local type a typed extern resolves against,
// which is the variable's type after modifiers, a function's prototype, or
// void for a typeless variable. The DATASEC becomes 4-byte slots, the
// variables allocated integers, and the functions global with the
// dummy_ksym VAR in their slots.
func TestKsymsCollect(t *testing.T) {
	tests := []struct {
		prog  string
		want  map[string]ksymWant
		dummy bool
	}{
		{ksymsProg, map[string]ksymWant{
			"bpf_prog_active":     {typeKind: btf.KindInt},
			"bpf_rcu_read_lock":   {typeKind: btf.KindFuncProto},
			"bpf_rcu_read_unlock": {typeKind: btf.KindFuncProto},
		}, true},
		{ksymsAddrProg, map[string]ksymWant{
			"bpf_prog_active": {typeKind: btf.KindVoid},
			"init_task":       {typeKind: btf.KindVoid},
		}, false},
		{ksymsWeakProg, map[string]ksymWant{
			"gobpfgo_missing_var":   {weak: true, typeKind: btf.KindInt},
			"gobpfgo_missing_sym":   {weak: true, typeKind: btf.KindVoid},
			"gobpfgo_missing_kfunc": {weak: true, typeKind: btf.KindFuncProto},
			"bpf_prog_active":       {weak: true, typeKind: btf.KindVoid},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.prog, func(t *testing.T) {
			obj := openProg(t, tt.prog)
			got := map[string]ksymWant{}
			for _, ext := range obj.externs {
				if ext.typ != extKsym {
					t.Fatalf("extern %s has kind %d", ext.name, ext.typ)
				}
				typ, err := obj.btf.TypeByID(ext.ksym.typeID)
				if err != nil {
					t.Fatalf("%s type: %v", ext.name, err)
				}
				got[ext.name] = ksymWant{weak: ext.isWeak, typeKind: typ.Kind, essent: ext.essentName}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("externs = %+v, want %+v", got, tt.want)
			}
			checkKsymsDatasec(t, obj.btf, len(tt.want), tt.dummy)
		})
	}
}

// checkKsymsDatasec checks the .ksyms DATASEC after open: n slots of 4
// bytes at increasing offsets, each an allocated VAR of a 32-bit integer,
// and dummy_ksym in the slot of every function when the object has one.
func checkKsymsDatasec(t *testing.T, spec *btf.Spec, n int, dummy bool) {
	t.Helper()

	sec := spec.Find(btf.KsymsSec, btf.KindDatasec)
	if sec == nil || len(sec.DataSec) != n || sec.SizeOrType != uint32(4*n) {
		t.Fatalf(".ksyms DATASEC = %+v, want %d slots", sec, n)
	}
	sawDummy := false
	for j, vsi := range sec.DataSec {
		v, err := spec.TypeByID(vsi.Type)
		if err != nil {
			t.Fatalf("slot %d: %v", j, err)
		}
		if vsi.Offset != uint32(4*j) || vsi.Size != 4 || v.Kind != btf.KindVar ||
			v.Var.Linkage != btf.VarGlobalAllocated || v.SizeOrType != findIntBtfID(spec) {
			t.Errorf("slot %d = %+v %s %+v, want an allocated int VAR at %d", j, vsi, v.Name, v.Var, 4*j)
		}
		sawDummy = sawDummy || v.Name == dummyKsymName
	}
	if sawDummy != dummy {
		t.Errorf("dummy_ksym in a slot = %v, want %v", sawDummy, dummy)
	}
	for i := range spec.Types {
		fn := &spec.Types[i]
		if fn.Kind == btf.KindFunc && fn.Vlen == btfFuncExtern {
			t.Errorf("function %s keeps extern linkage", fn.Name)
		}
	}
}

// TestKsymsDummyVar checks the dummy_ksym rules on synthetic BTF: no .ksyms
// DATASEC or one without functions adds nothing; a function adds an
// allocated VAR of the first 32-bit integer, reusing an existing
// "dummy_ksym" string, or of void when there is no such integer. An unnamed
// typed parameter of the function takes the dummy name; a named one and the
// variadic marker keep theirs.
func TestKsymsDummyVar(t *testing.T) {
	strs := "\x00int\x00short\x00f\x00.ksyms\x00a\x00dummy_ksym\x00"
	off := func(s string) uint32 { return uint32(strings.Index(strs, "\x00"+s+"\x00") + 1) }
	types := []btf.Type{
		{Kind: btf.KindVoid},
		{NameOff: off("short"), Kind: btf.KindInt, SizeOrType: 2, Int: &btf.Int{Encoding: 16}},
		{NameOff: off("int"), Kind: btf.KindInt, SizeOrType: 4, Int: &btf.Int{Encoding: 32}},
		{Kind: btf.KindFuncProto, Params: []btf.Param{{Type: 2}, {NameOff: off("a"), Type: 2}, {}}},
		{NameOff: off("f"), Kind: btf.KindFunc, Vlen: btfFuncExtern, SizeOrType: 3},
		{NameOff: off(".ksyms"), Kind: btf.KindDatasec, DataSec: []btf.VarSecInfo{{Type: 4}}},
	}

	spec := newTestSpec(t, types[:3], strs)
	if id, err := addDummyKsymVar(spec); id != 0 || err != nil {
		t.Fatalf("without .ksyms: %d, %v", id, err)
	}

	spec = newTestSpec(t, types, strs)
	id, err := addDummyKsymVar(spec)
	if err != nil {
		t.Fatalf("addDummyKsymVar: %v", err)
	}
	dummy := &spec.Types[id]
	if dummy.Name != dummyKsymName || dummy.NameOff != off(dummyKsymName) || dummy.SizeOrType != 2 ||
		dummy.Var.Linkage != btf.VarGlobalAllocated || len(spec.Strings) != len(strs) {
		t.Fatalf("dummy = %+v, strings %d, want an allocated int VAR reusing the string", dummy, len(spec.Strings))
	}

	externs := []externDesc{{typ: extKsym, name: "f"}}
	if err := layoutKsyms(spec, 5, id, externs); err != nil {
		t.Fatalf("layoutKsyms: %v", err)
	}
	reparsed, err := btf.Parse(spec.Raw(), binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse rewritten BTF: %v", err)
	}
	proto := reparsed.Types[3].Params
	if proto[0].Name != dummyKsymName || proto[1].Name != "a" || proto[2].NameOff != 0 {
		t.Errorf("params = %+v, want the first named dummy_ksym", proto)
	}
	if fn := reparsed.Types[4]; fn.Vlen != btfFuncGlobal {
		t.Errorf("function linkage = %d, want global", fn.Vlen)
	}
	if sec := reparsed.Types[5]; sec.SizeOrType != 4 || sec.DataSec[0] != (btf.VarSecInfo{Type: id, Offset: 0, Size: 4}) {
		t.Errorf("DATASEC = %d %+v, want one dummy slot", sec.SizeOrType, sec.DataSec)
	}

	if err := layoutKsyms(spec, 5, id, nil); !errors.Is(err, unix.ESRCH) {
		t.Errorf("slot without extern: %v, want ESRCH", err)
	}

	noInt := newTestSpec(t, []btf.Type{types[0], types[1], types[1], types[3], types[4], types[5]}, strs)
	if id, err := addDummyKsymVar(noInt); err != nil || noInt.Types[id].SizeOrType != 0 {
		t.Fatalf("without int: %d, %v, want a void VAR", id, err)
	}
}

// newTestSpec builds a spec from types and the string table strs.
func newTestSpec(t *testing.T, types []btf.Type, strs string) *btf.Spec {
	t.Helper()

	spec, err := btf.NewSpec(binary.NativeEndian, types, []byte(strs))
	if err != nil {
		t.Fatalf("NewSpec: %v", err)
	}
	for i := range spec.Types {
		if spec.Types[i].Name, err = spec.String(spec.Types[i].NameOff); err != nil {
			t.Fatalf("type %d name: %v", i, err)
		}
	}
	return spec
}

// errnoOf returns the errno err carries, 0 for nil.
func errnoOf(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	return errnoFromError(err)
}

// kallsymsEntry is one entry the kallsyms reader passed to its callback.
type kallsymsEntry struct {
	addr uint64
	typ  byte
	name string
}

// TestKallsymsParse reads synthetic /proc/kallsyms text: plain and module
// entries, a name longer than the 499 characters the reader keeps, an
// address with a 0x prefix, blank lines, and malformed entries, which stop
// the read with EINVAL after the entries before them.
func TestKallsymsParse(t *testing.T) {
	long := strings.Repeat("x", 600)
	tests := []struct {
		name  string
		input string
		want  []kallsymsEntry
		errno syscall.Errno
	}{
		{"empty", "", nil, 0},
		{"blank", "\n\n  \n", nil, 0},
		{"entries", "ffffffff81000000 T _stext\n0000000000001234 D bpf_prog_active\n", []kallsymsEntry{
			{0xffffffff81000000, 'T', "_stext"},
			{0x1234, 'D', "bpf_prog_active"},
		}, 0},
		{"module", "ffffffffc0a01000 t mod_func\t[mod]\nffffffffc0a02000 d mod_var.llvm.123\t[mod]", []kallsymsEntry{
			{0xffffffffc0a01000, 't', "mod_func"},
			{0xffffffffc0a02000, 'd', "mod_var.llvm.123"},
		}, 0},
		{"long name", "10 T " + long + " tail\n20 T next\n", []kallsymsEntry{
			{0x10, 'T', long[:kallsymsNameMax]},
			{0x20, 'T', "next"},
		}, 0},
		{"prefix", "0x10 T a\n", []kallsymsEntry{{0x10, 'T', "a"}}, 0},
		{"no address", "10 T a\nzz T b\n", []kallsymsEntry{{0x10, 'T', "a"}}, unix.EINVAL},
		{"no type", "10", nil, unix.EINVAL},
		{"no name", "10 T", nil, unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []kallsymsEntry
			err := kallsymsParse(strings.NewReader(tt.input), func(addr uint64, typ byte, name string) error {
				got = append(got, kallsymsEntry{addr, typ, name})
				return nil
			})
			if errnoOf(err) != tt.errno {
				t.Fatalf("kallsymsParse = %v, want errno %d", err, tt.errno)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("entries = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestKallsymsResolve applies synthetic kallsyms text to the externs of
// link_ksyms_weak.bpf.o. Only .ksyms variables take an address: a
// function's entry is ignored. A local data symbol with an LTO .llvm. suffix
// matches the plain name, another type letter does not. A repeated entry
// with the same address is fine, a different one is ambiguous.
func TestKallsymsResolve(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]uint64
		errno syscall.Errno
	}{
		{"variables", "1000 D bpf_prog_active\n2000 T gobpfgo_missing_kfunc\n3000 D gobpfgo_missing_var\n",
			map[string]uint64{"bpf_prog_active": 0x1000, "gobpfgo_missing_var": 0x3000}, 0},
		{"llvm suffix", "1000 d bpf_prog_active.llvm.42\n2000 D gobpfgo_missing_sym.llvm.7\n",
			map[string]uint64{"bpf_prog_active": 0x1000}, 0},
		{"same address", "1000 D bpf_prog_active\n1000 d bpf_prog_active\n",
			map[string]uint64{"bpf_prog_active": 0x1000}, 0},
		{"ambiguous", "1000 D bpf_prog_active\n2000 d bpf_prog_active\n", nil, unix.EINVAL},
		{"unprivileged", "0000000000000000 D bpf_prog_active\n",
			map[string]uint64{"bpf_prog_active": 0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := openProg(t, ksymsWeakProg)
			err := kallsymsParse(strings.NewReader(tt.input), func(addr uint64, typ byte, name string) error {
				return kallsymsCb(obj.externs, obj.btf, addr, typ, name)
			})
			if errnoOf(err) != tt.errno {
				t.Fatalf("resolve = %v, want errno %d", err, tt.errno)
			}
			if tt.errno != 0 {
				return
			}
			got := map[string]uint64{}
			for _, ext := range obj.externs {
				if ext.isSet {
					got[ext.name] = ext.ksym.addr
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("resolved = %#x, want %#x", got, tt.want)
			}
		})
	}
}

// TestBpfCoreEssentialNameLen checks the flavor suffix rule kernel function
// names follow: the name ends before the last triple underscore that has a
// non-underscore on both sides.
func TestBpfCoreEssentialNameLen(t *testing.T) {
	tests := map[string]string{
		"bpf_rcu_read_lock":     "",
		"bpf_kfunc___v2":        "bpf_kfunc",
		"a___b___c":             "a___b",
		"a____b":                "",
		"___a":                  "",
		"a___":                  "",
		"a___b":                 "a",
		"ab":                    "",
		"struct___flavor_one__": "struct",
	}
	for name, want := range tests {
		if got := essentialName(name); got != want {
			t.Errorf("essentialName(%q) = %q, want %q", name, got, want)
		}
	}
}
