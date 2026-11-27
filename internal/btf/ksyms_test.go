// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// buildSpec encodes types and strs and parses the blob back, so the result
// has names resolved like a spec read from an object.
func buildSpec(t *testing.T, types []Type, strs string) *Spec {
	t.Helper()

	built, err := NewSpec(binary.LittleEndian, types, []byte(strs))
	if err != nil {
		t.Fatalf("NewSpec: %v", err)
	}
	spec, err := Parse(built.Raw(), binary.LittleEndian)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return spec
}

// TestParseSplit parses a module's split BTF on top of a base: the module
// types continue the base IDs, their names may come from either string
// table, their references reach base types, and Find sees only the module.
func TestParseSplit(t *testing.T) {
	base := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
		{NameOff: 5, Kind: KindFunc, SizeOrType: 3},
		{Kind: KindFuncProto},
	}, "\x00int\x00shared\x00")

	strOff := uint32(len(base.Strings))
	module, err := NewSpec(binary.LittleEndian, []Type{
		{Kind: KindVoid},
		{NameOff: strOff + 1, Kind: KindVar, SizeOrType: 1, Var: &Var{Linkage: VarGlobalAllocated}},
		{NameOff: 5, Kind: KindFunc, SizeOrType: 3},
	}, []byte("\x00mod_var\x00"))
	if err != nil {
		t.Fatalf("module NewSpec: %v", err)
	}

	split, err := ParseSplit(module.Raw(), binary.LittleEndian, base)
	if err != nil {
		t.Fatalf("ParseSplit: %v", err)
	}
	if split.StartID() != 4 || base.StartID() != 1 {
		t.Fatalf("start IDs = %d and %d, want 4 and 1", split.StartID(), base.StartID())
	}

	v, err := split.TypeByID(4)
	if err != nil || v.Name != "mod_var" || v.ID != 4 || v.Kind != KindVar {
		t.Fatalf("type 4 = %+v, %v, want the module VAR", v, err)
	}
	fn, err := split.TypeByID(5)
	if err != nil || fn.Name != "shared" || fn.Kind != KindFunc {
		t.Fatalf("type 5 = %+v, %v, want the module FUNC named from the base", fn, err)
	}
	if typ, err := split.TypeByID(v.SizeOrType); err != nil || typ.Name != "int" {
		t.Fatalf("module VAR type = %+v, %v, want the base int", typ, err)
	}
	if _, err := split.TypeByID(6); err == nil {
		t.Fatal("type 6 exists")
	}
	if got := split.Find("shared", KindFunc); got == nil || got.ID != 5 {
		t.Fatalf("Find(shared) = %+v, want the module's own type 5", got)
	}
	if got := split.Find("int", KindInt); got != nil {
		t.Fatalf("Find(int) = %+v, want nil for a base type", got)
	}
	if _, err := split.AddVar("x", VarGlobalAllocated, 1); err == nil {
		t.Fatal("AddVar on split BTF succeeded")
	}
	if _, err := ParseSplit(module.Raw(), binary.LittleEndian, nil); err == nil {
		t.Fatal("ParseSplit without a base succeeded")
	}
}

// TestParseSplitKernel parses one module BTF of the running kernel on top of
// vmlinux, when both are readable, and resolves every type name. Parse alone
// cannot read module BTF, whose names refer to the vmlinux strings.
func TestParseSplitKernel(t *testing.T) {
	vmlinuxData, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Skipf("kernel BTF unavailable: %v", err)
	}
	modules, _ := filepath.Glob("/sys/kernel/btf/*")
	var moduleData []byte
	for _, path := range modules {
		if filepath.Base(path) == "vmlinux" {
			continue
		}
		if moduleData, err = os.ReadFile(path); err == nil {
			break
		}
	}
	if moduleData == nil {
		t.Skip("no readable module BTF")
	}

	vmlinux, err := Parse(vmlinuxData, binary.NativeEndian)
	if err != nil {
		t.Fatalf("Parse vmlinux: %v", err)
	}
	split, err := ParseSplit(moduleData, binary.NativeEndian, vmlinux)
	if err != nil {
		t.Fatalf("ParseSplit: %v", err)
	}
	if split.StartID() != uint32(len(vmlinux.Types)) {
		t.Fatalf("start ID = %d, want %d", split.StartID(), len(vmlinux.Types))
	}
	for i := 1; i < len(split.Types); i++ {
		if split.Types[i].ID != split.StartID()+uint32(i)-1 {
			t.Fatalf("own type %d has ID %d", i, split.Types[i].ID)
		}
	}
}

// TestAddVar appends VARs: an existing name reuses its string, a new one is
// appended, and the rebuilt blob parses back with the new type and the old
// ones unchanged. An empty name and an unknown linkage are rejected.
func TestAddVar(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
	}, "\x00int\x00dummy\x00")
	strs := len(spec.Strings)

	id, err := spec.AddVar("dummy", VarGlobalAllocated, 1)
	if err != nil || id != 2 || spec.Types[id].NameOff != 5 || len(spec.Strings) != strs {
		t.Fatalf("AddVar(dummy) = %d, %v, name at %d; want 2 reusing offset 5", id, err, spec.Types[id].NameOff)
	}
	id, err = spec.AddVar("fresh", VarStatic, 0)
	if err != nil || id != 3 || spec.Types[id].NameOff != uint32(strs) {
		t.Fatalf("AddVar(fresh) = %d, %v, want 3 appended at %d", id, err, strs)
	}

	reparsed, err := Parse(spec.Raw(), binary.LittleEndian)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(reparsed.Types) != 4 || reparsed.Types[1].Name != "int" {
		t.Fatalf("types = %+v", reparsed.Types)
	}
	for id, want := range map[int]Type{2: {Name: "dummy", SizeOrType: 1}, 3: {Name: "fresh"}} {
		got := reparsed.Types[id]
		if got.Kind != KindVar || got.Name != want.Name || got.SizeOrType != want.SizeOrType {
			t.Errorf("type %d = %+v, want VAR %s of type %d", id, got, want.Name, want.SizeOrType)
		}
	}
	if !bytes.HasSuffix(reparsed.Strings, []byte("fresh\x00")) {
		t.Errorf("strings = %q, want fresh appended", reparsed.Strings)
	}

	if _, err := spec.AddVar("", VarStatic, 0); err == nil {
		t.Error("AddVar with an empty name succeeded")
	}
	if _, err := spec.AddVar("x", 3, 0); err == nil {
		t.Error("AddVar with linkage 3 succeeded")
	}
}

// TestSetters rewrites a VAR type, a FUNC linkage, a parameter name and a
// DATASEC entry and requires the raw blob to parse back with the changes,
// and the setters to reject the wrong kinds and indexes.
func TestSetters(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
		{NameOff: 5, Kind: KindVar, SizeOrType: 0, Var: &Var{Linkage: VarGlobalExtern}},
		{Kind: KindFuncProto, Params: []Param{{Type: 1}}},
		{NameOff: 7, Kind: KindFunc, Vlen: 2, SizeOrType: 3},
		{NameOff: 9, Kind: KindDatasec, DataSec: []VarSecInfo{{Type: 2}, {Type: 4}}},
	}, "\x00int\x00v\x00f\x00.ksyms\x00")

	steps := []error{
		spec.SetVarType(2, 1),
		spec.SetFuncLinkage(4, 1),
		spec.SetParamNameOff(3, 0, 5),
		spec.SetDatasecVar(5, 1, VarSecInfo{Type: 2, Offset: 4, Size: 4}),
	}
	for i, err := range steps {
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}

	reparsed, err := Parse(spec.Raw(), binary.LittleEndian)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, s := range []*Spec{spec, reparsed} {
		if s.Types[2].SizeOrType != 1 || s.Types[4].Vlen != 1 || s.Types[4].Kind != KindFunc ||
			s.Types[3].Params[0].Name != "v" || s.Types[5].DataSec[1] != (VarSecInfo{Type: 2, Offset: 4, Size: 4}) {
			t.Fatalf("types = %+v", s.Types)
		}
	}

	bad := []error{
		spec.SetVarType(1, 1),
		spec.SetFuncLinkage(2, 1),
		spec.SetParamNameOff(4, 0, 1),
		spec.SetParamNameOff(3, 1, 1),
		spec.SetParamNameOff(3, 0, 1000),
		spec.SetDatasecVar(2, 0, VarSecInfo{}),
		spec.SetDatasecVar(5, 2, VarSecInfo{}),
	}
	for i, err := range bad {
		if err == nil {
			t.Errorf("bad step %d succeeded", i)
		}
	}
}

// TestTypesAreCompat checks the extern type compatibility rules: kinds must
// match, with the two enum kinds as one; aggregates, enums and forward
// declarations match by kind alone; integers match unless one has a bit
// offset; pointers and arrays compare their targets; function prototypes
// compare the parameter count, each parameter and the return type. Below
// the two types modifiers and typedefs are skipped on both sides, but the
// two types themselves are compared by kind first, as libbpf does, so a
// top-level typedef does not match its target.
func TestTypesAreCompat(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},          // 1 int
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 2<<16 | 30}},  // 2 int with a bit offset
		{NameOff: 5, Kind: KindStruct, SizeOrType: 4},                                // 3 struct
		{NameOff: 5, Kind: KindUnion, SizeOrType: 8},                                 // 4 union
		{NameOff: 5, Kind: KindEnum, SizeOrType: 4},                                  // 5 enum
		{NameOff: 5, Kind: KindEnum64, SizeOrType: 8},                                // 6 enum64
		{Kind: KindPtr, SizeOrType: 1},                                               // 7 int *
		{Kind: KindPtr, SizeOrType: 3},                                               // 8 struct *
		{Kind: KindConst, SizeOrType: 1},                                             // 9 const int
		{NameOff: 7, Kind: KindTypedef, SizeOrType: 9},                               // 10 typedef const int
		{Kind: KindArray, Array: &Array{Type: 1, IndexType: 1, Nelems: 4}},           // 11 int[4]
		{Kind: KindArray, Array: &Array{Type: 3, IndexType: 1, Nelems: 4}},           // 12 struct[4]
		{Kind: KindFuncProto, SizeOrType: 1, Params: []Param{{Type: 7}}},             // 13 int (int *)
		{Kind: KindFuncProto, SizeOrType: 10, Params: []Param{{Type: 7}}},            // 14 typedef (int *)
		{Kind: KindFuncProto, SizeOrType: 1, Params: []Param{{Type: 8}}},             // 15 int (struct *)
		{Kind: KindFuncProto, SizeOrType: 1},                                         // 16 int (void)
		{Kind: KindFuncProto, SizeOrType: 3, Params: []Param{{Type: 7}}},             // 17 struct (int *)
		{Kind: KindFwd, NameOff: 5},                                                  // 18 fwd
		{NameOff: 7, Kind: KindFloat, SizeOrType: 4},                                 // 19 float
		{Kind: KindFuncProto, SizeOrType: 0, Params: []Param{{Type: 1}, {Type: 0}}},  // 20 void (int, ...)
		{Kind: KindFuncProto, SizeOrType: 0, Params: []Param{{Type: 10}, {Type: 0}}}, // 21 void (typedef, ...)
		{Kind: KindVolatile, SizeOrType: 5},                                          // 22 volatile enum
		{Kind: KindPtr, SizeOrType: 7},                                               // 23 int **
		{Kind: KindPtr, SizeOrType: 11},                                              // 24 int (*)[4]
		{Kind: KindPtr, SizeOrType: 10},                                              // 25 typedef const int *
		{Kind: KindPtr, SizeOrType: 22},                                              // 26 volatile enum *
		{Kind: KindPtr, SizeOrType: 6},                                               // 27 enum64 *
	}, "\x00int\x00s\x00t\x00")

	tests := []struct {
		name          string
		local, target uint32
		want          bool
	}{
		{"int", 1, 1, true},
		{"void", 0, 0, true},
		{"bit offset", 1, 2, false},
		{"struct", 3, 3, true},
		{"struct union", 3, 4, false},
		{"enum enum64", 5, 6, true},
		{"enum struct", 5, 3, false},
		{"pointer", 7, 7, true},
		{"pointer target", 7, 8, false},
		{"top-level typedef", 10, 1, false},
		{"modifiers below a pointer", 25, 7, true},
		{"modifier on enum below a pointer", 26, 27, true},
		{"array", 11, 11, true},
		{"array element", 11, 12, false},
		{"proto", 13, 14, true},
		{"proto param", 13, 15, false},
		{"proto count", 13, 16, false},
		{"proto return", 13, 17, false},
		{"fwd", 18, 18, true},
		{"float", 19, 19, false},
		{"variadic", 20, 21, true},
		{"pointer chain", 23, 23, true},
		{"pointer to array", 24, 24, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TypesAreCompat(spec, tt.local, spec, tt.target)
			if got != tt.want || err != nil {
				t.Fatalf("TypesAreCompat(%d, %d) = %v, %v, want %v", tt.local, tt.target, got, err, tt.want)
			}
		})
	}

	if _, err := TypesAreCompat(spec, 1, spec, 99); err == nil {
		t.Error("an unknown type ID compared without an error")
	}
}

// TestTypesAreCompatDepth builds a pointer chain longer than the 32 steps
// libbpf follows and requires an error instead of an answer.
func TestTypesAreCompatDepth(t *testing.T) {
	types := []Type{{Kind: KindVoid}, {NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}}}
	for i := 0; i < 40; i++ {
		types = append(types, Type{Kind: KindPtr, SizeOrType: uint32(len(types) - 1)})
	}
	spec := buildSpec(t, types, "\x00int\x00")
	top := uint32(len(types) - 1)

	if ok, err := TypesAreCompat(spec, top, spec, top); ok || err == nil {
		t.Fatalf("TypesAreCompat over 40 pointers = %v, %v, want an error", ok, err)
	}
	if ok, err := TypesAreCompat(spec, 20, spec, 20); !ok || err != nil {
		t.Fatalf("TypesAreCompat over 19 pointers = %v, %v, want true", ok, err)
	}
}
