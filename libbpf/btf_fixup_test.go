// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

const (
	subprogHiddenObject = "../testdata/progs/subprog_hidden.bpf.o"
	subprogArgCtxObject = "../testdata/progs/subprog_arg_ctx.bpf.o"
)

// funcLinkage returns the linkage of the BTF FUNC named name.
func funcLinkage(t *testing.T, spec *btf.Spec, name string) uint32 {
	t.Helper()

	fn := spec.Find(name, btf.KindFunc)
	if fn == nil {
		t.Fatalf("no BTF FUNC %s", name)
	}
	return fn.Vlen
}

// TestSubprogHiddenOpen opens subprog_hidden.bpf.o and checks which
// functions are marked for static BTF linkage: the global ones with hidden
// visibility, the main program among them, but neither the default-visibility
// global subprogram nor the static subprograms of subprog.bpf.o. Open
// changes no linkage, so the object and its BTF match libbpf's after open.
func TestSubprogHiddenOpen(t *testing.T) {
	obj := openSubprogObject(t, "subprog_hidden.bpf.o")
	checkOpenFixture(t, obj, loadOpenFixture(t, "open-subprog-hidden.json"))

	plain := openSubprogObject(t, "subprog.bpf.o")
	for _, w := range []struct {
		obj    *BpfObject
		name   string
		global bool
		marked bool
	}{
		{obj, "subprog_hidden", true, true},
		{obj, "subprog_visible", true, false},
		{obj, "handle_hidden", true, true},
		{plain, "subprog_add", true, false},
		{plain, "subprog_count", false, false},
		{plain, "subprog_bump", false, false},
	} {
		p := findFunction(t, w.obj, w.name)
		if p.symGlobal != w.global || p.markBtfStatic != w.marked {
			t.Errorf("%s: global %v, marked static %v; want %v, %v", w.name, p.symGlobal, p.markBtfStatic, w.global, w.marked)
		}
		if !p.symGlobal && funcLinkage(t, w.obj.btf, w.name) != btf.FuncStatic {
			t.Errorf("static %s has linkage %d", w.name, funcLinkage(t, w.obj.btf, w.name))
		}
		if p.symGlobal && funcLinkage(t, w.obj.btf, w.name) != btf.FuncGlobal {
			t.Errorf("%s has linkage %d after open", w.name, funcLinkage(t, w.obj.btf, w.name))
		}
	}
}

// TestMarkBtfStatic applies the load's static-linkage fixup. In
// subprog_hidden.bpf.o only the hidden .text subprogram's FUNC changes: the
// hidden main program and the default-visibility subprogram stay global. In
// subprog.bpf.o, which has no hidden function, the BTF does not change.
func TestMarkBtfStatic(t *testing.T) {
	obj := openSubprogObject(t, "subprog_hidden.bpf.o")
	if err := markBtfStatic(obj); err != nil {
		t.Fatalf("markBtfStatic: %v", err)
	}
	for name, want := range map[string]uint32{
		"subprog_hidden":  btf.FuncStatic,
		"subprog_visible": btf.FuncGlobal,
		"handle_hidden":   btf.FuncGlobal,
	} {
		if got := funcLinkage(t, obj.btf, name); got != want {
			t.Errorf("%s linkage = %d, want %d", name, got, want)
		}
	}
	reparsed, err := btf.Parse(obj.btf.Raw(), obj.elf.ByteOrder)
	if err != nil || funcLinkage(t, reparsed, "subprog_hidden") != btf.FuncStatic {
		t.Errorf("raw BTF does not carry the static linkage: %v", err)
	}

	plain := openSubprogObject(t, "subprog.bpf.o")
	raw := bytes.Clone(plain.btf.Raw())
	if err := markBtfStatic(plain); err != nil || !bytes.Equal(plain.btf.Raw(), raw) {
		t.Errorf("markBtfStatic changed subprog.bpf.o: %v", err)
	}
}

// argCtxType is one type an arg:ctx test expects: its kind, name, the type
// it refers to and, for a decl tag, the component it tags.
type argCtxType struct {
	kind btf.Kind
	name string
	ref  uint32
	comp int32
}

// checkArgCtxTypes checks that spec holds exactly the types want from ID
// first on, with global linkage for every FUNC.
func checkArgCtxTypes(t *testing.T, spec *btf.Spec, first uint32, want []argCtxType) {
	t.Helper()

	if len(spec.Types) != int(first)+len(want) {
		t.Fatalf("%d types, want %d", len(spec.Types), int(first)+len(want))
	}
	for i, w := range want {
		got := spec.Types[first+uint32(i)]
		if got.Kind != w.kind || got.Name != w.name || got.SizeOrType != w.ref {
			t.Errorf("type %d = %v %q -> %d, want %v %q -> %d", got.ID, got.Kind, got.Name, got.SizeOrType, w.kind, w.name, w.ref)
		}
		if got.Kind == btf.KindFunc && got.Vlen != btf.FuncGlobal {
			t.Errorf("FUNC %d has linkage %d", got.ID, got.Vlen)
		}
		if got.Kind == btf.KindDeclTag && got.DeclTag.ComponentIdx != w.comp {
			t.Errorf("DECL_TAG %d tags component %d, want %d", got.ID, got.DeclTag.ComponentIdx, w.comp)
		}
	}
}

// protoParams returns the names and types of the FUNC_PROTO protoID's
// parameters.
func protoParams(t *testing.T, spec *btf.Spec, protoID uint32) []btf.Param {
	t.Helper()

	proto := spec.Types[protoID]
	if proto.Kind != btf.KindFuncProto {
		t.Fatalf("type %d is %v, not a FUNC_PROTO", protoID, proto.Kind)
	}
	var params []btf.Param
	for _, p := range proto.Params {
		name, err := spec.String(p.NameOff)
		if err != nil {
			t.Fatalf("FUNC_PROTO %d parameter name: %v", protoID, err)
		}
		params = append(params, btf.Param{Name: name, Type: p.Type})
	}
	return params
}

// TestArgCtxFixup opens subprog_arg_ctx.bpf.o, which matches libbpf's object
// and BTF after open, and relocates it as on a kernel without arg:ctx
// support. Each main program gets its own copy of subprog_arg_ctx's
// FUNC_PROTO and FUNC, its own empty struct bpf_user_pt_regs_t and pointer,
// and a copy of the decl tag, in libbpf's order. The second program's loop
// meets the first one's tag copy too and skips it, because its records do
// not name that clone. Each program's record for the subprogram names its
// own clone, whose ctx parameter points to the struct. The original types,
// the instructions and the line records do not change, the struct name is
// the only new string, the BTF parses back to the same types and the object
// BTF dumps with the new struct.
func TestArgCtxFixup(t *testing.T) {
	want := loadSubprogFixture(t, "subprog-arg-ctx.json")
	obj := openSubprogObject(t, "subprog_arg_ctx.bpf.o")
	checkOpenFixture(t, obj, loadOpenFixture(t, "open-subprog-arg-ctx.json"))
	openTypes, openStrings := uint32(len(obj.btf.Types)), string(obj.btf.Strings)
	if openTypes != 17 {
		t.Fatalf("%d types after open, want 17", openTypes)
	}

	codes, err := relocateWithoutKernelArgCtx(t, obj, objectExt(t, obj), argCtxTagMissing)
	if err != nil {
		t.Fatalf("relocate: %v", err)
	}

	wantTypes := []argCtxType{
		{btf.KindFuncProto, "", 5, 0}, {btf.KindFunc, "subprog_arg_ctx", 17, 0},
		{btf.KindStruct, "bpf_user_pt_regs_t", 0, 0}, {btf.KindPtr, "", 19, 0}, {btf.KindDeclTag, argCtxTag, 18, 1},
		{btf.KindFuncProto, "", 5, 0}, {btf.KindFunc, "subprog_arg_ctx", 22, 0},
		{btf.KindStruct, "bpf_user_pt_regs_t", 0, 0}, {btf.KindPtr, "", 24, 0}, {btf.KindDeclTag, argCtxTag, 23, 1},
	}
	checkArgCtxTypes(t, obj.btf, openTypes, wantTypes)
	for protoID, ctxType := range map[uint32]uint32{4: 3, 17: 20, 22: 25} {
		want := []btf.Param{{Name: "delta", Type: 1}, {Name: "ctx", Type: ctxType}}
		if got := protoParams(t, obj.btf, protoID); !slices.Equal(got, want) {
			t.Errorf("FUNC_PROTO %d parameters = %+v, want %+v", protoID, got, want)
		}
	}
	if got := string(obj.btf.Strings); got != openStrings+"bpf_user_pt_regs_t\x00" {
		t.Errorf("strings grew by %q, want only the struct name", got[min(len(got), len(openStrings)):])
	}

	for i, recs := range [][]subprogFixtureFuncInfo{
		{{InsnOff: 0, TypeID: 9}, {InsnOff: 6, TypeID: 18}},
		{{InsnOff: 0, TypeID: 11}, {InsnOff: 6, TypeID: 23}},
	} {
		w := want.Programs[i]
		if got := decodeFuncInfo(codes[i].funcInfo); !slices.Equal(got, recs) {
			t.Errorf("%s: function records = %+v, want %+v", w.Name, got, recs)
		}
		if got := decodeLineInfo(codes[i].lineInfo); !slices.Equal(got, w.LineInfo) {
			t.Errorf("%s: line records changed", w.Name)
		}
		if !bytes.Equal(codes[i].insns, mapLoadsByDescriptor(mustDecodeHex(t, w.Insns))) {
			t.Errorf("%s: instructions changed", w.Name)
		}
	}

	reparsed, err := btf.Parse(obj.btf.Raw(), obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("parse the fixed-up BTF: %v", err)
	}
	checkArgCtxTypes(t, reparsed, openTypes, wantTypes)
	if dump := dumpAllTypes(t, BpfObjectBTF(obj)); !strings.Contains(dump, "struct bpf_user_pt_regs_t {};") {
		t.Errorf("dump of the fixed-up BTF has no context struct:\n%s", dump)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// TestArgCtxFixupThenMarkStatic marks subprog_arg_ctx hidden. The arg:ctx
// fixup runs first and clones its FUNC with global linkage; the
// static-linkage fixup then changes only the first global FUNC with the
// name, the original, so the records keep naming global clones.
func TestArgCtxFixupThenMarkStatic(t *testing.T) {
	obj := openSubprogObject(t, "subprog_arg_ctx.bpf.o")
	findFunction(t, obj, "subprog_arg_ctx").markBtfStatic = true

	if _, err := relocateWithoutKernelArgCtx(t, obj, objectExt(t, obj), argCtxTagMissing); err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if err := markBtfStatic(obj); err != nil {
		t.Fatalf("markBtfStatic: %v", err)
	}
	for id, want := range map[int]uint32{6: btf.FuncStatic, 18: btf.FuncGlobal, 23: btf.FuncGlobal} {
		if fn := obj.btf.Types[id]; fn.Kind != btf.KindFunc || fn.Name != "subprog_arg_ctx" || fn.Vlen != want {
			t.Errorf("type %d = %v %s linkage %d, want subprog_arg_ctx linkage %d", id, fn.Kind, fn.Name, fn.Vlen, want)
		}
	}
}

// argCtxStrings is the string table of the synthetic arg:ctx objects, and
// argCtxOff each name's offset in it.
var argCtxStrings, argCtxOff = btfStrTab("int", "prog", "sub", "x", "ctx", argCtxTag, "arg:other", "__sk_buff")

// btfStrTab builds a BTF string table from names and returns it with each
// name's offset.
func btfStrTab(names ...string) (string, map[string]uint32) {
	tab, off := "\x00", map[string]uint32{"": 0}
	for _, name := range names {
		off[name] = uint32(len(tab))
		tab += name + "\x00"
	}
	return tab, off
}

// Type IDs of the synthetic arg:ctx object.
const (
	argCtxVoidPtr  = 2
	argCtxSubProto = 5
	argCtxSub      = 6
	argCtxTagID    = 7
	argCtxNumTypes = 8
)

// argCtxTypes returns the types of a synthetic object: the main program
// prog(void *ctx) as FUNC [4] and the global subprogram sub(int x, void
// *ctx) as FUNC [6], with an arg:ctx decl tag on ctx as [7]. edit, when not
// nil, may change or extend the types before the spec is built.
func argCtxTypes(edit func([]btf.Type) []btf.Type) []btf.Type {
	types := []btf.Type{
		{Kind: btf.KindVoid},
		{NameOff: argCtxOff["int"], Kind: btf.KindInt, SizeOrType: 4, Int: &btf.Int{Encoding: 1<<24 | 32}},
		{Kind: btf.KindPtr},
		{Kind: btf.KindFuncProto, SizeOrType: 1, Params: []btf.Param{{NameOff: argCtxOff["ctx"], Type: argCtxVoidPtr}}},
		{NameOff: argCtxOff["prog"], Kind: btf.KindFunc, Vlen: btf.FuncGlobal, SizeOrType: 3},
		{Kind: btf.KindFuncProto, SizeOrType: 1, Params: []btf.Param{
			{NameOff: argCtxOff["x"], Type: 1}, {NameOff: argCtxOff["ctx"], Type: argCtxVoidPtr},
		}},
		{NameOff: argCtxOff["sub"], Kind: btf.KindFunc, Vlen: btf.FuncGlobal, SizeOrType: argCtxSubProto},
		argCtxDeclTag(argCtxSub, 1),
	}
	if edit != nil {
		types = edit(types)
	}
	return types
}

// argCtxDeclTag returns an arg:ctx decl tag on component comp of type ref.
func argCtxDeclTag(ref uint32, comp int32) btf.Type {
	return btf.Type{NameOff: argCtxOff[argCtxTag], Kind: btf.KindDeclTag, SizeOrType: ref, DeclTag: &btf.DeclTag{ComponentIdx: comp}}
}

// argCtxCalled are the function records of a main program that calls sub.
var argCtxCalled = funcInfoRecords([2]uint32{0, 4}, [2]uint32{5, argCtxSub})

// funcInfoRecords encodes struct bpf_func_info records, one per pair of
// instruction offset and FUNC ID.
func funcInfoRecords(recs ...[2]uint32) []byte {
	var buf []byte
	for _, rec := range recs {
		buf = binary.NativeEndian.AppendUint32(buf, rec[0])
		buf = binary.NativeEndian.AppendUint32(buf, rec[1])
	}
	return buf
}

// runArgCtxFixup runs the arg:ctx fixup on spec for a main program named
// progName of progType with the function records funcInfo, and returns the
// records after it.
func runArgCtxFixup(t *testing.T, spec *btf.Spec, ext *btf.ExtSpec, progName string, progType BpfProgType, funcInfo []byte, argCtxTag func() bool) []byte {
	t.Helper()

	obj := &BpfObject{btf: spec}
	code := &progCode{prog: &BpfProgram{name: progName, progType: progType}, funcInfo: bytes.Clone(funcInfo)}
	if err := fixupFuncInfo(obj, ext, code, argCtxTag); err != nil {
		t.Fatalf("fixupFuncInfo: %v", err)
	}
	return code.funcInfo
}

// TestArgCtxFixupSkips runs the arg:ctx fixup on synthetic objects where it
// must change neither the BTF nor the records: no .BTF.ext or no function
// records, a kernel that reads the tag, a program type without a named
// context struct, a tag on a static function, on an argument out of range,
// on the function itself or on a FUNC_PROTO, a tag with another name, a
// subprogram the program does not call, a scalar argument, which libbpf only
// warns about, and a pointer to the program's context struct already.
func TestArgCtxFixupSkips(t *testing.T) {
	setTag := func(f func(tag *btf.Type)) func([]btf.Type) []btf.Type {
		return func(types []btf.Type) []btf.Type {
			f(&types[argCtxTagID])
			return types
		}
	}
	tests := []struct {
		name      string
		edit      func([]btf.Type) []btf.Type
		progType  BpfProgType
		funcInfo  []byte
		noExt     bool
		supported bool
	}{
		{name: "no .BTF.ext", noExt: true},
		{name: "no function records", funcInfo: []byte{}},
		{name: "kernel reads the tag", supported: true},
		{name: "tracepoint", progType: BPF_PROG_TYPE_TRACEPOINT},
		{name: "static subprogram", edit: func(types []btf.Type) []btf.Type {
			types[argCtxSub].Vlen = btf.FuncStatic
			return types
		}},
		{name: "argument out of range", edit: setTag(func(tag *btf.Type) { tag.DeclTag.ComponentIdx = 2 })},
		{name: "tag on the function", edit: setTag(func(tag *btf.Type) { tag.DeclTag.ComponentIdx = -1 })},
		{name: "tag on a FUNC_PROTO", edit: setTag(func(tag *btf.Type) { tag.SizeOrType = argCtxSubProto })},
		{name: "other tag", edit: setTag(func(tag *btf.Type) { tag.NameOff = argCtxOff["arg:other"] })},
		{name: "not called", funcInfo: funcInfoRecords([2]uint32{0, 4})},
		{name: "scalar argument", edit: setTag(func(tag *btf.Type) { tag.DeclTag.ComponentIdx = 0 })},
		{name: "context struct pointer", progType: BPF_PROG_TYPE_SCHED_CLS, edit: func(types []btf.Type) []btf.Type {
			skb, ptr := uint32(len(types)), uint32(len(types)+1)
			types[argCtxSubProto].Params[1].Type = ptr
			return append(types,
				btf.Type{NameOff: argCtxOff["__sk_buff"], Kind: btf.KindStruct},
				btf.Type{Kind: btf.KindPtr, SizeOrType: skb})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := newTestSpec(t, argCtxTypes(tt.edit), argCtxStrings)
			progType, funcInfo, ext := tt.progType, argCtxCalled, &btf.ExtSpec{}
			if progType == 0 {
				progType = BPF_PROG_TYPE_KPROBE
			}
			if tt.funcInfo != nil {
				funcInfo = tt.funcInfo
			}
			if tt.noExt {
				ext = nil
			}
			raw := bytes.Clone(spec.Raw())

			got := runArgCtxFixup(t, spec, ext, "prog", progType, funcInfo, func() bool { return tt.supported })
			if !bytes.Equal(spec.Raw(), raw) || !bytes.Equal(got, funcInfo) {
				t.Errorf("the fixup changed the BTF or the records %x", got)
			}
		})
	}
}

// TestArgCtxFixupClone runs the arg:ctx fixup on synthetic objects that need
// it. One tagged argument gives one clone, struct, pointer and tag copy. Two
// tagged arguments give one clone and one struct and pointer, and a tag copy
// for each argument. A main program whose name is not a BTF string yet adds
// it to the table before the struct name, because libbpf creates the clone
// under that name and then renames it.
func TestArgCtxFixupClone(t *testing.T) {
	cloneTypes := func(first uint32) []argCtxType {
		return []argCtxType{
			{btf.KindFuncProto, "", 1, 0}, {btf.KindFunc, "sub", first, 0},
			{btf.KindStruct, "bpf_user_pt_regs_t", 0, 0}, {btf.KindPtr, "", first + 2, 0},
		}
	}
	twoArgs := func(types []btf.Type) []btf.Type {
		types[argCtxSubProto].Params[0].Type = argCtxVoidPtr
		types[argCtxTagID].DeclTag.ComponentIdx = 0
		return append(types, argCtxDeclTag(argCtxSub, 1))
	}
	tests := []struct {
		name     string
		progName string
		edit     func([]btf.Type) []btf.Type
		// first is the first new type; want are the types from the
		// last original one on, and clone the cloned FUNC_PROTO's
		// parameter types.
		first   uint32
		want    []argCtxType
		clone   []uint32
		strings string
	}{
		{
			name:     "one argument",
			progName: "prog",
			first:    argCtxNumTypes,
			want: append([]argCtxType{{btf.KindDeclTag, argCtxTag, argCtxSub, 1}},
				append(cloneTypes(8), argCtxType{btf.KindDeclTag, argCtxTag, 9, 1})...),
			clone:   []uint32{1, 11},
			strings: "bpf_user_pt_regs_t\x00",
		},
		{
			name:     "two arguments",
			progName: "prog",
			edit:     twoArgs,
			first:    argCtxNumTypes + 1,
			want: append([]argCtxType{{btf.KindDeclTag, argCtxTag, argCtxSub, 1}},
				append(cloneTypes(9), argCtxType{btf.KindDeclTag, argCtxTag, 10, 0}, argCtxType{btf.KindDeclTag, argCtxTag, 10, 1})...),
			clone:   []uint32{12, 12},
			strings: "bpf_user_pt_regs_t\x00",
		},
		{
			name:     "new program name",
			progName: "renamed",
			first:    argCtxNumTypes,
			want: append([]argCtxType{{btf.KindDeclTag, argCtxTag, argCtxSub, 1}},
				append(cloneTypes(8), argCtxType{btf.KindDeclTag, argCtxTag, 9, 1})...),
			clone:   []uint32{1, 11},
			strings: "renamed\x00bpf_user_pt_regs_t\x00",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := newTestSpec(t, argCtxTypes(tt.edit), argCtxStrings)
			recs := runArgCtxFixup(t, spec, &btf.ExtSpec{}, tt.progName, BPF_PROG_TYPE_KPROBE, argCtxCalled, argCtxTagMissing)

			checkArgCtxTypes(t, spec, tt.first-1, tt.want)
			wantRecs := []subprogFixtureFuncInfo{{InsnOff: 0, TypeID: 4}, {InsnOff: 5, TypeID: tt.first + 1}}
			if got := decodeFuncInfo(recs); !slices.Equal(got, wantRecs) {
				t.Errorf("records = %+v, want %+v", got, wantRecs)
			}
			var types []uint32
			for _, p := range protoParams(t, spec, tt.first) {
				types = append(types, p.Type)
			}
			if !slices.Equal(types, tt.clone) {
				t.Errorf("clone parameter types = %v, want %v", types, tt.clone)
			}
			if got := string(spec.Strings); got != argCtxStrings+tt.strings {
				t.Errorf("strings = %q, want %q appended", got, tt.strings)
			}
		})
	}
}

// TestNeedFuncArgTypeFixup checks which argument types the arg:ctx fixup
// rewrites for each program type: a void pointer, through modifiers and
// typedefs, always; a pointer to the program's context struct never; a
// kprobe's struct pt_regs pointer, also when spelled bpf_user_pt_regs_t
// through its typedef; a perf_event's pointer to the host's register struct;
// a raw tracepoint's 64-bit integer pointer. Anything else, a scalar among
// them, is left alone.
func TestNeedFuncArgTypeFixup(t *testing.T) {
	strs, off := btfStrTab("int", "u64", "u32", "pt_regs", "bpf_user_pt_regs_t", "user_pt_regs", "__sk_buff", "foo", "vptr", "bpf_perf_event_data")
	named := func(kind btf.Kind, name string, ref uint32) btf.Type {
		return btf.Type{NameOff: off[name], Kind: kind, SizeOrType: ref}
	}
	integer := func(name string, size, bits uint32) btf.Type {
		return btf.Type{NameOff: off[name], Kind: btf.KindInt, SizeOrType: size, Int: &btf.Int{Encoding: bits}}
	}
	spec := newTestSpec(t, []btf.Type{
		{Kind: btf.KindVoid},
		integer("int", 4, 1<<24|32),                     // [1]
		integer("u64", 8, 64),                           // [2]
		integer("u32", 4, 32),                           // [3]
		named(btf.KindStruct, "pt_regs", 0),             // [4]
		named(btf.KindStruct, "bpf_user_pt_regs_t", 0),  // [5]
		named(btf.KindTypedef, "bpf_user_pt_regs_t", 4), // [6] typedef struct pt_regs
		named(btf.KindStruct, "user_pt_regs", 0),        // [7]
		named(btf.KindStruct, "__sk_buff", 0),           // [8]
		named(btf.KindStruct, "foo", 0),                 // [9]
		named(btf.KindPtr, "", 0),                       // [10] void *
		named(btf.KindConst, "", 10),                    // [11] void *const
		named(btf.KindPtr, "", 13),                      // [12] const void *
		named(btf.KindConst, "", 0),                     // [13]
		named(btf.KindTypedef, "vptr", 10),              // [14] typedef void *vptr
		named(btf.KindPtr, "", 4),                       // [15] struct pt_regs *
		named(btf.KindPtr, "", 5),                       // [16] struct bpf_user_pt_regs_t *
		named(btf.KindPtr, "", 6),                       // [17] bpf_user_pt_regs_t *
		named(btf.KindPtr, "", 7),                       // [18] struct user_pt_regs *
		named(btf.KindPtr, "", 2),                       // [19] u64 *
		named(btf.KindPtr, "", 3),                       // [20] u32 *
		named(btf.KindPtr, "", 8),                       // [21] struct __sk_buff *
		named(btf.KindPtr, "", 9),                       // [22] struct foo *
		named(btf.KindStruct, "bpf_perf_event_data", 0), // [23]
		named(btf.KindPtr, "", 23),                      // [24] struct bpf_perf_event_data *
	}, strs)
	ptRegs := userPtRegsStruct() == "pt_regs"

	tests := []struct {
		progType BpfProgType
		argType  uint32
		want     bool
	}{
		{BPF_PROG_TYPE_KPROBE, 10, true},
		{BPF_PROG_TYPE_KPROBE, 11, true},
		{BPF_PROG_TYPE_KPROBE, 12, true},
		{BPF_PROG_TYPE_KPROBE, 14, true},
		{BPF_PROG_TYPE_KPROBE, 16, false},
		{BPF_PROG_TYPE_KPROBE, 15, true},
		{BPF_PROG_TYPE_KPROBE, 17, true},
		{BPF_PROG_TYPE_KPROBE, 18, false},
		{BPF_PROG_TYPE_KPROBE, 19, false},
		{BPF_PROG_TYPE_KPROBE, 22, false},
		{BPF_PROG_TYPE_KPROBE, 1, false},
		{BPF_PROG_TYPE_PERF_EVENT, 10, true},
		{BPF_PROG_TYPE_PERF_EVENT, 24, false},
		{BPF_PROG_TYPE_PERF_EVENT, 15, ptRegs},
		{BPF_PROG_TYPE_PERF_EVENT, 17, ptRegs},
		{BPF_PROG_TYPE_PERF_EVENT, 18, !ptRegs},
		{BPF_PROG_TYPE_RAW_TRACEPOINT, 19, true},
		{BPF_PROG_TYPE_RAW_TRACEPOINT, 20, false},
		{BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, 19, true},
		{BPF_PROG_TYPE_RAW_TRACEPOINT, 10, true},
		{BPF_PROG_TYPE_SCHED_CLS, 21, false},
		{BPF_PROG_TYPE_SCHED_CLS, 15, false},
		{BPF_PROG_TYPE_SCHED_CLS, 19, false},
		{BPF_PROG_TYPE_XDP, 21, false},
		{BPF_PROG_TYPE_XDP, 10, true},
	}
	for _, tt := range tests {
		ctxName := progCtxName(tt.progType)
		if got := needFuncArgTypeFixup(spec, tt.progType, tt.argType, ctxName); got != tt.want {
			t.Errorf("program type %d, argument type %d, context %s: %v, want %v", tt.progType, tt.argType, ctxName, got, tt.want)
		}
	}
}

// TestGlobalCtxMap checks the program types that have a named context
// struct, the kprobe one being the bpf_user_pt_regs_t typedef's name, and
// two that have none.
func TestGlobalCtxMap(t *testing.T) {
	if len(globalCtxMap) != 25 {
		t.Errorf("%d program types with a context struct, want 25", len(globalCtxMap))
	}
	for progType, want := range map[BpfProgType]string{
		BPF_PROG_TYPE_KPROBE:           "bpf_user_pt_regs_t",
		BPF_PROG_TYPE_PERF_EVENT:       "bpf_perf_event_data",
		BPF_PROG_TYPE_RAW_TRACEPOINT:   "bpf_raw_tracepoint_args",
		BPF_PROG_TYPE_CGROUP_SOCKOPT:   "bpf_sockopt",
		BPF_PROG_TYPE_SK_LOOKUP:        "bpf_sk_lookup",
		BPF_PROG_TYPE_NETFILTER:        "bpf_nf_ctx",
		BPF_PROG_TYPE_XDP:              "xdp_md",
		BPF_PROG_TYPE_SOCKET_FILTER:    "__sk_buff",
		BPF_PROG_TYPE_TRACEPOINT:       "",
		BPF_PROG_TYPE_TRACING:          "",
		BPF_PROG_TYPE_CGROUP_DEVICE:    "bpf_cgroup_dev_ctx",
		BPF_PROG_TYPE_LWT_SEG6LOCAL:    "__sk_buff",
		BPF_PROG_TYPE_SK_REUSEPORT:     "sk_reuseport_md",
		BPF_PROG_TYPE_CGROUP_SOCK_ADDR: "bpf_sock_addr",
	} {
		if got := progCtxName(progType); got != want {
			t.Errorf("context of program type %d = %q, want %q", progType, got, want)
		}
	}
}

// TestArgCtxTagProbeBTF parses the BTF the arg:ctx probe loads: a 32-byte
// header, and the int, the void pointer, the two prototypes, the global
// FUNCs a and b and the arg:ctx tag on b's only parameter.
func TestArgCtxTagProbeBTF(t *testing.T) {
	raw := argCtxTagBTF()
	spec, err := btf.Parse(raw, binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if spec.Header.HdrLen != rawBTFHdrLen || spec.Header.StrLen != 14 {
		t.Errorf("header = %+v, want a 32-byte header and 14 string bytes", spec.Header)
	}
	want := []argCtxType{
		{btf.KindInt, "a", 4, 0}, {btf.KindPtr, "", 0, 0},
		{btf.KindFuncProto, "", 1, 0}, {btf.KindFunc, "a", 3, 0},
		{btf.KindFuncProto, "", 1, 0}, {btf.KindFunc, "b", 5, 0},
		{btf.KindDeclTag, argCtxTag, 6, 0},
	}
	checkArgCtxTypes(t, spec, 1, want)
	for protoID, name := range map[uint32]string{3: "a", 5: "b"} {
		if got := protoParams(t, spec, protoID); !slices.Equal(got, []btf.Param{{Name: name, Type: 2}}) {
			t.Errorf("FUNC_PROTO %d parameters = %+v", protoID, got)
		}
	}
}

// TestBtfDeclTagProbeBTF parses the BTF the decl tag probe loads: a 32-byte
// header, five string bytes, a signed 32-bit int, a static variable tag of
// it and a decl tag named tag on the variable itself.
func TestBtfDeclTagProbeBTF(t *testing.T) {
	spec, err := btf.Parse(declTagBTF(), binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if spec.Header.HdrLen != rawBTFHdrLen || spec.Header.StrLen != 5 {
		t.Errorf("header = %+v, want a 32-byte header and 5 string bytes", spec.Header)
	}
	checkArgCtxTypes(t, spec, 1, []argCtxType{
		{btf.KindInt, "", 4, 0}, {btf.KindVar, "tag", 1, 0}, {btf.KindDeclTag, "tag", 2, -1},
	})
	if enc := spec.Types[1].Int; enc == nil || enc.Encoding != 1<<24|32 {
		t.Errorf("INT encoding = %+v, want signed 32 bits", enc)
	}
	if v := spec.Types[2].Var; v == nil || v.Linkage != btf.VarStatic {
		t.Errorf("VAR = %+v, want static linkage", v)
	}
}

// allBTFFeatures stands in for a kernel whose BTF feature probes all
// succeed; withoutDeclTag for one that lacks only BTF_KIND_DECL_TAG.
var (
	allBTFFeatures = btf.KernelFeatures{
		DeclTag: true, TypeTag: true, Enum64: true, QmarkDatasec: true, Float: true,
		Func: true, Datasec: true, GlobalFunc: true, Layout: true,
	}
	withoutDeclTag = btf.KernelFeatures{
		TypeTag: true, Enum64: true, QmarkDatasec: true, Float: true,
		Func: true, Datasec: true, GlobalFunc: true, Layout: true,
	}
)

// TestSanitizeBTF builds the BTF that the load passes to the kernel for
// subprog_arg_ctx.bpf.o after both load fixups, the arg:ctx clones and the
// static linkage of the subprogram marked hidden. A kernel with every BTF
// feature gets the object BTF itself. Without decl tags it gets a copy in
// which the compiled tag and each program's copy of it are one-byte INTs
// under the same IDs and names. Every other type, which carries the
// open-time DATASEC fixups and both load fixups, and the string table are
// the object BTF's. The object BTF keeps its decl tags and its bytes.
func TestSanitizeBTF(t *testing.T) {
	obj := openSubprogObject(t, "subprog_arg_ctx.bpf.o")
	findFunction(t, obj, "subprog_arg_ctx").markBtfStatic = true
	if _, err := relocateWithoutKernelArgCtx(t, obj, objectExt(t, obj), argCtxTagMissing); err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if err := markBtfStatic(obj); err != nil {
		t.Fatalf("markBtfStatic: %v", err)
	}
	fixed := bytes.Clone(obj.btf.Raw())

	native, err := sanitizeBTF(obj.btf, allBTFFeatures)
	if err != nil || !bytes.Equal(native, fixed) {
		t.Fatalf("BTF for a kernel with every BTF feature: %d bytes, error %v; want the object BTF", len(native), err)
	}
	raw, err := sanitizeBTF(obj.btf, withoutDeclTag)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if !bytes.Equal(obj.btf.Raw(), fixed) {
		t.Fatal("sanitizing changed the object BTF")
	}

	orig, err := btf.Parse(fixed, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("parse the object BTF: %v", err)
	}
	sanitized, err := btf.Parse(raw, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("parse the sanitized BTF: %v", err)
	}
	if len(sanitized.Types) != len(orig.Types) || !bytes.Equal(sanitized.Strings, orig.Strings) {
		t.Fatalf("sanitized BTF has %d types and %d string bytes, want %d and %d",
			len(sanitized.Types), len(sanitized.Strings), len(orig.Types), len(orig.Strings))
	}
	if tags := checkSanitizedTags(t, orig, sanitized); !slices.Equal(tags, []uint32{7, 21, 26}) {
		t.Errorf("decl tags at %v, want the compiled one at 7 and the copies at 21 and 26", tags)
	}
	if fn := sanitized.Types[6]; fn.Name != "subprog_arg_ctx" || fn.Vlen != btf.FuncStatic {
		t.Errorf("type 6 = %s linkage %d, want static subprog_arg_ctx", fn.Name, fn.Vlen)
	}
	if ds := sanitized.Find("license", btf.KindDatasec); ds == nil || ds.SizeOrType == 0 {
		t.Errorf("license DATASEC = %+v, want its fixed-up size", ds)
	}
}

// checkSanitizedTags checks the sanitized copy of spec type by type, both
// parsed from their blobs, and returns the IDs of spec's decl tags. Each is
// a one-byte INT with encoding word 8 and the tag's name in the copy; every
// other type is unchanged.
func checkSanitizedTags(t *testing.T, spec, sanitized *btf.Spec) []uint32 {
	t.Helper()

	var tags []uint32
	for id := range spec.Types {
		want, got := &spec.Types[id], &sanitized.Types[id]
		if want.Kind != btf.KindDeclTag {
			if !reflect.DeepEqual(got, want) {
				t.Errorf("type %d = %+v, want it unchanged as %+v", id, got, want)
			}
			continue
		}
		tags = append(tags, uint32(id))
		if got.Kind != btf.KindInt || got.KindFlag || got.SizeOrType != 1 || got.Int == nil || got.Int.Encoding != 8 {
			t.Errorf("type %d = %v of size %d, int %+v; want a one-byte INT with encoding word 8", id, got.Kind, got.SizeOrType, got.Int)
		}
		if got.Name != want.Name {
			t.Errorf("type %d named %q, want the tag's %q", id, got.Name, want.Name)
		}
	}
	return tags
}
