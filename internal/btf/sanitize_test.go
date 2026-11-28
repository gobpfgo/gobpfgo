// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"syscall"
	"testing"
)

// allFeatures is a kernel with every BTF feature Sanitize handles.
var allFeatures = KernelFeatures{
	DeclTag: true, TypeTag: true, Enum64: true, QmarkDatasec: true, Float: true,
	Func: true, Datasec: true, GlobalFunc: true, Layout: true,
}

// without returns allFeatures with the features clear unsets, so every
// other feature is set explicitly.
func without(clear func(k *KernelFeatures)) KernelFeatures {
	k := allFeatures
	clear(&k)
	return k
}

// withoutDeclTag is a kernel that lacks only BTF_KIND_DECL_TAG.
var withoutDeclTag = without(func(k *KernelFeatures) { k.DeclTag = false })

// byteOrders are the orders the sanitizer tests build their blobs in.
var byteOrders = []binary.ByteOrder{binary.LittleEndian, binary.BigEndian}

// buildSpecOrder is buildSpec for a blob in order.
func buildSpecOrder(t *testing.T, order binary.ByteOrder, types []Type, strs string) *Spec {
	t.Helper()

	built, err := NewSpec(order, types, []byte(strs))
	mustSucceed(t, "NewSpec", err)
	return parseOrder(t, built.Raw(), order)
}

// parseOrder parses raw in order and fails the test on an error.
func parseOrder(t *testing.T, raw []byte, order binary.ByteOrder) *Spec {
	t.Helper()

	spec, err := Parse(raw, order)
	mustSucceed(t, "Parse", err)
	return spec
}

// testLayout is a layout section: the entries of libbpf's kind layout table
// for UNKN, INT, PTR, ARRAY and STRUCT, each info_sz, elem_sz and a zero
// 16-bit flags word.
var testLayout = []byte{0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 12, 0, 0}

// withLayout returns a copy of raw, a blob in order with a 32-byte header
// and the strings right after the types, with layout between the types and
// the strings, as libbpf writes it, and the header's string and layout
// offsets and lengths set to match.
func withLayout(raw []byte, order binary.ByteOrder, layout []byte) []byte {
	typeLen := order.Uint32(raw[12:])
	strStart := order.Uint32(raw[4:]) + order.Uint32(raw[16:])
	out := append(bytes.Clone(raw[:strStart]), layout...)
	out = append(out, raw[strStart:]...)
	order.PutUint32(out[16:], typeLen+uint32(len(layout)))
	order.PutUint32(out[hdrLayoutOff:], typeLen)
	order.PutUint32(out[hdrLayoutLen:], uint32(len(layout)))
	return out
}

// withHdrLen returns a copy of raw, a blob in order with a 32-byte header,
// whose header is hdrLen bytes: the first 32 or fewer, then tail, which
// fills the rest. The section offsets stay relative to the header's end.
func withHdrLen(raw []byte, order binary.ByteOrder, hdrLen int, tail []byte) []byte {
	out := bytes.Clone(raw[:min(hdrLen, builtHdrLen)])
	out = append(out, tail...)
	order.PutUint32(out[4:], uint32(hdrLen))
	return append(out, raw[builtHdrLen:]...)
}

// declTagSpec returns a spec with decl tags on a struct member, a function
// parameter and a variable, one of them with the kind flag, between and
// after other types.
func declTagSpec(t *testing.T) *Spec {
	t.Helper()

	return buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 1<<24 | 32}},
		{NameOff: 5, Kind: KindStruct, SizeOrType: 4, Members: []Member{{NameOff: 7, Type: 1}}},
		{NameOff: 9, Kind: KindVar, SizeOrType: 1, Var: &Var{Linkage: VarStatic}},
		{Kind: KindFuncProto, SizeOrType: 1, Params: []Param{{NameOff: 11, Type: 1}}},
		{NameOff: 13, Kind: KindFunc, SizeOrType: 4, Vlen: FuncGlobal},
		{NameOff: 15, Kind: KindDeclTag, SizeOrType: 2, DeclTag: &DeclTag{ComponentIdx: 0}},
		{NameOff: 19, Kind: KindDeclTag, SizeOrType: 5, DeclTag: &DeclTag{ComponentIdx: 0}},
		{NameOff: 15, Kind: KindDeclTag, KindFlag: true, SizeOrType: 3, DeclTag: &DeclTag{ComponentIdx: -1}},
		{Kind: KindPtr, SizeOrType: 2},
	}, "\x00int\x00s\x00x\x00v\x00a\x00f\x00tag\x00arg:ctx\x00")
}

// TestSanitizeDeclTags sanitizes a spec with three decl tags for a kernel
// without them. The copy has the blob's length, header and string table;
// each tag is now an unflagged INT of size 1 with encoding word 8 under the
// tag's name and type ID, and every other type parses back unchanged. The
// spec keeps its decl tags and its blob.
func TestSanitizeDeclTags(t *testing.T) {
	spec := declTagSpec(t)
	orig := bytes.Clone(spec.Raw())

	raw, err := spec.Sanitize(withoutDeclTag)
	mustSucceed(t, "Sanitize", err)
	if !bytes.Equal(spec.Raw(), orig) {
		t.Fatal("Sanitize changed the spec's blob")
	}
	for _, id := range []int{6, 7, 8} {
		if spec.Types[id].Kind != KindDeclTag {
			t.Fatalf("spec type %d is %v after Sanitize, want its DECL_TAG", id, spec.Types[id].Kind)
		}
	}
	if len(raw) != len(orig) || &raw[0] == &orig[0] {
		t.Fatalf("copy has %d bytes at %p, want %d bytes in a new buffer", len(raw), &raw[0], len(orig))
	}
	if hdr := spec.Header.HdrLen; !bytes.Equal(raw[:hdr], orig[:hdr]) {
		t.Error("header changed")
	}

	sanitized, err := Parse(raw, binary.LittleEndian)
	mustSucceed(t, "Parse", err)
	if !bytes.Equal(sanitized.Strings, spec.Strings) {
		t.Errorf("strings = %q, want %q", sanitized.Strings, spec.Strings)
	}
	if len(sanitized.Types) != len(spec.Types) {
		t.Fatalf("%d types, want %d", len(sanitized.Types), len(spec.Types))
	}
	for id := range spec.Types {
		checkSanitizedType(t, &spec.Types[id], &sanitized.Types[id])
	}
}

// checkSanitizedType checks the type got that sanitizing want's blob made:
// an INT in place of a decl tag, and want itself otherwise.
func checkSanitizedType(t *testing.T, want, got *Type) {
	t.Helper()

	if want.Kind != KindDeclTag {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("type %d = %+v, want it unchanged as %+v", want.ID, got, want)
		}
		return
	}
	if want.DeclTag == nil {
		t.Fatalf("type %d: decl tag without payload", want.ID)
	}
	if got.ID != want.ID || got.Kind != KindInt || got.KindFlag || got.Vlen != 0 {
		t.Errorf("type %d = %v kind flag %v vlen %d, want an INT %d without kind flag or vlen", got.ID, got.Kind, got.KindFlag, got.Vlen, want.ID)
	}
	if got.SizeOrType != 1 || got.Int == nil || got.Int.Encoding != 8 {
		t.Errorf("type %d: size %d, int %+v, want size 1 and encoding word 8", got.ID, got.SizeOrType, got.Int)
	}
	if got.NameOff != want.NameOff || got.Name != want.Name {
		t.Errorf("type %d named %q at %d, want the tag's %q at %d", got.ID, got.Name, got.NameOff, want.Name, want.NameOff)
	}
}

// TestSanitizeNone sanitizes a spec without any kind or name that Sanitize
// rewrites, for a kernel without any of the features, which comes back as
// an equal copy, and a split spec, which is an error.
func TestSanitizeNone(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
		{NameOff: 5, Kind: KindStruct, SizeOrType: 4, Members: []Member{{NameOff: 11, Type: 1}}},
		{NameOff: 13, Kind: KindTypedef, SizeOrType: 2},
		{Kind: KindPtr, SizeOrType: 3},
	}, "\x00int\x00.data\x00x\x00.t\x00")

	raw, err := spec.Sanitize(KernelFeatures{})
	mustSucceed(t, "Sanitize", err)
	if !bytes.Equal(raw, spec.Raw()) || &raw[0] == &spec.Raw()[0] {
		t.Error("blob without anything to sanitize did not come back as an equal copy")
	}

	split := &Spec{base: spec}
	if _, err := split.Sanitize(KernelFeatures{}); err == nil {
		t.Error("Sanitize on split BTF succeeded")
	}
}

// testStrings returns a string table that holds names after the empty
// string, each once, and the offset of each name.
func testStrings(names ...string) ([]byte, map[string]uint32) {
	strs := []byte{0}
	off := make(map[string]uint32, len(names))
	for _, name := range names {
		off[name] = uint32(len(strs))
		strs = append(append(strs, name...), 0)
	}
	return strs, off
}

// sanitizeTypes returns the types and strings of a blob with every kind
// and name that Sanitize rewrites, between types that it keeps:
//
//	[1] INT int             [2] TYPE_TAG user on [1]   [3] PTR to [2]
//	[4] signed ENUM s       [5] unsigned ENUM e        [6] ENUM64 w
//	[7] signed ENUM64 w2    [8] VAR p of [3]           [9] DATASEC ?.data of p
//	[10] DATASEC .bss       [11] STRUCT ?x             [12] DECL_TAG tag on [8]
//	[13] FLOAT float        [14] FLOAT double          [15] FUNC_PROTO int(int a, user *)
//	[16] FUNC f, global     [17] FUNC g, static        [18] FUNC h, extern
//	[19] VAR q of [1]       [20] DATASEC .data.?y of q, f and float
func sanitizeTypes() ([]Type, []byte, map[string]uint32) {
	strs, off := testStrings("int", "user", "s", "N", "P", "e", "E",
		"w", "L", "H", "w2", "M", "p", "?.data", ".bss", "?x", "tag",
		"float", "double", "a", "f", "g", "h", "q", ".data.?y")
	types := []Type{
		{Kind: KindVoid},
		{NameOff: off["int"], Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 1<<24 | 32}},
		{NameOff: off["user"], Kind: KindTypeTag, SizeOrType: 1},
		{Kind: KindPtr, SizeOrType: 2},
		{NameOff: off["s"], Kind: KindEnum, KindFlag: true, SizeOrType: 4,
			Enums: []Enum{{NameOff: off["N"], Value: -1}, {NameOff: off["P"], Value: 1}}},
		{NameOff: off["e"], Kind: KindEnum, SizeOrType: 4, Enums: []Enum{{NameOff: off["E"], Value: 7}}},
		{NameOff: off["w"], Kind: KindEnum64, SizeOrType: 8,
			Enum64s: []Enum64{{NameOff: off["L"], Value: 1}, {NameOff: off["H"], Value: 1 << 32}}},
		{NameOff: off["w2"], Kind: KindEnum64, KindFlag: true, SizeOrType: 8,
			Enum64s: []Enum64{{NameOff: off["M"], Value: ^uint64(0)}}},
		{NameOff: off["p"], Kind: KindVar, SizeOrType: 3, Var: &Var{Linkage: VarStatic}},
		{NameOff: off["?.data"], Kind: KindDatasec, SizeOrType: 16, DataSec: []VarSecInfo{{Type: 8, Offset: 8, Size: 8}}},
		{NameOff: off[".bss"], Kind: KindDatasec},
		{NameOff: off["?x"], Kind: KindStruct},
		{NameOff: off["tag"], Kind: KindDeclTag, SizeOrType: 8, DeclTag: &DeclTag{ComponentIdx: -1}},
		{NameOff: off["float"], Kind: KindFloat, SizeOrType: 4},
		{NameOff: off["double"], Kind: KindFloat, SizeOrType: 8},
		{Kind: KindFuncProto, SizeOrType: 1, Params: []Param{{NameOff: off["a"], Type: 1}, {Type: 3}}},
		{NameOff: off["f"], Kind: KindFunc, SizeOrType: 15, Vlen: FuncGlobal},
		{NameOff: off["g"], Kind: KindFunc, SizeOrType: 15, Vlen: FuncStatic},
		{NameOff: off["h"], Kind: KindFunc, SizeOrType: 15, Vlen: FuncExtern},
		{NameOff: off["q"], Kind: KindVar, SizeOrType: 1, Var: &Var{Linkage: VarGlobalAllocated}},
		{NameOff: off[".data.?y"], Kind: KindDatasec, SizeOrType: 12,
			DataSec: []VarSecInfo{{Type: 19, Offset: 0, Size: 4}, {Type: 16, Offset: 4}, {Type: 13, Offset: 8, Size: 4}}},
	}
	return types, strs, off
}

// sanitizeEdit makes the types and strings of sanitizeTypes what Sanitize
// should turn them into for one missing feature. The edits of a case run in
// the order libbpf's rewrites affect each other.
type sanitizeEdit func(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte)

// sanitizedInt is the one-byte INT that replaces a VAR or a decl tag
// named at nameOff.
func sanitizedInt(nameOff uint32) Type {
	return Type{NameOff: nameOff, Kind: KindInt, SizeOrType: 1, Int: &Int{Encoding: 8}}
}

// declTagEdit turns the decl tag into a one-byte INT under its name.
func declTagEdit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	types[12] = sanitizedInt(off["tag"])
	return types, strs
}

// typeTagEdit turns the type tag into an unnamed CONST of the same type.
func typeTagEdit(types []Type, strs []byte, _ map[string]uint32) ([]Type, []byte) {
	types[2] = Type{Kind: KindConst, SizeOrType: 1}
	return types, strs
}

// floatEdit turns both floats into unnamed STRUCTs of the same size and
// without members.
func floatEdit(types []Type, strs []byte, _ map[string]uint32) ([]Type, []byte) {
	types[13] = Type{Kind: KindStruct, SizeOrType: 4}
	types[14] = Type{Kind: KindStruct, SizeOrType: 8}
	return types, strs
}

// enum64Edit clears the signed ENUM's kind flag and turns both ENUM64s
// into UNIONs whose members keep the value names, at offset 0, of the
// enum64_placeholder INT, which comes after the last type with its name
// appended to the string table.
func enum64Edit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	id := uint32(len(types))
	types[4].KindFlag = false
	types[6] = Type{NameOff: off["w"], Kind: KindUnion, SizeOrType: 8,
		Members: []Member{{NameOff: off["L"], Type: id}, {NameOff: off["H"], Type: id}}}
	types[7] = Type{NameOff: off["w2"], Kind: KindUnion, SizeOrType: 8,
		Members: []Member{{NameOff: off["M"], Type: id}}}
	types = append(types, sanitizedInt(uint32(len(strs))))
	return types, append(append(strs, "enum64_placeholder"...), 0)
}

// qmarkEdit makes the '?.data' DATASEC name start with '_'.
func qmarkEdit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	strs[off["?.data"]] = '_'
	return types, strs
}

// datasecEdit turns both variables into one-byte INTs under their names
// and the three DATASECs into STRUCTs of the same size, with '_' for every
// '.' and '?' of their names. Each variable is a member at its offset in
// bits, of its type, named like that type as the earlier edits left it.
func datasecEdit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	for id, typ := range types {
		switch typ.Kind {
		case KindVar:
			types[id] = sanitizedInt(typ.NameOff)
		case KindDatasec:
			members := make([]Member, len(typ.DataSec))
			for j, v := range typ.DataSec {
				members[j] = Member{NameOff: types[v.Type].NameOff, Type: v.Type, Offset: v.Offset * 8}
			}
			types[id] = Type{NameOff: typ.NameOff, Kind: KindStruct, SizeOrType: typ.SizeOrType, Members: members}
		}
	}
	for _, name := range []string{"?.data", ".bss", ".data.?y"} {
		for i := off[name]; strs[i] != 0; i++ {
			if strs[i] == '.' || strs[i] == '?' {
				strs[i] = '_'
			}
		}
	}
	return types, strs
}

// funcEdit turns the prototype into a 4-byte ENUM whose values are its
// parameters' names and types, and each function into a TYPEDEF of it.
func funcEdit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	types[15] = Type{Kind: KindEnum, SizeOrType: 4,
		Enums: []Enum{{NameOff: off["a"], Value: 1}, {Value: 3}}}
	for id := 16; id <= 18; id++ {
		types[id] = Type{NameOff: types[id].NameOff, Kind: KindTypedef, SizeOrType: 15}
	}
	return types, strs
}

// globalFuncEdit gives each function static linkage.
func globalFuncEdit(types []Type, strs []byte, _ map[string]uint32) ([]Type, []byte) {
	for id := 16; id <= 18; id++ {
		types[id].Vlen = FuncStatic
	}
	return types, strs
}

// sanitizeCases are kernels that lack one feature, some or all of them, or
// none, with the edits that make the expected copy of sanitizeTypes.
var sanitizeCases = []struct {
	name  string
	kern  KernelFeatures
	edits []sanitizeEdit
}{
	{"decl tag", withoutDeclTag, []sanitizeEdit{declTagEdit}},
	{"type tag", without(func(k *KernelFeatures) { k.TypeTag = false }), []sanitizeEdit{typeTagEdit}},
	{"enum64", without(func(k *KernelFeatures) { k.Enum64 = false }), []sanitizeEdit{enum64Edit}},
	{"qmark datasec", without(func(k *KernelFeatures) { k.QmarkDatasec = false }), []sanitizeEdit{qmarkEdit}},
	{"float", without(func(k *KernelFeatures) { k.Float = false }), []sanitizeEdit{floatEdit}},
	{"datasec", without(func(k *KernelFeatures) { k.Datasec = false }), []sanitizeEdit{datasecEdit}},
	{"datasec and qmark datasec", without(func(k *KernelFeatures) { k.Datasec, k.QmarkDatasec = false, false }), []sanitizeEdit{datasecEdit}},
	{"datasec and float", without(func(k *KernelFeatures) { k.Datasec, k.Float = false, false }), []sanitizeEdit{floatEdit, datasecEdit}},
	{"func", without(func(k *KernelFeatures) { k.Func = false }), []sanitizeEdit{funcEdit}},
	{"global func", without(func(k *KernelFeatures) { k.GlobalFunc = false }), []sanitizeEdit{globalFuncEdit}},
	{"func and global func", without(func(k *KernelFeatures) { k.Func, k.GlobalFunc = false, false }), []sanitizeEdit{funcEdit}},
	{"layout", without(func(k *KernelFeatures) { k.Layout = false }), nil},
	{"layout and qmark datasec", without(func(k *KernelFeatures) { k.Layout, k.QmarkDatasec = false, false }), []sanitizeEdit{qmarkEdit}},
	{"layout and enum64", without(func(k *KernelFeatures) { k.Layout, k.Enum64 = false, false }), []sanitizeEdit{enum64Edit}},
	{"combined", KernelFeatures{}, []sanitizeEdit{declTagEdit, typeTagEdit, enum64Edit, floatEdit, datasecEdit, funcEdit}},
	{"none missing", allFeatures, nil},
}

// TestSanitize sanitizes the blob of sanitizeTypes for each of
// sanitizeCases and compares the copy, byte for byte, with the blob built
// from the expected types and strings: the kinds, sizes, names, members and
// the placeholder INT and its string, with the header lengths and offsets
// of that blob. Each case runs in both byte orders, on the blob as built
// and on one with a layout section between the types and the strings. A
// kernel with Layout gets the section back, after the placeholder if any;
// one without it gets the blob without it. Each type of the original keeps
// its ID in the copy, and the spec keeps its types, strings and blob.
func TestSanitize(t *testing.T) {
	for _, order := range byteOrders {
		for _, layout := range []bool{false, true} {
			for _, tt := range sanitizeCases {
				name := order.String() + "/" + tt.name
				if layout {
					name = order.String() + "/with layout/" + tt.name
				}
				t.Run(name, func(t *testing.T) {
					testSanitizeCase(t, order, layout, tt.kern, tt.edits)
				})
			}
		}
	}
}

func testSanitizeCase(t *testing.T, order binary.ByteOrder, layout bool, kern KernelFeatures, edits []sanitizeEdit) {
	types, strs, off := sanitizeTypes()
	origRaw := buildSpecOrder(t, order, types, string(strs)).Raw()
	if layout {
		origRaw = withLayout(origRaw, order, testLayout)
	}
	spec := parseOrder(t, origRaw, order)
	origRaw = bytes.Clone(origRaw)

	got, err := spec.Sanitize(kern)
	mustSucceed(t, "Sanitize", err)

	wantTypes, wantStrs, _ := sanitizeTypes()
	for _, edit := range edits {
		wantTypes, wantStrs = edit(wantTypes, wantStrs, off)
	}
	want := buildSpecOrder(t, order, wantTypes, string(wantStrs)).Raw()
	if layout && kern.Layout {
		want = withLayout(want, order, testLayout)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}
	checkSanitizedIDs(t, got, order, wantTypes)
	orig := parseOrder(t, origRaw, order)
	if !bytes.Equal(spec.Raw(), origRaw) || !reflect.DeepEqual(spec.Types, orig.Types) || !bytes.Equal(spec.Strings, orig.Strings) {
		t.Error("Sanitize changed the spec")
	}
}

// checkSanitizedIDs parses the sanitized blob raw, in order, and checks
// that it has the types want, each under its index as type ID.
func checkSanitizedIDs(t *testing.T, raw []byte, order binary.ByteOrder, want []Type) {
	t.Helper()

	sanitized := parseOrder(t, raw, order)
	if len(sanitized.Types) != len(want) {
		t.Fatalf("%d types, want %d", len(sanitized.Types), len(want))
	}
	for id := range want {
		got := &sanitized.Types[id]
		if got.ID != uint32(id) || got.Kind != want[id].Kind || got.NameOff != want[id].NameOff {
			t.Errorf("type %d = %v named at %d with ID %d, want %v named at %d", id, got.Kind, got.NameOff, got.ID, want[id].Kind, want[id].NameOff)
		}
	}
}

// TestSanitizeDatasecStruct sanitizes, for a kernel without DATASEC,
// FLOAT and TYPE_TAG, a DATASEC between a FLOAT and a TYPE_TAG whose name
// a TYPEDEF shares. Its variables refer to a VAR, the FLOAT, void, the
// TYPE_TAG and a FUNC_PROTO, the last at an offset whose bit offset wraps.
// Each member takes the name offset its type has when the DATASEC is
// rewritten: the FLOAT's is already 0, the TYPE_TAG's not yet. The renamed
// string renames the TYPEDEF too.
func TestSanitizeDatasecStruct(t *testing.T) {
	strs, off := testStrings("int", "float", "a", "?a.b?", "tt")
	types := []Type{
		{Kind: KindVoid},
		{NameOff: off["int"], Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
		{NameOff: off["float"], Kind: KindFloat, SizeOrType: 4},
		{NameOff: off["a"], Kind: KindVar, SizeOrType: 1, Var: &Var{Linkage: VarStatic}},
		{NameOff: off["?a.b?"], Kind: KindDatasec, SizeOrType: 32, DataSec: []VarSecInfo{
			{Type: 3, Offset: 4, Size: 4}, {Type: 2, Offset: 8, Size: 4}, {Type: 0, Offset: 12},
			{Type: 5, Offset: 16, Size: 4}, {Type: 7, Offset: 0x20000001, Size: 1}}},
		{NameOff: off["tt"], Kind: KindTypeTag, SizeOrType: 1},
		{NameOff: off["?a.b?"], Kind: KindTypedef, SizeOrType: 1},
		{Kind: KindFuncProto},
	}
	spec := buildSpec(t, types, string(strs))

	got, err := spec.Sanitize(without(func(k *KernelFeatures) { k.Datasec, k.Float, k.TypeTag = false, false, false }))
	mustSucceed(t, "Sanitize", err)
	wantStrs := bytes.Clone(strs)
	copy(wantStrs[off["?a.b?"]:], "_a_b_")
	want := buildSpec(t, []Type{
		{Kind: KindVoid},
		types[1],
		{Kind: KindStruct, SizeOrType: 4},
		sanitizedInt(off["a"]),
		{NameOff: off["?a.b?"], Kind: KindStruct, SizeOrType: 32, Members: []Member{
			{NameOff: off["a"], Type: 3, Offset: 32}, {Type: 2, Offset: 64}, {Type: 0, Offset: 96},
			{NameOff: off["tt"], Type: 5, Offset: 128}, {Type: 7, Offset: 8}}},
		{Kind: KindConst, SizeOrType: 1},
		types[6],
		types[7],
	}, string(wantStrs)).Raw()
	if !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}
	if typedef := parseOrder(t, got, binary.LittleEndian).Types[6]; typedef.Name != "_a_b_" {
		t.Errorf("TYPEDEF is named %q, want the renamed _a_b_", typedef.Name)
	}

	types[4].DataSec[2].Type = 8
	spec = buildSpec(t, types, string(strs))
	if _, err := spec.Sanitize(without(func(k *KernelFeatures) { k.Datasec = false })); err == nil {
		t.Error("Sanitize took a DATASEC variable of a type out of range")
	}
	if _, err := spec.Sanitize(allFeatures); err != nil {
		t.Errorf("Sanitize without a DATASEC rewrite: %v", err)
	}
}

// TestSanitizeFuncs sanitizes prototypes and global, static and extern
// functions. Without FUNC, each prototype is a 4-byte ENUM of its
// parameters and each function a TYPEDEF of its prototype, whatever the
// linkage and whether global functions are supported. Without global
// functions only, every function is static, the extern one too.
func TestSanitizeFuncs(t *testing.T) {
	strs, off := testStrings("int", "a", "f", "g", "h")
	types := []Type{
		{Kind: KindVoid},
		{NameOff: off["int"], Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 1<<24 | 32}},
		{Kind: KindFuncProto, SizeOrType: 1, Params: []Param{{NameOff: off["a"], Type: 1}, {Type: 3}}},
		{Kind: KindPtr, SizeOrType: 1},
		{NameOff: off["f"], Kind: KindFunc, SizeOrType: 2, Vlen: FuncGlobal},
		{NameOff: off["g"], Kind: KindFunc, SizeOrType: 2, Vlen: FuncStatic},
		{NameOff: off["h"], Kind: KindFunc, SizeOrType: 7, Vlen: FuncExtern},
		{Kind: KindFuncProto},
	}
	spec := buildSpec(t, types, string(strs))

	noFunc := []Type{
		types[0], types[1],
		{Kind: KindEnum, SizeOrType: 4, Enums: []Enum{{NameOff: off["a"], Value: 1}, {Value: 3}}},
		types[3],
		{NameOff: off["f"], Kind: KindTypedef, SizeOrType: 2},
		{NameOff: off["g"], Kind: KindTypedef, SizeOrType: 2},
		{NameOff: off["h"], Kind: KindTypedef, SizeOrType: 7},
		{Kind: KindEnum, SizeOrType: 4},
	}
	allStatic := append([]Type(nil), types...)
	for id := 4; id <= 6; id++ {
		allStatic[id].Vlen = FuncStatic
	}

	for _, tt := range []struct {
		name string
		kern KernelFeatures
		want []Type
	}{
		{"func", without(func(k *KernelFeatures) { k.Func = false }), noFunc},
		{"func and global func", without(func(k *KernelFeatures) { k.Func, k.GlobalFunc = false, false }), noFunc},
		{"global func", without(func(k *KernelFeatures) { k.GlobalFunc = false }), allStatic},
		{"none missing", allFeatures, types},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := spec.Sanitize(tt.kern)
			mustSucceed(t, "Sanitize", err)
			if want := buildSpec(t, tt.want, string(strs)).Raw(); !bytes.Equal(got, want) {
				t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
			}
		})
	}
}

// TestSanitizeEnum64PlaceholderName sanitizes an ENUM64 in a blob whose
// string table already holds enum64_placeholder, as a typedef name. The
// added INT takes that string, so the copy has the same string table, and
// the header still covers the types and strings.
func TestSanitizeEnum64PlaceholderName(t *testing.T) {
	strs, off := testStrings("enum64_placeholder", "w", "L")
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: off["w"], Kind: KindEnum64, SizeOrType: 8, Enum64s: []Enum64{{NameOff: off["L"], Value: 1}}},
		{NameOff: off["enum64_placeholder"], Kind: KindTypedef, SizeOrType: 1},
	}, string(strs))

	got, err := spec.Sanitize(without(func(k *KernelFeatures) { k.Enum64 = false }))
	mustSucceed(t, "Sanitize", err)
	want := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: off["w"], Kind: KindUnion, SizeOrType: 8, Members: []Member{{NameOff: off["L"], Type: 3}}},
		{NameOff: off["enum64_placeholder"], Kind: KindTypedef, SizeOrType: 1},
		sanitizedInt(off["enum64_placeholder"]),
	}, string(strs)).Raw()
	if !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}
}

// TestSanitizeEnum64PlaceholderNameOrder sanitizes, for a kernel without
// DATASEC and ENUM64, an ENUM64 and a DATASEC named enum64.placeholder,
// which the rewrite renames enum64_placeholder. libbpf looks the
// placeholder's name up when it rewrites the first ENUM64: a DATASEC before
// it is renamed by then and its string is reused, a DATASEC after it is
// not, so the name is appended and the table ends up with it twice.
func TestSanitizeEnum64PlaceholderNameOrder(t *testing.T) {
	strs, off := testStrings("enum64.placeholder", "w", "L")
	renamed := bytes.Clone(strs)
	copy(renamed[off["enum64.placeholder"]:], "enum64_placeholder")
	datasec := Type{NameOff: off["enum64.placeholder"], Kind: KindDatasec}
	enum64 := Type{NameOff: off["w"], Kind: KindEnum64, SizeOrType: 8, Enum64s: []Enum64{{NameOff: off["L"], Value: 1}}}
	union := func(id uint32) Type {
		return Type{NameOff: off["w"], Kind: KindUnion, SizeOrType: 8, Members: []Member{{NameOff: off["L"], Type: id}}}
	}
	structType := Type{NameOff: off["enum64.placeholder"], Kind: KindStruct}
	kern := without(func(k *KernelFeatures) { k.Datasec, k.Enum64 = false, false })

	for _, tt := range []struct {
		name      string
		types     []Type
		wantTypes []Type
		wantStrs  []byte
	}{
		{
			"datasec first",
			[]Type{{Kind: KindVoid}, datasec, enum64},
			[]Type{{Kind: KindVoid}, structType, union(3), sanitizedInt(off["enum64.placeholder"])},
			renamed,
		},
		{
			"enum64 first",
			[]Type{{Kind: KindVoid}, enum64, datasec},
			[]Type{{Kind: KindVoid}, union(3), structType, sanitizedInt(uint32(len(strs)))},
			append(bytes.Clone(renamed), "enum64_placeholder\x00"...),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildSpec(t, tt.types, string(strs)).Sanitize(kern)
			mustSucceed(t, "Sanitize", err)
			if want := buildSpec(t, tt.wantTypes, string(tt.wantStrs)).Raw(); !bytes.Equal(got, want) {
				t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
			}
		})
	}
}

// layoutSpecTypes returns a small spec for the layout tests: an int, a
// TYPE_TAG on it, an ENUM64 and a '?' DATASEC of a variable.
func layoutSpecTypes() ([]Type, []byte, map[string]uint32) {
	strs, off := testStrings("int", "user", "w", "L", "x", "?.data")
	return []Type{
		{Kind: KindVoid},
		{NameOff: off["int"], Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 1<<24 | 32}},
		{NameOff: off["user"], Kind: KindTypeTag, SizeOrType: 1},
		{NameOff: off["w"], Kind: KindEnum64, SizeOrType: 8, Enum64s: []Enum64{{NameOff: off["L"], Value: 1 << 33}}},
		{NameOff: off["x"], Kind: KindVar, SizeOrType: 1, Var: &Var{Linkage: VarStatic}},
		{NameOff: off["?.data"], Kind: KindDatasec, SizeOrType: 4, DataSec: []VarSecInfo{{Type: 4, Size: 4}}},
	}, strs, off
}

// layoutEnum64Types returns layoutSpecTypes with the ENUM64 rewritten as a
// UNION of the placeholder, and the table with its name appended.
func layoutEnum64Types() ([]Type, []byte) {
	types, strs, off := layoutSpecTypes()
	types[3] = Type{NameOff: off["w"], Kind: KindUnion, SizeOrType: 8, Members: []Member{{NameOff: off["L"], Type: 6}}}
	types = append(types, sanitizedInt(uint32(len(strs))))
	return types, append(strs, "enum64_placeholder\x00"...)
}

// TestSanitizeLayoutOffOnly sanitizes a blob whose header has layout_off
// set and layout_len 0, which libbpf parses as no layout section. A kernel
// without Layout gets layout_off cleared and the blob otherwise as it is.
// A kernel with Layout keeps it, also in the blob rebuilt with the enum64
// placeholder, where libbpf moves layout_off only with a section.
func TestSanitizeLayoutOffOnly(t *testing.T) {
	for _, order := range byteOrders {
		t.Run(order.String(), func(t *testing.T) {
			types, strs, _ := layoutSpecTypes()
			built := buildSpecOrder(t, order, types, string(strs)).Raw()
			raw := bytes.Clone(built)
			order.PutUint32(raw[hdrLayoutOff:], 4)
			spec := parseOrder(t, raw, order)

			got, err := spec.Sanitize(without(func(k *KernelFeatures) { k.Layout = false }))
			mustSucceed(t, "Sanitize", err)
			if !bytes.Equal(got, built) {
				t.Errorf("sanitized blob =\n%x\nwant\n%x", got, built)
			}

			got, err = spec.Sanitize(without(func(k *KernelFeatures) { k.Enum64 = false }))
			mustSucceed(t, "Sanitize", err)
			wantTypes, wantStrs := layoutEnum64Types()
			want := buildSpecOrder(t, order, wantTypes, string(wantStrs)).Raw()
			order.PutUint32(want[hdrLayoutOff:], 4)
			if !bytes.Equal(got, want) {
				t.Errorf("sanitized blob with the placeholder =\n%x\nwant\n%x", got, want)
			}
		})
	}
}

// TestSanitizeLayoutInvalid sanitizes blobs whose header places the layout
// section where libbpf's parser rejects it: unaligned, over the types, over
// the strings, not a whole number of entries, or with the types ending
// after the strings start. A kernel without Layout, which needs the section
// stripped, gets an error wrapping EINVAL. A kernel with Layout gets the
// blob back, but an error when the placeholder has to move the section.
func TestSanitizeLayoutInvalid(t *testing.T) {
	order := binary.LittleEndian
	types, strs, _ := layoutSpecTypes()
	built := buildSpecOrder(t, order, types, string(strs)).Raw()
	typeLen := order.Uint32(built[12:])
	valid := withLayout(built, order, testLayout)
	layoutLen := uint32(len(testLayout))

	// stringsFirst has the strings, padded to 4 bytes, before the types,
	// and layout_off set without a section.
	padded := append(bytes.Clone(built[builtHdrLen+typeLen:]), make([]byte, 4-len(strs)%4)...)
	stringsFirst := append(bytes.Clone(built[:builtHdrLen]), padded...)
	stringsFirst = append(stringsFirst, built[builtHdrLen:builtHdrLen+typeLen]...)
	order.PutUint32(stringsFirst[8:], uint32(len(padded)))
	order.PutUint32(stringsFirst[16:], 0)
	order.PutUint32(stringsFirst[20:], uint32(len(padded)))
	order.PutUint32(stringsFirst[hdrLayoutOff:], 4)

	for _, tt := range []struct {
		name        string
		raw         []byte
		off, length uint32
		moved       bool
	}{
		{"unaligned", valid, typeLen + 2, layoutLen - 4, true},
		{"over the types", valid, typeLen - 4, layoutLen, true},
		{"over the strings", valid, typeLen, layoutLen + 4, true},
		{"partial entry", valid, typeLen, layoutLen - 2, true},
		{"strings first", stringsFirst, 4, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := bytes.Clone(tt.raw)
			order.PutUint32(raw[hdrLayoutOff:], tt.off)
			order.PutUint32(raw[hdrLayoutLen:], tt.length)
			spec := parseOrder(t, raw, order)

			_, err := spec.Sanitize(without(func(k *KernelFeatures) { k.Layout = false }))
			if !errors.Is(err, syscall.EINVAL) {
				t.Errorf("Sanitize without Layout = %v, want EINVAL", err)
			}
			got, err := spec.Sanitize(allFeatures)
			if err != nil || !bytes.Equal(got, raw) {
				t.Errorf("Sanitize with every feature = %v, want an equal copy", err)
			}
			_, err = spec.Sanitize(without(func(k *KernelFeatures) { k.Enum64 = false }))
			if tt.moved && !errors.Is(err, syscall.EINVAL) {
				t.Errorf("Sanitize without Enum64 = %v, want EINVAL", err)
			}
			if !tt.moved && err != nil {
				t.Errorf("Sanitize without Enum64: %v", err)
			}
		})
	}
}

// TestSanitizeHeaderData sanitizes blobs whose header is longer than the
// 32 bytes libbpf knows. With zero bytes past them, the placeholder is
// added and the header keeps its length. With a nonzero byte, libbpf
// rewrites the type tag in place, but refuses to add the enum64 placeholder
// INT, as BTF it cannot modify, also after stripping a layout section. A
// header of 28 bytes has no layout fields for libbpf: the bytes past the
// string section fields stay, also when the blob is rebuilt.
func TestSanitizeHeaderData(t *testing.T) {
	order := binary.LittleEndian
	types, strs, _ := layoutSpecTypes()
	built := buildSpecOrder(t, order, types, string(strs)).Raw()
	enumTypes, enumStrs := layoutEnum64Types()
	withPlaceholder := buildSpecOrder(t, order, enumTypes, string(enumStrs)).Raw()
	noEnum64 := without(func(k *KernelFeatures) { k.Enum64 = false })
	noTypeTag := without(func(k *KernelFeatures) { k.TypeTag = false })

	zeroTail := withHdrLen(built, order, 40, make([]byte, 8))
	got, err := parseOrder(t, zeroTail, order).Sanitize(noEnum64)
	mustSucceed(t, "Sanitize with zero header bytes", err)
	if want := withHdrLen(withPlaceholder, order, 40, make([]byte, 8)); !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}

	tail := []byte{0, 0, 0, 0, 1, 0, 0, 0}
	extra := withHdrLen(built, order, 40, tail)
	spec := parseOrder(t, extra, order)
	got, err = spec.Sanitize(noTypeTag)
	mustSucceed(t, "Sanitize of the type tag", err)
	typeTagged := append([]Type(nil), types...)
	typeTagged[2] = Type{Kind: KindConst, SizeOrType: 1}
	if want := withHdrLen(buildSpecOrder(t, order, typeTagged, string(strs)).Raw(), order, 40, tail); !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}
	if _, err := spec.Sanitize(noEnum64); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Errorf("Sanitize added the enum64 placeholder to a blob with unknown header data: %v, want EOPNOTSUPP", err)
	}

	layoutExtra := withHdrLen(withLayout(built, order, testLayout), order, 40, tail)
	_, err = parseOrder(t, layoutExtra, order).Sanitize(without(func(k *KernelFeatures) { k.Layout, k.Enum64 = false, false }))
	if !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Errorf("Sanitize added the placeholder after stripping the layout of a blob with unknown header data: %v, want EOPNOTSUPP", err)
	}

	short := withHdrLen(built, order, 28, nil)
	order.PutUint32(short[hdrLayoutOff:], 4)
	got, err = parseOrder(t, short, order).Sanitize(without(func(k *KernelFeatures) { k.Layout, k.Enum64 = false, false }))
	mustSucceed(t, "Sanitize with a 28-byte header", err)
	want := withHdrLen(withPlaceholder, order, 28, nil)
	order.PutUint32(want[hdrLayoutOff:], 4)
	if !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}
}
