// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// allFeatures is a kernel with every BTF feature Sanitize handles, and
// withoutDeclTag one that lacks only BTF_KIND_DECL_TAG.
var (
	allFeatures    = KernelFeatures{DeclTag: true, TypeTag: true, Enum64: true, QmarkDatasec: true, Float: true}
	withoutDeclTag = KernelFeatures{TypeTag: true, Enum64: true, QmarkDatasec: true, Float: true}
)

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
		{NameOff: 5, Kind: KindDatasec, SizeOrType: 0},
	}, "\x00int\x00.data\x00")

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
//	[7] signed ENUM64 w2    [8] VAR p of [3]           [9] DATASEC ?.data
//	[10] DATASEC .bss       [11] STRUCT ?x             [12] DECL_TAG tag on [8]
//	[13] FLOAT float        [14] FLOAT double
func sanitizeTypes() ([]Type, []byte, map[string]uint32) {
	strs, off := testStrings("int", "user", "s", "N", "P", "e", "E",
		"w", "L", "H", "w2", "M", "p", "?.data", ".bss", "?x", "tag",
		"float", "double")
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
		{NameOff: off["?.data"], Kind: KindDatasec, SizeOrType: 8, DataSec: []VarSecInfo{{Type: 8, Size: 8}}},
		{NameOff: off[".bss"], Kind: KindDatasec},
		{NameOff: off["?x"], Kind: KindStruct},
		{NameOff: off["tag"], Kind: KindDeclTag, SizeOrType: 8, DeclTag: &DeclTag{ComponentIdx: -1}},
		{NameOff: off["float"], Kind: KindFloat, SizeOrType: 4},
		{NameOff: off["double"], Kind: KindFloat, SizeOrType: 8},
	}
	return types, strs, off
}

// sanitizeEdit makes the types and strings of sanitizeTypes what Sanitize
// should turn them into for one missing feature.
type sanitizeEdit func(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte)

// declTagEdit turns the decl tag into a one-byte INT under its name.
func declTagEdit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	types[12] = Type{NameOff: off["tag"], Kind: KindInt, SizeOrType: 1, Int: &Int{Encoding: 8}}
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
	types = append(types, Type{NameOff: uint32(len(strs)), Kind: KindInt, SizeOrType: 1, Int: &Int{Encoding: 8}})
	return types, append(append(strs, "enum64_placeholder"...), 0)
}

// qmarkEdit makes the '?.data' DATASEC name start with '_'.
func qmarkEdit(types []Type, strs []byte, off map[string]uint32) ([]Type, []byte) {
	strs[off["?.data"]] = '_'
	return types, strs
}

// TestSanitize sanitizes the blob of sanitizeTypes for kernels that lack
// one feature each, all of them, or none, and compares each copy with the
// blob built from the expected types and strings: the kinds, sizes, names,
// members and the placeholder INT and its string, with the header lengths
// and offsets of that blob. Each type of the original keeps its ID in the
// copy, and the spec keeps its types, strings and blob.
func TestSanitize(t *testing.T) {
	for _, tt := range []struct {
		name  string
		kern  KernelFeatures
		edits []sanitizeEdit
	}{
		{"decl tag", withoutDeclTag, []sanitizeEdit{declTagEdit}},
		{"type tag", KernelFeatures{DeclTag: true, Enum64: true, QmarkDatasec: true, Float: true}, []sanitizeEdit{typeTagEdit}},
		{"enum64", KernelFeatures{DeclTag: true, TypeTag: true, QmarkDatasec: true, Float: true}, []sanitizeEdit{enum64Edit}},
		{"qmark datasec", KernelFeatures{DeclTag: true, TypeTag: true, Enum64: true, Float: true}, []sanitizeEdit{qmarkEdit}},
		{"float", KernelFeatures{DeclTag: true, TypeTag: true, Enum64: true, QmarkDatasec: true}, []sanitizeEdit{floatEdit}},
		{"combined", KernelFeatures{}, []sanitizeEdit{declTagEdit, typeTagEdit, enum64Edit, qmarkEdit, floatEdit}},
		{"none missing", allFeatures, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			types, strs, off := sanitizeTypes()
			spec := buildSpec(t, types, string(strs))
			origRaw := bytes.Clone(spec.Raw())

			got, err := spec.Sanitize(tt.kern)
			mustSucceed(t, "Sanitize", err)

			wantTypes, wantStrs, _ := sanitizeTypes()
			for _, edit := range tt.edits {
				wantTypes, wantStrs = edit(wantTypes, wantStrs, off)
			}
			if want := buildSpec(t, wantTypes, string(wantStrs)).Raw(); !bytes.Equal(got, want) {
				t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
			}
			checkSanitizedIDs(t, got, wantTypes)
			orig, err := Parse(origRaw, binary.LittleEndian)
			mustSucceed(t, "Parse", err)
			if !bytes.Equal(spec.Raw(), origRaw) || !reflect.DeepEqual(spec.Types, orig.Types) || !bytes.Equal(spec.Strings, orig.Strings) {
				t.Error("Sanitize changed the spec")
			}
		})
	}
}

// checkSanitizedIDs parses the sanitized blob raw and checks that it has
// the types want, each under its index as type ID.
func checkSanitizedIDs(t *testing.T, raw []byte, want []Type) {
	t.Helper()

	sanitized, err := Parse(raw, binary.LittleEndian)
	mustSucceed(t, "Parse", err)
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

	got, err := spec.Sanitize(KernelFeatures{DeclTag: true, TypeTag: true, QmarkDatasec: true, Float: true})
	mustSucceed(t, "Sanitize", err)
	want := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: off["w"], Kind: KindUnion, SizeOrType: 8, Members: []Member{{NameOff: off["L"], Type: 3}}},
		{NameOff: off["enum64_placeholder"], Kind: KindTypedef, SizeOrType: 1},
		{NameOff: off["enum64_placeholder"], Kind: KindInt, SizeOrType: 1, Int: &Int{Encoding: 8}},
	}, string(strs)).Raw()
	if !bytes.Equal(got, want) {
		t.Errorf("sanitized blob =\n%x\nwant\n%x", got, want)
	}
}

// TestSanitizeHeaderData sanitizes a blob whose header has a field past the
// string section set. Sanitize rewrites its type tag in place, but cannot
// add the enum64 placeholder INT, which needs the blob rebuilt.
func TestSanitizeHeaderData(t *testing.T) {
	strs, off := testStrings("user", "w", "L")
	built := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: off["user"], Kind: KindTypeTag},
		{NameOff: off["w"], Kind: KindEnum64, SizeOrType: 8, Enum64s: []Enum64{{NameOff: off["L"], Value: 1}}},
	}, string(strs))
	raw := bytes.Clone(built.Raw())
	binary.LittleEndian.PutUint32(raw[minHdrLen:], 4)
	spec, err := Parse(raw, binary.LittleEndian)
	mustSucceed(t, "Parse", err)

	if _, err := spec.Sanitize(KernelFeatures{DeclTag: true, Enum64: true, QmarkDatasec: true, Float: true}); err != nil {
		t.Errorf("Sanitize of the type tag: %v", err)
	}
	if _, err := spec.Sanitize(KernelFeatures{DeclTag: true, TypeTag: true, QmarkDatasec: true, Float: true}); err == nil {
		t.Error("Sanitize added the enum64 placeholder to a blob with header data past the string section")
	}
}
