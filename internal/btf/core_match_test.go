// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"slices"
	"testing"
)

// TestEssentialName checks the flavor rule: a name loses everything from
// its last "___" that has a character other than '_' on both sides.
func TestEssentialName(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"task_struct", "task_struct"},
		{"task_struct___old", "task_struct"},
		{"a___b", "a"},
		{"a___b___c", "a___b"},
		{"ab___c", "ab"},
		{"x___y_", "x"},
		{"_a___b", "_a"},
		{"a___", "a___"},
		{"a____b", "a____b"},
		{"____x", "____x"},
		{"cm____odd___v", "cm____odd"},
		{"", ""},
	} {
		if got := essentialName(tc.name); got != tc.want {
			t.Errorf("essentialName(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCoreNamesMatch checks the name comparison of the type match: flavors
// are dropped on both sides, and an anonymous target matches only an
// anonymous local.
func TestCoreNamesMatch(t *testing.T) {
	for _, tc := range []struct {
		local, target string
		want          bool
	}{
		{"", "", true},
		{"a", "", false},
		{"", "a", false},
		{"a", "a", true},
		{"a___x", "a", true},
		{"a", "a___y", true},
		{"a___x", "a___y", true},
		{"a___x___y", "a", false},
		{"ab", "a", false},
	} {
		if got := coreNamesMatch(tc.local, tc.target); got != tc.want {
			t.Errorf("coreNamesMatch(%q, %q) = %v, want %v", tc.local, tc.target, got, tc.want)
		}
	}
}

// typeMatchSpec builds the synthetic types of TestTypesMatch, which C
// cannot express in core_match.bpf.c: integers of one name in another size
// or signedness, floats, enums and enum64s of the same size, forward
// declarations outside a pointer, and modifier and type tag chains.
func typeMatchSpec(t *testing.T) (*Spec, map[string]uint32) {
	t.Helper()

	b := newSpecBuilder()
	ids := map[string]uint32{}
	ids["int"] = b.add(intType("int", 4, 1))
	ids["int8"] = b.add(intType("int", 8, 1))
	ids["uint"] = b.add(intType("int", 4, 0))
	ids["float"] = b.add(Type{Kind: KindFloat, Name: "float", SizeOrType: 4})
	ids["enum"] = b.add(enumType("e", Enum{Name: "A", Value: 1}))
	ids["enum64"] = b.add(Type{Kind: KindEnum64, Name: "e", SizeOrType: 4, Enum64s: []Enum64{{Name: "A", Value: 1}, {Name: "B", Value: 2}}})
	ids["enum64_8"] = b.add(Type{Kind: KindEnum64, Name: "e", SizeOrType: 8, Enum64s: []Enum64{{Name: "A", Value: 1}}})
	ids["fwd"] = b.add(fwdType("s", false))
	ids["fwd_union"] = b.add(fwdType("s", true))
	ids["struct"] = b.add(structType(KindStruct, "s", 4, Member{Name: "x", Type: ids["int"]}))
	ids["union"] = b.add(structType(KindUnion, "s", 4, Member{Name: "x", Type: ids["int"]}))
	ids["ptr_struct"] = b.add(refType(KindPtr, "", ids["struct"]))
	ids["ptr_union"] = b.add(refType(KindPtr, "", ids["union"]))
	ids["ptr_fwd"] = b.add(refType(KindPtr, "", ids["fwd"]))
	ids["tag"] = b.add(refType(KindTypeTag, "user", ids["int"]))
	ids["const_tag"] = b.add(refType(KindConst, "", ids["tag"]))
	ids["typedef"] = b.add(refType(KindTypedef, "int_t", ids["const_tag"]))
	ids["proto"] = b.add(protoType(ids["int"], Param{Type: ids["int"]}))
	ids["proto_void"] = b.add(protoType(0, Param{Type: ids["int"]}))
	ids["array"] = b.add(arrayType(ids["int"], ids["int"], 2))
	ids["array_uint"] = b.add(arrayType(ids["uint"], ids["int"], 2))
	return b.spec(t), ids
}

// TestTypesMatch checks the match rules on synthetic types, in one spec used
// as both local and target. Every pair is matched both ways where the rule
// is symmetric.
func TestTypesMatch(t *testing.T) {
	s, ids := typeMatchSpec(t)

	for _, tc := range []struct {
		local, target string
		want          bool
	}{
		{"int", "int", true},
		{"int", "int8", false},
		{"int", "uint", false},
		{"float", "float", false},
		{"enum", "enum64", true},
		{"enum64", "enum", false},
		{"enum", "enum64_8", false},
		{"fwd", "fwd", true},
		{"fwd", "fwd_union", false},
		{"fwd", "struct", false},
		{"struct", "fwd", false},
		{"struct", "union", false},
		{"ptr_struct", "ptr_fwd", true},
		{"ptr_union", "ptr_fwd", false},
		{"ptr_fwd", "ptr_struct", true},
		{"ptr_fwd", "ptr_union", false},
		{"ptr_struct", "ptr_union", false},
		{"typedef", "int", true},
		{"int", "typedef", true},
		{"proto", "proto", true},
		{"proto", "proto_void", false},
		{"array", "array", true},
		{"array", "array_uint", false},
	} {
		got, err := TypesMatch(s, ids[tc.local], s, ids[tc.target])
		if err != nil || got != tc.want {
			t.Errorf("TypesMatch(%s, %s) = %v, %v, want %v", tc.local, tc.target, got, err, tc.want)
		}
	}

	if _, err := TypesMatch(s, 999, s, ids["int"]); err == nil {
		t.Error("TypesMatch with an invalid local type returned no error")
	}
	if _, err := TypesMatch(s, ids["ptr_struct"], s, ids["proto"]); err != nil {
		t.Errorf("TypesMatch of a pointer and a prototype: %v, want a mismatch", err)
	}
}

// TestTypesMatchLimits builds struct nesting and pointer chains around the
// limits: 31 nested structs match and 32 are an error, and so are 31 and 32
// pointers to an int.
func TestTypesMatchLimits(t *testing.T) {
	b := newSpecBuilder()
	intID := b.add(intType("int", 4, 1))
	nest := intID
	nests := map[int]uint32{}
	for n := 1; n <= 32; n++ {
		nest = b.add(structType(KindStruct, "nest", 4, Member{Name: "m", Type: nest}))
		nests[n] = nest
	}
	ptr := intID
	ptrs := map[int]uint32{}
	for n := 1; n <= 32; n++ {
		ptr = b.add(refType(KindPtr, "", ptr))
		ptrs[n] = ptr
	}
	s := b.spec(t)

	for _, tc := range []struct {
		name    string
		id      uint32
		wantErr bool
	}{
		{"31 nested structs", nests[31], false},
		{"32 nested structs", nests[32], true},
		{"31 pointers", ptrs[31], false},
		{"32 pointers", ptrs[32], true},
	} {
		got, err := TypesMatch(s, tc.id, s, tc.id)
		if (err != nil) != tc.wantErr || !tc.wantErr && !got {
			t.Errorf("%s: TypesMatch = %v, %v, want an error %v", tc.name, got, err, tc.wantErr)
		}
	}
}

// TestCoreCandidates checks the candidate search in one target spec: names
// compare without flavors, an enum finds an enum64, other kinds and
// anonymous types are skipped, and startID limits the search.
func TestCoreCandidates(t *testing.T) {
	b := newSpecBuilder()
	intID := b.add(intType("int", 4, 1))
	structID := b.add(structType(KindStruct, "s", 4, Member{Name: "x", Type: intID}))
	flavorID := b.add(structType(KindStruct, "s___v2", 4, Member{Name: "x", Type: intID}))
	b.add(structType(KindUnion, "s", 4, Member{Name: "x", Type: intID}))
	b.add(structType(KindStruct, "", 4, Member{Name: "x", Type: intID}))
	enum64ID := b.add(Type{Kind: KindEnum64, Name: "e", SizeOrType: 8, Enum64s: []Enum64{{Name: "A", Value: 1}}})
	s := b.spec(t)

	local := &Type{Kind: KindStruct, Name: "s___local"}
	if got := s.CoreCandidates(local, 1); !slices.Equal(got, []uint32{structID, flavorID}) {
		t.Errorf("struct candidates = %v, want [%d %d]", got, structID, flavorID)
	}
	if got := s.CoreCandidates(local, flavorID); !slices.Equal(got, []uint32{flavorID}) {
		t.Errorf("struct candidates from %d = %v, want [%d]", flavorID, got, flavorID)
	}
	if got := s.CoreCandidates(&Type{Kind: KindEnum, Name: "e"}, 1); !slices.Equal(got, []uint32{enum64ID}) {
		t.Errorf("enum candidates = %v, want [%d]", got, enum64ID)
	}
	if got := s.CoreCandidates(&Type{Kind: KindStruct, Name: "s___a___b"}, 1); len(got) != 0 {
		t.Errorf("candidates of s___a___b = %v, want none", got)
	}
}

// TestTypeMatchesRelo parses and computes a type_matches relocation on
// synthetic types: its access string must be "0", a match is 1 and a
// mismatch is not a candidate.
func TestTypeMatchesRelo(t *testing.T) {
	b := newSpecBuilder()
	intID := b.add(intType("int", 4, 1))
	localID := b.add(structType(KindStruct, "s___l", 4, Member{Name: "x", Type: intID}))
	badID := b.add(structType(KindStruct, "s___bad", 4, Member{Name: "y", Type: intID}))
	targetID := b.add(structType(KindStruct, "s", 8, Member{Name: "x", Type: intID}, Member{Name: "z", Type: intID}))
	zero := b.strs.add("0")
	field := b.strs.add("0:0")
	s := b.spec(t)

	relo := CoreRelo{TypeID: localID, AccessStrOff: zero, Kind: CoreTypeMatches}
	spec, err := s.ParseCoreSpec(relo)
	if err != nil || spec.RootTypeID != localID || spec.Kind != CoreTypeMatches || len(spec.Accessors) != 0 {
		t.Fatalf("ParseCoreSpec = %+v, %v, want a root-only type_matches spec", spec, err)
	}
	if _, err := s.ParseCoreSpec(CoreRelo{TypeID: localID, AccessStrOff: field, Kind: CoreTypeMatches}); err == nil {
		t.Error("ParseCoreSpec accepted a type_matches access string other than 0")
	}

	res, err := s.CalcCoreRelo(relo, s, targetID)
	if err != nil || !res.Matched || res.OrigVal != 1 || res.NewVal != 1 || !res.Validate || res.Poison {
		t.Errorf("matching CalcCoreRelo = %+v, %v, want a 1/1 match", res, err)
	}
	relo.TypeID = badID
	res, err = s.CalcCoreRelo(relo, s, targetID)
	if err != nil || res.Matched {
		t.Errorf("mismatching CalcCoreRelo = %+v, %v, want no match", res, err)
	}
}
