// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"strings"
	"testing"
)

// coreFormatSpec builds the types the synthetic spec format cases name:
// a named struct with a bitfield and an array, an anonymous struct, a typedef
// of the named struct, a signed and an unsigned enum, and a signed and an
// unsigned enum64.
func coreFormatSpec(t *testing.T) (*Spec, map[string]uint32) {
	t.Helper()

	b := newSpecBuilder()
	ids := map[string]uint32{}
	ids["int"] = b.add(intType("int", 4, 1))
	ids["array"] = b.add(arrayType(ids["int"], ids["int"], 4))
	ids["struct"] = b.add(structType(KindStruct, "sample", 24,
		Member{Name: "flags", Type: ids["int"], Offset: 11, BitfieldSize: 3},
		Member{Name: "values", Type: ids["array"], Offset: 32}))
	ids["anon"] = b.add(structType(KindStruct, "", 4, Member{Name: "x", Type: ids["int"]}))
	ids["typedef"] = b.add(refType(KindTypedef, "sample_t", ids["struct"]))
	signed := enumType("level", Enum{Name: "LOW", Value: -2}, Enum{Name: "HIGH", Value: 3})
	signed.KindFlag = true
	ids["signed"] = b.add(signed)
	ids["unsigned"] = b.add(enumType("mask", Enum{Name: "TOP", Value: -1}))
	wide := Type{Kind: KindEnum64, Name: "wide", SizeOrType: 8, Enum64s: []Enum64{{Name: "NEG", Value: 1<<64 - 5}}}
	wide.KindFlag = true
	ids["signed64"] = b.add(wide)
	ids["unsigned64"] = b.add(Type{Kind: KindEnum64, Name: "uwide", SizeOrType: 8, Enum64s: []Enum64{{Name: "BIG", Value: 1<<64 - 5}}})
	return b.spec(t), ids
}

// TestFormatCoreSpec formats synthetic specs for the cases core.bpf.o does
// not have: a bit offset inside a byte, a first index above zero, an
// anonymous or typedef root, signed and unsigned enum and enum64 values, the
// other relocation kind names, and an unknown kind, which has only the first
// part.
func TestFormatCoreSpec(t *testing.T) {
	s, ids := coreFormatSpec(t)
	field := func(kind CoreReloKind, root uint32, raw []uint32, bitOffset uint32, accessors ...CoreAccessor) *CoreSpec {
		return &CoreSpec{RootTypeID: root, Kind: kind, Raw: raw, Accessors: accessors, BitOffset: bitOffset}
	}
	enumval := func(kind CoreReloKind, root uint32, idx uint32) *CoreSpec {
		return &CoreSpec{RootTypeID: root, Kind: kind, Raw: []uint32{idx}}
	}

	for _, tc := range []struct {
		name string
		spec *CoreSpec
		want string
	}{
		{"bitfield", field(CoreFieldLShiftU64, ids["struct"], []uint32{0, 0}, 11,
			CoreAccessor{TypeID: ids["struct"]}, CoreAccessor{TypeID: ids["struct"], Name: "flags"}),
			"<lshift_u64> [3] struct sample.flags (0:0 @ offset 1.3)"},
		{"first index and array", field(CoreFieldByteSize, ids["struct"], []uint32{2, 1, 3}, 2*24*8+32+3*32,
			CoreAccessor{TypeID: ids["struct"], Index: 2}, CoreAccessor{TypeID: ids["struct"], Index: 1, Name: "values"},
			CoreAccessor{TypeID: ids["int"], Index: 3}),
			"<byte_sz> [3] struct sample[2].values[3] (2:1:3 @ offset 64)"},
		{"anonymous root", field(CoreFieldExists, ids["anon"], []uint32{0, 0}, 0,
			CoreAccessor{TypeID: ids["anon"]}, CoreAccessor{TypeID: ids["anon"], Name: "x"}),
			"<field_exists> [4] struct <anon>.x (0:0 @ offset 0)"},
		{"typedef root", field(CoreFieldSigned, ids["typedef"], []uint32{0}, 0, CoreAccessor{TypeID: ids["struct"]}),
			"<signed> [5] typedef sample_t (0 @ offset 0)"},
		{"rshift", field(CoreFieldRShiftU64, ids["struct"], []uint32{0, 0}, 11,
			CoreAccessor{TypeID: ids["struct"]}, CoreAccessor{TypeID: ids["struct"], Name: "flags"}),
			"<rshift_u64> [3] struct sample.flags (0:0 @ offset 1.3)"},
		{"signed enum", enumval(CoreEnumvalExists, ids["signed"], 0), "<enumval_exists> [6] enum level::LOW = -2"},
		{"unsigned enum", enumval(CoreEnumvalValue, ids["unsigned"], 0), "<enumval_value> [7] enum mask::TOP = 4294967295"},
		{"signed enum64", enumval(CoreEnumvalValue, ids["signed64"], 0), "<enumval_value> [8] enum64 wide::NEG = -5"},
		{"unsigned enum64", enumval(CoreEnumvalValue, ids["unsigned64"], 0), "<enumval_value> [9] enum64 uwide::BIG = 18446744073709551611"},
		{"type matches", &CoreSpec{RootTypeID: ids["struct"], Kind: CoreTypeMatches}, "<type_matches> [3] struct sample"},
		{"unknown kind", field(CoreReloKind(13), ids["struct"], []uint32{0}, 0, CoreAccessor{TypeID: ids["struct"]}),
			"<unknown> [3] struct sample"},
	} {
		got, err := s.FormatCoreSpec(tc.spec)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: spec = %q, want %q", tc.name, got, tc.want)
		}
	}

	for _, bad := range []*CoreSpec{
		{RootTypeID: 100, Kind: CoreTypeExists},
		enumval(CoreEnumvalValue, ids["signed"], 2),
		enumval(CoreEnumvalValue, ids["signed64"], 1),
		{RootTypeID: ids["signed"], Kind: CoreEnumvalValue},
	} {
		if got, err := s.FormatCoreSpec(bad); err == nil {
			t.Errorf("spec %+v formatted as %q, want an error", bad, got)
		}
	}
}

// TestFormatCoreSpecLong formats a spec longer than the 256 bytes libbpf's
// log buffer holds. The text is not cut; the caller cuts it.
func TestFormatCoreSpecLong(t *testing.T) {
	b := newSpecBuilder()
	intID := b.add(intType("int", 4, 1))
	long := strings.Repeat("f", 300)
	rootID := b.add(structType(KindStruct, "s", 4, Member{Name: long, Type: intID}))
	s := b.spec(t)

	got, err := s.FormatCoreSpec(&CoreSpec{
		RootTypeID: rootID,
		Kind:       CoreFieldByteOffset,
		Raw:        []uint32{0, 0},
		Accessors:  []CoreAccessor{{TypeID: rootID}, {TypeID: rootID, Name: long}},
	})
	want := "<byte_off> [2] struct s." + long + " (0:0 @ offset 0)"
	if err != nil || got != want {
		t.Fatalf("spec = %q, %v, want %q", got, err, want)
	}
}

// TestCoreReloKindLogString checks every short kind name against libbpf's
// core_relo_kind_str and that CoreReloKind.String keeps its own names.
func TestCoreReloKindLogString(t *testing.T) {
	want := map[CoreReloKind]string{
		CoreFieldByteOffset: "byte_off",
		CoreFieldByteSize:   "byte_sz",
		CoreFieldExists:     "field_exists",
		CoreFieldSigned:     "signed",
		CoreFieldLShiftU64:  "lshift_u64",
		CoreFieldRShiftU64:  "rshift_u64",
		CoreTypeIDLocal:     "local_type_id",
		CoreTypeIDTarget:    "target_type_id",
		CoreTypeExists:      "type_exists",
		CoreTypeSize:        "type_size",
		CoreEnumvalExists:   "enumval_exists",
		CoreEnumvalValue:    "enumval_value",
		CoreTypeMatches:     "type_matches",
		13:                  "unknown",
	}
	for k, name := range want {
		if got := coreReloKindLogString(k); got != name {
			t.Errorf("kind %d: %q, want %q", k, got, name)
		}
	}
	if got := CoreFieldByteOffset.String(); got != "field_byte_offset" {
		t.Errorf("CoreFieldByteOffset.String() = %q, want field_byte_offset", got)
	}
}

// TestBtfKindString checks every kind name against libbpf's
// __btf_kind_str, including the location kinds the parser does not read
// and an unknown kind.
func TestBtfKindString(t *testing.T) {
	want := []string{
		"void", "int", "ptr", "array", "struct", "union", "enum", "fwd",
		"typedef", "volatile", "const", "restrict", "func", "func_proto",
		"var", "datasec", "float", "decl_tag", "type_tag", "enum64",
		"loc_param", "loc_proto", "locsec", "unknown",
	}
	for k, name := range want {
		if got := btfKindString(Kind(k)); got != name {
			t.Errorf("kind %d: %q, want %q", k, got, name)
		}
	}
}
