// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/elf"
)

type coreFixtureAccessor struct {
	TypeID uint32 `json:"type_id"`
	Index  uint32 `json:"idx"`
	Name   string `json:"name"`
}

type coreFixtureRelo struct {
	Section    string                `json:"section"`
	InsnOff    uint32                `json:"insn_off"`
	TypeID     uint32                `json:"type_id"`
	Kind       uint32                `json:"kind"`
	Access     string                `json:"access"`
	RootTypeID uint32                `json:"root_type_id"`
	BitOffset  uint32                `json:"bit_offset"`
	Spec       string                `json:"spec"`
	Accessors  []coreFixtureAccessor `json:"accessors"`
}

type coreFixture struct {
	Relos []coreFixtureRelo `json:"relos"`
}

// TestParseCoreSpec parses the local spec of every CO-RE relocation in
// core.bpf.o and in core_match.bpf.o, whose relocations are all type-based,
// type_matches among them, formats it, and compares both with what libbpf's
// bpf_core_parse_spec and bpf_core_format_spec produce.
func TestParseCoreSpec(t *testing.T) {
	for _, tc := range []struct{ object, fixture string }{
		{"core.bpf.o", "core.json"},
		{"core_match.bpf.o", "core-match.json"},
	} {
		t.Run(tc.object, func(t *testing.T) {
			got := parseCoreSpecs(t, "../../testdata/progs/"+tc.object)
			data, err := os.ReadFile("../../testdata/oracle/" + tc.fixture)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var want coreFixture
			if err := json.Unmarshal(data, &want); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if !reflect.DeepEqual(got, want.Relos) {
				t.Fatalf("core specs differ\n got %+v\nwant %+v", got, want.Relos)
			}
		})
	}
}

// parseCoreSpecs parses and formats the local spec of every CO-RE
// relocation of the object at path, in .BTF.ext order.
func parseCoreSpecs(t *testing.T, path string) []coreFixtureRelo {
	t.Helper()

	o, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open object: %v", err)
	}
	spec, err := Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse BTF: %v", err)
	}
	ext, err := ParseExt(o.BTFExt, spec, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse BTF.ext: %v", err)
	}

	var got []coreFixtureRelo
	for _, section := range ext.CoreRelos {
		for _, relo := range section.Relos {
			access, err := spec.String(relo.AccessStrOff)
			if err != nil {
				t.Fatalf("access string: %v", err)
			}
			core, err := spec.ParseCoreSpec(relo)
			if err != nil {
				t.Fatalf("parse core spec of insn %d: %v", relo.InsnOff, err)
			}
			text, err := spec.FormatCoreSpec(core)
			if err != nil {
				t.Fatalf("format core spec of insn %d: %v", relo.InsnOff, err)
			}

			got = append(got, coreFixtureRelo{
				Section:    section.Section,
				InsnOff:    relo.InsnOff,
				TypeID:     relo.TypeID,
				Kind:       uint32(relo.Kind),
				Access:     access,
				RootTypeID: core.RootTypeID,
				BitOffset:  core.BitOffset,
				Spec:       text,
				Accessors:  coreFixtureAccessors(core.Accessors),
			})
		}
	}
	return got
}

func TestCalcCoreRelo(t *testing.T) {
	localO, err := elf.Open("../../testdata/progs/core.bpf.o")
	if err != nil {
		t.Fatalf("open local object: %v", err)
	}
	local, err := Parse(localO.BTF, localO.ByteOrder)
	if err != nil {
		t.Fatalf("parse local BTF: %v", err)
	}
	ext, err := ParseExt(localO.BTFExt, local, localO.ByteOrder)
	if err != nil {
		t.Fatalf("parse local BTF.ext: %v", err)
	}

	targetO, err := elf.Open("../../testdata/progs/core_target.bpf.o")
	if err != nil {
		t.Fatalf("open target object: %v", err)
	}
	target, err := Parse(targetO.BTF, targetO.ByteOrder)
	if err != nil {
		t.Fatalf("parse target BTF: %v", err)
	}

	targetType := target.Find("core_sample", KindStruct)
	if targetType == nil {
		t.Fatal("target core_sample not found")
	}
	var relo CoreRelo
	found := false
	for _, section := range ext.CoreRelos {
		for _, candidate := range section.Relos {
			if candidate.Kind != CoreFieldByteOffset {
				continue
			}
			localType, err := local.TypeByID(candidate.TypeID)
			if err == nil && localType.Name == "core_sample" {
				relo = candidate
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no field relocation in %+v", ext.CoreRelos)
	}

	res, err := local.CalcCoreRelo(relo, target, targetType.ID)
	if err != nil {
		t.Fatalf("CalcCoreRelo: %v", err)
	}
	if res.OrigVal != 4 || res.NewVal != 8 {
		t.Fatalf("values = %d/%d, want 4/8", res.OrigVal, res.NewVal)
	}
	if res.OrigSize != 4 || res.NewSize != 4 {
		t.Fatalf("sizes = %d/%d, want 4/4", res.OrigSize, res.NewSize)
	}
	if !res.Validate || res.Poison || res.FailMemSizeAdjust {
		t.Fatalf("flags = validate:%v poison:%v memsz:%v", res.Validate, res.Poison, res.FailMemSizeAdjust)
	}
}

func coreFixtureAccessors(accessors []CoreAccessor) []coreFixtureAccessor {
	out := make([]coreFixtureAccessor, 0, len(accessors))
	for _, acc := range accessors {
		out = append(out, coreFixtureAccessor{
			TypeID: acc.TypeID,
			Index:  acc.Index,
			Name:   acc.Name,
		})
	}
	return out
}

// openCoreObject parses the .BTF and the CO-RE records of the only CO-RE
// section of the named object in testdata/progs.
func openCoreObject(t *testing.T, name string) (*Spec, []CoreRelo) {
	t.Helper()

	o, err := elf.Open("../../testdata/progs/" + name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	spec, err := Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse %s BTF: %v", name, err)
	}
	if len(o.BTFExt) == 0 {
		return spec, nil
	}
	ext, err := ParseExt(o.BTFExt, spec, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse %s BTF.ext: %v", name, err)
	}
	if len(ext.CoreRelos) != 1 {
		t.Fatalf("%s: %d CO-RE sections, want one", name, len(ext.CoreRelos))
	}
	return spec, ext.CoreRelos[0].Relos
}

// TestCalcCoreFieldExists relocates field_exists of cc_amb.y from
// core_amb.bpf.o against the candidates of core_cands_target.bpf.o, which
// have y at bit 32 and bit 0, and against cc_pick, which has no y. The
// original value 1 is checked in every case, and a match records the bit
// offset of the target field.
func TestCalcCoreFieldExists(t *testing.T) {
	local, relos := openCoreObject(t, "core_amb.bpf.o")
	target, _ := openCoreObject(t, "core_cands_target.bpf.o")
	exists := relos[0]
	if exists.Kind != CoreFieldExists {
		t.Fatalf("first record kind = %s, want field_exists", exists.Kind)
	}

	for _, tc := range []struct {
		target    string
		matched   bool
		newVal    uint64
		bitOffset uint32
	}{
		{"cc_amb", true, 1, 32},
		{"cc_amb___v2", true, 1, 0},
		{"cc_pick", false, 0, 0},
	} {
		targetType := target.Find(tc.target, KindStruct)
		if targetType == nil {
			t.Fatalf("target %s not found", tc.target)
		}
		res, err := local.CalcCoreRelo(exists, target, targetType.ID)
		if err != nil {
			t.Fatalf("%s: CalcCoreRelo: %v", tc.target, err)
		}
		if res.Matched != tc.matched || res.OrigVal != 1 || res.NewVal != tc.newVal || !res.Validate || res.TargetBitOffset != tc.bitOffset {
			t.Errorf("%s: result %+v, want matched %v, 1/%d, validated, target bit offset %d",
				tc.target, res, tc.matched, tc.newVal, tc.bitOffset)
		}
	}
}

// TestCalcCoreFieldLocal computes the local side of the field records of
// core_local.bpf.o: field_exists is 1 and checked, the signedness of the int
// val is 1, and the signedness of the array element arr[1] fails. A
// type-based record is not a field record.
func TestCalcCoreFieldLocal(t *testing.T) {
	local, relos := openCoreObject(t, "core_local.bpf.o")
	exists, typeExists, signed, signedElem := relos[0], relos[1], relos[2], relos[3]

	res, err := local.CalcCoreFieldLocal(exists)
	if err != nil || res.OrigVal != 1 || !res.Validate || res.Poison || res.Matched {
		t.Errorf("field_exists = %+v, %v, want 1, validated", res, err)
	}
	res, err = local.CalcCoreFieldLocal(signed)
	if err != nil || res.OrigVal != 1 || !res.Validate {
		t.Errorf("field_signed of val = %+v, %v, want 1, validated", res, err)
	}
	if _, err := local.CalcCoreFieldLocal(signedElem); err == nil {
		t.Error("field_signed of arr[1] succeeded, want the array access error")
	}
	if _, err := local.CalcCoreFieldLocal(typeExists); err == nil {
		t.Errorf("CalcCoreFieldLocal accepted a %s record", typeExists.Kind)
	}
}
