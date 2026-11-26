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
	Accessors  []coreFixtureAccessor `json:"accessors"`
}

type coreFixture struct {
	Relos []coreFixtureRelo `json:"relos"`
}

func TestParseCoreSpec(t *testing.T) {
	o, err := elf.Open("../../testdata/progs/core.bpf.o")
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
				t.Fatalf("parse core spec: %v", err)
			}

			got = append(got, coreFixtureRelo{
				Section:    section.Section,
				InsnOff:    relo.InsnOff,
				TypeID:     relo.TypeID,
				Kind:       uint32(relo.Kind),
				Access:     access,
				RootTypeID: core.RootTypeID,
				BitOffset:  core.BitOffset,
				Accessors:  coreFixtureAccessors(core.Accessors),
			})
		}
	}

	data, err := os.ReadFile("../../testdata/oracle/core.json")
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
			if candidate.Kind == CoreFieldByteOffset {
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
