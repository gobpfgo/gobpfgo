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
