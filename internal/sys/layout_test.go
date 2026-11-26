// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

type fixtureField struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Size   int    `json:"size"`
}

type fixtureBlock struct {
	AttrSize int            `json:"attr_size"`
	Fields   []fixtureField `json:"fields"`
}

type layoutFixture struct {
	LibbpfCommit string       `json:"libbpf_commit"`
	Arch         string       `json:"arch"`
	Kernel       string       `json:"kernel"`
	MapCreate    fixtureBlock `json:"map_create"`
	MapElem      fixtureBlock `json:"map_elem"`
	BtfLoad      fixtureBlock `json:"btf_load"`
	ProgLoad     fixtureBlock `json:"prog_load"`
	ObjInfo      fixtureBlock `json:"obj_info"`
	MapInfo      fixtureBlock `json:"map_info"`
	ProgInfo     fixtureBlock `json:"prog_info"`
}

func loadLayoutFixture(t *testing.T) layoutFixture {
	t.Helper()

	data, err := os.ReadFile("../../testdata/oracle/layout.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var f layoutFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if !archMatches(f.Arch) {
		t.Skipf("fixture is for %s, running on %s", f.Arch, runtime.GOARCH)
	}
	if f.LibbpfCommit == "" {
		t.Fatal("fixture has no libbpf commit")
	}
	return f
}

func checkLayout(t *testing.T, name string, want fixtureBlock, gotSize int, got []fieldLayout) {
	t.Helper()

	if want.AttrSize != gotSize {
		t.Fatalf("%s attr size = %d, libbpf uses %d", name, gotSize, want.AttrSize)
	}

	fields := make(map[string]fieldLayout)
	for _, field := range got {
		fields[field.Name] = field
	}
	if len(fields) != len(want.Fields) {
		t.Fatalf("%s field count = %d, libbpf has %d", name, len(fields), len(want.Fields))
	}
	for _, w := range want.Fields {
		field, ok := fields[w.Name]
		if !ok {
			t.Errorf("%s field %s missing from Go layout", name, w.Name)
			continue
		}
		if field.Offset != w.Offset || field.Size != w.Size {
			t.Errorf("%s.%s: Go offset/size %d/%d, libbpf %d/%d",
				name, w.Name, field.Offset, field.Size, w.Offset, w.Size)
		}
	}
}

func TestMapCreateLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "map_create", f.MapCreate, MapCreateAttrSize, mapCreateFieldLayout())
}

func TestMapElemLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "map_elem", f.MapElem, MapElemAttrSize, mapElemFieldLayout())
}

func TestBtfLoadLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "btf_load", f.BtfLoad, BtfLoadAttrSize, btfLoadFieldLayout())
}

func TestProgLoadLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "prog_load", f.ProgLoad, ProgLoadAttrSize, progLoadFieldLayout())
}

func TestObjInfoLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "obj_info", f.ObjInfo, ObjInfoAttrSize, objInfoFieldLayout())
}

func TestMapInfoLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "map_info", f.MapInfo, MapInfoSize, mapInfoFieldLayout())
}

func TestProgInfoLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "prog_info", f.ProgInfo, ProgInfoSize, progInfoFieldLayout())
}
