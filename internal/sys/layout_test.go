// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

//go:build linux && (amd64 || arm64)

package sys

import (
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

type layoutFixture struct {
	LibbpfCommit string `json:"libbpf_commit"`
	Arch         string `json:"arch"`
	Kernel       string `json:"kernel"`
	MapCreate    struct {
		AttrSize int `json:"attr_size"`
		Fields   []struct {
			Name   string `json:"name"`
			Offset int    `json:"offset"`
			Size   int    `json:"size"`
		} `json:"fields"`
	} `json:"map_create"`
}

func TestMapCreateLayout(t *testing.T) {
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
	if f.MapCreate.AttrSize != MapCreateAttrSize {
		t.Fatalf("attr size = %d, libbpf uses %d", MapCreateAttrSize, f.MapCreate.AttrSize)
	}

	got := make(map[string]fieldLayout)
	for _, field := range mapCreateFieldLayout() {
		got[field.Name] = field
	}
	if len(got) != len(f.MapCreate.Fields) {
		t.Fatalf("field count = %d, libbpf has %d", len(got), len(f.MapCreate.Fields))
	}
	for _, want := range f.MapCreate.Fields {
		field, ok := got[want.Name]
		if !ok {
			t.Errorf("field %s missing from Go layout", want.Name)
			continue
		}
		if field.Offset != want.Offset || field.Size != want.Size {
			t.Errorf("%s: Go offset/size %d/%d, libbpf %d/%d",
				want.Name, field.Offset, field.Size, want.Offset, want.Size)
		}
	}
}
