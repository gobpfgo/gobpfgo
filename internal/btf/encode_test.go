// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/elf"
)

func parseObjectBTF(t *testing.T, name string) (*Spec, *elf.Object) {
	t.Helper()

	o, err := elf.Open(filepath.Join("../../testdata/progs", name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	spec, err := Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse %s BTF: %v", name, err)
	}
	return spec, o
}

// TestAppendTypeRoundTrip re-encodes every type of each object and expects
// the type section bytes back. dump.bpf.o covers every BTF kind.
func TestAppendTypeRoundTrip(t *testing.T) {
	for _, name := range []string{"dump.bpf.o", "kprobe.bpf.o", "core.bpf.o", "link_text_a.bpf.o"} {
		t.Run(name, func(t *testing.T) {
			spec, _ := parseObjectBTF(t, name)

			var got []byte
			for i := 1; i < len(spec.Types); i++ {
				got = AppendType(got, &spec.Types[i], binary.LittleEndian)
			}
			h := spec.Header
			want := spec.Raw()[h.HdrLen+h.TypeOff:][:h.TypeLen]
			if !bytes.Equal(got, want) {
				t.Fatalf("encoded %d bytes differ from the %d-byte type section", len(got), len(want))
			}
		})
	}
}

func TestTypeClone(t *testing.T) {
	spec, _ := parseObjectBTF(t, "dump.bpf.o")

	for i := 1; i < len(spec.Types); i++ {
		orig := &spec.Types[i]
		before := AppendType(nil, orig, binary.LittleEndian)

		c := orig.Clone()
		if err := c.VisitTypeIDs(func(id *uint32) error { *id += 1000; return nil }); err != nil {
			t.Fatalf("VisitTypeIDs: %v", err)
		}
		if c.Var != nil {
			c.Var.Linkage++
		}

		if after := AppendType(nil, orig, binary.LittleEndian); !bytes.Equal(before, after) {
			t.Fatalf("type %d changed through its clone", i)
		}
	}
}

func TestVisitTypeIDs(t *testing.T) {
	tests := []struct {
		name string
		t    Type
		want []uint32
	}{
		{"ptr", Type{Kind: KindPtr, SizeOrType: 3}, []uint32{3}},
		{"int", Type{Kind: KindInt, SizeOrType: 4, Int: &Int{}}, nil},
		{"array", Type{Kind: KindArray, Array: &Array{Type: 5, IndexType: 6, Nelems: 2}}, []uint32{5, 6}},
		{"struct", Type{Kind: KindStruct, Members: []Member{{Type: 7}, {Type: 8}}}, []uint32{7, 8}},
		{"func proto", Type{Kind: KindFuncProto, SizeOrType: 9, Params: []Param{{Type: 10}}}, []uint32{9, 10}},
		{"datasec", Type{Kind: KindDatasec, DataSec: []VarSecInfo{{Type: 11}, {Type: 12}}}, []uint32{11, 12}},
		{"decl tag", Type{Kind: KindDeclTag, SizeOrType: 13, DeclTag: &DeclTag{ComponentIdx: -1}}, []uint32{13}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []uint32
			err := tt.t.VisitTypeIDs(func(id *uint32) error {
				got = append(got, *id)
				return nil
			})
			if err != nil {
				t.Fatalf("VisitTypeIDs: %v", err)
			}
			if !equalIDs(got, tt.want) {
				t.Fatalf("ids = %v, want %v", got, tt.want)
			}
		})
	}
}

func equalIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestParseExtRaw checks the raw blocks of an object with a .text subprogram:
// one function block and one line block per program section, and function
// and line records that match ParseExt.
func TestParseExtRaw(t *testing.T) {
	spec, o := parseObjectBTF(t, "link_text_b.bpf.o")

	raw, err := ParseExtRaw(o.BTFExt, spec, o.ByteOrder)
	if err != nil {
		t.Fatalf("ParseExtRaw: %v", err)
	}
	ext, err := ParseExt(o.BTFExt, spec, o.ByteOrder)
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}

	if got := blockSections(raw.FuncInfo); !equalStrings(got, []string{"kprobe/do_sys_open", ".text"}) {
		t.Fatalf("func blocks = %v", got)
	}
	if got := blockSections(raw.LineInfo); !equalStrings(got, []string{"kprobe/do_sys_open", ".text"}) {
		t.Fatalf("line blocks = %v", got)
	}
	for i, block := range raw.FuncInfo {
		if block.RecSize != FuncInfoMinSize || len(block.Records) != FuncInfoMinSize*len(ext.FuncInfos[i].Records) {
			t.Fatalf("func block %s: record size %d, %d bytes", block.Section, block.RecSize, len(block.Records))
		}
		if got := o.ByteOrder.Uint32(block.Records[4:]); got != ext.FuncInfos[i].Records[0].TypeID {
			t.Fatalf("func block %s type id = %d, want %d", block.Section, got, ext.FuncInfos[i].Records[0].TypeID)
		}
	}
	if len(ext.LineInfos) != len(raw.LineInfo) {
		t.Fatalf("ParseExt line sections = %d, raw blocks = %d", len(ext.LineInfos), len(raw.LineInfo))
	}
	for i, block := range raw.LineInfo {
		records := ext.LineInfos[i].Records
		if ext.LineInfos[i].Section != block.Section || block.RecSize != LineInfoMinSize || len(block.Records) != LineInfoMinSize*len(records) {
			t.Fatalf("line block %s: record size %d, %d bytes, %d decoded records", block.Section, block.RecSize, len(block.Records), len(records))
		}
		for j, rec := range records {
			raw := block.Records[j*LineInfoMinSize:]
			want := LineInfo{
				InsnOff:     o.ByteOrder.Uint32(raw),
				FileNameOff: o.ByteOrder.Uint32(raw[4:]),
				LineOff:     o.ByteOrder.Uint32(raw[8:]),
				LineCol:     o.ByteOrder.Uint32(raw[12:]),
			}
			if rec != want {
				t.Fatalf("line block %s record %d = %+v, want %+v", block.Section, j, rec, want)
			}
		}
	}
}

func blockSections(blocks []ExtRecords) []string {
	var names []string
	for _, b := range blocks {
		names = append(names, b.Section)
	}
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
