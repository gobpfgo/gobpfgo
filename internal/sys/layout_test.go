// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"bytes"
	"encoding/binary"
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
	LibbpfCommit    string       `json:"libbpf_commit"`
	Arch            string       `json:"arch"`
	Kernel          string       `json:"kernel"`
	MapCreate       fixtureBlock `json:"map_create"`
	MapElem         fixtureBlock `json:"map_elem"`
	ObjPin          fixtureBlock `json:"obj_pin"`
	BtfLoad         fixtureBlock `json:"btf_load"`
	ProgLoad        fixtureBlock `json:"prog_load"`
	LinkCreate      fixtureBlock `json:"link_create"`
	LinkUpdate      fixtureBlock `json:"link_update"`
	RawTracepoint   fixtureBlock `json:"raw_tracepoint"`
	GetNextID       fixtureBlock `json:"get_next_id"`
	BtfGetFDByID    fixtureBlock `json:"btf_get_fd_by_id"`
	ObjInfo         fixtureBlock `json:"obj_info"`
	MapInfo         fixtureBlock `json:"map_info"`
	ProgInfo        fixtureBlock `json:"prog_info"`
	BtfInfo         fixtureBlock `json:"btf_info"`
	PerfEvent       fixtureBlock `json:"perf_event"`
	PerfEventHeader fixtureBlock `json:"perf_event_header"`
	PerfSample      fixtureBlock `json:"perf_sample"`
	PerfLost        fixtureBlock `json:"perf_lost"`
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

func TestObjPinLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "obj_pin", f.ObjPin, ObjPinAttrSize, objPinFieldLayout())
}

func TestBtfLoadLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "btf_load", f.BtfLoad, BtfLoadAttrSize, btfLoadFieldLayout())
}

func TestProgLoadLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "prog_load", f.ProgLoad, ProgLoadAttrSize, progLoadFieldLayout())
}

func TestLinkCreateLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "link_create", f.LinkCreate, LinkCreateAttrSize, linkCreateFieldLayout())
}

func TestLinkUpdateLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "link_update", f.LinkUpdate, LinkUpdateAttrSize, linkUpdateFieldLayout())
}

func TestRawTracepointLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "raw_tracepoint", f.RawTracepoint, RawTracepointAttrSize, rawTracepointFieldLayout())
}

func TestGetNextIDLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "get_next_id", f.GetNextID, GetNextIDAttrSize, getNextIDFieldLayout())
}

func TestBtfGetFDByIDLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "btf_get_fd_by_id", f.BtfGetFDByID, BtfGetFDByIDAttrSize, btfGetFDByIDFieldLayout())
}

func TestPerfEventLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "perf_event", f.PerfEvent, PerfEventDataTailEnd, perfEventFieldLayout())
}

func TestPerfEventHeaderLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "perf_event_header", f.PerfEventHeader, PerfEventHeaderSize, perfEventHeaderFieldLayout())
}

func TestPerfSampleLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "perf_sample", f.PerfSample, PerfSampleSizeEnd, perfSampleFieldLayout())
}

func TestPerfLostLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "perf_lost", f.PerfLost, PerfLostSize, perfLostFieldLayout())
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

func TestBtfInfoLayout(t *testing.T) {
	f := loadLayoutFixture(t)
	checkLayout(t, "btf_info", f.BtfInfo, BtfInfoSize, btfInfoFieldLayout())
}

// TestLinkCreateUprobeMultiAttrBytes places known values at the offsets and
// sizes libbpf's headers report for the uprobe multi fields and requires
// Marshal to produce exactly those bytes, with every other byte zero.
func TestLinkCreateUprobeMultiAttrBytes(t *testing.T) {
	f := loadLayoutFixture(t)

	attr := &LinkCreateAttr{
		ProgFD:                   7,
		AttachType:               48,
		UprobeMultiPath:          0x1111111111111111,
		UprobeMultiOffsets:       0x2222222222222222,
		UprobeMultiRefCtrOffsets: 0x3333333333333333,
		UprobeMultiCookies:       0x4444444444444444,
		UprobeMultiCnt:           3,
		UprobeMultiFlags:         1,
		UprobeMultiPID:           4242,
	}
	values := map[string]uint64{
		"prog_fd":                      7,
		"attach_type":                  48,
		"uprobe_multi.path":            0x1111111111111111,
		"uprobe_multi.offsets":         0x2222222222222222,
		"uprobe_multi.ref_ctr_offsets": 0x3333333333333333,
		"uprobe_multi.cookies":         0x4444444444444444,
		"uprobe_multi.cnt":             3,
		"uprobe_multi.flags":           1,
		"uprobe_multi.pid":             4242,
	}

	want := fixtureBytes(t, f.LinkCreate, values)
	if got := attr.Marshal(); !bytes.Equal(got, want) {
		t.Fatalf("link_create bytes:\n got %x\nwant %x", got, want)
	}
}

// fixtureBytes builds an attribute of block.AttrSize bytes with each named
// value written at the offset and size the fixture records for that field.
func fixtureBytes(t *testing.T, block fixtureBlock, values map[string]uint64) []byte {
	t.Helper()

	buf := make([]byte, block.AttrSize)
	written := 0
	for _, field := range block.Fields {
		value, ok := values[field.Name]
		if !ok {
			continue
		}
		switch field.Size {
		case 4:
			binary.NativeEndian.PutUint32(buf[field.Offset:], uint32(value))
		case 8:
			binary.NativeEndian.PutUint64(buf[field.Offset:], value)
		default:
			t.Fatalf("field %s has unsupported size %d", field.Name, field.Size)
		}
		written++
	}
	if written != len(values) {
		t.Fatalf("fixture has %d of the %d fields the test writes", written, len(values))
	}
	return buf
}

// TestBtfIDAttrBytes writes known values into the BTF ID iteration and open
// attributes and the program load fd_array, and requires Marshal to put
// them at the offsets libbpf's headers report, with every other byte zero.
func TestBtfIDAttrBytes(t *testing.T) {
	f := loadLayoutFixture(t)

	tests := []struct {
		name   string
		block  fixtureBlock
		got    []byte
		values map[string]uint64
	}{
		{
			name:   "get_next_id",
			block:  f.GetNextID,
			got:    (&GetNextIDAttr{StartID: 11, NextID: 12, OpenFlags: 13}).Marshal(),
			values: map[string]uint64{"start_id": 11, "next_id": 12, "open_flags": 13},
		},
		{
			name:   "btf_get_fd_by_id",
			block:  f.BtfGetFDByID,
			got:    (&BtfGetFDByIDAttr{BtfID: 21, OpenFlags: 22, FdByIDTokenFD: 23}).Marshal(),
			values: map[string]uint64{"btf_id": 21, "open_flags": 22, "fd_by_id_token_fd": 23},
		},
		{
			name:   "prog_load",
			block:  f.ProgLoad,
			got:    (&ProgLoadAttr{ProgType: 2, FdArray: 0x5555555555555555}).Marshal(),
			values: map[string]uint64{"prog_type": 2, "fd_array": 0x5555555555555555},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if want := fixtureBytes(t, tt.block, tt.values); !bytes.Equal(tt.got, want) {
				t.Fatalf("%s bytes:\n got %x\nwant %x", tt.name, tt.got, want)
			}
		})
	}
}
