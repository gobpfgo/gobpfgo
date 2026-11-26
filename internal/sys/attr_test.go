// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"testing"
)

type attrFixture struct {
	Case   string `json:"case"`
	Arch   string `json:"arch"`
	Kernel string `json:"kernel"`
	Input  struct {
		MapType               uint32 `json:"map_type"`
		Name                  string `json:"name"`
		KeySize               uint32 `json:"key_size"`
		ValueSize             uint32 `json:"value_size"`
		MaxEntries            uint32 `json:"max_entries"`
		MapFlags              uint32 `json:"map_flags"`
		BtfFD                 uint32 `json:"btf_fd"`
		BtfKeyTypeID          uint32 `json:"btf_key_type_id"`
		BtfValueTypeID        uint32 `json:"btf_value_type_id"`
		BtfVmlinuxValueTypeID uint32 `json:"btf_vmlinux_value_type_id"`
		InnerMapFD            uint32 `json:"inner_map_fd"`
		MapExtra              uint64 `json:"map_extra"`
		NumaNode              uint32 `json:"numa_node"`
		MapIfindex            uint32 `json:"map_ifindex"`
		ValueTypeBtfObjFD     int32  `json:"value_type_btf_obj_fd"`
		TokenFD               int32  `json:"token_fd"`
		ExclProgHashSize      uint32 `json:"excl_prog_hash_size"`
	} `json:"input"`
	Size int    `json:"size"`
	Hex  string `json:"hex"`
}

func TestMapCreateAttr(t *testing.T) {
	data, err := os.ReadFile("../../testdata/oracle/attr.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var f attrFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if !archMatches(f.Arch) {
		t.Skipf("fixture is for %s, running on %s", f.Arch, runtime.GOARCH)
	}
	if f.Size != MapCreateAttrSize {
		t.Fatalf("fixture size = %d, Go size = %d", f.Size, MapCreateAttrSize)
	}

	attr := &MapCreateAttr{
		MapType:               f.Input.MapType,
		KeySize:               f.Input.KeySize,
		ValueSize:             f.Input.ValueSize,
		MaxEntries:            f.Input.MaxEntries,
		MapFlags:              f.Input.MapFlags,
		InnerMapFD:            f.Input.InnerMapFD,
		NumaNode:              f.Input.NumaNode,
		MapIfindex:            f.Input.MapIfindex,
		BtfFD:                 f.Input.BtfFD,
		BtfKeyTypeID:          f.Input.BtfKeyTypeID,
		BtfValueTypeID:        f.Input.BtfValueTypeID,
		BtfVmlinuxValueTypeID: f.Input.BtfVmlinuxValueTypeID,
		MapExtra:              f.Input.MapExtra,
		ValueTypeBtfObjFD:     f.Input.ValueTypeBtfObjFD,
		MapTokenFD:            f.Input.TokenFD,
		ExclProgHashSize:      f.Input.ExclProgHashSize,
	}
	attr.SetMapName(f.Input.Name)

	got := attr.Marshal()
	if len(got) != f.Size {
		t.Fatalf("marshaled %d bytes, libbpf passes %d", len(got), f.Size)
	}
	want, err := hex.DecodeString(f.Hex)
	if err != nil {
		t.Fatalf("decode fixture hex: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("attribute mismatch\n got %x\nwant %x", got, want)
	}
}

func TestMapElemAttr(t *testing.T) {
	attr := &MapElemAttr{
		MapFD: 7,
		Key:   0x1122334455667788,
		Value: 0x99aabbccddeeff00,
		Flags: 3,
	}

	got := attr.Marshal()
	if len(got) != MapElemAttrSize {
		t.Fatalf("marshaled %d bytes, want %d", len(got), MapElemAttrSize)
	}
	if v := binary.NativeEndian.Uint32(got[0:]); v != attr.MapFD {
		t.Errorf("map_fd = %#x, want %#x", v, attr.MapFD)
	}
	if v := binary.NativeEndian.Uint64(got[8:]); v != attr.Key {
		t.Errorf("key = %#x, want %#x", v, attr.Key)
	}
	if v := binary.NativeEndian.Uint64(got[16:]); v != attr.Value {
		t.Errorf("value = %#x, want %#x", v, attr.Value)
	}
	if v := binary.NativeEndian.Uint64(got[24:]); v != attr.Flags {
		t.Errorf("flags = %#x, want %#x", v, attr.Flags)
	}
}
