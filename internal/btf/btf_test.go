// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"encoding/binary"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/elf"
)

func TestParseKprobeBTF(t *testing.T) {
	o, err := elf.Open("../../testdata/progs/kprobe.bpf.o")
	if err != nil {
		t.Fatalf("open object: %v", err)
	}
	spec, err := Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if spec.Header.Magic != 0xeb9f {
		t.Fatalf("magic = 0x%x", spec.Header.Magic)
	}
	if spec.Header.Version != 1 {
		t.Fatalf("version = %d", spec.Header.Version)
	}
	if len(spec.Types) < 22 {
		t.Fatalf("parsed %d types, want at least 22", len(spec.Types))
	}
	if spec.Types[0].Kind != KindVoid {
		t.Fatalf("type 0 kind = %v, want void", spec.Types[0].Kind)
	}

	counts := spec.Find("counts", KindVar)
	if counts == nil {
		t.Fatal("counts VAR not found")
	}
	if counts.Var == nil || counts.Var.Linkage != 1 {
		t.Fatalf("counts linkage = %+v, want global allocated", counts.Var)
	}

	st, err := spec.TypeByID(counts.SizeOrType)
	if err != nil {
		t.Fatalf("counts type: %v", err)
	}
	if st.Kind != KindStruct || len(st.Members) != 4 {
		t.Fatalf("counts type = %v with %d members", st.Kind, len(st.Members))
	}

	typeMember := spec.Member(st, "type")
	if typeMember == nil {
		t.Fatal("type member not found")
	}
	typePtr, err := spec.TypeByID(typeMember.Type)
	if err != nil || typePtr.Kind != KindPtr {
		t.Fatalf("type member type = %v, %v", typePtr, err)
	}
	typeArray, err := spec.TypeByID(typePtr.SizeOrType)
	if err != nil || typeArray.Kind != KindArray {
		t.Fatalf("type member array = %v, %v", typeArray, err)
	}
	if typeArray.Array == nil || typeArray.Array.Nelems != 2 {
		t.Fatalf("map type nelems = %+v, want 2", typeArray.Array)
	}

	maxMember := spec.Member(st, "max_entries")
	if maxMember == nil {
		t.Fatal("max_entries member not found")
	}
	maxPtr, err := spec.TypeByID(maxMember.Type)
	if err != nil || maxPtr.Kind != KindPtr {
		t.Fatalf("max_entries type = %v, %v", maxPtr, err)
	}
	maxArray, err := spec.TypeByID(maxPtr.SizeOrType)
	if err != nil || maxArray.Kind != KindArray {
		t.Fatalf("max_entries array = %v, %v", maxArray, err)
	}
	if maxArray.Array == nil || maxArray.Array.Nelems != 1 {
		t.Fatalf("max_entries nelems = %+v, want 1", maxArray.Array)
	}

	keyMember := spec.Member(st, "key")
	if keyMember == nil {
		t.Fatal("key member not found")
	}
	keyPtr, err := spec.TypeByID(keyMember.Type)
	if err != nil || keyPtr.Kind != KindPtr {
		t.Fatalf("key type = %v, %v", keyPtr, err)
	}
	keyTypedef, err := spec.TypeByID(keyPtr.SizeOrType)
	if err != nil || keyTypedef.Kind != KindTypedef || keyTypedef.Name != "__u32" {
		t.Fatalf("key typedef = %+v, %v", keyTypedef, err)
	}
	keyInt, err := spec.TypeByID(keyTypedef.SizeOrType)
	if err != nil || keyInt.Kind != KindInt {
		t.Fatalf("key int = %+v, %v", keyInt, err)
	}

	valueMember := spec.Member(st, "value")
	if valueMember == nil {
		t.Fatal("value member not found")
	}
	valuePtr, err := spec.TypeByID(valueMember.Type)
	if err != nil || valuePtr.Kind != KindPtr {
		t.Fatalf("value type = %v, %v", valuePtr, err)
	}
	valueTypedef, err := spec.TypeByID(valuePtr.SizeOrType)
	if err != nil || valueTypedef.Kind != KindTypedef || valueTypedef.Name != "__u64" {
		t.Fatalf("value typedef = %+v, %v", valueTypedef, err)
	}

	handle := spec.Find("handle_open", KindFunc)
	if handle == nil {
		t.Fatal("handle_open FUNC not found")
	}
	proto, err := spec.TypeByID(handle.SizeOrType)
	if err != nil || proto.Kind != KindFuncProto {
		t.Fatalf("handle_open proto = %+v, %v", proto, err)
	}
	if len(proto.Params) != 1 || proto.Params[0].Name != "ctx" {
		t.Fatalf("handle_open params = %+v", proto.Params)
	}
	ctxType, err := spec.TypeByID(proto.Params[0].Type)
	if err != nil || ctxType.Kind != KindPtr {
		t.Fatalf("ctx type = %+v, %v", ctxType, err)
	}
	ctxTarget, err := spec.TypeByID(ctxType.SizeOrType)
	if err != nil || ctxTarget.Kind != KindVoid {
		t.Fatalf("ctx target = %+v, %v", ctxTarget, err)
	}

	maps := spec.Find(".maps", KindDatasec)
	if maps == nil {
		t.Fatal(".maps DATASEC not found")
	}
	if len(maps.DataSec) != 1 {
		t.Fatalf(".maps has %d variables", len(maps.DataSec))
	}
	if maps.DataSec[0].Type != counts.ID {
		t.Fatalf(".maps variable type = %d, want %d", maps.DataSec[0].Type, counts.ID)
	}
	if maps.DataSec[0].Size != 32 {
		t.Fatalf(".maps variable size = %d, want 32", maps.DataSec[0].Size)
	}

	if _, err := spec.TypeByID(uint32(len(spec.Types))); err == nil {
		t.Fatal("TypeByID accepted an out-of-range id")
	}
}

func TestFixupDatasecSizes(t *testing.T) {
	o, err := elf.Open("../../testdata/progs/kprobe.bpf.o")
	if err != nil {
		t.Fatalf("open object: %v", err)
	}
	spec, err := Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	sizes := map[string]uint32{".maps": 32, "license": 4}
	if err := spec.FixupDatasecSizes(sizes); err != nil {
		t.Fatalf("FixupDatasecSizes: %v", err)
	}

	maps := spec.Find(".maps", KindDatasec)
	if maps == nil || maps.SizeOrType != 32 {
		t.Fatalf(".maps datasec = %+v, want size 32", maps)
	}
	license := spec.Find("license", KindDatasec)
	if license == nil || license.SizeOrType != 4 {
		t.Fatalf("license datasec = %+v, want size 4", license)
	}

	off := spec.typeStart + int(maps.rawOff) + 8
	if got := spec.ByteOrder.Uint32(spec.raw[off:]); got != 32 {
		t.Fatalf("patched .maps size = %d, want 32", got)
	}
	if got := spec.ByteOrder.Uint32(o.BTF[off:]); got != 0 {
		t.Fatalf("original .maps size = %d, want 0", got)
	}
	if len(spec.Raw()) != len(o.BTF) {
		t.Fatalf("Raw length = %d, want %d", len(spec.Raw()), len(o.BTF))
	}
}

func TestFixupDatasecOffsets(t *testing.T) {
	o, err := elf.Open("../../testdata/progs/ringbuf.bpf.o")
	if err != nil {
		t.Fatalf("open object: %v", err)
	}
	spec, err := Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := spec.FixupDatasecSizes(map[string]uint32{".maps": 32, "license": 4}); err != nil {
		t.Fatalf("FixupDatasecSizes: %v", err)
	}
	if err := spec.FixupDatasecOffsets(map[string]uint32{"events": 0, "events2": 16, "LICENSE": 0}); err != nil {
		t.Fatalf("FixupDatasecOffsets: %v", err)
	}

	maps := spec.Find(".maps", KindDatasec)
	if maps == nil || len(maps.DataSec) != 2 {
		t.Fatalf(".maps datasec = %+v, want two variables", maps)
	}
	for i, want := range []uint32{0, 16} {
		v, err := spec.TypeByID(maps.DataSec[i].Type)
		if err != nil {
			t.Fatalf("type %d: %v", maps.DataSec[i].Type, err)
		}
		if v.Kind != KindVar {
			t.Fatalf(".maps member %d kind = %v, want var", i, v.Kind)
		}
		if maps.DataSec[i].Offset != want {
			t.Errorf("%s offset = %d, want %d", v.Name, maps.DataSec[i].Offset, want)
		}
		off := spec.typeStart + int(maps.rawOff) + 12 + i*12 + 4
		if got := spec.ByteOrder.Uint32(spec.raw[off:]); got != want {
			t.Errorf("%s raw offset = %d, want %d", v.Name, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(nil, binary.LittleEndian); err == nil {
		t.Fatal("Parse accepted an empty blob")
	}
	if _, err := Parse(make([]byte, 24), binary.LittleEndian); err == nil {
		t.Fatal("Parse accepted a zero header")
	}
}
