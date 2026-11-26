// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
)

type coreRelocInsn struct {
	Code uint32 `json:"code"`
	Dst  uint32 `json:"dst"`
	Src  uint32 `json:"src"`
	Off  int32  `json:"off"`
	Imm  int32  `json:"imm"`
}

type coreRelocEntry struct {
	Section           string        `json:"section"`
	InsnOff           uint32        `json:"insn_off"`
	TypeID            uint32        `json:"type_id"`
	Kind              uint32        `json:"kind"`
	Access            string        `json:"access"`
	TargetTypeID      uint32        `json:"target_type_id"`
	OrigVal           uint64        `json:"orig_val"`
	NewVal            uint64        `json:"new_val"`
	OrigSz            uint32        `json:"orig_sz"`
	NewSz             uint32        `json:"new_sz"`
	OrigTypeID        uint32        `json:"orig_type_id"`
	NewTypeID         uint32        `json:"new_type_id"`
	Validate          bool          `json:"validate"`
	Poison            bool          `json:"poison"`
	FailMemSizeAdjust bool          `json:"fail_memsz_adjust"`
	OrigInsn          coreRelocInsn `json:"orig_insn"`
	NewInsn           coreRelocInsn `json:"new_insn"`
}

type coreRelocFixture struct {
	Relos []coreRelocEntry `json:"relos"`
}

func TestCoreReloc(t *testing.T) {
	localO, err := elf.Open("../testdata/progs/core.bpf.o")
	if err != nil {
		t.Fatalf("open local object: %v", err)
	}
	local, err := btf.Parse(localO.BTF, localO.ByteOrder)
	if err != nil {
		t.Fatalf("parse local BTF: %v", err)
	}
	ext, err := btf.ParseExt(localO.BTFExt, local, localO.ByteOrder)
	if err != nil {
		t.Fatalf("parse local BTF.ext: %v", err)
	}

	targetO, err := elf.Open("../testdata/progs/core_target.bpf.o")
	if err != nil {
		t.Fatalf("open target object: %v", err)
	}
	target, err := btf.Parse(targetO.BTF, targetO.ByteOrder)
	if err != nil {
		t.Fatalf("parse target BTF: %v", err)
	}
	targetType := target.Find("core_sample", btf.KindStruct)
	if targetType == nil {
		t.Fatal("target core_sample not found")
	}

	data, err := os.ReadFile("../testdata/oracle/core-reloc.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var want coreRelocFixture
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(want.Relos) != 1 || len(ext.CoreRelos) != 1 || len(ext.CoreRelos[0].Relos) != 1 {
		t.Fatalf("want one relocation, fixture %d, parsed %d", len(want.Relos), len(ext.CoreRelos))
	}

	section := ext.CoreRelos[0]
	relo := section.Relos[0]
	entry := want.Relos[0]

	if section.Section != entry.Section || relo.InsnOff != entry.InsnOff {
		t.Fatalf("relocation = %s/%d, want %s/%d", section.Section, relo.InsnOff, entry.Section, entry.InsnOff)
	}
	access, err := local.String(relo.AccessStrOff)
	if err != nil {
		t.Fatalf("access string: %v", err)
	}
	if access != entry.Access || uint32(relo.Kind) != entry.Kind {
		t.Fatalf("access/kind = %s/%d, want %s/%d", access, relo.Kind, entry.Access, entry.Kind)
	}
	if targetType.ID != entry.TargetTypeID {
		t.Fatalf("target type id = %d, want %d", targetType.ID, entry.TargetTypeID)
	}

	res, err := local.CalcCoreRelo(relo, target, targetType.ID)
	if err != nil {
		t.Fatalf("CalcCoreRelo: %v", err)
	}
	if res.OrigVal != entry.OrigVal || res.NewVal != entry.NewVal {
		t.Fatalf("values = %d/%d, want %d/%d", res.OrigVal, res.NewVal, entry.OrigVal, entry.NewVal)
	}
	if res.OrigSize != entry.OrigSz || res.NewSize != entry.NewSz {
		t.Fatalf("sizes = %d/%d, want %d/%d", res.OrigSize, res.NewSize, entry.OrigSz, entry.NewSz)
	}
	if res.OrigTypeID != entry.OrigTypeID || res.NewTypeID != entry.NewTypeID {
		t.Fatalf("type ids = %d/%d, want %d/%d", res.OrigTypeID, res.NewTypeID, entry.OrigTypeID, entry.NewTypeID)
	}
	if res.Validate != entry.Validate || res.Poison != entry.Poison || res.FailMemSizeAdjust != entry.FailMemSizeAdjust {
		t.Fatalf("flags = %v/%v/%v, want %v/%v/%v",
			res.Validate, res.Poison, res.FailMemSizeAdjust,
			entry.Validate, entry.Poison, entry.FailMemSizeAdjust)
	}

	var program []byte
	for _, s := range localO.Sections {
		if s.Name == entry.Section {
			program = s.Data
			break
		}
	}
	if program == nil {
		t.Fatalf("section %s not found", entry.Section)
	}
	off := int(relo.InsnOff)
	if off+bpfInsnLength > len(program) {
		t.Fatalf("instruction %d out of bounds", off)
	}
	insn := decodeBpfInsn(program[off:])
	wantOrig := bpfInsn{
		Code: uint8(entry.OrigInsn.Code),
		Dst:  uint8(entry.OrigInsn.Dst),
		Src:  uint8(entry.OrigInsn.Src),
		Off:  int16(entry.OrigInsn.Off),
		Imm:  entry.OrigInsn.Imm,
	}
	if insn != wantOrig {
		t.Fatalf("instruction = %+v, want %+v", insn, wantOrig)
	}
	if err := patchCoreInsn(&insn, res); err != nil {
		t.Fatalf("patchCoreInsn: %v", err)
	}
	wantNew := bpfInsn{
		Code: uint8(entry.NewInsn.Code),
		Dst:  uint8(entry.NewInsn.Dst),
		Src:  uint8(entry.NewInsn.Src),
		Off:  int16(entry.NewInsn.Off),
		Imm:  entry.NewInsn.Imm,
	}
	if insn != wantNew {
		t.Fatalf("patched instruction = %+v, want %+v", insn, wantNew)
	}

	var encoded [bpfInsnLength]byte
	encodeBpfInsn(encoded[:], insn)
	if got := decodeBpfInsn(encoded[:]); got != insn {
		t.Fatalf("instruction round trip = %+v, want %+v", got, insn)
	}
}
