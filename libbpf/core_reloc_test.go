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

type coreReloRef struct {
	section string
	relo    btf.CoreRelo
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

	data, err := os.ReadFile("../testdata/oracle/core-reloc.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var want coreRelocFixture
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	var relos []coreReloRef
	for _, section := range ext.CoreRelos {
		for _, relo := range section.Relos {
			relos = append(relos, coreReloRef{section.Section, relo})
		}
	}
	if len(relos) != len(want.Relos) {
		t.Fatalf("fixture has %d relocations, parsed %d", len(want.Relos), len(relos))
	}

	sections := make(map[string][]byte)
	for _, section := range localO.Sections {
		sections[section.Name] = section.Data
	}

	for i, ref := range relos {
		entry := want.Relos[i]
		relo := ref.relo

		if ref.section != entry.Section || relo.InsnOff != entry.InsnOff {
			t.Fatalf("relocation = %s/%d, want %s/%d", ref.section, relo.InsnOff, entry.Section, entry.InsnOff)
		}
		access, err := local.String(relo.AccessStrOff)
		if err != nil {
			t.Fatalf("access string: %v", err)
		}
		if access != entry.Access || uint32(relo.Kind) != entry.Kind {
			t.Fatalf("relocation %d: access/kind = %s/%d, want %s/%d", i, access, relo.Kind, entry.Access, entry.Kind)
		}

		localType, err := local.TypeByID(relo.TypeID)
		if err != nil {
			t.Fatalf("local type %d: %v", relo.TypeID, err)
		}
		targetType := target.Find(localType.Name, localType.Kind)
		if targetType == nil {
			t.Fatalf("target type %s not found", localType.Name)
		}
		if targetType.ID != entry.TargetTypeID {
			t.Fatalf("relocation %d: target type id = %d, want %d", i, targetType.ID, entry.TargetTypeID)
		}

		res, err := local.CalcCoreRelo(relo, target, targetType.ID)
		if err != nil {
			t.Fatalf("relocation %d: CalcCoreRelo: %v", i, err)
		}
		if res.OrigVal != entry.OrigVal || res.NewVal != entry.NewVal {
			t.Fatalf("relocation %d: values = %d/%d, want %d/%d", i, res.OrigVal, res.NewVal, entry.OrigVal, entry.NewVal)
		}
		if res.OrigSize != entry.OrigSz || res.NewSize != entry.NewSz {
			t.Fatalf("relocation %d: sizes = %d/%d, want %d/%d", i, res.OrigSize, res.NewSize, entry.OrigSz, entry.NewSz)
		}
		if res.OrigTypeID != entry.OrigTypeID || res.NewTypeID != entry.NewTypeID {
			t.Fatalf("relocation %d: type ids = %d/%d, want %d/%d", i, res.OrigTypeID, res.NewTypeID, entry.OrigTypeID, entry.NewTypeID)
		}
		if res.Validate != entry.Validate || res.Poison != entry.Poison || res.FailMemSizeAdjust != entry.FailMemSizeAdjust {
			t.Fatalf("relocation %d: flags = %v/%v/%v, want %v/%v/%v",
				i, res.Validate, res.Poison, res.FailMemSizeAdjust,
				entry.Validate, entry.Poison, entry.FailMemSizeAdjust)
		}

		program := sections[ref.section]
		if program == nil {
			t.Fatalf("section %s not found", ref.section)
		}
		off := int(relo.InsnOff)
		if off+bpfInsnLength > len(program) {
			t.Fatalf("relocation %d: instruction %d out of bounds", i, off)
		}
		insns := append([]byte(nil), program...)
		insn := decodeBpfInsn(insns[off:])
		wantOrig := bpfInsn{
			Code: uint8(entry.OrigInsn.Code),
			Dst:  uint8(entry.OrigInsn.Dst),
			Src:  uint8(entry.OrigInsn.Src),
			Off:  int16(entry.OrigInsn.Off),
			Imm:  entry.OrigInsn.Imm,
		}
		if insn != wantOrig {
			t.Fatalf("relocation %d: instruction = %+v, want %+v", i, insn, wantOrig)
		}
		if err := patchCoreInsn(insns[off:], res); err != nil {
			t.Fatalf("relocation %d: patchCoreInsn: %v", i, err)
		}
		wantNew := bpfInsn{
			Code: uint8(entry.NewInsn.Code),
			Dst:  uint8(entry.NewInsn.Dst),
			Src:  uint8(entry.NewInsn.Src),
			Off:  int16(entry.NewInsn.Off),
			Imm:  entry.NewInsn.Imm,
		}
		if got := decodeBpfInsn(insns[off:]); got != wantNew {
			t.Fatalf("relocation %d: patched instruction = %+v, want %+v", i, got, wantNew)
		}
	}
}
