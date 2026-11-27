// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

func TestCoreRelocLoad(t *testing.T) {
	obj, err := BpfObjectOpenFile("../testdata/progs/core_kernel.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}
	if !hasCoreRelos(ext) {
		t.Fatal("object has no core relocations")
	}

	kernel, err := loadKernelBTF()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("kernel BTF unavailable: %v", err)
		}
		t.Fatalf("loadKernelBTF: %v", err)
	}

	p := BpfObjectFindProgramByName(obj, "handle_regs")
	if p == nil {
		t.Fatal("program handle_regs not found")
	}

	var relo btf.CoreRelo
	found := false
	for _, section := range ext.CoreRelos {
		if section.Section != p.sectionName || len(section.Relos) == 0 {
			continue
		}
		relo = section.Relos[0]
		found = true
		break
	}
	if !found {
		t.Fatalf("no core relocation for %s", p.sectionName)
	}

	localType, err := obj.btf.TypeByID(relo.TypeID)
	if err != nil {
		t.Fatalf("local type %d: %v", relo.TypeID, err)
	}
	targetType := kernel.Find(localType.Name, localType.Kind)
	if targetType == nil {
		t.Fatalf("kernel type %s not found", localType.Name)
	}
	member := kernel.Member(targetType, "sp")
	if member == nil {
		t.Fatal("kernel pt_regs.sp not found")
	}

	res, err := obj.btf.CalcCoreRelo(relo, kernel, targetType.ID)
	if err != nil {
		t.Fatalf("CalcCoreRelo: %v", err)
	}
	wantOff := uint64(member.Offset / 8)
	if res.NewVal != wantOff {
		t.Fatalf("target offset = %d, want %d", res.NewVal, wantOff)
	}

	insns := append([]byte(nil), p.insns...)
	if err := relocateCore(p, insns, ext, obj.btf, []*btf.Spec{kernel}); err != nil {
		t.Fatalf("relocateCore: %v", err)
	}
	insn := decodeBpfInsn(insns[relo.InsnOff:])
	if uint64(insn.Off) != wantOff {
		t.Fatalf("patched offset = %d, want %d", insn.Off, wantOff)
	}

	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}
}

func TestCoreModuleCandidate(t *testing.T) {
	obj, err := BpfObjectOpenFile("../testdata/progs/core_module.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}
	p := BpfObjectFindProgramByName(obj, "handle_module")
	if p == nil {
		t.Fatal("program handle_module not found")
	}
	if len(ext.CoreRelos) != 1 || len(ext.CoreRelos[0].Relos) != 1 {
		t.Fatalf("unexpected core relos: %+v", ext.CoreRelos)
	}
	relo := ext.CoreRelos[0].Relos[0]

	emptyO, err := elf.Open("../testdata/progs/core_target.bpf.o")
	if err != nil {
		t.Fatalf("open empty target: %v", err)
	}
	empty, err := btf.Parse(emptyO.BTF, emptyO.ByteOrder)
	if err != nil {
		t.Fatalf("parse empty target: %v", err)
	}
	moduleO, err := elf.Open("../testdata/progs/core_module_target.bpf.o")
	if err != nil {
		t.Fatalf("open module target: %v", err)
	}
	module, err := btf.Parse(moduleO.BTF, moduleO.ByteOrder)
	if err != nil {
		t.Fatalf("parse module target: %v", err)
	}

	insns := append([]byte(nil), p.insns...)
	if err := relocateCore(p, insns, ext, obj.btf, []*btf.Spec{empty, module}); err != nil {
		t.Fatalf("relocateCore with module: %v", err)
	}
	if got := decodeBpfInsn(insns[relo.InsnOff:]); got.Imm != 1 {
		t.Fatalf("module type exists = %d, want 1", got.Imm)
	}

	insns = append([]byte(nil), p.insns...)
	if err := relocateCore(p, insns, ext, obj.btf, []*btf.Spec{empty}); err != nil {
		t.Fatalf("relocateCore without module: %v", err)
	}
	if got := decodeBpfInsn(insns[relo.InsnOff:]); got.Imm != 0 {
		t.Fatalf("missing type exists = %d, want 0", got.Imm)
	}
}

func TestLoadKernelBTFs(t *testing.T) {
	kernels, err := loadKernelBTFs()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("kernel BTF unavailable: %v", err)
		}
		t.Fatalf("loadKernelBTFs: %v", err)
	}
	if len(kernels) == 0 {
		t.Fatal("no kernel BTF loaded")
	}
	if len(kernels) > 1 {
		module := kernels[1]
		if module.StartID() <= 1 {
			t.Fatalf("module BTF has no own types: start id %d", module.StartID())
		}
		if _, err := module.TypeByID(module.StartID()); err != nil {
			t.Fatalf("module BTF first own type: %v", err)
		}
	}
}

func TestCoreMissingLoad(t *testing.T) {
	obj, err := BpfObjectOpenFile("../testdata/progs/core_missing.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}
}
