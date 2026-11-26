// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
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
	if err := relocateCore(p, insns, ext, obj.btf, kernel); err != nil {
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
