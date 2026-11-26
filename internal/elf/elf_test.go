// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original

package elf

import (
	"debug/elf"
	"testing"
)

func TestOpenKprobe(t *testing.T) {
	o, err := Open("../../testdata/progs/kprobe.bpf.o")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if o.Machine != elf.EM_BPF {
		t.Fatalf("machine = %v, want EM_BPF", o.Machine)
	}
	if o.License != "GPL" {
		t.Fatalf("license = %q, want GPL", o.License)
	}
	if len(o.Maps) == 0 {
		t.Fatal(".maps is empty")
	}
	if len(o.BTF) == 0 {
		t.Fatal(".BTF is empty")
	}
	if len(o.BTFExt) == 0 {
		t.Fatal(".BTF.ext is empty")
	}

	var prog *Program
	for i := range o.Programs {
		if o.Programs[i].Name == "kprobe/do_sys_open" {
			prog = &o.Programs[i]
			break
		}
	}
	if prog == nil {
		t.Fatalf("program section not found in %v", programNames(o.Programs))
	}
	if len(prog.Insns) == 0 || len(prog.Insns)%8 != 0 {
		t.Fatalf("instruction bytes = %d, want a non-zero multiple of 8", len(prog.Insns))
	}

	var handle *Symbol
	for i := range o.Symbols {
		if o.Symbols[i].Name == "handle_open" && o.Symbols[i].Type == elf.STT_FUNC {
			handle = &o.Symbols[i]
			break
		}
	}
	if handle == nil {
		t.Fatal("handle_open FUNC symbol not found")
	}
	if handle.Section != "kprobe/do_sys_open" {
		t.Fatalf("handle_open section = %q", handle.Section)
	}

	var mapReloc *Reloc
	for i := range o.Relocations {
		if o.Relocations[i].Symbol == "counts" && o.Relocations[i].Type == R_BPF_64_64 {
			mapReloc = &o.Relocations[i]
			break
		}
	}
	if mapReloc == nil {
		t.Fatal("counts R_BPF_64_64 relocation not found")
	}
	if mapReloc.Section != "kprobe/do_sys_open" {
		t.Fatalf("relocation target = %q", mapReloc.Section)
	}
	if len(prog.Relocs) == 0 {
		t.Fatal("program has no relocations")
	}
}

func programNames(programs []Program) []string {
	names := make([]string, len(programs))
	for i := range programs {
		names[i] = programs[i].Name
	}
	return names
}
