// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Section indices of testOutput.
const (
	testProgIndex   = 1
	testMapsIndex   = 2
	testBssIndex    = 3
	testRelIndex    = 4
	testSymtabIndex = 5
)

// testProgInsns is a BPF_LD_IMM64 r1 followed by BPF_EXIT, the shape of a
// map reference that needs an R_BPF_64_64 relocation.
var testProgInsns = []byte{
	0x18, 0x01, 0, 0, 0, 0, 0, 0,
	0x00, 0x00, 0, 0, 0, 0, 0, 0,
	0x95, 0x00, 0, 0, 0, 0, 0, 0,
}

// testOutput is a small object with code, map data, BSS, a relocation, and
// separate symbol and section name tables.
func testOutput() *Output {
	return &Output{
		Sections: []OutputSection{
			{Name: "kprobe/test", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addralign: 8, Data: testProgInsns},
			{Name: ".maps", Type: elf.SHT_PROGBITS, Flags: elf.SHF_WRITE | elf.SHF_ALLOC, Addralign: 8, Data: make([]byte, 32)},
			{Name: ".bss", Type: elf.SHT_NOBITS, Flags: elf.SHF_WRITE | elf.SHF_ALLOC, Addralign: 8, Size: 16},
			{Name: ".relkprobe/test", Type: elf.SHT_REL, Flags: elf.SHF_INFO_LINK, Addralign: 8, Info: testProgIndex,
				Relocs: []OutputReloc{{Offset: 0, Symbol: 4, Type: R_BPF_64_64}}},
			{Name: ".symtab", Type: elf.SHT_SYMTAB, Addralign: 8, Info: 3},
			{Name: ".strtab", Type: elf.SHT_STRTAB, Addralign: 1},
			{Name: ".shstrtab", Type: elf.SHT_STRTAB, Addralign: 1},
		},
		Symbols: []OutputSymbol{
			{Name: "test.bpf.c", Info: elf.ST_INFO(elf.STB_LOCAL, elf.STT_FILE), Section: elf.SHN_ABS},
			{Info: elf.ST_INFO(elf.STB_LOCAL, elf.STT_SECTION), Section: testProgIndex},
			{Name: "handle", Info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), Section: testProgIndex, Size: uint64(len(testProgInsns))},
			{Name: "counts", Info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT), Section: testMapsIndex, Size: 32},
			{Name: "scratch", Info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_OBJECT), Other: byte(elf.STV_HIDDEN), Section: testBssIndex, Value: 8, Size: 8},
		},
	}
}

func marshalTest(t *testing.T, out *Output) *elf.File {
	t.Helper()

	data, err := Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	return f
}

func TestMarshalHeader(t *testing.T) {
	f := marshalTest(t, testOutput())

	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Version != elf.EV_CURRENT {
		t.Fatalf("ident = %v %v %v", f.Class, f.Data, f.Version)
	}
	if f.Type != elf.ET_REL || f.Machine != elf.EM_BPF {
		t.Fatalf("type = %v, machine = %v", f.Type, f.Machine)
	}
	if got, want := len(f.Sections), len(testOutput().Sections)+1; got != want {
		t.Fatalf("section count = %d, want %d", got, want)
	}
}

func TestMarshalSections(t *testing.T) {
	out := testOutput()
	f := marshalTest(t, out)

	for i, want := range out.Sections {
		got := f.Sections[i+1]
		if got.Name != want.Name || got.Type != want.Type || got.Flags != want.Flags || got.Addralign != want.Addralign {
			t.Fatalf("section %d = %s %v %v align %d, want %s %v %v align %d", i+1,
				got.Name, got.Type, got.Flags, got.Addralign, want.Name, want.Type, want.Flags, want.Addralign)
		}
		if want.Addralign > 1 && got.Offset%want.Addralign != 0 {
			t.Fatalf("section %s offset %#x is not %d-aligned", got.Name, got.Offset, want.Addralign)
		}
	}

	checkSectionData(t, f, "kprobe/test", testProgInsns)
	checkSectionData(t, f, ".maps", out.Sections[1].Data)
	if bss := f.Section(".bss"); bss.Size != 16 {
		t.Fatalf(".bss size = %d, want 16", bss.Size)
	}

	symtab := f.Sections[testSymtabIndex]
	if symtab.Link != uint32(sectionIndex(f, ".strtab")) || symtab.Info != 3 || symtab.Entsize != symbolSize {
		t.Fatalf(".symtab link %d info %d entsize %d", symtab.Link, symtab.Info, symtab.Entsize)
	}
	rel := f.Sections[testRelIndex]
	if rel.Link != testSymtabIndex || rel.Info != testProgIndex || rel.Entsize != relSize {
		t.Fatalf(".relkprobe/test link %d info %d entsize %d", rel.Link, rel.Info, rel.Entsize)
	}
}

func checkSectionData(t *testing.T, f *elf.File, name string, want []byte) {
	t.Helper()

	got, err := f.Section(name).Data()
	if err != nil {
		t.Fatalf("%s data: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s data = %x, want %x", name, got, want)
	}
}

func TestMarshalSymbols(t *testing.T) {
	out := testOutput()
	f := marshalTest(t, out)

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	if len(syms) != len(out.Symbols) {
		t.Fatalf("symbol count = %d, want %d", len(syms), len(out.Symbols))
	}
	for i, want := range out.Symbols {
		got := syms[i]
		if got.Name != want.Name || got.Info != want.Info || got.Other != want.Other ||
			got.Section != want.Section || got.Value != want.Value || got.Size != want.Size {
			t.Fatalf("symbol %d = %+v, want %+v", i+1, got, want)
		}
	}
}

func TestMarshalRelocations(t *testing.T) {
	data, err := Marshal(testOutput())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	o, err := OpenBytes(data)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}

	want := []Reloc{{Section: "kprobe/test", Offset: 0, Symbol: "counts", SymbolIndex: 4, Type: R_BPF_64_64}}
	if !reflect.DeepEqual(o.Relocations, want) {
		t.Fatalf("relocations = %+v, want %+v", o.Relocations, want)
	}
	if len(o.Programs) != 1 || !reflect.DeepEqual(o.Programs[0].Relocs, want) {
		t.Fatalf("programs = %+v", o.Programs)
	}
}

func TestMarshalStringTables(t *testing.T) {
	f := marshalTest(t, testOutput())

	if got := stringTableEntries(t, f, ".shstrtab"); !reflect.DeepEqual(got, sectionNames(testOutput())) {
		t.Fatalf(".shstrtab = %q", got)
	}
	want := []string{"", "counts", "handle", "scratch", "test.bpf.c"}
	if got := stringTableEntries(t, f, ".strtab"); !reflect.DeepEqual(got, want) {
		t.Fatalf(".strtab = %q, want %q", got, want)
	}
}

// TestMarshalSharedStrtab checks the clang and BPF linker layout, where the
// section names live in .strtab and each string is stored once.
func TestMarshalSharedStrtab(t *testing.T) {
	out := testOutput()
	out.Sections = out.Sections[:len(out.Sections)-1]
	out.Symbols[1].Name = "kprobe/test"
	data, err := Marshal(out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}

	shstrndx := binary.LittleEndian.Uint16(data[62:])
	if f.Section(".shstrtab") != nil || int(shstrndx) != sectionIndex(f, ".strtab") {
		t.Fatalf("e_shstrndx = %d, want the .strtab index", shstrndx)
	}

	want := append(sectionNames(out), "counts", "handle", "scratch", "test.bpf.c")
	sort.Strings(want)
	if got := stringTableEntries(t, f, ".strtab"); !reflect.DeepEqual(got, want) {
		t.Fatalf(".strtab = %q, want %q", got, want)
	}
}

// sectionIndex returns the ELF index of the named section, or -1.
func sectionIndex(f *elf.File, name string) int {
	for i, s := range f.Sections {
		if s.Name == name {
			return i
		}
	}
	return -1
}

// sectionNames returns the section names plus the empty string, sorted.
func sectionNames(out *Output) []string {
	names := []string{""}
	for _, s := range out.Sections {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// stringTableEntries returns the strings of a string table section, sorted.
func stringTableEntries(t *testing.T, f *elf.File, name string) []string {
	t.Helper()

	data, err := f.Section(name).Data()
	if err != nil {
		t.Fatalf("%s data: %v", name, err)
	}
	var entries []string
	for _, s := range bytes.Split(bytes.TrimSuffix(data, []byte{0}), []byte{0}) {
		entries = append(entries, string(s))
	}
	sort.Strings(entries)
	return entries
}

func TestMarshalRelocationInfo(t *testing.T) {
	f := marshalTest(t, testOutput())

	rel, err := f.Sections[testRelIndex].Data()
	if err != nil {
		t.Fatalf("rel data: %v", err)
	}
	if len(rel) != relSize {
		t.Fatalf("rel size = %d, want %d", len(rel), relSize)
	}
	info := binary.LittleEndian.Uint64(rel[8:])
	if elf.R_SYM64(info) != 4 || elf.R_TYPE64(info) != R_BPF_64_64 {
		t.Fatalf("r_info = %#x", info)
	}
}

func TestMarshalErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Output)
		want   string
	}{
		{"unsupported type", func(o *Output) { o.Sections[0].Type = elf.SHT_RELA }, "unsupported type"},
		{"alignment", func(o *Output) { o.Sections[0].Addralign = 3 }, "not a power of two"},
		{"nobits data", func(o *Output) { o.Sections[2].Data = []byte{1} }, "data in a SHT_NOBITS"},
		{"duplicate symtab", func(o *Output) { o.Sections[1] = OutputSection{Name: ".symtab2", Type: elf.SHT_SYMTAB} }, "duplicate"},
		{"unknown strtab", func(o *Output) { o.Sections[1] = OutputSection{Name: ".dynstr", Type: elf.SHT_STRTAB} }, "not .strtab or .shstrtab"},
		{"no name table", func(o *Output) { o.Sections = o.Sections[:3]; o.Symbols = nil }, "no string table"},
		{"relocation without symtab", func(o *Output) { o.Sections[4].Type = elf.SHT_PROGBITS; o.Symbols = nil }, "without an SHT_SYMTAB"},
		{"relocation symbol", func(o *Output) { o.Sections[3].Relocs[0].Symbol = 9 }, "symbol index 9"},
		{"relocated section", func(o *Output) { o.Sections[3].Info = 42 }, "relocated section index 42"},
		{"symbol section", func(o *Output) { o.Symbols[2].Section = 42 }, "section index 42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := testOutput()
			tt.mutate(out)
			_, err := Marshal(out)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Marshal error = %v, want %q", err, tt.want)
			}
		})
	}
}
