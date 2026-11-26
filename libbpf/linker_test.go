// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

const linkerInputPath = "../testdata/progs/kprobe.bpf.o"

// linkerFixture is a linker oracle file: the object libbpf's linker writes
// for the listed objects, as bpf_object__open_file and libelf see it.
type linkerFixture struct {
	Objects    []string               `json:"objects"`
	ObjectName string                 `json:"object_name"`
	Maps       []linkerFixtureMap     `json:"maps"`
	Programs   []linkerFixtureProgram `json:"programs"`
	Sections   []linkerFixtureSection `json:"sections"`
	Symbols    []linkerFixtureSymbol  `json:"symbols"`
}

type linkerFixtureMap struct {
	Name       string `json:"name"`
	Type       uint32 `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
}

type linkerFixtureProgram struct {
	Name    string `json:"name"`
	Type    uint32 `json:"type"`
	Section string `json:"section"`
}

// linkerFixtureSection is one section. Data is the hex contents of a code or
// data section; the BTF sections have none. Relocations are the entries of a
// relocation section, with each symbol named the way readelf names it.
type linkerFixtureSection struct {
	Name        string               `json:"name"`
	Type        uint32               `json:"type"`
	Flags       uint64               `json:"flags"`
	Size        uint64               `json:"size"`
	Align       uint64               `json:"align"`
	Data        string               `json:"data,omitempty"`
	Relocations []linkerFixtureReloc `json:"relocations,omitempty"`
}

type linkerFixtureReloc struct {
	Offset uint64 `json:"offset"`
	Type   uint32 `json:"type"`
	Symbol string `json:"symbol"`
}

// linkerFixtureSymbol is one symbol table entry. A section symbol is named
// after its section, and Section is UND, ABS or the section name.
type linkerFixtureSymbol struct {
	Name    string `json:"name"`
	Type    uint32 `json:"type"`
	Bind    uint32 `json:"bind"`
	Section string `json:"section"`
	Value   uint64 `json:"value"`
	Size    uint64 `json:"size"`
}

func loadLinkerFixture(t *testing.T, name string) linkerFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("../testdata/oracle", name))
	if err != nil {
		t.Fatalf("read linker fixture: %v", err)
	}
	var f linkerFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse linker fixture: %v", err)
	}
	for i := range f.Sections {
		if len(f.Sections[i].Relocations) == 0 {
			f.Sections[i].Relocations = nil
		}
	}
	return f
}

// linkFile links the kprobe object into a new linked.bpf.o in a temporary
// directory, through BpfLinkerNew and BpfLinkerAddFile, and returns its path.
func linkFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "linked.bpf.o")
	l, err := BpfLinkerNew(path, nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)

	if err := BpfLinkerAddFile(l, linkerInputPath, nil); err != nil {
		t.Fatalf("BpfLinkerAddFile: %v", err)
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	return path
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// TestBpfLinkerKprobe compares the linked object with the one libbpf's linker
// writes: object name, maps and programs after open, and every section and
// symbol, including the section contents and relocations.
func TestBpfLinkerKprobe(t *testing.T) {
	compareLinked(t, loadLinkerFixture(t, "linker.json"), linkFile(t))
}

// compareLinked opens the linked object at path and compares it with the
// oracle fixture. The sections named in sizeExempt may differ in size from
// libbpf's, and only in size.
func compareLinked(t *testing.T, want linkerFixture, path string, sizeExempt ...string) {
	t.Helper()

	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	if got := BpfObjectName(obj); got != want.ObjectName {
		t.Fatalf("object name = %q, want %q", got, want.ObjectName)
	}
	if got := linkedMaps(obj); !reflect.DeepEqual(got, want.Maps) {
		t.Fatalf("maps = %+v, want %+v", got, want.Maps)
	}
	if got := linkedPrograms(obj); !reflect.DeepEqual(got, want.Programs) {
		t.Fatalf("programs = %+v, want %+v", got, want.Programs)
	}

	f := openLinkedELF(t, path)
	if got := linkedSymbols(t, f); !reflect.DeepEqual(got, want.Symbols) {
		t.Fatalf("symbols = %+v\nwant %+v", got, want.Symbols)
	}
	compareSections(t, linkedSections(t, f), want.Sections, sizeExempt)
}

// compareSections compares two sorted section lists, ignoring the size of the
// sections named in sizeExempt.
func compareSections(t *testing.T, got, want []linkerFixtureSection, sizeExempt []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("sections = %+v\nwant %+v", got, want)
	}
	for i := range got {
		g, w := got[i], want[i]
		if slices.Contains(sizeExempt, w.Name) {
			g.Size = w.Size
		}
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("section %s = %+v\nwant %+v", w.Name, got[i], w)
		}
	}
}

func linkedMaps(obj *BpfObject) []linkerFixtureMap {
	var maps []linkerFixtureMap
	for m := BpfObjectNextMap(obj, nil); m != nil; m = BpfObjectNextMap(obj, m) {
		maps = append(maps, linkerFixtureMap{
			Name:       BpfMapName(m),
			Type:       uint32(BpfMapTypeOf(m)),
			KeySize:    BpfMapKeySize(m),
			ValueSize:  BpfMapValueSize(m),
			MaxEntries: BpfMapMaxEntries(m),
		})
	}
	return maps
}

func linkedPrograms(obj *BpfObject) []linkerFixtureProgram {
	var programs []linkerFixtureProgram
	for p := BpfObjectNextProgram(obj, nil); p != nil; p = BpfObjectNextProgram(obj, p) {
		programs = append(programs, linkerFixtureProgram{
			Name:    BpfProgramName(p),
			Type:    uint32(BpfProgramTypeOf(p)),
			Section: BpfProgramSectionName(p),
		})
	}
	return programs
}

func openLinkedELF(t *testing.T, path string) *elf.File {
	t.Helper()

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// linkedSections returns the sections of f, without the null section, sorted
// by name like the oracle.
func linkedSections(t *testing.T, f *elf.File) []linkerFixtureSection {
	t.Helper()

	syms := elfSymbols(t, f)
	var sections []linkerFixtureSection
	for _, s := range f.Sections[1:] {
		sec := linkerFixtureSection{
			Name:  s.Name,
			Type:  uint32(s.Type),
			Flags: uint64(s.Flags),
			Size:  s.Size,
			Align: s.Addralign,
		}
		switch {
		case s.Type == elf.SHT_PROGBITS && s.Name != ".BTF" && s.Name != ".BTF.ext":
			sec.Data = hex.EncodeToString(sectionData(t, s))
		case s.Type == elf.SHT_REL:
			sec.Relocations = linkedRelocations(t, f, s, syms)
		}
		sections = append(sections, sec)
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].Name < sections[j].Name })
	return sections
}

func sectionData(t *testing.T, s *elf.Section) []byte {
	t.Helper()

	data, err := s.Data()
	if err != nil {
		t.Fatalf("section %s: %v", s.Name, err)
	}
	return data
}

// elfSymbols returns the symbol table with the null symbol at index 0, so a
// relocation's symbol index addresses it directly.
func elfSymbols(t *testing.T, f *elf.File) []elf.Symbol {
	t.Helper()

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		t.Fatalf("symbols: %v", err)
	}
	return append([]elf.Symbol{{}}, syms...)
}

func linkedRelocations(t *testing.T, f *elf.File, s *elf.Section, syms []elf.Symbol) []linkerFixtureReloc {
	t.Helper()

	data := sectionData(t, s)
	var relocs []linkerFixtureReloc
	for off := 0; off+elfRelSize <= len(data); off += elfRelSize {
		info := binary.LittleEndian.Uint64(data[off+8:])
		symIdx := int(elf.R_SYM64(info))
		if symIdx >= len(syms) {
			t.Fatalf("%s: relocation symbol %d out of range", s.Name, symIdx)
		}
		relocs = append(relocs, linkerFixtureReloc{
			Offset: binary.LittleEndian.Uint64(data[off:]),
			Type:   elf.R_TYPE64(info),
			Symbol: symbolLabel(f, &syms[symIdx]),
		})
	}
	return relocs
}

// linkedSymbols returns the symbol table of f in order, without the null
// symbol.
func linkedSymbols(t *testing.T, f *elf.File) []linkerFixtureSymbol {
	t.Helper()

	var symbols []linkerFixtureSymbol
	for _, sym := range elfSymbols(t, f)[1:] {
		symbols = append(symbols, linkerFixtureSymbol{
			Name:    symbolLabel(f, &sym),
			Type:    uint32(elf.ST_TYPE(sym.Info)),
			Bind:    uint32(elf.ST_BIND(sym.Info)),
			Section: symbolSection(f, &sym),
			Value:   sym.Value,
			Size:    sym.Size,
		})
	}
	return symbols
}

// symbolLabel names a section symbol after its section, like readelf.
func symbolLabel(f *elf.File, sym *elf.Symbol) string {
	if elf.ST_TYPE(sym.Info) == elf.STT_SECTION && int(sym.Section) < len(f.Sections) {
		return f.Sections[sym.Section].Name
	}
	return sym.Name
}

func symbolSection(f *elf.File, sym *elf.Symbol) string {
	switch {
	case sym.Section == elf.SHN_UNDEF:
		return "UND"
	case sym.Section == elf.SHN_ABS:
		return "ABS"
	case int(sym.Section) < len(f.Sections):
		return f.Sections[sym.Section].Name
	}
	return ""
}

func readELFSection(t *testing.T, path, name string) []byte {
	t.Helper()

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()

	s := f.Section(name)
	if s == nil {
		t.Fatalf("%s: no section %s", path, name)
	}
	data, err := s.Data()
	if err != nil {
		t.Fatalf("%s %s: %v", path, name, err)
	}
	return data
}

// TestBpfLinkerBTF checks the linked BTF: libbpf's 32-byte header, the input
// types, each DATASEC sized to its ELF section, and the same .BTF.ext records
// once their type IDs and strings are resolved.
func TestBpfLinkerBTF(t *testing.T) {
	path := linkFile(t)

	in := parseFileBTF(t, linkerInputPath)
	out := parseFileBTF(t, path)
	if out.Header.HdrLen != btfHdrLen {
		t.Fatalf("header length = %d, want %d", out.Header.HdrLen, btfHdrLen)
	}
	if len(out.Types) != len(in.Types) {
		t.Fatalf("type count = %d, want %d", len(out.Types), len(in.Types))
	}

	sizes := elfSectionSizes(t, path)
	for _, ty := range out.Types {
		if ty.Kind == btf.KindDatasec && uint64(ty.SizeOrType) != sizes[ty.Name] {
			t.Fatalf("DATASEC %s size = %d, want %d", ty.Name, ty.SizeOrType, sizes[ty.Name])
		}
	}

	if got, want := extRecords(t, path, nil), extRecords(t, linkerInputPath, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf(".BTF.ext records = %q\nwant %q", got, want)
	}
}

func parseFileBTF(t *testing.T, path string) *btf.Spec {
	t.Helper()

	spec, err := btf.Parse(readELFSection(t, path, ".BTF"), binary.LittleEndian)
	if err != nil {
		t.Fatalf("parse %s BTF: %v", path, err)
	}
	return spec
}

// extRecords describes every .BTF.ext record of the object at path with its
// type and strings resolved, so records from different BTF tables compare
// equal. shift moves the instruction offsets of the named sections.
func extRecords(t *testing.T, path string, shift map[string]uint32) []string {
	t.Helper()

	spec := parseFileBTF(t, path)
	ext, err := btf.ParseExtRaw(readELFSection(t, path, ".BTF.ext"), spec, binary.LittleEndian)
	if err != nil {
		t.Fatalf("parse %s .BTF.ext: %v", path, err)
	}

	le := binary.LittleEndian
	typeName := func(id uint32) string {
		ty, err := spec.TypeByID(id)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return ty.Kind.String() + " " + ty.Name
	}
	str := func(off uint32) string {
		s, err := spec.String(off)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return s
	}

	var recs []string
	describe := func(kind string, blocks []btf.ExtRecords, fields func(rec []byte) string) {
		for _, b := range blocks {
			for off := 0; off+b.RecSize <= len(b.Records); off += b.RecSize {
				rec := b.Records[off:]
				insn := le.Uint32(rec) + shift[b.Section]
				recs = append(recs, fmt.Sprintf("%s %s %d %s", kind, b.Section, insn, fields(rec)))
			}
		}
	}
	describe("func", ext.FuncInfo, func(rec []byte) string { return typeName(le.Uint32(rec[4:])) })
	describe("line", ext.LineInfo, func(rec []byte) string {
		return fmt.Sprintf("%s %q %d", str(le.Uint32(rec[4:])), str(le.Uint32(rec[8:])), le.Uint32(rec[12:]))
	})
	describe("core", ext.CoreRelo, func(rec []byte) string {
		return fmt.Sprintf("%s %s %d", typeName(le.Uint32(rec[4:])), str(le.Uint32(rec[8:])), le.Uint32(rec[12:]))
	})
	sort.Strings(recs)
	return recs
}

func elfSectionSizes(t *testing.T, path string) map[string]uint64 {
	t.Helper()

	sizes := make(map[string]uint64)
	for _, s := range linkedSections(t, openLinkedELF(t, path)) {
		sizes[s.Name] = s.Size
	}
	return sizes
}

// TestBpfLinkerInputs links through each add function and BpfLinkerNewFD and
// expects the same bytes as BpfLinkerNew with BpfLinkerAddFile.
func TestBpfLinkerInputs(t *testing.T) {
	want := readTestFile(t, linkFile(t))
	input := readTestFile(t, linkerInputPath)

	tests := []struct {
		name string
		add  func(*BpfLinker) error
	}{
		{"file", func(l *BpfLinker) error { return BpfLinkerAddFile(l, linkerInputPath, nil) }},
		{"mem", func(l *BpfLinker) error { return BpfLinkerAddBuf(l, input, nil) }},
		{"fd", func(l *BpfLinker) error { return addInputFD(t, l) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linkToFD(t, tt.add); !bytes.Equal(got, want) {
				t.Fatalf("linked %d bytes differ from the BpfLinkerNew output (%d bytes)", len(got), len(want))
			}
		})
	}
}

func addInputFD(t *testing.T, l *BpfLinker) error {
	f, err := os.Open(linkerInputPath)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	defer f.Close()
	return BpfLinkerAddFD(l, int(f.Fd()), nil)
}

// linkToFD links into a caller-owned descriptor that already holds more bytes
// than the output, checks that the linker leaves the descriptor open and
// truncates the file to the output, and returns the file contents.
func linkToFD(t *testing.T, add func(*BpfLinker) error) []byte {
	t.Helper()

	path := filepath.Join(t.TempDir(), "linked.bpf.o")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xff}, 1<<16), 0o644); err != nil {
		t.Fatalf("write stale output: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	l, err := BpfLinkerNewFD(int(f.Fd()), nil)
	if err != nil {
		t.Fatalf("BpfLinkerNewFD: %v", err)
	}
	if err := add(l); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	BpfLinkerFree(l)

	if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil {
		t.Fatalf("caller descriptor closed by the linker: %v", err)
	}
	return readTestFile(t, path)
}

// TestBpfLinkerConflict adds the same object twice. Its global symbols are
// strong in both copies, so the second add fails with EINVAL, as in libbpf,
// and leaves the first object's output unchanged.
func TestBpfLinkerConflict(t *testing.T) {
	want := readTestFile(t, linkFile(t))
	input := readTestFile(t, linkerInputPath)

	got := linkToFD(t, func(l *BpfLinker) error {
		if err := BpfLinkerAddBuf(l, input, nil); err != nil {
			return err
		}
		err := BpfLinkerAddFile(l, linkerInputPath, nil)
		if !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), "conflicting non-weak symbol") {
			t.Fatalf("second BpfLinkerAddFile = %v, want a conflicting symbol EINVAL", err)
		}
		return nil
	})
	if !bytes.Equal(got, want) {
		t.Fatal("output after the rejected second object differs")
	}
}

// TestBpfLinkerEmpty finalizes without an input object, which writes an
// object with only the string and symbol tables.
func TestBpfLinkerEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bpf.o")
	l, err := BpfLinkerNew(path, nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}

	want := []linkerFixtureSection{
		{Name: ".strtab", Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_STRINGS), Size: 17, Align: 1},
		{Name: ".symtab", Type: uint32(elf.SHT_SYMTAB), Size: elfSymSize, Align: 8},
	}
	if got := linkedSections(t, openLinkedELF(t, path)); !reflect.DeepEqual(got, want) {
		t.Fatalf("sections = %+v, want %+v", got, want)
	}
}

func TestBpfLinkerErrors(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	tests := []struct {
		name string
		add  func(*BpfLinker) error
		want unix.Errno
	}{
		{"missing file", func(l *BpfLinker) error { return BpfLinkerAddFile(l, "../testdata/progs/missing.bpf.o", nil) }, unix.ENOENT},
		{"not ELF", func(l *BpfLinker) error { return BpfLinkerAddBuf(l, []byte{1, 2, 3}, nil) }, unix.EINVAL},
		{"empty buffer", func(l *BpfLinker) error { return BpfLinkerAddBuf(l, nil, nil) }, unix.EINVAL},
		{"not BPF", func(l *BpfLinker) error { return BpfLinkerAddFile(l, exe, nil) }, unix.EOPNOTSUPP},
		{"negative fd", func(l *BpfLinker) error { return BpfLinkerAddFD(l, -1, nil) }, unix.EINVAL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := BpfLinkerNew(filepath.Join(t.TempDir(), "out.bpf.o"), nil)
			if err != nil {
				t.Fatalf("BpfLinkerNew: %v", err)
			}
			defer BpfLinkerFree(l)

			if err := tt.add(l); !errors.Is(err, tt.want) {
				t.Fatalf("add = %v, want %v", err, tt.want)
			}
			if err := BpfLinkerAddFile(l, linkerInputPath, nil); err != nil {
				t.Fatalf("add after a failed add: %v", err)
			}
		})
	}
}

func TestBpfLinkerLifecycle(t *testing.T) {
	if _, err := BpfLinkerNewFD(-1, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfLinkerNewFD(-1) = %v, want EINVAL", err)
	}
	if _, err := BpfLinkerNew(filepath.Join(t.TempDir(), "missing", "out.bpf.o"), nil); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("BpfLinkerNew in a missing directory = %v, want ENOENT", err)
	}

	l, err := BpfLinkerNew(filepath.Join(t.TempDir(), "out.bpf.o"), nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	if err := BpfLinkerAddFile(l, linkerInputPath, nil); err != nil {
		t.Fatalf("BpfLinkerAddFile: %v", err)
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	if err := BpfLinkerFinalize(l); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("second BpfLinkerFinalize = %v, want EINVAL", err)
	}
	if err := BpfLinkerAddFile(l, linkerInputPath, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfLinkerAddFile after finalize = %v, want EINVAL", err)
	}

	BpfLinkerFree(l)
	BpfLinkerFree(l)
	BpfLinkerFree(nil)
	if err := BpfLinkerFinalize(nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfLinkerFinalize(nil) = %v, want EINVAL", err)
	}
}

// TestBpfLinkerLoad loads the linked object into the kernel. It needs root or
// CAP_BPF and skips otherwise.
func TestBpfLinkerLoad(t *testing.T) {
	obj, err := BpfObjectOpenFile(linkFile(t), nil)
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
	if m := BpfObjectNextMap(obj, nil); m == nil || BpfMapFD(m) < 0 {
		t.Fatal("linked map has no descriptor")
	}
	if p := BpfObjectNextProgram(obj, nil); p == nil || BpfProgramFD(p) < 0 {
		t.Fatal("linked program has no descriptor")
	}
}
