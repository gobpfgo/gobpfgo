// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original ELF writer

package elf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// ELF64 record sizes.
const (
	fileHeaderSize    = 64
	sectionHeaderSize = 64
	symbolSize        = 24
	relSize           = 16
)

// Names of the string tables Marshal fills in.
const (
	strtabName   = ".strtab"
	shstrtabName = ".shstrtab"
)

var le = binary.LittleEndian

// Output describes a 64-bit little-endian ET_REL EM_BPF object for Marshal.
//
// Sections[i] becomes ELF section i+1, after the reserved null section, and
// Symbols[i] becomes symbol i+1, after the reserved null symbol. Marshal fills
// in the contents of the tables it owns:
//
//   - the SHT_STRTAB named .strtab holds the symbol names;
//   - the SHT_STRTAB named .shstrtab holds the section names. Without one, the
//     section names go into .strtab, which is the layout clang and the BPF
//     static linker produce;
//   - the SHT_SYMTAB holds Symbols and links to .strtab;
//   - every SHT_REL holds its Relocs and links to the SHT_SYMTAB.
//
// Each string is stored once, in the order it is first used.
type Output struct {
	Sections []OutputSection
	Symbols  []OutputSymbol
}

// OutputSection is one section of an Output.
//
// Data is the content of an SHT_PROGBITS section, Size the size of an
// SHT_NOBITS section and Relocs the entries of an SHT_REL section. Info is
// written to sh_info: the relocated section's index for SHT_REL, any value
// the caller chooses for SHT_SYMTAB. Marshal computes the contents, sizes,
// links and entry sizes of the string, symbol and relocation tables; Entsize
// is used as given for the other types.
type OutputSection struct {
	Name      string
	Type      elf.SectionType
	Flags     elf.SectionFlag
	Addralign uint64
	Entsize   uint64
	Info      uint32
	Data      []byte
	Size      uint64
	Relocs    []OutputReloc
}

// OutputSymbol is one symbol table entry. Section is st_shndx: an index into
// the output sections, SHN_UNDEF, or a reserved index such as SHN_ABS. Other
// holds the visibility bits.
type OutputSymbol struct {
	Name    string
	Info    byte
	Other   byte
	Section elf.SectionIndex
	Value   uint64
	Size    uint64
}

// OutputReloc is one Elf64_Rel entry. Symbol is the symbol table index, so
// Symbols[i] is i+1 and 0 is the null symbol.
type OutputReloc struct {
	Offset uint64
	Symbol uint32
	Type   uint32
}

// Marshal serializes out. It returns an error for a section type other than
// SHT_PROGBITS, SHT_NOBITS, SHT_SYMTAB, SHT_STRTAB and SHT_REL, an unknown or
// duplicate table, a missing .strtab or SHT_SYMTAB that a symbol or relocation
// needs, an alignment that is not a power of two, or an index out of range.
// out is not modified.
//
// The layout follows libelf: the ELF header, then each section's data at its
// alignment in section order, then the section header table at an 8-byte
// boundary.
func Marshal(out *Output) ([]byte, error) {
	w := &writer{out: out}
	if err := w.findTables(); err != nil {
		return nil, err
	}
	w.addNames()
	if err := w.buildSections(); err != nil {
		return nil, err
	}
	shoff := w.layout()
	return w.bytes(shoff), nil
}

// sectionHeader is an Elf64_Shdr without sh_addr, which is zero in a
// relocatable object.
type sectionHeader struct {
	name      uint32
	typ       elf.SectionType
	flags     elf.SectionFlag
	offset    uint64
	size      uint64
	link      uint32
	info      uint32
	addralign uint64
	entsize   uint64
}

// stringTable is an ELF string table with one copy of each string. Offset 0
// is the empty string.
type stringTable struct {
	data    []byte
	offsets map[string]uint32
}

func newStringTable() *stringTable {
	return &stringTable{data: []byte{0}, offsets: map[string]uint32{"": 0}}
}

func (t *stringTable) add(s string) uint32 {
	if off, ok := t.offsets[s]; ok {
		return off
	}
	off := uint32(len(t.data))
	t.data = append(t.data, s...)
	t.data = append(t.data, 0)
	t.offsets[s] = off
	return off
}

// writer holds the state of one Marshal call. The table indices are ELF
// section indices; zero means the table is absent.
type writer struct {
	out *Output

	strtab   int
	shstrtab int
	symtab   int

	shstrs   *stringTable
	strs     *stringTable
	symNames []uint32

	headers  []sectionHeader
	contents [][]byte
}

// findTables validates the section types and finds the string and symbol
// tables.
func (w *writer) findTables() error {
	if len(w.out.Sections)+1 >= int(elf.SHN_LORESERVE) {
		return fmt.Errorf("elf: %d sections need extended numbering", len(w.out.Sections))
	}

	hasRel := false
	for i := range w.out.Sections {
		s := &w.out.Sections[i]
		if err := checkSection(s); err != nil {
			return fmt.Errorf("elf: section %s: %w", s.Name, err)
		}
		if s.Type == elf.SHT_REL {
			hasRel = true
		}

		slot, err := w.tableSlot(s)
		if err != nil {
			return err
		}
		if slot != nil {
			*slot = i + 1
		}
	}

	if w.shstrtab == 0 {
		w.shstrtab = w.strtab
	}
	if w.shstrtab == 0 {
		return fmt.Errorf("elf: no string table for the section names")
	}
	if w.symtab == 0 && (len(w.out.Symbols) > 0 || hasRel) {
		return fmt.Errorf("elf: symbols or relocations without an SHT_SYMTAB section")
	}
	if w.symtab != 0 && w.strtab == 0 {
		return fmt.Errorf("elf: SHT_SYMTAB without a .strtab section")
	}
	return nil
}

// tableSlot returns the index field a string or symbol table section fills,
// or nil for other sections.
func (w *writer) tableSlot(s *OutputSection) (*int, error) {
	var slot *int
	switch {
	case s.Type == elf.SHT_STRTAB && s.Name == strtabName:
		slot = &w.strtab
	case s.Type == elf.SHT_STRTAB && s.Name == shstrtabName:
		slot = &w.shstrtab
	case s.Type == elf.SHT_STRTAB:
		return nil, fmt.Errorf("elf: string table %s is not .strtab or .shstrtab", s.Name)
	case s.Type == elf.SHT_SYMTAB:
		slot = &w.symtab
	default:
		return nil, nil
	}

	if *slot != 0 {
		return nil, fmt.Errorf("elf: duplicate %v section %s", s.Type, s.Name)
	}
	return slot, nil
}

// checkSection rejects unsupported types, alignments that are not a power of
// two and payloads that do not belong to the section type.
func checkSection(s *OutputSection) error {
	switch s.Type {
	case elf.SHT_PROGBITS, elf.SHT_NOBITS, elf.SHT_SYMTAB, elf.SHT_STRTAB, elf.SHT_REL:
	default:
		return fmt.Errorf("unsupported type %v", s.Type)
	}
	if s.Addralign != 0 && bits.OnesCount64(s.Addralign) != 1 {
		return fmt.Errorf("alignment %d is not a power of two", s.Addralign)
	}
	if len(s.Data) != 0 && s.Type != elf.SHT_PROGBITS {
		return fmt.Errorf("data in a %v section", s.Type)
	}
	if s.Size != 0 && s.Type != elf.SHT_NOBITS {
		return fmt.Errorf("size in a %v section", s.Type)
	}
	if len(s.Relocs) != 0 && s.Type != elf.SHT_REL {
		return fmt.Errorf("relocations in a %v section", s.Type)
	}
	return nil
}

// addNames fills the string tables: section names first, in section order,
// then symbol names. A shared .strtab gets both.
func (w *writer) addNames() {
	w.shstrs = newStringTable()
	w.strs = w.shstrs
	if w.shstrtab != w.strtab {
		w.strs = newStringTable()
	}

	w.headers = make([]sectionHeader, len(w.out.Sections))
	for i := range w.out.Sections {
		w.headers[i].name = w.shstrs.add(w.out.Sections[i].Name)
	}

	w.symNames = make([]uint32, len(w.out.Symbols))
	for i := range w.out.Symbols {
		w.symNames[i] = w.strs.add(w.out.Symbols[i].Name)
	}
}

// buildSections computes every section's file bytes and header fields except
// the file offset.
func (w *writer) buildSections() error {
	w.contents = make([][]byte, len(w.out.Sections))
	for i := range w.out.Sections {
		s := &w.out.Sections[i]
		h := &w.headers[i]
		h.typ = s.Type
		h.flags = s.Flags
		h.info = s.Info
		h.addralign = s.Addralign
		h.entsize = s.Entsize

		data, err := w.sectionData(i + 1)
		if err != nil {
			return fmt.Errorf("elf: section %s: %w", s.Name, err)
		}
		w.contents[i] = data
		h.size = uint64(len(data))

		switch s.Type {
		case elf.SHT_NOBITS:
			h.size = s.Size
		case elf.SHT_SYMTAB:
			h.link = uint32(w.strtab)
			h.entsize = symbolSize
		case elf.SHT_REL:
			h.link = uint32(w.symtab)
			h.entsize = relSize
		}
	}
	return nil
}

// sectionData returns the file bytes of the section with ELF index index.
// SHT_NOBITS sections have none.
func (w *writer) sectionData(index int) ([]byte, error) {
	s := &w.out.Sections[index-1]
	switch {
	case index == w.shstrtab:
		return w.shstrs.data, nil
	case index == w.strtab:
		return w.strs.data, nil
	case s.Type == elf.SHT_SYMTAB:
		return w.symbolTable()
	case s.Type == elf.SHT_REL:
		return w.relocationTable(s)
	case s.Type == elf.SHT_NOBITS:
		return nil, nil
	}
	return s.Data, nil
}

// symbolTable serializes the null symbol and the output symbols.
func (w *writer) symbolTable() ([]byte, error) {
	data := make([]byte, symbolSize, symbolSize*(len(w.out.Symbols)+1))
	for i, sym := range w.out.Symbols {
		if sym.Section < elf.SHN_LORESERVE && int(sym.Section) > len(w.out.Sections) {
			return nil, fmt.Errorf("symbol %s: section index %d out of range", sym.Name, sym.Section)
		}
		data = le.AppendUint32(data, w.symNames[i])
		data = append(data, sym.Info, sym.Other)
		data = le.AppendUint16(data, uint16(sym.Section))
		data = le.AppendUint64(data, sym.Value)
		data = le.AppendUint64(data, sym.Size)
	}
	return data, nil
}

// relocationTable serializes the entries of an SHT_REL section.
func (w *writer) relocationTable(s *OutputSection) ([]byte, error) {
	if s.Info == 0 || int(s.Info) > len(w.out.Sections) {
		return nil, fmt.Errorf("relocated section index %d out of range", s.Info)
	}

	data := make([]byte, 0, relSize*len(s.Relocs))
	for _, r := range s.Relocs {
		if int(r.Symbol) > len(w.out.Symbols) {
			return nil, fmt.Errorf("relocation at %#x: symbol index %d out of range", r.Offset, r.Symbol)
		}
		data = le.AppendUint64(data, r.Offset)
		data = le.AppendUint64(data, uint64(r.Symbol)<<32|uint64(r.Type))
	}
	return data, nil
}

// layout assigns the section file offsets and returns the section header
// table offset.
func (w *writer) layout() uint64 {
	off := uint64(fileHeaderSize)
	for i := range w.headers {
		h := &w.headers[i]
		off = alignUp(off, h.addralign)
		h.offset = off
		if h.typ != elf.SHT_NOBITS {
			off += h.size
		}
	}
	return alignUp(off, 8)
}

// bytes writes the ELF header, the section data and the section headers.
func (w *writer) bytes(shoff uint64) []byte {
	shnum := len(w.headers) + 1
	buf := make([]byte, 0, shoff+uint64(shnum*sectionHeaderSize))
	buf = appendFileHeader(buf, shoff, uint16(shnum), uint16(w.shstrtab))

	for i, data := range w.contents {
		buf = padTo(buf, w.headers[i].offset)
		buf = append(buf, data...)
	}

	buf = padTo(buf, shoff)
	buf = append(buf, make([]byte, sectionHeaderSize)...)
	for _, h := range w.headers {
		buf = appendSectionHeader(buf, h)
	}
	return buf
}

// appendFileHeader appends an Elf64_Ehdr for a relocatable BPF object with no
// program headers.
func appendFileHeader(b []byte, shoff uint64, shnum, shstrndx uint16) []byte {
	var ident [elf.EI_NIDENT]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	ident[elf.EI_OSABI] = byte(elf.ELFOSABI_NONE)

	b = append(b, ident[:]...)
	b = le.AppendUint16(b, uint16(elf.ET_REL))
	b = le.AppendUint16(b, uint16(elf.EM_BPF))
	b = le.AppendUint32(b, uint32(elf.EV_CURRENT))
	b = le.AppendUint64(b, 0) // e_entry
	b = le.AppendUint64(b, 0) // e_phoff
	b = le.AppendUint64(b, shoff)
	b = le.AppendUint32(b, 0) // e_flags
	b = le.AppendUint16(b, fileHeaderSize)
	b = le.AppendUint16(b, 0) // e_phentsize
	b = le.AppendUint16(b, 0) // e_phnum
	b = le.AppendUint16(b, sectionHeaderSize)
	b = le.AppendUint16(b, shnum)
	return le.AppendUint16(b, shstrndx)
}

// appendSectionHeader appends one Elf64_Shdr.
func appendSectionHeader(b []byte, h sectionHeader) []byte {
	b = le.AppendUint32(b, h.name)
	b = le.AppendUint32(b, uint32(h.typ))
	b = le.AppendUint64(b, uint64(h.flags))
	b = le.AppendUint64(b, 0) // sh_addr
	b = le.AppendUint64(b, h.offset)
	b = le.AppendUint64(b, h.size)
	b = le.AppendUint32(b, h.link)
	b = le.AppendUint32(b, h.info)
	b = le.AppendUint64(b, h.addralign)
	return le.AppendUint64(b, h.entsize)
}

// alignUp rounds off up to align, a power of two; 0 and 1 mean no alignment.
func alignUp(off, align uint64) uint64 {
	if align <= 1 {
		return off
	}
	return (off + align - 1) &^ (align - 1)
}

// padTo appends zero bytes until b is off bytes long.
func padTo(b []byte, off uint64) []byte {
	for uint64(len(b)) < off {
		b = append(b, 0)
	}
	return b
}
