// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original Go ELF reader
// libbpf-source: src/elf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__elf_init, bpf_object__elf_collect, bpf_object__elf_finish

// Package elf reads the parts of a 64-bit BPF ELF object that the loader
// needs: sections, symbols, relocations, the .maps, .BTF and .BTF.ext payloads
// and the executable program sections.
//
// The reader is independent of libelf. It keeps the section bytes in memory;
// the caller parses the BTF and map definitions from them.
package elf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// BPF relocation types used by the object loader.
const (
	R_BPF_64_64 = 1
	R_BPF_64_32 = 10
)

// Re-exported so callers do not need to import debug/elf as well.
const (
	EM_BPF   = elf.EM_BPF
	STT_FUNC = elf.STT_FUNC
)

// Reloc is one relocation entry. Section is the target section name, Symbol
// the referenced symbol, Type the ELF relocation type and Addend the RELA
// addend.
type Reloc struct {
	Section string
	Offset  uint64
	Symbol  string
	Type    uint32
	Addend  int64
}

// Symbol is one symbol table entry, with its section name resolved.
type Symbol struct {
	Name         string
	SectionIndex elf.SectionIndex
	Section      string
	Value        uint64
	Size         uint64
	Info         byte
	Type         elf.SymType
	Bind         elf.SymBind
}

// Section is one ELF section header plus its bytes. SHT_NOBITS sections have
// no data.
type Section struct {
	Name  string
	Index int
	Type  elf.SectionType
	Flags elf.SectionFlag
	Size  uint64
	Data  []byte
}

// Program is an executable section with its instruction bytes and
// relocations. The section name carries the SEC prefix.
type Program struct {
	Name         string
	SectionIndex int
	Insns        []byte
	Relocs       []Reloc
}

// Object is the parsed ELF view used by the object loader. Sections holds
// every section with its bytes; Symbols and Relocations hold the symbol table
// and relocation entries; Programs are the executable PROGBITS sections.
type Object struct {
	Class       elf.Class
	Machine     elf.Machine
	ByteOrder   binary.ByteOrder
	Sections    []Section
	Symbols     []Symbol
	Relocations []Reloc
	Programs    []Program

	License string
	Version uint32
	Maps    []byte
	BTF     []byte
	BTFExt  []byte
}

// Open reads path and parses it as a 64-bit ELF object. The file is read into
// memory; the returned sections own their bytes.
func Open(path string) (*Object, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("elf: read %s: %w", path, err)
	}
	return OpenBytes(data)
}

// OpenBytes parses a 64-bit ELF object from data. The input is read during the
// call; the returned sections own their bytes.
func OpenBytes(data []byte) (*Object, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("elf: parse: %w", err)
	}
	if f.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("elf: unsupported class %v", f.Class)
	}

	o := &Object{
		Class:     f.Class,
		Machine:   f.Machine,
		ByteOrder: f.ByteOrder,
	}

	for i, s := range f.Sections {
		sec := Section{
			Name:  s.Name,
			Index: i,
			Type:  s.Type,
			Flags: s.Flags,
			Size:  s.Size,
		}
		if s.Type != elf.SHT_NOBITS {
			sec.Data, err = s.Data()
			if err != nil {
				return nil, fmt.Errorf("elf: section %s: %w", s.Name, err)
			}
		}
		o.Sections = append(o.Sections, sec)

		switch s.Name {
		case ".maps":
			o.Maps = sec.Data
		case ".BTF":
			o.BTF = sec.Data
		case ".BTF.ext":
			o.BTFExt = sec.Data
		case "license", ".license":
			o.License = strings.TrimRight(string(sec.Data), "\x00")
		case "version", ".version":
			if len(sec.Data) >= 4 {
				o.Version = f.ByteOrder.Uint32(sec.Data)
			}
		}

		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Type == elf.SHT_PROGBITS && len(sec.Data) > 0 {
			o.Programs = append(o.Programs, Program{
				Name:         s.Name,
				SectionIndex: i,
				Insns:        sec.Data,
			})
		}
	}

	symbols, err := f.Symbols()
	if err == nil {
		// debug/elf omits the null symbol at index 0, while relocation
		// entries index the raw symbol table. Put the placeholder back so
		// relocation symbol indices line up.
		if len(symbols) == 0 || symbols[0].Name != "" || symbols[0].Section != 0 ||
			symbols[0].Value != 0 || symbols[0].Info != 0 {
			symbols = append([]elf.Symbol{{}}, symbols...)
		}
		for _, sym := range symbols {
			section := ""
			if int(sym.Section) < len(f.Sections) {
				section = f.Sections[sym.Section].Name
			}
			o.Symbols = append(o.Symbols, Symbol{
				Name:         sym.Name,
				SectionIndex: sym.Section,
				Section:      section,
				Value:        sym.Value,
				Size:         sym.Size,
				Info:         sym.Info,
				Type:         elf.ST_TYPE(sym.Info),
				Bind:         elf.ST_BIND(sym.Info),
			})
		}
	} else if !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("elf: symbols: %w", err)
	}

	for _, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		target := ""
		if int(s.Info) < len(f.Sections) {
			target = f.Sections[s.Info].Name
		}
		relocs, err := parseRelocs(s, target, o.Symbols, f.ByteOrder)
		if err != nil {
			return nil, err
		}
		o.Relocations = append(o.Relocations, relocs...)
		for i := range o.Programs {
			if o.Programs[i].SectionIndex == int(s.Info) {
				o.Programs[i].Relocs = append(o.Programs[i].Relocs, relocs...)
			}
		}
	}

	return o, nil
}

func parseRelocs(s *elf.Section, target string, symbols []Symbol, order binary.ByteOrder) ([]Reloc, error) {
	data, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("elf: relocations %s: %w", s.Name, err)
	}

	entSize := int(s.Entsize)
	if entSize == 0 {
		entSize = 16
		if s.Type == elf.SHT_RELA {
			entSize = 24
		}
	}
	if entSize < 16 {
		return nil, fmt.Errorf("elf: relocation entry size %d in %s", entSize, s.Name)
	}

	var relocs []Reloc
	for off := 0; off+entSize <= len(data); off += entSize {
		info := order.Uint64(data[off+8:])
		symIndex := info >> 32
		reloc := Reloc{
			Section: target,
			Offset:  order.Uint64(data[off:]),
			Type:    uint32(info & 0xffffffff),
		}
		if symIndex < uint64(len(symbols)) {
			reloc.Symbol = symbols[symIndex].Name
		}
		if s.Type == elf.SHT_RELA && entSize >= 24 {
			reloc.Addend = int64(order.Uint64(data[off+16:]))
		}
		relocs = append(relocs, reloc)
	}
	return relocs, nil
}
