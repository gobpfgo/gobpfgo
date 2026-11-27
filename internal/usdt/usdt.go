// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/usdt.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: sanity_check_usdt_elf, find_elf_sec_by_name, collect_usdt_targets, parse_usdt_note

//go:build linux && (amd64 || arm64)

// Package usdt reads the SystemTap SDT probes, or USDTs, of an ELF executable
// or shared library: the NT_STAPSDT records of its .note.stapsdt section and
// the argument spec of each one.
//
// A probe is named provider:name. The compiler can emit one probe at several
// call sites, so a name can have several notes, each with its own location
// and argument spec. Find returns all of them in file order.
//
// # Addresses
//
// Note.Location, Note.Base and Note.Semaphore are the link-time virtual
// addresses the note records; the package does not change them. A uprobe
// needs file offsets. libbpf derives them like this:
//
//   - When the file has a .stapsdt.base section (File.BaseAddr is nonzero)
//     and Note.Base is nonzero, the location moves by File.BaseAddr minus
//     Note.Base. This undoes prelink, which moves .stapsdt.base but not the
//     note. The semaphore is not adjusted.
//   - The address is then looked up in the PT_LOAD program headers: the
//     header whose [p_vaddr, p_vaddr+p_memsz) holds it gives the file offset
//     address - p_vaddr + p_offset. The location must be in an executable
//     segment and the semaphore in a non-executable one.
//   - The same offset follows from the section that holds the address:
//     address - sh_addr + sh_offset.
//
// A zero Semaphore means the probe has none.
//
// # Scope
//
// This package is the note and argument parser of libbpf's USDT support. The
// address conversion above, the BPF-side spec and IP maps, the USDT manager
// and the attach path are not ported yet.
package usdt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

const (
	noteSection = ".note.stapsdt"
	baseSection = ".stapsdt.base"

	// noteType is NT_STAPSDT and noteOwner the owner name of its records.
	noteType  = 3
	noteOwner = "stapsdt"

	// noteHeaderSize is the size of Elf64_Nhdr: namesz, descsz and type.
	noteHeaderSize = 12
	// noteAddrsSize is the location, base and semaphore at the start of
	// the descriptor.
	noteAddrsSize = 24
)

// The errors this package returns. Each one also wraps the errno libbpf
// returns in the same case, so errors.Is matches both the error and the
// errno.
var (
	// ErrInvalidELF is a file that is not a 64-bit little-endian ELF
	// executable or shared object (EBADF).
	ErrInvalidELF = errors.New("unsupported ELF file for USDT")
	// ErrNoNotes is a file without a .note.stapsdt section (ENOENT).
	ErrNoNotes = errors.New("no USDT notes section")
	// ErrMalformedNote is a .note.stapsdt section that is not SHT_NOTE or
	// a record libbpf rejects (EINVAL).
	ErrMalformedNote = errors.New("malformed USDT note")
	// ErrProbeNotFound is a provider:name with no note (ENOENT).
	ErrProbeNotFound = errors.New("USDT probe not found")
	// ErrUnsupportedArg is an argument spec libbpf cannot parse: an
	// unrecognized operand, size or scale (EINVAL), an unknown register
	// (ENOENT) or more than 12 arguments (E2BIG).
	ErrUnsupportedArg = errors.New("unsupported USDT argument")
	// ErrUnsupportedArch is an argument spec for a machine without an
	// operand parser (ENOTSUP).
	ErrUnsupportedArch = errors.New("unsupported USDT architecture")
)

func newError(kind error, errno unix.Errno, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %w", kind, fmt.Sprintf(format, args...), errno)
}

// Note is one NT_STAPSDT record.
type Note struct {
	Provider string
	Name     string
	// Args is the argument spec, such as "-4@%esi 8@-24(%rbp)". It is
	// empty when the probe has no arguments; a spec that starts with ':'
	// is also read as empty.
	Args string
	// Location is the address of the probe instruction, Base the address
	// of .stapsdt.base at link time and Semaphore the address of the
	// probe's semaphore, or 0. All three are virtual addresses.
	Location  uint64
	Base      uint64
	Semaphore uint64
}

// Probe is one call site of a USDT: its note and its parsed arguments.
type Probe struct {
	Note
	Spec []Arg
}

// File holds the USDT notes of one ELF file. It keeps no reference to the
// file it was read from.
type File struct {
	// Machine selects the operand syntax of the argument specs.
	Machine elf.Machine
	// Type is elf.ET_EXEC or elf.ET_DYN.
	Type elf.Type
	// BaseAddr is the address of the .stapsdt.base section, or 0 when the
	// file has none.
	BaseAddr uint64

	notes []Note
	// noteErr is the error of the first malformed record. notes holds the
	// records before it.
	noteErr error
}

// Open reads the USDT notes of the ELF file at path.
//
// The file must be a 64-bit little-endian executable or shared object
// (ErrInvalidELF) with a .note.stapsdt section (ErrNoNotes) of type SHT_NOTE
// (ErrMalformedNote). A malformed record does not fail Open: like libbpf,
// Notes and Find report it, after any error of a call site before it.
func Open(path string) (*File, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("usdt: %w", err)
	}
	defer r.Close()

	f, err := NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("usdt: %s: %w", path, err)
	}
	return f, nil
}

// NewFile reads the USDT notes of the ELF file in r, with the checks of Open.
// It reads everything it needs before returning.
func NewFile(r io.ReaderAt) (*File, error) {
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, newError(ErrInvalidELF, unix.EBADF, "%v", err)
	}
	if err := checkELF(ef); err != nil {
		return nil, err
	}

	sec := ef.Section(noteSection)
	if sec == nil {
		return nil, newError(ErrNoNotes, unix.ENOENT, "no %s section", noteSection)
	}
	if sec.Type != elf.SHT_NOTE {
		return nil, newError(ErrMalformedNote, unix.EINVAL, "%s has type %s", noteSection, sec.Type)
	}
	data, err := sectionData(sec)
	if err != nil {
		return nil, err
	}

	f := &File{Machine: ef.Machine, Type: ef.Type}
	if base := ef.Section(baseSection); base != nil {
		f.BaseAddr = base.Addr
	}
	f.notes, f.noteErr = readNotes(data, noteAlign(sec), ef.ByteOrder)
	return f, nil
}

// Arch returns the operand parser of the file's machine.
func (f *File) Arch() Arch {
	return ArchOf(f.Machine)
}

// Notes returns every note in file order. It fails with ErrMalformedNote when
// any record is malformed, because libbpf then rejects the whole file.
func (f *File) Notes() ([]Note, error) {
	if f.noteErr != nil {
		return nil, f.noteErr
	}
	return slices.Clone(f.notes), nil
}

// Find returns every call site of provider:name in file order, with its
// argument spec parsed for the file's machine.
//
// The records are checked in file order, as libbpf does: the spec error of a
// call site comes before the error of a malformed record after it. A name
// without notes fails with ErrProbeNotFound. Spec errors wrap
// ErrUnsupportedArg or ErrUnsupportedArch, as ParseSpec documents.
func (f *File) Find(provider, name string) ([]Probe, error) {
	arch := f.Arch()

	var probes []Probe
	for _, note := range f.notes {
		if note.Provider != provider || note.Name != name {
			continue
		}
		spec, err := ParseSpec(arch, note.Args)
		if err != nil {
			return nil, fmt.Errorf("%s:%s at %#x: %w", provider, name, note.Location, err)
		}
		probes = append(probes, Probe{Note: note, Spec: spec})
	}
	if f.noteErr != nil {
		return nil, f.noteErr
	}
	if len(probes) == 0 {
		return nil, newError(ErrProbeNotFound, unix.ENOENT, "%s:%s", provider, name)
	}
	return probes, nil
}

// checkELF accepts the files libbpf can attach USDTs to on a 64-bit
// little-endian host, which is every host this package builds for.
func checkELF(f *elf.File) error {
	if f.Class != elf.ELFCLASS64 {
		return newError(ErrInvalidELF, unix.EBADF, "%s file on a 64-bit host", f.Class)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return newError(ErrInvalidELF, unix.EBADF, "type %s, only ET_EXEC and ET_DYN are supported", f.Type)
	}
	if f.Data != elf.ELFDATA2LSB {
		return newError(ErrInvalidELF, unix.EBADF, "%s file on a little-endian host", f.Data)
	}
	return nil
}

// sectionData returns the bytes libelf hands to its note walker. A compressed
// section yields no records, and so does one that runs past the end of the
// file, because libelf has no data for it.
func sectionData(sec *elf.Section) ([]byte, error) {
	if sec.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, nil
	}
	data, err := sec.Data()
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", noteSection, err)
	}
	return data, nil
}

// noteAlign is the record alignment libelf uses for a note section: 8 bytes
// when the section is 8-byte aligned, 4 otherwise.
func noteAlign(sec *elf.Section) uint64 {
	if sec.Addralign == 8 {
		return 8
	}
	return 4
}

// readNotes parses the records of a note section in order. It returns the
// notes before the first malformed record and that record's error.
func readNotes(data []byte, align uint64, order binary.ByteOrder) ([]Note, error) {
	var notes []Note

	for off := uint64(0); ; {
		rec, next, ok := nextNoteRecord(data, off, align, order)
		if !ok {
			return notes, nil
		}
		note, err := parseNote(data, rec, order)
		if err != nil {
			return notes, err
		}
		notes = append(notes, note)
		off = next
	}
}

// noteRecord is the header of one note record and the offsets of its name
// and descriptor in the section.
type noteRecord struct {
	off     uint64
	namesz  uint32
	descsz  uint32
	typ     uint32
	nameOff uint64
	descOff uint64
}

// nextNoteRecord returns the record at off and the offset of the next one,
// following libelf's gelf_getnote. The name follows the header; the
// descriptor starts at the next multiple of align and is padded to one. A
// record that does not fit ends the walk without an error.
func nextNoteRecord(data []byte, off, align uint64, order binary.ByteOrder) (noteRecord, uint64, bool) {
	size := uint64(len(data))
	if off > size || size-off < noteHeaderSize {
		return noteRecord{}, 0, false
	}

	rec := noteRecord{
		off:    off,
		namesz: order.Uint32(data[off:]),
		descsz: order.Uint32(data[off+4:]),
		typ:    order.Uint32(data[off+8:]),
	}
	off += noteHeaderSize
	rec.nameOff = off
	if uint64(rec.namesz) > size || off > size-uint64(rec.namesz) {
		return noteRecord{}, 0, false
	}

	off = alignUp(off+uint64(rec.namesz), align)
	// libelf pads the descriptor size in 32 bits; a size that wraps to
	// zero is rejected.
	descsz := uint32(alignUp(uint64(rec.descsz), align))
	if off > size || size-off < uint64(descsz) || (descsz == 0 && rec.descsz != 0) {
		return noteRecord{}, 0, false
	}
	rec.descOff = off
	return rec, off + uint64(descsz), true
}

func alignUp(v, align uint64) uint64 {
	return (v + align - 1) &^ (align - 1)
}

// parseNote decodes one NT_STAPSDT record. The descriptor holds the
// location, base and semaphore addresses, then the provider, name and
// argument strings, each NUL terminated.
func parseNote(data []byte, rec noteRecord, order binary.ByteOrder) (Note, error) {
	if !ownerIsStapsdt(data[rec.nameOff : rec.nameOff+uint64(rec.namesz)]) {
		return Note{}, malformedNote(rec, "owner is not %s", noteOwner)
	}
	if rec.typ != noteType {
		return Note{}, malformedNote(rec, "type %d, want %d", rec.typ, noteType)
	}

	desc := data[rec.descOff : rec.descOff+uint64(rec.descsz)]
	if len(desc) < noteAddrsSize+3 {
		return Note{}, malformedNote(rec, "descriptor of %d bytes", len(desc))
	}
	note := Note{
		Location:  order.Uint64(desc[0:]),
		Base:      order.Uint64(desc[8:]),
		Semaphore: order.Uint64(desc[16:]),
	}

	provider, rest, ok := bytes.Cut(desc[noteAddrsSize:], []byte{0})
	if !ok {
		return Note{}, malformedNote(rec, "provider is not terminated")
	}
	if len(rest) == 0 || rest[0] == 0 {
		return Note{}, malformedNote(rec, "missing or empty name")
	}
	name, rest, ok := bytes.Cut(rest, []byte{0})
	if !ok {
		return Note{}, malformedNote(rec, "name is not terminated")
	}
	if len(rest) == 0 {
		return Note{}, malformedNote(rec, "missing argument spec")
	}

	// libbpf reads the spec as a C string, which may run past the
	// descriptor into its padding or the next record.
	argsOff := rec.descOff + uint64(len(desc)-len(rest))
	args, _, ok := bytes.Cut(data[argsOff:], []byte{0})
	if !ok {
		return Note{}, malformedNote(rec, "argument spec is not terminated in the section")
	}

	note.Provider = string(provider)
	note.Name = string(name)
	if len(args) > 0 && args[0] != ':' {
		note.Args = string(args)
	}
	return note, nil
}

// ownerIsStapsdt compares the record's owner name with "stapsdt" over its
// namesz bytes, stopping at a NUL like strncmp.
func ownerIsStapsdt(name []byte) bool {
	for i, c := range name {
		var want byte
		if i < len(noteOwner) {
			want = noteOwner[i]
		}
		if c != want {
			return false
		}
		if c == 0 {
			return true
		}
	}
	return true
}

func malformedNote(rec noteRecord, format string, args ...any) error {
	return newError(ErrMalformedNote, unix.EINVAL, "record at %#x: %s", rec.off, fmt.Sprintf(format, args...))
}
