// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original BTF parser
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-source: src/libbpf.c
// libbpf-symbols: btf__parse, btf__type_by_id, btf__find_by_name_kind, btf_fixup_datasec, btf__new_empty, btf_ensure_modifiable, btf_get_raw_data

// Package btf parses the BTF wire format used by BPF ELF objects.
//
// A Spec holds the header, the type table and the string table from a .BTF
// section. Type IDs index the table, with ID 0 reserved for void. Parse
// validates the header, the section bounds and every type record; it does not
// load anything into the kernel.
//
// The type model is a Go value per type with a kind-specific payload. It stays
// close to the wire format so later stages such as CO-RE can walk it without
// re-parsing.
//
// Parse keeps a private copy of the blob. FixupDatasecSizes patches the
// DATASEC sizes to the ELF section sizes before BPF_BTF_LOAD. Dedup merges
// duplicate types and rebuilds the blob; NewSpec wraps types built by a
// caller, such as a linker, so they can be deduplicated and encoded.
package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// Names of the DATASECs that back extern variables. The loader computes their
// sizes and variable offsets from the extern descriptors, and an extern VAR
// may have no ELF symbol, so the ELF-based DATASEC fixups leave them alone.
const (
	KconfigSec = ".kconfig"
	KsymsSec   = ".ksyms"
)

// isExternDatasec reports whether name is a DATASEC that backs externs.
func isExternDatasec(name string) bool {
	return name == KconfigSec || name == KsymsSec
}

// Header is the BTF header. The type and string offsets are relative to the
// end of the header, not to the start of the blob.
type Header struct {
	Magic   uint16
	Version uint8
	Flags   uint8
	HdrLen  uint32
	TypeOff uint32
	TypeLen uint32
	StrOff  uint32
	StrLen  uint32
}

// Spec is a parsed BTF object. Types[0] is the void placeholder, so a type ID
// is also its index in Types. Strings is the NUL-separated string table. The
// spec owns a private copy of the blob, so FixupDatasecSizes can patch it
// before BPF_BTF_LOAD.
type Spec struct {
	Header    Header
	ByteOrder binary.ByteOrder
	Types     []Type
	Strings   []byte

	raw       []byte
	typeStart int

	// stringsDeduped is set when every string in Strings is unique, so
	// Dedup keeps the string table.
	stringsDeduped bool

	// mergedSplit is set by MergeSplit and ParseSplit: the base and module
	// type names come from two string tables, so the spec cannot be
	// deduplicated.
	mergedSplit bool

	// base is the base spec of a split spec from ParseSplit, and nil
	// otherwise. A split spec's Types hold the void placeholder and its own
	// types; type IDs below startID and string offsets below startStrOff
	// belong to base.
	base        *Spec
	startID     uint32
	startStrOff uint32
}

// Header lengths: the fields up to the string section, and the full header
// with the layout section fields, which NewSpec writes.
const (
	minHdrLen   = 24
	builtHdrLen = 32
)

// NewSpec returns a spec of types and strings built by the caller rather than
// parsed, such as a linker's output. types[0] is the void placeholder, every
// type ID refers to an entry of types and every name offset to a string in
// strings, whose first byte is the empty string. Each string must appear
// once in strings: Dedup then keeps the table as it is.
//
// The spec keeps copies of the types and the strings; Raw returns the blob
// with a 32-byte header and no layout section. An order that cannot append,
// unlike the standard byte orders, is an error.
func NewSpec(order binary.ByteOrder, types []Type, strings []byte) (*Spec, error) {
	s := &Spec{
		Header:         Header{Magic: 0xeb9f, Version: 1, HdrLen: builtHdrLen},
		ByteOrder:      order,
		Types:          make([]Type, len(types)),
		Strings:        append([]byte(nil), strings...),
		stringsDeduped: true,
	}
	for i := range types {
		s.Types[i] = types[i].Clone()
	}
	if len(s.Types) == 0 {
		s.Types = []Type{{Kind: KindVoid}}
	}
	if len(s.Strings) == 0 {
		s.Strings = []byte{0}
	}
	if err := s.encode(); err != nil {
		return nil, err
	}
	return s, nil
}

// encode rebuilds the raw blob from the header, the types and the strings:
// the types right after the header and the strings right after the types.
// It refreshes each type's ID, info and offset and the header lengths, so the
// Set methods patch the new blob. Header bytes past the string section fields
// are kept from the old blob.
func (s *Spec) encode() error {
	order, ok := s.ByteOrder.(binary.AppendByteOrder)
	if !ok {
		return fmt.Errorf("btf: byte order %v cannot encode", s.ByteOrder)
	}

	var types []byte
	for i := 1; i < len(s.Types); i++ {
		t := &s.Types[i]
		t.ID = uint32(i)
		t.Info = infoWord(t)
		t.Vlen = vlenOf(t)
		t.rawOff = uint32(len(types))
		types = AppendType(types, t, order)
	}

	hdrLen := max(int(s.Header.HdrLen), minHdrLen)
	raw := make([]byte, hdrLen, hdrLen+len(types)+len(s.Strings))
	if len(s.raw) >= hdrLen {
		copy(raw[minHdrLen:], s.raw[minHdrLen:hdrLen])
	}
	s.Header.HdrLen = uint32(hdrLen)
	s.Header.TypeOff = 0
	s.Header.TypeLen = uint32(len(types))
	s.Header.StrOff = uint32(len(types))
	s.Header.StrLen = uint32(len(s.Strings))

	h, put := s.Header, s.ByteOrder
	put.PutUint16(raw[0:], h.Magic)
	raw[2], raw[3] = h.Version, h.Flags
	put.PutUint32(raw[4:], h.HdrLen)
	put.PutUint32(raw[8:], h.TypeOff)
	put.PutUint32(raw[12:], h.TypeLen)
	put.PutUint32(raw[16:], h.StrOff)
	put.PutUint32(raw[20:], h.StrLen)

	raw = append(append(raw, types...), s.Strings...)
	s.raw = raw
	s.typeStart = hdrLen
	s.Strings = raw[hdrLen+len(types):]
	return nil
}

// Parse validates and decodes a BTF blob. order is the byte order of the ELF
// object that contains the blob.
//
// Parse returns an error for a bad magic, an unsupported version, sections
// outside the blob, truncated type records or an unknown type kind.
func Parse(data []byte, order binary.ByteOrder) (*Spec, error) {
	data = append([]byte(nil), data...)
	hdr, sec, err := parseHeader(data, order)
	if err != nil {
		return nil, err
	}

	s := &Spec{
		Header:         hdr,
		ByteOrder:      order,
		Strings:        data[sec.strStart:sec.strEnd],
		Types:          []Type{{Kind: KindVoid}},
		raw:            data,
		typeStart:      sec.typeStart,
		stringsDeduped: hdr.StrLen <= 1,
	}
	if err := s.parseTypes(data[sec.typeStart:sec.typeEnd], 1); err != nil {
		return nil, err
	}
	for i := range s.Types {
		if err := s.resolveNames(&s.Types[i]); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// btfSections are the byte ranges of the type and string sections in a BTF
// blob.
type btfSections struct {
	typeStart, typeEnd int
	strStart, strEnd   int
}

// parseHeader decodes and checks the BTF header of data and returns it with
// the bounds of the type and string sections.
func parseHeader(data []byte, order binary.ByteOrder) (Header, btfSections, error) {
	if len(data) < 24 {
		return Header{}, btfSections{}, fmt.Errorf("btf: header too short: %d bytes", len(data))
	}
	hdr := Header{
		Magic:   order.Uint16(data[0:]),
		Version: data[2],
		Flags:   data[3],
		HdrLen:  order.Uint32(data[4:]),
		TypeOff: order.Uint32(data[8:]),
		TypeLen: order.Uint32(data[12:]),
		StrOff:  order.Uint32(data[16:]),
		StrLen:  order.Uint32(data[20:]),
	}
	if hdr.Magic != 0xeb9f {
		return Header{}, btfSections{}, fmt.Errorf("btf: bad magic 0x%x", hdr.Magic)
	}
	if hdr.Version != 1 {
		return Header{}, btfSections{}, fmt.Errorf("btf: unsupported version %d", hdr.Version)
	}
	if hdr.HdrLen < 24 || uint64(hdr.HdrLen) > uint64(len(data)) {
		return Header{}, btfSections{}, fmt.Errorf("btf: bad header length %d", hdr.HdrLen)
	}
	if hdr.TypeOff%4 != 0 {
		return Header{}, btfSections{}, fmt.Errorf("btf: type section is not aligned to 4 bytes")
	}

	typeStart := uint64(hdr.HdrLen) + uint64(hdr.TypeOff)
	typeEnd := typeStart + uint64(hdr.TypeLen)
	strStart := uint64(hdr.HdrLen) + uint64(hdr.StrOff)
	strEnd := strStart + uint64(hdr.StrLen)
	if typeEnd > uint64(len(data)) {
		return Header{}, btfSections{}, fmt.Errorf("btf: type section out of bounds")
	}
	if strEnd > uint64(len(data)) {
		return Header{}, btfSections{}, fmt.Errorf("btf: string section out of bounds")
	}
	return hdr, btfSections{int(typeStart), int(typeEnd), int(strStart), int(strEnd)}, nil
}

// parseTypes decodes the type records of typeData and appends them to
// s.Types; the first one gets type ID firstID.
func (s *Spec) parseTypes(typeData []byte, firstID uint32) error {
	id := firstID
	for pos := 0; pos < len(typeData); id++ {
		t, n, err := parseType(typeData[pos:], id, s.ByteOrder)
		if err != nil {
			return err
		}
		t.rawOff = uint32(pos)
		s.Types = append(s.Types, t)
		pos += n
	}
	return nil
}

func parseType(b []byte, id uint32, order binary.ByteOrder) (Type, int, error) {
	if len(b) < 12 {
		return Type{}, 0, fmt.Errorf("btf: type %d: header out of bounds", id)
	}

	t := Type{
		ID:         id,
		NameOff:    order.Uint32(b[0:]),
		Info:       order.Uint32(b[4:]),
		SizeOrType: order.Uint32(b[8:]),
	}
	t.Kind = Kind((t.Info >> 24) & 0x1f)
	t.KindFlag = t.Info>>31 != 0
	t.Vlen = t.Info & 0xffff

	n := 12
	switch t.Kind {
	case KindInt:
		if len(b) < n+4 {
			return Type{}, 0, fmt.Errorf("btf: type %d: int payload out of bounds", id)
		}
		t.Int = &Int{Encoding: order.Uint32(b[n:])}
		n += 4

	case KindArray:
		if len(b) < n+12 {
			return Type{}, 0, fmt.Errorf("btf: type %d: array payload out of bounds", id)
		}
		t.Array = &Array{
			Type:      order.Uint32(b[n:]),
			IndexType: order.Uint32(b[n+4:]),
			Nelems:    order.Uint32(b[n+8:]),
		}
		n += 12

	case KindStruct, KindUnion:
		size := int(t.Vlen) * 12
		if len(b) < n+size {
			return Type{}, 0, fmt.Errorf("btf: type %d: members out of bounds", id)
		}
		t.Members = make([]Member, t.Vlen)
		for i := range t.Members {
			m := &t.Members[i]
			m.NameOff = order.Uint32(b[n:])
			m.Type = order.Uint32(b[n+4:])
			rawOffset := order.Uint32(b[n+8:])
			if t.KindFlag {
				m.Offset = rawOffset & 0xffffff
				m.BitfieldSize = uint8(rawOffset >> 24)
			} else {
				m.Offset = rawOffset
			}
			n += 12
		}

	case KindEnum:
		size := int(t.Vlen) * 8
		if len(b) < n+size {
			return Type{}, 0, fmt.Errorf("btf: type %d: enum values out of bounds", id)
		}
		t.Enums = make([]Enum, t.Vlen)
		for i := range t.Enums {
			t.Enums[i].NameOff = order.Uint32(b[n:])
			t.Enums[i].Value = int32(order.Uint32(b[n+4:]))
			n += 8
		}

	case KindFuncProto:
		size := int(t.Vlen) * 8
		if len(b) < n+size {
			return Type{}, 0, fmt.Errorf("btf: type %d: params out of bounds", id)
		}
		t.Params = make([]Param, t.Vlen)
		for i := range t.Params {
			t.Params[i].NameOff = order.Uint32(b[n:])
			t.Params[i].Type = order.Uint32(b[n+4:])
			n += 8
		}

	case KindVar:
		if len(b) < n+4 {
			return Type{}, 0, fmt.Errorf("btf: type %d: var payload out of bounds", id)
		}
		t.Var = &Var{Linkage: order.Uint32(b[n:])}
		n += 4

	case KindDatasec:
		size := int(t.Vlen) * 12
		if len(b) < n+size {
			return Type{}, 0, fmt.Errorf("btf: type %d: data section out of bounds", id)
		}
		t.DataSec = make([]VarSecInfo, t.Vlen)
		for i := range t.DataSec {
			t.DataSec[i].Type = order.Uint32(b[n:])
			t.DataSec[i].Offset = order.Uint32(b[n+4:])
			t.DataSec[i].Size = order.Uint32(b[n+8:])
			n += 12
		}

	case KindDeclTag:
		if len(b) < n+4 {
			return Type{}, 0, fmt.Errorf("btf: type %d: decl tag out of bounds", id)
		}
		t.DeclTag = &DeclTag{ComponentIdx: int32(order.Uint32(b[n:]))}
		n += 4

	case KindEnum64:
		size := int(t.Vlen) * 12
		if len(b) < n+size {
			return Type{}, 0, fmt.Errorf("btf: type %d: enum64 values out of bounds", id)
		}
		t.Enum64s = make([]Enum64, t.Vlen)
		for i := range t.Enum64s {
			t.Enum64s[i].NameOff = order.Uint32(b[n:])
			lo := order.Uint32(b[n+4:])
			hi := order.Uint32(b[n+8:])
			t.Enum64s[i].Value = uint64(hi)<<32 | uint64(lo)
			n += 12
		}

	case KindVoid, KindPtr, KindFwd, KindTypedef, KindVolatile, KindConst,
		KindRestrict, KindFunc, KindFloat, KindTypeTag:
		// No payload.

	default:
		return Type{}, 0, fmt.Errorf("btf: type %d: unknown kind %d", id, t.Kind)
	}

	return t, n, nil
}

func (s *Spec) resolveNames(t *Type) error {
	var err error
	if t.Name, err = s.String(t.NameOff); err != nil {
		return err
	}
	for i := range t.Members {
		if t.Members[i].Name, err = s.String(t.Members[i].NameOff); err != nil {
			return err
		}
	}
	for i := range t.Enums {
		if t.Enums[i].Name, err = s.String(t.Enums[i].NameOff); err != nil {
			return err
		}
	}
	for i := range t.Enum64s {
		if t.Enum64s[i].Name, err = s.String(t.Enum64s[i].NameOff); err != nil {
			return err
		}
	}
	for i := range t.Params {
		if t.Params[i].Name, err = s.String(t.Params[i].NameOff); err != nil {
			return err
		}
	}
	return nil
}

// String returns the NUL-terminated string at off. Offset 0 is the empty
// string; an out-of-range or unterminated string is an error. In a split
// spec an offset below the base string table's length is a base string.
func (s *Spec) String(off uint32) (string, error) {
	if s.base != nil {
		if off < s.startStrOff {
			return s.base.String(off)
		}
		return stringAt(s.Strings, off-s.startStrOff)
	}
	if off == 0 {
		return "", nil
	}
	return stringAt(s.Strings, off)
}

// stringAt returns the NUL-terminated string at off in the string table
// strs.
func stringAt(strs []byte, off uint32) (string, error) {
	if int(off) >= len(strs) {
		return "", fmt.Errorf("btf: string offset %d out of range", off)
	}
	b := strs[off:]
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", fmt.Errorf("btf: unterminated string at %d", off)
	}
	return string(b[:i]), nil
}

// TypeByID returns the type with id. ID 0 is the void placeholder; an
// out-of-range ID is an error. In a split spec an ID below StartID is a base
// type.
func (s *Spec) TypeByID(id uint32) (*Type, error) {
	if s.base != nil {
		if id < s.startID {
			return s.base.TypeByID(id)
		}
		id = id - s.startID + 1
	}
	if id >= uint32(len(s.Types)) {
		return nil, fmt.Errorf("btf: type id %d out of range", id)
	}
	return &s.Types[id], nil
}

// Raw returns the BTF bytes owned by the spec. Pass it to BPF_BTF_LOAD after
// FixupDatasecSizes; the caller must not modify the slice.
func (s *Spec) Raw() []byte {
	return s.raw
}

// FixupDatasecSizes patches every DATASEC size to the matching ELF section
// size and updates the parsed types.
//
// The kernel rejects a DATASEC with size 0, while clang emits the section
// variables with a zero size in the BTF. libbpf applies the same fixup before
// loading BTF. The extern DATASECs .kconfig and .ksyms are skipped. Pass the
// result of Raw to BPF_BTF_LOAD.
func (s *Spec) FixupDatasecSizes(sectionSizes map[string]uint32) error {
	for i := range s.Types {
		t := &s.Types[i]
		if t.Kind != KindDatasec || t.ID == 0 || isExternDatasec(t.Name) {
			continue
		}
		size, ok := sectionSizes[t.Name]
		if !ok || size == 0 || t.SizeOrType == size {
			continue
		}
		if err := s.SetDatasecSize(t.ID, size); err != nil {
			return err
		}
	}
	return nil
}

// FixupDatasecOffsets writes the DATASEC variable offsets from the ELF
// symbol values, matching libbpf's btf_fixup_datasec. A variable whose offset
// is already nonzero is left alone, because a statically linked object
// carries the final offsets.
//
// offsets maps an ELF symbol name to its value. Static and extern variables
// and the extern DATASECs .kconfig and .ksyms are skipped; a global variable
// without a symbol is an error.
func (s *Spec) FixupDatasecOffsets(offsets map[string]uint32) error {
	for i := range s.Types {
		t := &s.Types[i]
		if t.Kind != KindDatasec || t.ID == 0 || isExternDatasec(t.Name) {
			continue
		}
		for j := range t.DataSec {
			vsi := &t.DataSec[j]
			if vsi.Offset != 0 {
				continue
			}

			varType, err := s.TypeByID(vsi.Type)
			if err != nil {
				return err
			}
			if varType.Kind != KindVar || varType.Var == nil {
				return fmt.Errorf("btf: datasec %s: member %d is not a VAR", t.Name, j)
			}
			if varType.Var.Linkage == VarStatic || varType.Var.Linkage == VarGlobalExtern {
				continue
			}

			value, ok := offsets[varType.Name]
			if !ok {
				return fmt.Errorf("btf: datasec %s: no ELF symbol for %s", t.Name, varType.Name)
			}
			if err := s.SetDatasecVarOffset(t.ID, j, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// FixupDatasecHiddenVars marks the global DATASEC variables named in hidden as
// static, in both the raw blob and the parsed types. The caller passes the
// variables whose ELF symbol has hidden or internal visibility; such a variable
// is not visible outside the object, so the loader treats it like a static
// one. Static and extern variables and the extern DATASECs are left alone.
func (s *Spec) FixupDatasecHiddenVars(hidden map[string]bool) error {
	for i := range s.Types {
		t := &s.Types[i]
		if t.Kind != KindDatasec || t.ID == 0 || isExternDatasec(t.Name) {
			continue
		}
		for j := range t.DataSec {
			varType, err := s.TypeByID(t.DataSec[j].Type)
			if err != nil {
				return err
			}
			if varType.Kind != KindVar || varType.Var == nil {
				return fmt.Errorf("btf: datasec %s: member %d is not a VAR", t.Name, j)
			}
			if varType.Var.Linkage == VarStatic || varType.Var.Linkage == VarGlobalExtern {
				continue
			}
			if !hidden[varType.Name] {
				continue
			}
			if err := s.SetVarLinkage(varType.ID, VarStatic); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetVarLinkage writes linkage into the VAR type id, in both the raw blob and
// the parsed type. It returns an error when id is not a VAR.
func (s *Spec) SetVarLinkage(id uint32, linkage uint32) error {
	t, err := s.TypeByID(id)
	if err != nil {
		return err
	}
	if t.Kind != KindVar || t.Var == nil {
		return fmt.Errorf("btf: type %d is %v, not a VAR", id, t.Kind)
	}
	off := s.typeStart + int(t.rawOff) + 12
	if off+4 > len(s.raw) {
		return fmt.Errorf("btf: var %s: linkage field out of bounds", t.Name)
	}
	s.ByteOrder.PutUint32(s.raw[off:], linkage)
	t.Var.Linkage = linkage
	return nil
}

// SortDatasecVars orders each DATASEC's variables by their offset, as libbpf
// does before BPF_BTF_LOAD. The kernel requires the offsets to be ascending.
func (s *Spec) SortDatasecVars() error {
	for i := range s.Types {
		t := &s.Types[i]
		if t.Kind != KindDatasec || t.ID == 0 || len(t.DataSec) < 2 {
			continue
		}

		sorted := append([]VarSecInfo(nil), t.DataSec...)
		sort.SliceStable(sorted, func(a, b int) bool {
			return sorted[a].Offset < sorted[b].Offset
		})

		for j := range sorted {
			off := s.typeStart + int(t.rawOff) + 12 + j*12
			if off+12 > len(s.raw) {
				return fmt.Errorf("btf: datasec %s: variable %d out of bounds", t.Name, j)
			}
			s.ByteOrder.PutUint32(s.raw[off:], sorted[j].Type)
			s.ByteOrder.PutUint32(s.raw[off+4:], sorted[j].Offset)
			s.ByteOrder.PutUint32(s.raw[off+8:], sorted[j].Size)
		}
		t.DataSec = sorted
	}
	return nil
}

// SetDatasecSize writes size into the DATASEC type id, in both the raw blob
// and the parsed type. It returns an error when id is not a DATASEC.
func (s *Spec) SetDatasecSize(id uint32, size uint32) error {
	t, err := s.datasec(id)
	if err != nil {
		return err
	}
	off := s.typeStart + int(t.rawOff) + 8
	if off+4 > len(s.raw) {
		return fmt.Errorf("btf: datasec %s: size field out of bounds", t.Name)
	}
	s.ByteOrder.PutUint32(s.raw[off:], size)
	t.SizeOrType = size
	return nil
}

// SetDatasecVarOffset writes offset into member j of the DATASEC type id, in
// both the raw blob and the parsed type. It returns an error when id is not a
// DATASEC or j is not one of its members.
func (s *Spec) SetDatasecVarOffset(id uint32, j int, offset uint32) error {
	t, err := s.datasec(id)
	if err != nil {
		return err
	}
	if j < 0 || j >= len(t.DataSec) {
		return fmt.Errorf("btf: datasec %s: member %d out of range", t.Name, j)
	}
	off := s.typeStart + int(t.rawOff) + 12 + j*12 + 4
	if off+4 > len(s.raw) {
		return fmt.Errorf("btf: datasec %s: offset field out of bounds", t.Name)
	}
	s.ByteOrder.PutUint32(s.raw[off:], offset)
	t.DataSec[j].Offset = offset
	return nil
}

// datasec returns the DATASEC type with id.
func (s *Spec) datasec(id uint32) (*Type, error) {
	t, err := s.TypeByID(id)
	if err != nil {
		return nil, err
	}
	if t.Kind != KindDatasec {
		return nil, fmt.Errorf("btf: type %d is %v, not a DATASEC", id, t.Kind)
	}
	return t, nil
}

// Find returns the first type with the given name and kind, or nil. Names are
// compared exactly; an empty name matches only empty names. A split spec
// searches only its own types, not its base.
func (s *Spec) Find(name string, kind Kind) *Type {
	for i := 1; i < len(s.Types); i++ {
		if s.Types[i].Name == name && s.Types[i].Kind == kind {
			return &s.Types[i]
		}
	}
	return nil
}

// Member returns the named member of a struct or union, or nil. It is a
// convenience for the map definition parser.
func (s *Spec) Member(t *Type, name string) *Member {
	if t == nil {
		return nil
	}
	for i := range t.Members {
		if t.Members[i].Name == name {
			return &t.Members[i]
		}
	}
	return nil
}
