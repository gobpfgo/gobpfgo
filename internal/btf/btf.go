// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original BTF parser
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__parse, btf__type_by_id, btf__find_by_name_kind

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
// DATASEC sizes to the ELF section sizes before BPF_BTF_LOAD.
package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
}

// Parse validates and decodes a BTF blob. order is the byte order of the ELF
// object that contains the blob.
//
// Parse returns an error for a bad magic, an unsupported version, sections
// outside the blob, truncated type records or an unknown type kind.
func Parse(data []byte, order binary.ByteOrder) (*Spec, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("btf: header too short: %d bytes", len(data))
	}
	data = append([]byte(nil), data...)

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
		return nil, fmt.Errorf("btf: bad magic 0x%x", hdr.Magic)
	}
	if hdr.Version != 1 {
		return nil, fmt.Errorf("btf: unsupported version %d", hdr.Version)
	}
	if hdr.HdrLen < 24 || uint64(hdr.HdrLen) > uint64(len(data)) {
		return nil, fmt.Errorf("btf: bad header length %d", hdr.HdrLen)
	}

	typeStart := uint64(hdr.HdrLen) + uint64(hdr.TypeOff)
	typeEnd := typeStart + uint64(hdr.TypeLen)
	strStart := uint64(hdr.HdrLen) + uint64(hdr.StrOff)
	strEnd := strStart + uint64(hdr.StrLen)
	if typeEnd > uint64(len(data)) {
		return nil, fmt.Errorf("btf: type section out of bounds")
	}
	if strEnd > uint64(len(data)) {
		return nil, fmt.Errorf("btf: string section out of bounds")
	}

	s := &Spec{
		Header:    hdr,
		ByteOrder: order,
		Strings:   data[int(strStart):int(strEnd)],
		Types:     []Type{{Kind: KindVoid}},
		raw:       data,
		typeStart: int(typeStart),
	}

	typeData := data[int(typeStart):int(typeEnd)]
	for pos := 0; pos < len(typeData); {
		t, n, err := parseType(typeData[pos:], uint32(len(s.Types)), order)
		if err != nil {
			return nil, err
		}
		t.rawOff = uint32(pos)
		s.Types = append(s.Types, t)
		pos += n
	}

	for i := range s.Types {
		if err := s.resolveNames(&s.Types[i]); err != nil {
			return nil, err
		}
	}

	return s, nil
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
// string; an out-of-range or unterminated string is an error.
func (s *Spec) String(off uint32) (string, error) {
	if off == 0 {
		return "", nil
	}
	if int(off) >= len(s.Strings) {
		return "", fmt.Errorf("btf: string offset %d out of range", off)
	}
	b := s.Strings[off:]
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", fmt.Errorf("btf: unterminated string at %d", off)
	}
	return string(b[:i]), nil
}

// TypeByID returns the type with id. ID 0 is the void placeholder; an
// out-of-range ID is an error.
func (s *Spec) TypeByID(id uint32) (*Type, error) {
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
// loading BTF. Pass the result of Raw to BPF_BTF_LOAD.
func (s *Spec) FixupDatasecSizes(sectionSizes map[string]uint32) error {
	for i := range s.Types {
		t := &s.Types[i]
		if t.Kind != KindDatasec || t.ID == 0 {
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
// are skipped; a global variable without a symbol is an error.
func (s *Spec) FixupDatasecOffsets(offsets map[string]uint32) error {
	for i := range s.Types {
		t := &s.Types[i]
		if t.Kind != KindDatasec || t.ID == 0 {
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
// compared exactly; an empty name matches only empty names.
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
