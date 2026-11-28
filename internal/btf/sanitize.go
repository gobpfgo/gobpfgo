// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__sanitize_btf, starts_with_qmark, btf__add_int, btf_get_raw_data, btf_parse_hdr, btf_parse_layout_sec, btf_ensure_modifiable, btf_hdr_update_type_len

package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"syscall"
)

// KernelFeatures lists the BTF features that a kernel's BPF_BTF_LOAD
// accepts, as the loader's feature probes report them. Sanitize rewrites
// the types, names and header fields that need a feature the kernel lacks,
// so the zero value, a kernel without any of them, makes it rewrite
// everything it can.
type KernelFeatures struct {
	// DeclTag is BTF_KIND_DECL_TAG, from Linux 5.16.
	DeclTag bool
	// TypeTag is BTF_KIND_TYPE_TAG, from Linux 5.17.
	TypeTag bool
	// Enum64 is BTF_KIND_ENUM64 and the kind flag that marks a signed
	// ENUM, both from Linux 6.0.
	Enum64 bool
	// QmarkDatasec is a DATASEC name that starts with '?'.
	QmarkDatasec bool
	// Float is BTF_KIND_FLOAT, from Linux 5.13.
	Float bool
	// Func is BTF_KIND_FUNC and BTF_KIND_FUNC_PROTO, from Linux 5.0.
	Func bool
	// Datasec is BTF_KIND_VAR and BTF_KIND_DATASEC, from Linux 5.2.
	Datasec bool
	// GlobalFunc is a FUNC with global linkage, from Linux 5.6.
	GlobalFunc bool
	// Layout is the layout section that a 32-byte header places with
	// layout_off and layout_len, from Linux 7.1.
	Layout bool
}

// The INT that Sanitize writes over a VAR or a DECL_TAG, and the one it
// adds as the member type of the UNIONs that replace ENUM64s: one byte,
// with the encoding word BTF_INT_ENC(0, 0, 8), so no encoding flag, bit
// offset 0 and 8 bits.
const (
	sanitizedIntSize = 1
	sanitizedIntEnc  = 8
)

// sanitizedEnumSize is the size of the ENUM that Sanitize writes over a
// FUNC_PROTO, the four bytes the kernel requires of an ENUM.
const sanitizedEnumSize = 4

// Offsets of the layout section fields in a header of builtHdrLen bytes or
// more, and the size of one layout entry, struct btf_layout.
const (
	hdrLayoutOff    = 24
	hdrLayoutLen    = 28
	layoutEntrySize = 4
)

// enum64Placeholder names the INT that Sanitize adds for ENUM64s.
const enum64Placeholder = "enum64_placeholder"

// Sanitize returns a copy of the BTF blob for a kernel that lacks some of
// the features in k. In the copy:
//
//   - without Layout, a header of 32 bytes or more whose layout_off or
//     layout_len is set has both fields zero, and the blob has no layout
//     section: it ends with the string table, right after the types, and
//     str_off says so. hdr_len and every other header byte stay. This
//     happens first, so the rest applies to the stripped copy;
//   - without Datasec, every VAR is an INT of one byte with the encoding
//     word BTF_INT_ENC(0, 0, 8), without kind flag, that keeps the
//     variable's name, and every DATASEC is a STRUCT of the same size and
//     vlen. Each of its variables becomes a member at the variable's offset
//     times 8, a bit offset, of the type the variable refers to, named with
//     that type's name offset as the copy holds it when the DATASEC is
//     rewritten. Every '.' and '?' of the DATASEC's name is '_';
//   - without Func, every FUNC_PROTO is an ENUM of 4 bytes and the same
//     vlen, whose values are the parameters' name offsets and type IDs, and
//     every FUNC is a TYPEDEF of its prototype;
//   - with Func but without GlobalFunc, every FUNC has static linkage;
//   - without DeclTag, every DECL_TAG is the same one-byte INT, under the
//     tag's name;
//   - without TypeTag, every TYPE_TAG is an unnamed CONST of the same type;
//   - without Float, every FLOAT is an unnamed STRUCT of the same size and
//     without members;
//   - without Enum64, no ENUM has the kind flag, and every ENUM64 is a
//     UNION of the same size whose members keep the value names, each at
//     offset 0 with the type enum64_placeholder: a one-byte INT with
//     encoding word 8 that the copy adds once, after the last type;
//   - with Datasec but without QmarkDatasec, a DATASEC name that starts
//     with '?' starts with '_' instead.
//
// Every rewritten kind loses its kind flag. The names change in the string
// table, so every name at the same offset changes with them; other names
// do not. The types are rewritten in ID order, as libbpf does.
//
// The records keep their lengths, so every type keeps its ID. Without the
// placeholder, the copy has the blob's layout and length, or the stripped
// one's. With it, the copy is the header, the types, the placeholder, the
// layout section that Layout kept, if any, and the string table, with the
// header's type, layout and string offsets and lengths updated; the type
// offset is 0. The placeholder's name is the first equal string of the
// table when the first ENUM64 is rewritten, or is appended to it.
//
// The spec is not changed; its types, strings and Raw keep the original
// kinds and names. A blob that needs no change comes back as an equal copy.
// A split spec is an error. So is a layout section that libbpf would have
// rejected when it parsed the blob, when Sanitize strips or moves it, and,
// wrapping EOPNOTSUPP, a blob that needs the placeholder and has a nonzero
// header byte past the 32 that libbpf knows.
func (s *Spec) Sanitize(k KernelFeatures) ([]byte, error) {
	if s.base != nil || s.raw == nil {
		return nil, fmt.Errorf("btf: cannot sanitize split BTF")
	}

	z, err := s.newSanitizer(k.Layout)
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(s.Types); i++ {
		t := &s.Types[i]
		var err error
		switch {
		case !k.Datasec && t.Kind == KindVar, !k.DeclTag && t.Kind == KindDeclTag:
			err = z.put(t, 4, typeInfo(KindInt, 0), sanitizedIntSize, sanitizedIntEnc)
		case !k.Datasec && t.Kind == KindDatasec:
			err = z.datasecToStruct(t)
		case !k.QmarkDatasec && t.Kind == KindDatasec:
			err = z.renameDatasec(t, false)
		case !k.Func && t.Kind == KindFuncProto:
			err = z.put(t, 4, typeInfo(KindEnum, t.Vlen), sanitizedEnumSize)
		case !k.Func && t.Kind == KindFunc:
			err = z.put(t, 4, typeInfo(KindTypedef, 0))
		case !k.GlobalFunc && t.Kind == KindFunc:
			err = z.put(t, 4, typeInfo(KindFunc, FuncStatic))
		case !k.Float && t.Kind == KindFloat:
			err = z.put(t, 0, 0, typeInfo(KindStruct, 0))
		case !k.TypeTag && t.Kind == KindTypeTag:
			err = z.put(t, 0, 0, typeInfo(KindConst, 0))
		case !k.Enum64 && t.Kind == KindEnum:
			err = z.put(t, 4, typeInfo(KindEnum, t.Vlen))
		case !k.Enum64 && t.Kind == KindEnum64:
			err = z.enum64ToUnion(t)
		}
		if err != nil {
			return nil, err
		}
	}
	if z.placeholderID == 0 {
		return z.raw, nil
	}
	return z.appendEnum64Placeholder(), nil
}

// sanitizer is one Sanitize call: the copy it rewrites, and the enum64
// placeholder once the first ENUM64 needs it.
type sanitizer struct {
	spec *Spec
	raw  []byte
	// strs is the string section of raw.
	strs []byte

	// placeholderID is the type ID of the enum64 placeholder INT, or 0
	// before the first ENUM64. placeholderNameOff is the offset of its
	// name in strs, if placeholderNameFound, and order is the byte order
	// the INT is encoded in.
	placeholderID        uint32
	placeholderNameOff   uint32
	placeholderNameFound bool
	order                binary.AppendByteOrder
}

// typeInfo returns the info word of a type of kind with vlen and without
// kind flag.
func typeInfo(kind Kind, vlen uint32) uint32 {
	return uint32(kind)<<24 | vlen&0xffff
}

// layoutFields returns layout_off and layout_len from the header of raw,
// a copy of s's blob, or zeros when the header is shorter than
// builtHdrLen: libbpf then sees no layout section.
func (s *Spec) layoutFields(raw []byte) (off, length uint32) {
	if s.Header.HdrLen < builtHdrLen {
		return 0, 0
	}
	return s.ByteOrder.Uint32(raw[hdrLayoutOff:]), s.ByteOrder.Uint32(raw[hdrLayoutLen:])
}

// newSanitizer returns a sanitizer on a copy of s's blob. Without
// hasLayout, a header with layout_off or layout_len set has the layout
// section stripped first, as libbpf does before it parses the copy: the
// types stay where they are, the strings follow them and end the copy, and
// the header has str_off moved and both layout fields zero.
func (s *Spec) newSanitizer(hasLayout bool) (*sanitizer, error) {
	h := s.Header
	z := &sanitizer{spec: s}
	strStart := int(h.HdrLen) + int(h.StrOff)
	layoutOff, layoutLen := s.layoutFields(s.raw)
	if hasLayout || layoutOff == 0 && layoutLen == 0 {
		z.raw = bytes.Clone(s.raw)
		z.strs = z.raw[strStart : strStart+int(h.StrLen)]
		return z, nil
	}

	if err := s.checkLayout(layoutOff, layoutLen); err != nil {
		return nil, err
	}
	typeEnd := int(h.HdrLen) + int(h.TypeOff) + int(h.TypeLen)
	z.raw = make([]byte, typeEnd+int(h.StrLen))
	copy(z.raw, s.raw[:typeEnd])
	z.strs = z.raw[typeEnd:]
	copy(z.strs, s.raw[strStart:strStart+int(h.StrLen)])
	s.ByteOrder.PutUint32(z.raw[16:], h.TypeOff+h.TypeLen)
	s.ByteOrder.PutUint32(z.raw[hdrLayoutOff:], 0)
	s.ByteOrder.PutUint32(z.raw[hdrLayoutLen:], 0)
	return z, nil
}

// checkLayout checks the sections of s's blob, whose header has the layout
// fields off and length, as libbpf's btf_parse_hdr and btf_parse_layout_sec
// did when libbpf parsed it: the types end at or before the strings start
// and, unless length is 0, the layout section of whole entries starts
// 4-byte aligned after the types and ends at or before the strings. The
// error wraps EINVAL, as libbpf's does.
func (s *Spec) checkLayout(off, length uint32) error {
	h := s.Header
	typeEnd := uint64(h.TypeOff) + uint64(h.TypeLen)
	if typeEnd > uint64(h.StrOff) {
		return fmt.Errorf("btf: %w: invalid BTF data sections layout: type data at %d + %d, strings data at %d + %d",
			syscall.EINVAL, h.TypeOff, h.TypeLen, h.StrOff, h.StrLen)
	}
	if length == 0 {
		return nil
	}
	switch {
	case off%4 != 0:
		return fmt.Errorf("btf: %w: BTF layout section is not aligned to 4 bytes", syscall.EINVAL)
	case uint64(off) < typeEnd:
		return fmt.Errorf("btf: %w: invalid BTF data sections layout: type data at %d + %d, layout data at %d + %d",
			syscall.EINVAL, h.TypeOff, h.TypeLen, off, length)
	case uint64(off)+uint64(length) > uint64(h.StrOff):
		return fmt.Errorf("btf: %w: invalid BTF data sections layout: layout data at %d + %d, strings data at %d",
			syscall.EINVAL, off, length, h.StrOff)
	case length%layoutEntrySize != 0:
		return fmt.Errorf("btf: %w: invalid BTF kind layout section", syscall.EINVAL)
	}
	return nil
}

// renameDatasec replaces '_' for the '?' that starts the name of the
// DATASEC t in the copy's string table or, with all, for every '.' and '?'
// of the name.
func (z *sanitizer) renameDatasec(t *Type, all bool) error {
	if t.NameOff >= uint32(len(z.strs)) {
		return fmt.Errorf("btf: type %d: name offset %d out of bounds", t.ID, t.NameOff)
	}
	name := z.strs[t.NameOff:]
	if !all {
		if name[0] == '?' {
			name[0] = '_'
		}
		return nil
	}
	for i := 0; i < len(name) && name[i] != 0; i++ {
		if name[i] == '.' || name[i] == '?' {
			name[i] = '_'
		}
	}
	return nil
}

// datasecToStruct rewrites the DATASEC t as a STRUCT of the same size and
// vlen, renamed with renameDatasec. A variable's type, offset and size take
// three words, like a member's name, type and offset: libbpf writes the
// offset, from the variable's offset, then the type, then the name, from
// the type the variable refers to, so each word is read before it is
// overwritten. The name comes from the copy, where a lower ID may already
// be rewritten.
func (z *sanitizer) datasecToStruct(t *Type) error {
	if err := z.renameDatasec(t, true); err != nil {
		return err
	}
	if err := z.put(t, 4, typeInfo(KindStruct, t.Vlen)); err != nil {
		return err
	}
	for j := range int(t.Vlen) {
		off := 12 + 12*j
		typeID, err := z.word(t, off)
		if err != nil {
			return err
		}
		varOff, err := z.word(t, off+4)
		if err != nil {
			return err
		}
		nameOff, err := z.nameOffOf(t, typeID)
		if err != nil {
			return err
		}
		if err := z.put(t, off, nameOff, typeID, varOff*8); err != nil {
			return err
		}
	}
	return nil
}

// nameOffOf returns the name offset of the type id that the DATASEC t
// refers to, as the copy holds it: 0 for void.
func (z *sanitizer) nameOffOf(t *Type, id uint32) (uint32, error) {
	if id == 0 {
		return 0, nil
	}
	if id >= uint32(len(z.spec.Types)) {
		return 0, fmt.Errorf("btf: type %d: variable type %d out of range", t.ID, id)
	}
	return z.word(&z.spec.Types[id], 0)
}

// enum64ToUnion rewrites the ENUM64 t in the copy as a UNION of the same
// size and vlen. An ENUM64 value and a member both take three words: the
// name stays, and the value's low and high words become the member's type,
// the placeholder, and its bit offset, 0. The first ENUM64 sets up the
// placeholder, where libbpf adds it.
func (z *sanitizer) enum64ToUnion(t *Type) error {
	if z.placeholderID == 0 {
		if err := z.preparePlaceholder(); err != nil {
			return err
		}
	}
	if err := z.put(t, 4, typeInfo(KindUnion, t.Vlen)); err != nil {
		return err
	}
	for j := range int(t.Vlen) {
		if err := z.put(t, 12+12*j+4, z.placeholderID, 0); err != nil {
			return err
		}
	}
	return nil
}

// preparePlaceholder checks that the copy can be rebuilt with the enum64
// placeholder, as libbpf's btf__add_int does, and picks its type ID and
// name. libbpf refuses to modify BTF with a nonzero header byte past the
// 32 it knows, and looks the name up in the string table as rewritten so
// far.
func (z *sanitizer) preparePlaceholder() error {
	s := z.spec
	order, ok := s.ByteOrder.(binary.AppendByteOrder)
	if !ok {
		return fmt.Errorf("btf: byte order %v cannot encode", s.ByteOrder)
	}
	id := uint32(len(s.Types))
	if err := validateTypeID(id); err != nil {
		return err
	}
	if hdrLen := int(s.Header.HdrLen); hdrLen > builtHdrLen &&
		slices.ContainsFunc(z.raw[builtHdrLen:hdrLen], func(b byte) bool { return b != 0 }) {
		return fmt.Errorf("btf: cannot add %s: %w: unknown BTF header data", enum64Placeholder, syscall.EOPNOTSUPP)
	}
	if off, length := s.layoutFields(z.raw); length != 0 {
		if err := s.checkLayout(off, length); err != nil {
			return err
		}
	}

	z.order = order
	z.placeholderID = id
	z.placeholderNameOff, z.placeholderNameFound = findString(z.strs, enum64Placeholder)
	return nil
}

// appendEnum64Placeholder returns the copy rebuilt with the
// enum64_placeholder INT as type placeholderID after the last type: the
// header, the types, the INT, the layout section if the header still has
// one, and the string table, which gains the name unless it already held
// it. The header keeps its bytes but the section offsets and lengths, as
// libbpf's btf_get_raw_data writes them; libbpf keeps the type offset,
// which a clang blob has at 0, but the types follow the header either way.
func (z *sanitizer) appendEnum64Placeholder() []byte {
	s := z.spec
	h := s.Header
	nameOff := z.placeholderNameOff
	if !z.placeholderNameFound {
		nameOff = uint32(len(z.strs))
	}
	placeholder := Type{
		NameOff:    nameOff,
		Kind:       KindInt,
		SizeOrType: sanitizedIntSize,
		Int:        &Int{Encoding: sanitizedIntEnc},
	}

	var layout []byte
	if off, length := s.layoutFields(z.raw); length != 0 {
		start := int(h.HdrLen) + int(off)
		layout = z.raw[start : start+int(length)]
	}

	out := make([]byte, 0, len(z.raw)+16+len(enum64Placeholder)+1)
	out = append(out, z.raw[:h.HdrLen]...)
	out = append(out, z.raw[s.typeStart:s.typeStart+int(h.TypeLen)]...)
	out = AppendType(out, &placeholder, z.order)
	typeLen := uint32(len(out)) - h.HdrLen
	if layout != nil {
		s.ByteOrder.PutUint32(out[hdrLayoutOff:], typeLen)
		out = append(out, layout...)
	}
	strOff := uint32(len(out)) - h.HdrLen
	out = append(out, z.strs...)
	if !z.placeholderNameFound {
		out = append(append(out, enum64Placeholder...), 0)
	}

	s.ByteOrder.PutUint32(out[8:], 0)
	s.ByteOrder.PutUint32(out[12:], typeLen)
	s.ByteOrder.PutUint32(out[16:], strOff)
	s.ByteOrder.PutUint32(out[20:], uint32(len(out))-h.HdrLen-strOff)
	return out
}

// put writes words into t's record in the copy, the first one at byte off.
func (z *sanitizer) put(t *Type, off int, words ...uint32) error {
	return z.spec.putRecordWords(z.raw, t, off, words...)
}

// word reads the word at byte off of t's record in the copy.
func (z *sanitizer) word(t *Type, off int) (uint32, error) {
	pos := z.spec.typeStart + int(t.rawOff) + off
	if pos < 0 || pos+4 > len(z.raw) {
		return 0, fmt.Errorf("btf: type %d: field at %d out of bounds", t.ID, off)
	}
	return z.spec.ByteOrder.Uint32(z.raw[pos:]), nil
}

// putRecordWords writes words into t's record in raw, the first one at
// byte off.
func (s *Spec) putRecordWords(raw []byte, t *Type, off int, words ...uint32) error {
	for i, word := range words {
		if err := s.putRecordWord(raw, t, off+4*i, word); err != nil {
			return err
		}
	}
	return nil
}
