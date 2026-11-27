// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__sanitize_btf, starts_with_qmark, btf__add_int, btf_get_raw_data

package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
)

// KernelFeatures lists the BTF features that a kernel's BPF_BTF_LOAD
// accepts, as the loader's feature probes report them. Sanitize rewrites
// the types and names that need a feature the kernel lacks.
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
}

// The INT that Sanitize writes over a DECL_TAG, and the one it adds as the
// member type of the UNIONs that replace ENUM64s: one byte, with the
// encoding word BTF_INT_ENC(0, 0, 8), so no encoding flag, bit offset 0 and
// 8 bits.
const (
	sanitizedIntSize = 1
	sanitizedIntEnc  = 8
)

// enum64Placeholder names the INT that Sanitize adds for ENUM64s.
const enum64Placeholder = "enum64_placeholder"

// Sanitize returns a copy of the BTF blob for a kernel that lacks some of
// the features in k. In the copy:
//
//   - without DeclTag, every DECL_TAG is an INT of one byte with the
//     encoding word BTF_INT_ENC(0, 0, 8), without kind flag, that keeps the
//     tag's name;
//   - without TypeTag, every TYPE_TAG is an unnamed CONST of the same type;
//   - without Float, every FLOAT is an unnamed STRUCT of the same size and
//     without members;
//   - without Enum64, no ENUM has the kind flag, and every ENUM64 is a
//     UNION of the same size whose members keep the value names, each at
//     offset 0 with the type enum64_placeholder: a one-byte INT with
//     encoding word 8 that the copy adds once, after the last type;
//   - without QmarkDatasec, a DATASEC name that starts with '?' starts
//     with '_' instead. The byte changes in the string table, so every name
//     at the same offset changes with it; other names do not.
//
// The records keep their lengths, so every type keeps its ID. Without the
// placeholder, the copy has the blob's layout and length. With it, the copy
// is the header, the types, the placeholder and the string table, with the
// header's type and string offsets and lengths updated. The placeholder's
// name is the first equal string of the table, or is appended to it.
//
// The spec is not changed; its types, strings and Raw keep the original
// kinds and names. A blob that needs no change comes back as an equal copy.
// A split spec is an error, and so is a blob that needs the placeholder
// and has header fields set past the string section, such as a layout
// section.
func (s *Spec) Sanitize(k KernelFeatures) ([]byte, error) {
	if s.base != nil || s.raw == nil {
		return nil, fmt.Errorf("btf: cannot sanitize split BTF")
	}

	raw := bytes.Clone(s.raw)
	var placeholderID uint32
	for i := 1; i < len(s.Types); i++ {
		t := &s.Types[i]
		var err error
		switch {
		case !k.DeclTag && t.Kind == KindDeclTag:
			err = s.putRecordWords(raw, t, 4, typeInfo(KindInt, 0), sanitizedIntSize, sanitizedIntEnc)
		case !k.QmarkDatasec && t.Kind == KindDatasec:
			err = s.renameQmarkDatasec(raw, t)
		case !k.Float && t.Kind == KindFloat:
			err = s.putRecordWords(raw, t, 0, 0, typeInfo(KindStruct, 0))
		case !k.TypeTag && t.Kind == KindTypeTag:
			err = s.putRecordWords(raw, t, 0, 0, typeInfo(KindConst, 0))
		case !k.Enum64 && t.Kind == KindEnum:
			err = s.putRecordWords(raw, t, 4, typeInfo(KindEnum, t.Vlen))
		case !k.Enum64 && t.Kind == KindEnum64:
			if placeholderID == 0 {
				placeholderID = uint32(len(s.Types))
			}
			err = s.enum64ToUnion(raw, t, placeholderID)
		}
		if err != nil {
			return nil, err
		}
	}
	if placeholderID == 0 {
		return raw, nil
	}
	return s.appendEnum64Placeholder(raw, placeholderID)
}

// typeInfo returns the info word of a type of kind with vlen and without
// kind flag.
func typeInfo(kind Kind, vlen uint32) uint32 {
	return uint32(kind)<<24 | vlen&0xffff
}

// renameQmarkDatasec replaces a '?' that starts the name of the DATASEC t
// with '_' in raw's string table.
func (s *Spec) renameQmarkDatasec(raw []byte, t *Type) error {
	pos := int(s.Header.HdrLen) + int(s.Header.StrOff) + int(t.NameOff)
	if t.NameOff >= s.Header.StrLen || pos >= len(raw) {
		return fmt.Errorf("btf: type %d: name offset %d out of bounds", t.ID, t.NameOff)
	}
	if raw[pos] == '?' {
		raw[pos] = '_'
	}
	return nil
}

// enum64ToUnion rewrites the ENUM64 t in raw as a UNION of the same size
// and vlen. An ENUM64 value and a member both take three words: the name
// stays, and the value's low and high words become the member's type,
// placeholderID, and its bit offset, 0.
func (s *Spec) enum64ToUnion(raw []byte, t *Type, placeholderID uint32) error {
	if err := s.putRecordWords(raw, t, 4, typeInfo(KindUnion, t.Vlen)); err != nil {
		return err
	}
	for j := range t.Enum64s {
		if err := s.putRecordWords(raw, t, 12+12*j+4, placeholderID, 0); err != nil {
			return err
		}
	}
	return nil
}

// appendEnum64Placeholder returns raw, the sanitized copy of the blob,
// rebuilt with the enum64_placeholder INT as type id after the last type:
// the header, the types, the INT and the string table, which gains the
// name unless it already holds it.
func (s *Spec) appendEnum64Placeholder(raw []byte, id uint32) ([]byte, error) {
	order, ok := s.ByteOrder.(binary.AppendByteOrder)
	if !ok {
		return nil, fmt.Errorf("btf: byte order %v cannot encode", s.ByteOrder)
	}
	if err := validateTypeID(id); err != nil {
		return nil, err
	}
	h := s.Header
	if slices.ContainsFunc(raw[minHdrLen:h.HdrLen], func(b byte) bool { return b != 0 }) {
		return nil, fmt.Errorf("btf: cannot add %s to BTF with header data past the string section", enum64Placeholder)
	}

	strStart := int(h.HdrLen) + int(h.StrOff)
	strs := raw[strStart : strStart+int(h.StrLen)]
	nameOff, found := findString(strs, enum64Placeholder)
	if !found {
		nameOff = uint32(len(strs))
	}
	placeholder := Type{
		NameOff:    nameOff,
		Kind:       KindInt,
		SizeOrType: sanitizedIntSize,
		Int:        &Int{Encoding: sanitizedIntEnc},
	}

	out := make([]byte, 0, len(raw)+16+len(enum64Placeholder)+1)
	out = append(out, raw[:h.HdrLen]...)
	out = append(out, raw[s.typeStart:s.typeStart+int(h.TypeLen)]...)
	out = AppendType(out, &placeholder, order)
	typeLen := uint32(len(out)) - h.HdrLen
	out = append(out, strs...)
	if !found {
		out = append(append(out, enum64Placeholder...), 0)
	}

	s.ByteOrder.PutUint32(out[8:], 0)
	s.ByteOrder.PutUint32(out[12:], typeLen)
	s.ByteOrder.PutUint32(out[16:], typeLen)
	s.ByteOrder.PutUint32(out[20:], uint32(len(out))-h.HdrLen-typeLen)
	return out, nil
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
