// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original BTF type encoder
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_type_size, btf_field_iter_init, btf_field_iter_next

package btf

import "encoding/binary"

// AppendType appends the wire encoding of t to b, the inverse of Parse for
// one type record. The info word is rebuilt from Kind, KindFlag and the
// payload: the vlen of a struct, union, enum, enum64, function prototype or
// data section is the length of its slice, and Vlen is used for the other
// kinds. Name offsets are written as stored in the NameOff fields.
func AppendType(b []byte, t *Type, order binary.AppendByteOrder) []byte {
	info := uint32(t.Kind)<<24 | vlenOf(t)&0xffff
	if t.KindFlag {
		info |= 1 << 31
	}
	b = order.AppendUint32(b, t.NameOff)
	b = order.AppendUint32(b, info)
	b = order.AppendUint32(b, t.SizeOrType)

	switch t.Kind {
	case KindInt:
		var enc uint32
		if t.Int != nil {
			enc = t.Int.Encoding
		}
		b = order.AppendUint32(b, enc)
	case KindArray:
		var a Array
		if t.Array != nil {
			a = *t.Array
		}
		b = order.AppendUint32(b, a.Type)
		b = order.AppendUint32(b, a.IndexType)
		b = order.AppendUint32(b, a.Nelems)
	case KindStruct, KindUnion:
		b = appendMembers(b, t, order)
	case KindEnum:
		for _, e := range t.Enums {
			b = order.AppendUint32(b, e.NameOff)
			b = order.AppendUint32(b, uint32(e.Value))
		}
	case KindEnum64:
		for _, e := range t.Enum64s {
			b = order.AppendUint32(b, e.NameOff)
			b = order.AppendUint32(b, uint32(e.Value))
			b = order.AppendUint32(b, uint32(e.Value>>32))
		}
	case KindFuncProto:
		for _, p := range t.Params {
			b = order.AppendUint32(b, p.NameOff)
			b = order.AppendUint32(b, p.Type)
		}
	case KindVar:
		var linkage uint32
		if t.Var != nil {
			linkage = t.Var.Linkage
		}
		b = order.AppendUint32(b, linkage)
	case KindDatasec:
		for _, v := range t.DataSec {
			b = order.AppendUint32(b, v.Type)
			b = order.AppendUint32(b, v.Offset)
			b = order.AppendUint32(b, v.Size)
		}
	case KindDeclTag:
		var idx int32
		if t.DeclTag != nil {
			idx = t.DeclTag.ComponentIdx
		}
		b = order.AppendUint32(b, uint32(idx))
	}
	return b
}

// appendMembers encodes struct and union members. With the kind flag set, the
// offset word carries the bitfield size in its top byte.
func appendMembers(b []byte, t *Type, order binary.AppendByteOrder) []byte {
	for _, m := range t.Members {
		offset := m.Offset
		if t.KindFlag {
			offset = uint32(m.BitfieldSize)<<24 | m.Offset&0xffffff
		}
		b = order.AppendUint32(b, m.NameOff)
		b = order.AppendUint32(b, m.Type)
		b = order.AppendUint32(b, offset)
	}
	return b
}

func vlenOf(t *Type) uint32 {
	switch t.Kind {
	case KindStruct, KindUnion:
		return uint32(len(t.Members))
	case KindEnum:
		return uint32(len(t.Enums))
	case KindEnum64:
		return uint32(len(t.Enum64s))
	case KindFuncProto:
		return uint32(len(t.Params))
	case KindDatasec:
		return uint32(len(t.DataSec))
	}
	return t.Vlen
}

// VisitTypeIDs calls fn with a pointer to every type ID field of t, in wire
// order: the referenced type of pointers, modifiers, typedefs, functions,
// variables and tags, the element and index types of an array, member types,
// the return and parameter types of a function prototype, and the variables
// of a data section. fn may rewrite the ID; the first error stops the walk.
func (t *Type) VisitTypeIDs(fn func(id *uint32) error) error {
	switch t.Kind {
	case KindPtr, KindTypedef, KindVolatile, KindConst, KindRestrict,
		KindFunc, KindVar, KindTypeTag, KindDeclTag:
		return fn(&t.SizeOrType)
	case KindArray:
		if t.Array == nil {
			return nil
		}
		if err := fn(&t.Array.Type); err != nil {
			return err
		}
		return fn(&t.Array.IndexType)
	case KindStruct, KindUnion:
		for i := range t.Members {
			if err := fn(&t.Members[i].Type); err != nil {
				return err
			}
		}
	case KindFuncProto:
		if err := fn(&t.SizeOrType); err != nil {
			return err
		}
		for i := range t.Params {
			if err := fn(&t.Params[i].Type); err != nil {
				return err
			}
		}
	case KindDatasec:
		for i := range t.DataSec {
			if err := fn(&t.DataSec[i].Type); err != nil {
				return err
			}
		}
	}
	return nil
}

// Clone returns a deep copy of t, so the copy's payload can be changed
// without touching t.
func (t *Type) Clone() Type {
	c := *t
	c.Members = append([]Member(nil), t.Members...)
	c.Enums = append([]Enum(nil), t.Enums...)
	c.Enum64s = append([]Enum64(nil), t.Enum64s...)
	c.Params = append([]Param(nil), t.Params...)
	c.DataSec = append([]VarSecInfo(nil), t.DataSec...)
	if t.Int != nil {
		v := *t.Int
		c.Int = &v
	}
	if t.Array != nil {
		v := *t.Array
		c.Array = &v
	}
	if t.Var != nil {
		v := *t.Var
		c.Var = &v
	}
	if t.DeclTag != nil {
		v := *t.DeclTag
		c.DeclTag = &v
	}
	return c
}
