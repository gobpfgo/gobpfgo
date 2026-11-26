// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/btf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: enum btf_kind, struct btf_type, struct btf_member, struct btf_array, struct btf_enum, struct btf_param, struct btf_var, struct btf_var_secinfo, struct btf_decl_tag, struct btf_enum64

package btf

import "fmt"

// Kind is a BTF type kind from enum btf_kind.
type Kind uint8

const (
	KindVoid      Kind = 0
	KindInt       Kind = 1
	KindPtr       Kind = 2
	KindArray     Kind = 3
	KindStruct    Kind = 4
	KindUnion     Kind = 5
	KindEnum      Kind = 6
	KindFwd       Kind = 7
	KindTypedef   Kind = 8
	KindVolatile  Kind = 9
	KindConst     Kind = 10
	KindRestrict  Kind = 11
	KindFunc      Kind = 12
	KindFuncProto Kind = 13
	KindVar       Kind = 14
	KindDatasec   Kind = 15
	KindFloat     Kind = 16
	KindDeclTag   Kind = 17
	KindTypeTag   Kind = 18
	KindEnum64    Kind = 19
)

func (k Kind) String() string {
	switch k {
	case KindVoid:
		return "void"
	case KindInt:
		return "int"
	case KindPtr:
		return "ptr"
	case KindArray:
		return "array"
	case KindStruct:
		return "struct"
	case KindUnion:
		return "union"
	case KindEnum:
		return "enum"
	case KindFwd:
		return "fwd"
	case KindTypedef:
		return "typedef"
	case KindVolatile:
		return "volatile"
	case KindConst:
		return "const"
	case KindRestrict:
		return "restrict"
	case KindFunc:
		return "func"
	case KindFuncProto:
		return "func_proto"
	case KindVar:
		return "var"
	case KindDatasec:
		return "datasec"
	case KindFloat:
		return "float"
	case KindDeclTag:
		return "decl_tag"
	case KindTypeTag:
		return "type_tag"
	case KindEnum64:
		return "enum64"
	default:
		return fmt.Sprintf("kind(%d)", uint8(k))
	}
}

// Int is the BTF_KIND_INT payload. Encoding packs the signedness, bit offset
// and bit width in one word.
type Int struct {
	Encoding uint32
}

// Array is the BTF_KIND_ARRAY payload. Type is the element type, IndexType is
// the index type and Nelems is the number of elements.
type Array struct {
	Type      uint32
	IndexType uint32
	Nelems    uint32
}

// Member is one struct or union member. Offset is in bits; BitfieldSize is
// non-zero for a bitfield.
type Member struct {
	NameOff      uint32
	Name         string
	Type         uint32
	Offset       uint32
	BitfieldSize uint8
}

// Enum is one BTF_KIND_ENUM value.
type Enum struct {
	NameOff uint32
	Name    string
	Value   int32
}

// Enum64 is one BTF_KIND_ENUM64 value.
type Enum64 struct {
	NameOff uint32
	Name    string
	Value   uint64
}

// Param is one function prototype parameter.
type Param struct {
	NameOff uint32
	Name    string
	Type    uint32
}

// Var is the BTF_KIND_VAR payload. Linkage is one of the BTF_VAR_* values.
type Var struct {
	Linkage uint32
}

// VarSecInfo is one variable inside a data section. Offset and Size are
// relative to the section.
type VarSecInfo struct {
	Type   uint32
	Offset uint32
	Size   uint32
}

// DeclTag is the BTF_KIND_DECL_TAG payload.
type DeclTag struct {
	ComponentIdx int32
}

// Type is one BTF type. SizeOrType is the size for sized kinds and the
// referenced type ID for the other kinds; the kind-specific payload is in the
// corresponding field. Fields that do not apply to the kind are zero.
type Type struct {
	ID         uint32
	NameOff    uint32
	Name       string
	Info       uint32
	Kind       Kind
	KindFlag   bool
	Vlen       uint32
	SizeOrType uint32

	Int     *Int
	Array   *Array
	Members []Member
	Enums   []Enum
	Enum64s []Enum64
	Params  []Param
	Var     *Var
	DataSec []VarSecInfo
	DeclTag *DeclTag

	rawOff uint32
}
