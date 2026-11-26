// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

package btf

import "fmt"

// Kind is a BTF type kind.
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

// Int is the BTF_KIND_INT payload.
type Int struct {
	Encoding uint32
}

// Array is the BTF_KIND_ARRAY payload.
type Array struct {
	Type      uint32
	IndexType uint32
	Nelems    uint32
}

// Member is one struct or union member.
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

// Var is the BTF_KIND_VAR payload.
type Var struct {
	Linkage uint32
}

// VarSecInfo is one variable inside a data section.
type VarSecInfo struct {
	Type   uint32
	Offset uint32
	Size   uint32
}

// DeclTag is the BTF_KIND_DECL_TAG payload.
type DeclTag struct {
	ComponentIdx int32
}

// Type is one BTF type. SizeOrType is the size for INT, STRUCT, UNION, ENUM,
// DATASEC, FLOAT and ENUM64, and the referenced type ID for the other kinds.
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
}
