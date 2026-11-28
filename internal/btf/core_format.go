// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/relo_core.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_core_format_spec, core_relo_kind_str, __btf_kind_str, btf_kind_str

package btf

import (
	"fmt"
	"strings"
)

// BTF kinds after BTF_KIND_ENUM64. The parser does not read them, but their
// names are part of the kind names a log message prints.
const (
	kindLocParam Kind = 20
	kindLocProto Kind = 21
	kindLocsec   Kind = 22
)

// FormatCoreSpec returns the text that CO-RE log messages print for spec, a
// local access spec resolved against s:
//
//	<kind> [<root type id>] <btf kind> <root type name>
//
// with "<anon>" for an unnamed root type. A field-based spec adds its named
// accessors as ".name" and its array indexes as "[idx]", the first index only
// when it is not zero, then the raw access string and the byte offset, with
// the bit within the byte when the field does not start on a byte:
//
//	<byte_off> [11] struct core_sample.second (0:1 @ offset 4)
//
// An enum value spec adds "::<name> = <value>", signed for a signed enum. A
// type-based spec has only the first part. The error is set when spec names
// a type or enumerator s does not have.
func (s *Spec) FormatCoreSpec(spec *CoreSpec) (string, error) {
	root, err := s.TypeByID(spec.RootTypeID)
	if err != nil {
		return "", err
	}
	name := root.Name
	if name == "" {
		name = "<anon>"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "<%s> [%d] %s %s", coreReloKindLogString(spec.Kind), spec.RootTypeID, btfKindString(root.Kind), name)

	switch {
	case spec.Kind.typeBased():
	case spec.Kind.enumvalBased():
		if err := s.formatCoreEnumval(&b, spec); err != nil {
			return "", err
		}
	case spec.Kind.fieldBased():
		formatCoreField(&b, spec)
	}
	return b.String(), nil
}

// formatCoreEnumval appends the enumerator of an enum value spec and its
// value. The root type, past modifiers and typedefs, is an enum or an enum64;
// its kind flag makes the value signed.
func (s *Spec) formatCoreEnumval(b *strings.Builder, spec *CoreSpec) error {
	t, _, err := s.skipModsTypedefs(spec.RootTypeID)
	if err != nil {
		return err
	}
	if len(spec.Raw) == 0 {
		return fmt.Errorf("btf: enum value spec without an index")
	}
	idx := spec.Raw[0]

	if t.Kind == KindEnum {
		if idx >= uint32(len(t.Enums)) {
			return fmt.Errorf("btf: enum index %d out of range", idx)
		}
		e := t.Enums[idx]
		if t.KindFlag {
			fmt.Fprintf(b, "::%s = %d", e.Name, e.Value)
		} else {
			fmt.Fprintf(b, "::%s = %d", e.Name, uint32(e.Value))
		}
		return nil
	}

	if idx >= uint32(len(t.Enum64s)) {
		return fmt.Errorf("btf: enum64 index %d out of range", idx)
	}
	e := t.Enum64s[idx]
	if t.KindFlag {
		fmt.Fprintf(b, "::%s = %d", e.Name, int64(e.Value))
	} else {
		fmt.Fprintf(b, "::%s = %d", e.Name, e.Value)
	}
	return nil
}

// formatCoreField appends the accessors, raw access string and offset of a
// field-based spec.
func formatCoreField(b *strings.Builder, spec *CoreSpec) {
	for i, acc := range spec.Accessors {
		if acc.Name != "" {
			fmt.Fprintf(b, ".%s", acc.Name)
		} else if i > 0 || acc.Index > 0 {
			fmt.Fprintf(b, "[%d]", acc.Index)
		}
	}

	b.WriteString(" (")
	for i, raw := range spec.Raw {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(b, "%d", int32(raw))
	}

	if spec.BitOffset%8 != 0 {
		fmt.Fprintf(b, " @ offset %d.%d)", spec.BitOffset/8, spec.BitOffset%8)
	} else {
		fmt.Fprintf(b, " @ offset %d)", spec.BitOffset/8)
	}
}

// coreReloKindLogString returns the short name CO-RE log messages use for k,
// or "unknown". CoreReloKind.String returns longer names.
func coreReloKindLogString(k CoreReloKind) string {
	switch k {
	case CoreFieldByteOffset:
		return "byte_off"
	case CoreFieldByteSize:
		return "byte_sz"
	case CoreFieldExists:
		return "field_exists"
	case CoreFieldSigned:
		return "signed"
	case CoreFieldLShiftU64:
		return "lshift_u64"
	case CoreFieldRShiftU64:
		return "rshift_u64"
	case CoreTypeIDLocal:
		return "local_type_id"
	case CoreTypeIDTarget:
		return "target_type_id"
	case CoreTypeExists:
		return "type_exists"
	case CoreTypeMatches:
		return "type_matches"
	case CoreTypeSize:
		return "type_size"
	case CoreEnumvalExists:
		return "enumval_exists"
	case CoreEnumvalValue:
		return "enumval_value"
	default:
		return "unknown"
	}
}

// btfKindString returns the name log messages use for BTF kind k, or
// "unknown". Kind.String names an unknown kind by its number instead.
func btfKindString(k Kind) string {
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
	case kindLocParam:
		return "loc_param"
	case kindLocProto:
		return "loc_proto"
	case kindLocsec:
		return "locsec"
	default:
		return "unknown"
	}
}
