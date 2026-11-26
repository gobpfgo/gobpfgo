// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/relo_core.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_core_parse_spec, bpf_core_spec, bpf_core_accessor

package btf

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// CoreReloKind is enum bpf_core_relo_kind.
type CoreReloKind uint32

const (
	CoreFieldByteOffset CoreReloKind = 0
	CoreFieldByteSize   CoreReloKind = 1
	CoreFieldExists     CoreReloKind = 2
	CoreFieldSigned     CoreReloKind = 3
	CoreFieldLShiftU64  CoreReloKind = 4
	CoreFieldRShiftU64  CoreReloKind = 5
	CoreTypeIDLocal     CoreReloKind = 6
	CoreTypeIDTarget    CoreReloKind = 7
	CoreTypeExists      CoreReloKind = 8
	CoreTypeSize        CoreReloKind = 9
	CoreEnumvalExists   CoreReloKind = 10
	CoreEnumvalValue    CoreReloKind = 11
	CoreTypeMatches     CoreReloKind = 12
)

func (k CoreReloKind) String() string {
	switch k {
	case CoreFieldByteOffset:
		return "field_byte_offset"
	case CoreFieldByteSize:
		return "field_byte_size"
	case CoreFieldExists:
		return "field_exists"
	case CoreFieldSigned:
		return "field_signed"
	case CoreFieldLShiftU64:
		return "field_lshift_u64"
	case CoreFieldRShiftU64:
		return "field_rshift_u64"
	case CoreTypeIDLocal:
		return "type_id_local"
	case CoreTypeIDTarget:
		return "type_id_target"
	case CoreTypeExists:
		return "type_exists"
	case CoreTypeSize:
		return "type_size"
	case CoreEnumvalExists:
		return "enumval_exists"
	case CoreEnumvalValue:
		return "enumval_value"
	case CoreTypeMatches:
		return "type_matches"
	default:
		return fmt.Sprintf("kind(%d)", uint32(k))
	}
}

func (k CoreReloKind) fieldBased() bool {
	return k >= CoreFieldByteOffset && k <= CoreFieldRShiftU64
}

func (k CoreReloKind) typeBased() bool {
	return k >= CoreTypeIDLocal && k <= CoreTypeSize
}

func (k CoreReloKind) enumvalBased() bool {
	return k == CoreEnumvalExists || k == CoreEnumvalValue
}

// CoreAccessor is one bpf_core_accessor: a named field or an array index.
type CoreAccessor struct {
	TypeID uint32
	Index  uint32
	Name   string
}

// CoreSpec is the resolved local access spec of a CO-RE relocation. It is
// the Go view of bpf_core_spec without the target BTF fields.
type CoreSpec struct {
	RootTypeID uint32
	Kind       CoreReloKind
	Raw        []uint32
	Accessors  []CoreAccessor
	BitOffset  uint32
}

// ParseCoreSpec resolves the access string of relo against the local BTF.
//
// It handles the field-based, type-based and enum-value kinds. Target type
// matching, flexible array members and instruction patching come later.
func (s *Spec) ParseCoreSpec(relo CoreRelo) (*CoreSpec, error) {
	access, err := s.String(relo.AccessStrOff)
	if err != nil {
		return nil, fmt.Errorf("btf: core access string: %w", err)
	}
	if access == "" || strings.HasPrefix(access, ":") {
		return nil, fmt.Errorf("btf: core access string is empty")
	}

	spec := &CoreSpec{
		RootTypeID: relo.TypeID,
		Kind:       relo.Kind,
	}

	if relo.Kind.typeBased() {
		if access != "0" {
			return nil, fmt.Errorf("btf: type-based relocation access string %q", access)
		}
		return spec, nil
	}

	raw, err := parseCoreAccess(access)
	if err != nil {
		return nil, err
	}
	spec.Raw = raw

	t, id, err := s.skipModsTypedefs(relo.TypeID)
	if err != nil {
		return nil, err
	}

	if relo.Kind.enumvalBased() {
		if len(raw) != 1 {
			return nil, fmt.Errorf("btf: enum relocation access string %q", access)
		}
		acc := CoreAccessor{TypeID: id, Index: raw[0]}
		switch t.Kind {
		case KindEnum:
			if raw[0] >= uint32(len(t.Enums)) {
				return nil, fmt.Errorf("btf: enum index %d out of range", raw[0])
			}
			acc.Name = t.Enums[raw[0]].Name
		case KindEnum64:
			if raw[0] >= uint32(len(t.Enum64s)) {
				return nil, fmt.Errorf("btf: enum64 index %d out of range", raw[0])
			}
			acc.Name = t.Enum64s[raw[0]].Name
		default:
			return nil, fmt.Errorf("btf: enum relocation on kind %s", t.Kind)
		}
		spec.Accessors = []CoreAccessor{acc}
		return spec, nil
	}

	if !relo.Kind.fieldBased() {
		return nil, fmt.Errorf("btf: unsupported core relocation kind %s", relo.Kind)
	}

	size, err := s.SizeOf(id)
	if err != nil {
		return nil, err
	}
	spec.Accessors = append(spec.Accessors, CoreAccessor{TypeID: id, Index: raw[0]})
	spec.BitOffset, err = addBitOffset(0, raw[0], size)
	if err != nil {
		return nil, err
	}

	for i := 1; i < len(raw); i++ {
		t, id, err = s.skipModsTypedefs(id)
		if err != nil {
			return nil, err
		}

		switch t.Kind {
		case KindStruct, KindUnion:
			if raw[i] >= uint32(len(t.Members)) {
				return nil, fmt.Errorf("btf: struct index %d out of range", raw[i])
			}
			m := t.Members[raw[i]]
			if uint64(spec.BitOffset)+uint64(m.Offset) > math.MaxUint32 {
				return nil, fmt.Errorf("btf: bit offset overflows")
			}
			spec.BitOffset += m.Offset
			if m.Name != "" {
				spec.Accessors = append(spec.Accessors, CoreAccessor{
					TypeID: id,
					Index:  raw[i],
					Name:   m.Name,
				})
			}
			id = m.Type

		case KindArray:
			if t.Array == nil {
				return nil, fmt.Errorf("btf: type %d has no array payload", id)
			}
			if t.Array.Nelems == 0 {
				return nil, fmt.Errorf("btf: flexible array access is not supported")
			}
			if raw[i] >= t.Array.Nelems {
				return nil, fmt.Errorf("btf: array index %d out of range", raw[i])
			}
			_, elemID, err := s.skipModsTypedefs(t.Array.Type)
			if err != nil {
				return nil, err
			}
			size, err := s.SizeOf(elemID)
			if err != nil {
				return nil, err
			}
			spec.BitOffset, err = addBitOffset(spec.BitOffset, raw[i], size)
			if err != nil {
				return nil, err
			}
			spec.Accessors = append(spec.Accessors, CoreAccessor{
				TypeID: elemID,
				Index:  raw[i],
			})
			id = elemID

		default:
			return nil, fmt.Errorf("btf: core access on kind %s", t.Kind)
		}
	}

	return spec, nil
}

// skipModsTypedefs follows typedefs and type modifiers to the underlying
// type, the same rule libbpf applies before resolving an access.
func (s *Spec) skipModsTypedefs(id uint32) (*Type, uint32, error) {
	for {
		t, err := s.TypeByID(id)
		if err != nil {
			return nil, 0, err
		}
		switch t.Kind {
		case KindTypedef, KindVolatile, KindConst, KindRestrict, KindTypeTag:
			id = t.SizeOrType
		default:
			return t, id, nil
		}
	}
}

// parseCoreAccess parses an access string such as "0:1:2" into its indices.
func parseCoreAccess(access string) ([]uint32, error) {
	parts := strings.Split(access, ":")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, fmt.Errorf("btf: core access string %q is too long", access)
	}

	raw := make([]uint32, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("btf: core access string %q has an empty index", access)
		}
		idx, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("btf: core access string %q: %w", access, err)
		}
		raw = append(raw, uint32(idx))
	}
	return raw, nil
}

// addBitOffset adds idx elements of size bytes to offset and rejects a result
// that does not fit the 32-bit bit offset.
func addBitOffset(offset, idx, size uint32) (uint32, error) {
	total := uint64(offset) + uint64(idx)*uint64(size)*8
	if total > math.MaxUint32 {
		return 0, fmt.Errorf("btf: bit offset overflows")
	}
	return uint32(total), nil
}
