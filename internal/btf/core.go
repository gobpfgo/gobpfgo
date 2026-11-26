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
			flex := isFlexArray(s, spec.Accessors, t.Array)
			if !flex && raw[i] >= t.Array.Nelems {
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

// CoreReloResult is the computed local and target values of a CO-RE
// relocation. It is the Go view of bpf_core_relo_res.
type CoreReloResult struct {
	OrigVal           uint64
	NewVal            uint64
	OrigSize          uint32
	NewSize           uint32
	OrigTypeID        uint32
	NewTypeID         uint32
	Validate          bool
	Poison            bool
	FailMemSizeAdjust bool

	// Matched is false when the target type or field did not match.
	Matched bool
}

// CalcCoreRelo matches relo against targetTypeID and computes the local and
// target relocation values.
//
// It supports the field-based kinds. A field missing from the target yields
// NewVal zero for FIELD_EXISTS and a poisoned result for every other kind.
// Type-based and enum-value target matching are not implemented yet.
func (s *Spec) CalcCoreRelo(relo CoreRelo, target *Spec, targetTypeID uint32) (*CoreReloResult, error) {
	if relo.Kind == CoreTypeIDLocal {
		return &CoreReloResult{
			OrigVal: uint64(relo.TypeID),
			NewVal:  uint64(relo.TypeID),
			Matched: true,
		}, nil
	}
	if target == nil {
		return nil, fmt.Errorf("btf: nil target spec")
	}
	if relo.Kind.typeBased() {
		return s.calcTypeRelo(relo, target, targetTypeID)
	}
	if relo.Kind.enumvalBased() {
		return s.calcEnumRelo(relo, target, targetTypeID)
	}
	if !relo.Kind.fieldBased() {
		return nil, fmt.Errorf("btf: target matching for %s is not implemented", relo.Kind)
	}

	local, err := s.ParseCoreSpec(relo)
	if err != nil {
		return nil, err
	}
	targ, found, err := s.matchCoreSpec(local, target, targetTypeID)
	if err != nil {
		return nil, err
	}

	res := &CoreReloResult{}
	if !found {
		if relo.Kind == CoreFieldExists {
			res.OrigVal = 1
			res.Validate = true
			return res, nil
		}
		res.Poison = true
		return res, nil
	}
	res.Matched = true

	origVal, origSize, origType, validate, err := local.calcField(s, relo.Kind)
	if err != nil {
		return nil, err
	}
	newVal, newSize, newType, _, err := targ.calcField(target, relo.Kind)
	if err != nil {
		return nil, err
	}

	res.OrigVal = origVal
	res.NewVal = newVal
	res.OrigSize = origSize
	res.NewSize = newSize
	res.OrigTypeID = origType
	res.NewTypeID = newType
	res.Validate = validate

	if origSize != newSize {
		origBtfType, err := s.TypeByID(origType)
		if err != nil {
			return nil, err
		}
		newBtfType, err := target.TypeByID(newType)
		if err != nil {
			return nil, err
		}
		safe := origBtfType.Kind == KindPtr && newBtfType.Kind == KindPtr
		if origBtfType.Kind == KindInt && newBtfType.Kind == KindInt {
			safe = intEncoding(origBtfType)&(1<<24) == 0 && intEncoding(newBtfType)&(1<<24) == 0
		}
		res.FailMemSizeAdjust = !safe
	}

	return res, nil
}

// calcTypeRelo computes a type-based relocation against the target type.
func (s *Spec) calcTypeRelo(relo CoreRelo, target *Spec, targetTypeID uint32) (*CoreReloResult, error) {
	compatible := coreTypesCompatible(s, relo.TypeID, target, targetTypeID)
	res := &CoreReloResult{Validate: true, Matched: compatible}

	switch relo.Kind {
	case CoreTypeIDTarget:
		res.OrigVal = uint64(relo.TypeID)
		res.Validate = false
		if compatible {
			res.NewVal = uint64(targetTypeID)
		}
	case CoreTypeExists:
		res.OrigVal = 1
		if compatible {
			res.NewVal = 1
		}
	case CoreTypeSize:
		size, err := s.SizeOf(relo.TypeID)
		if err != nil {
			return nil, err
		}
		res.OrigVal = uint64(size)
		if compatible {
			size, err := target.SizeOf(targetTypeID)
			if err != nil {
				return nil, err
			}
			res.NewVal = uint64(size)
		}
	default:
		return nil, fmt.Errorf("btf: unsupported type relocation %s", relo.Kind)
	}

	return res, nil
}

// calcEnumRelo computes an enum-value relocation against the target enum.
func (s *Spec) calcEnumRelo(relo CoreRelo, target *Spec, targetTypeID uint32) (*CoreReloResult, error) {
	local, err := s.ParseCoreSpec(relo)
	if err != nil {
		return nil, err
	}
	if len(local.Accessors) != 1 {
		return nil, fmt.Errorf("btf: enum relocation has %d accessors", len(local.Accessors))
	}
	localEnum, err := s.TypeByID(local.Accessors[0].TypeID)
	if err != nil {
		return nil, err
	}
	localValue, err := enumValue(localEnum, local.Accessors[0].Index)
	if err != nil {
		return nil, err
	}

	targetEnum, err := target.TypeByID(targetTypeID)
	if err != nil {
		return nil, err
	}
	_, targetValue, found, err := findEnumValue(targetEnum, local.Accessors[0].Name)
	if err != nil {
		return nil, err
	}

	res := &CoreReloResult{Validate: true, Matched: found}
	switch relo.Kind {
	case CoreEnumvalExists:
		res.OrigVal = 1
		if found {
			res.NewVal = 1
		}
	case CoreEnumvalValue:
		res.OrigVal = localValue
		if !found {
			res.Poison = true
		} else {
			res.NewVal = targetValue
		}
	default:
		return nil, fmt.Errorf("btf: unsupported enum relocation %s", relo.Kind)
	}

	return res, nil
}

// coreTypesCompatible applies the field compatibility rules to a root type.
func coreTypesCompatible(local *Spec, localID uint32, target *Spec, targetID uint32) bool {
	return coreFieldsCompatible(local, localID, target, targetID)
}

// enumValue returns the value of the enum member at index.
func enumValue(t *Type, index uint32) (uint64, error) {
	switch t.Kind {
	case KindEnum:
		if index >= uint32(len(t.Enums)) {
			return 0, fmt.Errorf("btf: enum index %d out of range", index)
		}
		return uint64(int64(t.Enums[index].Value)), nil
	case KindEnum64:
		if index >= uint32(len(t.Enum64s)) {
			return 0, fmt.Errorf("btf: enum64 index %d out of range", index)
		}
		return t.Enum64s[index].Value, nil
	default:
		return 0, fmt.Errorf("btf: type %s is not an enum", t.Kind)
	}
}

// findEnumValue finds the enumerator by name and returns its index and value.
func findEnumValue(t *Type, name string) (uint32, uint64, bool, error) {
	essential := essentialName(name)

	switch t.Kind {
	case KindEnum:
		for i := range t.Enums {
			if essentialName(t.Enums[i].Name) == essential {
				return uint32(i), uint64(int64(t.Enums[i].Value)), true, nil
			}
		}
	case KindEnum64:
		for i := range t.Enum64s {
			if essentialName(t.Enum64s[i].Name) == essential {
				return uint32(i), t.Enum64s[i].Value, true, nil
			}
		}
	default:
		return 0, 0, false, fmt.Errorf("btf: type %s is not an enum", t.Kind)
	}

	return 0, 0, false, nil
}

// matchCoreSpec walks the target type with the field and array accessors of
// the local spec. It returns found false when a field is absent.
func (s *Spec) matchCoreSpec(local *CoreSpec, target *Spec, targetTypeID uint32) (*CoreSpec, bool, error) {
	targ := &CoreSpec{
		RootTypeID: targetTypeID,
		Kind:       local.Kind,
	}
	targID := targetTypeID

	for i, acc := range local.Accessors {
		t, id, err := target.skipModsTypedefs(targID)
		if err != nil {
			return nil, false, err
		}
		targID = id

		if acc.Name != "" {
			found, nextID, err := s.matchMember(&acc, target, t, targID, targ)
			if err != nil {
				return nil, false, err
			}
			if !found {
				return nil, false, nil
			}
			targID = nextID
			continue
		}

		if i == 0 {
			size, err := target.SizeOf(targID)
			if err != nil {
				return nil, false, err
			}
			targ.BitOffset, err = addBitOffset(targ.BitOffset, acc.Index, size)
			if err != nil {
				return nil, false, err
			}
			targ.Accessors = append(targ.Accessors, CoreAccessor{TypeID: targID, Index: acc.Index})
			continue
		}

		if t.Kind != KindArray || t.Array == nil {
			return nil, false, nil
		}
		flex := isFlexArray(target, targ.Accessors, t.Array)
		if !flex && acc.Index >= t.Array.Nelems {
			return nil, false, nil
		}
		_, elemID, err := target.skipModsTypedefs(t.Array.Type)
		if err != nil {
			return nil, false, err
		}
		size, err := target.SizeOf(elemID)
		if err != nil {
			return nil, false, err
		}
		targ.BitOffset, err = addBitOffset(targ.BitOffset, acc.Index, size)
		if err != nil {
			return nil, false, err
		}
		targ.Accessors = append(targ.Accessors, CoreAccessor{TypeID: elemID, Index: acc.Index})
		targID = elemID
	}

	return targ, true, nil
}

// matchMember finds the named local member in the target composite, including
// anonymous embedded structs and unions. It returns the matched member type
// for the next accessor.
func (s *Spec) matchMember(localAcc *CoreAccessor, target *Spec, targetType *Type, targetID uint32, targ *CoreSpec) (bool, uint32, error) {
	if targetType.Kind != KindStruct && targetType.Kind != KindUnion {
		return false, 0, nil
	}

	localType, err := s.TypeByID(localAcc.TypeID)
	if err != nil {
		return false, 0, err
	}
	if localAcc.Index >= uint32(len(localType.Members)) {
		return false, 0, fmt.Errorf("btf: local field index %d out of range", localAcc.Index)
	}
	localMember := localType.Members[localAcc.Index]

	for i := range targetType.Members {
		member := targetType.Members[i]

		if member.Name == "" {
			savedOffset := targ.BitOffset
			savedAccessors := len(targ.Accessors)
			if uint64(targ.BitOffset)+uint64(member.Offset) > math.MaxUint32 {
				return false, 0, fmt.Errorf("btf: bit offset overflows")
			}
			targ.BitOffset += member.Offset
			memberType := targetMemberType(target, member.Type)
			if memberType == nil {
				return false, 0, fmt.Errorf("btf: anonymous member type %d not found", member.Type)
			}
			found, nextID, err := s.matchMember(localAcc, target, memberType, member.Type, targ)
			if err != nil {
				return false, 0, err
			}
			if found {
				return true, nextID, nil
			}
			targ.BitOffset = savedOffset
			targ.Accessors = targ.Accessors[:savedAccessors]
			continue
		}

		if member.Name != localMember.Name {
			continue
		}
		if !coreFieldsCompatible(s, localMember.Type, target, member.Type) {
			continue
		}

		if uint64(targ.BitOffset)+uint64(member.Offset) > math.MaxUint32 {
			return false, 0, fmt.Errorf("btf: bit offset overflows")
		}
		targ.BitOffset += member.Offset
		targ.Accessors = append(targ.Accessors, CoreAccessor{
			TypeID: targetID,
			Index:  uint32(i),
			Name:   member.Name,
		})
		return true, member.Type, nil
	}

	return false, 0, nil
}

func targetMemberType(spec *Spec, id uint32) *Type {
	t, _, err := spec.skipModsTypedefs(id)
	if err != nil {
		return nil
	}
	return t
}

// calcField implements bpf_core_calc_field_relo for one spec.
func (spec *CoreSpec) calcField(s *Spec, kind CoreReloKind) (uint64, uint32, uint32, bool, error) {
	if kind == CoreFieldExists {
		return 1, 0, 0, false, nil
	}
	if len(spec.Accessors) == 0 {
		return 0, 0, 0, false, fmt.Errorf("btf: empty core access spec")
	}

	acc := spec.Accessors[len(spec.Accessors)-1]
	t, err := s.TypeByID(acc.TypeID)
	if err != nil {
		return 0, 0, 0, false, err
	}

	if acc.Name == "" {
		switch kind {
		case CoreFieldByteOffset:
			val := uint64(spec.BitOffset / 8)
			size, err := s.elementSize(acc.TypeID)
			if err != nil {
				return 0, 0, 0, false, err
			}
			return val, size, acc.TypeID, true, nil
		case CoreFieldByteSize:
			size, err := s.SizeOf(acc.TypeID)
			if err != nil {
				return 0, 0, 0, false, err
			}
			return uint64(size), 0, 0, true, nil
		default:
			return 0, 0, 0, false, fmt.Errorf("btf: %s on an array access", kind)
		}
	}

	if acc.Index >= uint32(len(t.Members)) {
		return 0, 0, 0, false, fmt.Errorf("btf: field index %d out of range", acc.Index)
	}
	member := t.Members[acc.Index]
	memberType, fieldTypeID, err := s.skipModsTypedefs(member.Type)
	if err != nil {
		return 0, 0, 0, false, err
	}

	bitOff := spec.BitOffset
	bitSize := uint32(member.BitfieldSize)
	bitfield := bitSize > 0
	byteSize, err := s.SizeOf(fieldTypeID)
	if err != nil {
		return 0, 0, 0, false, err
	}
	byteOff := bitOff / 8
	if bitfield {
		byteOff = bitOff / 8 / byteSize * byteSize
		for bitOff+bitSize-byteOff*8 > byteSize*8 {
			if byteSize >= 8 {
				return 0, 0, 0, false, fmt.Errorf("btf: bitfield does not fit")
			}
			byteSize *= 2
			byteOff = bitOff / 8 / byteSize * byteSize
		}
	} else {
		bitSize = byteSize * 8
	}

	validate := !bitfield
	switch kind {
	case CoreFieldByteOffset:
		val := uint64(byteOff)
		if bitfield {
			return val, 0, 0, validate, nil
		}
		size, err := s.elementSize(fieldTypeID)
		if err != nil {
			return 0, 0, 0, false, err
		}
		return val, size, fieldTypeID, validate, nil
	case CoreFieldByteSize:
		return uint64(byteSize), 0, 0, validate, nil
	case CoreFieldSigned:
		signed := (memberType.Kind == KindEnum || memberType.Kind == KindEnum64) && memberType.KindFlag ||
			memberType.Kind == KindInt && intEncoding(memberType)&(1<<24) != 0
		return boolUint64(signed), 0, 0, true, nil
	case CoreFieldLShiftU64:
		return uint64(64 - (bitOff + bitSize - byteOff*8)), 0, 0, validate, nil
	case CoreFieldRShiftU64:
		return uint64(64 - bitSize), 0, 0, true, nil
	default:
		return 0, 0, 0, false, fmt.Errorf("btf: unsupported field relocation %s", kind)
	}
}

// elementSize returns the size of the element type after stripping arrays.
func (s *Spec) elementSize(id uint32) (uint32, error) {
	for {
		t, next, err := s.skipModsTypedefs(id)
		if err != nil {
			return 0, err
		}
		if t.Kind != KindArray {
			return s.SizeOf(next)
		}
		if t.Array == nil {
			return 0, fmt.Errorf("btf: type %d has no array payload", next)
		}
		id = t.Array.Type
	}
}

func intEncoding(t *Type) uint32 {
	if t.Int == nil {
		return 0
	}
	return t.Int.Encoding
}

func boolUint64(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

// coreFieldsCompatible mirrors libbpf's field compatibility rules closely
// enough for the field accessor match.
func coreFieldsCompatible(local *Spec, localID uint32, target *Spec, targetID uint32) bool {
	localType, localID, err := local.skipModsTypedefs(localID)
	if err != nil {
		return false
	}
	targetType, targetID, err := target.skipModsTypedefs(targetID)
	if err != nil {
		return false
	}

	if (localType.Kind == KindStruct || localType.Kind == KindUnion) &&
		(targetType.Kind == KindStruct || targetType.Kind == KindUnion) {
		return true
	}
	if isEnumKind(localType.Kind) && isEnumKind(targetType.Kind) {
		localName := essentialName(localType.Name)
		targetName := essentialName(targetType.Name)
		return localName == "" || targetName == "" || localName == targetName
	}
	if localType.Kind != targetType.Kind {
		return false
	}

	switch localType.Kind {
	case KindPtr, KindFloat:
		return true
	case KindFwd, KindEnum, KindEnum64:
		localName := essentialName(localType.Name)
		targetName := essentialName(targetType.Name)
		return localName == "" || targetName == "" || localName == targetName
	case KindInt:
		return intOffset(localType) == 0 && intOffset(targetType) == 0
	case KindArray:
		if localType.Array == nil || targetType.Array == nil {
			return false
		}
		return coreFieldsCompatible(local, localType.Array.Type, target, targetType.Array.Type)
	default:
		return false
	}
}

func intOffset(t *Type) uint32 {
	return (intEncoding(t) >> 16) & 0xff
}

func isEnumKind(k Kind) bool {
	return k == KindEnum || k == KindEnum64
}

// essentialName drops the ___flavor suffix libbpf ignores during matching.
func essentialName(name string) string {
	if i := strings.Index(name, "___"); i >= 0 {
		return name[:i]
	}
	return name
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

// isFlexArray reports whether arr is a flexible array member: zero-length,
// named by the previous accessor, and the last member of its struct or union.
func isFlexArray(s *Spec, accessors []CoreAccessor, arr *Array) bool {
	if arr == nil || arr.Nelems != 0 || len(accessors) == 0 {
		return false
	}
	acc := &accessors[len(accessors)-1]
	if acc.Name == "" {
		return false
	}
	t, err := s.TypeByID(acc.TypeID)
	if err != nil || (t.Kind != KindStruct && t.Kind != KindUnion) {
		return false
	}
	return acc.Index == uint32(len(t.Members))-1
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
