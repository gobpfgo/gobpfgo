// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: hash_combine, btf_hash_typedef, btf_hash_common, btf_equal_common, btf_equal_typedef, btf_hash_int_decl_tag, btf_equal_int_tag, btf_hash_enum, btf_equal_enum_members, btf_equal_enum64_members, btf_equal_enum, btf_is_enum_fwd, btf_compat_enum, btf_hash_struct, btf_shallow_equal_struct, btf_hash_array, btf_equal_array, btf_compat_array, btf_hash_fnproto, btf_equal_fnproto, btf_compat_fnproto, btf_hash_by_kind, btf_equal_by_kind, btf_fwd_kind

package btf

// The signature hashes and equality checks of the dedup passes. A hash
// covers the fields a check compares, except where noted, so equal types
// share a hash; different types may collide, and the checks decide.

func hashCombine(h, value uint64) uint64 {
	return h*31 + value
}

// hashTypedef hashes the name and info of a typedef, not the type it names.
func hashTypedef(t *Type) uint64 {
	h := hashCombine(0, uint64(t.NameOff))
	return hashCombine(h, uint64(infoWord(t)))
}

// hashCommon hashes the name, info and size or referenced type ID.
func hashCommon(t *Type) uint64 {
	h := hashCombine(0, uint64(t.NameOff))
	h = hashCombine(h, uint64(infoWord(t)))
	return hashCombine(h, uint64(t.SizeOrType))
}

func equalCommon(t1, t2 *Type) bool {
	return t1.NameOff == t2.NameOff && infoWord(t1) == infoWord(t2) && t1.SizeOrType == t2.SizeOrType
}

func equalTypedef(t1, t2 *Type) bool {
	return t1.NameOff == t2.NameOff && infoWord(t1) == infoWord(t2)
}

// intDeclTagWord returns the word that follows the common type header of an
// INT or DECL_TAG: the integer encoding or the component index.
func intDeclTagWord(t *Type) uint32 {
	switch {
	case t.Kind == KindInt && t.Int != nil:
		return t.Int.Encoding
	case t.Kind == KindDeclTag && t.DeclTag != nil:
		return uint32(t.DeclTag.ComponentIdx)
	}
	return 0
}

func hashIntDeclTag(t *Type) uint64 {
	return hashCombine(hashCommon(t), uint64(intDeclTagWord(t)))
}

func equalIntTag(t1, t2 *Type) bool {
	return equalCommon(t1, t2) && intDeclTagWord(t1) == intDeclTagWord(t2)
}

// hashEnum hashes only the name of an ENUM or ENUM64, so a forward
// declaration shares the hash of the full enum.
func hashEnum(t *Type) uint64 {
	return hashCombine(0, uint64(t.NameOff))
}

// equalEnum compares two ENUMs or two ENUM64s, including their values.
func equalEnum(t1, t2 *Type) bool {
	if !equalCommon(t1, t2) {
		return false
	}
	if t1.Kind == KindEnum {
		for i := range t1.Enums {
			if t1.Enums[i].NameOff != t2.Enums[i].NameOff || t1.Enums[i].Value != t2.Enums[i].Value {
				return false
			}
		}
		return true
	}
	for i := range t1.Enum64s {
		if t1.Enum64s[i].NameOff != t2.Enum64s[i].NameOff || t1.Enum64s[i].Value != t2.Enum64s[i].Value {
			return false
		}
	}
	return true
}

func isAnyEnum(t *Type) bool {
	return t.Kind == KindEnum || t.Kind == KindEnum64
}

// isEnumFwd reports whether t is an enum forward declaration, an ENUM or
// ENUM64 without values.
func isEnumFwd(t *Type) bool {
	return isAnyEnum(t) && vlenOf(t) == 0
}

// compatEnum reports whether two enums are equal, or whether one is a
// forward declaration of the other: then only the names must match, and an
// ENUM forward declaration matches an ENUM64 of any size.
func compatEnum(t1, t2 *Type) bool {
	if !isEnumFwd(t1) && !isEnumFwd(t2) {
		return equalEnum(t1, t2)
	}
	return t1.NameOff == t2.NameOff && isAnyEnum(t1) && isAnyEnum(t2)
}

// hashStruct hashes a struct or union without its member types, which may
// not be deduplicated yet.
func hashStruct(t *Type) uint64 {
	h := hashCommon(t)
	for i := range t.Members {
		h = hashCombine(h, uint64(t.Members[i].NameOff))
		h = hashCombine(h, uint64(memberOffsetWord(t, &t.Members[i])))
	}
	return h
}

// shallowEqualStruct compares two structs or unions without their member
// types.
func shallowEqualStruct(t1, t2 *Type) bool {
	if !equalCommon(t1, t2) {
		return false
	}
	for i := range t1.Members {
		m1, m2 := &t1.Members[i], &t2.Members[i]
		if m1.NameOff != m2.NameOff || memberOffsetWord(t1, m1) != memberOffsetWord(t2, m2) {
			return false
		}
	}
	return true
}

// arrayOf returns the array payload of t, or a zero payload.
func arrayOf(t *Type) Array {
	if t.Array == nil {
		return Array{}
	}
	return *t.Array
}

// hashArray hashes an array including its element and index types, which
// are canonical by the time arrays are deduplicated.
func hashArray(t *Type) uint64 {
	a := arrayOf(t)
	h := hashCommon(t)
	h = hashCombine(h, uint64(a.Type))
	h = hashCombine(h, uint64(a.IndexType))
	return hashCombine(h, uint64(a.Nelems))
}

func equalArray(t1, t2 *Type) bool {
	return equalCommon(t1, t2) && arrayOf(t1) == arrayOf(t2)
}

// compatArray compares two arrays without their element and index types.
func compatArray(t1, t2 *Type) bool {
	return equalCommon(t1, t2) && arrayOf(t1).Nelems == arrayOf(t2).Nelems
}

// hashFnproto hashes a function prototype including its return and
// parameter types, which are canonical by the time prototypes are
// deduplicated.
func hashFnproto(t *Type) uint64 {
	h := hashCommon(t)
	for _, p := range t.Params {
		h = hashCombine(h, uint64(p.NameOff))
		h = hashCombine(h, uint64(p.Type))
	}
	return h
}

func equalFnproto(t1, t2 *Type) bool {
	if !equalCommon(t1, t2) {
		return false
	}
	for i := range t1.Params {
		if t1.Params[i].NameOff != t2.Params[i].NameOff || t1.Params[i].Type != t2.Params[i].Type {
			return false
		}
	}
	return true
}

// compatFnproto compares two function prototypes without their return and
// parameter types.
func compatFnproto(t1, t2 *Type) bool {
	if t1.NameOff != t2.NameOff || infoWord(t1) != infoWord(t2) {
		return false
	}
	for i := range t1.Params {
		if t1.Params[i].NameOff != t2.Params[i].NameOff {
			return false
		}
	}
	return true
}

// hashByKind and equalByKind pick the typedef or the struct and union check
// for the struct pass.
func hashByKind(t *Type) uint64 {
	if t.Kind == KindTypedef {
		return hashTypedef(t)
	}
	return hashStruct(t)
}

func equalByKind(t1, t2 *Type) bool {
	if t1.Kind == KindTypedef {
		return equalTypedef(t1, t2)
	}
	return shallowEqualStruct(t1, t2)
}

// fwdKind returns the kind a forward declaration names: a union when the
// kind flag is set, otherwise a struct.
func fwdKind(t *Type) Kind {
	if t.KindFlag {
		return KindUnion
	}
	return KindStruct
}
