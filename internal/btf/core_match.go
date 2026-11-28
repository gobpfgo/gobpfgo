// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/relo_core.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: __bpf_core_types_match, bpf_core_types_match, bpf_core_names_match, bpf_core_enums_match, bpf_core_composites_match, bpf_core_essential_name_len, bpf_core_is_flavor_sep, bpf_core_add_cands

package btf

import "errors"

// coreMatchMaxLevel is the nesting limit of TypesMatch, counted in struct,
// union and function prototype levels, and coreMatchMaxDepth the number of
// pointer, array and return type steps one level follows before it gives up.
const (
	coreMatchMaxLevel = 32
	coreMatchMaxDepth = 32
)

// errMatchDepth reports a type graph too deep, or broken, to match.
var errMatchDepth = errors.New("btf: type match check exceeded its depth")

// TypesMatch reports whether type localID of local matches type targetID of
// target, the check behind a bpf_core_type_matches relocation. The caller
// has already matched the root names, ignoring a ___flavor suffix.
//
// Modifiers and typedefs are skipped, and at every step the two names must
// match, again ignoring flavors; anonymous types and members only match
// anonymous ones. The kinds must then be equal, except that an enum matches
// an enum64, and a struct or union behind a pointer also matches a forward
// declaration of the same kind. Integers match when their sizes and
// signedness do, pointers when their targets do, and arrays when their
// lengths and element types do. Each local enumerator name must exist in
// the target, and the sizes must be equal. Each local struct or union member
// must have a target member of the same name whose type matches, unless the
// struct is already behind a pointer, where the names are enough. Function
// prototypes need the same number of parameters, each matching, and
// matching return types. Every other kind, such as a float, does not match.
//
// It returns an error, which a relocation treats as a failure rather than a
// mismatch, when a type ID is invalid or the types nest deeper than libbpf
// follows.
func TypesMatch(local *Spec, localID uint32, target *Spec, targetID uint32) (bool, error) {
	return typesMatch(local, localID, target, targetID, false, coreMatchMaxLevel)
}

// typesMatch matches localID and targetID at nesting level, which counts
// down. behindPtr is set once a pointer was followed on the way.
func typesMatch(local *Spec, localID uint32, target *Spec, targetID uint32, behindPtr bool, level int) (bool, error) {
	if level <= 0 {
		return false, errMatchDepth
	}

	for depth := coreMatchMaxDepth; depth > 0; depth-- {
		localType, _, err := local.skipModsTypedefs(localID)
		if err != nil {
			return false, errMatchDepth
		}
		targetType, _, err := target.skipModsTypedefs(targetID)
		if err != nil {
			return false, errMatchDepth
		}

		// The root names are matched again here, past their typedefs.
		if !coreNamesMatch(localType.Name, targetType.Name) {
			return false, nil
		}

		switch localType.Kind {
		case KindVoid:
			return targetType.Kind == KindVoid, nil
		case KindFwd:
			return fwdMatches(localType, targetType, behindPtr), nil
		case KindEnum, KindEnum64:
			return isEnumKind(targetType.Kind) && enumsMatch(localType, targetType), nil
		case KindStruct, KindUnion:
			if behindPtr {
				return compositeMatchesBehindPtr(localType, targetType), nil
			}
			if localType.Kind != targetType.Kind {
				return false, nil
			}
			return compositesMatch(local, localType, target, targetType, behindPtr, level)
		case KindInt:
			return targetType.Kind == KindInt && localType.SizeOrType == targetType.SizeOrType &&
				intSigned(localType) == intSigned(targetType), nil
		case KindPtr:
			if targetType.Kind != KindPtr {
				return false, nil
			}
			behindPtr = true
			localID, targetID = localType.SizeOrType, targetType.SizeOrType
		case KindArray:
			if targetType.Kind != KindArray || localType.Array == nil || targetType.Array == nil {
				return false, nil
			}
			if localType.Array.Nelems != targetType.Array.Nelems {
				return false, nil
			}
			localID, targetID = localType.Array.Type, targetType.Array.Type
		case KindFuncProto:
			if targetType.Kind != KindFuncProto || len(localType.Params) != len(targetType.Params) {
				return false, nil
			}
			for i := range localType.Params {
				ok, err := typesMatch(local, localType.Params[i].Type, target, targetType.Params[i].Type, behindPtr, level-1)
				if !ok || err != nil {
					return ok, err
				}
			}
			// The return types are matched by the next step.
			localID, targetID = localType.SizeOrType, targetType.SizeOrType
		default:
			return false, nil
		}
	}
	return false, errMatchDepth
}

// fwdMatches matches a local forward declaration. Its kind flag tells a
// union from a struct. Behind a pointer it also matches a struct or union of
// that kind; otherwise only a forward declaration of the same kind.
func fwdMatches(localType, targetType *Type, behindPtr bool) bool {
	if targetType.Kind == KindFwd {
		return localType.KindFlag == targetType.KindFlag
	}
	if !behindPtr {
		return false
	}
	return targetType.Kind == KindStruct && !localType.KindFlag ||
		targetType.Kind == KindUnion && localType.KindFlag
}

// compositeMatchesBehindPtr matches a local struct or union behind a
// pointer, without its members: a target of the same kind matches, and so
// does a forward declaration of that kind.
func compositeMatchesBehindPtr(localType, targetType *Type) bool {
	if localType.Kind == targetType.Kind {
		return true
	}
	if targetType.Kind != KindFwd {
		return false
	}
	return (localType.Kind == KindUnion) == targetType.KindFlag
}

// compositesMatch reports whether every member of the local struct or union
// has a target member with a matching name and a matching type, one level
// down. The target may have more members, in any order.
func compositesMatch(local *Spec, localType *Type, target *Spec, targetType *Type, behindPtr bool, level int) (bool, error) {
	if len(localType.Members) > len(targetType.Members) {
		return false, nil
	}
	for _, localMember := range localType.Members {
		matched := false
		for _, targetMember := range targetType.Members {
			if !coreNamesMatch(localMember.Name, targetMember.Name) {
				continue
			}
			ok, err := typesMatch(local, localMember.Type, target, targetMember.Type, behindPtr, level-1)
			if err != nil {
				return false, err
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

// enumsMatch reports whether two enums of either kind have the same size and
// every local enumerator name is in the target. The values are not compared.
func enumsMatch(localType, targetType *Type) bool {
	if localType.SizeOrType != targetType.SizeOrType {
		return false
	}
	localNames, targetNames := enumNames(localType), enumNames(targetType)
	if len(localNames) > len(targetNames) {
		return false
	}
	for _, localName := range localNames {
		matched := false
		for _, targetName := range targetNames {
			if coreNamesMatch(localName, targetName) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// enumNames returns the enumerator names of an enum or enum64.
func enumNames(t *Type) []string {
	var names []string
	for _, e := range t.Enums {
		names = append(names, e.Name)
	}
	for _, e := range t.Enum64s {
		names = append(names, e.Name)
	}
	return names
}

// intSigned reports whether an integer type has the signed encoding.
func intSigned(t *Type) bool {
	return intEncoding(t)&(1<<24) != 0
}

// coreNamesMatch reports whether a local and a target name are equal once a
// ___flavor suffix is dropped from each. An empty target name only matches
// an empty local name.
func coreNamesMatch(local, target string) bool {
	if target == "" {
		return local == ""
	}
	return essentialName(local) == essentialName(target)
}

// essentialName drops a ___flavor suffix from name: everything from the last
// "___" that has a character other than '_' before and after it.
func essentialName(name string) string {
	for i := len(name) - 5; i >= 0; i-- {
		if isFlavorSep(name[i:]) {
			return name[:i+1]
		}
	}
	return name
}

// isFlavorSep reports whether s starts with the X___Y pattern of a flavor
// separator, where X and Y are not underscores.
func isFlavorSep(s string) bool {
	return s[0] != '_' && s[1] == '_' && s[2] == '_' && s[3] == '_' && s[4] != '_'
}

// CoreCandidates returns the IDs of the types of s, from startID on, that can
// be the target of a CO-RE relocation on localType: named types of the same
// kind, with an enum and an enum64 counting as one kind, whose names equal
// localType's once a ___flavor suffix is dropped from each. Pass StartID to
// search only the types a split spec owns.
func (s *Spec) CoreCandidates(localType *Type, startID uint32) []uint32 {
	essential := essentialName(localType.Name)
	var ids []uint32
	for id := startID; ; id++ {
		t, err := s.TypeByID(id)
		if err != nil {
			return ids
		}
		if !kindCoreCompat(t, localType) || t.Name == "" || essentialName(t.Name) != essential {
			continue
		}
		ids = append(ids, id)
	}
}
