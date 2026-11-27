// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/relo_core.c
// libbpf-source: src/libbpf.c
// libbpf-source: src/btf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: __bpf_core_types_are_compat, bpf_core_types_are_compat, btf_kind_core_compat, skip_mods_and_typedefs

package btf

import "errors"

// coreCompatMaxLevel is the function prototype nesting limit of
// TypesAreCompat, and coreCompatMaxDepth the number of type steps it follows
// before it gives up.
const (
	coreCompatMaxLevel = 32
	coreCompatMaxDepth = 32
)

// errCompatDepth reports a type chain too deep, or broken, to compare.
var errCompatDepth = errors.New("btf: type compatibility check exceeded its depth")

// TypesAreCompat reports whether type localID of local and type targetID of
// target are compatible in the CO-RE sense used to match an extern against
// the kernel: names are not compared, any two structs, unions, forward
// declarations or enums of either size match, integers match unless one is
// a bitfield-like integer with a bit offset, pointers and arrays match when
// their targets do, and function prototypes match when they have the same
// number of parameters and every parameter and the return type match. Every
// other kind is incompatible. Modifiers and typedefs are skipped on the way,
// but the two types passed in must already be past theirs: their kinds are
// compared first, so a typedef does not match the type it names.
//
// It returns an error, which a caller treats like incompatible, when a
// type ID is invalid or the chain is deeper than libbpf follows.
func TypesAreCompat(local *Spec, localID uint32, target *Spec, targetID uint32) (bool, error) {
	return typesAreCompat(local, localID, target, targetID, coreCompatMaxLevel)
}

func typesAreCompat(local *Spec, localID uint32, target *Spec, targetID uint32, level int) (bool, error) {
	localType, err := local.TypeByID(localID)
	if err != nil {
		return false, err
	}
	targetType, err := target.TypeByID(targetID)
	if err != nil {
		return false, err
	}
	if !kindCoreCompat(localType, targetType) {
		return false, nil
	}

	for depth := coreCompatMaxDepth; depth > 0; depth-- {
		localType, localID, err = local.skipModsTypedefs(localID)
		if err != nil {
			return false, errCompatDepth
		}
		targetType, targetID, err = target.skipModsTypedefs(targetID)
		if err != nil {
			return false, errCompatDepth
		}
		if !kindCoreCompat(localType, targetType) {
			return false, nil
		}

		switch localType.Kind {
		case KindVoid, KindStruct, KindUnion, KindEnum, KindFwd, KindEnum64:
			return true, nil
		case KindInt:
			return intOffset(localType) == 0 && intOffset(targetType) == 0, nil
		case KindPtr:
			localID, targetID = localType.SizeOrType, targetType.SizeOrType
		case KindArray:
			if localType.Array == nil || targetType.Array == nil {
				return false, errCompatDepth
			}
			localID, targetID = localType.Array.Type, targetType.Array.Type
		case KindFuncProto:
			ok, err := paramsAreCompat(local, localType, target, targetType, level)
			if !ok || err != nil {
				return ok, err
			}
			// The return types are compared by the next step.
			localID, targetID = localType.SizeOrType, targetType.SizeOrType
		default:
			return false, nil
		}
	}
	return false, errCompatDepth
}

// paramsAreCompat compares the parameters of two function prototypes, one
// nesting level down.
func paramsAreCompat(local *Spec, localProto *Type, target *Spec, targetProto *Type, level int) (bool, error) {
	if len(localProto.Params) != len(targetProto.Params) {
		return false, nil
	}
	for i := range localProto.Params {
		if level <= 0 {
			return false, errCompatDepth
		}
		_, localID, err := local.skipModsTypedefs(localProto.Params[i].Type)
		if err != nil {
			return false, errCompatDepth
		}
		_, targetID, err := target.skipModsTypedefs(targetProto.Params[i].Type)
		if err != nil {
			return false, errCompatDepth
		}
		ok, err := typesAreCompat(local, localID, target, targetID, level-1)
		if !ok || err != nil {
			return ok, err
		}
	}
	return true, nil
}

// kindCoreCompat reports whether two types have the same kind, counting the
// two enum kinds as one.
func kindCoreCompat(a, b *Type) bool {
	return a.Kind == b.Kind || (isEnumKind(a.Kind) && isEnumKind(b.Kind))
}
