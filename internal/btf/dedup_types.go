// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_dedup_prim_type, btf_dedup_prim_types, is_type_mapped, resolve_type_id, resolve_fwd_id, btf_dedup_identical_types, btf_dedup_is_equiv, btf_dedup_merge_hypot_map, btf_dedup_struct_type, btf_dedup_struct_types, btf_dedup_ref_type, btf_dedup_ref_types, btf_dedup_fill_unique_names_map, btf_dedup_resolve_fwd, btf_dedup_resolve_fwds

package btf

import (
	"fmt"
	"syscall"
)

// identicalDepth bounds the structural comparison of two candidate types
// that the same canonical type maps to.
const identicalDepth = 16

// dedupPrimTypes deduplicates the types that reference no other type: INT,
// ENUM, ENUM64, FWD and FLOAT. A type equal to a canonical candidate maps to
// it; otherwise it becomes a candidate itself. An enum forward declaration
// resolves to the full enum of the same name, whichever comes first.
func (d *dedup) dedupPrimTypes() error {
	for id := 1; id < len(d.spec.Types); id++ {
		if err := d.dedupPrimType(uint32(id)); err != nil {
			return err
		}
	}
	return nil
}

func (d *dedup) dedupPrimType(id uint32) error {
	t := d.typ(id)
	newID := id
	var h uint64

	switch t.Kind {
	case KindConst, KindVolatile, KindRestrict, KindPtr, KindTypedef, KindArray,
		KindStruct, KindUnion, KindFunc, KindFuncProto, KindVar, KindDatasec,
		KindDeclTag, KindTypeTag:
		return nil

	case KindInt:
		h = hashIntDeclTag(t)
		for _, cand := range d.table.candidates(h) {
			if equalIntTag(t, d.typ(cand)) {
				newID = cand
				break
			}
		}

	case KindEnum, KindEnum64:
		h = hashEnum(t)
		for _, cand := range d.table.candidates(h) {
			c := d.typ(cand)
			if equalEnum(t, c) {
				newID = cand
				break
			}
			if !compatEnum(t, c) {
				continue
			}
			if isEnumFwd(t) {
				newID = cand
				break
			}
			d.canon[cand] = id
		}

	case KindFwd, KindFloat:
		h = hashCommon(t)
		for _, cand := range d.table.candidates(h) {
			if equalCommon(t, d.typ(cand)) {
				newID = cand
				break
			}
		}

	default:
		return fmt.Errorf("%w: type %d has unknown kind %v", syscall.EINVAL, id, t.Kind)
	}

	d.canon[id] = newID
	if newID == id {
		d.table.add(h, id)
	}
	return nil
}

// dedupStructTypes deduplicates structs, unions and typedefs. Each one is
// compared with the canonical candidates of its hash by walking both type
// graphs side by side; the first equivalent candidate wins, and the walk's
// correspondences resolve forward declarations. A type with no equivalent
// candidate becomes one.
func (d *dedup) dedupStructTypes() error {
	for id := 1; id < len(d.spec.Types); id++ {
		if err := d.dedupStructType(uint32(id)); err != nil {
			return err
		}
	}
	return nil
}

func (d *dedup) dedupStructType(id uint32) error {
	if d.isTypeMapped(id) {
		return nil
	}
	t := d.typ(id)
	if t.Kind != KindStruct && t.Kind != KindUnion && t.Kind != KindTypedef {
		return nil
	}

	h := hashByKind(t)
	newID := id
	for _, cand := range d.table.candidates(h) {
		// A hash collision can offer a forward declaration; comparing it
		// as equivalent could map a struct and its declaration onto each
		// other.
		if !equalByKind(t, d.typ(cand)) {
			continue
		}

		d.clearHypotMap()
		eq, err := d.isEquiv(id, cand)
		if err != nil {
			return err
		}
		if !eq {
			continue
		}
		d.mergeHypotMap()
		newID = cand
		break
	}

	d.canon[id] = newID
	if newID == id {
		d.table.add(h, id)
	}
	return nil
}

// isEquiv reports whether the type graph of candID is equivalent to the
// graph of canonID. It records each canonical-graph type it visits in the
// hypothetical map, which ends a cycle and catches one canonical type
// corresponding to two different candidate types. A forward declaration is
// equivalent to a struct or union of the same name and kind, and only the
// canonical side follows a forward declaration to its resolved type. The
// error wraps EINVAL for a kind that cannot appear in a type graph.
func (d *dedup) isEquiv(candID, canonID uint32) (bool, error) {
	if d.resolveTypeID(candID) == d.resolveTypeID(canonID) {
		return true, nil
	}
	canonID = d.resolveFwdID(canonID)

	if hypotID := d.hypot[canonID]; hypotID <= maxNrTypes {
		if hypotID == candID {
			return true, nil
		}
		// A compiler may emit identical but separate types for fields of
		// one struct, which breaks the one-to-one correspondence; accept
		// them when they are structurally identical.
		return d.identicalTypes(hypotID, candID, identicalDepth), nil
	}
	d.hypotMapAdd(canonID, candID)

	cand, canon := d.typ(candID), d.typ(canonID)
	if cand.NameOff != canon.NameOff {
		return false, nil
	}
	if (cand.Kind == KindFwd || canon.Kind == KindFwd) && cand.Kind != canon.Kind {
		if cand.Kind == KindFwd {
			return fwdKind(cand) == canon.Kind, nil
		}
		return fwdKind(canon) == cand.Kind, nil
	}
	if cand.Kind != canon.Kind {
		return false, nil
	}

	switch cand.Kind {
	case KindInt:
		return equalIntTag(cand, canon), nil
	case KindEnum, KindEnum64:
		return compatEnum(cand, canon), nil
	case KindFwd, KindFloat:
		return equalCommon(cand, canon), nil
	case KindConst, KindVolatile, KindRestrict, KindPtr, KindTypedef, KindFunc, KindTypeTag:
		if infoWord(cand) != infoWord(canon) {
			return false, nil
		}
		return d.isEquiv(cand.SizeOrType, canon.SizeOrType)
	case KindArray:
		if !compatArray(cand, canon) {
			return false, nil
		}
		return d.allEquiv(
			[]uint32{arrayOf(cand).IndexType, arrayOf(cand).Type},
			[]uint32{arrayOf(canon).IndexType, arrayOf(canon).Type})
	case KindStruct, KindUnion:
		if !shallowEqualStruct(cand, canon) {
			return false, nil
		}
		return d.allEquiv(memberTypes(cand), memberTypes(canon))
	case KindFuncProto:
		if !compatFnproto(cand, canon) {
			return false, nil
		}
		return d.allEquiv(protoTypes(cand), protoTypes(canon))
	}
	return false, fmt.Errorf("%w: type %d of kind %v in a type graph", syscall.EINVAL, candID, cand.Kind)
}

// allEquiv checks each pair of referenced types in order and stops at the
// first pair that is not equivalent.
func (d *dedup) allEquiv(cands, canons []uint32) (bool, error) {
	for i := range cands {
		eq, err := d.isEquiv(cands[i], canons[i])
		if err != nil || !eq {
			return eq, err
		}
	}
	return true, nil
}

func memberTypes(t *Type) []uint32 {
	ids := make([]uint32, len(t.Members))
	for i := range t.Members {
		ids[i] = t.Members[i].Type
	}
	return ids
}

// protoTypes returns the return type and then the parameter types.
func protoTypes(t *Type) []uint32 {
	ids := make([]uint32, 0, len(t.Params)+1)
	ids = append(ids, t.SizeOrType)
	for i := range t.Params {
		ids = append(ids, t.Params[i].Type)
	}
	return ids
}

// identicalTypes compares two type graphs structurally, up to depth levels
// of arrays, structs, unions and function prototypes. Modifier, pointer,
// typedef and function chains do not use up depth; a chain longer than the
// type table is a cycle and compares as different.
func (d *dedup) identicalTypes(id1, id2 uint32, depth int) bool {
	for chain := 0; chain < len(d.spec.Types); chain++ {
		t1, t2 := d.typ(id1), d.typ(id2)
		if depth <= 0 || t1.Kind != t2.Kind {
			return false
		}

		switch t1.Kind {
		case KindVoid:
			return true
		case KindInt:
			return equalIntTag(t1, t2)
		case KindEnum, KindEnum64:
			return compatEnum(t1, t2)
		case KindFwd, KindFloat:
			return equalCommon(t1, t2)
		case KindConst, KindVolatile, KindRestrict, KindPtr, KindTypedef, KindFunc, KindTypeTag:
			if infoWord(t1) != infoWord(t2) || t1.NameOff != t2.NameOff {
				return false
			}
			id1, id2 = t1.SizeOrType, t2.SizeOrType
		case KindArray:
			if !compatArray(t1, t2) {
				return false
			}
			a1, a2 := arrayOf(t1), arrayOf(t2)
			return d.allIdentical([]uint32{a1.IndexType, a1.Type}, []uint32{a2.IndexType, a2.Type}, depth-1)
		case KindStruct, KindUnion:
			if !shallowEqualStruct(t1, t2) {
				return false
			}
			return d.allIdentical(memberTypes(t1), memberTypes(t2), depth-1)
		case KindFuncProto:
			if !compatFnproto(t1, t2) {
				return false
			}
			return d.allIdentical(protoTypes(t1), protoTypes(t2), depth-1)
		default:
			return false
		}
	}
	return false
}

// allIdentical compares each pair of referenced types in order; a pair with
// the same ID is identical without a walk.
func (d *dedup) allIdentical(ids1, ids2 []uint32, depth int) bool {
	for i := range ids1 {
		if ids1[i] != ids2[i] && !d.identicalTypes(ids1[i], ids2[i], depth) {
			return false
		}
	}
	return true
}

// mergeHypotMap records what a successful equivalence walk established: a
// forward declaration on either side maps to the struct or union it matched,
// and a candidate-graph struct or union without a canonical type maps to the
// canonical-graph one when that one is already canonical.
func (d *dedup) mergeHypotMap() {
	for _, canonID := range d.hypotList {
		tID := d.resolveTypeID(d.hypot[canonID])
		cID := d.resolveTypeID(canonID)
		tKind, cKind := d.typ(tID).Kind, d.typ(cID).Kind

		if tKind != KindFwd && cKind == KindFwd {
			d.canon[cID] = tID
		}
		if tKind == KindFwd && cKind != KindFwd {
			d.canon[tID] = cID
		}
		if (tKind == KindStruct || tKind == KindUnion) && cKind != KindFwd &&
			d.isTypeMapped(cID) && !d.isTypeMapped(tID) {
			d.canon[tID] = cID
		}
	}
}

// resolveFwds maps each still unresolved struct or union forward declaration
// to the canonical struct or union of the same name and kind, when exactly
// one canonical struct or union has that name.
func (d *dedup) resolveFwds() error {
	types := d.spec.Types
	unique := make(map[uint32]uint32)
	for id := 1; id < len(types); id++ {
		t := &types[id]
		if (t.Kind != KindStruct && t.Kind != KindUnion) || d.canon[id] != uint32(id) {
			continue
		}
		if _, seen := unique[t.NameOff]; seen {
			unique[t.NameOff] = 0
		} else {
			unique[t.NameOff] = uint32(id)
		}
	}

	for id := 1; id < len(types); id++ {
		t := &types[id]
		if t.Kind != KindFwd || d.canon[id] != uint32(id) {
			continue
		}
		cand := unique[t.NameOff]
		if cand != 0 && types[cand].Kind == fwdKind(t) {
			d.canon[id] = cand
		}
	}
	return nil
}

// dedupRefTypes deduplicates the reference types: modifiers, pointers,
// functions, tags, arrays and function prototypes. Each one first resolves
// the types it references to their canonical IDs, recursively, and is then
// compared with the canonical candidates including those IDs.
func (d *dedup) dedupRefTypes() error {
	for id := 1; id < len(d.spec.Types); id++ {
		if _, err := d.dedupRefType(uint32(id)); err != nil {
			return err
		}
	}
	d.table = dedupTable{}
	return nil
}

// dedupRefType returns the canonical ID of id. A reference type rewrites its
// referenced type IDs to their canonical IDs. The error wraps ELOOP for a
// reference cycle that does not go through a struct, union or typedef.
func (d *dedup) dedupRefType(id uint32) (uint32, error) {
	if d.canon[id] == inProgressID {
		return 0, fmt.Errorf("%w: reference cycle at type %d", syscall.ELOOP, id)
	}
	if d.isTypeMapped(id) {
		return d.resolveTypeID(id), nil
	}

	t := d.typ(id)
	d.canon[id] = inProgressID

	var ids []*uint32
	var hash func(*Type) uint64
	var equal func(t1, t2 *Type) bool
	switch t.Kind {
	case KindConst, KindVolatile, KindRestrict, KindPtr, KindFunc, KindTypeTag:
		ids, hash, equal = []*uint32{&t.SizeOrType}, hashCommon, equalCommon
	case KindDeclTag:
		ids, hash, equal = []*uint32{&t.SizeOrType}, hashIntDeclTag, equalIntTag
	case KindArray:
		ids, hash, equal = []*uint32{&t.Array.Type, &t.Array.IndexType}, hashArray, equalArray
	case KindFuncProto:
		ids, hash, equal = protoTypeRefs(t), hashFnproto, equalFnproto
	default:
		return 0, fmt.Errorf("%w: type %d has unexpected kind %v", syscall.EINVAL, id, t.Kind)
	}

	for _, ref := range ids {
		canonRef, err := d.dedupRefType(*ref)
		if err != nil {
			return 0, err
		}
		*ref = canonRef
	}

	h := hash(t)
	newID := id
	for _, cand := range d.table.candidates(h) {
		if equal(t, d.typ(cand)) {
			newID = cand
			break
		}
	}

	d.canon[id] = newID
	if newID == id {
		d.table.add(h, id)
	}
	return newID, nil
}

// protoTypeRefs returns pointers to the return type and then the parameter
// types of a function prototype.
func protoTypeRefs(t *Type) []*uint32 {
	refs := make([]*uint32, 0, len(t.Params)+1)
	refs = append(refs, &t.SizeOrType)
	for i := range t.Params {
		refs = append(refs, &t.Params[i].Type)
	}
	return refs
}
