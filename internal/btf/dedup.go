// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-source: src/hashmap.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__dedup, btf_dedup_new, btf_dedup_free, btf_dedup_table_add, btf_dedup_hypot_map_add, btf_dedup_clear_hypot_map, btf_for_each_str_off, strs_dedup_remap_str_off, btf_dedup_strings, btf_dedup_compact_types, btf_dedup_remap_type_id, btf_dedup_remap_types, hashmap__append, hashmap_grow, hashmap__for_each_key_entry

package btf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
)

// Values of the canonical and hypothetical maps. An entry at most
// maxNrTypes is a type ID; the others mark a type that has no mapping yet or
// whose reference chain is being resolved.
const (
	maxNrTypes    = 0x7fffffff
	unprocessedID = ^uint32(0)
	inProgressID  = ^uint32(0) - 1
)

// DedupOpts are the options of Dedup.
type DedupOpts struct {
	// Ext is the .BTF.ext section that goes with the spec, or nil, in the
	// spec's byte order. Dedup keeps the strings it references and
	// rewrites its type IDs and string offsets in place.
	Ext []byte
}

// dedup is the state of one Dedup call. canon maps each type ID to its
// canonical type ID, or to unprocessedID; a canonical type maps to itself,
// and a resolved forward declaration to the struct or union it names. hypot
// is the hypothetical map of one struct equivalence check, from a type of the
// canonical graph to the type of the candidate graph, and hypotList lists
// the IDs it maps; after compaction hypot maps each canonical type ID to its
// final ID.
type dedup struct {
	spec      *Spec
	ext       []byte
	table     dedupTable
	canon     []uint32
	hypot     []uint32
	hypotList []uint32
}

// Dedup removes duplicate types from the spec and returns the type ID map:
// remap[id] is the new ID of the type that had ID id.
//
// Types that describe the same C type are merged into the first of them,
// including struct and union graphs with cycles. A struct or union forward
// declaration is resolved to the struct or union of that name when a type
// graph comparison links them or the name is unambiguous, and an enum
// forward declaration to the full enum. VAR and DATASEC types are never
// merged. The kept types stay in their original order, and every type ID in
// the spec and in opts.Ext is rewritten.
//
// The string table is rebuilt from the strings the types and opts.Ext
// reference, in the order they are referenced, unless the strings are
// already unique, as in a spec from NewSpec, which keeps its table.
//
// On success Raw returns the new blob, and the Set and Fixup methods work on
// the new type IDs. On error the types, the strings and opts.Ext may be
// partly rewritten and must be discarded. The error wraps EINVAL for a type
// that cannot be deduplicated, ELOOP for a reference cycle that does not go
// through a struct, union or typedef, and EOPNOTSUPP for a BTF header with a
// layout section or unknown fields and for a spec from MergeSplit; split BTF
// is not deduplicated against its base.
func (s *Spec) Dedup(opts *DedupOpts) ([]uint32, error) {
	d := newDedup(s, opts)
	if err := s.checkDedup(d.ext); err != nil {
		return nil, fmt.Errorf("btf: dedup: %w", err)
	}

	steps := []struct {
		name string
		run  func() error
	}{
		{"strings", d.dedupStrings},
		{"primitive types", d.dedupPrimTypes},
		{"struct types", d.dedupStructTypes},
		{"forward declarations", d.resolveFwds},
		{"reference types", d.dedupRefTypes},
		{"compaction", d.compactTypes},
		{"type remap", d.remapTypes},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			return nil, fmt.Errorf("btf: dedup %s: %w", step.name, err)
		}
	}

	remap := make([]uint32, len(d.canon))
	for id := range remap {
		remap[id] = d.hypot[d.resolveTypeID(uint32(id))]
	}
	if err := s.encode(); err != nil {
		return nil, err
	}
	return remap, nil
}

// checkDedup rejects what Dedup cannot handle before it changes anything: a
// spec merged from split BTF, a byte order that cannot encode, a header with a layout section or nonzero
// bytes past its known fields, a type without its kind's payload, a type ID
// out of range in the types or in ext, and a malformed ext.
func (s *Spec) checkDedup(ext []byte) error {
	if s.mergedSplit {
		return fmt.Errorf("%w: split BTF merged with its base", syscall.EOPNOTSUPP)
	}
	if _, ok := s.ByteOrder.(binary.AppendByteOrder); !ok {
		return fmt.Errorf("%w: byte order %v cannot encode", syscall.EINVAL, s.ByteOrder)
	}
	if len(s.Types) == 0 || s.Types[0].Kind != KindVoid {
		return fmt.Errorf("%w: type 0 is not void", syscall.EINVAL)
	}

	if hdrLen := int(s.Header.HdrLen); hdrLen > minHdrLen && len(s.raw) >= hdrLen {
		extra := s.raw[minHdrLen:hdrLen]
		if len(extra) >= 8 && s.ByteOrder.Uint32(extra[4:]) != 0 {
			return fmt.Errorf("%w: BTF layout section", syscall.EOPNOTSUPP)
		}
		for i := builtHdrLen - minHdrLen; i < len(extra); i++ {
			if extra[i] != 0 {
				return fmt.Errorf("%w: unknown BTF header fields", syscall.EOPNOTSUPP)
			}
		}
	}

	n := uint32(len(s.Types))
	for id := 1; id < len(s.Types); id++ {
		t := &s.Types[id]
		if missingPayload(t) {
			return fmt.Errorf("%w: type %d has no %v payload", syscall.EINVAL, id, t.Kind)
		}
		err := t.VisitTypeIDs(func(ref *uint32) error {
			if *ref >= n {
				return fmt.Errorf("%w: type %d refers to type %d out of range", syscall.EINVAL, id, *ref)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	if ext == nil {
		return nil
	}
	err := visitExtTypeIDs(ext, s.ByteOrder, func(ref *uint32) error {
		if *ref >= n {
			return fmt.Errorf("%w: .BTF.ext refers to type %d out of range", syscall.EINVAL, *ref)
		}
		return nil
	})
	if err != nil {
		return withErrno(err)
	}
	return nil
}

// missingPayload reports whether t lacks the payload of its kind.
func missingPayload(t *Type) bool {
	switch t.Kind {
	case KindInt:
		return t.Int == nil
	case KindArray:
		return t.Array == nil
	case KindVar:
		return t.Var == nil
	case KindDeclTag:
		return t.DeclTag == nil
	}
	return false
}

// newDedup sets up the maps: void is canonical, VAR and DATASEC types are
// canonical for themselves, and every other type is unprocessed.
func newDedup(s *Spec, opts *DedupOpts) *dedup {
	d := &dedup{
		spec:  s,
		canon: make([]uint32, len(s.Types)),
		hypot: make([]uint32, len(s.Types)),
	}
	if opts != nil {
		d.ext = opts.Ext
	}
	for id := 1; id < len(s.Types); id++ {
		switch s.Types[id].Kind {
		case KindVar, KindDatasec:
			d.canon[id] = uint32(id)
		default:
			d.canon[id] = unprocessedID
		}
	}
	for id := range d.hypot {
		d.hypot[id] = unprocessedID
	}
	return d
}

// typ returns the type with id, which the caller has checked.
func (d *dedup) typ(id uint32) *Type {
	return &d.spec.Types[id]
}

// isTypeMapped reports whether id already has a canonical type, possibly
// itself.
func (d *dedup) isTypeMapped(id uint32) bool {
	return d.canon[id] <= maxNrTypes
}

// resolveTypeID follows the canonical map from id to its canonical type ID,
// through a resolved forward declaration if needed. A type without a mapping
// resolves to itself.
func (d *dedup) resolveTypeID(id uint32) uint32 {
	for d.isTypeMapped(id) && d.canon[id] != id {
		id = d.canon[id]
	}
	return id
}

// resolveFwdID returns the struct or union a forward declaration id resolves
// to, or id when it is not a forward declaration or is unresolved.
func (d *dedup) resolveFwdID(id uint32) uint32 {
	if d.typ(id).Kind != KindFwd {
		return id
	}
	resolved := d.resolveTypeID(id)
	if d.typ(resolved).Kind != KindFwd {
		return resolved
	}
	return id
}

func (d *dedup) hypotMapAdd(from, to uint32) {
	d.hypotList = append(d.hypotList, from)
	d.hypot[from] = to
}

func (d *dedup) clearHypotMap() {
	for _, id := range d.hypotList {
		d.hypot[id] = unprocessedID
	}
	d.hypotList = d.hypotList[:0]
}

// dedupTable maps a type signature hash to the canonical candidates with
// that hash. Iteration order matters, because the first matching candidate
// wins: a new candidate goes first, and every time the table grows, each
// hash's candidates reverse, as entries do when they move to the new buckets
// of a chained hash table that inserts at the bucket head. size and capacity
// track when it grows: from empty to 4 buckets, then doubling whenever one
// more entry would fill more than three quarters of them.
type dedupTable struct {
	cands    map[uint64][]uint32
	size     int
	capacity int
}

// candidates returns the canonical candidates for hash h in iteration order.
func (tb *dedupTable) candidates(h uint64) []uint32 {
	return tb.cands[h]
}

// add makes id a canonical candidate for hash h.
func (tb *dedupTable) add(h uint64, id uint32) {
	if tb.capacity == 0 || (tb.size+1)*4/3 > tb.capacity {
		tb.grow()
	}
	tb.cands[h] = append([]uint32{id}, tb.cands[h]...)
	tb.size++
}

func (tb *dedupTable) grow() {
	if tb.cands == nil {
		tb.cands = make(map[uint64][]uint32)
	}
	tb.capacity = max(4, tb.capacity*2)
	for _, ids := range tb.cands {
		for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
			ids[i], ids[j] = ids[j], ids[i]
		}
	}
}

// dedupStrings rebuilds the string table from the strings the types and the
// .BTF.ext section reference, in visiting order, and rewrites every string
// offset. The empty string stays at offset 0. Unique strings are left alone.
func (d *dedup) dedupStrings() error {
	s := d.spec
	if s.stringsDeduped {
		return nil
	}

	set := newStrSet()
	remap := func(off *uint32) error {
		if *off == 0 {
			return nil
		}
		str, err := s.String(*off)
		if err != nil {
			return withErrno(err)
		}
		*off = set.add(str)
		return nil
	}

	for id := 1; id < len(s.Types); id++ {
		if err := s.Types[id].visitStrOffs(remap); err != nil {
			return err
		}
	}
	if d.ext != nil {
		if err := visitExtStrOffs(d.ext, s.ByteOrder, remap); err != nil {
			return withErrno(err)
		}
	}

	s.Strings = set.data
	s.stringsDeduped = true
	return nil
}

// strSet is a string table that stores each string once.
type strSet struct {
	data []byte
	offs map[string]uint32
}

func newStrSet() *strSet {
	return &strSet{data: []byte{0}, offs: map[string]uint32{"": 0}}
}

// add returns the offset of str, appending it if it is new.
func (ss *strSet) add(str string) uint32 {
	if off, ok := ss.offs[str]; ok {
		return off
	}
	off := uint32(len(ss.data))
	ss.data = append(append(ss.data, str...), 0)
	ss.offs[str] = off
	return off
}

// visitStrOffs calls fn with a pointer to every string offset of t: its name,
// then the names of its members, enum values or parameters.
func (t *Type) visitStrOffs(fn func(off *uint32) error) error {
	if err := fn(&t.NameOff); err != nil {
		return err
	}
	switch t.Kind {
	case KindStruct, KindUnion:
		for i := range t.Members {
			if err := fn(&t.Members[i].NameOff); err != nil {
				return err
			}
		}
	case KindEnum:
		for i := range t.Enums {
			if err := fn(&t.Enums[i].NameOff); err != nil {
				return err
			}
		}
	case KindEnum64:
		for i := range t.Enum64s {
			if err := fn(&t.Enum64s[i].NameOff); err != nil {
				return err
			}
		}
	case KindFuncProto:
		for i := range t.Params {
			if err := fn(&t.Params[i].NameOff); err != nil {
				return err
			}
		}
	}
	return nil
}

// compactTypes keeps only the canonical types, in order, and records each
// one's new ID in hypot.
func (d *dedup) compactTypes() error {
	for id := range d.hypot {
		d.hypot[id] = unprocessedID
	}
	d.hypot[0] = 0

	types := d.spec.Types
	kept := types[:1]
	for id := 1; id < len(types); id++ {
		if d.canon[id] != uint32(id) {
			continue
		}
		d.hypot[id] = uint32(len(kept))
		kept = append(kept, types[id])
	}
	d.spec.Types = kept
	return nil
}

// remapTypeID rewrites an original type ID to the final ID of its canonical
// type.
func (d *dedup) remapTypeID(id *uint32) error {
	if *id >= uint32(len(d.canon)) {
		return fmt.Errorf("%w: type id %d out of range", syscall.EINVAL, *id)
	}
	newID := d.hypot[d.resolveTypeID(*id)]
	if newID > maxNrTypes {
		return fmt.Errorf("%w: type id %d has no final id", syscall.EINVAL, *id)
	}
	*id = newID
	return nil
}

// remapTypes rewrites the type IDs of the kept types and of the .BTF.ext
// records to their final IDs.
func (d *dedup) remapTypes() error {
	types := d.spec.Types
	for id := 1; id < len(types); id++ {
		if err := types[id].VisitTypeIDs(d.remapTypeID); err != nil {
			return err
		}
	}
	if d.ext == nil {
		return nil
	}
	if err := visitExtTypeIDs(d.ext, d.spec.ByteOrder, d.remapTypeID); err != nil {
		return withErrno(err)
	}
	return nil
}

// withErrno wraps err with EINVAL unless it already carries an errno.
func withErrno(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return err
	}
	return fmt.Errorf("%w: %v", syscall.EINVAL, err)
}
