// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original size resolver
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__resolve_size

package btf

import "fmt"

// SizeOf returns the size in bytes of a type. Pointers are 8 bytes, matching
// the 64-bit BPF objects the loader accepts.
func (s *Spec) SizeOf(id uint32) (uint32, error) {
	t, err := s.TypeByID(id)
	if err != nil {
		return 0, err
	}

	switch t.Kind {
	case KindInt, KindStruct, KindUnion, KindEnum, KindEnum64, KindFloat:
		return t.SizeOrType, nil
	case KindPtr:
		return 8, nil
	case KindArray:
		if t.Array == nil {
			return 0, fmt.Errorf("btf: type %d has no array payload", id)
		}
		elem, err := s.SizeOf(t.Array.Type)
		if err != nil {
			return 0, err
		}
		return elem * t.Array.Nelems, nil
	case KindTypedef, KindVolatile, KindConst, KindRestrict, KindTypeTag:
		return s.SizeOf(t.SizeOrType)
	case KindVoid:
		return 0, nil
	default:
		return 0, fmt.Errorf("btf: type %d: no size for kind %v", id, t.Kind)
	}
}
