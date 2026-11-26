// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__align_of

package btf

import "fmt"

// AlignOf returns the natural alignment of a type in bytes, matching the C
// library's btf__align_of on a 64-bit target.
//
// A struct or union whose members are not naturally aligned, or whose size is
// not a multiple of its alignment, is packed and returns 1.
func (s *Spec) AlignOf(id uint32) (int, error) {
	t, err := s.TypeByID(id)
	if err != nil {
		return 0, err
	}

	switch t.Kind {
	case KindInt, KindEnum, KindEnum64, KindFloat:
		size := int(t.SizeOrType)
		if size > 8 {
			size = 8
		}
		return size, nil
	case KindPtr:
		return 8, nil
	case KindTypedef, KindVolatile, KindConst, KindRestrict, KindTypeTag:
		return s.AlignOf(t.SizeOrType)
	case KindArray:
		if t.Array == nil {
			return 0, fmt.Errorf("btf: type %d has no array payload", id)
		}
		return s.AlignOf(t.Array.Type)
	case KindStruct, KindUnion:
		maxAlign := 1
		for _, member := range t.Members {
			align, err := s.AlignOf(member.Type)
			if err != nil {
				return 0, err
			}
			if align <= 0 {
				return 0, fmt.Errorf("btf: member %s has no alignment", member.Name)
			}
			if align > maxAlign {
				maxAlign = align
			}
			if member.BitfieldSize == 0 && member.Offset%uint32(8*align) != 0 {
				return 1, nil
			}
		}
		if t.SizeOrType%uint32(maxAlign) != 0 {
			return 1, nil
		}
		return maxAlign, nil
	default:
		return 0, fmt.Errorf("btf: type %d has no alignment for kind %v", id, t.Kind)
	}
}
