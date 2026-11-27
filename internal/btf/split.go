// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__parse_split, btf_new, btf__find_by_name_kind_own

package btf

import (
	"encoding/binary"
	"fmt"
)

// MergeSplit appends a module's split BTF types to the vmlinux base.
//
// The module type IDs start after the base types and the module's references
// already use those split IDs. The merged spec keeps the module string table;
// the type names are already resolved, so target matching never needs to
// resolve a base string through it. Dedup rejects the merged spec.
func MergeSplit(base, module *Spec) (*Spec, error) {
	if base == nil || module == nil {
		return nil, fmt.Errorf("btf: nil split BTF")
	}
	if len(base.Types) == 0 || len(module.Types) == 0 {
		return nil, fmt.Errorf("btf: empty split BTF")
	}

	baseCount := len(base.Types) - 1
	types := make([]Type, len(base.Types)+len(module.Types)-1)
	copy(types, base.Types)
	copy(types[len(base.Types):], module.Types[1:])
	for i := 1; i < len(module.Types); i++ {
		types[baseCount+i].ID = uint32(baseCount + i)
	}

	return &Spec{
		ByteOrder:   base.ByteOrder,
		Types:       types,
		Strings:     module.Strings,
		mergedSplit: true,
	}, nil
}

// ParseSplit decodes the split BTF data of a kernel module on top of base,
// the vmlinux BTF, as the kernel reports it for a module BTF object.
//
// The module's types continue the base type IDs and its string offsets
// continue the base string table, so a module type may refer to base types
// and names. The returned spec shares base instead of copying it: TypeByID
// and String resolve the base part through base, while Types holds only the
// void placeholder and the module's own types, and Find searches only those.
// StartID returns the ID of the first own type. Raw returns nil, and the
// spec cannot be deduplicated or modified.
func ParseSplit(data []byte, order binary.ByteOrder, base *Spec) (*Spec, error) {
	if base == nil || len(base.Types) == 0 {
		return nil, fmt.Errorf("btf: split BTF without a base")
	}
	data = append([]byte(nil), data...)
	hdr, sec, err := parseHeader(data, order)
	if err != nil {
		return nil, err
	}

	s := &Spec{
		Header:      hdr,
		ByteOrder:   order,
		Strings:     data[sec.strStart:sec.strEnd],
		Types:       []Type{{Kind: KindVoid}},
		mergedSplit: true,
		base:        base,
		startID:     uint32(len(base.Types)),
		startStrOff: uint32(len(base.Strings)),
	}
	if err := s.parseTypes(data[sec.typeStart:sec.typeEnd], s.startID); err != nil {
		return nil, err
	}
	for i := 1; i < len(s.Types); i++ {
		if err := s.resolveNames(&s.Types[i]); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// StartID returns the ID of the first type the spec owns: 1, or the type
// count of the base for a split spec.
func (s *Spec) StartID() uint32 {
	if s.base != nil {
		return s.startID
	}
	return 1
}
