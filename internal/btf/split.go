// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__parse_split

package btf

import "fmt"

// MergeSplit appends a module's split BTF types to the vmlinux base.
//
// The module type IDs start after the base types and the module's references
// already use those split IDs. The merged spec keeps the module string table;
// the type names are already resolved, so target matching never needs to
// resolve a base string through it.
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
		ByteOrder: base.ByteOrder,
		Types:     types,
		Strings:   module.Strings,
	}, nil
}
