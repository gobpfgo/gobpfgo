// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/elf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: elf_find_func_offset_from_file, elf_sym_offset

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"debug/elf"
	"fmt"

	"golang.org/x/sys/unix"
)

// findFuncOffset returns the file offset of name in the ELF file at path.
//
// Uprobe offsets are file offsets, not virtual addresses: the symbol value is
// translated through its section address and offset, the same way libbpf
// does. Symbol version suffixes such as name@@LIB are not handled.
func findFuncOffset(path, name string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		syms, err = f.DynamicSymbols()
		if err != nil {
			return 0, err
		}
	}
	for _, sym := range syms {
		if sym.Name != name || elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		if sym.Section == elf.SHN_UNDEF || int(sym.Section) >= len(f.Sections) {
			continue
		}
		section := f.Sections[sym.Section]
		if sym.Value < section.Addr {
			continue
		}
		return sym.Value - section.Addr + section.Offset, nil
	}

	return 0, fmt.Errorf("%w: function %s not found in %s", unix.ENOENT, name, path)
}
