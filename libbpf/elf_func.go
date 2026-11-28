// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/elf.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: elf_find_func_offset_from_file, elf_sym_offset, elf_find_func_offset_from_archive, elf_resolve_pattern_offsets, elf_sym_iter_new

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/zip"
	"golang.org/x/sys/unix"
)

// archiveSep separates an archive path from the path of a member inside it,
// as in "app.apk!/lib/arm64-v8a/libfoo.so".
const archiveSep = "!/"

// libbpfErrnoFormat is libbpf's LIBBPF_ERRNO__FORMAT, the error code for an
// input the library cannot use. It lies above the kernel errno range.
const libbpfErrnoFormat syscall.Errno = 4001

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

	return elfFuncOffset(f, path, name)
}

// elfFuncOffset returns the file offset of the function name in f. path only
// names the file in the error.
func elfFuncOffset(f *elf.File, path, name string) (uint64, error) {
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

// findFuncOffsetFromArchive returns the offset of the function funcName in
// the archive file at archivePath, where fileName is an ELF member stored
// without compression. The offset is the member's data offset in the archive
// plus the function's offset in the member, so a uprobe on the archive file
// hits the function when the member is mapped from the archive in place.
//
// The error wraps the archive open or lookup errno, LIBBPF_ERRNO__FORMAT
// (4001) when the member is compressed or is not an ELF file, or ENOENT when
// the member has no such function.
func findFuncOffsetFromArchive(archivePath, fileName, funcName string) (uint64, error) {
	archive, err := zip.Open(archivePath)
	if err != nil {
		return 0, err
	}
	defer archive.Close()

	entry, err := archive.FindEntry(fileName)
	if err != nil {
		return 0, err
	}
	if entry.Compression != 0 {
		return 0, fmt.Errorf("%w: entry %s of %s is compressed and cannot be handled", libbpfErrnoFormat, fileName, archivePath)
	}

	f, err := elf.NewFile(bytes.NewReader(entry.Data))
	if err != nil {
		return 0, fmt.Errorf("%w: elf file %s in %s: %v", libbpfErrnoFormat, fileName, archivePath, err)
	}
	defer f.Close()

	offset, err := elfFuncOffset(f, fileName, funcName)
	if err != nil {
		return 0, err
	}
	return offset + uint64(entry.DataOffset), nil
}

// elfResolvePatternOffsets returns the file offsets of the functions in the
// ELF file at path whose symbol names match pattern, as globMatch does, in
// symbol table order.
//
// The static symbol table is searched first. Only when it is missing or has
// no match is the dynamic symbol table searched, so a function listed in
// both is found once. Names are matched as the symbol table stores them;
// debug/elf does not append the .gnu.version suffix. Only STT_FUNC symbols that
// name a section count; an undefined symbol, SHN_UNDEF, has no file offset
// and is skipped, as libbpf's symbol iterator skips it.
//
// An error opening path returns its errno, a file that is not ELF or has a
// symbol table it cannot read returns EINVAL, and no match returns ENOENT.
func elfResolvePatternOffsets(path, pattern string) ([]uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	f, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", unix.EINVAL, path, err)
	}

	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		syms, err := elfSymbolTable(f, typ)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v symbols: %v", unix.EINVAL, path, typ, err)
		}

		var offsets []uint64
		for _, sym := range syms {
			if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Section == elf.SHN_UNDEF ||
				int(sym.Section) >= len(f.Sections) {
				continue
			}
			if !globMatch(sym.Name, pattern) {
				continue
			}
			section := f.Sections[sym.Section]
			if sym.Value < section.Addr {
				continue
			}
			offsets = append(offsets, sym.Value-section.Addr+section.Offset)
		}
		if len(offsets) > 0 {
			return offsets, nil
		}
	}

	return nil, fmt.Errorf("%w: no function matches %q in %s", unix.ENOENT, pattern, path)
}

// elfSymbolTable returns the symbols of the first section of type typ in f,
// SHT_SYMTAB or SHT_DYNSYM, without the null symbol. A missing or empty
// table has no symbols; one without an entry size cannot be read.
func elfSymbolTable(f *elf.File, typ elf.SectionType) ([]elf.Symbol, error) {
	section := f.SectionByType(typ)
	if section == nil {
		return nil, nil
	}
	if section.Entsize == 0 {
		return nil, errors.New("zero symbol entry size")
	}
	if section.Size == 0 {
		return nil, nil
	}
	var syms []elf.Symbol
	var err error
	if typ == elf.SHT_DYNSYM {
		syms, err = f.DynamicSymbols()
	} else {
		syms, err = f.Symbols()
	}
	if errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil
	}
	return syms, err
}

// findUprobeFuncOffset resolves funcName for a uprobe on binaryPath and
// returns the path the probe event must name with the function's offset in
// that file.
//
// A binaryPath of the form "archive!/member" names an ELF member of a zip
// archive: the function is found in the member and the result is the archive
// path with the combined offset, because the kernel probes the archive file.
// Any other binaryPath is an ELF file and is returned unchanged.
func findUprobeFuncOffset(binaryPath, funcName string) (string, uint64, error) {
	archivePath, member, ok := strings.Cut(binaryPath, archiveSep)
	if !ok {
		offset, err := findFuncOffset(binaryPath, funcName)
		return binaryPath, offset, err
	}

	offset, err := findFuncOffsetFromArchive(archivePath, member, funcName)
	return archivePath, offset, err
}
