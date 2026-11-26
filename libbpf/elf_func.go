// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/elf.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: elf_find_func_offset_from_file, elf_sym_offset, elf_find_func_offset_from_archive

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"fmt"
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
