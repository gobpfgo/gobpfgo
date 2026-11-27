// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__collect_rodata_relos, cmp_func_ptrs, bpf_object__collect_relos

package libbpf

import (
	"cmp"
	"fmt"
	"slices"

	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// funcPtrSize is the size of a function pointer in BPF data.
const funcPtrSize = 8

// funcPtr is a pointer to a .text function stored in read-only data, such as
// an entry of a table of functions, a structure of operations or a vtable. A
// program calls through it with callx. secIdx is the ELF section that holds
// the pointer, secOff the pointer's offset in it and textOff the function's
// offset in .text.
type funcPtr struct {
	secIdx  int
	secOff  uint64
	textOff uint64
}

// funcPtrMap is one program's copy of a read-only data map with function
// pointers. The kernel turns a function's offset in the program into its
// address, and the offsets differ between programs, so each program that has
// callx loads its own copy, fd, of the map m.
type funcPtrMap struct {
	prog *BpfProgram
	m    *BpfMap
	fd   int
}

// collectFuncPtrs returns the pointers to .text functions in the read-only
// data sections of e, sorted by section and offset. A pointer is an
// R_BPF_64_ABS64 relocation against a static function, through the .text
// section symbol, or against a global or weak function, with the offset from
// the symbol stored at the relocated location. A relocation of another type
// or against another symbol, such as a pointer to data, is skipped. So is a
// pointer that is not 8-byte aligned or does not fit in the section, and one
// whose function offset is not instruction aligned, because the kernel
// recognizes aligned pointers to functions only. A relocation against a
// symbol that does not exist is an error.
func collectFuncPtrs(e *objelf.Object, textShndx int) ([]funcPtr, error) {
	var ptrs []funcPtr
	relIdx := 0
	for i, rel := range e.Relocations {
		// The relocations of one section are next to each other; relIdx
		// counts them from 0 for the error message.
		if i > 0 && rel.SectionIndex == e.Relocations[i-1].SectionIndex {
			relIdx++
		} else {
			relIdx = 0
		}
		if rel.SectionIndex <= 0 || rel.SectionIndex >= len(e.Sections) {
			continue
		}
		sec := &e.Sections[rel.SectionIndex]
		if dataSectionType(sec) != libbpfMapRodata {
			continue
		}
		if int(rel.SymbolIndex) >= len(e.Symbols) {
			return nil, fmt.Errorf("sec '.rel%s': symbol #%d not found for relo #%d", sec.Name, rel.SymbolIndex, relIdx)
		}

		ptr, ok := funcPtrFromReloc(e, sec, rel, textShndx)
		if ok {
			ptrs = append(ptrs, ptr)
		}
	}

	slices.SortStableFunc(ptrs, cmpFuncPtrs)
	return ptrs, nil
}

// funcPtrFromReloc returns the function pointer that rel, a relocation in the
// read-only data section sec, stores, and whether it is one.
func funcPtrFromReloc(e *objelf.Object, sec *objelf.Section, rel objelf.Reloc, textShndx int) (funcPtr, bool) {
	sym := e.Symbols[rel.SymbolIndex]
	if rel.Type != objelf.R_BPF_64_ABS64 || !symIsSubprog(sym, textShndx) {
		return funcPtr{}, false
	}

	size := uint64(len(sec.Data))
	if rel.Offset%funcPtrSize != 0 || rel.Offset >= size || size-rel.Offset < funcPtrSize {
		return funcPtr{}, false
	}

	addend := e.ByteOrder.Uint64(sec.Data[rel.Offset:])
	textOff := sym.Value + addend
	if textOff%bpfInsnSize != 0 {
		return funcPtr{}, false
	}
	return funcPtr{secIdx: rel.SectionIndex, secOff: rel.Offset, textOff: textOff}, true
}

// cmpFuncPtrs orders function pointers by section and then by offset.
func cmpFuncPtrs(a, b funcPtr) int {
	if a.secIdx != b.secIdx {
		return cmp.Compare(a.secIdx, b.secIdx)
	}
	return cmp.Compare(a.secOff, b.secOff)
}

// assignFuncPtrs gives each read-only data map the pointers of its section,
// a slice of ptrs, which must be sorted with cmpFuncPtrs. A map whose
// section has none gets nil.
func assignFuncPtrs(maps []*BpfMap, ptrs []funcPtr) {
	for _, m := range maps {
		if m.libbpfType != libbpfMapRodata {
			continue
		}
		first := slices.IndexFunc(ptrs, func(p funcPtr) bool { return p.secIdx == m.secIdx })
		if first < 0 {
			continue
		}
		last := first
		for last < len(ptrs) && ptrs[last].secIdx == m.secIdx {
			last++
		}
		m.funcPtrs = ptrs[first:last:last]
	}
}

// closeFuncPtrMaps closes every program's copy of a map with function
// pointers and forgets them.
func (obj *BpfObject) closeFuncPtrMaps() {
	for _, c := range obj.funcPtrMaps {
		if c.fd >= 0 {
			unix.Close(c.fd)
		}
	}
	obj.funcPtrMaps = nil
}
