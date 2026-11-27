// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: prog_has_callx, bpf_object__append_func_ptrs, bpf_object__append_func_ptrs_code, create_func_ptr_map

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// funcPtrMapCreator creates the kernel map of a program's copy of the
// read-only data map m, whose only element is value, and returns its
// descriptor. BpfObjectLoad uses createFuncPtrMap.
type funcPtrMapCreator func(m *BpfMap, value []byte) (int, error)

// progHasCallx reports whether insns has an indirect call,
// BPF_JMP|BPF_CALL|BPF_X.
func progHasCallx(insns []byte) bool {
	for off := 0; off+bpfInsnLength <= len(insns); off += bpfInsnLength {
		if insns[off] == bpfJMP|bpfCall|bpfSourceX {
			return true
		}
	}
	return false
}

// appendFuncPtrs sets code.hasCallx when code, with the subprograms it calls
// already appended, has an indirect call. Such a program may call any static
// function that the read-only data it loads points to, so each one code does
// not hold yet is appended and relocated, with its relocations. A global
// function is not appended, because callx cannot call it. A program without
// callx cannot call the functions, and the kernel does not look for pointers
// in its data.
func (r *relocator) appendFuncPtrs(code *progCode) error {
	code.hasCallx = progHasCallx(code.insns)
	if !code.hasCallx {
		return nil
	}

	// An appended function brings its relocations, which this loop visits
	// as well.
	for i := 0; i < len(code.relocs); i++ {
		rel := code.relocs[i]
		if rel.kind != relocData || len(rel.m.funcPtrs) == 0 {
			continue
		}
		if err := r.appendFuncPtrsCode(code, rel.m); err != nil {
			return err
		}
	}
	return nil
}

// appendFuncPtrsCode appends to code every static function that the data of
// m points to and that code does not hold yet. A pointer must point at the
// start of a .text function.
func (r *relocator) appendFuncPtrsCode(code *progCode, m *BpfMap) error {
	for _, ptr := range m.funcPtrs {
		subprog := funcPtrSubprog(r.obj, ptr)
		if subprog == nil {
			return fmt.Errorf("prog '%s': map '%s': no function at .text+%d for the pointer at offset %d",
				code.prog.name, BpfMapName(m), ptr.textOff, ptr.secOff)
		}
		if subprog.symGlobal {
			continue
		}
		if _, ok := code.subInsnOff[subprog]; ok {
			continue
		}
		r.appendSubprogCode(code, subprog)
		if err := r.relocCode(code, subprog); err != nil {
			return err
		}
	}
	return nil
}

// funcPtrSubprog returns the .text function that starts where ptr points, or
// nil when no function starts there.
func funcPtrSubprog(obj *BpfObject, ptr funcPtr) *BpfProgram {
	secInsnOff := ptr.textOff / bpfInsnLength
	subprog := findProgBySecInsn(obj.programs, obj.textShndx, int(secInsnOff))
	if subprog == nil || uint64(subprog.secInsnOff) != secInsnOff {
		return nil
	}
	return subprog
}

// funcPtrMapFD returns the descriptor of the copy of the read-only data map
// m that code's program loads. The first call for a program and a map makes
// the copy's value with funcPtrMapValue and creates the copy with newMap; the
// object keeps the descriptor, later calls return it, and BpfObjectClose
// closes it.
func funcPtrMapFD(code *progCode, m *BpfMap, newMap funcPtrMapCreator) (int, error) {
	obj := code.prog.obj
	for _, c := range obj.funcPtrMaps {
		if c.prog == code.prog && c.m == m {
			return c.fd, nil
		}
	}

	value, err := funcPtrMapValue(code, m)
	if err != nil {
		return -1, err
	}
	fd, err := newMap(m, value)
	if err != nil {
		return -1, err
	}
	obj.funcPtrMaps = append(obj.funcPtrMaps, funcPtrMap{prog: code.prog, m: m, fd: fd})
	return fd, nil
}

// funcPtrMapValue returns the value of code's copy of the read-only data map
// m: the map's initial value with each function pointer replaced by the byte
// offset of that function in code. The kernel recognizes a pointer by that
// value and turns it into the function's address. A pointer to a function
// code does not hold, a global one callx cannot call, is 0. A pointer that
// does not fit in the value is an error.
func funcPtrMapValue(code *progCode, m *BpfMap) ([]byte, error) {
	if m.initialValue == nil {
		return nil, &Error{Op: "bpf_map_create", Errno: unix.EINVAL, Log: fmt.Sprintf("map '%s' has no initial value", BpfMapName(m))}
	}

	obj := code.prog.obj
	value := make([]byte, m.valueSize)
	copy(value, m.initialValue)
	for _, ptr := range m.funcPtrs {
		if ptr.secOff+funcPtrSize > uint64(m.valueSize) {
			return nil, &Error{
				Op:    "bpf_map_create",
				Errno: libbpfErrnoFormat,
				Log:   fmt.Sprintf("map '%s': pointer at offset %d past the value", BpfMapName(m), ptr.secOff),
			}
		}

		var off uint64
		if subprog := funcPtrSubprog(obj, ptr); subprog != nil {
			if subInsnOff, ok := code.subInsnOff[subprog]; ok {
				off = uint64(subInsnOff) * bpfInsnLength
			}
		}
		binary.NativeEndian.PutUint64(value[ptr.secOff:], off)
	}
	return value, nil
}

// createFuncPtrMap creates a program's copy of the read-only data map m: a
// single-element array named like m and read-only for programs, with value as
// its element. The copy is frozen, so neither user space nor a program can
// change it. On failure the map is closed.
func createFuncPtrMap(m *BpfMap, value []byte) (int, error) {
	attr := &sys.MapCreateAttr{
		MapType:    uint32(BPF_MAP_TYPE_ARRAY),
		KeySize:    internalMapKeySize,
		ValueSize:  uint32(len(value)),
		MaxEntries: 1,
		MapFlags:   unix.BPF_F_RDONLY_PROG,
	}
	attr.SetMapName(m.name)

	fd, err := sys.MapCreate(attr, nil)
	if err != nil {
		return -1, &Error{Op: "bpf_map_create", Errno: errnoFromError(err), Log: BpfMapName(m)}
	}

	key := make([]byte, internalMapKeySize)
	if err := sys.MapUpdateElem(fd, key, value, 0); err != nil {
		unix.Close(fd)
		return -1, &Error{Op: "bpf_map_update_elem", Errno: errnoFromError(err), Log: BpfMapName(m)}
	}
	if err := sys.MapFreeze(fd); err != nil {
		unix.Close(fd)
		return -1, &Error{Op: "bpf_map_freeze", Errno: errnoFromError(err), Log: BpfMapName(m)}
	}
	return fd, nil
}
