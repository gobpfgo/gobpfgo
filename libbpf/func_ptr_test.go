// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const callxObject = "../testdata/progs/callx.bpf.o"

// bpfJMP32 is the 32-bit jump instruction class, which has no callx.
const bpfJMP32 = 0x06

// callxBias is callx_bias, the plain read-only value in .rodata.
const callxBias = 0x100

// callxMarks are what the programs of callx.bpf.o record, by slot:
// callx_first(0), callx_second(0), which adds callx_third(0), and callx_bias.
var callxMarks = []uint64{0x1111, 0x2222 + 0x4444, callxBias}

// callxPointers are the function pointers of callx.bpf.o, sorted by section
// and offset: callx_table_one after callx_bias in .rodata, callx_table_two in
// .rodata.two and callx_table_three in .rodata.three.
var callxPointers = []struct {
	section  string
	off      uint64
	function string
}{
	{".rodata", 8, "callx_first"},
	{".rodata", 16, "callx_second"},
	{".rodata", 24, "callx_global"},
	{".rodata.two", 0, "callx_second"},
	{".rodata.two", 8, "callx_first"},
	{".rodata.three", 0, "callx_third"},
}

// callxLayouts are the functions each main program of callx.bpf.o loads, in
// order, and whether it has callx. handle_callx_one calls callx_dispatch,
// whose table load appends callx_first and callx_second; handle_callx_two's
// table lists them the other way round. In both, the table load that
// callx_second brings appends callx_third last. No program gets the global
// callx_global, and handle_callx_plain, without callx, gets nothing.
var callxLayouts = map[string]struct {
	parts    []string
	hasCallx bool
}{
	"handle_callx_one":   {[]string{"handle_callx_one", "callx_dispatch", "callx_first", "callx_second", "callx_third"}, true},
	"handle_callx_two":   {[]string{"handle_callx_two", "callx_second", "callx_first", "callx_third"}, true},
	"handle_callx_plain": {[]string{"handle_callx_plain"}, false},
}

// callxCopies are the copies the relocation of callx.bpf.o makes, in order:
// the program, the map a table it loads is in, the generated loader's map
// index after the object's four maps, and the copy's value as 64-bit words.
// The offsets are the byte offsets of the functions in libbpf's code: at
// instructions 20, 23 and 29 in handle_callx_one, and 18, 24 and 27 in
// handle_callx_two. The global function's slot is 0. Both programs copy
// .rodata.three, with callx_third at their own offset. The load replaces the
// offsets, see callxReached.
var callxCopies = []struct {
	prog  string
	m     string
	fd    int
	value []uint64
}{
	{"handle_callx_one", ".rodata", 4, []uint64{callxBias, 20 * 8, 23 * 8, 0}},
	{"handle_callx_one", ".rodata.three", 5, []uint64{29 * 8}},
	{"handle_callx_two", ".rodata.two", 6, []uint64{18 * 8, 24 * 8}},
	{"handle_callx_two", ".rodata.three", 7, []uint64{27 * 8}},
}

// callxReached are the functions each program with callx keeps after a
// privileged load, in order. The tables are frozen read-only data, so the
// verifier knows the function each table load reaches and removes the
// appended functions it never reaches as dead code. The kernel then stores
// the jited address of each kept function in the program's copies and 0 for
// a removed one. handle_callx_one reaches callx_first through the first
// table; handle_callx_two reaches callx_second through the second and
// callx_third through the third.
var callxReached = map[string][]string{
	"handle_callx_one": {"handle_callx_one", "callx_dispatch", "callx_first"},
	"handle_callx_two": {"handle_callx_two", "callx_second", "callx_third"},
}

// words encodes 64-bit values in native byte order.
func words(values ...uint64) []byte {
	buf := make([]byte, 8*len(values))
	for i, v := range values {
		binary.NativeEndian.PutUint64(buf[8*i:], v)
	}
	return buf
}

// elfSectionIndex returns the index of the section name in e.
func elfSectionIndex(t *testing.T, e *objelf.Object, name string) int {
	t.Helper()

	for i, s := range e.Sections {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("no section %s", name)
	return 0
}

// elfSymbolIndex returns the index of the symbol name in e.
func elfSymbolIndex(t *testing.T, e *objelf.Object, name string) int {
	t.Helper()

	for i, s := range e.Symbols {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("no symbol %s", name)
	return 0
}

// elfReloc returns the relocation at offset off of the section name in e.
func elfReloc(t *testing.T, e *objelf.Object, name string, off uint64) *objelf.Reloc {
	t.Helper()

	idx := elfSectionIndex(t, e, name)
	for i, rel := range e.Relocations {
		if rel.SectionIndex == idx && rel.Offset == off {
			return &e.Relocations[i]
		}
	}
	t.Fatalf("no relocation at %s+%d", name, off)
	return nil
}

// wantCallxPointers returns callxPointers as the function pointers of e.
func wantCallxPointers(t *testing.T, e *objelf.Object) []funcPtr {
	t.Helper()

	var ptrs []funcPtr
	for _, p := range callxPointers {
		ptrs = append(ptrs, funcPtr{
			secIdx:  elfSectionIndex(t, e, p.section),
			secOff:  p.off,
			textOff: e.Symbols[elfSymbolIndex(t, e, p.function)].Value,
		})
	}
	return ptrs
}

// TestFuncPtrCollect checks the function pointers of callx.bpf.o after open:
// the three of the first table in .rodata, after callx_bias, then those of
// .rodata.two and .rodata.three, sorted by section and offset, each with its
// function's .text offset. The static functions' pointers are relocated against the .text
// section symbol with the function offset stored in place, the global one's
// against its own symbol. Each read-only data map holds the slice of the
// object's pointers in its section, and the .maps map none.
func TestFuncPtrCollect(t *testing.T) {
	obj := openSubprogObject(t, "callx.bpf.o")
	want := wantCallxPointers(t, obj.elf)
	if !reflect.DeepEqual(obj.funcPtrs, want) {
		t.Fatalf("function pointers = %+v, want %+v", obj.funcPtrs, want)
	}

	for _, tt := range []struct {
		name        string
		first, last int
	}{
		{"callx_marks", 0, 0},
		{".rodata", 0, 3},
		{".rodata.two", 3, 5},
		{".rodata.three", 5, 6},
	} {
		m := BpfObjectFindMapByName(obj, tt.name)
		if m == nil {
			t.Fatalf("no map %s", tt.name)
		}
		if !slices.Equal(m.funcPtrs, want[tt.first:tt.last]) {
			t.Errorf("%s: function pointers = %+v, want %+v", tt.name, m.funcPtrs, want[tt.first:tt.last])
		}
		if len(m.funcPtrs) > 0 && &m.funcPtrs[0] != &obj.funcPtrs[tt.first] {
			t.Errorf("%s: function pointers are not the object's slice", tt.name)
		}
	}
}

// TestFuncPtrCollectChecks changes callx.bpf.o's relocations or read-only
// data and collects the pointers again. Most cases change the pointer at
// .rodata.two+8 and expect it skipped: an unaligned offset, an offset at
// the section end, a pointer that does not fit in the section, a function
// offset that is not instruction aligned, another relocation type, a pointer
// to data and a relocation outside read-only data. The stored offset is
// added to the symbol value, the relocation order does not change the sorted
// result, and a missing symbol is an error.
func TestFuncPtrCollectChecks(t *testing.T) {
	// The pointer at .rodata.two+8 is callxPointers[4].
	skipped := func(ptrs []funcPtr) []funcPtr { return slices.Delete(ptrs, 4, 5) }
	unchanged := func(ptrs []funcPtr) []funcPtr { return ptrs }
	store := func(t *testing.T, e *objelf.Object, name string, off, value uint64) {
		e.ByteOrder.PutUint64(e.Sections[elfSectionIndex(t, e, name)].Data[off:], value)
	}

	tests := []struct {
		name   string
		change func(t *testing.T, e *objelf.Object)
		want   func(ptrs []funcPtr) []funcPtr
		err    string
	}{
		{"unaligned offset", func(t *testing.T, e *objelf.Object) {
			elfReloc(t, e, ".rodata.two", 8).Offset = 9
		}, skipped, ""},
		{"offset at the section end", func(t *testing.T, e *objelf.Object) {
			elfReloc(t, e, ".rodata.two", 8).Offset = 16
		}, skipped, ""},
		{"pointer past the section end", func(t *testing.T, e *objelf.Object) {
			sec := &e.Sections[elfSectionIndex(t, e, ".rodata.two")]
			sec.Data = sec.Data[:12]
		}, skipped, ""},
		{"unaligned function", func(t *testing.T, e *objelf.Object) {
			store(t, e, ".rodata.two", 8, 0x31)
		}, skipped, ""},
		{"absolute 32-bit relocation", func(t *testing.T, e *objelf.Object) {
			elfReloc(t, e, ".rodata.two", 8).Type = objelf.R_BPF_64_ABS32
		}, skipped, ""},
		{"pointer to data", func(t *testing.T, e *objelf.Object) {
			elfReloc(t, e, ".rodata.two", 8).SymbolIndex = uint32(elfSymbolIndex(t, e, "callx_bias"))
		}, skipped, ""},
		{"not read-only data", func(t *testing.T, e *objelf.Object) {
			elfReloc(t, e, ".rodata.two", 8).SectionIndex = elfSectionIndex(t, e, ".maps")
		}, skipped, ""},
		{"symbol value plus stored offset", func(t *testing.T, e *objelf.Object) {
			e.Symbols[elfSymbolIndex(t, e, "callx_global")].Value = 0x18
			store(t, e, ".rodata", 24, 0x18)
		}, func(ptrs []funcPtr) []funcPtr {
			ptrs[2].textOff = 0x30
			return ptrs
		}, ""},
		{"reversed relocations", func(t *testing.T, e *objelf.Object) {
			slices.Reverse(e.Relocations)
		}, unchanged, ""},
		{"missing symbol", func(t *testing.T, e *objelf.Object) {
			elfReloc(t, e, ".rodata.two", 8).SymbolIndex = uint32(len(e.Symbols))
		}, nil, "sec '.rel.rodata.two': symbol #%d not found for relo #1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := objelf.Open(callxObject)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			want := wantCallxPointers(t, e)
			tt.change(t, e)

			got, err := collectFuncPtrs(e, elfSectionIndex(t, e, ".text"))
			if tt.err != "" {
				if msg := fmt.Sprintf(tt.err, len(e.Symbols)); err == nil || err.Error() != msg {
					t.Fatalf("collectFuncPtrs = %+v, %v; want %q", got, err, msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("collectFuncPtrs: %v", err)
			}
			if want = tt.want(want); !slices.Equal(got, want) {
				t.Errorf("function pointers = %+v, want %+v", got, want)
			}
		})
	}
}

// TestProgHasCallx checks the callx detection: only a 64-bit jump class call
// with the register source is an indirect call, at any instruction boundary.
// A helper or subprogram call, the 32-bit jump class and the opcode byte
// inside an immediate are not.
func TestProgHasCallx(t *testing.T) {
	exit := bpfInsn{Code: bpfJMP | bpfExit}
	callx := bpfInsn{Code: bpfJMP | bpfCall | bpfSourceX, Dst: 2}
	tests := []struct {
		name  string
		insns []bpfInsn
		want  bool
	}{
		{"no code", nil, false},
		{"exit", []bpfInsn{exit}, false},
		{"helper call", []bpfInsn{{Code: bpfJMP | bpfCall, Imm: 2}, exit}, false},
		{"subprogram call", []bpfInsn{{Code: bpfJMP | bpfCall, Src: bpfPseudoCall, Imm: 1}, exit}, false},
		{"callx", []bpfInsn{callx, exit}, true},
		{"callx last", []bpfInsn{exit, exit, callx}, true},
		{"32-bit jump class", []bpfInsn{{Code: bpfJMP32 | bpfCall | bpfSourceX, Dst: 2}, exit}, false},
		{"opcode in an immediate", []bpfInsn{{Code: bpfLD | bpfImm | bpfSizeDW, Imm: 0x0d8d8d8d}, {Imm: 0x8d}, exit}, false},
	}
	for _, tt := range tests {
		insns := make([]byte, len(tt.insns)*bpfInsnLength)
		for i, insn := range tt.insns {
			encodeBpfInsn(insns[i*bpfInsnLength:], insn)
		}
		if got := progHasCallx(insns); got != tt.want {
			t.Errorf("%s: progHasCallx = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestCallxRelocate relocates callx.bpf.o without a kernel and checks each
// main program's code against callxLayouts. handle_callx_one has no callx of
// its own: it gets it with callx_dispatch, and the table load that appends
// callx_first and callx_second is one of the relocations callx_dispatch
// brought. callx_third shows that the relocations of a function appended for
// a pointer are visited too.
func TestCallxRelocate(t *testing.T) {
	obj := openSubprogObject(t, "callx.bpf.o")
	codes := relocateObjectCode(t, obj)
	if len(codes) != len(callxLayouts) {
		t.Fatalf("%d main programs, want %d", len(codes), len(callxLayouts))
	}

	for name, layout := range callxLayouts {
		code := codes[name]
		if code == nil {
			t.Fatalf("no code for %s", name)
		}
		checkSubprogParts(t, obj, code, layout.parts)
		if code.hasCallx != layout.hasCallx {
			t.Errorf("%s: hasCallx = %v, want %v", name, code.hasCallx, layout.hasCallx)
		}
	}
	if progHasCallx(BpfObjectFindProgramByName(obj, "handle_callx_one").insns) {
		t.Error("handle_callx_one has callx of its own")
	}
}

// libbpfFuncOffsets returns the byte offset of each function in libbpf's code
// of the program name, from the function records of the subprog oracle.
func libbpfFuncOffsets(t *testing.T, obj *BpfObject, fixture subprogFixture, name string) map[string]uint64 {
	t.Helper()

	for _, p := range fixture.Programs {
		if p.Name != name {
			continue
		}
		offsets := make(map[string]uint64, len(p.FuncInfo))
		for _, rec := range p.FuncInfo {
			fn, err := obj.btf.TypeByID(rec.TypeID)
			if err != nil {
				t.Fatalf("%s: function record type %d: %v", name, rec.TypeID, err)
			}
			offsets[fn.Name] = uint64(rec.InsnOff) * bpfInsnLength
		}
		return offsets
	}
	t.Fatalf("no program %s in the fixture", name)
	return nil
}

// TestFuncPtrMapValue checks the copies the relocation of callx.bpf.o makes,
// against callxCopies: one per program with callx and map with function
// pointers it loads, numbered after the object's four maps as libbpf's
// generated loader numbers them. Each copy is the map's initial value with every pointer set
// to its function's byte offset in the program and the global function's
// pointer set to 0. The offsets are checked against the function records of
// libbpf's code too.
func TestFuncPtrMapValue(t *testing.T) {
	fixture := loadSubprogFixture(t, "subprog-callx.json")
	obj := openSubprogObject(t, "callx.bpf.o")
	_, copies, err := relocateWithStandIns(t, obj, objectExt(t, obj), argCtxTagSupported)
	if err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if len(copies) != len(callxCopies) {
		t.Fatalf("%d copies, want %d", len(copies), len(callxCopies))
	}

	for i, want := range callxCopies {
		c := copies[i]
		m := BpfObjectFindMapByName(obj, want.m)
		if c.prog.name != want.prog || c.m != m || c.fd != want.fd {
			t.Errorf("copy %d = %s's copy of %s with descriptor %d, want %s's of %s with %d",
				i, c.prog.name, BpfMapName(c.m), c.fd, want.prog, want.m, want.fd)
		}
		if !bytes.Equal(c.value, words(want.value...)) {
			t.Errorf("%s's copy of %s = %x, want %x", want.prog, want.m, c.value, words(want.value...))
		}

		offsets := libbpfFuncOffsets(t, obj, fixture, want.prog)
		for _, ptr := range m.funcPtrs {
			fn := funcPtrSubprog(obj, ptr)
			got := binary.NativeEndian.Uint64(c.value[ptr.secOff:])
			if got != offsets[fn.name] {
				t.Errorf("%s: pointer to %s at %s+%d = %d, libbpf's code has it at %d",
					want.prog, fn.name, want.m, ptr.secOff, got, offsets[fn.name])
			}
		}
	}
}

// TestFuncPtrMapCache checks that a program gets one copy of a map: asking
// again for handle_callx_one's copy of .rodata returns it without creating
// another, while handle_callx_two gets its own copy of the same map, with
// callx_first and callx_second at its own offsets.
func TestFuncPtrMapCache(t *testing.T) {
	obj := openSubprogObject(t, "callx.bpf.o")
	codes := relocateObjectCode(t, obj)
	rodata := BpfObjectFindMapByName(obj, ".rodata")
	t.Cleanup(func() { obj.funcPtrMaps = nil })

	var created [][]byte
	create := func(_ *BpfMap, value []byte) (int, error) {
		created = append(created, value)
		return 100 + len(created), nil
	}
	fdFor := func(prog string) int {
		fd, err := funcPtrMapFD(codes[prog], rodata, create)
		if err != nil {
			t.Fatalf("%s: funcPtrMapFD: %v", prog, err)
		}
		return fd
	}

	first, again, other := fdFor("handle_callx_one"), fdFor("handle_callx_one"), fdFor("handle_callx_two")
	if first != 101 || again != first || other != 102 {
		t.Errorf("descriptors = %d, %d, %d; want 101, 101, 102", first, again, other)
	}
	want := [][]byte{words(callxBias, 20*8, 23*8, 0), words(callxBias, 24*8, 18*8, 0)}
	if !slices.EqualFunc(created, want, bytes.Equal) {
		t.Errorf("created %x, want %x", created, want)
	}
	if len(obj.funcPtrMaps) != 2 {
		t.Errorf("object has %d copies, want 2", len(obj.funcPtrMaps))
	}
}

// TestFuncPtrMapPatch checks the global data loads of callx.bpf.o after
// relocation, in relocation order. A program with callx loads its copies of
// its tables' maps, each with the table's offset in the map value;
// handle_callx_plain, without callx, loads callx_bias from the object's
// .rodata map, although that map has function pointers.
func TestFuncPtrMapPatch(t *testing.T) {
	type load struct{ fd, off int32 }

	obj := openSubprogObject(t, "callx.bpf.o")
	codes := relocateObjectCode(t, obj)
	rodata := slices.Index(obj.maps, BpfObjectFindMapByName(obj, ".rodata"))

	want := map[string][]load{
		"handle_callx_one":   {{4, 8}, {5, 0}},
		"handle_callx_two":   {{6, 0}, {7, 0}},
		"handle_callx_plain": {{int32(rodata), 0}},
	}
	for name, wantLoads := range want {
		code := codes[name]
		var loads []load
		for _, r := range code.relocs {
			if r.kind != relocData {
				continue
			}
			insn, next := decodeBpfInsn(code.insns[r.insnOff:]), decodeBpfInsn(code.insns[r.insnOff+bpfInsnLength:])
			if insn.Src != bpfPseudoMapValue {
				t.Errorf("%s: load at insn %d has source %d, want a map value", name, r.insnOff/bpfInsnLength, insn.Src)
			}
			loads = append(loads, load{insn.Imm, next.Imm})
		}
		if !slices.Equal(loads, wantLoads) {
			t.Errorf("%s: loads from map value %v, want %v", name, loads, wantLoads)
		}
	}
}

// TestFuncPtrMapErrors checks the failures around the copies. A pointer that
// is not at the start of a .text function fails the relocation of a program
// with callx. A failed copy fails the data relocation with the copy's errno.
// A read-only data map the load does not create is poisoned in a program
// with callx, which gets no copy.
func TestFuncPtrMapErrors(t *testing.T) {
	t.Run("pointer inside a function", func(t *testing.T) {
		obj := openSubprogObject(t, "callx.bpf.o")
		BpfObjectFindMapByName(obj, ".rodata").funcPtrs[2].textOff = 8

		_, _, err := relocateObject(obj, objectExt(t, obj), nil, argCtxTagSupported, declTagSupported)
		msg := "prog 'handle_callx_one': map 'callx.rodata': no function at .text+8 for the pointer at offset 24"
		if !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), msg) {
			t.Fatalf("relocateObject = %v, want %q", err, msg)
		}
	})

	t.Run("failed copy", func(t *testing.T) {
		obj := openSubprogObject(t, "callx.bpf.o")
		codes, _, err := relocateObject(obj, objectExt(t, obj), nil, argCtxTagSupported, declTagSupported)
		if err != nil {
			t.Fatalf("relocateObject: %v", err)
		}
		for i, m := range obj.maps {
			m.fd = i
		}
		t.Cleanup(func() {
			for _, m := range obj.maps {
				m.fd = -1
			}
		})

		err = relocateObjectData(codes, func(*BpfMap, []byte) (int, error) {
			return -1, &Error{Op: "bpf_map_create", Errno: unix.EPERM}
		})
		msg := "can't create a copy of map 'callx.rodata' with pointers to functions"
		if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), msg) || obj.funcPtrMaps != nil {
			t.Fatalf("relocateObjectData = %v with %d copies, want EPERM and %q", err, len(obj.funcPtrMaps), msg)
		}
	})

	t.Run("map not created", func(t *testing.T) {
		obj := openSubprogObject(t, "callx.bpf.o")
		rodata := BpfObjectFindMapByName(obj, ".rodata")
		rodata.autocreate = false

		codes, copies, err := relocateWithStandIns(t, obj, objectExt(t, obj), argCtxTagSupported)
		if err != nil {
			t.Fatalf("relocate: %v", err)
		}
		if len(copies) != 3 || slices.ContainsFunc(copies, func(c standInCopy) bool { return c.m == rodata }) {
			t.Errorf("copies = %+v, want three, none of .rodata", copies)
		}

		code := codes[0]
		off := code.subInsnOff[findFunction(t, obj, "callx_dispatch")] * bpfInsnLength
		poison := bpfInsn{Code: bpfJMP | bpfCall, Imm: int32(poisonLdimm64MapBase + slices.Index(obj.maps, rodata))}
		if got := decodeBpfInsn(code.insns[off:]); code.prog.name != "handle_callx_one" || got != poison {
			t.Errorf("%s: table load = %+v, want %+v", code.prog.name, got, poison)
		}
	})
}

// TestFuncPtrMapsClose checks that the object closes every program's copy and
// forgets them, both when a load fails and on BpfObjectClose. Pipe
// descriptors stand in for the copies.
func TestFuncPtrMapsClose(t *testing.T) {
	closers := map[string]func(*BpfObject){
		"failed load": (*BpfObject).closeLoadFDs,
		"close":       BpfObjectClose,
	}
	for name, closeObj := range closers {
		t.Run(name, func(t *testing.T) {
			obj := openSubprogObject(t, "callx.bpf.o")
			var fds []int
			for _, prog := range []string{"handle_callx_one", "handle_callx_two"} {
				pipe := make([]int, 2)
				if err := unix.Pipe2(pipe, unix.O_CLOEXEC); err != nil {
					t.Fatalf("pipe: %v", err)
				}
				t.Cleanup(func() { unix.Close(pipe[1]) })
				fds = append(fds, pipe[0])
				obj.funcPtrMaps = append(obj.funcPtrMaps, funcPtrMap{prog: BpfObjectFindProgramByName(obj, prog), fd: pipe[0]})
			}

			closeObj(obj)
			if obj.funcPtrMaps != nil {
				t.Errorf("object keeps %d copies", len(obj.funcPtrMaps))
			}
			for _, fd := range fds {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					t.Errorf("copy descriptor %d is still open: %v", fd, err)
				}
			}
		})
	}
}

// TestFuncPtrMapCreate creates handle_callx_one's copy of callx.bpf.o's
// .rodata in the kernel and checks it: a single-element array without BTF,
// named like the map and read-only for programs, holding the program's
// function offsets and frozen, so user space cannot update it. It needs root
// or CAP_BPF and does not need a kernel that runs callx.
func TestFuncPtrMapCreate(t *testing.T) {
	obj := openSubprogObject(t, "callx.bpf.o")
	codes := relocateObjectCode(t, obj)
	rodata := BpfObjectFindMapByName(obj, ".rodata")
	value, err := funcPtrMapValue(codes["handle_callx_one"], rodata)
	if err != nil {
		t.Fatalf("funcPtrMapValue: %v", err)
	}

	fd, err := createFuncPtrMap(rodata, value)
	if err != nil {
		skipIfNotPermitted(t, err)
		t.Fatalf("createFuncPtrMap: %v", err)
	}
	defer unix.Close(fd)

	info, err := sys.MapInfoByFD(fd)
	if err != nil {
		t.Fatalf("MapInfoByFD: %v", err)
	}
	want := sys.MapInfo{
		Type:       uint32(BPF_MAP_TYPE_ARRAY),
		ID:         info.ID,
		KeySize:    internalMapKeySize,
		ValueSize:  uint32(len(value)),
		MaxEntries: 1,
		MapFlags:   unix.BPF_F_RDONLY_PROG,
		Name:       "callx.rodata",
	}
	if *info != want {
		t.Errorf("map info = %+v, want %+v", *info, want)
	}

	key := make([]byte, internalMapKeySize)
	got := make([]byte, len(value))
	if err := sys.MapLookupElem(fd, key, got, 0); err != nil || !bytes.Equal(got, words(callxCopies[0].value...)) {
		t.Errorf("value = %x, %v; want %x", got, err, words(callxCopies[0].value...))
	}
	if err := sys.MapUpdateElem(fd, key, value, 0); !errors.Is(err, unix.EPERM) {
		t.Errorf("update = %v, want EPERM from a frozen map", err)
	}
}

// openMapNames returns the names of the BPF maps the test process has open.
func openMapNames(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	var names []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil || target != "anon_inode:bpf-map" {
			continue
		}
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if info, err := sys.MapInfoByFD(fd); err == nil {
			names = append(names, info.Name)
		}
	}
	return names
}

// checkNoCallxMaps fails the test when the process still has a map of
// callx.bpf.o's read-only data, an object map or a copy, open.
func checkNoCallxMaps(t *testing.T, when string) {
	t.Helper()

	for _, name := range openMapNames(t) {
		if name == "callx.rodata" || name == ".rodata.two" || name == ".rodata.three" {
			t.Errorf("%s: map %s is still open", when, name)
		}
	}
}

// callxRejected reports whether err is the kernel refusing to load
// handle_callx_one, the first program with callx. A kernel without callx
// does not know that the static functions reached only through pointers are
// subprograms, so it rejects their function records, or the BPF_CALL with a
// register source when it checks the instructions first. TestSubprogOracle
// proves the code and the records are libbpf's.
func callxRejected(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Op != "bpf_prog_load" || !errors.Is(err, unix.EINVAL) ||
		!strings.HasPrefix(e.Log, "handle_callx_one: ") {
		return false
	}
	return strings.Contains(e.Log, "number of funcs in func_info doesn't match number of subprogs") ||
		strings.Contains(e.Log, "BPF_CALL uses reserved fields")
}

// TestCallxLoad loads callx.bpf.o, checks the copies with checkCallxCopies,
// attaches its three programs to do_sys_openat2, opens a file and checks
// callxMarks: handle_callx_one called callx_first and handle_callx_two
// callx_second through their tables, callx_second called callx_third through
// the third, and handle_callx_plain read callx_bias. Each mark is a distinct
// sum, so no other function ran, callx_global included. The copies are
// closed with the object.
//
// 7.4 runs callx. 5.10, 6.18 and 7.3.6 reject handle_callx_one; the test then
// checks that the failed load closed the maps, the copies included, and
// skips. It needs root: the kernel resolves the pointers and removes dead
// code only for a privileged load.
func TestCallxLoad(t *testing.T) {
	obj, err := BpfObjectOpenFile(callxObject, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer BpfObjectClose(obj)

	if err := BpfObjectLoad(obj); err != nil {
		skipIfNotPermitted(t, err)
		if !callxRejected(err) {
			t.Fatalf("load: %v", err)
		}
		if obj.funcPtrMaps != nil {
			t.Errorf("failed load keeps %d copies", len(obj.funcPtrMaps))
		}
		checkNoCallxMaps(t, "after the failed load")
		t.Skipf("kernel rejects callx: %v", err)
	}

	checkCallxCopies(t, obj)
	attachKprobes(t, obj, map[string]string{
		"handle_callx_one":   "do_sys_openat2",
		"handle_callx_two":   "do_sys_openat2",
		"handle_callx_plain": "do_sys_openat2",
	})
	triggerOpen(t)
	for slot, want := range callxMarks {
		if got := mapSlot(t, obj, "callx_marks", uint32(slot)); got != want {
			t.Errorf("callx_marks[%d] = %#x, want %#x", slot, got, want)
		}
	}

	BpfObjectClose(obj)
	checkNoCallxMaps(t, "after close")
}

// checkCallxCopies checks the copies of a loaded callx.bpf.o against
// callxCopies: each with its own descriptor, not an object map, and frozen.
// The load has replaced the function offsets in each copy, so it holds
// callxLoadedValue.
func checkCallxCopies(t *testing.T, obj *BpfObject) {
	t.Helper()

	if len(obj.funcPtrMaps) != len(callxCopies) {
		t.Fatalf("%d copies, want %d", len(obj.funcPtrMaps), len(callxCopies))
	}
	key := make([]byte, internalMapKeySize)
	for i, want := range callxCopies {
		c := obj.funcPtrMaps[i]
		if c.prog.name != want.prog || c.m != BpfObjectFindMapByName(obj, want.m) || c.fd < 0 {
			t.Fatalf("copy %d = %s's copy of %s with descriptor %d", i, c.prog.name, BpfMapName(c.m), c.fd)
		}
		for m := BpfObjectNextMap(obj, nil); m != nil; m = BpfObjectNextMap(obj, m) {
			if BpfMapFD(m) == c.fd {
				t.Errorf("%s's copy is object map %s", want.prog, BpfMapName(m))
			}
		}

		wantValue := callxLoadedValue(t, obj, want.prog, want.m)
		got := make([]byte, len(wantValue))
		if err := sys.MapLookupElem(c.fd, key, got, 0); err != nil || !bytes.Equal(got, wantValue) {
			t.Errorf("%s's copy of %s = %x, %v; want %x", want.prog, want.m, got, err, wantValue)
		}
		if err := sys.MapUpdateElem(c.fd, key, got, 0); !errors.Is(err, unix.EPERM) {
			t.Errorf("%s's copy update = %v, want EPERM from a frozen map", want.prog, err)
		}
	}
}

// callxLoadedValue returns what prog's copy of the map of section holds after
// the load. It starts from the object map of the section, which keeps the
// section's bytes, and sets each pointer of callxPointers in the section to
// the jited address of its function in prog, or to 0 when prog does not have
// the function: callx_global, or one the verifier removed. Every other byte
// stays the object map's.
func callxLoadedValue(t *testing.T, obj *BpfObject, prog, section string) []byte {
	t.Helper()

	m := BpfObjectFindMapByName(obj, section)
	value := make([]byte, BpfMapValueSize(m))
	if err := sys.MapLookupElem(BpfMapFD(m), make([]byte, internalMapKeySize), value, 0); err != nil {
		t.Fatalf("lookup %s: %v", BpfMapName(m), err)
	}

	addrs := callxFuncAddrs(t, obj, prog)
	for _, ptr := range callxPointers {
		if ptr.section == section {
			binary.NativeEndian.PutUint64(value[ptr.off:], addrs[ptr.function])
		}
	}
	return value
}

// callxFuncAddrs returns the jited address of each function of the loaded
// program prog by name. The kernel lists the jited functions in program order,
// so they must be callxReached[prog], one nonzero address each; any other
// count means the verifier kept or removed other functions. A caller that may
// not read kernel addresses gets no addresses and fails here.
func callxFuncAddrs(t *testing.T, obj *BpfObject, prog string) map[string]uint64 {
	t.Helper()

	reached := callxReached[prog]
	info, err := BpfProgramInfo(BpfObjectFindProgramByName(obj, prog))
	if err != nil {
		t.Fatalf("%s: program info: %v", prog, err)
	}
	if info.NrJitedKsyms != uint32(len(reached)) {
		t.Fatalf("%s has %d jited functions, want %d: %v", prog, info.NrJitedKsyms, len(reached), reached)
	}
	if len(info.JitedKsyms) != len(reached) || slices.Contains(info.JitedKsyms, 0) {
		t.Fatalf("%s: jited function addresses %x, want %d nonzero", prog, info.JitedKsyms, len(reached))
	}

	addrs := make(map[string]uint64, len(reached))
	for i, name := range reached {
		addrs[name] = info.JitedKsyms[i]
	}
	return addrs
}
