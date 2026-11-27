// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

const (
	subprogObject         = "../testdata/progs/subprog.bpf.o"
	subprogCallbackObject = "../testdata/progs/subprog_callback.bpf.o"
)

// bpfFuncLoop is the bpf_loop helper id, which subprog_callback.bpf.o calls.
const bpfFuncLoop BpfFuncID = 181

// Source register values of the map loads in libbpf's generated loader,
// which refer to a map by its index instead of a descriptor.
const (
	bpfPseudoMapIdx      = 5
	bpfPseudoMapIdxValue = 6
)

// relocateProgram records p's relocations against insns and patches its map,
// global data and extern loads in place, as the loader does for a program
// that calls no subprogram.
func relocateProgram(obj *BpfObject, p *BpfProgram, insns []byte) error {
	relocs, err := recordRelocs(obj, p, insns)
	if err != nil {
		return err
	}
	return relocateData(&progCode{prog: p, insns: insns, relocs: relocs})
}

// subprogFixture is the output of the subprog oracle: libbpf's final code of
// every main program after a load through a generated loader, and the map
// names in map index order.
type subprogFixture struct {
	Objects  []string                `json:"objects"`
	Errno    int32                   `json:"errno"`
	Maps     []string                `json:"maps"`
	Programs []subprogFixtureProgram `json:"programs"`
}

// subprogFixtureProgram is one main program. Insns is the hex code with the
// subprograms appended.
type subprogFixtureProgram struct {
	Name     string                   `json:"name"`
	Section  string                   `json:"section"`
	InsnCnt  int                      `json:"insn_cnt"`
	Insns    string                   `json:"insns"`
	FuncInfo []subprogFixtureFuncInfo `json:"func_info"`
	LineInfo []subprogFixtureLineInfo `json:"line_info"`
}

type subprogFixtureFuncInfo struct {
	InsnOff uint32 `json:"insn_off"`
	TypeID  uint32 `json:"type_id"`
}

type subprogFixtureLineInfo struct {
	InsnOff     uint32 `json:"insn_off"`
	FileNameOff uint32 `json:"file_name_off"`
	LineOff     uint32 `json:"line_off"`
	LineCol     uint32 `json:"line_col"`
}

func loadSubprogFixture(t *testing.T, name string) subprogFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("../testdata/oracle", name))
	if err != nil {
		t.Fatalf("read subprog fixture: %v", err)
	}
	var f subprogFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse subprog fixture: %v", err)
	}
	return f
}

// openSubprogObject opens one object from testdata/progs, or the object the
// Go linker builds from several, in order.
func openSubprogObject(t *testing.T, names ...string) *BpfObject {
	t.Helper()

	path := filepath.Join(progsDir, names[0])
	if len(names) > 1 {
		path = linkObjects(t, names...)
	}
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// relocateWithoutKernel relocates obj with each map's index standing in for
// its descriptor, as libbpf's generated loader does, and no CO-RE target. The
// stand-in descriptors are cleared before it returns, so closing the object
// does not close them.
func relocateWithoutKernel(t *testing.T, obj *BpfObject, ext *btf.ExtSpec) ([]*progCode, error) {
	t.Helper()

	for i, m := range obj.maps {
		m.fd = i
	}
	defer func() {
		for _, m := range obj.maps {
			m.fd = -1
		}
	}()
	return relocateObject(obj, ext, nil)
}

func objectExt(t *testing.T, obj *BpfObject) *btf.ExtSpec {
	t.Helper()

	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}
	return ext
}

func relocateObjectCode(t *testing.T, obj *BpfObject) map[string]*progCode {
	t.Helper()

	codes, err := relocateWithoutKernel(t, obj, objectExt(t, obj))
	if err != nil {
		t.Fatalf("relocateObject: %v", err)
	}
	byName := make(map[string]*progCode, len(codes))
	for _, code := range codes {
		byName[code.prog.name] = code
	}
	return byName
}

// TestSubprogOpen checks the program model of subprog.bpf.o. The public
// iteration and the name lookup see the two main programs only. Every
// function is a program with its own instructions, sorted by section and
// offset, and every relocation belongs to the function that holds it, with
// its offset from the function's first instruction.
func TestSubprogOpen(t *testing.T) {
	obj := openSubprogObject(t, "subprog.bpf.o")

	var public []string
	for p := BpfObjectNextProgram(obj, nil); p != nil; p = BpfObjectNextProgram(obj, p) {
		public = append(public, BpfProgramName(p))
	}
	if want := []string{"handle_subprog", "handle_subprog_shared"}; !reflect.DeepEqual(public, want) {
		t.Fatalf("programs = %v, want %v", public, want)
	}

	want := []struct {
		name, section    string
		subprog          bool
		insnOff, insnCnt int
		relocs           []uint64
	}{
		{"subprog_add", ".text", true, 0, 3, nil},
		{"subprog_count", ".text", true, 3, 10, []uint64{32}},
		{"subprog_bump", ".text", true, 13, 4, nil},
		{"handle_subprog", "kprobe/do_sys_openat2", false, 0, 6, []uint64{0, 24}},
		{"handle_subprog_shared", "kprobe/do_sys_openat2", false, 6, 5, []uint64{16}},
	}
	if len(obj.programs) != len(want) {
		t.Fatalf("object has %d functions, want %d", len(obj.programs), len(want))
	}
	for i, w := range want {
		p := obj.programs[i]
		var relocs []uint64
		for _, rel := range p.relocs {
			relocs = append(relocs, rel.Offset)
		}
		if p.name != w.name || p.sectionName != w.section || progIsSubprog(obj, p) != w.subprog ||
			p.secInsnOff != w.insnOff || p.secInsnCnt != w.insnCnt || BpfProgramInsnCnt(p) != w.insnCnt ||
			!reflect.DeepEqual(relocs, w.relocs) {
			t.Errorf("function %d = %s in %s, subprogram %v, insns %d+%d, relocations %v; want %+v",
				i, p.name, p.sectionName, progIsSubprog(obj, p), p.secInsnOff, p.secInsnCnt, relocs, w)
		}
		if w.subprog && BpfObjectFindProgramByName(obj, w.name) != nil {
			t.Errorf("subprogram %s found by name", w.name)
		}
		if BpfProgramFD(p) != -1 {
			t.Errorf("%s descriptor = %d before load", w.name, BpfProgramFD(p))
		}
	}
}

// TestSubprogOracle relocates each object without a kernel and compares every
// main program's code, function records and line records with libbpf's: the
// subprograms appended in libbpf's order, the call and callback offsets, and
// the .BTF.ext records moved to each copy. The link-text cases link
// link_text_a.bpf.o and link_text_b.bpf.o first, in both orders, so each
// program calls its own static bump in the merged .text.
func TestSubprogOracle(t *testing.T) {
	fixtures := []string{
		"subprog.json", "subprog-callback.json",
		"subprog-link-text.json", "subprog-link-text-reverse.json",
		"subprog-link-extern.json", "subprog-link-extern-reverse.json",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			want := loadSubprogFixture(t, fixture)
			if want.Errno != 0 {
				t.Fatalf("libbpf load errno = %d", want.Errno)
			}
			obj := openSubprogObject(t, want.Objects...)

			var maps []string
			for _, m := range obj.maps {
				maps = append(maps, BpfMapName(m))
			}
			if !reflect.DeepEqual(maps, want.Maps) {
				t.Fatalf("maps = %v, want %v", maps, want.Maps)
			}

			codes, err := relocateWithoutKernel(t, obj, objectExt(t, obj))
			if err != nil {
				t.Fatalf("relocateObject: %v", err)
			}
			if len(codes) != len(want.Programs) {
				t.Fatalf("%d programs, want %d", len(codes), len(want.Programs))
			}
			for i, w := range want.Programs {
				compareSubprogCode(t, codes[i], w)
			}
		})
	}
}

// compareSubprogCode compares one main program's code with libbpf's. libbpf's
// generated loader loads a map by index with its own source registers; the
// Go code uses the index as the descriptor, so only the register differs.
func compareSubprogCode(t *testing.T, code *progCode, want subprogFixtureProgram) {
	t.Helper()

	p := code.prog
	if p.name != want.Name || p.sectionName != want.Section || len(code.insns)/bpfInsnLength != want.InsnCnt {
		t.Fatalf("program %s in %s with %d instructions, want %s in %s with %d",
			p.name, p.sectionName, len(code.insns)/bpfInsnLength, want.Name, want.Section, want.InsnCnt)
	}

	wantInsns, err := hex.DecodeString(want.Insns)
	if err != nil {
		t.Fatalf("%s: instructions: %v", want.Name, err)
	}
	wantInsns = mapLoadsByDescriptor(wantInsns)
	for i := 0; i < len(wantInsns); i += bpfInsnLength {
		if !bytes.Equal(code.insns[i:i+bpfInsnLength], wantInsns[i:i+bpfInsnLength]) {
			t.Fatalf("%s: insn %d = %+v, want %+v", want.Name, i/bpfInsnLength,
				decodeBpfInsn(code.insns[i:]), decodeBpfInsn(wantInsns[i:]))
		}
	}

	if got := decodeFuncInfo(code.funcInfo); !reflect.DeepEqual(got, want.FuncInfo) {
		t.Errorf("%s: function records = %+v\nwant %+v", want.Name, got, want.FuncInfo)
	}
	if got := decodeLineInfo(code.lineInfo); !reflect.DeepEqual(got, want.LineInfo) {
		t.Errorf("%s: line records = %+v\nwant %+v", want.Name, got, want.LineInfo)
	}
}

// mapLoadsByDescriptor turns the generated loader's map index loads into the
// descriptor loads the Go loader emits, with the same immediates.
func mapLoadsByDescriptor(insns []byte) []byte {
	out := slices.Clone(insns)
	for off := 0; off+2*bpfInsnLength <= len(out); off += bpfInsnLength {
		insn := decodeBpfInsn(out[off:])
		if insn.Code != bpfLD|bpfImm|bpfSizeDW {
			continue
		}
		switch insn.Src {
		case bpfPseudoMapIdx:
			insn.Src = bpfPseudoMapFD
		case bpfPseudoMapIdxValue:
			insn.Src = bpfPseudoMapValue
		}
		encodeBpfInsn(out[off:], insn)
		off += bpfInsnLength
	}
	return out
}

func decodeFuncInfo(buf []byte) []subprogFixtureFuncInfo {
	recs := []subprogFixtureFuncInfo{}
	for off := 0; off < len(buf); off += btf.FuncInfoMinSize {
		recs = append(recs, subprogFixtureFuncInfo{
			InsnOff: binary.NativeEndian.Uint32(buf[off+bpfFuncInfoOffInsnOff:]),
			TypeID:  binary.NativeEndian.Uint32(buf[off+bpfFuncInfoOffTypeID:]),
		})
	}
	return recs
}

func decodeLineInfo(buf []byte) []subprogFixtureLineInfo {
	recs := []subprogFixtureLineInfo{}
	for off := 0; off < len(buf); off += btf.LineInfoMinSize {
		recs = append(recs, subprogFixtureLineInfo{
			InsnOff:     binary.NativeEndian.Uint32(buf[off+bpfLineInfoOffInsnOff:]),
			FileNameOff: binary.NativeEndian.Uint32(buf[off+bpfLineInfoOffFileNameOff:]),
			LineOff:     binary.NativeEndian.Uint32(buf[off+bpfLineInfoOffLineOff:]),
			LineCol:     binary.NativeEndian.Uint32(buf[off+bpfLineInfoOffLineCol:]),
		})
	}
	return recs
}

// subprogLayouts is the code each main program of subprog.bpf.o loads: its
// functions in the order they are appended, and every subprogram call by
// instruction index and callee. handle_subprog reaches subprog_count through
// subprog_bump before it calls subprog_add, so subprog_count comes before
// subprog_add there and after it in handle_subprog_shared.
var subprogLayouts = map[string]struct {
	parts []string
	calls map[int]string
}{
	"handle_subprog": {
		parts: []string{"handle_subprog", "subprog_bump", "subprog_count", "subprog_add"},
		calls: map[int]string{0: "subprog_bump", 3: "subprog_add", 8: "subprog_count", 20: "subprog_count"},
	},
	"handle_subprog_shared": {
		parts: []string{"handle_subprog_shared", "subprog_add", "subprog_count"},
		calls: map[int]string{2: "subprog_add", 5: "subprog_count"},
	},
}

// TestSubprogRelocateCalls relocates subprog.bpf.o without a kernel and
// checks each main program's code: every function it reaches appended once,
// in call order, with its own instructions; every call pointing at the start
// of its callee's copy; and the map load of subprog_count patched in every
// copy.
func TestSubprogRelocateCalls(t *testing.T) {
	obj := openSubprogObject(t, "subprog.bpf.o")
	codes := relocateObjectCode(t, obj)
	if len(codes) != len(subprogLayouts) {
		t.Fatalf("%d main programs, want %d", len(codes), len(subprogLayouts))
	}

	for name, layout := range subprogLayouts {
		code := codes[name]
		if code == nil {
			t.Fatalf("no code for %s", name)
		}
		starts := checkSubprogParts(t, obj, code, layout.parts)

		calls := 0
		for off := 0; off < len(code.insns); off += bpfInsnLength {
			insn := decodeBpfInsn(code.insns[off:])
			if insn.Code == bpfLD|bpfImm|bpfSizeDW && insn.Src == bpfPseudoMapFD && insn.Imm != 0 {
				t.Errorf("%s: map load at insn %d uses descriptor %d, want 0", name, off/bpfInsnLength, insn.Imm)
			}
			if !insnIsSubprogCall(insn) {
				continue
			}
			calls++
			idx := off / bpfInsnLength
			callee, ok := layout.calls[idx]
			if !ok || idx+int(insn.Imm)+1 != starts[callee] {
				t.Errorf("%s: call at insn %d jumps to %d, want %s at %d", name, idx, idx+int(insn.Imm)+1, callee, starts[callee])
			}
		}
		if calls != len(layout.calls) {
			t.Errorf("%s: %d calls, want %d", name, calls, len(layout.calls))
		}
	}
}

// checkSubprogParts checks that code is made of the named functions, in order,
// each a copy of the function's instructions except for the calls and the map
// loads the relocation patches. It returns each function's first instruction
// in code.
func checkSubprogParts(t *testing.T, obj *BpfObject, code *progCode, parts []string) map[string]int {
	t.Helper()

	starts := make(map[string]int, len(parts))
	off := 0
	for _, name := range parts {
		p := findFunction(t, obj, name)
		if got, ok := code.subInsnOff[p]; !ok || got != off {
			t.Fatalf("%s: %s starts at %d (appended %v), want %d", code.prog.name, name, got, ok, off)
		}
		starts[name] = off

		for i := 0; i < p.secInsnCnt; i++ {
			got := decodeBpfInsn(code.insns[(off+i)*bpfInsnLength:])
			orig := decodeBpfInsn(p.insns[i*bpfInsnLength:])
			if got.Code != orig.Code || got.Dst != orig.Dst || got.Off != orig.Off {
				t.Errorf("%s: %s insn %d = %+v, want a copy of %+v", code.prog.name, name, i, got, orig)
			}
		}
		off += p.secInsnCnt
	}
	if off*bpfInsnLength != len(code.insns) {
		t.Fatalf("%s: code has %d instructions, want %d", code.prog.name, len(code.insns)/bpfInsnLength, off)
	}
	return starts
}

// findFunction returns the program or subprogram named name.
func findFunction(t *testing.T, obj *BpfObject, name string) *BpfProgram {
	t.Helper()

	for _, p := range obj.programs {
		if p.name == name {
			return p
		}
	}
	t.Fatalf("no function %s", name)
	return nil
}

// TestSubprogFuncLineInfo checks the .BTF.ext records of each main program of
// subprog.bpf.o: one function record per function, at the start of its copy
// and with its BTF FUNC type, and every line record of every function, moved
// with the copy. handle_subprog_shared starts at instruction 6 of its
// section, so its own record also proves the byte offsets become
// instruction indexes.
func TestSubprogFuncLineInfo(t *testing.T) {
	obj := openSubprogObject(t, "subprog.bpf.o")
	ext := objectExt(t, obj)
	codes := relocateObjectCode(t, obj)

	for name, layout := range subprogLayouts {
		code := codes[name]
		var wantFunc []subprogFixtureFuncInfo
		wantLines := 0
		for _, part := range layout.parts {
			p := findFunction(t, obj, part)
			fn := obj.btf.Find(part, btf.KindFunc)
			if fn == nil {
				t.Fatalf("no BTF FUNC %s", part)
			}
			wantFunc = append(wantFunc, subprogFixtureFuncInfo{InsnOff: uint32(code.subInsnOff[p]), TypeID: fn.ID})
			wantLines += len(programLineInfo(ext, p, 0)) / btf.LineInfoMinSize
		}
		if got := decodeFuncInfo(code.funcInfo); !reflect.DeepEqual(got, wantFunc) {
			t.Errorf("%s: function records = %+v, want %+v", name, got, wantFunc)
		}

		lines := decodeLineInfo(code.lineInfo)
		if len(lines) != wantLines {
			t.Errorf("%s: %d line records, want %d", name, len(lines), wantLines)
		}
		for _, f := range wantFunc {
			if !slices.ContainsFunc(lines, func(l subprogFixtureLineInfo) bool { return l.InsnOff == f.InsnOff }) {
				t.Errorf("%s: no line record at function start %d", name, f.InsnOff)
			}
		}
		for _, l := range lines {
			if int(l.InsnOff) >= len(code.insns)/bpfInsnLength {
				t.Errorf("%s: line record at insn %d past the code", name, l.InsnOff)
			}
		}
	}

	shared := BpfObjectFindProgramByName(obj, "handle_subprog_shared")
	for _, subInsnOff := range []int{0, 7} {
		got := decodeFuncInfo(programFuncInfo(ext, shared, subInsnOff))
		want := []subprogFixtureFuncInfo{{InsnOff: uint32(subInsnOff), TypeID: obj.btf.Find("handle_subprog_shared", btf.KindFunc).ID}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("programFuncInfo(handle_subprog_shared, %d) = %+v, want %+v", subInsnOff, got, want)
		}
	}
}

// TestSubprogFuncInfoMissing drops .BTF.ext function records. Without the
// subprograms' records the load must fail, because the kernel needs one per
// function; without the main programs' records no function record is passed
// at all.
func TestSubprogFuncInfoMissing(t *testing.T) {
	without := func(ext *btf.ExtSpec, section string) *btf.ExtSpec {
		out := *ext
		out.FuncInfos = slices.DeleteFunc(slices.Clone(ext.FuncInfos), func(s btf.FuncInfoSection) bool {
			return s.Section == section
		})
		return &out
	}

	obj := openSubprogObject(t, "subprog.bpf.o")
	ext := objectExt(t, obj)

	_, err := relocateWithoutKernel(t, obj, without(ext, textSec))
	if !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), "missing .BTF.ext function info") {
		t.Fatalf("relocate without .text function records: %v", err)
	}

	codes, err := relocateWithoutKernel(t, obj, without(ext, "kprobe/do_sys_openat2"))
	if err != nil {
		t.Fatalf("relocate without the main programs' function records: %v", err)
	}
	for _, code := range codes {
		if code.funcInfo != nil || code.lineInfo == nil {
			t.Errorf("%s: %d function and %d line record bytes, want only line records",
				code.prog.name, len(code.funcInfo), len(code.lineInfo))
		}
	}
}

// TestSubprogRelocErrors checks the relocation errors of a subprogram call:
// a call relocated against a symbol outside .text, a call relocation on an
// instruction that is not a subprogram call, and a static program outside
// .text.
func TestSubprogRelocErrors(t *testing.T) {
	obj := openSubprogObject(t, "subprog.bpf.o")
	p := BpfObjectFindProgramByName(obj, "handle_subprog")
	callToAdd := p.relocs[1]

	mapRel := callToAdd
	mapRel.SymbolIndex = findFunction(t, obj, "subprog_count").relocs[0].SymbolIndex
	if _, err := recordReloc(obj, p, mapRel, p.insns); err == nil || !strings.Contains(err.Error(), "bad call relo against 'subprog_counts' in section '.maps'") {
		t.Errorf("call against a map: %v", err)
	}

	insns := slices.Clone(p.insns)
	insns[callToAdd.Offset+1] = 0
	if _, err := recordReloc(obj, p, callToAdd, insns); err == nil || !strings.Contains(err.Error(), "incorrect bpf_call opcode") {
		t.Errorf("helper call with a relocation: %v", err)
	}

	e, err := objelf.OpenBytes(marshalSynth(t, synthOutput([]byte("abcd"), 4, 4, "x_bss")))
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	if _, _, err := parsePrograms(e); !errors.Is(err, unix.ENOTSUP) || !strings.Contains(err.Error(), "program 'prog' is static") {
		t.Errorf("static program in kprobe/x: %v", err)
	}
}

// TestSubprogTarget checks how a call or address load finds its subprogram:
// a global call through the symbol, a static call through the section symbol
// and the immediate, a call without a relocation relative to its position,
// and an address load, which must be relocated.
func TestSubprogTarget(t *testing.T) {
	prog := &BpfProgram{name: "prog", secInsnOff: 6, secInsnCnt: 5}
	call := func(imm int32) bpfInsn {
		return bpfInsn{Code: bpfJMP | bpfCall, Src: bpfPseudoCall, Imm: imm}
	}
	addr := bpfInsn{Code: bpfLD | bpfImm | bpfSizeDW, Src: bpfPseudoFunc, Imm: 0x58}

	tests := []struct {
		name   string
		insn   bpfInsn
		reloc  *progReloc
		target int
		err    string
	}{
		{"global call", call(-1), &progReloc{kind: relocCall, symOff: 24}, 3, ""},
		{"static call", call(12), &progReloc{kind: relocCall}, 13, ""},
		{"same section", call(2), nil, 6 + 1 + 2 + 1, ""},
		{"address", addr, &progReloc{kind: relocSubprogAddr}, 11, ""},
		{"global address", bpfInsn{Code: addr.Code, Src: bpfPseudoFunc}, &progReloc{kind: relocSubprogAddr, symOff: 0x58}, 11, ""},
		{"address without relocation", addr, nil, 0, "missing subprog addr relo for insn #1"},
		{"map relocation", call(-1), &progReloc{kind: relocLD64}, 0, "unexpected relo for insn #1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := subprogTarget(prog, 1, tt.insn, tt.reloc)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("subprogTarget = %d, %v; want %q", got, err, tt.err)
				}
				return
			}
			if err != nil || got != tt.target {
				t.Fatalf("subprogTarget = %d, %v; want %d", got, err, tt.target)
			}
		})
	}
}

// mapSlot reads the u64 value at index slot of the array map name.
func mapSlot(t *testing.T, obj *BpfObject, name string, slot uint32) uint64 {
	t.Helper()

	m := BpfObjectFindMapByName(obj, name)
	if m == nil {
		t.Fatalf("map %q not found", name)
	}
	key := make([]byte, BpfMapKeySize(m))
	binary.NativeEndian.PutUint32(key, slot)
	value := make([]byte, BpfMapValueSize(m))
	if err := BpfMapLookupElem(m, key, value, 0); err != nil {
		t.Fatalf("lookup %s[%d]: %v", name, slot, err)
	}
	return binary.NativeEndian.Uint64(value)
}

// attachKprobes attaches each named program to its kprobe target and destroys
// the links when the test ends.
func attachKprobes(t *testing.T, obj *BpfObject, targets map[string]string) {
	t.Helper()

	for name, target := range targets {
		prog := BpfObjectFindProgramByName(obj, name)
		if prog == nil {
			t.Fatalf("program %s not found", name)
		}
		link, err := BpfProgramAttachKprobe(prog, false, target)
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				t.Skipf("kprobe attach not permitted: %v", err)
			}
			t.Fatalf("attach %s to %s: %v", name, target, err)
		}
		t.Cleanup(func() { BpfLinkDestroy(link) })
	}
}

// checkSubprogDescriptors requires a descriptor for every main program and
// none for the subprograms.
func checkSubprogDescriptors(t *testing.T, obj *BpfObject) {
	t.Helper()

	for _, p := range obj.programs {
		fd := BpfProgramFD(p)
		if progIsSubprog(obj, p) && fd != -1 {
			t.Errorf("subprogram %s has descriptor %d", p.name, fd)
		}
		if !progIsSubprog(obj, p) && fd < 0 {
			t.Errorf("program %s has no descriptor", p.name)
		}
	}
}

// TestSubprogLoad loads subprog.bpf.o, checks that only the main programs
// have descriptors and that the kernel saw each one's functions and line
// records, attaches both to do_sys_openat2, opens a file and reads what the
// subprograms counted. Each call adds its own delta, so a wrong argument or
// call target shows in the values. It then closes the object and checks that
// every descriptor is gone. It needs root or CAP_BPF and skips otherwise.
func TestSubprogLoad(t *testing.T) {
	obj := loadTestObject(t, subprogObject)
	defer BpfObjectClose(obj)

	checkSubprogDescriptors(t, obj)
	if _, err := BpfProgramInfo(findFunction(t, obj, "subprog_add")); !errors.Is(err, unix.EINVAL) {
		t.Errorf("BpfProgramInfo(subprog_add) = %v, want EINVAL", err)
	}
	for name, layout := range subprogLayouts {
		info, err := BpfProgramInfo(BpfObjectFindProgramByName(obj, name))
		if err != nil {
			t.Fatalf("BpfProgramInfo(%s): %v", name, err)
		}
		if info.NrJitedKsyms != 0 && int(info.NrJitedKsyms) != len(layout.parts) {
			t.Errorf("%s: kernel jited %d functions, want %d", name, info.NrJitedKsyms, len(layout.parts))
		}
		if info.NrLineInfo == 0 {
			t.Errorf("%s: kernel has no line records", name)
		}
	}

	attachKprobes(t, obj, map[string]string{
		"handle_subprog":        "do_sys_openat2",
		"handle_subprog_shared": "do_sys_openat2",
	})
	triggerOpen(t)

	for slot, delta := range []uint64{1, 2, 3} {
		got := mapSlot(t, obj, "subprog_counts", uint32(slot))
		if got == 0 || got%delta != 0 {
			t.Errorf("subprog_counts[%d] = %d, want a positive multiple of %d", slot, got, delta)
		}
	}

	functions := slices.Clone(obj.programs)
	BpfObjectClose(obj)
	for _, p := range functions {
		if fd := BpfProgramFD(p); fd != -1 {
			t.Errorf("%s descriptor = %d after close", p.name, fd)
		}
	}
}

// TestSubprogCallbackLoad loads subprog_callback.bpf.o, whose program passes
// a static .text function to bpf_loop, attaches it to do_sys_openat2 and
// checks that both the callback and the global subprogram ran. Other
// processes open files too, so the counters are read while the program may
// still run, and only lower bounds are exact. bpf_loop needs Linux 5.17, so
// the test skips on older kernels; it also needs root or CAP_BPF.
func TestSubprogCallbackLoad(t *testing.T) {
	if ok, err := LibbpfProbeBpfHelper(BPF_PROG_TYPE_KPROBE, bpfFuncLoop); err != nil || !ok {
		t.Skipf("bpf_loop not available: %v, %v", ok, err)
	}
	obj := loadTestObject(t, subprogCallbackObject)
	defer BpfObjectClose(obj)

	checkSubprogDescriptors(t, obj)
	attachKprobes(t, obj, map[string]string{"handle_callback": "do_sys_openat2"})
	triggerOpen(t)

	steps := mapSlot(t, obj, "callback_counts", 0)
	calls := mapSlot(t, obj, "callback_counts", 1)
	if steps < 4 || calls == 0 {
		t.Errorf("callback ran %d times in %d calls, want at least 4 in 1", steps, calls)
	}
}
