// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"reflect"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// kernelDecl is one VAR or FUNC of a synthetic kernel BTF. A compatible
// declaration is an int variable or a function taking nothing and returning
// nothing, like the fixtures' externs; an incompatible one is a struct
// variable or a function taking an int.
type kernelDecl struct {
	name string
	kind btf.Kind
	bad  bool
}

// IDs of the base types every synthetic kernel BTF starts with.
const (
	kernIntID     = 1
	kernStructID  = 2
	kernVoidFnID  = 3
	kernIntFnID   = 4
	kernBaseTypes = 5
)

// kernelBaseTypes returns the types every synthetic kernel BTF starts with:
// void, int, a 4-byte struct and the two function prototypes. intOff and
// structOff are the offsets of their names.
func kernelBaseTypes(intOff, structOff uint32) []btf.Type {
	return []btf.Type{
		{Kind: btf.KindVoid},
		{NameOff: intOff, Kind: btf.KindInt, SizeOrType: 4, Int: &btf.Int{Encoding: btfIntSigned<<24 | 32}},
		{NameOff: structOff, Kind: btf.KindStruct, SizeOrType: 4},
		{Kind: btf.KindFuncProto},
		{Kind: btf.KindFuncProto, Params: []btf.Param{{Type: kernIntID}}},
	}
}

// declType returns the BTF type of decl, named at nameOff.
func declType(decl kernelDecl, nameOff uint32) btf.Type {
	if decl.kind == btf.KindVar {
		typ := uint32(kernIntID)
		if decl.bad {
			typ = kernStructID
		}
		return btf.Type{NameOff: nameOff, Kind: btf.KindVar, SizeOrType: typ, Var: &btf.Var{Linkage: btf.VarGlobalAllocated}}
	}
	typ := uint32(kernVoidFnID)
	if decl.bad {
		typ = kernIntFnID
	}
	return btf.Type{NameOff: nameOff, Kind: btf.KindFunc, Vlen: btfFuncGlobal, SizeOrType: typ}
}

// kernelBTF builds a vmlinux-like BTF with the base types and decls.
func kernelBTF(t *testing.T, decls ...kernelDecl) *btf.Spec {
	t.Helper()

	strs := []byte("\x00int\x00s\x00")
	types := kernelBaseTypes(1, 5)
	for _, decl := range decls {
		types = append(types, declType(decl, uint32(len(strs))))
		strs = append(append(strs, decl.name...), 0)
	}
	return newTestSpec(t, types, string(strs))
}

// splitModuleBTF builds the split BTF of a module on top of base with decls,
// as the kernel reports it, and parses it back.
func splitModuleBTF(t *testing.T, base *btf.Spec, decls ...kernelDecl) *btf.Spec {
	t.Helper()

	strOff := uint32(len(base.Strings))
	strs := []byte{0}
	types := []btf.Type{{Kind: btf.KindVoid}}
	for _, decl := range decls {
		types = append(types, declType(decl, strOff+uint32(len(strs))))
		strs = append(append(strs, decl.name...), 0)
	}
	raw, err := btf.NewSpec(binary.NativeEndian, types, strs)
	if err != nil {
		t.Fatalf("module NewSpec: %v", err)
	}
	mod, err := btf.ParseSplit(raw.Raw(), binary.NativeEndian, base)
	if err != nil {
		t.Fatalf("ParseSplit: %v", err)
	}
	return mod
}

// testModuleFD is the descriptor the synthetic module BTF pretends to have.
// The tests never close it.
const testModuleFD = 77

// withKernel makes obj resolve against vmlinux and, when modDecls is not
// empty, one module BTF holding them, without asking the kernel.
func withKernel(t *testing.T, obj *BpfObject, vmlinux []kernelDecl, modDecls []kernelDecl) {
	t.Helper()

	obj.btfVmlinux = kernelBTF(t, vmlinux...)
	obj.btfModulesLoaded = true
	if len(modDecls) > 0 {
		mod := splitModuleBTF(t, obj.btfVmlinux, modDecls...)
		obj.btfModules = []moduleBTF{{spec: mod, name: "gobpfgo_mod", id: 1, fd: testModuleFD}}
	}
	t.Cleanup(func() {
		obj.btfModules = nil
		obj.fdArray = nil
	})
}

var (
	varDecl    = func(name string) kernelDecl { return kernelDecl{name: name, kind: btf.KindVar} }
	funcDecl   = func(name string) kernelDecl { return kernelDecl{name: name, kind: btf.KindFunc} }
	badVarDecl = func(name string) kernelDecl { return kernelDecl{name: name, kind: btf.KindVar, bad: true} }
	badFnDecl  = func(name string) kernelDecl { return kernelDecl{name: name, kind: btf.KindFunc, bad: true} }
)

// ksymResult is what resolution leaves in one .ksyms extern.
type ksymResult struct {
	set      bool
	btfID    uint32
	objFD    int
	fdArrIdx int16
}

// ksymResults returns the resolution result of every .ksyms extern of obj.
func ksymResults(obj *BpfObject) map[string]ksymResult {
	got := map[string]ksymResult{}
	for _, ext := range obj.externs {
		got[ext.name] = ksymResult{ext.isSet, ext.ksym.kernelBtfID, ext.ksym.kernelBtfObjFD, ext.ksym.btfFdIdx}
	}
	return got
}

// TestResolveKsymsTyped resolves the typed externs of link_ksyms.bpf.o
// against synthetic kernel BTF. vmlinux types resolve with no descriptor; a
// module function takes fd array slot 1, which a second function of the same
// module shares, and a module variable carries the module descriptor. A
// strong extern the kernel lacks, or has with an incompatible type, fails
// the resolution with EINVAL before anything is loaded.
func TestResolveKsymsTyped(t *testing.T) {
	base := kernelBaseTypes(0, 0)
	active, lock, unlock := uint32(len(base)), uint32(len(base)+1), uint32(len(base)+2)
	vmlinuxAll := []kernelDecl{varDecl("bpf_prog_active"), funcDecl("bpf_rcu_read_lock"), funcDecl("bpf_rcu_read_unlock")}

	tests := []struct {
		name    string
		vmlinux []kernelDecl
		module  []kernelDecl
		want    map[string]ksymResult
		fdArray []int32
		errno   syscall.Errno
	}{
		{name: "vmlinux", vmlinux: vmlinuxAll, want: map[string]ksymResult{
			"bpf_prog_active":     {set: true, btfID: active},
			"bpf_rcu_read_lock":   {set: true, btfID: lock},
			"bpf_rcu_read_unlock": {set: true, btfID: unlock},
		}},
		{
			name:    "module",
			vmlinux: []kernelDecl{funcDecl("bpf_rcu_read_lock")},
			module:  []kernelDecl{varDecl("bpf_prog_active"), funcDecl("bpf_rcu_read_unlock"), funcDecl("bpf_rcu_read_lock")},
			want: map[string]ksymResult{
				"bpf_prog_active":     {set: true, btfID: kernBaseTypes + 1, objFD: testModuleFD},
				"bpf_rcu_read_lock":   {set: true, btfID: kernBaseTypes},
				"bpf_rcu_read_unlock": {set: true, btfID: kernBaseTypes + 2, objFD: testModuleFD, fdArrIdx: 1},
			},
			fdArray: []int32{0, testModuleFD},
		},
		{name: "strong var missing", vmlinux: vmlinuxAll[1:], errno: unix.EINVAL},
		{name: "strong func missing", vmlinux: vmlinuxAll[:2], errno: unix.EINVAL},
		{name: "var incompatible", vmlinux: []kernelDecl{badVarDecl("bpf_prog_active"), vmlinuxAll[1], vmlinuxAll[2]}, errno: unix.EINVAL},
		{name: "func incompatible", vmlinux: []kernelDecl{vmlinuxAll[0], badFnDecl("bpf_rcu_read_lock"), vmlinuxAll[2]}, errno: unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := openProg(t, ksymsProg)
			withKernel(t, obj, tt.vmlinux, tt.module)

			err := resolveExterns(obj)
			if errnoOf(err) != tt.errno {
				t.Fatalf("resolveExterns = %v, want errno %d", err, tt.errno)
			}
			if tt.errno != 0 {
				return
			}
			if got := ksymResults(obj); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("externs = %+v, want %+v", got, tt.want)
			}
			if !reflect.DeepEqual(obj.fdArray, tt.fdArray) {
				t.Errorf("fd array = %v, want %v", obj.fdArray, tt.fdArray)
			}
		})
	}
}

// TestResolveKsymsWeak resolves the typed weak externs of
// link_ksyms_weak.bpf.o. A weak variable or function the kernel lacks stays
// unset, and so does a weak function with an incompatible prototype; a weak
// variable with an incompatible type still fails with EINVAL. The typeless
// externs resolve through the real /proc/kallsyms, where the gobpfgo_ name
// never appears, so they cannot fail.
func TestResolveKsymsWeak(t *testing.T) {
	tests := []struct {
		name    string
		vmlinux []kernelDecl
		want    map[string]bool
		errno   syscall.Errno
	}{
		{name: "missing", want: map[string]bool{"gobpfgo_missing_var": false, "gobpfgo_missing_kfunc": false}},
		{name: "present", vmlinux: []kernelDecl{varDecl("gobpfgo_missing_var"), funcDecl("gobpfgo_missing_kfunc")},
			want: map[string]bool{"gobpfgo_missing_var": true, "gobpfgo_missing_kfunc": true}},
		{name: "func incompatible", vmlinux: []kernelDecl{badFnDecl("gobpfgo_missing_kfunc")},
			want: map[string]bool{"gobpfgo_missing_var": false, "gobpfgo_missing_kfunc": false}},
		{name: "var incompatible", vmlinux: []kernelDecl{badVarDecl("gobpfgo_missing_var")}, errno: unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := openProg(t, ksymsWeakProg)
			withKernel(t, obj, tt.vmlinux, nil)

			err := resolveExterns(obj)
			if errnoOf(err) != tt.errno {
				t.Fatalf("resolveExterns = %v, want errno %d", err, tt.errno)
			}
			if tt.errno != 0 {
				return
			}
			for name, want := range tt.want {
				if got := findExternByName(obj.externs, name).isSet; got != want {
					t.Errorf("%s set = %v, want %v", name, got, want)
				}
			}
			if ext := findExternByName(obj.externs, "gobpfgo_missing_sym"); ext.isSet {
				t.Errorf("gobpfgo_missing_sym resolved to %#x", ext.ksym.addr)
			}
		})
	}
}

// TestResolveKsymsTypelessStrong renames a typeless extern of
// link_ksyms_addr.bpf.o to a symbol no kernel has: kallsyms leaves the
// strong extern unset, which is ESRCH.
func TestResolveKsymsTypelessStrong(t *testing.T) {
	obj := openProg(t, ksymsAddrProg)
	findExternByName(obj.externs, "init_task").name = "gobpfgo_no_such_symbol"

	if err := resolveExterns(obj); errnoOf(err) != unix.ESRCH {
		t.Fatalf("resolveExterns = %v, want ESRCH", err)
	}
}

// TestFdArraySlots fills the fd array up to the slots a 16-bit instruction
// offset can name and requires E2BIG for the next module.
func TestFdArraySlots(t *testing.T) {
	obj := &BpfObject{}
	for i := 1; i < 32767; i++ {
		mod := &moduleBTF{fd: 100 + i}
		if err := addFdArraySlot(obj, mod, "kfunc"); err != nil || mod.fdArrayIdx != i {
			t.Fatalf("slot %d: index %d, %v", i, mod.fdArrayIdx, err)
		}
	}
	if err := addFdArraySlot(obj, &moduleBTF{fd: 1}, "kfunc"); errnoOf(err) != unix.E2BIG {
		t.Fatalf("slot 32767: %v, want E2BIG", err)
	}
	if got := fdArrayBytes(obj); len(got) != 4*32767 || binary.NativeEndian.Uint32(got) != 0 ||
		binary.NativeEndian.Uint32(got[4:]) != 101 {
		t.Fatalf("fd array bytes start %x, want slot 0 empty and slot 1 = 101", got[:8])
	}
	if fdArrayBytes(&BpfObject{}) != nil {
		t.Fatal("empty fd array is not nil")
	}
}

// ldImm64 returns an ld_imm64 pair loading into r1 with source src.
func ldImm64(src uint8) []byte {
	insn := make([]byte, 2*bpfInsnLength)
	encodeBpfInsn(insn, bpfInsn{Code: bpfLD | bpfImm | bpfSizeDW, Dst: 1, Src: src})
	return insn
}

// TestPatchKsymLD64 checks the ld_imm64 of a .ksyms extern: a resolved
// typed extern becomes a BPF_PSEUDO_BTF_ID load of the BTF ID with the
// module descriptor in the second immediate; a typeless one, and an
// unresolved weak typed one, load the address halves with the source
// register unchanged.
func TestPatchKsymLD64(t *testing.T) {
	tests := []struct {
		name      string
		ext       externDesc
		src       uint8
		imm, imm2 uint32
	}{
		{"typed", externDesc{isSet: true, ksym: ksymExtern{typeID: 5, kernelBtfID: 1234, kernelBtfObjFD: 9}}, bpfPseudoBtfID, 1234, 9},
		{"typed vmlinux", externDesc{isSet: true, ksym: ksymExtern{typeID: 5, kernelBtfID: 77}}, bpfPseudoBtfID, 77, 0},
		{"typeless", externDesc{isSet: true, ksym: ksymExtern{addr: 0xffffffff81234567}}, 0, 0x81234567, 0xffffffff},
		{"typed unresolved", externDesc{ksym: ksymExtern{typeID: 5}}, 0, 0, 0},
		{"typed with kallsyms address", externDesc{ksym: ksymExtern{typeID: 5, addr: 0x1000}}, 0, 0x1000, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn := ldImm64(0)
			patchKsymLD64(insn, &tt.ext)
			first, second := decodeBpfInsn(insn), decodeBpfInsn(insn[bpfInsnLength:])
			if first.Code != bpfLD|bpfImm|bpfSizeDW || first.Dst != 1 || first.Src != tt.src ||
				uint32(first.Imm) != tt.imm || uint32(second.Imm) != tt.imm2 {
				t.Fatalf("insn = %+v %+v, want src %d imm %#x %#x", first, second, tt.src, tt.imm, tt.imm2)
			}
		})
	}
}

// TestPatchExternCall checks a kfunc call: a resolved one becomes a
// BPF_PSEUDO_KFUNC_CALL of the BTF ID with the fd array slot as the offset;
// an unresolved weak one is poisoned into a helper call the verifier
// rejects only when it is reachable.
func TestPatchExternCall(t *testing.T) {
	call := bpfInsn{Code: bpfJMP | bpfCall, Src: bpfPseudoCall, Imm: -1}
	tests := []struct {
		name string
		ext  externDesc
		want bpfInsn
	}{
		{"vmlinux", externDesc{isSet: true, ksym: ksymExtern{kernelBtfID: 4321}},
			bpfInsn{Code: bpfJMP | bpfCall, Src: bpfPseudoKfuncCall, Imm: 4321}},
		{"module", externDesc{isSet: true, ksym: ksymExtern{kernelBtfID: 99, btfFdIdx: 3}},
			bpfInsn{Code: bpfJMP | bpfCall, Src: bpfPseudoKfuncCall, Off: 3, Imm: 99}},
		{"unresolved weak", externDesc{isWeak: true},
			bpfInsn{Code: bpfJMP | bpfCall, Imm: poisonCallKfuncBase + 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insn := make([]byte, bpfInsnLength)
			encodeBpfInsn(insn, call)
			patchExternCall(insn, 7, &tt.ext)
			if got := decodeBpfInsn(insn); got != tt.want {
				t.Fatalf("insn = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// relocatedProgram relocates obj with every map given a placeholder
// descriptor and returns the code of the named main program.
func relocatedProgram(t *testing.T, obj *BpfObject, name string) *progCode {
	t.Helper()

	for _, m := range obj.maps {
		m.fd = 1000
	}
	t.Cleanup(func() {
		for _, m := range obj.maps {
			m.fd = -1
		}
	})
	codes, err := relocateObject(obj, nil, nil, argCtxTagSupported, declTagSupported)
	if err != nil {
		t.Fatalf("relocateObject: %v", err)
	}
	if err := relocateObjectData(codes, noFuncPtrMap); err != nil {
		t.Fatalf("relocateObjectData: %v", err)
	}
	for _, code := range codes {
		if code.prog.name == name {
			return code
		}
	}
	t.Fatalf("no code for %s", name)
	return nil
}

// insnAt decodes instruction idx of code and, for an ld_imm64, the second
// immediate.
func insnAt(code *progCode, idx int) (bpfInsn, uint32) {
	off := idx * bpfInsnLength
	insn := decodeBpfInsn(code.insns[off:])
	var imm2 uint32
	if insn.Code == bpfLD|bpfImm|bpfSizeDW {
		imm2 = binary.NativeEndian.Uint32(code.insns[off+12:])
	}
	return insn, imm2
}

// TestRelocateKsyms relocates link_ksyms.bpf.o after resolving it against
// synthetic BTF with bpf_rcu_read_unlock in a module: the per-CPU variable
// load becomes a BPF_PSEUDO_BTF_ID of its vmlinux ID, the lock call a kfunc
// call with offset 0, the unlock call a kfunc call through fd array slot 1,
// and the .bss store still targets the map. The subprogram relocation
// leaves the kfunc calls alone.
func TestRelocateKsyms(t *testing.T) {
	obj := openProg(t, ksymsProg)
	withKernel(t, obj, []kernelDecl{varDecl("bpf_prog_active"), funcDecl("bpf_rcu_read_lock")},
		[]kernelDecl{funcDecl("bpf_rcu_read_unlock")})
	if err := resolveExterns(obj); err != nil {
		t.Fatalf("resolveExterns: %v", err)
	}
	code := relocatedProgram(t, obj, "handle_ksyms")

	want := map[int]bpfInsn{
		0: {Code: bpfLD | bpfImm | bpfSizeDW, Dst: 1, Src: bpfPseudoBtfID, Imm: kernBaseTypes},
		4: {Code: bpfJMP | bpfCall, Src: bpfPseudoKfuncCall, Imm: kernBaseTypes + 1},
		6: {Code: bpfLD | bpfImm | bpfSizeDW, Dst: 2, Src: bpfPseudoMapValue, Imm: 1000},
		9: {Code: bpfJMP | bpfCall, Src: bpfPseudoKfuncCall, Off: 1, Imm: kernBaseTypes + 2},
	}
	for idx, w := range want {
		if got, imm2 := insnAt(code, idx); got != w || (idx == 0 && imm2 != 0) {
			t.Errorf("insn %d = %+v (imm2 %d), want %+v", idx, got, imm2, w)
		}
	}
	if !reflect.DeepEqual(obj.fdArray, []int32{0, testModuleFD}) {
		t.Errorf("fd array = %v, want [0 %d]", obj.fdArray, testModuleFD)
	}
}

// TestRelocateKsymsWeak relocates link_ksyms_weak.bpf.o with only
// bpf_prog_active resolved: the missing variables and the kfunc address
// load zero, the guarded kfunc call is poisoned with the extern's index, and
// bpf_prog_active loads its address.
func TestRelocateKsymsWeak(t *testing.T) {
	obj := openProg(t, ksymsWeakProg)
	active := findExternByName(obj.externs, "bpf_prog_active")
	active.isSet, active.ksym.addr = true, 0xffffffff00abcdef
	code := relocatedProgram(t, obj, "handle_ksyms_weak")

	kfuncIdx := -1
	for i := range obj.externs {
		if obj.externs[i].name == "gobpfgo_missing_kfunc" {
			kfuncIdx = i
		}
	}
	zero := bpfInsn{Code: bpfLD | bpfImm | bpfSizeDW}
	tests := []struct {
		idx  int
		want bpfInsn
		imm2 uint32
	}{
		{2, bpfInsn{Code: zero.Code, Dst: 2}, 0},
		{6, bpfInsn{Code: zero.Code, Dst: 4}, 0},
		{11, bpfInsn{Code: zero.Code, Dst: 4}, 0},
		{18, bpfInsn{Code: bpfJMP | bpfCall, Imm: int32(poisonCallKfuncBase + kfuncIdx)}, 0},
		{21, bpfInsn{Code: zero.Code, Dst: 2, Imm: 0x00abcdef}, 0xffffffff},
	}
	for _, tt := range tests {
		if got, imm2 := insnAt(code, tt.idx); got != tt.want || imm2 != tt.imm2 {
			t.Errorf("insn %d = %+v (imm2 %#x), want %+v (imm2 %#x)", tt.idx, got, imm2, tt.want, tt.imm2)
		}
	}
}
