// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"errors"
	"maps"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// sectionBytes copies the instruction bytes of every executable section of
// obj, by section index.
func sectionBytes(obj *BpfObject) map[int][]byte {
	secs := make(map[int][]byte)
	for _, sec := range obj.elf.Programs {
		secs[sec.SectionIndex] = bytes.Clone(sec.Insns)
	}
	return secs
}

// TestBpfProgramInsnsFinal relocates subprog.bpf.o without a kernel and
// installs each main program's code as the load does after loading it.
// Before that, every function returns its own instructions. After it, each
// main program returns its final code, libbpf's with the subprograms
// appended, in a buffer of its own; the subprograms keep their own
// instructions and the object's section data does not change.
func TestBpfProgramInsnsFinal(t *testing.T) {
	want := loadSubprogFixture(t, "subprog.json")
	obj := openSubprogObject(t, "subprog.bpf.o")
	secs := sectionBytes(obj)

	own := make(map[*BpfProgram][]byte, len(obj.programs))
	for _, p := range obj.programs {
		if BpfProgramInsnCnt(p) != p.secInsnCnt {
			t.Errorf("%s: %d instructions before load, want its own %d", p.name, BpfProgramInsnCnt(p), p.secInsnCnt)
		}
		own[p] = bytes.Clone(BpfProgramInsns(p))
	}

	codes, err := relocateWithoutKernel(t, obj, objectExt(t, obj))
	if err != nil {
		t.Fatalf("relocate: %v", err)
	}
	setFinalInsns(codes)

	for i, w := range want.Programs {
		p := BpfObjectFindProgramByName(obj, w.Name)
		insns := BpfProgramInsns(p)
		if p != codes[i].prog || BpfProgramInsnCnt(p) != w.InsnCnt || len(insns) != w.InsnCnt*bpfInsnLength {
			t.Fatalf("%s: %d instructions after load, want %d", w.Name, BpfProgramInsnCnt(p), w.InsnCnt)
		}
		if !bytes.Equal(insns, mapLoadsByDescriptor(mustDecodeHex(t, w.Insns))) {
			t.Errorf("%s: final code differs from libbpf's", w.Name)
		}
		if &insns[0] == &sectionInsns(t, obj, p.secIdx)[p.secInsnOff*bpfInsnLength] {
			t.Errorf("%s: final code aliases the section data", w.Name)
		}
	}
	for _, p := range obj.programs {
		if progIsSubprog(obj, p) && !bytes.Equal(BpfProgramInsns(p), own[p]) {
			t.Errorf("subprogram %s: instructions changed", p.name)
		}
	}
	if !maps.EqualFunc(sectionBytes(obj), secs, bytes.Equal) {
		t.Error("section data changed")
	}
}

// sectionInsns returns the instruction bytes the object holds for the
// executable section with index secIdx.
func sectionInsns(t *testing.T, obj *BpfObject, secIdx int) []byte {
	t.Helper()

	for _, sec := range obj.elf.Programs {
		if sec.SectionIndex == secIdx {
			return sec.Insns
		}
	}
	t.Fatalf("no executable section %d", secIdx)
	return nil
}

// checkFinalInsnCounts requires every main program of obj, after a load, to
// return the instruction count of libbpf's final code in fixture.
func checkFinalInsnCounts(t *testing.T, obj *BpfObject, fixture string) {
	t.Helper()

	for _, w := range loadSubprogFixture(t, fixture).Programs {
		p := BpfObjectFindProgramByName(obj, w.Name)
		if p == nil {
			t.Fatalf("program %s not found", w.Name)
		}
		if got := BpfProgramInsnCnt(p); got != w.InsnCnt || len(BpfProgramInsns(p)) != w.InsnCnt*bpfInsnLength {
			t.Errorf("%s: %d instructions after load, want %d", w.Name, got, w.InsnCnt)
		}
	}
}

// TestSubprogHiddenLoad loads subprog_hidden.bpf.o. Its hidden subprogram
// dereferences a pointer argument without a NULL check, which the verifier
// accepts only for a static function, so the load proves its BTF FUNC
// became static; the hidden main program stays global. Only the main
// program has a descriptor, and it returns its final code with both
// subprograms appended. It needs root or CAP_BPF and skips otherwise.
func TestSubprogHiddenLoad(t *testing.T) {
	obj := loadTestObject(t, subprogHiddenObject)
	defer BpfObjectClose(obj)

	checkSubprogDescriptors(t, obj)
	checkFinalInsnCounts(t, obj, "subprog-hidden.json")
	for name, want := range map[string]uint32{
		"subprog_hidden":  btf.FuncStatic,
		"subprog_visible": btf.FuncGlobal,
		"handle_hidden":   btf.FuncGlobal,
	} {
		if got := funcLinkage(t, obj.btf, name); got != want {
			t.Errorf("%s linkage = %d after load, want %d", name, got, want)
		}
	}
}

// TestSubprogArgCtxLoad loads subprog_arg_ctx.bpf.o, whose global
// subprogram reads its __arg_ctx context argument. A kernel that reads the
// arg:ctx tag loads the BTF as compiled; on an older kernel the load must
// first rewrite the argument's BTF type, adding ten types, two of them decl
// tags. A kernel without BTF decl tags gets a sanitized copy of that BTF,
// while the object BTF keeps every decl tag. The test checks that the
// rewrite ran exactly when the feature probe found no support and that the
// object BTF still has its tags, then that both programs loaded with their
// final code. It logs which paths the kernel took. It needs root or CAP_BPF
// and skips otherwise.
func TestSubprogArgCtxLoad(t *testing.T) {
	obj, err := BpfObjectOpenFile(subprogArgCtxObject, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer BpfObjectClose(obj)
	openTypes, openTags := len(obj.btf.Types), countKind(obj.btf, btf.KindDeclTag)

	err = BpfObjectLoad(obj)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("bpf() not permitted: %v", err)
	}
	native, declTag := featArgCtxTag.supported(), featBtfDeclTag.supported()
	added, addedTags := len(obj.btf.Types)-openTypes, countKind(obj.btf, btf.KindDeclTag)-openTags
	t.Logf("kernel %s: native arg:ctx support %v, decl tag support %v, types added %d", kernelRelease(t), native, declTag, added)
	if native && !declTag {
		t.Error("the kernel reads the arg:ctx decl tag but rejects decl tags")
	}
	if want := map[bool]int{true: 0, false: 10}[native]; added != want {
		t.Errorf("load added %d types, want %d", added, want)
	}
	if want := map[bool]int{true: 0, false: 2}[native]; addedTags != want {
		t.Errorf("object BTF gained %d decl tags, want %d", addedTags, want)
	}
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	checkSubprogDescriptors(t, obj)
	checkFinalInsnCounts(t, obj, "subprog-arg-ctx.json")
}

// countKind returns the number of types of kind in spec.
func countKind(spec *btf.Spec, kind btf.Kind) int {
	n := 0
	for i := range spec.Types {
		if spec.Types[i].Kind == kind {
			n++
		}
	}
	return n
}
