// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
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
// installs the instructions as the load does after loading it. Before that,
// every function returns its own instructions. After it, each main program
// returns its final code, libbpf's with the subprograms appended, in a
// buffer of its own. The subprograms have no CO-RE relocation and no
// subprogram address load, so each returns its own instructions unchanged,
// though in a buffer of its own, and the object's section data does not
// change.
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

	rel, err := relocateWithTargets(t, obj, objectExt(t, obj), nil, argCtxTagSupported)
	if err != nil {
		t.Fatalf("relocate: %v", err)
	}
	setFinalInsns(rel.codes, rel.subprogInsns)

	for i, w := range want.Programs {
		p := BpfObjectFindProgramByName(obj, w.Name)
		insns := BpfProgramInsns(p)
		if p != rel.codes[i].prog || BpfProgramInsnCnt(p) != w.InsnCnt || len(insns) != w.InsnCnt*bpfInsnLength {
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
		if !progIsSubprog(obj, p) {
			continue
		}
		insns := BpfProgramInsns(p)
		if !bytes.Equal(insns, own[p]) {
			t.Errorf("subprogram %s: instructions changed", p.name)
		}
		if &insns[0] == &sectionInsns(t, obj, p.secIdx)[p.secInsnOff*bpfInsnLength] {
			t.Errorf("subprogram %s: instructions alias the section data", p.name)
		}
	}
	if !maps.EqualFunc(sectionBytes(obj), secs, bytes.Equal) {
		t.Error("section data changed")
	}
}

// TestSubprogInsnsCore relocates subprog_core.bpf.o against the BTF of
// core_target.bpf.o and installs the instructions as a successful load does.
// Each .text subprogram then returns what libbpf leaves in it: its own
// function with libbpf's patched instruction, from the core-reloc oracle,
// at every CO-RE record inside it, and its load of the bpf_loop callback's
// address marked BPF_PSEUDO_FUNC. Nothing else changes, so the callback
// load keeps its .text offset, the map load stays unpatched and the call to
// the global subprogram keeps its object-file immediate. The main program
// returns its final code: libbpf's from the subprog oracle, whose generated
// loader leaves CO-RE to the kernel, with every record's patched instruction
// at its place in the main program's own code or in the appended copy of
// the subprogram that holds it.
func TestSubprogInsnsCore(t *testing.T) {
	obj := openSubprogObject(t, "subprog_core.bpf.o")
	target := objectBTF(t, "core_target.bpf.o")
	relos := loadCoreRelocFixture(t, "core-reloc-subprog.json")
	final := loadSubprogFixture(t, "subprog-core.json")
	secs := sectionBytes(obj)

	rel, err := relocateWithTargets(t, obj, objectExt(t, obj), []*btf.Spec{target}, argCtxTagSupported)
	if err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if len(rel.codes) != 1 || len(final.Programs) != 1 {
		t.Fatalf("%d main programs, fixture %d, want 1", len(rel.codes), len(final.Programs))
	}
	setFinalInsns(rel.codes, rel.subprogInsns)

	// The own-code index of each subprogram's subprogram address load and
	// the CO-RE records each holds.
	wantMarks := map[string][]int{"subprog_core_enum": nil, "subprog_core_read": {10}, "subprog_core_step": nil}
	wantRecords := map[string]int{"subprog_core_enum": 1, "subprog_core_read": 2, "subprog_core_step": 1}

	text := sectionInsns(t, obj, obj.textShndx)
	for _, p := range obj.programs {
		if !progIsSubprog(obj, p) {
			continue
		}
		marks, ok := wantMarks[p.name]
		if !ok {
			t.Fatalf("unexpected subprogram %s", p.name)
		}
		want := bytes.Clone(text[p.secInsnOff*bpfInsnLength : (p.secInsnOff+p.secInsnCnt)*bpfInsnLength])
		records := 0
		for _, r := range relos.Relos {
			idx := int(r.InsnOff / bpfInsnLength)
			if r.Section != textSec || !progContainsInsn(p, idx) {
				continue
			}
			off := (idx - p.secInsnOff) * bpfInsnLength
			if got := decodeBpfInsn(want[off:]); got != r.OrigInsn.bpfInsn() {
				t.Fatalf("%s: insn %d = %+v, oracle original %+v", p.name, idx-p.secInsnOff, got, r.OrigInsn.bpfInsn())
			}
			encodeBpfInsn(want[off:], r.NewInsn.bpfInsn())
			records++
		}
		if records != wantRecords[p.name] {
			t.Errorf("%s: %d CO-RE records, want %d", p.name, records, wantRecords[p.name])
		}
		for _, idx := range marks {
			want[idx*bpfInsnLength+1] = want[idx*bpfInsnLength+1]&0x0f | bpfPseudoFunc<<4
		}

		insns := BpfProgramInsns(p)
		if BpfProgramInsnCnt(p) != p.secInsnCnt {
			t.Errorf("%s: %d instructions after load, want its own %d", p.name, BpfProgramInsnCnt(p), p.secInsnCnt)
		}
		for i := 0; i < len(want); i += bpfInsnLength {
			if !bytes.Equal(insns[i:i+bpfInsnLength], want[i:i+bpfInsnLength]) {
				t.Errorf("%s: insn %d = %+v, want %+v", p.name, i/bpfInsnLength, decodeBpfInsn(insns[i:]), decodeBpfInsn(want[i:]))
			}
		}
		if &insns[0] == &text[p.secInsnOff*bpfInsnLength] {
			t.Errorf("%s: instructions alias the section data", p.name)
		}
	}

	code := rel.codes[0]
	main := code.prog
	want := mapLoadsByDescriptor(mustDecodeHex(t, final.Programs[0].Insns))
	for _, r := range relos.Relos {
		idx := int(r.InsnOff / bpfInsnLength)
		holder := main
		if r.Section == textSec {
			holder = findProgBySecInsn(obj.programs, obj.textShndx, idx)
		}
		start, ok := code.subInsnOff[holder]
		if holder == nil || !ok || (holder == main && r.Section != main.sectionName) {
			t.Fatalf("record %s+%d: no copy in %s", r.Section, r.InsnOff, main.name)
		}
		encodeBpfInsn(want[(start+idx-holder.secInsnOff)*bpfInsnLength:], r.NewInsn.bpfInsn())
	}
	if insns := BpfProgramInsns(main); !bytes.Equal(insns, want) {
		for i := 0; i < len(want) && i < len(insns); i += bpfInsnLength {
			if !bytes.Equal(insns[i:i+bpfInsnLength], want[i:i+bpfInsnLength]) {
				t.Errorf("%s: insn %d = %+v, want %+v", main.name, i/bpfInsnLength, decodeBpfInsn(insns[i:]), decodeBpfInsn(want[i:]))
			}
		}
		t.Errorf("%s: final code has %d instructions, want %d", main.name, len(insns)/bpfInsnLength, len(want)/bpfInsnLength)
	}

	if !maps.EqualFunc(sectionBytes(obj), secs, bytes.Equal) {
		t.Error("section data changed")
	}
}

// objectBTF parses the .BTF section of the object name in testdata/progs.
func objectBTF(t *testing.T, name string) *btf.Spec {
	t.Helper()

	o, err := elf.Open(progsDir + "/" + name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	spec, err := btf.Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse %s BTF: %v", name, err)
	}
	return spec
}

// loadCoreRelocFixture reads a core-reloc oracle fixture.
func loadCoreRelocFixture(t *testing.T, name string) coreRelocFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var f coreRelocFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if len(f.Relos) == 0 || !slices.ContainsFunc(f.Relos, func(r coreRelocEntry) bool { return r.Section == textSec }) {
		t.Fatalf("%s has no .text relocation", name)
	}
	return f
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
