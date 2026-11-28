// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// coreCandsObject opens the named object from testdata/progs, which has one
// program and one CO-RE section, and returns it with its CO-RE records in
// .BTF.ext order and the BTF of the named targets.
func coreCandsObject(t *testing.T, object string, targets ...string) (*BpfObject, *btf.ExtSpec, []btf.CoreRelo, []*btf.Spec) {
	t.Helper()

	obj := openProg(t, object)
	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("%s: ParseExt: %v", object, err)
	}
	if len(obj.programs) != 1 || len(ext.CoreRelos) != 1 {
		t.Fatalf("%s: %d programs and %d CO-RE sections, want one each", object, len(obj.programs), len(ext.CoreRelos))
	}

	var kernels []*btf.Spec
	for _, target := range targets {
		_, spec, _ := coreMatchObject(t, target)
		kernels = append(kernels, spec)
	}
	return obj, ext, ext.CoreRelos[0].Relos, kernels
}

// checkCoreImms checks the immediate of the instruction each CO-RE record
// of the object's only program relocated.
func checkCoreImms(t *testing.T, obj *BpfObject, insns map[*BpfProgram][]byte, relos []btf.CoreRelo, want []int32) {
	t.Helper()

	code := insns[obj.programs[0]]
	if len(relos) != len(want) {
		t.Fatalf("%d CO-RE records, want %d", len(relos), len(want))
	}
	for i, relo := range relos {
		if got := decodeBpfInsn(code[relo.InsnOff:]).Imm; got != want[i] {
			t.Errorf("record %d at insn %d = %d, want %d", i, relo.InsnOff/bpfInsnLength, got, want[i])
		}
	}
}

// TestCoreFieldOffsetAmbiguity relocates core_amb.bpf.o, whose records read
// cc_amb.y, against two candidates that both have y, at bit 32 in cc_amb and
// at bit 0 in cc_amb___v2. Both candidates match, so the relocation fails on
// the bit offsets before it compares values: field_exists resolves to 1 for
// both and would otherwise pass. Against the single candidate cc_amb the
// same records resolve.
func TestCoreFieldOffsetAmbiguity(t *testing.T) {
	obj, ext, relos, kernels := coreCandsObject(t, "core_amb.bpf.o", "core_cands_target.bpf.o")

	_, err := coreRelocatedInsns(obj, ext, kernels)
	if want := "core relocation at insn 0: field offset ambiguity: 0 != 32"; err == nil || err.Error() != want {
		t.Fatalf("relocation with two candidates: %v, want %q", err, want)
	}

	_, single, _ := coreMatchObject(t, "core_amb_single.bpf.o")
	insns, err := coreRelocatedInsns(obj, ext, []*btf.Spec{single})
	if err != nil {
		t.Fatalf("relocation with one candidate: %v", err)
	}
	checkCoreImms(t, obj, insns, relos, []int32{1, 4})
}

// TestCoreCandidateNarrowing relocates core_cands.bpf.o against two
// candidates for each local type. The first record of each type matches only
// one candidate, which then is the type's only candidate: the offset of
// cc_nar.b comes from cc_nar alone, and cc_pick.b, which only cc_pick___v2
// has, does not exist. Relocated with the full candidate list instead, the
// same records fail on the offsets of b and find b.
func TestCoreCandidateNarrowing(t *testing.T) {
	obj, ext, relos, kernels := coreCandsObject(t, "core_cands.bpf.o", "core_cands_target.bpf.o")

	insns, err := coreRelocatedInsns(obj, ext, kernels)
	if err != nil {
		t.Fatalf("relocateCore: %v", err)
	}
	// nar.a exists, nar.b's byte offset, pick.a exists, pick.b exists.
	checkCoreImms(t, obj, insns, relos, []int32{1, 4, 1, 0})

	_, err = coreReloResult(obj.btf, relos[1], kernels, make(coreCandCache))
	if want := "field offset ambiguity: 64 != 32"; err == nil || err.Error() != want {
		t.Errorf("cc_nar.b with both candidates: %v, want %q", err, want)
	}
	res, err := coreReloResult(obj.btf, relos[3], kernels, make(coreCandCache))
	if err != nil || res.NewVal != 1 {
		t.Errorf("cc_pick.b with both candidates = %+v, %v, want 1", res, err)
	}
}

// TestCoreCandCacheNoMatch relocates the cc_pick records of core_cands.bpf.o
// in reverse order with one cache. cc_pick.b matches only cc_pick___v2, which
// becomes the only candidate; cc_pick.a then matches nothing, resolves to 0
// and leaves that list as it was.
func TestCoreCandCacheNoMatch(t *testing.T) {
	obj, _, relos, kernels := coreCandsObject(t, "core_cands.bpf.o", "core_cands_target.bpf.o")
	pickA, pickB := relos[2], relos[3]
	cache := make(coreCandCache)

	res, err := coreReloResult(obj.btf, pickB, kernels, cache)
	if err != nil || res.NewVal != 1 {
		t.Fatalf("cc_pick.b = %+v, %v, want 1", res, err)
	}
	if got := coreCandNames(t, cache[pickB.TypeID]); got != "cc_pick___v2" {
		t.Errorf("candidates after cc_pick.b = %q, want cc_pick___v2", got)
	}

	res, err = coreReloResult(obj.btf, pickA, kernels, cache)
	if err != nil || res.NewVal != 0 || res.Poison {
		t.Fatalf("cc_pick.a = %+v, %v, want 0", res, err)
	}
	if got := coreCandNames(t, cache[pickA.TypeID]); got != "cc_pick___v2" {
		t.Errorf("candidates after cc_pick.a = %q, want cc_pick___v2 still", got)
	}
}

// coreCandNames returns the names of cands, comma-separated.
func coreCandNames(t *testing.T, cands []coreCandidate) string {
	t.Helper()

	names := make([]string, 0, len(cands))
	for _, cand := range cands {
		typ, err := cand.spec.TypeByID(cand.id)
		if err != nil {
			t.Fatalf("candidate %d: %v", cand.id, err)
		}
		names = append(names, typ.Name)
	}
	return strings.Join(names, ",")
}

// TestCoreNoTargetResult computes the field records of core_local.bpf.o,
// whose struct the target lacks, without a candidate. Each first computes its
// local side: field_exists resolves to 0 and keeps the check of its original
// 1, the signedness of the int val is 1 locally and poisoned, and the
// signedness of an array element cannot be computed and fails.
func TestCoreNoTargetResult(t *testing.T) {
	obj, _, relos, _ := coreCandsObject(t, "core_local.bpf.o")
	exists, signed, signedElem := relos[0], relos[2], relos[3]

	res, err := coreNoTargetResult(obj.btf, exists)
	if err != nil || res.OrigVal != 1 || res.NewVal != 0 || !res.Validate || res.Poison {
		t.Errorf("field_exists = %+v, %v, want 1/0, validated, not poisoned", res, err)
	}
	res, err = coreNoTargetResult(obj.btf, signed)
	if err != nil || res.OrigVal != 1 || !res.Validate || !res.Poison {
		t.Errorf("field_signed of val = %+v, %v, want 1 locally, validated, poisoned", res, err)
	}
	if res, err = coreNoTargetResult(obj.btf, signedElem); err == nil || !strings.Contains(err.Error(), "array access") {
		t.Errorf("field_signed of arr[1] = %+v, %v, want the array access error", res, err)
	}
}

// TestCoreLocalFieldLoad loads core_local.bpf.o. No kernel has its struct,
// and the signedness of arr[1] cannot be computed even locally, so the load
// fails with EINVAL while it relocates, before any program reaches the
// kernel, instead of loading a poisoned instruction the type check keeps out
// of reach. It needs no privileges and skips without kernel BTF.
func TestCoreLocalFieldLoad(t *testing.T) {
	requireKernelBTF(t)
	obj := openProg(t, "core_local.bpf.o")

	err := BpfObjectLoad(obj)
	var lerr *Error
	if !errors.As(err, &lerr) || lerr.Op != "bpf_object__relocate_core" || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("load: %v, want a bpf_object__relocate_core EINVAL", err)
	}
	if !strings.Contains(lerr.Log, "array access") {
		t.Errorf("load log = %q, want the array access error", lerr.Log)
	}
}
