// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
)

// coreMatchCand is one target candidate of a core-match fixture relocation,
// with libbpf's type match and compatibility results: 1, 0 or a negative
// errno.
type coreMatchCand struct {
	TypeID uint32 `json:"type_id"`
	Name   string `json:"name"`
	Match  int    `json:"match"`
	Compat int    `json:"compat"`
}

// coreMatchEntry is one relocation of the core-match fixture: its candidates
// and libbpf's result over all of them, which is set when Err is 0.
type coreMatchEntry struct {
	Section  string          `json:"section"`
	InsnOff  uint32          `json:"insn_off"`
	TypeID   uint32          `json:"type_id"`
	Kind     uint32          `json:"kind"`
	Name     string          `json:"name"`
	Cands    []coreMatchCand `json:"cands"`
	Err      int             `json:"err"`
	OrigVal  uint64          `json:"orig_val"`
	NewVal   uint64          `json:"new_val"`
	Validate bool            `json:"validate"`
	Poison   bool            `json:"poison"`
	NewInsn  coreRelocInsn   `json:"new_insn"`
}

// coreMatchObject parses the .BTF, .BTF.ext and sections of an object in
// testdata/progs.
func coreMatchObject(t *testing.T, name string) (*elf.Object, *btf.Spec, *btf.ExtSpec) {
	t.Helper()

	o, err := elf.Open(progsDir + "/" + name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	spec, err := btf.Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse %s BTF: %v", name, err)
	}
	var ext *btf.ExtSpec
	if len(o.BTFExt) > 0 {
		if ext, err = btf.ParseExt(o.BTFExt, spec, o.ByteOrder); err != nil {
			t.Fatalf("parse %s BTF.ext: %v", name, err)
		}
	}
	return o, spec, ext
}

// TestCoreMatch replays the core-match fixtures, in which libbpf relocates
// every CO-RE record of an object against the BTF of a target, in .BTF.ext
// order, with one candidate list per local type that each relocation
// narrows to the candidates it matched:
//
//   - core-match-reloc.json: the type-based records of core_match.bpf.o,
//     with matching and non-matching type_matches pairs, type_exists,
//     type_size and type_id_kernel records, a flavored name that is not a
//     flavor, two candidates that agree and two that do not, and type graphs
//     one step or one level too deep;
//   - core-local-reloc.json: field records of core_local.bpf.o on a type
//     the target lacks, whose local side is still computed, so the
//     signedness of an array element fails;
//   - core-amb-reloc.json and core-amb-single-reloc.json: field records of
//     core_amb.bpf.o against two candidates that have the field at
//     different offsets, which fail, and against one, which does not;
//   - core-cands-reloc.json: field records of core_cands.bpf.o whose second
//     relocation of a type sees only the candidate the first one matched.
//
// For each record it compares the candidate list the relocation sees,
// TypesMatch and TypesAreCompat against every candidate, whether the
// relocation fails, and the values and patched instruction of one that does
// not.
func TestCoreMatch(t *testing.T) {
	for _, tc := range []struct{ fixture, object, target string }{
		{"core-match-reloc.json", "core_match.bpf.o", "core_match_target.bpf.o"},
		{"core-local-reloc.json", "core_local.bpf.o", "core_target.bpf.o"},
		{"core-amb-reloc.json", "core_amb.bpf.o", "core_cands_target.bpf.o"},
		{"core-amb-single-reloc.json", "core_amb.bpf.o", "core_amb_single.bpf.o"},
		{"core-cands-reloc.json", "core_cands.bpf.o", "core_cands_target.bpf.o"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			replayCoreMatch(t, tc.fixture, tc.object, tc.target)
		})
	}
}

// replayCoreMatch relocates every CO-RE record of object against the BTF of
// target with one candidate cache, as the load does, and compares each record
// with the oracle fixture.
func replayCoreMatch(t *testing.T, fixture, object, target string) {
	o, local, ext := coreMatchObject(t, object)
	_, targetSpec, _ := coreMatchObject(t, target)

	data, err := os.ReadFile("../testdata/oracle/" + fixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var want struct {
		Relos []coreMatchEntry `json:"relos"`
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	sections := make(map[string][]byte)
	for _, section := range o.Sections {
		sections[section.Name] = section.Data
	}
	kernels := []*btf.Spec{targetSpec}
	cache := make(coreCandCache)
	i := 0
	for _, section := range ext.CoreRelos {
		for _, relo := range section.Relos {
			if i >= len(want.Relos) {
				t.Fatalf("the fixture has %d relocations, the object more", len(want.Relos))
			}
			entry := want.Relos[i]
			i++
			if section.Section != entry.Section || relo.InsnOff != entry.InsnOff || uint32(relo.Kind) != entry.Kind {
				t.Fatalf("relocation %s/%d kind %d, want %s/%d kind %d",
					section.Section, relo.InsnOff, relo.Kind, entry.Section, entry.InsnOff, entry.Kind)
			}
			checkCoreMatchCands(t, local, relo, kernels, cache, entry)
			checkCoreMatchResult(t, local, relo, kernels, cache, sections[section.Section], entry)
		}
	}
	if i != len(want.Relos) {
		t.Fatalf("the object has %d relocations, the fixture %d", i, len(want.Relos))
	}
}

// checkCoreMatchCands compares the candidates relo sees in cache, and the
// type match and compatibility results for each, with the entry. A
// type_id_local relocation has none.
func checkCoreMatchCands(t *testing.T, local *btf.Spec, relo btf.CoreRelo, kernels []*btf.Spec, cache coreCandCache, entry coreMatchEntry) {
	t.Helper()

	var cands []coreCandidate
	if relo.Kind != btf.CoreTypeIDLocal {
		var err error
		if cands, err = cache.cands(local, relo.TypeID, kernels); err != nil {
			t.Fatalf("%s: candidates: %v", entry.Name, err)
		}
	}
	var got []coreMatchCand
	for _, cand := range cands {
		targetType, err := cand.spec.TypeByID(cand.id)
		if err != nil {
			t.Fatalf("%s: candidate %d: %v", entry.Name, cand.id, err)
		}
		got = append(got, coreMatchCand{
			TypeID: cand.id,
			Name:   targetType.Name,
			Match:  coreCheckResult(btf.TypesMatch(local, relo.TypeID, cand.spec, cand.id)),
			Compat: coreCheckResult(btf.TypesAreCompat(local, relo.TypeID, cand.spec, cand.id)),
		})
	}
	if len(got) != len(entry.Cands) {
		t.Errorf("%s: candidates %+v, want %+v", entry.Name, got, entry.Cands)
		return
	}
	for j := range got {
		if got[j] != entry.Cands[j] {
			t.Errorf("%s: candidate %d = %+v, want %+v", entry.Name, j, got[j], entry.Cands[j])
		}
	}
}

// coreCheckResult turns a match or compatibility result into libbpf's int:
// 1 for true, 0 for false, and -EINVAL for an error.
func coreCheckResult(ok bool, err error) int {
	switch {
	case err != nil:
		return -22
	case ok:
		return 1
	default:
		return 0
	}
}

// checkCoreMatchResult relocates relo against kernels with coreReloResult
// and the shared cache, and compares the failure, the values and the patched
// instruction with the entry.
func checkCoreMatchResult(t *testing.T, local *btf.Spec, relo btf.CoreRelo, kernels []*btf.Spec, cache coreCandCache, program []byte, entry coreMatchEntry) {
	t.Helper()

	res, err := coreReloResult(local, relo, kernels, cache)
	if (err != nil) != (entry.Err != 0) {
		t.Errorf("%s kind %d: relocation error %v, want libbpf's %d", entry.Name, entry.Kind, err, entry.Err)
		return
	}
	if err != nil {
		return
	}
	if res.OrigVal != entry.OrigVal || res.NewVal != entry.NewVal || res.Validate != entry.Validate || res.Poison != entry.Poison {
		t.Errorf("%s kind %d: result %d/%d validate %v poison %v, want %d/%d validate %v poison %v",
			entry.Name, entry.Kind, res.OrigVal, res.NewVal, res.Validate, res.Poison,
			entry.OrigVal, entry.NewVal, entry.Validate, entry.Poison)
	}

	off := int(relo.InsnOff)
	if off+bpfInsnLength > len(program) {
		t.Fatalf("%s: instruction %d out of bounds", entry.Name, off)
	}
	insns := append([]byte(nil), program...)
	if err := patchCoreInsn(insns[off:], res); err != nil {
		t.Fatalf("%s: patchCoreInsn: %v", entry.Name, err)
	}
	if got := decodeBpfInsn(insns[off:]); got != entry.NewInsn.bpfInsn() {
		t.Errorf("%s kind %d: patched instruction %+v, want %+v", entry.Name, entry.Kind, got, entry.NewInsn.bpfInsn())
	}
}
