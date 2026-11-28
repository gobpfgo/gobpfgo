// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/relo_core.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__relocate_core, bpf_core_calc_relo_insn, bpf_core_patch_insn, bpf_core_resolve_relo, bpf_core_find_cands, elf_sec_by_name

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

// vmlinuxBTFPath is the kernel BTF blob used for CO-RE target matching.
const vmlinuxBTFPath = "/sys/kernel/btf/vmlinux"

// kernelBTFDir holds the module BTF blobs next to vmlinux.
const kernelBTFDir = "/sys/kernel/btf"

// objectCoreRelocations parses the object's .BTF.ext and, when it carries
// CO-RE records, loads the vmlinux and module BTF targets. The targets are
// nil when there is nothing to relocate.
func objectCoreRelocations(obj *BpfObject) (*btf.ExtSpec, []*btf.Spec, error) {
	if obj == nil || obj.btf == nil || obj.elf == nil || len(obj.elf.BTFExt) == 0 {
		return nil, nil, nil
	}

	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		return nil, nil, err
	}
	if !hasCoreRelos(ext) {
		return ext, nil, nil
	}

	kernels, err := loadKernelBTFs()
	if err != nil {
		return nil, nil, err
	}
	return ext, kernels, nil
}

func hasCoreRelos(ext *btf.ExtSpec) bool {
	if ext == nil {
		return false
	}
	for _, section := range ext.CoreRelos {
		if len(section.Relos) > 0 {
			return true
		}
	}
	return false
}

// loadKernelBTF reads and parses the running kernel's vmlinux BTF.
func loadKernelBTF() (*btf.Spec, error) {
	data, err := os.ReadFile(vmlinuxBTFPath)
	if err != nil {
		return nil, fmt.Errorf("read kernel BTF: %w", err)
	}
	kernel, err := btf.Parse(data, binary.NativeEndian)
	if err != nil {
		return nil, fmt.Errorf("parse kernel BTF: %w", err)
	}
	return kernel, nil
}

// loadKernelBTFs loads vmlinux BTF and every module BTF the kernel exposes.
// A module BTF that cannot be read or parsed is skipped; the matching type may
// still be in vmlinux or another module.
func loadKernelBTFs() ([]*btf.Spec, error) {
	vmlinux, err := loadKernelBTF()
	if err != nil {
		return nil, err
	}
	kernels := []*btf.Spec{vmlinux}

	entries, err := os.ReadDir(kernelBTFDir)
	if err != nil {
		return kernels, nil
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "vmlinux" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(kernelBTFDir, entry.Name()))
		if err != nil {
			continue
		}
		module, err := btf.ParseSplit(data, binary.NativeEndian, vmlinux)
		if err != nil {
			continue
		}
		kernels = append(kernels, module)
	}

	return kernels, nil
}

type coreCandidate struct {
	spec *btf.Spec
	id   uint32
}

// coreCandCache holds the target candidates of each local type, by local
// type ID, for the CO-RE relocation of one object. The first relocation of a
// local type searches its candidates; every relocation then keeps only the
// candidates it matched, when it matched any, so later relocations of the
// type see fewer candidates.
type coreCandCache map[uint32][]coreCandidate

// cands returns the candidate list of the local type localID, searching it
// with coreFindCandidates on first use. A failed search is not cached.
func (c coreCandCache) cands(local *btf.Spec, localID uint32, kernels []*btf.Spec) ([]coreCandidate, error) {
	if cands, ok := c[localID]; ok {
		return cands, nil
	}
	cands, err := coreFindCandidates(local, localID, kernels)
	if err != nil {
		return nil, err
	}
	c[localID] = cands
	return cands, nil
}

// relocateCore applies the CO-RE records of obj to insns, the private
// copies of its programs' instructions, in .BTF.ext order: section by
// section, each in record order. Clang records byte offsets from the section
// start; a record outside every program, such as one of a weak function that
// another object overrode, is skipped, and so is every record of a section
// the object does not have, which no program is in. Field, type and enum
// values are matched against the candidates of the record's local type in
// the vmlinux and module BTFs, which every record of that type shares and
// narrows, as coreCandCache describes; a value that cannot be resolved is
// poisoned, which the verifier rejects only if the instruction is reachable.
// The first record that cannot be relocated stops the relocation with an
// error.
func relocateCore(obj *BpfObject, insns map[*BpfProgram][]byte, ext *btf.ExtSpec, kernels []*btf.Spec) error {
	if ext == nil || obj.btf == nil || len(kernels) == 0 {
		return nil
	}

	cache := make(coreCandCache)
	for _, section := range ext.CoreRelos {
		if section.Section == "" {
			return fmt.Errorf("core relocation section has no name")
		}
		secIdx := elfSecIdxByName(obj, section.Section)

		for _, relo := range section.Relos {
			if relo.InsnOff%bpfInsnLength != 0 {
				return fmt.Errorf("core relocation at insn %d is not aligned", relo.InsnOff)
			}
			insnIdx := int(relo.InsnOff / bpfInsnLength)
			p := findProgBySecInsn(obj.programs, secIdx, insnIdx)
			if p == nil {
				continue
			}

			code := insns[p]
			off := (insnIdx - p.secInsnOff) * bpfInsnLength
			if off+bpfInsnLength > len(code) {
				return fmt.Errorf("core relocation at insn %d is out of bounds", relo.InsnOff)
			}
			if code[off] == bpfLD|bpfImm|bpfSizeDW && off+2*bpfInsnLength > len(code) {
				return fmt.Errorf("core relocation at insn %d: LDIMM64 is truncated", relo.InsnOff)
			}
			res, err := coreReloResult(obj.btf, relo, kernels, cache)
			if err != nil {
				return fmt.Errorf("core relocation at insn %d: %w", relo.InsnOff, err)
			}
			if err := patchCoreInsn(code[off:], res); err != nil {
				return fmt.Errorf("core relocation at insn %d: %w", relo.InsnOff, err)
			}
		}
	}

	return nil
}

// elfSecIdxByName returns the index of the first ELF section of obj named
// name, or 0, the index no program has, when there is none.
func elfSecIdxByName(obj *BpfObject, name string) int {
	for _, sec := range obj.elf.Sections {
		if sec.Name == name {
			return sec.Index
		}
	}
	return 0
}

// coreReloResult computes relo against every candidate of its local type in
// cache, in order, and rejects an ambiguous result: the candidates that match
// must agree on the target field's bit offset, then on poisoning and the
// value. The candidates that matched replace the cached list, in place; when
// none matched, the list stays and the result is the one libbpf computes
// without a target. The candidate search runs first, then the access string
// is parsed before any candidate is tried: a malformed string fails even
// without candidates, and on an anonymous local type the failed search is
// reported instead.
func coreReloResult(local *btf.Spec, relo btf.CoreRelo, kernels []*btf.Spec, cache coreCandCache) (*btf.CoreReloResult, error) {
	var cands []coreCandidate
	if relo.Kind != btf.CoreTypeIDLocal {
		var err error
		if cands, err = cache.cands(local, relo.TypeID, kernels); err != nil {
			return nil, err
		}
	}
	if _, err := local.ParseCoreSpec(relo); err != nil {
		return nil, err
	}
	if relo.Kind == btf.CoreTypeIDLocal {
		return local.CalcCoreRelo(relo, nil, 0)
	}

	var matched *btf.CoreReloResult
	kept := 0
	for _, cand := range cands {
		res, err := local.CalcCoreRelo(relo, cand.spec, cand.id)
		if err != nil {
			return nil, err
		}
		if !res.Matched {
			continue
		}
		switch {
		case matched == nil:
			matched = res
		case res.TargetBitOffset != matched.TargetBitOffset:
			return nil, fmt.Errorf("field offset ambiguity: %d != %d", res.TargetBitOffset, matched.TargetBitOffset)
		case res.Poison != matched.Poison || res.NewVal != matched.NewVal:
			return nil, fmt.Errorf("relocation decision ambiguity: %s %d != %s %d",
				coreDecision(res), res.NewVal, coreDecision(matched), matched.NewVal)
		}
		// Compacting in place, as libbpf does, leaves the list of a failed
		// relocation partly rewritten; the load stops there.
		cands[kept] = cand
		kept++
	}

	if matched == nil {
		return coreNoTargetResult(local, relo)
	}
	cache[relo.TypeID] = cands[:kept]
	return matched, nil
}

// coreDecision names the relocation decision of res in an ambiguity error.
func coreDecision(res *btf.CoreReloResult) string {
	if res.Poison {
		return "failure"
	}
	return "success"
}

// coreFindCandidates returns the target candidates for the local type
// localID: the types btf.Spec.CoreCandidates finds in vmlinux, kernels[0],
// and only when vmlinux has none, those it finds among the types each module
// BTF owns, in module order. A local type without a name has no candidates
// and is an error.
func coreFindCandidates(local *btf.Spec, localID uint32, kernels []*btf.Spec) ([]coreCandidate, error) {
	localType, err := local.TypeByID(localID)
	if err != nil {
		return nil, err
	}
	if localType.Name == "" {
		return nil, fmt.Errorf("target candidate search failed for [%d] %s: anonymous type", localID, localType.Kind)
	}

	var cands []coreCandidate
	for i, kernel := range kernels {
		if i == 1 && len(cands) > 0 {
			break
		}
		for _, id := range kernel.CoreCandidates(localType, kernel.StartID()) {
			cands = append(cands, coreCandidate{spec: kernel, id: id})
		}
	}
	return cands, nil
}

// coreNoTargetResult is the value libbpf computes with no matching
// candidate. A field-based relocation first computes its local side, so an
// access its kind cannot apply to, such as the signedness of an array
// element, fails the relocation; field_exists then resolves to 0 and every
// other field kind is poisoned. Type-based relocations and enumval_exists
// resolve to 0, and enumval_value is poisoned.
func coreNoTargetResult(local *btf.Spec, relo btf.CoreRelo) (*btf.CoreReloResult, error) {
	switch relo.Kind {
	case btf.CoreFieldByteOffset, btf.CoreFieldByteSize, btf.CoreFieldExists,
		btf.CoreFieldSigned, btf.CoreFieldLShiftU64, btf.CoreFieldRShiftU64:
		res, err := local.CalcCoreFieldLocal(relo)
		if err != nil {
			return nil, err
		}
		res.Poison = relo.Kind != btf.CoreFieldExists
		return res, nil
	}

	res := &btf.CoreReloResult{}
	switch relo.Kind {
	case btf.CoreTypeExists, btf.CoreTypeMatches:
		res.OrigVal = 1
		res.Validate = true
	case btf.CoreTypeIDTarget:
		res.OrigVal = uint64(relo.TypeID)
	case btf.CoreTypeSize:
		size, err := local.SizeOf(relo.TypeID)
		if err != nil {
			return nil, err
		}
		res.OrigVal = uint64(size)
		res.Validate = true
	case btf.CoreEnumvalExists:
		res.OrigVal = 1
		res.Validate = true
	default:
		res.Poison = true
	}

	return res, nil
}
