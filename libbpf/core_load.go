// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/relo_core.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__relocate_core, bpf_core_calc_relo_insn, bpf_core_patch_insn

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
		module, err := btf.Parse(data, binary.NativeEndian)
		if err != nil {
			continue
		}
		merged, err := btf.MergeSplit(vmlinux, module)
		if err != nil {
			continue
		}
		kernels = append(kernels, merged)
	}

	return kernels, nil
}

type coreCandidate struct {
	spec *btf.Spec
	id   uint32
}

// relocateCore applies the CO-RE records of p's section to a private copy of
// its instructions. Field, type and enum values are matched across the
// vmlinux and module BTFs; a value that cannot be resolved is poisoned, which
// the verifier rejects only if the instruction is reachable.
func relocateCore(p *BpfProgram, insns []byte, ext *btf.ExtSpec, local *btf.Spec, kernels []*btf.Spec) error {
	if ext == nil || local == nil || len(kernels) == 0 {
		return nil
	}

	for _, section := range ext.CoreRelos {
		if section.Section != p.sectionName {
			continue
		}

		for _, relo := range section.Relos {
			res, err := coreReloResult(local, relo, kernels)
			if err != nil {
				return fmt.Errorf("core relocation at insn %d: %w", relo.InsnOff, err)
			}

			off := int(relo.InsnOff)
			if off < 0 || off+bpfInsnLength > len(insns) {
				return fmt.Errorf("core relocation at insn %d is out of bounds", relo.InsnOff)
			}
			if err := patchCoreInsn(insns[off:], res); err != nil {
				return fmt.Errorf("core relocation at insn %d: %w", relo.InsnOff, err)
			}
		}
	}

	return nil
}

// coreReloResult picks the matching target across the kernel BTFs and
// rejects an ambiguous result. With no match, it returns the value libbpf
// uses when a candidate is absent.
func coreReloResult(local *btf.Spec, relo btf.CoreRelo, kernels []*btf.Spec) (*btf.CoreReloResult, error) {
	if relo.Kind == btf.CoreTypeIDLocal {
		return local.CalcCoreRelo(relo, nil, 0)
	}

	localType, err := local.TypeByID(relo.TypeID)
	if err != nil {
		return nil, err
	}

	var matched *btf.CoreReloResult
	if localType.Name != "" {
		for _, kernel := range kernels {
			targetType := kernel.Find(localType.Name, localType.Kind)
			if targetType == nil {
				continue
			}
			res, err := local.CalcCoreRelo(relo, kernel, targetType.ID)
			if err != nil {
				return nil, err
			}
			if !res.Matched {
				continue
			}
			if matched == nil {
				matched = res
				continue
			}
			if matched.NewVal != res.NewVal || matched.Poison != res.Poison || matched.Validate != res.Validate {
				return nil, fmt.Errorf("core relocation %s is ambiguous across target BTFs", localType.Name)
			}
		}
	}

	if matched != nil {
		return matched, nil
	}
	return coreNoTargetResult(local, relo)
}

// coreNoTargetResult is the value libbpf computes with no matching candidate.
func coreNoTargetResult(local *btf.Spec, relo btf.CoreRelo) (*btf.CoreReloResult, error) {
	res := &btf.CoreReloResult{}

	switch relo.Kind {
	case btf.CoreTypeExists:
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
	case btf.CoreFieldExists, btf.CoreEnumvalExists:
		res.OrigVal = 1
		res.Validate = true
	default:
		res.Poison = true
	}

	return res, nil
}
