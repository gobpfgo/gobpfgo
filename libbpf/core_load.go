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

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

// vmlinuxBTFPath is the kernel BTF blob used for CO-RE target matching.
const vmlinuxBTFPath = "/sys/kernel/btf/vmlinux"

// objectCoreRelocations parses the object's .BTF.ext and, when it carries
// CO-RE records, loads the kernel BTF. Both are nil when there is nothing to
// relocate.
func objectCoreRelocations(obj *BpfObject) (*btf.ExtSpec, *btf.Spec, error) {
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

	kernel, err := loadKernelBTF()
	if err != nil {
		return nil, nil, err
	}
	return ext, kernel, nil
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

// relocateCore applies the CO-RE records of p's section to a private copy of
// its instructions. Field accessors are matched against the kernel BTF and
// the accessed offset or immediate is patched in place.
func relocateCore(p *BpfProgram, insns []byte, ext *btf.ExtSpec, local, kernel *btf.Spec) error {
	if ext == nil || local == nil || kernel == nil {
		return nil
	}

	for _, section := range ext.CoreRelos {
		if section.Section != p.sectionName {
			continue
		}

		for _, relo := range section.Relos {
			localType, err := local.TypeByID(relo.TypeID)
			if err != nil {
				return fmt.Errorf("core relocation type %d: %w", relo.TypeID, err)
			}
			var targetTypeID uint32
			if relo.Kind != btf.CoreTypeIDLocal {
				if localType.Name == "" {
					return fmt.Errorf("core relocation type %d is anonymous", relo.TypeID)
				}
				targetType := kernel.Find(localType.Name, localType.Kind)
				if targetType == nil {
					return fmt.Errorf("core relocation target %s not found", localType.Name)
				}
				targetTypeID = targetType.ID
			}

			res, err := local.CalcCoreRelo(relo, kernel, targetTypeID)
			if err != nil {
				return fmt.Errorf("core relocation %s: %w", localType.Name, err)
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
