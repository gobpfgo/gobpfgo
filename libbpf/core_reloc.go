// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/relo_core.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_core_patch_insn
// gobpfgo-origin: original Go instruction helpers

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

const (
	bpfClassMask  = 0x07
	bpfALU        = 0x04
	bpfALU64      = 0x07
	bpfLD         = 0x00
	bpfLDX        = 0x01
	bpfST         = 0x02
	bpfSTX        = 0x03
	bpfJMP        = 0x05
	bpfCall       = 0x80
	bpfSourceX    = 0x08
	bpfSizeMask   = 0x18
	bpfSizeW      = 0x00
	bpfSizeH      = 0x08
	bpfSizeB      = 0x10
	bpfSizeDW     = 0x18
	bpfPoisonImm  = 195896080
	bpfInsnLength = 8
)

// bpfInsn is one 8-byte instruction.
type bpfInsn struct {
	Code uint8
	Dst  uint8
	Src  uint8
	Off  int16
	Imm  int32
}

// decodeBpfInsn reads one instruction from b.
func decodeBpfInsn(b []byte) bpfInsn {
	regs := b[1]

	return bpfInsn{
		Code: b[0],
		Dst:  regs & 0x0f,
		Src:  regs >> 4,
		Off:  int16(binary.NativeEndian.Uint16(b[2:])),
		Imm:  int32(binary.NativeEndian.Uint32(b[4:])),
	}
}

// encodeBpfInsn writes one instruction to b.
func encodeBpfInsn(b []byte, insn bpfInsn) {
	b[0] = insn.Code
	b[1] = insn.Dst&0x0f | insn.Src<<4
	binary.NativeEndian.PutUint16(b[2:], uint16(insn.Off))
	binary.NativeEndian.PutUint32(b[4:], uint32(insn.Imm))
}

// patchCoreInsn applies a resolved CO-RE relocation to insn. It mirrors the
// ALU, LDX, ST and STX cases of libbpf's bpf_core_patch_insn. The 64-bit load
// form is not patched yet.
func patchCoreInsn(insn *bpfInsn, res *btf.CoreReloResult) error {
	if res.Poison {
		poisonCoreInsn(insn)
		return nil
	}

	switch insn.Code & bpfClassMask {
	case bpfALU, bpfALU64:
		if insn.Code&bpfSourceX != 0 {
			return fmt.Errorf("core patch: ALU source is not an immediate")
		}
		if res.Validate && uint64(int64(insn.Imm)) != res.OrigVal {
			return fmt.Errorf("core patch: ALU value %d, want %d", insn.Imm, res.OrigVal)
		}
		insn.Imm = int32(res.NewVal)

	case bpfLDX, bpfST, bpfSTX:
		if res.Validate && uint64(int64(insn.Off)) != res.OrigVal {
			return fmt.Errorf("core patch: memory offset %d, want %d", insn.Off, res.OrigVal)
		}
		if res.NewVal > math.MaxInt16 {
			return fmt.Errorf("core patch: memory offset %d is too large", res.NewVal)
		}
		if res.FailMemSizeAdjust {
			poisonCoreInsn(insn)
			return nil
		}
		insn.Off = int16(res.NewVal)

		if res.OrigSize != res.NewSize {
			if insnSizeBytes(insn.Code) != res.OrigSize {
				return fmt.Errorf("core patch: instruction size %d, want %d", insnSizeBytes(insn.Code), res.OrigSize)
			}
			size, ok := bpfSizeBits(res.NewSize)
			if !ok {
				return fmt.Errorf("core patch: invalid size %d", res.NewSize)
			}
			insn.Code = insn.Code&^bpfSizeMask | size
		}

	default:
		return fmt.Errorf("core patch: unsupported instruction class %#x", insn.Code&bpfClassMask)
	}

	return nil
}

func poisonCoreInsn(insn *bpfInsn) {
	*insn = bpfInsn{Code: bpfJMP | bpfCall, Imm: bpfPoisonImm}
}

func bpfSizeBits(size uint32) (uint8, bool) {
	switch size {
	case 8:
		return bpfSizeDW, true
	case 4:
		return bpfSizeW, true
	case 2:
		return bpfSizeH, true
	case 1:
		return bpfSizeB, true
	default:
		return 0, false
	}
}

func insnSizeBytes(code uint8) uint32 {
	switch code & bpfSizeMask {
	case bpfSizeDW:
		return 8
	case bpfSizeW:
		return 4
	case bpfSizeH:
		return 2
	case bpfSizeB:
		return 1
	default:
		return 0
	}
}
