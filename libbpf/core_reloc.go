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
	bpfExit       = 0x90
	bpfImm        = 0x00
	bpfMem        = 0x60
	bpfSourceK    = 0x00
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

// patchCoreInsn applies a resolved CO-RE relocation to the instruction bytes
// at b. It mirrors the ALU, LDX, ST, STX and LDIMM64 cases of libbpf's
// bpf_core_patch_insn.
func patchCoreInsn(b []byte, res *btf.CoreReloResult) error {
	if len(b) < bpfInsnLength {
		return fmt.Errorf("core patch: truncated instruction")
	}

	insn := decodeBpfInsn(b)
	if res.Poison {
		poisonCoreInsn(b, insn.Code)
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
		encodeBpfInsn(b, insn)

	case bpfLDX, bpfST, bpfSTX:
		if res.Validate && uint64(int64(insn.Off)) != res.OrigVal {
			return fmt.Errorf("core patch: memory offset %d, want %d", insn.Off, res.OrigVal)
		}
		if res.NewVal > math.MaxInt16 {
			return fmt.Errorf("core patch: memory offset %d is too large", res.NewVal)
		}
		if res.FailMemSizeAdjust {
			poisonCoreInsn(b, insn.Code)
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
		encodeBpfInsn(b, insn)

	case bpfLD:
		if insn.Code != bpfLD|bpfSizeDW|bpfImm || insn.Src != 0 || insn.Off != 0 {
			return fmt.Errorf("core patch: unexpected 64-bit load form")
		}
		if len(b) < 2*bpfInsnLength {
			return fmt.Errorf("core patch: truncated 64-bit load")
		}
		second := decodeBpfInsn(b[bpfInsnLength:])
		if second.Code != 0 || second.Dst != 0 || second.Src != 0 || second.Off != 0 {
			return fmt.Errorf("core patch: unexpected 64-bit load tail")
		}
		imm := uint64(uint32(insn.Imm)) | uint64(uint32(second.Imm))<<32
		if res.Validate && imm != res.OrigVal {
			return fmt.Errorf("core patch: 64-bit value %d, want %d", imm, res.OrigVal)
		}
		insn.Imm = int32(res.NewVal)
		second.Imm = int32(res.NewVal >> 32)
		encodeBpfInsn(b, insn)
		encodeBpfInsn(b[bpfInsnLength:], second)

	default:
		return fmt.Errorf("core patch: unsupported instruction class %#x", insn.Code&bpfClassMask)
	}

	return nil
}

func poisonCoreInsn(b []byte, code uint8) {
	poison := bpfInsn{Code: bpfJMP | bpfCall, Imm: bpfPoisonImm}

	encodeBpfInsn(b, poison)
	if code == bpfLD|bpfSizeDW|bpfImm && len(b) >= 2*bpfInsnLength {
		encodeBpfInsn(b[bpfInsnLength:], poison)
	}
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
