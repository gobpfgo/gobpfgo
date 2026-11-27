// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/usdt.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: parse_usdt_spec, parse_usdt_arg, calc_pt_regs_off

//go:build linux && (amd64 || arm64)

package usdt

import (
	"debug/elf"
	"strings"

	"golang.org/x/sys/unix"
)

// maxArgs is the most arguments one USDT spec may have, the size of the
// argument array in the BPF-side spec.
const maxArgs = 12

// Arch selects the operand syntax and the register layout used to parse an
// argument spec.
type Arch uint8

const (
	// ArchUnsupported has no operand parser: a spec with arguments fails
	// with ErrUnsupportedArch, an empty spec parses to no arguments.
	ArchUnsupported Arch = iota
	// ArchAMD64 reads AT&T operands such as -4@-20(%rbp) and maps the
	// registers to x86-64 struct pt_regs offsets.
	ArchAMD64
	// ArchARM64 reads operands such as -4@[sp, 96] and maps the registers
	// to arm64 struct user_pt_regs offsets.
	ArchARM64
)

// ArchOf returns the parser for an ELF machine, or ArchUnsupported.
func ArchOf(machine elf.Machine) Arch {
	switch machine {
	case elf.EM_X86_64:
		return ArchAMD64
	case elf.EM_AARCH64:
		return ArchARM64
	default:
		return ArchUnsupported
	}
}

// String returns the Go name of the architecture, or "unsupported".
func (a Arch) String() string {
	switch a {
	case ArchAMD64:
		return "amd64"
	case ArchARM64:
		return "arm64"
	default:
		return "unsupported"
	}
}

// ArgType says where the value of a USDT argument lives. The values are the
// ones the BPF side of libbpf's USDT support reads from its spec map.
type ArgType uint8

const (
	// USDT_ARG_CONST is an immediate: the value is ValOff.
	USDT_ARG_CONST ArgType = iota
	// USDT_ARG_REG is a register: the value is the register at RegOff.
	USDT_ARG_REG
	// USDT_ARG_REG_DEREF is memory at the register at RegOff plus ValOff.
	USDT_ARG_REG_DEREF
	// USDT_ARG_SIB is memory at the register at RegOff, plus the register
	// at IdxRegOff shifted left by ScaleBitshift, plus ValOff.
	USDT_ARG_SIB
)

// String returns the C name of the argument type.
func (t ArgType) String() string {
	switch t {
	case USDT_ARG_CONST:
		return "USDT_ARG_CONST"
	case USDT_ARG_REG:
		return "USDT_ARG_REG"
	case USDT_ARG_REG_DEREF:
		return "USDT_ARG_REG_DEREF"
	case USDT_ARG_SIB:
		return "USDT_ARG_SIB"
	default:
		return "USDT_ARG_UNKNOWN"
	}
}

// Arg is one parsed USDT argument, with the fields libbpf stores for it in
// the BPF-side spec. The register fields are byte offsets into the
// architecture's pt_regs, which is how the BPF program finds the register.
type Arg struct {
	// ValOff is the constant of USDT_ARG_CONST and the memory offset of
	// USDT_ARG_REG_DEREF and USDT_ARG_SIB. It is zero for USDT_ARG_REG.
	ValOff int64
	// ArgType says how ValOff and the registers combine into the value.
	ArgType ArgType
	// IdxRegOff and ScaleBitshift are the index register and the log2 of
	// the scale of USDT_ARG_SIB; both are zero for the other types.
	IdxRegOff     uint16
	ScaleBitshift uint8
	// RegOff is the base register; it is zero for USDT_ARG_CONST.
	RegOff int16
	// ArgSigned reports a negative size in the spec: the value is sign
	// extended.
	ArgSigned bool
	// ArgBitshift is 64 minus the operand width in bits. Shifting the
	// 64-bit value left and back right by it truncates and extends it.
	ArgBitshift uint8
}

// Size returns the operand width in bytes: 1, 2, 4 or 8.
func (a Arg) Size() int {
	return int(64-a.ArgBitshift) / 8
}

// ParseSpec parses a USDT argument spec, such as "-4@%esi -8@-24(%rbp)
// 8@$5", with the operand syntax of arch. An empty spec has no arguments.
//
// Each operand is SIZE@LOCATION. A negative size is a signed value; the
// size must be 1, 2, 4 or 8 bytes. The location is an immediate, a register
// or a memory reference through a register, written in the assembler syntax
// of arch. The spec is read like a C string: it ends at the first NUL byte.
//
// Errors wrap ErrUnsupportedArg and the errno libbpf returns: EINVAL for an
// unrecognized operand, a bad size or a bad scale, ENOENT for an unknown
// register and E2BIG for more than 12 arguments. A spec with arguments for
// ArchUnsupported wraps ErrUnsupportedArch and ENOTSUP.
func ParseSpec(arch Arch, spec string) ([]Arg, error) {
	if i := strings.IndexByte(spec, 0); i >= 0 {
		spec = spec[:i]
	}

	var args []Arg
	for s := spec; s != ""; {
		if len(args) >= maxArgs {
			return nil, newError(ErrUnsupportedArg, unix.E2BIG, "too many arguments (> %d) in spec %q", maxArgs, spec)
		}

		op, err := parseArg(arch, s, len(args))
		if err != nil {
			return nil, err
		}

		size := op.size
		op.arg.ArgSigned = size < 0
		if size < 0 {
			size = -size
		}
		switch size {
		case 1, 2, 4, 8:
			op.arg.ArgBitshift = uint8(64 - size*8)
		default:
			return nil, newError(ErrUnsupportedArg, unix.EINVAL, "arg #%d (spec %q) size %d", len(args), s, size)
		}

		args = append(args, op.arg)
		s = s[op.consumed:]
	}
	return args, nil
}

// operand is one location parseArg recognized: the argument without its size
// fields, the signed size written in the spec and the number of spec bytes it
// used, including the white space after it.
type operand struct {
	arg      Arg
	size     int32
	consumed int
}

// operandForm is one sscanf pattern of parse_usdt_arg. A spec matches the
// form when sscanf assigns all count conversions: the signed size, then,
// when present, the offset or constant, the register names and the scale.
type operandForm struct {
	format  string
	count   int
	argType ArgType
	offset  bool
	regs    int
	scale   bool
}

// amd64Forms are the x86-64 operand patterns in libbpf's order: scale-index-
// base references, memory references through one register, registers and
// immediates. A register name follows a '%' and may hold any byte but the
// delimiter, white space included.
var amd64Forms = []operandForm{
	{" %d @ %ld ( %%%15[^,] , %%%15[^,] , %d ) %n", 5, USDT_ARG_SIB, true, 2, true},
	{" %d @ ( %%%15[^,] , %%%15[^,] , %d ) %n", 4, USDT_ARG_SIB, false, 2, true},
	{" %d @ %ld ( %%%15[^,] , %%%15[^)] ) %n", 4, USDT_ARG_SIB, true, 2, false},
	{" %d @ ( %%%15[^,] , %%%15[^)] ) %n", 3, USDT_ARG_SIB, false, 2, false},
	{" %d @ %ld ( %%%15[^)] ) %n", 3, USDT_ARG_REG_DEREF, true, 1, false},
	{" %d @ ( %%%15[^)] ) %n", 2, USDT_ARG_REG_DEREF, false, 1, false},
	{" %d @ %%%15s %n", 2, USDT_ARG_REG, false, 1, false},
	{" %d @ $%ld %n", 2, USDT_ARG_CONST, true, 0, false},
}

// arm64Forms are the arm64 operand patterns in libbpf's order: memory
// references with and without an offset, immediates and registers.
var arm64Forms = []operandForm{
	{" %d @ [ %15[a-z0-9] , %ld ] %n", 3, USDT_ARG_REG_DEREF, true, 1, false},
	{" %d @ [ %15[a-z0-9] ] %n", 2, USDT_ARG_REG_DEREF, false, 1, false},
	{" %d @ %ld %n", 2, USDT_ARG_CONST, true, 0, false},
	{" %d @ %15[a-z0-9] %n", 2, USDT_ARG_REG, false, 1, false},
}

// parseArg parses the operand at the start of s, the argument at index idx.
func parseArg(arch Arch, s string, idx int) (operand, error) {
	switch arch {
	case ArchAMD64:
		return parseOperand(amd64Forms, amd64RegOff, s, idx)
	case ArchARM64:
		return parseOperand(arm64Forms, arm64RegOff, s, idx)
	default:
		return operand{}, newError(ErrUnsupportedArch, unix.ENOTSUP, "no USDT operand parser for %s", arch)
	}
}

// parseOperand tries each form in order and builds the argument from the
// first one that matches.
func parseOperand(forms []operandForm, regOff func(string) (int, bool), s string, idx int) (operand, error) {
	for _, form := range forms {
		m := sscanf(s, form.format)
		if m.count == form.count {
			return form.build(m, regOff, s, idx)
		}
	}
	return operand{}, newError(ErrUnsupportedArg, unix.EINVAL, "unrecognized arg #%d spec %q", idx, s)
}

// build turns the conversions of a matching form into an operand. The
// registers are checked first, then the scale, then the length: libbpf
// returns the errors in that order.
func (form operandForm) build(m scanResult, regOff func(string) (int, bool), s string, idx int) (operand, error) {
	op := operand{size: int32(m.ints[0])}
	op.arg.ArgType = form.argType
	if form.offset {
		op.arg.ValOff = m.ints[1]
	}

	if form.regs > 0 {
		off, err := lookupReg(regOff, m.strs[0])
		if err != nil {
			return operand{}, err
		}
		op.arg.RegOff = int16(off)
	}
	if form.regs > 1 {
		off, err := lookupReg(regOff, m.strs[1])
		if err != nil {
			return operand{}, err
		}
		op.arg.IdxRegOff = uint16(off)
	}

	if form.argType == USDT_ARG_SIB {
		scale := int64(1)
		if form.scale {
			scale = m.ints[len(m.ints)-1]
		}
		shift, ok := scaleBitshift(scale)
		if !ok {
			return operand{}, newError(ErrUnsupportedArg, unix.EINVAL, "invalid SIB scale %d, expected 1, 2, 4, 8", scale)
		}
		op.arg.ScaleBitshift = shift
	}

	// sscanf assigned every conversion but stopped before %n, so a closing
	// delimiter is missing. libbpf would continue with an uninitialized
	// length; the operand is rejected instead.
	if m.consumed < 0 {
		return operand{}, newError(ErrUnsupportedArg, unix.EINVAL, "unterminated arg #%d spec %q", idx, s)
	}
	op.consumed = m.consumed
	return op, nil
}

func lookupReg(regOff func(string) (int, bool), name string) (int, error) {
	off, ok := regOff(name)
	if !ok {
		return 0, newError(ErrUnsupportedArg, unix.ENOENT, "unrecognized register %q", name)
	}
	return off, nil
}

func scaleBitshift(scale int64) (uint8, bool) {
	switch scale {
	case 1:
		return 0, true
	case 2:
		return 1, true
	case 4:
		return 2, true
	case 8:
		return 3, true
	default:
		return 0, false
	}
}

// Byte offsets of the general-purpose registers in the x86-64 struct
// pt_regs of the kernel UAPI.
const (
	ptRegsR15 = 0
	ptRegsR14 = 8
	ptRegsR13 = 16
	ptRegsR12 = 24
	ptRegsRBP = 32
	ptRegsRBX = 40
	ptRegsR11 = 48
	ptRegsR10 = 56
	ptRegsR9  = 64
	ptRegsR8  = 72
	ptRegsRAX = 80
	ptRegsRCX = 88
	ptRegsRDX = 96
	ptRegsRSI = 104
	ptRegsRDI = 112
	ptRegsRIP = 128
	ptRegsRSP = 152
)

// amd64Regs names every register by its 64-, 32-, 16- and 8-bit names. The
// empty names only pad the rip row and never match.
var amd64Regs = []struct {
	names [4]string
	off   int
}{
	{[4]string{"rip", "eip", "", ""}, ptRegsRIP},
	{[4]string{"rax", "eax", "ax", "al"}, ptRegsRAX},
	{[4]string{"rbx", "ebx", "bx", "bl"}, ptRegsRBX},
	{[4]string{"rcx", "ecx", "cx", "cl"}, ptRegsRCX},
	{[4]string{"rdx", "edx", "dx", "dl"}, ptRegsRDX},
	{[4]string{"rsi", "esi", "si", "sil"}, ptRegsRSI},
	{[4]string{"rdi", "edi", "di", "dil"}, ptRegsRDI},
	{[4]string{"rbp", "ebp", "bp", "bpl"}, ptRegsRBP},
	{[4]string{"rsp", "esp", "sp", "spl"}, ptRegsRSP},
	{[4]string{"r8", "r8d", "r8w", "r8b"}, ptRegsR8},
	{[4]string{"r9", "r9d", "r9w", "r9b"}, ptRegsR9},
	{[4]string{"r10", "r10d", "r10w", "r10b"}, ptRegsR10},
	{[4]string{"r11", "r11d", "r11w", "r11b"}, ptRegsR11},
	{[4]string{"r12", "r12d", "r12w", "r12b"}, ptRegsR12},
	{[4]string{"r13", "r13d", "r13w", "r13b"}, ptRegsR13},
	{[4]string{"r14", "r14d", "r14w", "r14b"}, ptRegsR14},
	{[4]string{"r15", "r15d", "r15w", "r15b"}, ptRegsR15},
}

// amd64RegOff returns the pt_regs offset of an x86-64 register name.
func amd64RegOff(name string) (int, bool) {
	for _, reg := range amd64Regs {
		for _, n := range reg.names {
			if n != "" && n == name {
				return reg.off, true
			}
		}
	}
	return 0, false
}

// Byte offsets in the arm64 struct user_pt_regs of the kernel UAPI: 31
// eight-byte general registers, then the stack pointer.
const (
	userPtRegsRegs  = 0
	userPtRegsSP    = 248
	userPtRegsCount = 31
)

// arm64RegOff returns the user_pt_regs offset of an arm64 register name: x0
// to x30 or sp. The number is read like C's sscanf "x%d", so leading zeros
// and trailing letters are accepted and a number past the C int range wraps.
func arm64RegOff(name string) (int, bool) {
	if m := sscanf(name, "x%d"); m.count == 1 {
		n := m.ints[0]
		if n >= 0 && n < userPtRegsCount {
			return userPtRegsRegs + int(n)*8, true
		}
		return 0, false
	}
	if name == "sp" {
		return userPtRegsSP, true
	}
	return 0, false
}
