// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/usdt.c
// libbpf-source: src/usdt.bpf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: struct usdt_arg_spec, struct usdt_spec, parse_usdt_spec

//go:build linux && (amd64 || arm64)

package usdt

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// The layout of struct __bpf_usdt_spec in usdt.bpf.h on a little-endian
// machine. The spec map of an object that includes usdt.bpf.h stores one per
// spec ID: twelve argument specs, the USDT cookie and the argument count.
const (
	// ArgSpecSize is sizeof(struct __bpf_usdt_arg_spec).
	ArgSpecSize = 24
	// SpecSize is sizeof(struct __bpf_usdt_spec).
	SpecSize = 304

	// Offsets in struct __bpf_usdt_arg_spec. The byte at
	// argSpecOffArgType holds the 8-bit arg_type bitfield. The 12-bit
	// idx_reg_off does not fit in the rest of that 16-bit unit, so it
	// starts the next one, at argSpecOffIdxRegOff, in bits 0-11;
	// scale_bitshift takes bits 12-15. The byte at argSpecOffReserved is
	// the 8-bit __reserved bitfield.
	argSpecOffValOff      = 0
	argSpecOffArgType     = 8
	argSpecOffIdxRegOff   = 10
	argSpecOffReserved    = 12
	argSpecOffRegOff      = 14
	argSpecOffArgSigned   = 16
	argSpecOffArgBitshift = 17

	// Bit layout of the 16-bit unit at argSpecOffIdxRegOff.
	idxRegOffBits      = 12
	idxRegOffMask      = 1<<idxRegOffBits - 1
	scaleBitshiftShift = idxRegOffBits
	scaleBitshiftMask  = 0xf

	// Offsets in struct __bpf_usdt_spec.
	specOffArgs       = 0
	specOffUsdtCookie = maxArgs * ArgSpecSize
	specOffArgCnt     = specOffUsdtCookie + 8
)

// MarshalSpec returns the struct __bpf_usdt_spec bytes for a parsed argument
// spec and a USDT cookie: one argument spec per argument, zeroed slots after
// them, the cookie and the argument count. The program reads the cookie with
// bpf_usdt_cookie. More than 12 arguments fail with ErrUnsupportedArg and
// E2BIG, as ParseSpec does.
//
// The index register offset and the scale are stored in their 12-bit and
// 4-bit fields; ParseSpec produces values that fit.
func MarshalSpec(args []Arg, cookie uint64) ([]byte, error) {
	if len(args) > maxArgs {
		return nil, newError(ErrUnsupportedArg, unix.E2BIG, "%d arguments, at most %d", len(args), maxArgs)
	}

	buf := make([]byte, SpecSize)
	for i, arg := range args {
		putArgSpec(buf[specOffArgs+i*ArgSpecSize:], arg)
	}
	binary.LittleEndian.PutUint64(buf[specOffUsdtCookie:], cookie)
	binary.LittleEndian.PutUint16(buf[specOffArgCnt:], uint16(len(args)))
	return buf, nil
}

// putArgSpec writes one struct __bpf_usdt_arg_spec at the start of b.
func putArgSpec(b []byte, arg Arg) {
	binary.LittleEndian.PutUint64(b[argSpecOffValOff:], uint64(arg.ValOff))
	b[argSpecOffArgType] = byte(arg.ArgType)
	unit := arg.IdxRegOff&idxRegOffMask | uint16(arg.ScaleBitshift&scaleBitshiftMask)<<scaleBitshiftShift
	binary.LittleEndian.PutUint16(b[argSpecOffIdxRegOff:], unit)
	b[argSpecOffReserved] = 0
	binary.LittleEndian.PutUint16(b[argSpecOffRegOff:], uint16(arg.RegOff))
	if arg.ArgSigned {
		b[argSpecOffArgSigned] = 1
	}
	b[argSpecOffArgBitshift] = arg.ArgBitshift
}
