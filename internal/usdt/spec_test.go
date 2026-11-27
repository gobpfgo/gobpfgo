// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package usdt

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// specObjectPath is a BPF object that includes usdt.bpf.h. clang wrote the
// BPF-side spec structs into its BTF, with the bit offset and width of every
// field, which is the layout the spec bytes must have.
const specObjectPath = "../../testdata/progs/usdt_attach.bpf.o"

// specStructs are the two usdt.bpf.h structs read from the BPF object's BTF.
type specStructs struct {
	argSpec *btf.Type
	spec    *btf.Type
}

func loadSpecStructs(t *testing.T) specStructs {
	t.Helper()

	f, err := elf.Open(specObjectPath)
	if err != nil {
		t.Fatalf("open %s: %v", specObjectPath, err)
	}
	defer f.Close()

	sec := f.Section(".BTF")
	if sec == nil {
		t.Fatalf("%s has no .BTF", specObjectPath)
	}
	data, err := sec.Data()
	if err != nil {
		t.Fatalf("read .BTF: %v", err)
	}
	spec, err := btf.Parse(data, f.ByteOrder)
	if err != nil {
		t.Fatalf("parse .BTF: %v", err)
	}

	s := specStructs{
		argSpec: spec.Find("__bpf_usdt_arg_spec", btf.KindStruct),
		spec:    spec.Find("__bpf_usdt_spec", btf.KindStruct),
	}
	if s.argSpec == nil || s.spec == nil {
		t.Fatalf("%s lacks the usdt.bpf.h spec structs", specObjectPath)
	}
	return s
}

// member returns the named member of a BTF struct.
func member(t *testing.T, st *btf.Type, name string) btf.Member {
	t.Helper()

	for _, m := range st.Members {
		if m.Name == name {
			return m
		}
	}
	t.Fatalf("struct %s has no member %s", st.Name, name)
	return btf.Member{}
}

// bitsAt reads the little-endian unsigned field of width bits at bit offset
// off of b.
func bitsAt(b []byte, off, width uint32) uint64 {
	var v uint64
	for i := uint32(0); i < width; i++ {
		bit := off + i
		if b[bit/8]>>(bit%8)&1 != 0 {
			v |= 1 << i
		}
	}
	return v
}

// fieldWidth is the bitfield width of m, or the size of a plain field.
func fieldWidth(m btf.Member, size uint32) uint32 {
	if m.BitfieldSize != 0 {
		return uint32(m.BitfieldSize)
	}
	return size * 8
}

// TestSpecLayoutMatchesBTF compares the Go offsets of the spec structs with
// the layout clang gave them for the BPF target.
func TestSpecLayoutMatchesBTF(t *testing.T) {
	s := loadSpecStructs(t)

	if s.argSpec.SizeOrType != ArgSpecSize {
		t.Errorf("sizeof(struct __bpf_usdt_arg_spec) = %d, Go %d", s.argSpec.SizeOrType, ArgSpecSize)
	}
	if s.spec.SizeOrType != SpecSize {
		t.Errorf("sizeof(struct __bpf_usdt_spec) = %d, Go %d", s.spec.SizeOrType, SpecSize)
	}

	fields := []struct {
		st    *btf.Type
		name  string
		off   uint32
		width uint32
	}{
		{s.argSpec, "val_off", argSpecOffValOff * 8, 64},
		{s.argSpec, "arg_type", argSpecOffArgType * 8, 8},
		{s.argSpec, "idx_reg_off", argSpecOffIdxRegOff * 8, idxRegOffBits},
		{s.argSpec, "scale_bitshift", argSpecOffIdxRegOff*8 + scaleBitshiftShift, 4},
		{s.argSpec, "__reserved", argSpecOffReserved * 8, 8},
		{s.argSpec, "reg_off", argSpecOffRegOff * 8, 16},
		{s.argSpec, "arg_signed", argSpecOffArgSigned * 8, 8},
		{s.argSpec, "arg_bitshift", argSpecOffArgBitshift * 8, 8},
		{s.spec, "args", specOffArgs * 8, 0},
		{s.spec, "usdt_cookie", specOffUsdtCookie * 8, 64},
		{s.spec, "arg_cnt", specOffArgCnt * 8, 16},
	}
	for _, f := range fields {
		m := member(t, f.st, f.name)
		if m.Offset != f.off {
			t.Errorf("%s.%s at bit %d, Go %d", f.st.Name, f.name, m.Offset, f.off)
		}
		if m.BitfieldSize != 0 && uint32(m.BitfieldSize) != f.width {
			t.Errorf("%s.%s is %d bits wide, Go %d", f.st.Name, f.name, m.BitfieldSize, f.width)
		}
	}
}

// specTestArgs covers every argument type, a signed and an unsigned size, the
// largest register offsets and every SIB field.
func specTestArgs(t *testing.T) []Arg {
	t.Helper()

	args, err := ParseSpec(ArchAMD64, "-4@$-9 8@%rsp -2@-1204(%rbp) -1@-96(%r15,%rip,8) 4@(%rax,%rsi)")
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	return args
}

// TestMarshalSpec decodes the marshalled spec with the BTF bit offsets and
// checks every field of every argument, the cookie and the count.
func TestMarshalSpec(t *testing.T) {
	const cookie = 0x0123_4567_89ab_cdef
	s := loadSpecStructs(t)
	args := specTestArgs(t)

	buf, err := MarshalSpec(args, cookie)
	if err != nil {
		t.Fatalf("MarshalSpec: %v", err)
	}
	if len(buf) != SpecSize {
		t.Fatalf("spec is %d bytes, want %d", len(buf), SpecSize)
	}

	read := func(st *btf.Type, base uint32, name string, size uint32) uint64 {
		m := member(t, st, name)
		return bitsAt(buf, base+m.Offset, fieldWidth(m, size))
	}
	for i := 0; i < maxArgs; i++ {
		var want Arg
		if i < len(args) {
			want = args[i]
		}
		base := uint32(i * ArgSpecSize * 8)
		got := Arg{
			ValOff:        int64(read(s.argSpec, base, "val_off", 8)),
			ArgType:       ArgType(read(s.argSpec, base, "arg_type", 4)),
			IdxRegOff:     uint16(read(s.argSpec, base, "idx_reg_off", 2)),
			ScaleBitshift: uint8(read(s.argSpec, base, "scale_bitshift", 2)),
			RegOff:        int16(read(s.argSpec, base, "reg_off", 2)),
			ArgSigned:     read(s.argSpec, base, "arg_signed", 1) != 0,
			ArgBitshift:   uint8(read(s.argSpec, base, "arg_bitshift", 1)),
		}
		if got != want {
			t.Errorf("args[%d] = %+v, want %+v", i, got, want)
		}
		if r := read(s.argSpec, base, "__reserved", 1); r != 0 {
			t.Errorf("args[%d].__reserved = %d, want 0", i, r)
		}
	}
	if got := read(s.spec, 0, "usdt_cookie", 8); got != cookie {
		t.Errorf("usdt_cookie = %#x, want %#x", got, uint64(cookie))
	}
	if got := read(s.spec, 0, "arg_cnt", 2); got != uint64(len(args)) {
		t.Errorf("arg_cnt = %d, want %d", got, len(args))
	}
}

// TestMarshalSpecBytes pins the bytes of one SIB argument, so a change in the
// packing shows up even without the BTF.
func TestMarshalSpecBytes(t *testing.T) {
	arg := Arg{ValOff: -96, ArgType: USDT_ARG_SIB, IdxRegOff: ptRegsRAX, ScaleBitshift: 3, RegOff: ptRegsRBP, ArgSigned: true, ArgBitshift: 56}
	buf, err := MarshalSpec([]Arg{arg}, 7)
	if err != nil {
		t.Fatalf("MarshalSpec: %v", err)
	}

	want := []byte{
		0xa0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // val_off -96
		3, 0, // arg_type SIB, padding
		0x50, 0x30, // idx_reg_off 80, scale_bitshift 3
		0, 0, // __reserved, padding
		0x20, 0x00, // reg_off 32
		1, 56, // arg_signed, arg_bitshift
		0, 0, 0, 0, 0, 0, // padding
	}
	if got := buf[:ArgSpecSize]; string(got) != string(want) {
		t.Errorf("arg spec = % x\nwant      % x", got, want)
	}
	if got := binary.LittleEndian.Uint64(buf[specOffUsdtCookie:]); got != 7 {
		t.Errorf("usdt_cookie = %d, want 7", got)
	}
	if got := binary.LittleEndian.Uint16(buf[specOffArgCnt:]); got != 1 {
		t.Errorf("arg_cnt = %d, want 1", got)
	}
}

func TestMarshalSpecLimits(t *testing.T) {
	buf, err := MarshalSpec(nil, 5)
	if err != nil {
		t.Fatalf("MarshalSpec(nil): %v", err)
	}
	for i, b := range buf[:specOffUsdtCookie] {
		if b != 0 {
			t.Fatalf("byte %d of an empty spec = %#x, want 0", i, b)
		}
	}
	if got := binary.LittleEndian.Uint16(buf[specOffArgCnt:]); got != 0 {
		t.Errorf("arg_cnt = %d, want 0", got)
	}

	_, err = MarshalSpec(make([]Arg, maxArgs+1), 0)
	checkError(t, err, ErrUnsupportedArg, unix.E2BIG)
}
