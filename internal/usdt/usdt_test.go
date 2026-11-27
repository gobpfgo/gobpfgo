// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package usdt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// ELF header fields the tests patch in the fixture.
const (
	elfOffData    = 5
	elfOffMachine = 18
)

func readFixture(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// fixtureWithMachine returns the fixture binary with e_machine replaced.
func fixtureWithMachine(t *testing.T, machine elf.Machine) *File {
	t.Helper()

	data := readFixture(t)
	binary.LittleEndian.PutUint16(data[elfOffMachine:], uint16(machine))
	f, err := NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewFile with machine %s: %v", machine, err)
	}
	return f
}

// noteCaseImage returns the image of one crafted oracle note case.
func noteCaseImage(t *testing.T, name string) []byte {
	t.Helper()

	for _, c := range loadOracle(t).NoteCases {
		if c.Name != name {
			continue
		}
		image, err := hex.DecodeString(c.Image)
		if err != nil {
			t.Fatalf("decode image %s: %v", name, err)
		}
		return image
	}
	t.Fatalf("no note case %q", name)
	return nil
}

// checkError requires err to match both the package error and the errno.
func checkError(t *testing.T, err, kind error, errno unix.Errno) {
	t.Helper()

	if !errors.Is(err, kind) || !errors.Is(err, errno) {
		t.Fatalf("error = %v, want %v and %v", err, kind, errno)
	}
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()

	_, err := Open(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(missing) = %v, want fs.ErrNotExist", err)
	}

	text := filepath.Join(t.TempDir(), "text")
	if err := os.WriteFile(text, []byte("not an ELF file"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(text)
	checkError(t, err, ErrInvalidELF, unix.EBADF)

	bigEndian := readFixture(t)
	bigEndian[elfOffData] = byte(elf.ELFDATA2MSB)
	_, err = NewFile(bytes.NewReader(bigEndian))
	checkError(t, err, ErrInvalidELF, unix.EBADF)
}

func TestFindErrors(t *testing.T) {
	t.Parallel()

	f, err := Open(fixturePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, probe := range [][2]string{{"gobpfgo", "missing"}, {"other", "args"}, {"", ""}} {
		_, err := f.Find(probe[0], probe[1])
		checkError(t, err, ErrProbeNotFound, unix.ENOENT)
	}
}

func TestMalformedNote(t *testing.T) {
	t.Parallel()

	f, err := NewFile(bytes.NewReader(noteCaseImage(t, "wrong-type")))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	_, err = f.Notes()
	checkError(t, err, ErrMalformedNote, unix.EINVAL)
	_, err = f.Find("gobpfgo", "first")
	checkError(t, err, ErrMalformedNote, unix.EINVAL)

	_, err = NewFile(bytes.NewReader(noteCaseImage(t, "progbits-section")))
	checkError(t, err, ErrMalformedNote, unix.EINVAL)

	_, err = NewFile(bytes.NewReader(noteCaseImage(t, "no-notes-section")))
	checkError(t, err, ErrNoNotes, unix.ENOENT)
}

// TestArgsPastSection covers a spec with no NUL before the end of the
// section. libbpf would read past the section; the parser rejects the note.
func TestArgsPastSection(t *testing.T) {
	t.Parallel()

	padded := []byte("-8@%rax\x00\x00\x00")
	image := noteCaseImage(t, "args-in-padding")
	if bytes.Count(image, padded) != 1 {
		t.Fatal("args-in-padding has no padded spec")
	}
	image = bytes.Replace(image, padded, []byte("-8@%raxxxx"), 1)

	f, err := NewFile(bytes.NewReader(image))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	_, err = f.Notes()
	checkError(t, err, ErrMalformedNote, unix.EINVAL)
}

func TestArchOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		machine elf.Machine
		want    Arch
	}{
		{elf.EM_X86_64, ArchAMD64},
		{elf.EM_AARCH64, ArchARM64},
		{elf.EM_386, ArchUnsupported},
		{elf.EM_RISCV, ArchUnsupported},
		{elf.EM_S390, ArchUnsupported},
	}
	for _, tt := range tests {
		if got := ArchOf(tt.machine); got != tt.want {
			t.Errorf("ArchOf(%s) = %s, want %s", tt.machine, got, tt.want)
		}
	}
}

// TestFindUnsupportedArch reads the fixture as a RISC-V file: a probe
// without arguments still parses, the others fail.
func TestFindUnsupportedArch(t *testing.T) {
	t.Parallel()

	f := fixtureWithMachine(t, elf.EM_RISCV)
	if _, err := f.Find("gobpfgo", "start"); err != nil {
		t.Errorf("Find(start) = %v, want no error", err)
	}
	_, err := f.Find("gobpfgo", "args")
	checkError(t, err, ErrUnsupportedArch, unix.ENOTSUP)
}

// TestFindMachineSyntax reads the x86-64 fixture as an arm64 file: the arm64
// parser rejects the AT&T operands.
func TestFindMachineSyntax(t *testing.T) {
	t.Parallel()

	f := fixtureWithMachine(t, elf.EM_AARCH64)
	_, err := f.Find("gobpfgo", "args")
	checkError(t, err, ErrUnsupportedArg, unix.EINVAL)
}

func TestParseSpecUnsupportedArch(t *testing.T) {
	t.Parallel()

	spec, err := ParseSpec(ArchUnsupported, "")
	if err != nil || len(spec) != 0 {
		t.Errorf("ParseSpec(empty) = %v, %v; want no arguments", spec, err)
	}
	_, err = ParseSpec(ArchUnsupported, "8@%rax")
	checkError(t, err, ErrUnsupportedArch, unix.ENOTSUP)
}

// TestParseSpecUndefinedInLibbpf covers the inputs on which libbpf reads an
// uninitialized length or negates INT_MIN, which the oracle cannot record.
// The parser rejects them.
func TestParseSpecUndefinedInLibbpf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		arch Arch
		spec string
	}{
		{ArchAMD64, "-4@-8(%rbp"},
		{ArchAMD64, "8@(%rsp"},
		{ArchAMD64, "1@-96(%rbp,%rax,8"},
		{ArchAMD64, "1@-96(%rbp,%rax,8]"},
		{ArchAMD64, "-2147483648@%rax"},
		{ArchARM64, "-4@[sp, 96"},
		{ArchARM64, "-4@[x0, #8]"},
		{ArchARM64, "-2147483648@x0"},
	}
	for _, tt := range tests {
		_, err := ParseSpec(tt.arch, tt.spec)
		if !errors.Is(err, ErrUnsupportedArg) || !errors.Is(err, unix.EINVAL) {
			t.Errorf("ParseSpec(%s, %q) = %v, want ErrUnsupportedArg and EINVAL", tt.arch, tt.spec, err)
		}
	}
}

func TestParseSpecErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		spec  string
		errno unix.Errno
	}{
		{"8@rax", unix.EINVAL},
		{"3@%rax", unix.EINVAL},
		{"1@(%rbp,%rax,3)", unix.EINVAL},
		{"8@%xmm0", unix.ENOENT},
		{"1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al", unix.E2BIG},
	}
	for _, tt := range tests {
		_, err := ParseSpec(ArchAMD64, tt.spec)
		if !errors.Is(err, ErrUnsupportedArg) || !errors.Is(err, tt.errno) {
			t.Errorf("ParseSpec(%q) = %v, want ErrUnsupportedArg and %v", tt.spec, err, tt.errno)
		}
	}
}

// TestParseSpecNUL reads the spec like a C string.
func TestParseSpecNUL(t *testing.T) {
	t.Parallel()

	spec, err := ParseSpec(ArchAMD64, "8@%rax\x00 garbage")
	if err != nil || len(spec) != 1 {
		t.Fatalf("ParseSpec = %+v, %v; want one argument", spec, err)
	}
}

func TestArgSize(t *testing.T) {
	t.Parallel()

	spec, err := ParseSpec(ArchAMD64, "-1@%al 2@%ax -4@%eax 8@%rax")
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	for i, want := range []int{1, 2, 4, 8} {
		if got := spec[i].Size(); got != want {
			t.Errorf("arg %d Size = %d, want %d", i, got, want)
		}
	}
}
