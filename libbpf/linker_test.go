// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

const linkerInputPath = "../testdata/progs/kprobe.bpf.o"

// linkerFixture is testdata/oracle/linker.json: the object libbpf's linker
// writes for kprobe.bpf.o, as bpf_object__open_file and libelf see it.
type linkerFixture struct {
	ObjectName string                 `json:"object_name"`
	Maps       []linkerFixtureMap     `json:"maps"`
	Programs   []linkerFixtureProgram `json:"programs"`
	Sections   []linkerFixtureSection `json:"sections"`
}

type linkerFixtureMap struct {
	Name       string `json:"name"`
	Type       uint32 `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
}

type linkerFixtureProgram struct {
	Name    string `json:"name"`
	Type    uint32 `json:"type"`
	Section string `json:"section"`
}

type linkerFixtureSection struct {
	Name  string `json:"name"`
	Type  uint32 `json:"type"`
	Flags uint64 `json:"flags"`
	Size  uint64 `json:"size"`
}

func loadLinkerFixture(t *testing.T) linkerFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/linker.json")
	if err != nil {
		t.Fatalf("read linker fixture: %v", err)
	}
	var f linkerFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse linker fixture: %v", err)
	}
	return f
}

// linkFile links the kprobe object into a new linked.bpf.o in a temporary
// directory, through BpfLinkerNew and BpfLinkerAddFile, and returns its path.
func linkFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "linked.bpf.o")
	l, err := BpfLinkerNew(path, nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)

	if err := BpfLinkerAddFile(l, linkerInputPath, nil); err != nil {
		t.Fatalf("BpfLinkerAddFile: %v", err)
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	return path
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// TestBpfLinkerKprobe compares the linked object with the one libbpf's linker
// writes: object name, maps and programs after open, and every section's
// name, type, flags and size.
func TestBpfLinkerKprobe(t *testing.T) {
	want := loadLinkerFixture(t)
	path := linkFile(t)

	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	if got := BpfObjectName(obj); got != want.ObjectName {
		t.Fatalf("object name = %q, want %q", got, want.ObjectName)
	}
	if got := linkedMaps(obj); !reflect.DeepEqual(got, want.Maps) {
		t.Fatalf("maps = %+v, want %+v", got, want.Maps)
	}
	if got := linkedPrograms(obj); !reflect.DeepEqual(got, want.Programs) {
		t.Fatalf("programs = %+v, want %+v", got, want.Programs)
	}
	if got := linkedSections(t, path); !reflect.DeepEqual(got, want.Sections) {
		t.Fatalf("sections = %+v\nwant %+v", got, want.Sections)
	}
}

func linkedMaps(obj *BpfObject) []linkerFixtureMap {
	var maps []linkerFixtureMap
	for m := BpfObjectNextMap(obj, nil); m != nil; m = BpfObjectNextMap(obj, m) {
		maps = append(maps, linkerFixtureMap{
			Name:       BpfMapName(m),
			Type:       uint32(BpfMapTypeOf(m)),
			KeySize:    BpfMapKeySize(m),
			ValueSize:  BpfMapValueSize(m),
			MaxEntries: BpfMapMaxEntries(m),
		})
	}
	return maps
}

func linkedPrograms(obj *BpfObject) []linkerFixtureProgram {
	var programs []linkerFixtureProgram
	for p := BpfObjectNextProgram(obj, nil); p != nil; p = BpfObjectNextProgram(obj, p) {
		programs = append(programs, linkerFixtureProgram{
			Name:    BpfProgramName(p),
			Type:    uint32(BpfProgramTypeOf(p)),
			Section: BpfProgramSectionName(p),
		})
	}
	return programs
}

// linkedSections returns the sections of the ELF file at path, without the
// null section, sorted by name like the oracle.
func linkedSections(t *testing.T, path string) []linkerFixtureSection {
	t.Helper()

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()

	var sections []linkerFixtureSection
	for _, s := range f.Sections[1:] {
		sections = append(sections, linkerFixtureSection{
			Name:  s.Name,
			Type:  uint32(s.Type),
			Flags: uint64(s.Flags),
			Size:  s.Size,
		})
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].Name < sections[j].Name })
	return sections
}

func readELFSection(t *testing.T, path, name string) []byte {
	t.Helper()

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()

	s := f.Section(name)
	if s == nil {
		t.Fatalf("%s: no section %s", path, name)
	}
	data, err := s.Data()
	if err != nil {
		t.Fatalf("%s %s: %v", path, name, err)
	}
	return data
}

// TestBpfLinkerBTF checks the linked BTF: libbpf's 32-byte header, the input
// types, each DATASEC sized to its ELF section, and .BTF.ext unchanged.
func TestBpfLinkerBTF(t *testing.T) {
	path := linkFile(t)

	in, err := btf.Parse(readELFSection(t, linkerInputPath, ".BTF"), binary.LittleEndian)
	if err != nil {
		t.Fatalf("parse input BTF: %v", err)
	}
	out, err := btf.Parse(readELFSection(t, path, ".BTF"), binary.LittleEndian)
	if err != nil {
		t.Fatalf("parse linked BTF: %v", err)
	}

	if out.Header.HdrLen != btfHdrLen {
		t.Fatalf("header length = %d, want %d", out.Header.HdrLen, btfHdrLen)
	}
	if len(out.Types) != len(in.Types) {
		t.Fatalf("type count = %d, want %d", len(out.Types), len(in.Types))
	}

	sizes := elfSectionSizes(t, path)
	for _, ty := range out.Types {
		if ty.Kind == btf.KindDatasec && uint64(ty.SizeOrType) != sizes[ty.Name] {
			t.Fatalf("DATASEC %s size = %d, want %d", ty.Name, ty.SizeOrType, sizes[ty.Name])
		}
	}

	if !bytes.Equal(readELFSection(t, path, ".BTF.ext"), readELFSection(t, linkerInputPath, ".BTF.ext")) {
		t.Fatal(".BTF.ext differs from the input")
	}
}

func elfSectionSizes(t *testing.T, path string) map[string]uint64 {
	t.Helper()

	sizes := make(map[string]uint64)
	for _, s := range linkedSections(t, path) {
		sizes[s.Name] = s.Size
	}
	return sizes
}

// TestBpfLinkerInputs links through each add function and BpfLinkerNewFD and
// expects the same bytes as BpfLinkerNew with BpfLinkerAddFile.
func TestBpfLinkerInputs(t *testing.T) {
	want := readTestFile(t, linkFile(t))
	input := readTestFile(t, linkerInputPath)

	tests := []struct {
		name string
		add  func(*BpfLinker) error
	}{
		{"file", func(l *BpfLinker) error { return BpfLinkerAddFile(l, linkerInputPath, nil) }},
		{"mem", func(l *BpfLinker) error { return BpfLinkerAddBuf(l, input, nil) }},
		{"fd", func(l *BpfLinker) error { return addInputFD(t, l) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := linkToFD(t, tt.add); !bytes.Equal(got, want) {
				t.Fatalf("linked %d bytes differ from the BpfLinkerNew output (%d bytes)", len(got), len(want))
			}
		})
	}
}

func addInputFD(t *testing.T, l *BpfLinker) error {
	f, err := os.Open(linkerInputPath)
	if err != nil {
		t.Fatalf("open input: %v", err)
	}
	defer f.Close()
	return BpfLinkerAddFD(l, int(f.Fd()), nil)
}

// linkToFD links into a caller-owned descriptor that already holds more bytes
// than the output, checks that the linker leaves the descriptor open and
// truncates the file to the output, and returns the file contents.
func linkToFD(t *testing.T, add func(*BpfLinker) error) []byte {
	t.Helper()

	path := filepath.Join(t.TempDir(), "linked.bpf.o")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xff}, 1<<16), 0o644); err != nil {
		t.Fatalf("write stale output: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	l, err := BpfLinkerNewFD(int(f.Fd()), nil)
	if err != nil {
		t.Fatalf("BpfLinkerNewFD: %v", err)
	}
	if err := add(l); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	BpfLinkerFree(l)

	if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err != nil {
		t.Fatalf("caller descriptor closed by the linker: %v", err)
	}
	return readTestFile(t, path)
}

// TestBpfLinkerOneObject checks that a second object is rejected with
// EOPNOTSUPP and leaves the first one intact.
func TestBpfLinkerOneObject(t *testing.T) {
	want := readTestFile(t, linkFile(t))
	input := readTestFile(t, linkerInputPath)

	got := linkToFD(t, func(l *BpfLinker) error {
		if err := BpfLinkerAddBuf(l, input, nil); err != nil {
			return err
		}
		if err := BpfLinkerAddFile(l, linkerInputPath, nil); !errors.Is(err, unix.EOPNOTSUPP) {
			t.Fatalf("second BpfLinkerAddFile = %v, want EOPNOTSUPP", err)
		}
		if err := BpfLinkerAddBuf(l, input, nil); !errors.Is(err, unix.EOPNOTSUPP) {
			t.Fatalf("second BpfLinkerAddBuf = %v, want EOPNOTSUPP", err)
		}
		return nil
	})
	if !bytes.Equal(got, want) {
		t.Fatal("output after the rejected second object differs")
	}
}

// TestBpfLinkerEmpty finalizes without an input object, which writes an
// object with only the string and symbol tables.
func TestBpfLinkerEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bpf.o")
	l, err := BpfLinkerNew(path, nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}

	want := []linkerFixtureSection{
		{Name: ".strtab", Type: uint32(elf.SHT_STRTAB), Flags: uint64(elf.SHF_STRINGS), Size: 17},
		{Name: ".symtab", Type: uint32(elf.SHT_SYMTAB), Size: elfSymSize},
	}
	if got := linkedSections(t, path); !reflect.DeepEqual(got, want) {
		t.Fatalf("sections = %+v, want %+v", got, want)
	}
}

func TestBpfLinkerErrors(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	tests := []struct {
		name string
		add  func(*BpfLinker) error
		want unix.Errno
	}{
		{"missing file", func(l *BpfLinker) error { return BpfLinkerAddFile(l, "../testdata/progs/missing.bpf.o", nil) }, unix.ENOENT},
		{"not ELF", func(l *BpfLinker) error { return BpfLinkerAddBuf(l, []byte{1, 2, 3}, nil) }, unix.EINVAL},
		{"empty buffer", func(l *BpfLinker) error { return BpfLinkerAddBuf(l, nil, nil) }, unix.EINVAL},
		{"not BPF", func(l *BpfLinker) error { return BpfLinkerAddFile(l, exe, nil) }, unix.EOPNOTSUPP},
		{"negative fd", func(l *BpfLinker) error { return BpfLinkerAddFD(l, -1, nil) }, unix.EINVAL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := BpfLinkerNew(filepath.Join(t.TempDir(), "out.bpf.o"), nil)
			if err != nil {
				t.Fatalf("BpfLinkerNew: %v", err)
			}
			defer BpfLinkerFree(l)

			if err := tt.add(l); !errors.Is(err, tt.want) {
				t.Fatalf("add = %v, want %v", err, tt.want)
			}
			if err := BpfLinkerAddFile(l, linkerInputPath, nil); err != nil {
				t.Fatalf("add after a failed add: %v", err)
			}
		})
	}
}

func TestBpfLinkerLifecycle(t *testing.T) {
	if _, err := BpfLinkerNewFD(-1, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfLinkerNewFD(-1) = %v, want EINVAL", err)
	}
	if _, err := BpfLinkerNew(filepath.Join(t.TempDir(), "missing", "out.bpf.o"), nil); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("BpfLinkerNew in a missing directory = %v, want ENOENT", err)
	}

	l, err := BpfLinkerNew(filepath.Join(t.TempDir(), "out.bpf.o"), nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	if err := BpfLinkerAddFile(l, linkerInputPath, nil); err != nil {
		t.Fatalf("BpfLinkerAddFile: %v", err)
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	if err := BpfLinkerFinalize(l); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("second BpfLinkerFinalize = %v, want EINVAL", err)
	}
	if err := BpfLinkerAddFile(l, linkerInputPath, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfLinkerAddFile after finalize = %v, want EINVAL", err)
	}

	BpfLinkerFree(l)
	BpfLinkerFree(l)
	BpfLinkerFree(nil)
	if err := BpfLinkerFinalize(nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfLinkerFinalize(nil) = %v, want EINVAL", err)
	}
}

// TestBpfLinkerLoad loads the linked object into the kernel. It needs root or
// CAP_BPF and skips otherwise.
func TestBpfLinkerLoad(t *testing.T) {
	obj, err := BpfObjectOpenFile(linkFile(t), nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}
	if m := BpfObjectNextMap(obj, nil); m == nil || BpfMapFD(m) < 0 {
		t.Fatal("linked map has no descriptor")
	}
	if p := BpfObjectNextProgram(obj, nil); p == nil || BpfProgramFD(p) < 0 {
		t.Fatal("linked program has no descriptor")
	}
}
