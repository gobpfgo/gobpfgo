// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

const progsDir = "../testdata/progs"

// linkObjects links the named objects from testdata/progs, in order, into a
// new linked.bpf.o and returns its path.
func linkObjects(t *testing.T, names ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "linked.bpf.o")
	l, err := BpfLinkerNew(path, nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)

	for _, name := range names {
		if err := BpfLinkerAddFile(l, filepath.Join(progsDir, name), nil); err != nil {
			t.Fatalf("BpfLinkerAddFile %s: %v", name, err)
		}
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	return path
}

// TestBpfLinkerMergeOracle links two objects and compares the result with
// libbpf's linker: maps, programs, symbols, and every section's header,
// contents and relocations, including the deduplicated .BTF and the .BTF.ext
// that follows its type IDs.
func TestBpfLinkerMergeOracle(t *testing.T) {
	fixtures := []string{"linker-merge.json", "linker-merge-reverse.json", "linker-text.json"}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			want := loadLinkerFixture(t, fixture)
			compareLinked(t, want, linkObjects(t, want.Objects...))
		})
	}
}

// TestBpfLinkerMergeBTF checks the deduplicated BTF of link_a.bpf.o and
// link_b.bpf.o in both orders: every type of the inputs appears once, the
// three map variables share one map definition struct, both programs share
// one prototype, and the .maps DATASEC lists each map at its symbol's
// offset, with the strong shared_counts from link_b.bpf.o.
func TestBpfLinkerMergeBTF(t *testing.T) {
	for _, names := range [][]string{
		{"link_a.bpf.o", "link_b.bpf.o"},
		{"link_b.bpf.o", "link_a.bpf.o"},
	} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			path := linkObjects(t, names...)
			out := parseFileBTF(t, path)

			if dups := duplicateTypes(t, out); len(dups) != 0 {
				t.Fatalf("duplicate types: %v", dups)
			}
			if got := sharedTypes(t, out, btf.KindVar, "counts_a", "shared_counts", "counts_b"); len(got) != 1 {
				t.Fatalf("map variables use %d struct types, want 1", len(got))
			}
			if got := sharedTypes(t, out, btf.KindFunc, "handle_a", "handle_b"); len(got) != 1 {
				t.Fatalf("programs use %d prototypes, want 1", len(got))
			}
			checkMapsDatasec(t, out, symbolValues(t, path))
		})
	}
}

// duplicateTypes describes every type that has the same encoding as an
// earlier one. After dedup a linked object of C types has none.
func duplicateTypes(t *testing.T, spec *btf.Spec) []string {
	t.Helper()

	seen := make(map[string]uint32)
	var dups []string
	for i := 1; i < len(spec.Types); i++ {
		key := string(btf.AppendType(nil, &spec.Types[i], binary.LittleEndian))
		if first, ok := seen[key]; ok {
			dups = append(dups, fmt.Sprintf("%d duplicates %d (%v %q)", i, first, spec.Types[i].Kind, spec.Types[i].Name))
			continue
		}
		seen[key] = uint32(i)
	}
	return dups
}

// sharedTypes returns the set of types that the named types of kind refer to.
func sharedTypes(t *testing.T, spec *btf.Spec, kind btf.Kind, names ...string) map[uint32]bool {
	t.Helper()

	ids := make(map[uint32]bool)
	for _, name := range names {
		ty := spec.Find(name, kind)
		if ty == nil {
			t.Fatalf("no %v %s", kind, name)
		}
		ids[ty.SizeOrType] = true
	}
	return ids
}

// checkMapsDatasec checks that the .maps DATASEC lists counts_a,
// shared_counts and counts_b, each at its symbol value with the 32-byte map
// definition size.
func checkMapsDatasec(t *testing.T, spec *btf.Spec, values map[string]uint64) {
	t.Helper()

	maps := spec.Find(".maps", btf.KindDatasec)
	if maps == nil {
		t.Fatal("no .maps DATASEC")
	}
	var names []string
	for _, v := range maps.DataSec {
		vt, err := spec.TypeByID(v.Type)
		if err != nil {
			t.Fatalf("DATASEC variable: %v", err)
		}
		names = append(names, vt.Name)
		if uint64(v.Offset) != values[vt.Name] || v.Size != 32 {
			t.Fatalf("%s at %d size %d, want %d size 32", vt.Name, v.Offset, v.Size, values[vt.Name])
		}
	}
	slices.Sort(names)
	if want := []string{"counts_a", "counts_b", "shared_counts"}; !reflect.DeepEqual(names, want) {
		t.Fatalf(".maps variables = %v, want %v", names, want)
	}
}

func symbolValues(t *testing.T, path string) map[string]uint64 {
	t.Helper()

	values := make(map[string]uint64)
	for _, sym := range linkedSymbols(t, openLinkedELF(t, path)) {
		values[sym.Name] = sym.Value
	}
	return values
}

// TestBpfLinkerMergeBTFExt checks that the merged .BTF.ext holds the records
// of both objects, with link_text_b.bpf.o's .text records moved past
// link_text_a.bpf.o's .text.
func TestBpfLinkerMergeBTFExt(t *testing.T) {
	path := linkObjects(t, "link_text_a.bpf.o", "link_text_b.bpf.o")

	textA := elfSectionSizes(t, filepath.Join(progsDir, "link_text_a.bpf.o"))[".text"]
	want := slices.Concat(
		extRecords(t, filepath.Join(progsDir, "link_text_a.bpf.o"), nil),
		extRecords(t, filepath.Join(progsDir, "link_text_b.bpf.o"), map[string]uint32{".text": uint32(textA)}),
	)
	slices.Sort(want)
	if got := extRecords(t, path, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf(".BTF.ext records = %q\nwant %q", got, want)
	}
}

// TestBpfLinkerMergeDeterministic links the same two objects through each add
// function and expects identical bytes every time.
func TestBpfLinkerMergeDeterministic(t *testing.T) {
	names := []string{"link_a.bpf.o", "link_b.bpf.o"}
	want := readTestFile(t, linkObjects(t, names...))

	bufs := make([][]byte, len(names))
	for i, name := range names {
		bufs[i] = readTestFile(t, filepath.Join(progsDir, name))
	}

	got := linkToFD(t, func(l *BpfLinker) error {
		if err := BpfLinkerAddBuf(l, bufs[0], nil); err != nil {
			return err
		}
		f, err := os.Open(filepath.Join(progsDir, names[1]))
		if err != nil {
			return err
		}
		defer f.Close()
		return BpfLinkerAddFD(l, int(f.Fd()), nil)
	})
	if !bytes.Equal(got, want) {
		t.Fatal("linking through buffer and descriptor gave different bytes")
	}
	if again := readTestFile(t, linkObjects(t, names...)); !bytes.Equal(again, want) {
		t.Fatal("linking twice gave different bytes")
	}
}

// Section indices of synthObject.
const (
	synthProg   = 1
	synthRel    = 2
	synthRodata = 3
	synthBss    = 4
	synthLic    = 5
)

// synthInsns is ld_imm64 r1 with immediate imm, which a relocation against
// the .rodata section symbol turns into a .rodata address, then exit.
func synthInsns(imm uint32) []byte {
	insns := make([]byte, 3*bpfInsnSize)
	insns[0], insns[1] = 0x18, 0x01
	binary.LittleEndian.PutUint32(insns[4:], imm)
	insns[16] = 0x95
	return insns
}

// synthObject builds an object without BTF: a program that loads .rodata+4
// through the .rodata section symbol, .rodata, .bss and a license, with
// local symbols only. The .rodata contents and alignment and the .bss size
// and symbol vary per object.
func synthObject(t *testing.T, rodata []byte, rodataAlign uint64, bssSize uint64, bssName string) []byte {
	t.Helper()
	return marshalSynth(t, synthOutput(rodata, rodataAlign, bssSize, bssName))
}

// synthOutput returns the writer input of synthObject, without the symbol
// and string tables, so a test can change it before marshalling.
func synthOutput(rodata []byte, rodataAlign uint64, bssSize uint64, bssName string) objelf.Output {
	local := func(typ elf.SymType) byte { return elf.ST_INFO(elf.STB_LOCAL, typ) }
	return objelf.Output{
		Sections: []objelf.OutputSection{
			{Name: "kprobe/x", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC | elf.SHF_EXECINSTR, Addralign: 8, Data: synthInsns(4)},
			{Name: ".relkprobe/x", Type: elf.SHT_REL, Flags: elf.SHF_INFO_LINK, Addralign: 8, Info: synthProg,
				Relocs: []objelf.OutputReloc{{Offset: 0, Symbol: 2, Type: objelf.R_BPF_64_64}}},
			{Name: ".rodata", Type: elf.SHT_PROGBITS, Flags: elf.SHF_ALLOC, Addralign: rodataAlign, Data: rodata},
			{Name: ".bss", Type: elf.SHT_NOBITS, Flags: elf.SHF_WRITE | elf.SHF_ALLOC, Addralign: bssSize, Size: bssSize},
			{Name: "license", Type: elf.SHT_PROGBITS, Flags: elf.SHF_WRITE | elf.SHF_ALLOC, Addralign: 1, Data: []byte("GPL\x00")},
		},
		Symbols: []objelf.OutputSymbol{
			{Info: local(elf.STT_SECTION), Section: synthProg},
			{Info: local(elf.STT_SECTION), Section: synthRodata},
			{Name: bssName, Info: local(elf.STT_OBJECT), Section: synthBss, Size: bssSize},
			{Name: "prog", Info: local(elf.STT_FUNC), Section: synthProg, Size: 3 * bpfInsnSize},
		},
	}
}

// marshalSynth adds the symbol and string tables to out and serializes it.
func marshalSynth(t *testing.T, out objelf.Output) []byte {
	t.Helper()

	out.Sections = append(out.Sections,
		objelf.OutputSection{Name: ".symtab", Type: elf.SHT_SYMTAB, Addralign: 8},
		objelf.OutputSection{Name: ".strtab", Type: elf.SHT_STRTAB, Addralign: 1},
	)
	data, err := objelf.Marshal(&out)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

// linkBufs links objects from memory and returns the output path.
func linkBufs(t *testing.T, objects ...[]byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "linked.bpf.o")
	l, err := BpfLinkerNew(path, nil)
	if err != nil {
		t.Fatalf("BpfLinkerNew: %v", err)
	}
	defer BpfLinkerFree(l)

	for i, obj := range objects {
		if err := BpfLinkerAddBuf(l, obj, nil); err != nil {
			t.Fatalf("BpfLinkerAddBuf #%d: %v", i, err)
		}
	}
	if err := BpfLinkerFinalize(l); err != nil {
		t.Fatalf("BpfLinkerFinalize: %v", err)
	}
	return path
}

// TestBpfLinkerMergeSections merges two objects with the same sections. The
// second object's code lands after the first's, its relocation moves with it,
// and its load of .rodata+4 now points 8 bytes further, past the padded
// first .rodata. .bss grows to the larger alignment, the license is kept
// once, and both local prog symbols stay.
func TestBpfLinkerMergeSections(t *testing.T) {
	x := synthObject(t, []byte("abcd"), 4, 4, "x_bss")
	y := synthObject(t, []byte("efghijkl"), 8, 8, "y_bss")
	f := openLinkedELF(t, linkBufs(t, x, y))

	if got, want := sectionData(t, f.Section("kprobe/x")), slices.Concat(synthInsns(4), synthInsns(12)); !bytes.Equal(got, want) {
		t.Fatalf("kprobe/x = %x, want %x", got, want)
	}
	if got := sectionData(t, f.Section(".rodata")); !bytes.Equal(got, []byte("abcd\x00\x00\x00\x00efghijkl")) {
		t.Fatalf(".rodata = %q", got)
	}
	if s := f.Section(".rodata"); s.Addralign != 8 {
		t.Fatalf(".rodata alignment = %d, want 8", s.Addralign)
	}
	if s := f.Section(".bss"); s.Size != 16 || s.Addralign != 8 {
		t.Fatalf(".bss size %d alignment %d, want 16 and 8", s.Size, s.Addralign)
	}
	if s := f.Section("license"); s.Size != 4 {
		t.Fatalf("license size = %d, want 4", s.Size)
	}

	syms := elfSymbols(t, f)
	wantRelocs := []linkerFixtureReloc{
		{Offset: 0, Type: objelf.R_BPF_64_64, Symbol: ".rodata"},
		{Offset: 24, Type: objelf.R_BPF_64_64, Symbol: ".rodata"},
	}
	if got := linkedRelocations(t, f, f.Section(".relkprobe/x"), syms); !reflect.DeepEqual(got, wantRelocs) {
		t.Fatalf("relocations = %+v, want %+v", got, wantRelocs)
	}

	wantSyms := []string{"kprobe/x@0", ".rodata@0", "x_bss@0", "prog@0", "y_bss@8", "prog@24"}
	var gotSyms []string
	for _, sym := range linkedSymbols(t, f) {
		gotSyms = append(gotSyms, sym.Name+"@"+strconv.FormatUint(sym.Value, 10))
	}
	if !reflect.DeepEqual(gotSyms, wantSyms) {
		t.Fatalf("symbols = %v, want %v", gotSyms, wantSyms)
	}
}

// TestBpfLinkerMergeErrors adds an object that conflicts with the first and
// checks the error, then that a compatible object still links: a failed add
// leaves the linker unchanged.
func TestBpfLinkerMergeErrors(t *testing.T) {
	first := synthObject(t, []byte("abcd"), 4, 4, "x_bss")
	next := synthObject(t, []byte("efgh"), 4, 4, "y_bss")

	tests := []struct {
		name   string
		mutate func(*objelf.Output)
		errno  unix.Errno
		reason string
	}{
		{"section type", func(o *objelf.Output) {
			o.Sections[synthBss-1] = objelf.OutputSection{Name: ".bss", Type: elf.SHT_PROGBITS, Flags: elf.SHF_WRITE | elf.SHF_ALLOC, Data: []byte{0}}
		}, unix.EINVAL, "type mismatch"},
		{"section flags", func(o *objelf.Output) { o.Sections[synthRodata-1].Flags |= elf.SHF_WRITE }, unix.EINVAL, "flags mismatch"},
		{"section entsize", func(o *objelf.Output) { o.Sections[synthRodata-1].Entsize = 1 }, unix.EINVAL, "entsize mismatch"},
		{"license", func(o *objelf.Output) { o.Sections[synthLic-1].Data = []byte("MIT\x00") }, unix.EINVAL, "non-identical contents"},
		{"extern", func(o *objelf.Output) {
			o.Symbols = append(o.Symbols, objelf.OutputSymbol{Name: "ext", Info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_NOTYPE)})
		}, unix.EOPNOTSUPP, "extern"},
		{"data section relocation", func(o *objelf.Output) {
			o.Sections[synthRel-1].Info = synthRodata
			o.Sections[synthRel-1].Name = ".rel.rodata"
		}, unix.EINVAL, "STT_SECTION in non-exec section"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := synthOutput([]byte("ijkl"), 4, 4, "z_bss")
			tt.mutate(&out)
			bad := marshalSynth(t, out)
			l, err := BpfLinkerNew(filepath.Join(t.TempDir(), "out.bpf.o"), nil)
			if err != nil {
				t.Fatalf("BpfLinkerNew: %v", err)
			}
			defer BpfLinkerFree(l)

			if err := BpfLinkerAddBuf(l, first, nil); err != nil {
				t.Fatalf("first add: %v", err)
			}
			err = BpfLinkerAddBuf(l, bad, nil)
			if !errors.Is(err, tt.errno) || !strings.Contains(err.Error(), tt.reason) {
				t.Fatalf("conflicting add = %v, want %v with %q", err, tt.errno, tt.reason)
			}
			if err := BpfLinkerAddBuf(l, next, nil); err != nil {
				t.Fatalf("add after a failed add: %v", err)
			}
		})
	}
}

// TestBpfLinkerMergeLoad loads the object linked from link_a.bpf.o and
// link_b.bpf.o into the kernel: the merged BTF, the three maps and both
// programs with their function info. It needs root or CAP_BPF and skips
// otherwise.
func TestBpfLinkerMergeLoad(t *testing.T) {
	for _, names := range [][]string{
		{"link_a.bpf.o", "link_b.bpf.o"},
		{"link_b.bpf.o", "link_a.bpf.o"},
	} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			obj, err := BpfObjectOpenFile(linkObjects(t, names...), nil)
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
			for m := BpfObjectNextMap(obj, nil); m != nil; m = BpfObjectNextMap(obj, m) {
				if BpfMapFD(m) < 0 {
					t.Fatalf("map %s has no descriptor", BpfMapName(m))
				}
			}
			for p := BpfObjectNextProgram(obj, nil); p != nil; p = BpfObjectNextProgram(obj, p) {
				if BpfProgramFD(p) < 0 {
					t.Fatalf("program %s has no descriptor", BpfProgramName(p))
				}
			}
		})
	}
}

// TestBpfLinkerTextLoad loads the object linked from link_text_a.bpf.o and
// link_text_b.bpf.o, in both orders, and runs it. Each program calls its own
// static bump, and the second object's bump follows the first in the merged
// .text, so one call is relocated past the first bump. Only the two programs
// get descriptors. Both attach to do_sys_openat2, and opening a file must
// count in each program's own map. It needs root or CAP_BPF and skips
// otherwise.
func TestBpfLinkerTextLoad(t *testing.T) {
	for _, names := range [][]string{
		{"link_text_a.bpf.o", "link_text_b.bpf.o"},
		{"link_text_b.bpf.o", "link_text_a.bpf.o"},
	} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			obj := loadTestObject(t, linkObjects(t, names...))
			defer BpfObjectClose(obj)

			checkSubprogDescriptors(t, obj)
			attachKprobes(t, obj, map[string]string{
				"handle_text_a": "do_sys_openat2",
				"handle_text_b": "do_sys_openat2",
			})
			triggerOpen(t)

			for _, name := range []string{"text_counts_a", "text_counts_b"} {
				if got := mapValue(t, obj, name); got == 0 {
					t.Errorf("%s = 0, want the open counted", name)
				}
			}
		})
	}
}
