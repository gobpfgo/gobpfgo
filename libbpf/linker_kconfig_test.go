// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// The pass-through fixtures. kconfig.bpf.o declares four .kconfig externs;
// link_kconfig.bpf.o declares CONFIG_TEST, weak, and LINUX_KERNEL_VERSION
// again, adds CONFIG_GOBPFGO_LINKED and brings a tracepoint section and .bss
// of its own. link_ksyms.bpf.o declares a typed .ksyms variable and two
// kernel functions. link_map_extern.bpf.o declares an extern map, which
// link_map_def.bpf.o defines.
const (
	kconfigProg   = "kconfig.bpf.o"
	kconfigLinked = "link_kconfig.bpf.o"
	ksymsProg     = "link_ksyms.bpf.o"
	mapExtern     = "link_map_extern.bpf.o"
	mapDef        = "link_map_def.bpf.o"

	// kconfigLinkedValue is CONFIG_GOBPFGO_LINKED in the fixtures' config.
	kconfigLinkedValue = 1234567890123
)

// The externs of the fixtures, by name.
var (
	kconfigProgExterns   = []string{"CONFIG_TEST", "LINUX_KERNEL_VERSION", "LINUX_GOBPFGO_UNKNOWN", "LINUX_GOBPFGO_FLAG"}
	kconfigLinkedExterns = []string{"CONFIG_TEST", "LINUX_KERNEL_VERSION", "CONFIG_GOBPFGO_LINKED"}
	ksymsExterns         = []string{"bpf_prog_active", "bpf_rcu_read_lock", "bpf_rcu_read_unlock"}
)

// TestBpfLinkerKconfigOracle links the .kconfig, .ksyms and extern map
// fixtures and compares the result with libbpf's linker: symbols,
// relocations and every section, including the .BTF and .BTF.ext bytes, the
// maps and programs after open or the open errno, and, for the .kconfig
// objects, the .kconfig value libbpf resolves with the fixture's config.
func TestBpfLinkerKconfigOracle(t *testing.T) {
	fixtures := []string{
		"linker-kconfig.json",
		"linker-kconfig-merge.json",
		"linker-kconfig-merge-reverse.json",
		"linker-ksyms.json",
		"linker-kconfig-ksyms.json",
		"linker-map-extern.json",
		"linker-map-extern-reverse.json",
		"linker-map-extern-unresolved.json",
	}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			want := loadLinkerFixture(t, fixture)
			compareLinked(t, want, linkObjects(t, want.Objects...))
		})
	}
}

// compareLinkedKconfig opens the linked object at path with the fixture's
// config, resolves its externs as the load does before it creates anything,
// and compares the errno and the .kconfig map value with libbpf's.
func compareLinkedKconfig(t *testing.T, want linkerFixture, path string) {
	t.Helper()

	obj := openKconfig(t, path, &want.Kconfig.Config)
	var errno int32
	if err := resolveExterns(obj); err != nil {
		errno = -int32(errnoFromError(err))
	}
	if errno != want.Kconfig.Errno {
		t.Fatalf("resolve errno = %d, want %d", errno, want.Kconfig.Errno)
	}
	if got, image := kconfigMap(t, obj).initialValue, linkedKconfigImage(t, obj, want); !bytes.Equal(got, image) {
		t.Fatalf(".kconfig value = %x, want %x", got, image)
	}
}

// linkedKconfigImage returns the fixture's .kconfig value for the running
// kernel. LINUX_KERNEL_VERSION holds the version of the kernel the fixture
// was made on, so on another kernel its bytes become the running kernel's.
func linkedKconfigImage(t *testing.T, obj *BpfObject, want linkerFixture) []byte {
	t.Helper()

	image, err := hex.DecodeString(want.Kconfig.Value)
	if err != nil {
		t.Fatalf("fixture .kconfig value: %v", err)
	}
	ext := findExternByName(obj.externs, "LINUX_KERNEL_VERSION")
	if ext == nil || kernelRelease(t) == want.Kernel {
		return image
	}
	if ext.kcfg.dataOff+4 > len(image) {
		t.Fatalf("LINUX_KERNEL_VERSION at %d is outside the %d-byte value", ext.kcfg.dataOff, len(image))
	}
	binary.NativeEndian.PutUint32(image[ext.kcfg.dataOff:], getKernelVersion())
	return image
}

// TestBpfLinkerKconfigExterns links the .kconfig fixtures alone and together
// and checks what the linker passes through. Every extern stays one
// undefined symbol, strong when any input declares it strong, and its BTF VAR
// keeps extern linkage. The .kconfig DATASEC lists each extern once, with
// the DATASEC size and the offsets left at zero for the loader to lay out.
// No .kconfig ELF section is written.
func TestBpfLinkerKconfigExterns(t *testing.T) {
	global, weak := undefSym(elf.STB_GLOBAL), undefSym(elf.STB_WEAK)
	both := map[string]externSym{
		"CONFIG_TEST":           global,
		"LINUX_KERNEL_VERSION":  global,
		"LINUX_GOBPFGO_UNKNOWN": weak,
		"LINUX_GOBPFGO_FLAG":    weak,
		"CONFIG_GOBPFGO_LINKED": global,
	}
	tests := []struct {
		name    string
		objects []string
		want    map[string]externSym
	}{
		{"strong alone", []string{kconfigProg}, map[string]externSym{
			"CONFIG_TEST":           global,
			"LINUX_KERNEL_VERSION":  global,
			"LINUX_GOBPFGO_UNKNOWN": weak,
			"LINUX_GOBPFGO_FLAG":    weak,
		}},
		{"weak alone", []string{kconfigLinked}, map[string]externSym{
			"CONFIG_TEST":           weak,
			"LINUX_KERNEL_VERSION":  global,
			"CONFIG_GOBPFGO_LINKED": global,
		}},
		{"strong first", []string{kconfigProg, kconfigLinked}, both},
		{"weak first", []string{kconfigLinked, kconfigProg}, both},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := linkObjects(t, tt.objects...)
			syms := externSymbols(t, path)
			for name, want := range tt.want {
				if got := syms[name]; got != want {
					t.Errorf("%s = %+v, want %+v", name, got, want)
				}
			}
			checkExternDatasec(t, parseFileBTF(t, path), btf.KconfigSec, slices.Collect(maps.Keys(tt.want)))
			if s := openLinkedELF(t, path).Section(btf.KconfigSec); s != nil {
				t.Errorf("linked object has a %s ELF section", btf.KconfigSec)
			}
		})
	}
}

// checkExternDatasec checks that the DATASEC name has size 0 and lists the
// extern VARs and FUNCs names once each, at offset 0, a VAR with its type's
// size and extern linkage, a FUNC with size 0 and extern linkage.
func checkExternDatasec(t *testing.T, spec *btf.Spec, name string, names []string) {
	t.Helper()

	ds := spec.Find(name, btf.KindDatasec)
	if ds == nil {
		t.Fatalf("no %s DATASEC", name)
	}
	if ds.SizeOrType != 0 {
		t.Errorf("%s DATASEC size = %d, want 0", name, ds.SizeOrType)
	}

	var got []string
	for _, vsi := range ds.DataSec {
		vt, err := spec.TypeByID(vsi.Type)
		if err != nil {
			t.Fatalf("%s variable: %v", name, err)
		}
		got = append(got, vt.Name)
		if err := checkExternVar(spec, vt, vsi); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(names))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s variables = %v, want %v", name, got, want)
	}
}

// checkExternVar describes how the DATASEC entry vsi of the extern vt differs
// from the pass-through layout, or returns nil.
func checkExternVar(spec *btf.Spec, vt *btf.Type, vsi btf.VarSecInfo) error {
	if vsi.Offset != 0 {
		return fmt.Errorf("%s at offset %d, want 0", vt.Name, vsi.Offset)
	}
	switch vt.Kind {
	case btf.KindVar:
		size, err := spec.SizeOf(vt.SizeOrType)
		if err != nil || vsi.Size != size {
			return fmt.Errorf("%s size %d, want %d (%v)", vt.Name, vsi.Size, size, err)
		}
		if vt.Var == nil || vt.Var.Linkage != btf.VarGlobalExtern {
			return fmt.Errorf("%s VAR %+v, want extern linkage", vt.Name, vt.Var)
		}
	case btf.KindFunc:
		if vsi.Size != 0 || vt.Vlen != btfFuncExtern {
			return fmt.Errorf("%s FUNC size %d linkage %d, want 0 and %d", vt.Name, vsi.Size, vt.Vlen, btfFuncExtern)
		}
	default:
		return fmt.Errorf("%s is a %v, want a VAR or FUNC", vt.Name, vt.Kind)
	}
	return nil
}

// TestBpfLinkerKsyms links link_ksyms.bpf.o alone and after kconfig.bpf.o.
// The .ksyms externs stay undefined with extern BTF in the .ksyms DATASEC,
// next to .kconfig when both are linked. The linked object opens, and loading
// it fails with EOPNOTSUPP before anything reaches the kernel, because this
// port does not resolve .ksyms externs.
func TestBpfLinkerKsyms(t *testing.T) {
	for _, names := range [][]string{{ksymsProg}, {kconfigProg, ksymsProg}} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			path := linkObjects(t, names...)
			syms := externSymbols(t, path)
			for _, name := range ksymsExterns {
				if got, want := syms[name], undefSym(elf.STB_GLOBAL); got != want {
					t.Errorf("%s = %+v, want %+v", name, got, want)
				}
			}
			spec := parseFileBTF(t, path)
			checkExternDatasec(t, spec, btf.KsymsSec, ksymsExterns)
			if slices.Contains(names, kconfigProg) {
				checkExternDatasec(t, spec, btf.KconfigSec, kconfigProgExterns)
			}

			obj, err := BpfObjectOpenFile(path, nil)
			if err != nil {
				t.Fatalf("BpfObjectOpenFile: %v", err)
			}
			defer BpfObjectClose(obj)
			err = BpfObjectLoad(obj)
			if !errors.Is(err, unix.EOPNOTSUPP) || !strings.Contains(err.Error(), "extern (ksym)") {
				t.Fatalf("BpfObjectLoad = %v, want EOPNOTSUPP for the .ksyms extern", err)
			}
		})
	}
}

// TestBpfLinkerEphemeralSections checks the section bookkeeping behind the
// pass-through. kconfig.bpf.o's .kconfig DATASEC has no ELF section, so the
// input gets an ephemeral .kconfig section after its ELF sections and the
// DATASEC keeps the size clang wrote, while .maps takes its ELF size. In the
// output the ephemeral section has a position, between .maps and the
// relocation section added after it, but no ELF index, so the relocation
// section is numbered one lower and only the other sections are written.
func TestBpfLinkerEphemeralSections(t *testing.T) {
	in, err := linkerLoadObj(kconfigProg, readProg(t, kconfigProg))
	if err != nil {
		t.Fatalf("linkerLoadObj: %v", err)
	}
	if len(in.secs) != len(in.elf.Sections)+1 {
		t.Fatalf("input has %d sections for %d ELF sections, want one ephemeral", len(in.secs), len(in.elf.Sections))
	}
	kcfg := in.secs[len(in.secs)-1]
	if !kcfg.ephemeral || kcfg.name != btf.KconfigSec || in.elfIndex(len(in.secs)-1) != 0 {
		t.Fatalf("last input section = %+v, want the ephemeral %s", kcfg, btf.KconfigSec)
	}
	if ds := &in.btf.Types[kcfg.btfTypeID]; ds.Kind != btf.KindDatasec || ds.Name != btf.KconfigSec || ds.SizeOrType != 0 {
		t.Fatalf("ephemeral DATASEC = %v %q size %d", ds.Kind, ds.Name, ds.SizeOrType)
	}
	if ds := in.btf.Find(mapsSecName, btf.KindDatasec); ds == nil || ds.SizeOrType != 32 {
		t.Fatalf(".maps DATASEC = %+v, want size 32", ds)
	}

	out := newLinkerOutput()
	if err := out.addObject(in); err != nil {
		t.Fatalf("addObject: %v", err)
	}
	want := []string{".strtab@1", ".symtab@2", "kprobe/do_sys_openat2@3", "license@4", ".maps@5", ".kconfig@0", ".relkprobe/do_sys_openat2@6"}
	if got := outputSecIndices(out.secs); !reflect.DeepEqual(got, want) {
		t.Fatalf("output sections = %v, want %v", got, want)
	}
	written := []string{".strtab@1", ".symtab@2", "kprobe/do_sys_openat2@3", "license@4", ".maps@5", ".relkprobe/do_sys_openat2@6"}
	if got := outputSecIndices(out.elfSecs()); !reflect.DeepEqual(got, written) {
		t.Fatalf("written sections = %v, want %v", got, written)
	}
	if rel := out.sec(out.findSec(".relkprobe/do_sys_openat2")); rel.info != 3 {
		t.Fatalf("relocation section info = %d, want 3", rel.info)
	}
}

// outputSecIndices names each output section with its ELF index.
func outputSecIndices(secs []*linkerSec) []string {
	var names []string
	for _, s := range secs {
		names = append(names, fmt.Sprintf("%s@%d", s.name, s.elfIdx))
	}
	return names
}

// TestBpfLinkerEphemeralMaterialize links link_map_extern.bpf.o, whose extern
// map gives it an ephemeral .maps section, then link_map_def.bpf.o, whose
// .maps ELF section turns it into a written one. The section keeps its
// position, so its DATASEC does not move, and takes the next ELF index,
// after the first object's relocation section. The extern resolves to the
// definition.
func TestBpfLinkerEphemeralMaterialize(t *testing.T) {
	out := newLinkerOutput()
	for _, name := range []string{mapExtern, mapDef} {
		in, err := linkerLoadObj(name, readProg(t, name))
		if err != nil {
			t.Fatalf("linkerLoadObj %s: %v", name, err)
		}
		if err := out.addObject(in); err != nil {
			t.Fatalf("addObject %s: %v", name, err)
		}
		if name == mapExtern {
			want := []string{".strtab@1", ".symtab@2", "kprobe/do_sys_openat2@3", "license@4", ".maps@0", ".relkprobe/do_sys_openat2@5"}
			if got := outputSecIndices(out.secs); !reflect.DeepEqual(got, want) {
				t.Fatalf("sections after %s = %v, want %v", name, got, want)
			}
		}
	}

	want := []string{".strtab@1", ".symtab@2", "kprobe/do_sys_openat2@3", "license@4", ".maps@6", ".relkprobe/do_sys_openat2@5"}
	if got := outputSecIndices(out.secs); !reflect.DeepEqual(got, want) {
		t.Fatalf("sections = %v, want %v", got, want)
	}
	sec := out.sec(out.findSec(mapsSecName))
	if sec.typ != elf.SHT_PROGBITS || sec.flags != elf.SHF_WRITE|elf.SHF_ALLOC || sec.addralign != 8 || sec.size != 32 {
		t.Fatalf(".maps = %+v, want the definition's header and 32 bytes", sec)
	}

	path := linkObjects(t, mapExtern, mapDef)
	if got, want := externSymbols(t, path)["map_extern_counts"], (externSym{uint32(elf.STT_OBJECT), uint32(elf.STB_GLOBAL), mapsSecName, 0}); got != want {
		t.Fatalf("map_extern_counts = %+v, want %+v", got, want)
	}
	v := parseFileBTF(t, path).Find("map_extern_counts", btf.KindVar)
	if v == nil || v.Var == nil || v.Var.Linkage != btf.VarGlobalAllocated {
		t.Fatalf("map_extern_counts VAR = %+v, want allocated", v)
	}
}

// TestBpfLinkerKconfigLoad loads the linked .kconfig fixtures with their
// oracle config, checks the .kconfig map value against libbpf's and its
// freeze, attaches every program and opens a file. handle_kconfig must read
// CONFIG_TEST, the kernel version and zero for the two weak externs, and
// handle_link_kconfig CONFIG_TEST, the kernel version and
// CONFIG_GOBPFGO_LINKED. It needs root or CAP_BPF and skips otherwise.
func TestBpfLinkerKconfigLoad(t *testing.T) {
	fixtures := []string{"linker-kconfig.json", "linker-kconfig-merge.json", "linker-kconfig-merge-reverse.json"}
	for _, fixture := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			want := loadLinkerFixture(t, fixture)
			path := linkObjects(t, want.Objects...)
			opts := NewBpfObjectOpenOpts()
			opts.Kconfig = &want.Kconfig.Config
			obj := loadTestObjectOpts(t, path, opts)
			defer BpfObjectClose(obj)

			m := kconfigMap(t, obj)
			image := linkedKconfigImage(t, obj, want)
			if got := lookupGlobal(t, m); !bytes.Equal(got, image) {
				t.Fatalf(".kconfig contents = %x, want %x", got, image)
			}
			err := sys.MapUpdateElem(BpfMapFD(m), make([]byte, internalMapKeySize), image, 0)
			if !errors.Is(err, unix.EPERM) {
				t.Fatalf("update frozen .kconfig: %v, want EPERM", err)
			}

			linked := slices.Contains(want.Objects, kconfigLinked)
			attachKprobes(t, obj, map[string]string{"handle_kconfig": "do_sys_openat2"})
			if linked {
				attachOpenatTracepoint(t, obj, "handle_link_kconfig")
			}
			triggerOpen(t)

			kver := uint64(getKernelVersion())
			if got, want := mapU64s(t, obj, "values", 4), []uint64{kconfigTest, kver, 0, 0}; !reflect.DeepEqual(got, want) {
				t.Errorf("values = %#x, want %#x", got, want)
			}
			if !linked {
				return
			}
			if got, want := linkedSeen(t, obj, path), []uint64{kconfigTest, kver, kconfigLinkedValue}; !reflect.DeepEqual(got, want) {
				t.Errorf("linked_seen = %#x, want %#x", got, want)
			}
		})
	}
}

// attachOpenatTracepoint attaches the named program to the
// syscalls/sys_enter_openat tracepoint until the test ends.
func attachOpenatTracepoint(t *testing.T, obj *BpfObject, name string) {
	t.Helper()

	prog := BpfObjectFindProgramByName(obj, name)
	if prog == nil {
		t.Fatalf("program %s not found", name)
	}
	link, err := BpfProgramAttachTracepoint(prog, "syscalls", "sys_enter_openat")
	if err != nil {
		if isAttachUnsupported(err) {
			t.Skipf("tracepoint attach is not supported: %v", err)
		}
		t.Fatalf("attach %s: %v", name, err)
	}
	t.Cleanup(func() { BpfLinkDestroy(link) })
}

// mapU64s reads keys 0 to n-1 of the named array map of 64-bit values.
func mapU64s(t *testing.T, obj *BpfObject, name string, n int) []uint64 {
	t.Helper()

	m := BpfObjectFindMapByName(obj, name)
	if m == nil {
		t.Fatalf("map %q not found", name)
	}
	values := make([]uint64, n)
	for i := range values {
		key := binary.NativeEndian.AppendUint32(nil, uint32(i))
		value := make([]byte, 8)
		if err := BpfMapLookupElem(m, key, value, 0); err != nil {
			t.Fatalf("lookup %s[%d]: %v", name, i, err)
		}
		values[i] = binary.NativeEndian.Uint64(value)
	}
	return values
}

// linkedSeen reads link_kconfig.bpf.o's linked_seen array from the .bss map,
// at its offset in the linked BTF.
func linkedSeen(t *testing.T, obj *BpfObject, path string) []uint64 {
	t.Helper()

	off := int(datasecVarOffset(t, parseFileBTF(t, path), ".bss", "linked_seen"))
	bss := lookupGlobal(t, globalDataMap(t, obj, ".bss"))
	if off+3*8 > len(bss) {
		t.Fatalf("linked_seen at %d is outside the %d-byte .bss", off, len(bss))
	}
	seen := make([]uint64, 3)
	for i := range seen {
		seen[i] = binary.NativeEndian.Uint64(bss[off+8*i:])
	}
	return seen
}

// TestBpfLinkerMapExternLoad loads link_map_extern.bpf.o linked with the
// map definition of link_map_def.bpf.o, in both orders, attaches
// handle_map_extern and opens a file: the program must count in the defined
// map. It needs root or CAP_BPF and skips otherwise.
func TestBpfLinkerMapExternLoad(t *testing.T) {
	for _, names := range [][]string{{mapExtern, mapDef}, {mapDef, mapExtern}} {
		t.Run(strings.Join(names, "_"), func(t *testing.T) {
			obj := loadTestObject(t, linkObjects(t, names...))
			defer BpfObjectClose(obj)

			attachKprobes(t, obj, map[string]string{"handle_map_extern": "do_sys_openat2"})
			triggerOpen(t)
			if got := mapValue(t, obj, "map_extern_counts"); got == 0 {
				t.Fatal("map_extern_counts = 0, want the open counted")
			}
		})
	}
}
