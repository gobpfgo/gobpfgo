// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// logBTFFeatures logs the kernel release and the nine BTF feature probes
// in kern.
func logBTFFeatures(t *testing.T, kern btf.KernelFeatures) {
	t.Helper()

	t.Logf("kernel %s: func %v, datasec %v, global func %v, float %v, decl tag %v, type tag %v, enum64 %v, qmark datasec %v, layout %v",
		kernelRelease(t), kern.Func, kern.Datasec, kern.GlobalFunc, kern.Float, kern.DeclTag,
		kern.TypeTag, kern.Enum64, kern.QmarkDatasec, kern.Layout)
}

// TestBtfFuncProbeBTF parses the BTF the FUNC and global function probes
// load: a signed 32-bit int named int, the prototype void (int a) and the
// function x of it, static for the FUNC probe and global for the other.
func TestBtfFuncProbeBTF(t *testing.T) {
	for _, linkage := range []uint32{btf.FuncStatic, btf.FuncGlobal} {
		spec := parseProbeBTF(t, funcBTF(linkage), 48, "\x00int\x00x\x00a\x00")
		if len(spec.Types) != 4 {
			t.Fatalf("%d types, want 4", len(spec.Types))
		}
		checkSignedInt32(t, spec, 1)
		if i := spec.Types[1]; i.Name != "int" || i.SizeOrType != 4 {
			t.Errorf("INT = %q of %d bytes, want int of 4", i.Name, i.SizeOrType)
		}
		proto := spec.Types[2]
		if proto.Kind != btf.KindFuncProto || proto.Name != "" || proto.SizeOrType != 0 ||
			len(proto.Params) != 1 || proto.Params[0].Name != "a" || proto.Params[0].Type != 1 {
			t.Errorf("type 2 = %+v, want the prototype void (int a)", proto)
		}
		fn := spec.Types[3]
		if fn.Kind != btf.KindFunc || fn.Name != "x" || fn.SizeOrType != 2 || fn.Vlen != linkage || fn.KindFlag {
			t.Errorf("type 3 = %v %q of %d linkage %d, want FUNC x of 2 with linkage %d", fn.Kind, fn.Name, fn.SizeOrType, fn.Vlen, linkage)
		}
	}
}

// TestBtfDatasecProbeBTF parses the BTF the DATASEC probe loads: a signed
// 32-bit int, a static variable x of it, and a 4-byte DATASEC named .data
// that holds x at offset 0.
func TestBtfDatasecProbeBTF(t *testing.T) {
	spec := parseProbeBTF(t, datasecBTF(), 56, "\x00x\x00.data\x00")
	checkArgCtxTypes(t, spec, 1, []argCtxType{
		{btf.KindInt, "", 4, 0}, {btf.KindVar, "x", 1, 0}, {btf.KindDatasec, ".data", 4, 0},
	})
	checkSignedInt32(t, spec, 1)
	if v := spec.Types[2].Var; v == nil || v.Linkage != btf.VarStatic {
		t.Errorf("VAR = %+v, want static linkage", v)
	}
	if ds := spec.Types[3].DataSec; len(ds) != 1 || ds[0] != (btf.VarSecInfo{Type: 2, Offset: 0, Size: 4}) {
		t.Errorf("DATASEC variables = %+v, want x at offset 0 of size 4", ds)
	}
}

// TestBtfLayoutProbeBTF parses the BTF the layout probe loads, which
// libbpf__load_raw_btf_hdr lays out: a 32-byte header, a signed 32-bit int
// named int, a layout section with the entries of BTF_KIND_UNKN and
// BTF_KIND_INT right after it, and the string table.
func TestBtfLayoutProbeBTF(t *testing.T) {
	raw := layoutBTF()
	const strs = "\x00int\x00"
	spec, err := btf.Parse(raw, binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := btf.Header{Magic: 0xeb9f, Version: 1, HdrLen: rawBTFHdrLen, TypeLen: 16, StrOff: 24, StrLen: uint32(len(strs))}
	if spec.Header != want {
		t.Errorf("header = %+v, want %+v", spec.Header, want)
	}
	if off, length := binary.NativeEndian.Uint32(raw[24:]), binary.NativeEndian.Uint32(raw[28:]); off != 16 || length != 8 {
		t.Errorf("layout section at %d + %d, want 16 + 8", off, length)
	}
	if len(raw) != rawBTFHdrLen+16+8+len(strs) || string(spec.Strings) != strs {
		t.Errorf("%d bytes with strings %q, want %d bytes with %q", len(raw), spec.Strings, rawBTFHdrLen+16+8+len(strs), strs)
	}
	if layout := raw[rawBTFHdrLen+16 : rawBTFHdrLen+24]; !bytes.Equal(layout, []byte{0, 0, 0, 0, 4, 0, 0, 0}) {
		t.Errorf("layout section = %x, want UNKN without payload and INT with 4 bytes", layout)
	}
	if len(spec.Types) != 2 || spec.Types[1].Name != "int" {
		t.Fatalf("types = %+v, want one INT named int", spec.Types)
	}
	checkSignedInt32(t, spec, 1)
}

// requireBTFLoad skips the test when BPF_BTF_LOAD is not permitted, and
// fails it when the kernel rejects a blob of one int.
func requireBTFLoad(t *testing.T) {
	t.Helper()

	fd, err := sys.BtfLoad(rawBTF([]uint32{1, btfTypeInfo(btf.KindInt, 0), 4, 1<<24 | 32}, "\x00int\x00"), nil, 0)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("BPF_BTF_LOAD not permitted: %v", err)
	}
	if err != nil {
		t.Fatalf("load a minimal BTF: %v", err)
	}
	unix.Close(fd)
}

// TestBtfFeatureProbes runs the FUNC, global function, DATASEC and layout
// probes on the running kernel. Each test kernel, 5.10 or later, has the
// first three, from Linux 5.0, 5.6 and 5.2. The layout section comes with
// Linux 7.1, so its probe fails before and succeeds from it on. The cached
// results of kernelBTFFeatures agree with fresh probes. It needs root or
// CAP_BPF and skips otherwise.
func TestBtfFeatureProbes(t *testing.T) {
	requireBTFLoad(t)
	kern := kernelBTFFeatures()
	logBTFFeatures(t, kern)

	if !kern.Func || !kern.GlobalFunc || !kern.Datasec {
		t.Errorf("func %v, global func %v, datasec %v; every test kernel has them", kern.Func, kern.GlobalFunc, kern.Datasec)
	}
	if want := getKernelVersion() >= kernelVersion(7, 1, 0); kern.Layout != want {
		t.Errorf("layout %v on kernel %s, want %v", kern.Layout, kernelRelease(t), want)
	}
	for _, tt := range []struct {
		name   string
		cached bool
		probe  func() bool
	}{
		{"func", kern.Func, probeBtfFunc},
		{"global func", kern.GlobalFunc, probeBtfGlobalFunc},
		{"datasec", kern.Datasec, probeBtfDatasec},
		{"layout", kern.Layout, probeBtfLayout},
	} {
		if got := tt.probe(); got != tt.cached {
			t.Errorf("%s probe = %v, cached %v", tt.name, got, tt.cached)
		}
	}
}

// btfKindLayouts is libbpf's kind layout table up to BTF_KIND_ENUM64: for
// each kind, the size of the payload after struct btf_type and of each of
// its vlen entries.
var btfKindLayouts = [][2]byte{
	{0, 0}, {4, 0}, {0, 0}, {12, 0}, {0, 12}, {0, 12}, {0, 8}, {0, 0}, {0, 0}, {0, 0},
	{0, 0}, {0, 0}, {0, 0}, {0, 8}, {4, 0}, {0, 12}, {0, 0}, {4, 0}, {0, 0}, {0, 12},
}

// layoutObjectBTF returns a BTF blob with a layout section of
// btfKindLayouts, laid out like the layout probe's: an int, a static
// variable x of it in a DATASEC .data, and the global function f of the
// prototype int (int a).
func layoutObjectBTF() []byte {
	const strs = "\x00int\x00x\x00.data\x00a\x00f\x00"
	types := []uint32{
		// [1] INT int: signed, 32 bits, 4 bytes.
		1, btfTypeInfo(btf.KindInt, 0), 4, 1<<24 | 32,
		// [2] VAR x of [1], static.
		5, btfTypeInfo(btf.KindVar, 0), 1, btf.VarStatic,
		// [3] DATASEC .data: 4 bytes, x at offset 0.
		7, btfTypeInfo(btf.KindDatasec, 1), 4, 2, 0, 4,
		// [4] FUNC_PROTO int (int a).
		0, btfTypeInfo(btf.KindFuncProto, 1), 1, 13, 1,
		// [5] FUNC f of [4], global.
		15, btfTypeInfo(btf.KindFunc, btf.FuncGlobal), 4,
	}
	var layout []byte
	for _, l := range btfKindLayouts {
		layout = append(layout, l[0], l[1], 0, 0)
	}
	return rawBTFLayout(types, layout, strs)
}

// TestSanitizeLayoutLoad loads a BTF blob with a layout section. clang 23
// writes a 24-byte BTF header and has no option for a layout section, so no
// fixture object carries one, and the blob is built by hand, like the
// layout probe's. A kernel with the layout section, Linux 7.1 or later,
// accepts it as built, and an older one rejects the header. The copy that
// the load uploads, and a copy for a kernel without the layout section
// alone, load on every kernel; without the section they have none. It
// needs root or CAP_BPF and skips otherwise.
func TestSanitizeLayoutLoad(t *testing.T) {
	requireBTFLoad(t)
	raw := layoutObjectBTF()
	spec, err := btf.Parse(raw, binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	kern := kernelBTFFeatures()
	logBTFFeatures(t, kern)

	fd, err := sys.BtfLoad(raw, nil, 0)
	if err == nil {
		unix.Close(fd)
	}
	if kern.Layout != (err == nil) {
		t.Fatalf("blob with a layout section: load error %v, kernel layout support %v", err, kern.Layout)
	}

	noLayout := kern
	noLayout.Layout = false
	for _, tt := range []struct {
		name string
		kern btf.KernelFeatures
	}{
		{"kernel", kern},
		{"without layout", noLayout},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uploaded, err := sanitizeBTF(spec, tt.kern)
			if err != nil {
				t.Fatalf("sanitize: %v", err)
			}
			if !tt.kern.Layout {
				typeLen := spec.Header.TypeLen
				if len(uploaded) != rawBTFHdrLen+int(typeLen)+len(spec.Strings) ||
					binary.NativeEndian.Uint32(uploaded[16:]) != typeLen ||
					binary.NativeEndian.Uint64(uploaded[24:]) != 0 {
					t.Errorf("uploaded blob %x still has a layout section", uploaded)
				}
			}
			fd, err := sys.BtfLoad(uploaded, nil, 0)
			if err != nil {
				t.Fatalf("load the uploaded blob: %v", err)
			}
			unix.Close(fd)
			if !bytes.Equal(spec.Raw(), raw) {
				t.Error("sanitizing changed the spec")
			}
		})
	}
}

// sanitizeLoadObjects are the fixture objects whose BTF
// TestSanitizeConversionsLoad uploads. Their prototypes name every
// parameter: without FUNC, Sanitize makes each parameter an ENUM value, as
// libbpf does, and every kernel since 4.20 rejects an ENUM value without a
// name, so for an object with an unnamed parameter that rewrite only loads
// on 4.18 and 4.19.
var sanitizeLoadObjects = []string{
	"global_data.bpf.o", "kconfig_types.bpf.o", "subprog.bpf.o", "subprog_hidden.bpf.o",
	"sanitize_type_tag.bpf.o", "sanitize_enum64.bpf.o", "sanitize_float.bpf.o", "percpu.bpf.o",
}

// TestSanitizeConversionsLoad uploads the BTF of sanitizeLoadObjects as
// sanitized for the running kernel and, in addition, without DATASEC,
// without FUNC, without global functions, and without any feature. The
// kernel accepts each copy, so the rewrites make BTF it validates. Between
// them the objects have variables, DATASECs, prototypes and global
// functions, and the copy without any feature has none left. It needs root
// or CAP_BPF and skips otherwise.
func TestSanitizeConversionsLoad(t *testing.T) {
	requireBTFLoad(t)
	kern := kernelBTFFeatures()
	logBTFFeatures(t, kern)

	seen := map[string]int{}
	for _, name := range sanitizeLoadObjects {
		t.Run(name, func(t *testing.T) {
			obj, err := BpfObjectOpenFile(filepath.Join(progsDir, name), nil)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer BpfObjectClose(obj)
			for _, typ := range obj.btf.Types {
				switch {
				case typ.Kind == btf.KindVar, typ.Kind == btf.KindDatasec, typ.Kind == btf.KindFuncProto:
					seen[typ.Kind.String()]++
				case typ.Kind == btf.KindFunc && typ.Vlen == btf.FuncGlobal:
					seen["global func"]++
				}
			}

			for _, tt := range []struct {
				name  string
				clear func(k *btf.KernelFeatures)
			}{
				{"kernel", func(*btf.KernelFeatures) {}},
				{"datasec", func(k *btf.KernelFeatures) { k.Datasec = false }},
				{"func", func(k *btf.KernelFeatures) { k.Func = false }},
				{"global func", func(k *btf.KernelFeatures) { k.GlobalFunc = false }},
				{"none", func(k *btf.KernelFeatures) { *k = btf.KernelFeatures{} }},
			} {
				k := kern
				tt.clear(&k)
				raw, err := sanitizeBTF(obj.btf, k)
				if err != nil {
					t.Fatalf("%s: sanitize: %v", tt.name, err)
				}
				fd, err := sys.BtfLoad(raw, nil, 0)
				if err != nil {
					t.Errorf("%s: load the sanitized BTF: %v", tt.name, err)
					continue
				}
				unix.Close(fd)
				if tt.name != "none" {
					continue
				}
				sanitized, err := btf.Parse(raw, obj.elf.ByteOrder)
				if err != nil {
					t.Fatalf("parse the sanitized BTF: %v", err)
				}
				for _, kind := range []btf.Kind{btf.KindVar, btf.KindDatasec, btf.KindFuncProto, btf.KindFunc} {
					if n := countKind(sanitized, kind); n != 0 {
						t.Errorf("BTF sanitized without any feature has %d %v types", n, kind)
					}
				}
			}
		})
	}
	for _, kind := range []string{btf.KindVar.String(), btf.KindDatasec.String(), btf.KindFuncProto.String(), "global func"} {
		if seen[kind] == 0 {
			t.Errorf("no fixture object has a %s", kind)
		}
	}
}

// sanitizeOracle is the objects part of testdata/oracle/sanitize.json: the
// object BTF of fixture objects after libbpf's open, and the copy
// bpf_object__sanitize_btf made of it for a kernel without any BTF feature.
type sanitizeOracle struct {
	Objects []struct {
		Object    string `json:"object"`
		BTF       string `json:"btf"`
		Errno     int    `json:"errno"`
		Sanitized string `json:"sanitized"`
	} `json:"objects"`
}

// TestSanitizeOracleObjects opens each object of the sanitize oracle and
// checks that its object BTF is libbpf's after open, and that the blob the
// load would upload to a kernel without any BTF feature is libbpf's copy,
// byte for byte.
func TestSanitizeOracleObjects(t *testing.T) {
	data, err := os.ReadFile("../testdata/oracle/sanitize.json")
	if err != nil {
		t.Fatalf("read sanitize fixture: %v", err)
	}
	var f sanitizeOracle
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse sanitize fixture: %v", err)
	}
	if len(f.Objects) == 0 {
		t.Fatal("sanitize fixture has no objects")
	}
	for _, want := range f.Objects {
		t.Run(want.Object, func(t *testing.T) {
			if want.Errno != 0 {
				t.Fatalf("libbpf failed to sanitize with errno %d", want.Errno)
			}
			obj, err := BpfObjectOpenFile(filepath.Join(progsDir, want.Object), nil)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer BpfObjectClose(obj)
			if got := hex.EncodeToString(obj.btf.Raw()); got != want.BTF {
				t.Fatalf("object BTF = %s\nwant         %s", got, want.BTF)
			}
			raw, err := sanitizeBTF(obj.btf, btf.KernelFeatures{})
			if err != nil {
				t.Fatalf("sanitize: %v", err)
			}
			if got := hex.EncodeToString(raw); got != want.Sanitized {
				t.Fatalf("sanitized = %s\nwant        %s", got, want.Sanitized)
			}
		})
	}
}
