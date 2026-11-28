// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// newLogBuf returns a log buffer of size bytes that holds log and its NUL.
func newLogBuf(log string, size int) []byte {
	buf := make([]byte, size)
	copy(buf, log)
	return buf
}

// coreLogObject returns an object with the BTF and ELF of core.bpf.o, so
// its CO-RE relocations resolve, and the code of its handle_core program as
// loaded on its own, with no subprogram.
func coreLogObject(t *testing.T) (*BpfObject, *progCode) {
	t.Helper()

	core := openProg(t, "core.bpf.o")
	p := BpfObjectFindProgramByName(core, "handle_core")
	if p == nil {
		t.Fatal("no handle_core program")
	}
	obj := &BpfObject{btf: core.btf, elf: core.elf, btfFD: -1}
	return obj, &progCode{prog: p, subInsnOff: map[*BpfProgram]int{p: 0}}
}

// TestFixupVerifierLog runs the log fixup over verifier logs of an object
// with two maps, two externs and the CO-RE relocations of core.bpf.o's
// handle_core. A poisoned call in the last ten lines for an existing map or
// extern becomes the instruction index and the map or kernel function name,
// and one for a CO-RE relocation the index and the relocation's spec; every
// other log stays as it is.
func TestFixupVerifierLog(t *testing.T) {
	longName := strings.Repeat("k", 100)
	obj, code := coreLogObject(t)
	obj.maps = []*BpfMap{{name: ".percpu", fd: -1}, {name: "percpu.bss", fd: -1}}
	obj.externs = []externDesc{{name: "bpf_missing_kfunc"}, {name: longName}}

	const (
		head    = "func#0 @0\n0: R1=ctx() R10=fp0\n; percpu_last = tid; @ percpu.bpf.c:27\n"
		call0   = "9: (85) call unknown#2001000000\n"
		error0  = "invalid func unknown#2001000000\n"
		call1   = "9: (85) call unknown#2001000001\n"
		error1  = "invalid func unknown#2001000001\n"
		kcall0  = "18: (85) call unknown#2002000000\n"
		kerror0 = "invalid func unknown#2002000000\n"
		stats   = "processed 10 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1\n"
		fixed0  = "9: <invalid BPF map reference>\nBPF map '.percpu' is referenced but wasn't created\n"
		fixed1  = "9: <invalid BPF map reference>\nBPF map 'percpu.bss' is referenced but wasn't created\n"
		kfixed0 = "18: <invalid kfunc call>\nkfunc 'bpf_missing_kfunc' is referenced but wasn't resolved\n"
		ccall   = "18: (85) call unknown#195896080\n"
		cerror  = "invalid func unknown#195896080\n"
		cfixed  = "18: <invalid CO-RE relocation>\nfailed to resolve CO-RE relocation <byte_off> [11] struct core_sample.second (0:1 @ offset 4)\n"
	)
	// libbpf formats the patch into a 128-byte buffer, so a long name
	// loses the end of the second line, newline included.
	kfixed1 := ("18: <invalid kfunc call>\nkfunc '" + longName + "' is referenced but wasn't resolved\n")[:maxLogPatchLen]

	for _, tc := range []struct {
		name string
		log  string
		want string
	}{
		{"last line", head + call0 + error0, head + fixed0},
		{"before the stats", head + call1 + error1 + stats, head + fixed1 + stats},
		{"nine lines after", head + call0 + error0 + strings.Repeat(stats, 9), head + fixed0 + strings.Repeat(stats, 9)},
		{"ten lines after", head + call0 + error0 + strings.Repeat(stats, 10), ""},
		{"scanf whitespace", "  12:(85)call unknown#2001000000\n" + error0, "12: <invalid BPF map reference>\nBPF map '.percpu' is referenced but wasn't created\n"},
		{"no map", head + "9: (85) call unknown#2001000002\ninvalid func unknown#2001000002\n", ""},
		{"no instruction line", error0 + stats, ""},
		{"other call line", head + "9: (85) call bpf_get_current_pid_tgid#14\n" + error0, ""},
		{"CO-RE poison", head + ccall + cerror, head + cfixed},
		{"CO-RE before the stats", head + ccall + cerror + strings.Repeat(stats, 9), head + cfixed + strings.Repeat(stats, 9)},
		{"CO-RE ten lines after", head + ccall + cerror + strings.Repeat(stats, 10), ""},
		{"CO-RE without a relocation", head + "9: (85) call unknown#195896080\n" + cerror, ""},
		{"CO-RE after a map poison", head + call0 + error0 + ccall + cerror, head + call0 + error0 + cfixed},
		{"map after a CO-RE poison", head + ccall + cerror + call0 + error0, head + ccall + cerror + fixed0},
		{"kfunc poison", head + kcall0 + kerror0, head + kfixed0},
		{"kfunc before the stats", head + kcall0 + kerror0 + strings.Repeat(stats, 9), head + kfixed0 + strings.Repeat(stats, 9)},
		{"kfunc ten lines after", head + kcall0 + kerror0 + strings.Repeat(stats, 10), ""},
		{"kfunc scanf whitespace", "  18:(  85)call unknown# 2002000000\n" + kerror0, kfixed0},
		{"kfunc space before colon", " 18 : (85) call unknown#2002000000\n" + kerror0, ""},
		{"kfunc long name", head + "18: (85) call unknown#2002000001\ninvalid func unknown#2002000001\n" + stats, head + kfixed1 + stats},
		{"no extern", head + "18: (85) call unknown#2002000002\ninvalid func unknown#2002000002\n", ""},
		{"below the kfunc base", head + "18: (85) call unknown#2002\ninvalid func unknown#2002\n", ""},
		{"kfunc without instruction line", kerror0 + stats, ""},
		{"kfunc after a map poison", head + call0 + error0 + kcall0 + kerror0, head + call0 + error0 + kfixed0},
		{"map after a kfunc poison", head + kcall0 + kerror0 + call0 + error0, head + kcall0 + kerror0 + fixed0},
		{"empty", "", ""},
	} {
		buf := newLogBuf(tc.log, 4096)
		fixupVerifierLog(obj, code, buf)

		want := tc.want
		if want == "" {
			want = tc.log
		}
		if got := verifierLogString(buf); got != want {
			t.Errorf("%s: log =\n%s\nwant\n%s", tc.name, got, want)
		}
	}
}

// TestPatchLog checks the replacement inside a log buffer of fixed capacity,
// byte for byte. A shorter patch moves the rest of the log and its NUL left
// and leaves the old tail behind the NUL. A longer patch moves them right,
// the rest is cut where the buffer ends, and a patch that reaches the end is
// cut one byte short of it and drops the rest.
func TestPatchLog(t *testing.T) {
	for _, tc := range []struct {
		name          string
		log           string
		size          int
		orig, origSz  int
		patch         string
		want, wantLog string
	}{
		{"shorter", "ab\nXXXX\ncd\n", 16, 3, 5, "Y\n", "ab\nY\ncd\n\x00d\n\x00\x00\x00\x00\x00", "ab\nY\ncd\n"},
		{"same size", "ab\nXY\ncd\n", 12, 3, 3, "ZZ\n", "ab\nZZ\ncd\n\x00\x00\x00", "ab\nZZ\ncd\n"},
		{"longer", "ab\nX\ncd\n", 16, 3, 2, "YYYY\n", "ab\nYYYY\ncd\n\x00\x00\x00\x00\x00", "ab\nYYYY\ncd\n"},
		{"rest cut", "ab\nX\ncdef\n", 13, 3, 2, "YYYY\n", "ab\nYYYY\ncdef\n", "ab\nYYYY\ncdef\n"},
		{"patch cut", "ab\nX\ncd\n", 10, 3, 2, "YYYYYYYY\n", "ab\nYYYYYY\x00", "ab\nYYYYYY"},
	} {
		buf := newLogBuf(tc.log, tc.size)
		patchLog(buf, len(tc.log)+1, tc.orig, tc.origSz, tc.patch)
		if !bytes.Equal(buf, []byte(tc.want)) {
			t.Errorf("%s: buffer = %q, want %q", tc.name, buf, tc.want)
		}
		if got := verifierLogString(buf); got != tc.wantLog {
			t.Errorf("%s: log = %q, want %q", tc.name, got, tc.wantLog)
		}
	}
}

// TestFixupVerifierLogFullBuffer fixes logs that fill their buffer, as a
// truncated kernel log does. The longer map text pushes the end of the log
// out of the buffer, and the log then fills it without a NUL. The kfunc text
// alone reaches the end of the buffer, so it is cut one byte short of it,
// before the old NUL, and the rest of the log is dropped.
func TestFixupVerifierLogFullBuffer(t *testing.T) {
	obj := &BpfObject{maps: []*BpfMap{{name: ".percpu", fd: -1}}, externs: []externDesc{{name: "bpf_missing_kfunc"}}}
	const (
		mapLog     = "9: (85) call unknown#2001000000\ninvalid func unknown#2001000000\nprocessed 3 insns\n"
		mapFixed   = "9: <invalid BPF map reference>\nBPF map '.percpu' is referenced but wasn't created\nprocessed 3 insns\n"
		kfuncLog   = "18: (85) call unknown#2002000000\ninvalid func unknown#2002000000\nprocessed 3 insns\n"
		kfuncFixed = "18: <invalid kfunc call>\nkfunc 'bpf_missing_kfunc' is referenced but wasn't resolved\n"
	)
	for _, tc := range []struct {
		name, log, want string
	}{
		{"map", mapLog, mapFixed[:len(mapLog)+1]},
		{"kfunc", kfuncLog, kfuncFixed[:len(kfuncLog)]},
	} {
		buf := newLogBuf(tc.log, len(tc.log)+1)
		fixupVerifierLog(obj, nil, buf)
		if got := verifierLogString(buf); got != tc.want {
			t.Errorf("%s: log = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestVerifierLogString checks that the log ends at its NUL, even with bytes
// left behind it, and fills the buffer when there is none.
func TestVerifierLogString(t *testing.T) {
	if got := verifierLogString([]byte("ok\n\x00old tail\x00")); got != "ok\n" {
		t.Errorf("log with a NUL = %q, want %q", got, "ok\n")
	}
	if got := verifierLogString([]byte("full")); got != "full" {
		t.Errorf("log without a NUL = %q, want %q", got, "full")
	}
}

// coreSpecFixture is the part of core.json the CO-RE log fixup test uses:
// each relocation's section, instruction offset and libbpf's formatted spec.
type coreSpecFixture struct {
	Relos []struct {
		Section string `json:"section"`
		InsnOff int    `json:"insn_off"`
		Spec    string `json:"spec"`
	} `json:"relos"`
}

// coreReloPoisonLog returns a verifier log that ends with the poisoned call
// at insnIdx and the verifier's error for it, followed by tail.
func coreReloPoisonLog(insnIdx int, tail string) string {
	return fmt.Sprintf("func#0 @0\n0: R1=ctx() R10=fp0\n%d: (85) call unknown#195896080\ninvalid func unknown#195896080\n%s",
		insnIdx, tail)
}

// TestFixupVerifierLogCoreRelo poisons the instruction of every CO-RE
// relocation in core.bpf.o in a log of the program loaded on its own and
// checks the two patched lines against the spec libbpf formats for it in
// core.json.
func TestFixupVerifierLogCoreRelo(t *testing.T) {
	data, err := os.ReadFile("../testdata/oracle/core.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f coreSpecFixture
	if err := json.Unmarshal(data, &f); err != nil || len(f.Relos) == 0 {
		t.Fatalf("parse fixture: %d relocations, %v", len(f.Relos), err)
	}

	core := openProg(t, "core.bpf.o")
	const tail = "processed 20 insns (limit 1000000)\n"
	for _, relo := range f.Relos {
		p := programAtInsn(t, core, relo.Section, relo.InsnOff/bpfInsnLength)
		code := &progCode{prog: p, subInsnOff: map[*BpfProgram]int{p: 0}}
		insnIdx := relo.InsnOff/bpfInsnLength - p.secInsnOff

		buf := newLogBuf(coreReloPoisonLog(insnIdx, tail), 4096)
		fixupVerifierLog(core, code, buf)
		want := fmt.Sprintf("func#0 @0\n0: R1=ctx() R10=fp0\n%d: <invalid CO-RE relocation>\nfailed to resolve CO-RE relocation %s\n%s",
			insnIdx, relo.Spec, tail)
		if got := verifierLogString(buf); got != want {
			t.Errorf("%s insn %d: log =\n%s\nwant\n%s", relo.Section, insnIdx, got, want)
		}
	}
}

// programAtInsn returns the program of obj whose function in section holds
// the instruction at secInsnIdx.
func programAtInsn(t *testing.T, obj *BpfObject, section string, secInsnIdx int) *BpfProgram {
	t.Helper()

	for _, p := range obj.programs {
		if p.sectionName == section && progContainsInsn(p, secInsnIdx) {
			return p
		}
	}
	t.Fatalf("no program in %s holds instruction %d", section, secInsnIdx)
	return nil
}

// TestFixupVerifierLogCoreReloLines covers the line matching of the CO-RE
// fixup with the field relocation at instruction 18 of handle_core. libbpf's
// scanf result counts only the instruction index, so any line that starts
// with one is accepted. The error line must end in a newline, and the
// relocation must belong to the program that failed.
func TestFixupVerifierLogCoreReloLines(t *testing.T) {
	obj, code := coreLogObject(t)
	const (
		cerror = "invalid func unknown#195896080\n"
		spec   = "<byte_off> [11] struct core_sample.second (0:1 @ offset 4)"
		fixed  = "18: <invalid CO-RE relocation>\nfailed to resolve CO-RE relocation " + spec + "\n"
	)
	other := &progCode{prog: code.prog, subInsnOff: map[*BpfProgram]int{code.prog: 100}}

	for _, tc := range []struct {
		name string
		code *progCode
		log  string
		want string
	}{
		{"scanf whitespace", code, "  +18:(85)call unknown#195896080\n" + cerror, fixed},
		{"other call line", code, "18: (85) call bpf_get_current_pid_tgid#14\n" + cerror, fixed},
		{"index only", code, "18\n" + cerror, fixed},
		{"no index", code, "x18: (85) call unknown#195896080\n" + cerror, ""},
		{"error without newline", code, "18: (85) call unknown#195896080\ninvalid func unknown#195896080", ""},
		{"error with more digits", code, "18: (85) call unknown#1958960801\ninvalid func unknown#1958960801\n", ""},
		{"no instruction line", code, cerror, ""},
		{"no program code", nil, "18: (85) call unknown#195896080\n" + cerror, ""},
		{"program at another offset", other, "18: (85) call unknown#195896080\n" + cerror, ""},
		{"negative index", code, "-18: (85) call unknown#195896080\n" + cerror, ""},
	} {
		buf := newLogBuf(tc.log, 4096)
		fixupVerifierLog(obj, tc.code, buf)

		want := tc.want
		if want == "" {
			want = tc.log
		}
		if got := verifierLogString(buf); got != want {
			t.Errorf("%s: log = %q, want %q", tc.name, got, want)
		}
	}
}

// TestFixupVerifierLogCoreReloSubprog relocates subprog_core.bpf.o, whose
// .text subprograms carry CO-RE relocations, and poisons each relocation's
// instruction at its index in the main program's final code: the main
// program's own relocation at its own index, a subprogram's at the offset
// where its copy starts.
func TestFixupVerifierLogCoreReloSubprog(t *testing.T) {
	obj := openProg(t, "subprog_core.bpf.o")
	codes, _, err := relocateObject(obj, objectExt(t, obj), nil, argCtxTagSupported, declTagSupported)
	if err != nil || len(codes) != 1 {
		t.Fatalf("relocateObject: %d codes, %v", len(codes), err)
	}
	code := codes[0]

	// The specs of the relocations, keyed by section and instruction.
	specs := map[string]string{
		".text/0":                 "<enumval_value> [16] enum core_enum::CORE_FIRST = 1",
		".text/18":                "<byte_off> [11] struct core_sample.second (0:1 @ offset 4)",
		".text/19":                "<enumval_value> [16] enum core_enum::CORE_SECOND = 2",
		".text/26":                "<type_size> [11] struct core_sample",
		"kprobe/do_sys_openat2/1": "<type_size> [11] struct core_sample",
	}
	checked := 0
	for p, start := range code.subInsnOff {
		for secInsnIdx := p.secInsnOff; secInsnIdx < p.secInsnOff+p.secInsnCnt; secInsnIdx++ {
			spec, ok := specs[fmt.Sprintf("%s/%d", p.sectionName, secInsnIdx)]
			if !ok {
				continue
			}
			insnIdx := secInsnIdx - p.secInsnOff + start
			buf := newLogBuf(coreReloPoisonLog(insnIdx, ""), 4096)
			fixupVerifierLog(obj, code, buf)
			want := fmt.Sprintf("func#0 @0\n0: R1=ctx() R10=fp0\n%d: <invalid CO-RE relocation>\nfailed to resolve CO-RE relocation %s\n",
				insnIdx, spec)
			if got := verifierLogString(buf); got != want {
				t.Errorf("%s in %s at %d: log =\n%s\nwant\n%s", spec, BpfProgramName(p), insnIdx, got, want)
			}
			checked++
		}
	}
	if checked != len(specs) {
		t.Errorf("checked %d relocations in the final code, want %d", checked, len(specs))
	}
}

// TestCoreReloLogPatch checks the CO-RE patch text around libbpf's buffer
// sizes: a spec of 255 bytes fits, one of 256 is cut to 255 and followed by
// "...", and the lines stop at maxCoreLogPatchLen bytes.
func TestCoreReloLogPatch(t *testing.T) {
	const prefix = "7: <invalid CO-RE relocation>\nfailed to resolve CO-RE relocation "
	fits := strings.Repeat("a", coreSpecLogLen-1)
	long := strings.Repeat("b", coreSpecLogLen)

	if got, want := coreReloLogPatch(7, fits), prefix+fits+"\n"; got != want {
		t.Errorf("255-byte spec: %q, want %q", got, want)
	}
	if got, want := coreReloLogPatch(7, long), prefix+long[:coreSpecLogLen-1]+"...\n"; got != want {
		t.Errorf("256-byte spec: %q, want %q", got, want)
	}

	// An index of ten digits leaves room for the whole patch, so the
	// 511-byte limit is reached only through truncateLogPatch itself.
	if got := coreReloLogPatch(1234567890, long); len(got) > maxCoreLogPatchLen || !strings.HasSuffix(got, "...\n") {
		t.Errorf("long index: %d bytes, %q", len(got), got)
	}
	if got := truncateLogPatch(strings.Repeat("c", 600), maxCoreLogPatchLen); len(got) != maxCoreLogPatchLen {
		t.Errorf("truncateLogPatch kept %d bytes, want %d", len(got), maxCoreLogPatchLen)
	}
}
