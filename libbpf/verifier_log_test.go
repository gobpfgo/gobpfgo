// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package libbpf

import (
	"bytes"
	"strings"
	"testing"
)

// newLogBuf returns a log buffer of size bytes that holds log and its NUL.
func newLogBuf(log string, size int) []byte {
	buf := make([]byte, size)
	copy(buf, log)
	return buf
}

// TestFixupVerifierLog runs the log fixup over verifier logs of an object
// with two maps and two externs. A poisoned call for an existing map or
// extern in the last ten lines becomes the instruction index and the map or
// kernel function name; every other log, including a CO-RE poison, stays as
// it is.
func TestFixupVerifierLog(t *testing.T) {
	longName := strings.Repeat("k", 100)
	obj := &BpfObject{
		maps:    []*BpfMap{{name: ".percpu"}, {name: "percpu.bss"}},
		externs: []externDesc{{name: "bpf_missing_kfunc"}, {name: longName}},
	}

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
		{"CO-RE poison", head + "9: (85) call unknown#195896080\ninvalid func unknown#195896080\n", ""},
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
		fixupVerifierLog(obj, buf)

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
	obj := &BpfObject{maps: []*BpfMap{{name: ".percpu"}}, externs: []externDesc{{name: "bpf_missing_kfunc"}}}
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
		fixupVerifierLog(obj, buf)
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
