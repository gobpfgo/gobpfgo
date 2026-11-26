// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

type probeEntry struct {
	Name   string `json:"name"`
	ID     uint32 `json:"id"`
	Result int32  `json:"result"`
}

type probeHelperEntry struct {
	ProgType   string `json:"prog_type"`
	ProgTypeID uint32 `json:"prog_type_id"`
	Helper     string `json:"helper"`
	HelperID   uint32 `json:"helper_id"`
	Result     int32  `json:"result"`
}

type probeFixture struct {
	Kernel       string             `json:"kernel"`
	PossibleCPUs int                `json:"possible_cpus"`
	ProgTypes    []probeEntry       `json:"prog_types"`
	MapTypes     []probeEntry       `json:"map_types"`
	Helpers      []probeHelperEntry `json:"helpers"`
}

func loadProbeFixture(t *testing.T) probeFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/probe.json")
	if err != nil {
		t.Fatalf("read probe fixture: %v", err)
	}
	var f probeFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse probe fixture: %v", err)
	}
	if len(f.ProgTypes) == 0 || len(f.MapTypes) == 0 || len(f.Helpers) == 0 {
		t.Fatal("probe fixture is incomplete")
	}
	return f
}

// TestLibbpfProbes compares the Go probes with libbpf on the kernel that
// produced the fixture. Other kernels run the stable subset below, because a
// probe result is a kernel fact and not a property of the port.
func TestLibbpfProbes(t *testing.T) {
	f := loadProbeFixture(t)
	if os.Geteuid() != 0 {
		t.Skip("probe results require root or CAP_BPF")
	}

	if running := kernelRelease(t); running != f.Kernel {
		t.Logf("fixture kernel %s, running %s: checking the stable subset", f.Kernel, running)
		checkStableProbes(t)
		return
	}

	for _, c := range f.ProgTypes {
		supported, err := LibbpfProbeBpfProgType(BpfProgType(c.ID))
		checkProbeResult(t, "prog type", c.Name, c.Result, supported, err)
	}
	for _, c := range f.MapTypes {
		supported, err := LibbpfProbeBpfMapType(BpfMapType(c.ID))
		checkProbeResult(t, "map type", c.Name, c.Result, supported, err)
	}
	for _, c := range f.Helpers {
		supported, err := LibbpfProbeBpfHelper(BpfProgType(c.ProgTypeID), BpfFuncID(c.HelperID))
		checkProbeResult(t, "helper "+c.ProgType+"/"+c.Helper, "", c.Result, supported, err)
	}

	cpus, err := LibbpfNumPossibleCpus()
	if err != nil {
		t.Fatalf("LibbpfNumPossibleCpus: %v", err)
	}
	if cpus != f.PossibleCPUs {
		t.Fatalf("possible cpus = %d, libbpf reports %d", cpus, f.PossibleCPUs)
	}
}

// checkProbeResult compares one probe with the oracle's signed result: 1 is
// supported, 0 is unsupported, and a negative value is an errno.
func checkProbeResult(t *testing.T, kind, name string, want int32, got bool, err error) {
	t.Helper()

	if want < 0 {
		if err == nil || !errors.Is(err, unix.Errno(-want)) {
			t.Errorf("%s %s = %v, %v; want errno %d", kind, name, got, err, -want)
		}
		return
	}
	if err != nil {
		t.Errorf("%s %s: %v", kind, name, err)
		return
	}
	if got != (want == 1) {
		t.Errorf("%s %s = %v, want %v", kind, name, got, want == 1)
	}
}

// checkStableProbes checks results that hold on every kernel the port tests.
func checkStableProbes(t *testing.T) {
	t.Helper()

	for _, progType := range []BpfProgType{
		BPF_PROG_TYPE_SOCKET_FILTER,
		BPF_PROG_TYPE_KPROBE,
		BPF_PROG_TYPE_TRACEPOINT,
		BPF_PROG_TYPE_XDP,
	} {
		supported, err := LibbpfProbeBpfProgType(progType)
		if err != nil || !supported {
			t.Errorf("prog type %d = %v, %v; want supported", progType, supported, err)
		}
	}
	if supported, err := LibbpfProbeBpfProgType(BPF_PROG_TYPE_UNSPEC); err != nil || supported {
		t.Errorf("unspec prog type = %v, %v; want unsupported", supported, err)
	}

	for _, mapType := range []BpfMapType{
		BPF_MAP_TYPE_HASH,
		BPF_MAP_TYPE_ARRAY,
		BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		BPF_MAP_TYPE_RINGBUF,
	} {
		supported, err := LibbpfProbeBpfMapType(mapType)
		if err != nil || !supported {
			t.Errorf("map type %d = %v, %v; want supported", mapType, supported, err)
		}
	}
	if supported, err := LibbpfProbeBpfMapType(BPF_MAP_TYPE_UNSPEC); err == nil || supported {
		t.Errorf("unspec map type = %v, %v; want EOPNOTSUPP", supported, err)
	}

	supported, err := LibbpfProbeBpfHelper(BPF_PROG_TYPE_SOCKET_FILTER, BPF_FUNC_map_lookup_elem)
	if err != nil || !supported {
		t.Errorf("socket_filter/map_lookup_elem = %v, %v; want supported", supported, err)
	}
	supported, err = LibbpfProbeBpfHelper(BPF_PROG_TYPE_KPROBE, BPF_FUNC_probe_read)
	if err != nil || !supported {
		t.Errorf("kprobe/probe_read = %v, %v; want supported", supported, err)
	}

	if cpus, err := LibbpfNumPossibleCpus(); err != nil || cpus < 1 {
		t.Errorf("possible cpus = %d, %v; want at least 1", cpus, err)
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		in   string
		want uint32
	}{
		{"5.10.46-1 (2022-09-29)", 5<<16 | 10<<8 | 46},
		{"6.18.63-3-lts", 6<<16 | 18<<8 | 63},
		{"5.4.8", 5<<16 | 4<<8 | 8},
		{"5.10", 0},
		{"invalid", 0},
	}
	for _, tt := range tests {
		if got := parseKernelVersion(tt.in); got != tt.want {
			t.Errorf("parseKernelVersion(%q) = %#x, want %#x", tt.in, got, tt.want)
		}
	}

	if got := debianKernelVersion("#1 SMP Debian 5.10.46-1 (2022-09-29)"); got != 5<<16|10<<8|46 {
		t.Errorf("debianKernelVersion = %#x, want 5.10.46", got)
	}
	if got := debianKernelVersion("not a Debian kernel"); got != 0 {
		t.Errorf("debianKernelVersion = %#x, want 0", got)
	}
	if got := getKernelVersion(); got == 0 {
		t.Error("getKernelVersion returned 0")
	}
}
