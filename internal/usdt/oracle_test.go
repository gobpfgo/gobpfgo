// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package usdt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"syscall"
	"testing"
)

const (
	oraclePath  = "../../testdata/oracle/usdt.json"
	fixturePath = "../../testdata/progs/usdt_target"
)

// oracleFixture is usdt.json: the notes of the fixture binary, the crafted
// note sections and the argument specs, as libbpf parsed them.
type oracleFixture struct {
	File        string           `json:"file"`
	StapsdtBase uint64           `json:"stapsdt_base"`
	Probes      []oracleProbe    `json:"probes"`
	NoteCases   []oracleNoteCase `json:"note_cases"`
	SpecCases   []oracleSpecCase `json:"spec_cases"`
}

type oracleNote struct {
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Args      string `json:"args"`
	Location  uint64 `json:"location"`
	Base      uint64 `json:"base"`
	Semaphore uint64 `json:"semaphore"`
}

// oracleProbe is one note of the fixture with its parsed spec.
type oracleProbe struct {
	oracleNote
	Errno int32       `json:"errno"`
	Spec  []oracleArg `json:"spec"`
}

type oracleArg struct {
	ArgType       string `json:"arg_type"`
	Size          int    `json:"size"`
	ArgSigned     bool   `json:"arg_signed"`
	ValOff        int64  `json:"val_off"`
	RegOff        int16  `json:"reg_off"`
	IdxRegOff     uint16 `json:"idx_reg_off"`
	ScaleBitshift uint8  `json:"scale_bitshift"`
	ArgBitshift   uint8  `json:"arg_bitshift"`
}

// oracleNoteCase is one crafted ELF image: the errno and notes of listing
// every note, and the errno and locations of looking one probe up.
type oracleNoteCase struct {
	Name           string       `json:"name"`
	Image          string       `json:"image"`
	Errno          int32        `json:"errno"`
	StapsdtBase    uint64       `json:"stapsdt_base"`
	Notes          []oracleNote `json:"notes"`
	LookupProvider string       `json:"lookup_provider"`
	LookupName     string       `json:"lookup_name"`
	FindErrno      int32        `json:"find_errno"`
	Found          []uint64     `json:"found"`
}

type oracleSpecCase struct {
	Arch  string      `json:"arch"`
	Args  string      `json:"args"`
	Errno int32       `json:"errno"`
	Spec  []oracleArg `json:"spec"`
}

func loadOracle(t *testing.T) oracleFixture {
	t.Helper()

	data, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Fatalf("read usdt fixture: %v", err)
	}
	var f oracleFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse usdt fixture: %v", err)
	}
	if len(f.Probes) == 0 || len(f.NoteCases) == 0 || len(f.SpecCases) == 0 {
		t.Fatal("usdt fixture has an empty section")
	}
	return f
}

// errnoOf returns the errno err wraps, 0 for nil and -1 for an error without
// one, so it compares directly with the oracle.
func errnoOf(err error) int32 {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return -1
	}
	return int32(errno)
}

func toOracleNote(n Note) oracleNote {
	return oracleNote{
		Provider:  n.Provider,
		Name:      n.Name,
		Args:      n.Args,
		Location:  n.Location,
		Base:      n.Base,
		Semaphore: n.Semaphore,
	}
}

func toOracleNotes(notes []Note) []oracleNote {
	out := make([]oracleNote, 0, len(notes))
	for _, n := range notes {
		out = append(out, toOracleNote(n))
	}
	return out
}

func toOracleSpec(spec []Arg) []oracleArg {
	out := make([]oracleArg, 0, len(spec))
	for _, a := range spec {
		out = append(out, oracleArg{
			ArgType:       a.ArgType.String(),
			Size:          a.Size(),
			ArgSigned:     a.ArgSigned,
			ValOff:        a.ValOff,
			RegOff:        a.RegOff,
			IdxRegOff:     a.IdxRegOff,
			ScaleBitshift: a.ScaleBitshift,
			ArgBitshift:   a.ArgBitshift,
		})
	}
	return out
}

func checkSpec(t *testing.T, got []Arg, want []oracleArg) {
	t.Helper()

	if g := toOracleSpec(got); !slices.Equal(g, want) {
		t.Errorf("spec =\n%+v\nwant\n%+v", g, want)
	}
}

// TestOracleProbes compares every note of the fixture binary, and the spec
// of each probe, with libbpf.
func TestOracleProbes(t *testing.T) {
	t.Parallel()

	want := loadOracle(t)
	f, err := Open(fixturePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if f.BaseAddr != want.StapsdtBase {
		t.Errorf("BaseAddr = %#x, want %#x", f.BaseAddr, want.StapsdtBase)
	}

	notes, err := f.Notes()
	if err != nil {
		t.Fatalf("Notes: %v", err)
	}
	wantNotes := make([]oracleNote, 0, len(want.Probes))
	for _, p := range want.Probes {
		wantNotes = append(wantNotes, p.oracleNote)
	}
	if got := toOracleNotes(notes); !slices.Equal(got, wantNotes) {
		t.Errorf("Notes =\n%+v\nwant\n%+v", got, wantNotes)
	}

	for _, p := range want.Probes {
		t.Run(p.Name, func(t *testing.T) {
			probes, err := f.Find(p.Provider, p.Name)
			if got := errnoOf(err); got != p.Errno {
				t.Fatalf("Find errno = %d (%v), want %d", got, err, p.Errno)
			}
			if len(probes) != 1 {
				t.Fatalf("Find returned %d call sites, want 1", len(probes))
			}
			if got := toOracleNote(probes[0].Note); got != p.oracleNote {
				t.Errorf("note = %+v, want %+v", got, p.oracleNote)
			}
			checkSpec(t, probes[0].Spec, p.Spec)
		})
	}
}

// TestOracleNoteCases replays every crafted ELF image libbpf read and
// compares the listing, the lookup and their errnos.
func TestOracleNoteCases(t *testing.T) {
	t.Parallel()

	for _, c := range loadOracle(t).NoteCases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()

			image, err := hex.DecodeString(c.Image)
			if err != nil {
				t.Fatalf("decode image: %v", err)
			}
			f, err := NewFile(bytes.NewReader(image))
			if err != nil {
				checkOpenError(t, err, c)
				return
			}
			if f.BaseAddr != c.StapsdtBase {
				t.Errorf("BaseAddr = %#x, want %#x", f.BaseAddr, c.StapsdtBase)
			}

			notes, err := f.Notes()
			if got := errnoOf(err); got != c.Errno {
				t.Fatalf("Notes errno = %d (%v), want %d", got, err, c.Errno)
			}
			if got := toOracleNotes(notes); !slices.Equal(got, c.Notes) {
				t.Errorf("Notes =\n%+v\nwant\n%+v", got, c.Notes)
			}

			probes, err := f.Find(c.LookupProvider, c.LookupName)
			if got := errnoOf(err); got != c.FindErrno {
				t.Fatalf("Find(%s:%s) errno = %d (%v), want %d", c.LookupProvider, c.LookupName, got, err, c.FindErrno)
			}
			found := []uint64{}
			for _, p := range probes {
				found = append(found, p.Location)
			}
			if !slices.Equal(found, c.Found) {
				t.Errorf("Find locations = %#x, want %#x", found, c.Found)
			}
		})
	}
}

// checkOpenError checks a NewFile failure: libbpf fails both the listing and
// the lookup with the same errno.
func checkOpenError(t *testing.T, err error, c oracleNoteCase) {
	t.Helper()

	if got := errnoOf(err); got != c.Errno || got != c.FindErrno {
		t.Fatalf("NewFile errno = %d (%v), want %d for listing and %d for lookup", got, err, c.Errno, c.FindErrno)
	}
}

// TestOracleSpecCases parses every argument spec libbpf parsed, for both
// architectures, and compares the errno and the arguments.
func TestOracleSpecCases(t *testing.T) {
	t.Parallel()

	arches := map[string]Arch{"amd64": ArchAMD64, "arm64": ArchARM64}
	for _, c := range loadOracle(t).SpecCases {
		arch, ok := arches[c.Arch]
		if !ok {
			t.Fatalf("unknown oracle arch %q", c.Arch)
		}

		spec, err := ParseSpec(arch, c.Args)
		if got := errnoOf(err); got != c.Errno {
			t.Errorf("%s %q: errno = %d (%v), want %d", c.Arch, c.Args, got, err, c.Errno)
			continue
		}
		checkSpec(t, spec, c.Spec)
	}
}

// TestFixtureForms keeps the fixture honest: a rebuilt usdt_target must
// still have a probe without arguments, a semaphore, every operand type the
// compiler emits for it and every size, signed and unsigned.
func TestFixtureForms(t *testing.T) {
	t.Parallel()

	want := loadOracle(t)
	types := map[string]bool{}
	sizes := map[oracleArg]bool{}
	empty, semaphore := false, false
	for _, p := range want.Probes {
		empty = empty || len(p.Spec) == 0
		semaphore = semaphore || p.Semaphore != 0
		for _, a := range p.Spec {
			types[a.ArgType] = true
			sizes[oracleArg{Size: a.Size, ArgSigned: a.ArgSigned}] = true
		}
	}

	if !empty || !semaphore {
		t.Errorf("fixture has a probe without arguments: %v, with a semaphore: %v", empty, semaphore)
	}
	for _, typ := range []string{"USDT_ARG_CONST", "USDT_ARG_REG", "USDT_ARG_REG_DEREF"} {
		if !types[typ] {
			t.Errorf("fixture has no %s argument", typ)
		}
	}
	for _, size := range []int{1, 2, 4, 8} {
		for _, signed := range []bool{false, true} {
			if !sizes[oracleArg{Size: size, ArgSigned: signed}] {
				t.Errorf("fixture has no size %d signed %v argument", size, signed)
			}
		}
	}
}
