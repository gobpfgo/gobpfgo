// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
)

// sanitizeOracleCase is one blob of testdata/oracle/sanitize.json: the BTF
// libbpf sanitized, named by its object or case, and the errno of
// bpf_object__sanitize_btf or the copy it returned.
type sanitizeOracleCase struct {
	Object    string `json:"object"`
	Name      string `json:"name"`
	BTF       string `json:"btf"`
	Errno     int    `json:"errno"`
	Sanitized string `json:"sanitized"`
}

// sanitizeFixture is testdata/oracle/sanitize.json: libbpf's
// bpf_object__sanitize_btf, run without CAP_BPF so that every BTF feature
// probe fails, on the object BTF of fixture objects after open and on
// synthetic BTF built with libbpf, some with a layout section or a reshaped
// header. It is the only feature combination the oracle can set; the
// others are pinned by the unit tests.
type sanitizeFixture struct {
	Features map[string]bool      `json:"features"`
	Objects  []sanitizeOracleCase `json:"objects"`
	Cases    []sanitizeOracleCase `json:"cases"`
}

func loadSanitizeFixture(t *testing.T) sanitizeFixture {
	t.Helper()

	data, err := os.ReadFile("../../testdata/oracle/sanitize.json")
	if err != nil {
		t.Fatalf("read sanitize fixture: %v", err)
	}
	var f sanitizeFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse sanitize fixture: %v", err)
	}
	return f
}

// TestSanitizeOracle parses each blob libbpf sanitized for a kernel
// without any BTF feature, sanitizes it with the zero KernelFeatures and
// compares the copy, byte for byte, or the errno with libbpf's.
func TestSanitizeOracle(t *testing.T) {
	f := loadSanitizeFixture(t)
	if len(f.Features) != 9 {
		t.Fatalf("fixture lists %d BTF features, want 9", len(f.Features))
	}
	for name, supported := range f.Features {
		if supported {
			t.Fatalf("fixture made with BTF %s supported", name)
		}
	}
	if len(f.Objects) == 0 || len(f.Cases) == 0 {
		t.Fatalf("fixture has %d objects and %d cases", len(f.Objects), len(f.Cases))
	}

	for _, want := range append(f.Objects, f.Cases...) {
		name := want.Object + want.Name
		t.Run(name, func(t *testing.T) {
			raw := decodeHex(t, want.BTF)
			spec, err := Parse(raw, binary.LittleEndian)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := spec.Sanitize(KernelFeatures{})
			if want.Errno != 0 {
				if !errors.Is(err, syscall.Errno(want.Errno)) {
					t.Fatalf("Sanitize = %v, want errno %d", err, want.Errno)
				}
				return
			}
			if err != nil {
				t.Fatalf("Sanitize: %v", err)
			}
			if hex.EncodeToString(got) != want.Sanitized {
				t.Fatalf("sanitized = %x\nwant        %s", got, want.Sanitized)
			}
		})
	}
}
