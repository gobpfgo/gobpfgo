// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package zip

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"testing"
)

// oracleCase is one case of zip.json: an archive the C library opened, the
// name it looked up, the positive errnos and the entry it returned.
type oracleCase struct {
	Name      string       `json:"name"`
	Lookup    string       `json:"lookup"`
	Archive   string       `json:"archive"`
	OpenErrno int32        `json:"open_errno"`
	FindErrno int32        `json:"find_errno"`
	Entry     *oracleEntry `json:"entry"`
}

type oracleEntry struct {
	Compression uint16 `json:"compression"`
	Name        string `json:"name"`
	DataOffset  uint32 `json:"data_offset"`
	DataLength  uint32 `json:"data_length"`
	Data        string `json:"data"`
}

func loadOracleCases(t *testing.T) []oracleCase {
	t.Helper()

	data, err := os.ReadFile("../../testdata/oracle/zip.json")
	if err != nil {
		t.Fatalf("read zip fixture: %v", err)
	}
	var f struct {
		Cases []oracleCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse zip fixture: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("zip fixture has no cases")
	}
	return f.Cases
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
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

func checkOracleEntry(t *testing.T, got Entry, want *oracleEntry) {
	t.Helper()

	if want == nil {
		t.Fatalf("FindEntry returned %+v, the oracle found no entry", got)
	}
	if got.Compression != want.Compression || got.Name != want.Name || got.DataOffset != want.DataOffset {
		t.Errorf("entry = compression %d, name %q, offset %d; want %d, %q, %d",
			got.Compression, got.Name, got.DataOffset, want.Compression, want.Name, want.DataOffset)
	}
	if uint32(len(got.Data)) != want.DataLength {
		t.Errorf("data length = %d, want %d", len(got.Data), want.DataLength)
	}
	if wantData := decodeHex(t, want.Data); !bytes.Equal(got.Data, wantData) {
		t.Errorf("data = %x, want %x", got.Data, wantData)
	}
}

// TestOracle replays every archive the C reader saw and compares the open
// and lookup errnos and the entry.
func TestOracle(t *testing.T) {
	t.Parallel()

	for _, c := range loadOracleCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()

			archive, err := Open(writeTemp(t, decodeHex(t, c.Archive)))
			if got := errnoOf(err); got != c.OpenErrno {
				t.Fatalf("Open errno = %d (%v), want %d", got, err, c.OpenErrno)
			}
			if err != nil {
				return
			}
			defer archive.Close()

			entry, err := archive.FindEntry(c.Lookup)
			if got := errnoOf(err); got != c.FindErrno {
				t.Fatalf("FindEntry(%q) errno = %d (%v), want %d", c.Lookup, got, err, c.FindErrno)
			}
			if err == nil {
				checkOracleEntry(t, entry, c.Entry)
			}
		})
	}
}
