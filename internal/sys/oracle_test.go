// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"testing"
)

func archMatches(uname string) bool {
	switch runtime.GOARCH {
	case "amd64":
		return uname == "x86_64"
	case "arm64":
		return uname == "aarch64"
	default:
		return false
	}
}

// readOracleFixture reads testdata/oracle/<name>-<GOARCH>.json when it exists
// and testdata/oracle/<name>.json otherwise. perArch reports which one it read:
// a per-arch fixture must match the running arch, while the shared one may be
// for another arch and the caller skips.
func readOracleFixture(t *testing.T, name string) (data []byte, path string, perArch bool) {
	t.Helper()

	path = "../../testdata/oracle/" + name + "-" + runtime.GOARCH + ".json"
	data, err := os.ReadFile(path)
	if err == nil {
		return data, path, true
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read fixture: %v", err)
	}

	path = "../../testdata/oracle/" + name + ".json"
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data, path, false
}

// checkFixtureArch skips the test when the shared fixture is for another arch
// and fails it when a per-arch fixture is.
func checkFixtureArch(t *testing.T, path, arch string, perArch bool) {
	t.Helper()

	if archMatches(arch) {
		return
	}
	if perArch {
		t.Fatalf("fixture %s is for %s, running on %s", path, arch, runtime.GOARCH)
	}
	t.Skipf("fixture is for %s, running on %s", arch, runtime.GOARCH)
}
