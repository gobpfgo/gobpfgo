// SPDX-License-Identifier: LGPL-2.1-only
// golbpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"errors"
	"strings"
	"testing"

	"github.com/golbpfgo/golbpfgo/internal/btf"
	"github.com/golbpfgo/golbpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

func TestBtfLoad(t *testing.T) {
	o, err := elf.Open("../../testdata/progs/kprobe.bpf.o")
	if err != nil {
		t.Fatalf("open object: %v", err)
	}

	spec, err := btf.Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse BTF: %v", err)
	}
	sizes := make(map[string]uint32, len(o.Sections))
	for _, section := range o.Sections {
		sizes[section.Name] = uint32(section.Size)
	}
	if err := spec.FixupDatasecSizes(sizes); err != nil {
		t.Fatalf("fixup BTF: %v", err)
	}

	logBuf := make([]byte, 64*1024)
	fd, err := BtfLoad(spec.Raw(), logBuf, 1)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BtfLoad: %v\n%s", err, strings.TrimRight(string(logBuf), "\x00"))
	}
	defer unix.Close(fd)

	if fd < 0 {
		t.Fatalf("fd = %d", fd)
	}
}
