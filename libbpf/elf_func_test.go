// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	funcTestObject = "../testdata/progs/kprobe.bpf.o"
	funcTestMember = "kprobe.bpf.o"
	funcTestName   = "handle_open"

	// zipalignExtraID is the extra field Android's zipalign uses to pad
	// member data to an alignment.
	zipalignExtraID = 0xd935
	// archiveDataAlign keeps member data aligned for arm64, where uprobe
	// offsets must be multiples of the 4-byte breakpoint instruction.
	archiveDataAlign = 8
)

// archiveMember is one member written by writeArchive.
type archiveMember struct {
	name   string
	data   []byte
	method uint16
}

// writeArchive writes members to a zip file in a temporary directory and
// returns its path. CreateRaw keeps the headers as given, so no member has a
// data descriptor, and each member's data is padded to archiveDataAlign with
// a zipalign extra field. A Deflate member is stored as given; the archive
// reader never decompresses.
func writeArchive(t *testing.T, members ...archiveMember) string {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, m := range members {
		if err := w.Flush(); err != nil {
			t.Fatalf("flush archive: %v", err)
		}
		fw, err := w.CreateRaw(&zip.FileHeader{
			Name:               m.name,
			Method:             m.method,
			CRC32:              crc32.ChecksumIEEE(m.data),
			CompressedSize64:   uint64(len(m.data)),
			UncompressedSize64: uint64(len(m.data)),
			Extra:              zipalignExtra(buf.Len(), len(m.name)),
		})
		if err != nil {
			t.Fatalf("create %s: %v", m.name, err)
		}
		if _, err := fw.Write(m.data); err != nil {
			t.Fatalf("write %s: %v", m.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// zipalignExtra returns a zipalign extra field that moves the data of a
// member whose local header starts at headerOffset to archiveDataAlign.
func zipalignExtra(headerOffset, nameLength int) []byte {
	const localHeaderSize, extraHeaderSize = 30, 6

	dataOffset := headerOffset + localHeaderSize + nameLength + extraHeaderSize
	pad := (archiveDataAlign - dataOffset%archiveDataAlign) % archiveDataAlign
	extra := make([]byte, extraHeaderSize+pad)
	binary.LittleEndian.PutUint16(extra[0:], zipalignExtraID)
	binary.LittleEndian.PutUint16(extra[2:], uint16(len(extra)-4))
	binary.LittleEndian.PutUint16(extra[4:], archiveDataAlign)
	return extra
}

// memberDataOffset returns the data offset archive/zip reads for name, the
// independent reference for the archive reader.
func memberDataOffset(t *testing.T, path, name string) uint64 {
	t.Helper()

	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("archive/zip open %s: %v", path, err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == name {
			offset, err := f.DataOffset()
			if err != nil {
				t.Fatalf("data offset of %s: %v", name, err)
			}
			return uint64(offset)
		}
	}
	t.Fatalf("archive %s has no member %s", path, name)
	return 0
}

// objectArchive stores the kprobe test object after a text member, so the
// ELF member's data does not start right after the first local header.
func objectArchive(t *testing.T, method uint16) string {
	t.Helper()

	return writeArchive(t,
		archiveMember{name: "README", data: []byte("not an ELF file\n")},
		archiveMember{name: funcTestMember, data: readTestFile(t, funcTestObject), method: method},
	)
}

func TestFindUprobeFuncOffsetArchive(t *testing.T) {
	t.Parallel()

	archivePath := objectArchive(t, zip.Store)
	symOffset, err := findFuncOffset(funcTestObject, funcTestName)
	if err != nil {
		t.Fatalf("findFuncOffset(%s): %v", funcTestObject, err)
	}

	path, offset, err := findUprobeFuncOffset(archivePath+"!/"+funcTestMember, funcTestName)
	if err != nil {
		t.Fatalf("findUprobeFuncOffset: %v", err)
	}
	if path != archivePath {
		t.Errorf("path = %q, want the archive %q", path, archivePath)
	}
	want := memberDataOffset(t, archivePath, funcTestMember) + symOffset
	if offset != want {
		t.Errorf("offset = %#x, want data offset + symbol offset %#x", offset, want)
	}

	// The archive offset must hold the same instructions as the object.
	archive, object := readTestFile(t, archivePath), readTestFile(t, funcTestObject)
	const insnSize = 8
	if !bytes.Equal(archive[offset:offset+insnSize], object[symOffset:symOffset+insnSize]) {
		t.Errorf("archive bytes at %#x differ from object bytes at %#x", offset, symOffset)
	}
}

func TestFindUprobeFuncOffsetPlainFile(t *testing.T) {
	t.Parallel()

	want, err := findFuncOffset(funcTestObject, funcTestName)
	if err != nil {
		t.Fatalf("findFuncOffset: %v", err)
	}
	path, offset, err := findUprobeFuncOffset(funcTestObject, funcTestName)
	if err != nil {
		t.Fatalf("findUprobeFuncOffset: %v", err)
	}
	if path != funcTestObject || offset != want {
		t.Fatalf("findUprobeFuncOffset = %q, %#x; want %q, %#x", path, offset, funcTestObject, want)
	}
}

func TestFindUprobeFuncOffsetErrors(t *testing.T) {
	t.Parallel()

	stored := objectArchive(t, zip.Store)
	deflated := objectArchive(t, zip.Deflate)
	truncated := filepath.Join(t.TempDir(), "truncated.zip")
	data := readTestFile(t, stored)
	if err := os.WriteFile(truncated, data[:len(data)-1], 0o600); err != nil {
		t.Fatalf("write %s: %v", truncated, err)
	}

	tests := []struct {
		name       string
		binaryPath string
		funcName   string
		want       syscall.Errno
	}{
		{"missing function in file", funcTestObject, "no_such_function", unix.ENOENT},
		{"version suffix in file", funcTestObject, funcTestName + "@@LIBBPF_1.0", unix.ENOENT},
		{"missing function in member", stored + "!/" + funcTestMember, "no_such_function", unix.ENOENT},
		{"version suffix in member", stored + "!/" + funcTestMember, funcTestName + "@LIBBPF_1.0", unix.ENOENT},
		{"missing member", stored + "!/lib/libmissing.so", funcTestName, unix.ENOENT},
		{"missing archive", filepath.Join(t.TempDir(), "missing.zip") + "!/" + funcTestMember, funcTestName, unix.ENOENT},
		{"truncated archive", truncated + "!/" + funcTestMember, funcTestName, unix.EINVAL},
		{"compressed member", deflated + "!/" + funcTestMember, funcTestName, libbpfErrnoFormat},
		{"member is not ELF", stored + "!/README", funcTestName, libbpfErrnoFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := findUprobeFuncOffset(tt.binaryPath, tt.funcName)
			if got := errnoFromError(err); err == nil || got != tt.want {
				t.Fatalf("findUprobeFuncOffset = %v (errno %d), want errno %d", err, got, tt.want)
			}
		})
	}
}

// TestBpfProgramAttachUprobeArchive attaches a uprobe to a function inside a
// stored archive member in the legacy mode and checks the tracefs event the
// kernel registered. The probe never fires: nothing maps the archive and runs
// the member, which a test without cgo cannot do. The offset test is the
// proof of the offset; this one proves the event names the archive file at
// that offset.
func TestBpfProgramAttachUprobeArchive(t *testing.T) {
	archivePath := objectArchive(t, zip.Store)
	_, want, err := findUprobeFuncOffset(archivePath+"!/"+funcTestMember, funcTestName)
	if err != nil {
		t.Fatalf("findUprobeFuncOffset: %v", err)
	}
	root, err := tracefsRoot()
	if err != nil {
		t.Skipf("tracefs is not available: %v", err)
	}

	obj := loadTestObject(t, "../testdata/progs/uprobe.bpf.o")
	defer BpfObjectClose(obj)
	prog := BpfObjectFindProgramByName(obj, "handle_uprobe")
	if prog == nil {
		t.Fatal("program handle_uprobe not found")
	}

	link, err := BpfProgramAttachUprobeOpts(prog, -1, archivePath+"!/"+funcTestMember, 0, &BpfUprobeOpts{
		FuncName:   funcTestName,
		AttachMode: ProbeAttachModeLegacy,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skipf("uprobe attach not permitted: %v", err)
		}
		t.Fatalf("attach uprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	events := string(readTestFile(t, filepath.Join(root, "uprobe_events")))
	line := fmt.Sprintf("p:%s/%s %s:0x%016x", link.legacy.group(), link.legacy.name, archivePath, want)
	if !strings.Contains(events, line) {
		t.Fatalf("uprobe_events has no %q:\n%s", line, events)
	}
}
