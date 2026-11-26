// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package zip

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// member is one archive member for buildArchive. stored holds the bytes as
// they appear in the archive; size and crc describe the uncompressed data.
type member struct {
	name   string
	stored []byte
	size   uint64
	crc    uint32
	method uint16
	flags  uint16
}

// storedMember is an uncompressed member.
func storedMember(name, data string) member {
	return member{
		name:   name,
		stored: []byte(data),
		size:   uint64(len(data)),
		crc:    crc32.ChecksumIEEE([]byte(data)),
		method: stdzip.Store,
	}
}

// deflatedMember is a member compressed with DEFLATE.
func deflatedMember(t *testing.T, name, data string) member {
	t.Helper()

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		t.Fatalf("deflate %s: %v", name, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("deflate %s: %v", name, err)
	}

	m := storedMember(name, data)
	m.stored = buf.Bytes()
	m.method = stdzip.Deflate
	return m
}

func withFlags(m member, flags uint16) member {
	m.flags = flags
	return m
}

// buildArchive writes the members with CreateRaw, which keeps each header as
// given. CreateHeader would always set the data descriptor flag, and the
// reader skips such members.
func buildArchive(t *testing.T, comment string, members ...member) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := stdzip.NewWriter(&buf)
	for _, m := range members {
		fw, err := w.CreateRaw(&stdzip.FileHeader{
			Name:               m.name,
			Method:             m.method,
			Flags:              m.flags,
			CRC32:              m.crc,
			CompressedSize64:   uint64(len(m.stored)),
			UncompressedSize64: m.size,
		})
		if err != nil {
			t.Fatalf("create %s: %v", m.name, err)
		}
		if _, err := fw.Write(m.stored); err != nil {
			t.Fatalf("write %s: %v", m.name, err)
		}
	}
	if err := w.SetComment(comment); err != nil {
		t.Fatalf("set comment: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return buf.Bytes()
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.zip")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func openArchive(t *testing.T, path string) *Archive {
	t.Helper()

	archive, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = archive.Close() })
	return archive
}

// stdEntry returns the data offset and stored size archive/zip reports for
// name, the independent reference for Entry.
func stdEntry(t *testing.T, path, name string) (uint32, uint64) {
	t.Helper()

	r, err := stdzip.OpenReader(path)
	if err != nil {
		t.Fatalf("archive/zip open: %v", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name != name {
			continue
		}
		offset, err := f.DataOffset()
		if err != nil {
			t.Fatalf("archive/zip data offset of %s: %v", name, err)
		}
		return uint32(offset), f.CompressedSize64
	}
	t.Fatalf("archive/zip: no member %s", name)
	return 0, 0
}

// checkEntry compares an Entry with the member it came from and with the
// layout archive/zip reads from the same file.
func checkEntry(t *testing.T, path string, got Entry, want member) {
	t.Helper()

	offset, size := stdEntry(t, path, want.name)
	if got.Name != want.name {
		t.Errorf("Name = %q, want %q", got.Name, want.name)
	}
	if got.Compression != want.method {
		t.Errorf("Compression = %d, want %d", got.Compression, want.method)
	}
	if got.DataOffset != offset {
		t.Errorf("DataOffset = %d, want %d", got.DataOffset, offset)
	}
	if uint64(len(got.Data)) != size {
		t.Errorf("len(Data) = %d, want %d", len(got.Data), size)
	}
	if !bytes.Equal(got.Data, want.stored) {
		t.Errorf("Data = %q, want %q", got.Data, want.stored)
	}
}

func TestFindEntry(t *testing.T) {
	t.Parallel()

	one := []member{storedMember("lib/libone.so", "one member")}
	several := []member{
		storedMember("first.txt", "first"),
		storedMember("dir/second.bin", "\x7fELF second"),
		storedMember("third", ""),
		storedMember("first.txt", "a later duplicate is not returned"),
	}
	compressed := []member{deflatedMember(t, "packed.txt", "compress compress compress compress")}

	tests := []struct {
		name    string
		comment string
		members []member
		want    member
	}{
		{"one member", "", one, one[0]},
		{"first of several", "", several, several[0]},
		{"middle of several", "", several, several[1]},
		{"empty member", "", several, several[2]},
		{"compressed member", "", compressed, compressed[0]},
		{"archive comment", "an archive comment", one, one[0]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := writeTemp(t, buildArchive(t, tt.comment, tt.members...))
			entry, err := openArchive(t, path).FindEntry(tt.want.name)
			if err != nil {
				t.Fatalf("FindEntry(%q): %v", tt.want.name, err)
			}
			checkEntry(t, path, entry, tt.want)
		})
	}
}

func TestFindEntryErrors(t *testing.T) {
	t.Parallel()

	plain := storedMember("plain.txt", "plain")
	tests := []struct {
		name    string
		members []member
		lookup  string
		want    error
	}{
		{"missing member", []member{plain}, "absent.txt", unix.ENOENT},
		{"name prefix", []member{plain}, "plain.tx", unix.ENOENT},
		{"encrypted member", []member{withFlags(plain, flagEncrypted)}, plain.name, unix.ENOENT},
		{"data descriptor member", []member{withFlags(plain, flagHasDataDescriptor)}, plain.name, unix.ENOENT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := writeTemp(t, buildArchive(t, "", tt.members...))
			if _, err := openArchive(t, path).FindEntry(tt.lookup); !errors.Is(err, tt.want) {
				t.Fatalf("FindEntry(%q) = %v, want %v", tt.lookup, err, tt.want)
			}
		})
	}
}

// TestFindEntryLocalFlags sets a flag only in the local file header. The
// central directory still matches, so the local header check rejects it.
func TestFindEntryLocalFlags(t *testing.T) {
	t.Parallel()

	for _, flag := range []uint16{flagEncrypted, flagHasDataDescriptor} {
		data := buildArchive(t, "", storedMember("plain.txt", "plain"))
		binary.LittleEndian.PutUint16(data[localFileHeaderOffFlags:], flag)
		path := writeTemp(t, data)

		if _, err := openArchive(t, path).FindEntry("plain.txt"); !errors.Is(err, unix.EINVAL) {
			t.Errorf("flag %#x: FindEntry = %v, want EINVAL", flag, err)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()

	valid := buildArchive(t, "", storedMember("plain.txt", "plain"))
	eocd := len(valid) - endOfCDRecordSize
	patch16 := func(off int, value uint16) []byte {
		data := bytes.Clone(valid)
		binary.LittleEndian.PutUint16(data[eocd+off:], value)
		return data
	}
	patch32 := func(off int, value uint32) []byte {
		data := bytes.Clone(valid)
		binary.LittleEndian.PutUint32(data[eocd+off:], value)
		return data
	}

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty file", nil, unix.EINVAL},
		{"empty archive", buildArchive(t, ""), unix.EINVAL},
		{"truncated by one byte", valid[:len(valid)-1], unix.EINVAL},
		{"truncated record", valid[:eocd+endOfCDRecordSize/2], unix.EINVAL},
		{"trailing byte", append(bytes.Clone(valid), 0), unix.EINVAL},
		{"second disk", patch16(endOfCDOffThisDisk, 1), unix.EOPNOTSUPP},
		{"directory on another disk", patch16(endOfCDOffCDDisk, 1), unix.EOPNOTSUPP},
		{"record count mismatch", patch16(endOfCDOffCDRecordsTotal, 2), unix.EOPNOTSUPP},
		{"zip64 directory offset", patch32(endOfCDOffCDOffset, 0xffffffff), unix.EINVAL},
		{"directory past the end", patch32(endOfCDOffCDSize, uint32(len(valid))), unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			archive, err := Open(writeTemp(t, tt.data))
			if err == nil {
				_ = archive.Close()
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Open = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOpenMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := Open(filepath.Join(t.TempDir(), "missing.zip")); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("Open = %v, want ENOENT", err)
	}
}

func TestClose(t *testing.T) {
	t.Parallel()

	archive, err := Open(writeTemp(t, buildArchive(t, "", storedMember("plain.txt", "plain"))))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := archive.FindEntry("plain.txt"); !errors.Is(err, unix.EBADF) {
		t.Fatalf("FindEntry after Close = %v, want EBADF", err)
	}
}
