// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/zip.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: zip_archive_open, zip_archive_close, zip_archive_find_entry, check_access, try_parse_end_of_cd, find_cd, local_file_header_at_offset, get_entry_at_offset

//go:build linux && (amd64 || arm64)

// Package zip finds members of a zip archive without extracting them, so a
// uprobe can target an ELF file stored inside an APK or another zip.
//
// Only single-file, non-ZIP64 archives are read. Encrypted members and
// members written with a data descriptor are never returned. The reader does
// not decompress: an Entry reports its compression method and the caller
// decides whether it can use the bytes.
package zip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/gobpfgo/gobpfgo/internal/mmap"
	"golang.org/x/sys/unix"
)

// Record magic numbers, from sections 4.3.7, 4.3.12 and 4.3.16 of the PKWARE
// APPNOTE.
const (
	endOfCDRecordMagic   = 0x06054b50
	cdFileHeaderMagic    = 0x02014b50
	localFileHeaderMagic = 0x04034b50
)

// General purpose flag bits that make a member unreadable in place.
const (
	flagEncrypted         = 1 << 0
	flagHasDataDescriptor = 1 << 3
)

// End of central directory record: 22 bytes plus a comment of up to 64 KiB.
const (
	endOfCDRecordSize        = 22
	endOfCDOffThisDisk       = 4
	endOfCDOffCDDisk         = 6
	endOfCDOffCDRecords      = 8
	endOfCDOffCDRecordsTotal = 10
	endOfCDOffCDSize         = 12
	endOfCDOffCDOffset       = 16
	endOfCDOffCommentLength  = 20
	endOfCDScanWindow        = 1 << 16
)

// Central directory file header: 46 bytes plus the name, extra field and
// comment.
const (
	cdFileHeaderSize             = 46
	cdFileHeaderOffFlags         = 8
	cdFileHeaderOffNameLength    = 28
	cdFileHeaderOffExtraLength   = 30
	cdFileHeaderOffCommentLength = 32
	cdFileHeaderOffLocalHeader   = 42
)

// Local file header: 30 bytes plus the name and extra field, followed by the
// member data.
const (
	localFileHeaderSize              = 30
	localFileHeaderOffFlags          = 6
	localFileHeaderOffCompression    = 8
	localFileHeaderOffCompressedSize = 18
	localFileHeaderOffNameLength     = 26
	localFileHeaderOffExtraLength    = 28
)

var le = binary.LittleEndian

// Archive is an open zip archive. The file is mapped read-only until Close,
// and every Entry it returns refers to that mapping.
type Archive struct {
	data      []byte
	size      uint32
	cdOffset  uint32
	cdRecords uint32
}

// Entry is one archive member as stored in its local file header.
//
// Compression is the APPNOTE method number; 0 means the member is stored
// uncompressed. Data holds the stored bytes, compressed or not, and aliases
// the archive mapping, so it is valid only until the archive is closed.
// DataOffset is the position of Data in the archive file.
type Entry struct {
	Compression uint16
	Name        string
	Data        []byte
	DataOffset  uint32
}

// Open maps the archive at path and locates its central directory.
//
// The error wraps the open or mmap errno; EINVAL when the file is larger than
// 4 GiB or has no valid end of central directory record; and EOPNOTSUPP when
// the record describes a multi-disk or ZIP64 archive. The caller must release
// the archive with Close.
func Open(path string) (*Archive, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("zip: open %s: %w", path, err)
	}
	defer unix.Close(fd)

	size, err := unix.Seek(fd, 0, io.SeekEnd)
	if err != nil || size > math.MaxUint32 {
		return nil, fmt.Errorf("zip: size of %s: %w", path, unix.EINVAL)
	}

	data, err := mmap.Map(fd, 0, int(size), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("zip: mmap %s: %w", path, err)
	}

	archive := &Archive{data: data, size: uint32(size)}
	if err := archive.findCD(); err != nil {
		_ = mmap.Unmap(data)
		return nil, fmt.Errorf("zip: %s: central directory: %w", path, err)
	}
	return archive, nil
}

// Close unmaps the archive. Entries found in it must not be used afterwards.
// Calling Close more than once, or on a nil archive, is a no-op.
func (a *Archive) Close() error {
	if a == nil || a.data == nil {
		return nil
	}
	err := mmap.Unmap(a.data)
	a.data = nil
	a.size = 0
	return err
}

// FindEntry returns the first central directory member called name that is
// neither encrypted nor written with a data descriptor.
//
// The error wraps ENOENT when no such member exists, and EINVAL when a
// central directory record or the member's local file header is out of
// bounds, has the wrong magic, or sets the encrypted or data descriptor flag.
// A closed archive returns EBADF.
func (a *Archive) FindEntry(name string) (Entry, error) {
	if a == nil || a.data == nil {
		return Entry{}, fmt.Errorf("zip: find %s: %w", name, unix.EBADF)
	}

	offset := a.cdOffset
	for i := uint32(0); i < a.cdRecords; i++ {
		cdfh, ok := a.checkAccess(offset, cdFileHeaderSize)
		if !ok || le.Uint32(cdfh) != cdFileHeaderMagic {
			return Entry{}, fmt.Errorf("zip: central directory record %d: %w", i, unix.EINVAL)
		}

		offset += cdFileHeaderSize
		nameLength := le.Uint16(cdfh[cdFileHeaderOffNameLength:])
		cdfhName, ok := a.checkAccess(offset, uint32(nameLength))
		if !ok {
			return Entry{}, fmt.Errorf("zip: central directory record %d name: %w", i, unix.EINVAL)
		}

		flags := le.Uint16(cdfh[cdFileHeaderOffFlags:])
		if flags&(flagEncrypted|flagHasDataDescriptor) == 0 && string(cdfhName) == name {
			entry, err := a.entryAtOffset(le.Uint32(cdfh[cdFileHeaderOffLocalHeader:]))
			if err != nil {
				return Entry{}, fmt.Errorf("zip: local file header of %s: %w", name, err)
			}
			return entry, nil
		}

		offset += uint32(nameLength)
		offset += uint32(le.Uint16(cdfh[cdFileHeaderOffExtraLength:]))
		offset += uint32(le.Uint16(cdfh[cdFileHeaderOffCommentLength:]))
	}

	return Entry{}, fmt.Errorf("zip: member %s: %w", name, unix.ENOENT)
}

// checkAccess returns size bytes of the archive at offset. The sum is
// computed in 32 bits, and a sum that wraps is rejected.
func (a *Archive) checkAccess(offset, size uint32) ([]byte, bool) {
	end := offset + size
	if end > a.size || offset > end {
		return nil, false
	}
	return a.data[offset:end], true
}

// tryParseEndOfCD accepts an end of central directory record at offset when
// its comment ends exactly at the end of the file and its central directory
// is in bounds. A valid record for a multi-disk or ZIP64 archive returns
// EOPNOTSUPP.
func (a *Archive) tryParseEndOfCD(offset uint32) error {
	eocd, ok := a.checkAccess(offset, endOfCDRecordSize)
	if !ok || le.Uint32(eocd) != endOfCDRecordMagic {
		return unix.EINVAL
	}

	commentLength := le.Uint16(eocd[endOfCDOffCommentLength:])
	if uint64(offset)+endOfCDRecordSize+uint64(commentLength) != uint64(a.size) {
		return unix.EINVAL
	}

	cdRecords := le.Uint16(eocd[endOfCDOffCDRecords:])
	if le.Uint16(eocd[endOfCDOffThisDisk:]) != 0 || le.Uint16(eocd[endOfCDOffCDDisk:]) != 0 ||
		le.Uint16(eocd[endOfCDOffCDRecordsTotal:]) != cdRecords {
		return unix.EOPNOTSUPP
	}

	cdOffset := le.Uint32(eocd[endOfCDOffCDOffset:])
	if _, ok := a.checkAccess(cdOffset, le.Uint32(eocd[endOfCDOffCDSize:])); !ok {
		return unix.EINVAL
	}

	a.cdOffset = cdOffset
	a.cdRecords = uint32(cdRecords)
	return nil
}

// findCD scans backwards from the last possible end of central directory
// position over the 64 KiB a comment can occupy. It stops at the first valid
// record, or at the first record that describes an unsupported layout.
func (a *Archive) findCD() error {
	if a.size <= endOfCDRecordSize {
		return unix.EINVAL
	}

	offset := int64(a.size) - endOfCDRecordSize
	limit := offset - endOfCDScanWindow
	err := error(unix.EINVAL)
	for ; offset >= 0 && offset > limit && err != nil; offset-- {
		err = a.tryParseEndOfCD(uint32(offset))
		if errors.Is(err, unix.EOPNOTSUPP) {
			break
		}
	}
	return err
}

// entryAtOffset reads the local file header at offset and returns its name
// and stored bytes. The local flags are checked again because they may differ
// from the central directory copy.
func (a *Archive) entryAtOffset(offset uint32) (Entry, error) {
	lfh, ok := a.checkAccess(offset, localFileHeaderSize)
	if !ok || le.Uint32(lfh) != localFileHeaderMagic {
		return Entry{}, unix.EINVAL
	}

	offset += localFileHeaderSize
	if le.Uint16(lfh[localFileHeaderOffFlags:])&(flagEncrypted|flagHasDataDescriptor) != 0 {
		return Entry{}, unix.EINVAL
	}

	nameLength := uint32(le.Uint16(lfh[localFileHeaderOffNameLength:]))
	name, ok := a.checkAccess(offset, nameLength)
	if !ok {
		return Entry{}, unix.EINVAL
	}

	offset += nameLength
	extraLength := uint32(le.Uint16(lfh[localFileHeaderOffExtraLength:]))
	if _, ok := a.checkAccess(offset, extraLength); !ok {
		return Entry{}, unix.EINVAL
	}

	offset += extraLength
	data, ok := a.checkAccess(offset, le.Uint32(lfh[localFileHeaderOffCompressedSize:]))
	if !ok {
		return Entry{}, unix.EINVAL
	}

	return Entry{
		Compression: le.Uint16(lfh[localFileHeaderOffCompression:]),
		Name:        string(name),
		Data:        data,
		DataOffset:  offset,
	}, nil
}
