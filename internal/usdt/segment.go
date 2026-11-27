// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/usdt.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: parse_elf_segs, parse_vma_segs, find_elf_seg, find_vma_seg, collect_usdt_targets

//go:build linux && (amd64 || arm64)

package usdt

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrNoSegment is an address that no suitable segment holds: a file without
// PT_LOAD program headers, a probe outside an executable segment, a
// semaphore in an executable one, or a file the process has not mapped
// (ESRCH).
var ErrNoSegment = errors.New("no USDT segment")

// Segment is one mapped range of a file: a PT_LOAD program header, or an
// executable mapping of the file in a process. The virtual addresses
// [Start, End) hold the file bytes from Offset on.
type Segment struct {
	Start  uint64
	End    uint64
	Offset uint64
	Exec   bool
}

// loadSegments returns the PT_LOAD program headers of f sorted by address.
func loadSegments(f *elf.File) []Segment {
	var segs []Segment
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		segs = append(segs, Segment{
			Start:  p.Vaddr,
			End:    p.Vaddr + p.Memsz,
			Offset: p.Off,
			Exec:   p.Flags&elf.PF_X != 0,
		})
	}
	sortSegments(segs)
	return segs
}

func sortSegments(segs []Segment) {
	slices.SortStableFunc(segs, func(a, b Segment) int {
		switch {
		case a.Start < b.Start:
			return -1
		case a.Start > b.Start:
			return 1
		default:
			return 0
		}
	})
}

// FindSegment returns the segment whose virtual addresses hold addr.
func FindSegment(segs []Segment, addr uint64) (Segment, bool) {
	for _, s := range segs {
		if s.Start <= addr && addr < s.End {
			return s, true
		}
	}
	return Segment{}, false
}

// FindMappedSegment returns the segment that maps the file offset off.
func FindMappedSegment(segs []Segment, off uint64) (Segment, bool) {
	for _, s := range segs {
		if s.Offset <= off && off < s.Offset+(s.End-s.Start) {
			return s, true
		}
	}
	return Segment{}, false
}

// Address returns the virtual address of the probe instruction. When the file
// has a .stapsdt.base section and the note records a base, the location moves
// by their difference, which undoes prelink.
func (f *File) Address(note Note) uint64 {
	addr := note.Location
	if f.BaseAddr != 0 && note.Base != 0 {
		addr += f.BaseAddr - note.Base
	}
	return addr
}

// LocationOffset returns the file offset of the probe instruction, from
// Address and the PT_LOAD segment that holds it. A file without PT_LOAD
// headers, or an address outside every segment or in a segment that is not
// executable, fails with ErrNoSegment.
func (f *File) LocationOffset(note Note) (uint64, error) {
	addr := f.Address(note)
	seg, err := f.segmentFor(addr, "probe", note)
	if err != nil {
		return 0, err
	}
	if !seg.Exec {
		return 0, newError(ErrNoSegment, unix.ESRCH, "%s:%s at %#x is in segment [%#x, %#x), which is not executable",
			note.Provider, note.Name, addr, seg.Start, seg.End)
	}
	return addr - seg.Start + seg.Offset, nil
}

// SemaphoreOffset returns the file offset of the probe's semaphore, which must
// be in a segment that is not executable. The semaphore address is not moved
// by the .stapsdt.base difference. It fails with ErrNoSegment as
// LocationOffset does.
func (f *File) SemaphoreOffset(note Note) (uint64, error) {
	seg, err := f.segmentFor(note.Semaphore, "semaphore", note)
	if err != nil {
		return 0, err
	}
	if seg.Exec {
		return 0, newError(ErrNoSegment, unix.ESRCH, "semaphore of %s:%s at %#x is in executable segment [%#x, %#x)",
			note.Provider, note.Name, note.Semaphore, seg.Start, seg.End)
	}
	return note.Semaphore - seg.Start + seg.Offset, nil
}

func (f *File) segmentFor(addr uint64, what string, note Note) (Segment, error) {
	if len(f.Segments) == 0 {
		return Segment{}, newError(ErrNoSegment, unix.ESRCH, "no PT_LOAD program headers")
	}
	seg, ok := FindSegment(f.Segments, addr)
	if !ok {
		return Segment{}, newError(ErrNoSegment, unix.ESRCH, "no segment holds the %s of %s:%s at %#x",
			what, note.Provider, note.Name, addr)
	}
	return seg, nil
}

// ProcessSegments returns the executable mappings of the file at path in
// process pid, read from /proc/<pid>/maps and sorted by address. The path is
// compared with the mapped file names after resolving it to an absolute path
// without symlinks; a path under /proc/<pid>/root of the same process is
// compared without that prefix, as the process sees it. No mapping fails with
// ErrNoSegment.
func ProcessSegments(pid int, path string) ([]Segment, error) {
	mapped := mappedPath(pid, path)

	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	r, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("usdt: %w", err)
	}
	defer r.Close()

	segs, err := parseMaps(r, mapped)
	if err != nil {
		return nil, fmt.Errorf("usdt: %s: %w", mapsPath, err)
	}
	if len(segs) == 0 {
		return nil, newError(ErrNoSegment, unix.ESRCH, "%s (resolved to %s) is not mapped in PID %d", path, mapped, pid)
	}
	sortSegments(segs)
	return segs, nil
}

// mappedPath returns the name /proc/<pid>/maps uses for path.
func mappedPath(pid int, path string) string {
	if rest, ok := procRootPath(pid, path); ok {
		return rest
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return path
	}
	return resolved
}

// procRootPath strips a /proc/<pid>/root prefix naming pid itself and returns
// the path inside that root.
func procRootPath(pid int, path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return "", false
	}
	digits, rest, ok := strings.Cut(rest, "/")
	if !ok {
		return "", false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n != pid {
		return "", false
	}
	rest, ok = strings.CutPrefix(rest, "root/")
	if !ok {
		return "", false
	}
	return "/" + rest, true
}

// parseMaps returns the executable mappings of path in a /proc/<pid>/maps
// text. Each line is "start-end mode offset dev inode [name]"; the name may
// hold spaces. Reading stops at the first line that does not have that form.
func parseMaps(r io.Reader, path string) ([]Segment, error) {
	var segs []Segment

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		m, ok := parseMapsLine(sc.Text())
		if !ok {
			break
		}
		if m.name != path || len(m.mode) < 3 || m.mode[2] != 'x' {
			continue
		}
		segs = append(segs, m.seg)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return segs, nil
}

// mapsLine is one parsed /proc/<pid>/maps line.
type mapsLine struct {
	seg  Segment
	mode string
	name string
}

func parseMapsLine(line string) (mapsLine, bool) {
	var fields [5]string
	rest := line
	for i := range fields {
		rest = strings.TrimLeft(rest, " \t")
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		fields[i], rest = rest[:end], rest[end:]
	}

	startHex, endHex, ok := strings.Cut(fields[0], "-")
	if !ok || fields[1] == "" || fields[3] == "" {
		return mapsLine{}, false
	}
	start, err1 := strconv.ParseUint(startHex, 16, 64)
	end, err2 := strconv.ParseUint(endHex, 16, 64)
	off, err3 := strconv.ParseUint(fields[2], 16, 64)
	_, err4 := strconv.ParseUint(fields[4], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return mapsLine{}, false
	}

	return mapsLine{
		seg:  Segment{Start: start, End: end, Offset: off, Exec: true},
		mode: fields[1],
		name: strings.TrimLeft(rest, " \t"),
	}, true
}
