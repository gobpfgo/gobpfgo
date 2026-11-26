// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

// progInfoCounts are the array counts and record sizes the kernel reports
// from the first BPF_OBJ_GET_INFO_BY_FD call.
type progInfoCounts struct {
	nrJitedKsyms, nrJitedFuncLens         uint32
	nrLineInfo, lineInfoRecSize           uint32
	nrJitedLineInfo, jitedLineInfoRecSize uint32
}

// firstProgInfo returns a first-call struct bpf_prog_info with the counts and
// a few scalar fields the second call must not echo back.
func firstProgInfo(c progInfoCounts) []byte {
	info := make([]byte, ProgInfoSize)
	put32 := func(off int, v uint32) { binary.NativeEndian.PutUint32(info[off:], v) }

	put32(progInfoOffType, 2)
	put32(progInfoOffJitedProgLen, 100)
	put32(progInfoOffXlatedProgLen, 144)
	put32(progInfoOffNrJitedKsyms, c.nrJitedKsyms)
	put32(progInfoOffNrJitedFuncLens, c.nrJitedFuncLens)
	put32(progInfoOffNrLineInfo, c.nrLineInfo)
	put32(progInfoOffLineInfoRecSize, c.lineInfoRecSize)
	put32(progInfoOffNrJitedLineInfo, c.nrJitedLineInfo)
	put32(progInfoOffJitedLineInfoRecSize, c.jitedLineInfoRecSize)
	return info
}

func u32At(buf []byte, off int) uint32 { return binary.NativeEndian.Uint32(buf[off:]) }
func u64At(buf []byte, off int) uint64 { return binary.NativeEndian.Uint64(buf[off:]) }

func TestNewProgInfoRequest(t *testing.T) {
	first := firstProgInfo(progInfoCounts{2, 2, 3, 16, 3, 8})
	req, bufs := newProgInfoRequest(first)

	if len(req) != ProgInfoSize {
		t.Fatalf("request size = %d, want %d", len(req), ProgInfoSize)
	}
	arrays := []struct {
		name               string
		buf                []byte
		wantLen            int
		countOff, ptrOff   int
		wantCount, recSize uint32
		recSizeOff         int
	}{
		{"jited_ksyms", bufs.jitedKsyms, 16, progInfoOffNrJitedKsyms, progInfoOffJitedKsyms, 2, 0, -1},
		{"jited_func_lens", bufs.jitedFuncLens, 8, progInfoOffNrJitedFuncLens, progInfoOffJitedFuncLens, 2, 0, -1},
		{"line_info", bufs.lineInfo, 48, progInfoOffNrLineInfo, progInfoOffLineInfo, 3, 16, progInfoOffLineInfoRecSize},
		{"jited_line_info", bufs.jitedLineInfo, 24, progInfoOffNrJitedLineInfo, progInfoOffJitedLineInfo, 3, 8, progInfoOffJitedLineInfoRecSize},
	}
	for _, a := range arrays {
		if len(a.buf) != a.wantLen {
			t.Errorf("%s buffer = %d bytes, want %d", a.name, len(a.buf), a.wantLen)
		}
		if got := u32At(req, a.countOff); got != a.wantCount {
			t.Errorf("%s count = %d, want %d", a.name, got, a.wantCount)
		}
		if got := u64At(req, a.ptrOff); got != uint64(addr(a.buf)) {
			t.Errorf("%s pointer = %#x, want the buffer address %#x", a.name, got, addr(a.buf))
		}
		if a.recSizeOff >= 0 {
			if got := u32At(req, a.recSizeOff); got != a.recSize {
				t.Errorf("%s record size = %d, want %d", a.name, got, a.recSize)
			}
		}
	}

	// The kernel copies every array whose count is set, so the scalar
	// fields of the first answer must not reach the second request.
	for _, off := range []int{progInfoOffType, progInfoOffJitedProgLen, progInfoOffXlatedProgLen} {
		if got := u32At(req, off); got != 0 {
			t.Errorf("request field at %d = %d, want 0", off, got)
		}
	}
}

func TestNewProgInfoRequestEmpty(t *testing.T) {
	// An unprivileged caller gets zero counts but the record sizes.
	first := firstProgInfo(progInfoCounts{lineInfoRecSize: 16, jitedLineInfoRecSize: 8})
	req, bufs := newProgInfoRequest(first)

	if bufs.jitedKsyms != nil || bufs.jitedFuncLens != nil || bufs.lineInfo != nil || bufs.jitedLineInfo != nil {
		t.Fatalf("buffers = %+v, want none", bufs)
	}
	if !bytes.Equal(req, make([]byte, ProgInfoSize)) {
		t.Fatal("request is not zero")
	}
}

// fillProgInfo stands in for the kernel's second answer: it copies the
// arrays, writes the scalars, and clears the jited symbol pointer the way the
// kernel does for a caller that may not read kernel addresses.
func fillProgInfo(req []byte, bufs *progInfoBufs) {
	binary.NativeEndian.PutUint32(req[progInfoOffType:], 2)
	binary.NativeEndian.PutUint32(req[progInfoOffID:], 77)
	binary.NativeEndian.PutUint32(req[progInfoOffJitedProgLen:], 100)
	binary.NativeEndian.PutUint32(req[progInfoOffXlatedProgLen:], 144)
	copy(req[progInfoOffName:], "handle_open")

	binary.NativeEndian.PutUint64(req[progInfoOffJitedKsyms:], 0)
	binary.NativeEndian.PutUint32(bufs.jitedFuncLens, 0x40)
	binary.NativeEndian.PutUint32(bufs.jitedFuncLens[4:], 0x30)
	for i := range bufs.lineInfo {
		bufs.lineInfo[i] = byte(i)
	}
	binary.NativeEndian.PutUint64(bufs.jitedLineInfo, 0x1000)
	binary.NativeEndian.PutUint64(bufs.jitedLineInfo[8:], 0x1008)
	binary.NativeEndian.PutUint64(bufs.jitedLineInfo[16:], 0x2000)
}

func TestDecodeProgInfo(t *testing.T) {
	req, bufs := newProgInfoRequest(firstProgInfo(progInfoCounts{2, 2, 3, 16, 3, 8}))
	fillProgInfo(req, bufs)
	info := decodeProgInfo(req, bufs)

	if info.Type != 2 || info.ID != 77 || info.JitedProgLen != 100 || info.XlatedProgLen != 144 || info.Name != "handle_open" {
		t.Errorf("scalars = %+v", info)
	}
	if info.NrJitedKsyms != 2 || info.JitedKsyms != nil {
		t.Errorf("jited ksyms = %d %v, want the count and no array", info.NrJitedKsyms, info.JitedKsyms)
	}
	if info.NrJitedFuncLens != 2 || !slices.Equal(info.JitedFuncLens, []uint32{0x40, 0x30}) {
		t.Errorf("jited func lens = %d %v", info.NrJitedFuncLens, info.JitedFuncLens)
	}
	if info.NrLineInfo != 3 || info.LineInfoRecSize != 16 || !bytes.Equal(info.LineInfo, bufs.lineInfo) {
		t.Errorf("line info = %d records of %d bytes, %d bytes copied", info.NrLineInfo, info.LineInfoRecSize, len(info.LineInfo))
	}
	if info.NrJitedLineInfo != 3 || info.JitedLineInfoRecSize != 8 || len(info.JitedLineInfo) != 24 ||
		u64At(info.JitedLineInfo, 16) != 0x2000 {
		t.Errorf("jited line info = %d records of %d bytes: %x", info.NrJitedLineInfo, info.JitedLineInfoRecSize, info.JitedLineInfo)
	}
}

func TestDecodeProgInfoShorterAnswer(t *testing.T) {
	req, bufs := newProgInfoRequest(firstProgInfo(progInfoCounts{nrLineInfo: 3, lineInfoRecSize: 16}))
	binary.NativeEndian.PutUint32(req[progInfoOffNrLineInfo:], 2)
	info := decodeProgInfo(req, bufs)

	if info.NrLineInfo != 2 || len(info.LineInfo) != 32 {
		t.Fatalf("line info = %d records, %d bytes; want the 2 records the kernel reported", info.NrLineInfo, len(info.LineInfo))
	}
}
