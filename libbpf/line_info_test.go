// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// packLineInfo lays the records out in slots of recSize bytes and copies at
// most the 16 bytes of struct bpf_line_info into each, as the oracle does.
func packLineInfo(recs []BpfLineInfo, recSize uint32) []byte {
	out := make([]byte, len(recs)*int(recSize))
	for i, r := range recs {
		var rec [16]byte
		binary.NativeEndian.PutUint32(rec[0:], r.InsnOff)
		binary.NativeEndian.PutUint32(rec[4:], r.FileNameOff)
		binary.NativeEndian.PutUint32(rec[8:], r.LineOff)
		binary.NativeEndian.PutUint32(rec[12:], r.LineCol)
		copy(out[i*int(recSize):(i+1)*int(recSize)], rec[:])
	}
	return out
}

// packJitedLineInfo lays the jited addresses out in slots of recSize bytes.
func packJitedLineInfo(addrs []uint64, recSize uint32) []byte {
	out := make([]byte, len(addrs)*int(recSize))
	for i, a := range addrs {
		var rec [8]byte
		binary.NativeEndian.PutUint64(rec[:], a)
		copy(out[i*int(recSize):(i+1)*int(recSize)], rec[:])
	}
	return out
}

// xlatedLineInfo has four records and no jited info.
var xlatedLineInfo = []BpfLineInfo{
	{InsnOff: 0, FileNameOff: 1, LineOff: 10, LineCol: 5<<10 | 2},
	{InsnOff: 3, FileNameOff: 1, LineOff: 20, LineCol: 6<<10 | 4},
	{InsnOff: 7, FileNameOff: 1, LineOff: 30, LineCol: 8<<10 | 1},
	{InsnOff: 12, FileNameOff: 1, LineOff: 40, LineCol: 9<<10 | 3},
}

// twoFuncsLineInfo has records 0-2 in the function at 0x1000 and records 3-5
// in the function at 0x2000.
var (
	twoFuncsLineInfo = []BpfLineInfo{
		{InsnOff: 0, FileNameOff: 1, LineOff: 10, LineCol: 10<<10 | 1},
		{InsnOff: 2, FileNameOff: 1, LineOff: 20, LineCol: 11<<10 | 2},
		{InsnOff: 5, FileNameOff: 1, LineOff: 30, LineCol: 12<<10 | 3},
		{InsnOff: 8, FileNameOff: 2, LineOff: 40, LineCol: 20<<10 | 1},
		{InsnOff: 10, FileNameOff: 2, LineOff: 50, LineCol: 21<<10 | 2},
		{InsnOff: 14, FileNameOff: 2, LineOff: 60, LineCol: 22<<10 | 3},
	}
	twoFuncsJited = []uint64{0x1000, 0x1008, 0x1020, 0x2000, 0x2010, 0x2018}
	twoFuncsKsyms = []uint64{0x1000, 0x2000}
	twoFuncsLens  = []uint32{0x40, 0x30}
)

// newTestProgInfo builds a program info with 16-byte line records and 8-byte
// jited records whose counts match the arrays.
func newTestProgInfo(recs []BpfLineInfo, jited, ksyms []uint64, lens []uint32) *BpfProgInfo {
	return &BpfProgInfo{
		NrLineInfo:           uint32(len(recs)),
		LineInfoRecSize:      16,
		LineInfo:             packLineInfo(recs, 16),
		NrJitedLineInfo:      uint32(len(jited)),
		JitedLineInfoRecSize: 8,
		JitedLineInfo:        packJitedLineInfo(jited, 8),
		NrJitedKsyms:         uint32(len(ksyms)),
		JitedKsyms:           ksyms,
		NrJitedFuncLens:      uint32(len(lens)),
		JitedFuncLens:        lens,
	}
}

func twoFuncsProgInfo() *BpfProgInfo {
	return newTestProgInfo(twoFuncsLineInfo, twoFuncsJited, twoFuncsKsyms, twoFuncsLens)
}

func mustProgLineInfo(t *testing.T, info *BpfProgInfo) *BpfProgLineInfo {
	t.Helper()

	linfo, err := BpfProgLineInfoNew(info)
	if err != nil {
		t.Fatalf("BpfProgLineInfoNew: %v", err)
	}
	t.Cleanup(func() { BpfProgLineInfoFree(linfo) })
	return linfo
}

// checkFound compares a search result with record want of recs, or with the
// ENOENT failure when want is negative.
func checkFound(t *testing.T, name string, got *BpfLineInfo, err error, recs []BpfLineInfo, want int) {
	t.Helper()

	if want < 0 {
		if !errors.Is(err, unix.ENOENT) {
			t.Errorf("%s = %+v, %v; want ENOENT", name, got, err)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: %v; want record %d", name, err, want)
		return
	}
	if *got != recs[want] {
		t.Errorf("%s = %+v, want record %d %+v", name, *got, want, recs[want])
	}
}

func TestBpfProgLineInfoNewInvalid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BpfProgInfo)
	}{
		{"no records", func(info *BpfProgInfo) { info.NrLineInfo = 0 }},
		{"record smaller than insn_off", func(info *BpfProgInfo) { info.LineInfoRecSize = 3 }},
		{"line info shorter than its count", func(info *BpfProgInfo) { info.LineInfo = info.LineInfo[:16*5] }},
		{"jited line info shorter than its count", func(info *BpfProgInfo) { info.JitedLineInfo = info.JitedLineInfo[:8] }},
		{"fewer jited symbols than functions", func(info *BpfProgInfo) { info.JitedKsyms = info.JitedKsyms[:1] }},
		{"fewer function lengths than functions", func(info *BpfProgInfo) { info.JitedFuncLens = info.JitedFuncLens[:1] }},
		{"first record is not the first function", func(info *BpfProgInfo) { info.JitedKsyms = []uint64{0x1004, 0x2000} }},
		{"function address never reached", func(info *BpfProgInfo) { info.JitedKsyms = []uint64{0x1000, 0x2004} }},
		{"repeated address inside a function", func(info *BpfProgInfo) {
			info.JitedLineInfo = packJitedLineInfo([]uint64{0x1000, 0x1008, 0x1008, 0x2000, 0x2010, 0x2018}, 8)
		}},
		{"function longer than its length", func(info *BpfProgInfo) { info.JitedFuncLens = []uint32{0x20, 0x30} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := twoFuncsProgInfo()
			tt.mutate(info)
			if _, err := BpfProgLineInfoNew(info); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("BpfProgLineInfoNew = %v, want EINVAL", err)
			}
		})
	}

	if _, err := BpfProgLineInfoNew(nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("BpfProgLineInfoNew(nil) = %v, want EINVAL", err)
	}
}

func TestBpfProgLineInfoLfind(t *testing.T) {
	linfo := mustProgLineInfo(t, newTestProgInfo(xlatedLineInfo, nil, nil, nil))

	tests := []struct {
		insnOff, nrSkip uint32
		want            int
	}{
		{0, 0, 0},
		{2, 0, 0},
		{3, 0, 1},
		{11, 0, 2},
		{12, 0, 3},
		{1000, 0, 3},
		{2, 1, -1},  // before the first record searched
		{3, 1, 1},   // the skipped record is not returned
		{11, 2, 2},  // resume from a known record
		{12, 3, 3},  // the last record alone
		{12, 4, -1}, // nr_skip equal to the record count
		{0, 100, -1},
	}
	for _, tt := range tests {
		got, err := BpfProgLineInfoLfind(linfo, tt.insnOff, tt.nrSkip)
		checkFound(t, fmt.Sprintf("lfind(%d, %d)", tt.insnOff, tt.nrSkip), got, err, xlatedLineInfo, tt.want)
	}
}

func TestBpfProgLineInfoLfindAddrFunc(t *testing.T) {
	linfo := mustProgLineInfo(t, twoFuncsProgInfo())

	tests := []struct {
		addr            uint64
		funcIdx, nrSkip uint32
		want            int
	}{
		{0x0fff, 0, 0, -1},
		{0x1000, 0, 0, 0},
		{0x1007, 0, 0, 0},
		{0x1008, 0, 0, 1},
		{0x1fff, 0, 0, 2}, // no upper bound: past the function returns its last record
		{0x2000, 0, 0, 2}, // the search stays inside the function
		{0x1007, 0, 1, -1},
		{0x1008, 0, 1, 1},
		{0x1020, 0, 2, 2},
		{0x1020, 0, 3, -1}, // nr_skip equal to the function's record count
		{0x1fff, 1, 0, -1},
		{0x2000, 1, 0, 3},
		{0x2017, 1, 0, 4},
		{^uint64(0), 1, 0, 5},
		{0x2010, 1, 2, -1},
		{0x2018, 1, 2, 5},
		{0x1000, 2, 0, -1}, // func_idx past the last function
	}
	for _, tt := range tests {
		got, err := BpfProgLineInfoLfindAddrFunc(linfo, tt.addr, tt.funcIdx, tt.nrSkip)
		checkFound(t, fmt.Sprintf("lfind_addr_func(%#x, %d, %d)", tt.addr, tt.funcIdx, tt.nrSkip), got, err, twoFuncsLineInfo, tt.want)
	}
}

// TestBpfProgLineInfoJitedQuirks covers jited layouts the C library accepts:
// a last address exactly at the function length, a single function whose
// length is never checked, and a last function whose addresses decrease.
func TestBpfProgLineInfoJitedQuirks(t *testing.T) {
	exact := twoFuncsProgInfo()
	exact.JitedFuncLens = []uint32{0x21, 0x30}
	mustProgLineInfo(t, exact)

	single := mustProgLineInfo(t, newTestProgInfo(xlatedLineInfo, []uint64{0x5000, 0x5004, 0x5010, 0x5020}, []uint64{0x5000}, []uint32{0x8}))
	got, err := BpfProgLineInfoLfindAddrFunc(single, 0x5020, 0, 0)
	checkFound(t, "single function", got, err, xlatedLineInfo, 3)

	decreasing := twoFuncsProgInfo()
	decreasing.JitedLineInfo = packJitedLineInfo([]uint64{0x1000, 0x1008, 0x1020, 0x2000, 0x1ff0, 0x1fe0}, 8)
	linfo := mustProgLineInfo(t, decreasing)
	got, err = BpfProgLineInfoLfindAddrFunc(linfo, 0x2000, 1, 0)
	checkFound(t, "decreasing last function", got, err, twoFuncsLineInfo, 5)
}

func TestBpfProgLineInfoWithoutJited(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BpfProgInfo)
	}{
		{"no jited functions", func(info *BpfProgInfo) { info.NrJitedKsyms = 0 }},
		{"no jited line info", func(info *BpfProgInfo) { info.JitedLineInfo = nil }},
		{"jited count differs", func(info *BpfProgInfo) { info.NrJitedLineInfo = 5 }},
		{"jited record too small", func(info *BpfProgInfo) { info.JitedLineInfoRecSize = 4 }},
		{"length count differs", func(info *BpfProgInfo) { info.NrJitedFuncLens = 1 }},
		{"no jited symbols", func(info *BpfProgInfo) { info.JitedKsyms = nil }},
		{"no function lengths", func(info *BpfProgInfo) { info.JitedFuncLens = []uint32{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := twoFuncsProgInfo()
			tt.mutate(info)
			linfo := mustProgLineInfo(t, info)

			got, err := BpfProgLineInfoLfind(linfo, 5, 0)
			checkFound(t, "lfind", got, err, twoFuncsLineInfo, 2)
			got, err = BpfProgLineInfoLfindAddrFunc(linfo, 0x1000, 0, 0)
			checkFound(t, "lfind_addr_func", got, err, twoFuncsLineInfo, -1)
		})
	}
}

func TestBpfProgLineInfoRecordSize(t *testing.T) {
	tests := []struct {
		recSize uint32
		want    BpfLineInfo
	}{
		{24, xlatedLineInfo[2]},
		{16, xlatedLineInfo[2]},
		{12, BpfLineInfo{InsnOff: 7, FileNameOff: 1, LineOff: 30}},
		{8, BpfLineInfo{InsnOff: 7, FileNameOff: 1}},
		{4, BpfLineInfo{InsnOff: 7}},
	}
	for _, tt := range tests {
		info := &BpfProgInfo{
			NrLineInfo:      uint32(len(xlatedLineInfo)),
			LineInfoRecSize: tt.recSize,
			LineInfo:        packLineInfo(xlatedLineInfo, tt.recSize),
		}
		linfo := mustProgLineInfo(t, info)

		got, err := BpfProgLineInfoLfind(linfo, 9, 0)
		if err != nil || *got != tt.want {
			t.Errorf("record size %d: lfind(9) = %+v, %v; want %+v", tt.recSize, got, err, tt.want)
		}
	}
}

func TestBpfProgLineInfoCopiesInput(t *testing.T) {
	info := twoFuncsProgInfo()
	linfo := mustProgLineInfo(t, info)
	clear(info.LineInfo)
	clear(info.JitedLineInfo)

	got, err := BpfProgLineInfoLfind(linfo, 10, 0)
	checkFound(t, "lfind", got, err, twoFuncsLineInfo, 4)
	got, err = BpfProgLineInfoLfindAddrFunc(linfo, 0x2010, 1, 0)
	checkFound(t, "lfind_addr_func", got, err, twoFuncsLineInfo, 4)
}

func TestBpfProgLineInfoFree(t *testing.T) {
	BpfProgLineInfoFree(nil)

	linfo, err := BpfProgLineInfoNew(twoFuncsProgInfo())
	if err != nil {
		t.Fatalf("BpfProgLineInfoNew: %v", err)
	}
	BpfProgLineInfoFree(linfo)
	BpfProgLineInfoFree(linfo)

	if _, err := BpfProgLineInfoLfind(linfo, 0, 0); !errors.Is(err, unix.EINVAL) {
		t.Errorf("lfind after free = %v, want EINVAL", err)
	}
	if _, err := BpfProgLineInfoLfindAddrFunc(linfo, 0x1000, 0, 0); !errors.Is(err, unix.EINVAL) {
		t.Errorf("lfind_addr_func after free = %v, want EINVAL", err)
	}
	if _, err := BpfProgLineInfoLfind(nil, 0, 0); !errors.Is(err, unix.EINVAL) {
		t.Errorf("lfind(nil) = %v, want EINVAL", err)
	}
}

type linfoFixtureRecord struct {
	InsnOff     uint32 `json:"insn_off"`
	FileNameOff uint32 `json:"file_name_off"`
	LineOff     uint32 `json:"line_off"`
	LineCol     uint32 `json:"line_col"`
}

type linfoFixtureCase struct {
	Name                 string               `json:"name"`
	LineInfoRecSize      uint32               `json:"line_info_rec_size"`
	NrLineInfo           uint32               `json:"nr_line_info"`
	LineInfo             []linfoFixtureRecord `json:"line_info"`
	JitedLineInfoRecSize uint32               `json:"jited_line_info_rec_size"`
	NrJitedLineInfo      uint32               `json:"nr_jited_line_info"`
	JitedLineInfo        []uint64             `json:"jited_line_info"`
	NrJitedKsyms         uint32               `json:"nr_jited_ksyms"`
	JitedKsyms           []uint64             `json:"jited_ksyms"`
	NrJitedFuncLens      uint32               `json:"nr_jited_func_lens"`
	JitedFuncLens        []uint32             `json:"jited_func_lens"`
	NewErrno             int32                `json:"new_errno"`
	InsnOffs             []uint32             `json:"insn_offs"`
	Lfind                []struct {
		NrSkip  uint32  `json:"nr_skip"`
		Records []int32 `json:"records"`
	} `json:"lfind"`
	Addrs         []uint64 `json:"addrs"`
	LfindAddrFunc []struct {
		FuncIdx uint32  `json:"func_idx"`
		NrSkip  uint32  `json:"nr_skip"`
		Records []int32 `json:"records"`
	} `json:"lfind_addr_func"`
}

type linfoFixture struct {
	LibbpfVersion string             `json:"libbpf_version"`
	Cases         []linfoFixtureCase `json:"cases"`
}

func loadLinfoFixture(t *testing.T) linfoFixture {
	t.Helper()

	data, err := os.ReadFile("../testdata/oracle/linfo.json")
	if err != nil {
		t.Fatalf("read linfo fixture: %v", err)
	}
	var f linfoFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse linfo fixture: %v", err)
	}
	if f.LibbpfVersion == "" || len(f.Cases) == 0 {
		t.Fatal("linfo fixture is incomplete")
	}
	return f
}

func (c *linfoFixtureCase) records() []BpfLineInfo {
	recs := make([]BpfLineInfo, len(c.LineInfo))
	for i, r := range c.LineInfo {
		recs[i] = BpfLineInfo{InsnOff: r.InsnOff, FileNameOff: r.FileNameOff, LineOff: r.LineOff, LineCol: r.LineCol}
	}
	return recs
}

func (c *linfoFixtureCase) progInfo() *BpfProgInfo {
	return &BpfProgInfo{
		NrLineInfo:           c.NrLineInfo,
		LineInfoRecSize:      c.LineInfoRecSize,
		LineInfo:             packLineInfo(c.records(), c.LineInfoRecSize),
		NrJitedLineInfo:      c.NrJitedLineInfo,
		JitedLineInfoRecSize: c.JitedLineInfoRecSize,
		JitedLineInfo:        packJitedLineInfo(c.JitedLineInfo, c.JitedLineInfoRecSize),
		NrJitedKsyms:         c.NrJitedKsyms,
		JitedKsyms:           c.JitedKsyms,
		NrJitedFuncLens:      c.NrJitedFuncLens,
		JitedFuncLens:        c.JitedFuncLens,
	}
}

// expected returns the record the oracle found, with the fields past the
// record size cleared, or the errno the oracle reported as a negative value.
func (c *linfoFixtureCase) expected(result int32) (BpfLineInfo, syscall.Errno) {
	if result < 0 {
		return BpfLineInfo{}, syscall.Errno(-result)
	}
	want := c.records()[result]
	if c.LineInfoRecSize < bpfLineInfoOffLineCol+4 {
		want.LineCol = 0
	}
	if c.LineInfoRecSize < bpfLineInfoOffLineOff+4 {
		want.LineOff = 0
	}
	if c.LineInfoRecSize < bpfLineInfoOffFileNameOff+4 {
		want.FileNameOff = 0
	}
	return want, 0
}

func (c *linfoFixtureCase) check(t *testing.T, query string, got *BpfLineInfo, err error, result int32) {
	t.Helper()

	want, wantErrno := c.expected(result)
	if wantErrno != 0 {
		if !errors.Is(err, wantErrno) {
			t.Errorf("%s = %+v, %v; libbpf returned %v", query, got, err, wantErrno)
		}
		return
	}
	if err != nil || *got != want {
		t.Errorf("%s = %+v, %v; libbpf returned %+v", query, got, err, want)
	}
}

// TestBpfProgLineInfoOracle runs every synthetic program info of linfo.json
// through the Go port and compares the constructor result and every search
// with libbpf.
func TestBpfProgLineInfoOracle(t *testing.T) {
	f := loadLinfoFixture(t)

	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			linfo, err := BpfProgLineInfoNew(c.progInfo())
			if c.NewErrno != 0 {
				if !errors.Is(err, syscall.Errno(c.NewErrno)) {
					t.Fatalf("BpfProgLineInfoNew = %v, libbpf returned %v", err, syscall.Errno(c.NewErrno))
				}
				return
			}
			if err != nil {
				t.Fatalf("BpfProgLineInfoNew: %v", err)
			}
			defer BpfProgLineInfoFree(linfo)

			for _, row := range c.Lfind {
				for i, insnOff := range c.InsnOffs {
					got, err := BpfProgLineInfoLfind(linfo, insnOff, row.NrSkip)
					c.check(t, fmt.Sprintf("lfind(%d, %d)", insnOff, row.NrSkip), got, err, row.Records[i])
				}
			}
			for _, row := range c.LfindAddrFunc {
				for i, addr := range c.Addrs {
					got, err := BpfProgLineInfoLfindAddrFunc(linfo, addr, row.FuncIdx, row.NrSkip)
					c.check(t, fmt.Sprintf("lfind_addr_func(%#x, %d, %d)", addr, row.FuncIdx, row.NrSkip), got, err, row.Records[i])
				}
			}
		})
	}
}

// TestProgramLineInfo checks the line records the loader passes to
// BPF_PROG_LOAD: every .BTF.ext record of the program section, with the byte
// offset turned into an instruction index.
func TestProgramLineInfo(t *testing.T) {
	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer BpfObjectClose(obj)

	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("ParseExt: %v", err)
	}
	prog := BpfObjectFindProgramByName(obj, "handle_open")
	if prog == nil {
		t.Fatal("handle_open not found")
	}

	var want []btf.LineInfo
	for _, section := range ext.LineInfos {
		if section.Section == prog.sectionName {
			want = section.Records
		}
	}
	got := programLineInfo(ext, prog)
	if len(want) == 0 || len(got) != len(want)*btf.LineInfoMinSize {
		t.Fatalf("encoded %d bytes for %d .BTF.ext records", len(got), len(want))
	}

	insnCnt := uint32(len(prog.insns) / bpfInsnSize)
	for i, w := range want {
		rec := got[i*btf.LineInfoMinSize:]
		insnOff := binary.NativeEndian.Uint32(rec[bpfLineInfoOffInsnOff:])
		if insnOff != w.InsnOff/bpfInsnSize || insnOff >= insnCnt {
			t.Errorf("record %d insn_off = %d, want %d of %d instructions", i, insnOff, w.InsnOff/bpfInsnSize, insnCnt)
		}
		if binary.NativeEndian.Uint32(rec[bpfLineInfoOffFileNameOff:]) != w.FileNameOff ||
			binary.NativeEndian.Uint32(rec[bpfLineInfoOffLineOff:]) != w.LineOff ||
			binary.NativeEndian.Uint32(rec[bpfLineInfoOffLineCol:]) != w.LineCol {
			t.Errorf("record %d = %x, want %+v", i, rec[:btf.LineInfoMinSize], w)
		}
	}
	if first := binary.NativeEndian.Uint32(got); first != 0 {
		t.Errorf("first record insn_off = %d, want 0", first)
	}
}

func TestBpfProgramInfoInvalid(t *testing.T) {
	if _, err := BpfProgramInfo(nil); !errors.Is(err, unix.EINVAL) {
		t.Errorf("BpfProgramInfo(nil) = %v, want EINVAL", err)
	}

	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer BpfObjectClose(obj)
	if _, err := BpfProgramInfo(BpfObjectFindProgramByName(obj, "handle_open")); !errors.Is(err, unix.EINVAL) {
		t.Errorf("BpfProgramInfo(unloaded) = %v, want EINVAL", err)
	}
}

// TestBpfProgramInfoLineInfo loads the kprobe object, reads the program's
// line info back from the kernel and finds the record of instruction 0. It
// needs root and skips without it.
func TestBpfProgramInfoLineInfo(t *testing.T) {
	obj := loadTestObject(t, "../testdata/progs/kprobe.bpf.o")
	defer BpfObjectClose(obj)

	info, err := BpfProgramInfo(BpfObjectFindProgramByName(obj, "handle_open"))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfProgramInfo: %v", err)
	}
	if info.Name != "handle_open" || info.NrLineInfo == 0 {
		t.Fatalf("program %q has %d line records, want handle_open with line info", info.Name, info.NrLineInfo)
	}
	if info.LineInfoRecSize != bpfLineInfoOffLineCol+4 || len(info.LineInfo) != int(info.NrLineInfo*info.LineInfoRecSize) {
		t.Fatalf("line info = %d records of %d bytes in %d bytes", info.NrLineInfo, info.LineInfoRecSize, len(info.LineInfo))
	}

	linfo := mustProgLineInfo(t, info)
	first, err := BpfProgLineInfoLfind(linfo, 0, 0)
	if err != nil {
		t.Fatalf("lfind(0, 0): %v", err)
	}
	want := BpfLineInfo{
		InsnOff:     binary.NativeEndian.Uint32(info.LineInfo[bpfLineInfoOffInsnOff:]),
		FileNameOff: binary.NativeEndian.Uint32(info.LineInfo[bpfLineInfoOffFileNameOff:]),
		LineOff:     binary.NativeEndian.Uint32(info.LineInfo[bpfLineInfoOffLineOff:]),
		LineCol:     binary.NativeEndian.Uint32(info.LineInfo[bpfLineInfoOffLineCol:]),
	}
	if first.InsnOff != 0 || *first != want {
		t.Fatalf("lfind(0, 0) = %+v, want the first record %+v at insn_off 0", *first, want)
	}
	if file, err := obj.btf.String(first.FileNameOff); err != nil || !strings.HasSuffix(file, "kprobe.bpf.c") {
		t.Errorf("first record file = %q, %v; want kprobe.bpf.c", file, err)
	}

	if info.JitedKsyms == nil || info.NrJitedLineInfo != info.NrLineInfo {
		t.Logf("no jited line info: %d jited records, jited symbols withheld = %v", info.NrJitedLineInfo, info.JitedKsyms == nil)
		return
	}
	got, err := BpfProgLineInfoLfindAddrFunc(linfo, info.JitedKsyms[0], 0, 0)
	if err != nil || *got != want {
		t.Errorf("lfind_addr_func(%#x, 0, 0) = %+v, %v; want the first record", info.JitedKsyms[0], got, err)
	}
}
