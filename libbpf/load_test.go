// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
)

// progLoadOffKernVersion is offsetof(union bpf_attr, kern_version) in the
// BPF_PROG_LOAD attributes.
const progLoadOffKernVersion = 40

// TestProgLoadAttr builds the BPF_PROG_LOAD attributes of a synthetic main
// program and checks every field the loader sets, kern_version included,
// in the struct and in the bytes the syscall gets. A program without
// function or line records sends both record sizes as zero.
func TestProgLoadAttr(t *testing.T) {
	const kernVersion = 6<<16 | 18<<8 | 63
	obj := &BpfObject{btfFD: 7, kernVersion: kernVersion}
	p := &BpfProgram{
		name:               "a_long_program_name",
		progType:           BPF_PROG_TYPE_TRACING,
		expectedAttachType: BPF_TRACE_FENTRY,
		progFlags:          BPF_F_SLEEPABLE,
		attachBTFID:        1234,
		attachBTFObjFD:     9,
	}
	code := &progCode{
		prog:     p,
		insns:    make([]byte, 5*bpfInsnLength),
		funcInfo: make([]byte, 2*btf.FuncInfoMinSize),
		lineInfo: make([]byte, 3*btf.LineInfoMinSize),
	}

	attr := progLoadAttr(obj, code)
	want := &sys.ProgLoadAttr{
		ProgType:           uint32(BPF_PROG_TYPE_TRACING),
		InsnCnt:            5,
		LogLevel:           1,
		KernVersion:        kernVersion,
		ProgFlags:          BPF_F_SLEEPABLE,
		ExpectedAttachType: uint32(BPF_TRACE_FENTRY),
		ProgBtfFD:          7,
		FuncInfoRecSize:    btf.FuncInfoMinSize,
		FuncInfoCnt:        2,
		LineInfoRecSize:    btf.LineInfoMinSize,
		LineInfoCnt:        3,
		AttachBtfID:        1234,
		AttachBtfObjFD:     9,
	}
	want.SetProgName("a_long_program_name")
	if *attr != *want {
		t.Errorf("attr = %+v\nwant %+v", *attr, *want)
	}
	if got := binary.NativeEndian.Uint32(attr.Marshal()[progLoadOffKernVersion:]); got != kernVersion {
		t.Errorf("marshaled kern_version = %#x, want %#x", got, kernVersion)
	}

	code.funcInfo, code.lineInfo = nil, nil
	attr = progLoadAttr(obj, code)
	if attr.FuncInfoRecSize != 0 || attr.FuncInfoCnt != 0 || attr.LineInfoRecSize != 0 || attr.LineInfoCnt != 0 {
		t.Errorf("attr without records = %+v, want zero record sizes and counts", *attr)
	}
}

// TestObjectKernVersion checks the kern_version an object loads with. An
// opened object without a "version" section takes the running kernel's
// KERNEL_VERSION code; a 4-byte "version" section replaces it, the last one
// winning, and any other size fails the open with LIBBPF_ERRNO__FORMAT. A
// ".version" section is not libbpf's and changes nothing.
func TestObjectKernVersion(t *testing.T) {
	obj := openProg(t, "kprobe.bpf.o")
	if want := getKernelVersion(); obj.kernVersion != want || want == 0 {
		t.Errorf("kprobe.bpf.o kern_version = %#x, want the running kernel's %#x", obj.kernVersion, want)
	}
	code := &progCode{prog: obj.programs[0], insns: obj.programs[0].insns}
	if got := progLoadAttr(obj, code).KernVersion; got != obj.kernVersion {
		t.Errorf("BPF_PROG_LOAD kern_version = %#x, want %#x", got, obj.kernVersion)
	}

	const running = 0x061200
	version := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
	for _, tc := range []struct {
		name     string
		sections []elf.Section
		want     uint32
		errno    error
	}{
		{"none", []elf.Section{{Name: ".text"}, {Name: "license", Data: []byte("GPL\x00")}}, running, nil},
		{"version", []elf.Section{{Name: "version", Data: version(0x040e00)}}, 0x040e00, nil},
		{"last wins", []elf.Section{{Name: "version", Data: version(1)}, {Name: "version", Data: version(2)}}, 2, nil},
		{"dot version", []elf.Section{{Name: ".version", Data: version(0x040e00)}}, running, nil},
		{"short", []elf.Section{{Name: "version", Data: []byte{1, 2}}}, 0, libbpfErrnoFormat},
		{"long", []elf.Section{{Name: "version", Data: make([]byte, 8)}}, 0, libbpfErrnoFormat},
		{"no data", []elf.Section{{Name: "version", Size: 4}}, 0, libbpfErrnoFormat},
	} {
		got, err := objectKernVersion(&elf.Object{Sections: tc.sections}, running)
		if tc.errno != nil {
			if !errors.Is(err, tc.errno) {
				t.Errorf("%s: err = %v, want %v", tc.name, err, tc.errno)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: kern_version = %#x, %v; want %#x", tc.name, got, err, tc.want)
		}
	}
}
