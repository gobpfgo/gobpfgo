// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
)

func TestBtfDump(t *testing.T) {
	table, err := BtfParse("../testdata/progs/dump.bpf.o")
	if err != nil {
		t.Fatalf("BtfParse: %v", err)
	}
	defer BtfFree(table)

	wantBytes, err := os.ReadFile("../testdata/oracle/dump.txt")
	if err != nil {
		t.Fatalf("read dump fixture: %v", err)
	}
	if got, want := dumpAllTypes(t, table), string(wantBytes); got != want {
		reportFirstDiff(t, "dump", want, got)
	}
}

func TestBtfNewDump(t *testing.T) {
	obj, err := elf.Open("../testdata/progs/dump.bpf.o")
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	table, err := BtfNew(obj.BTF)
	if err != nil {
		t.Fatalf("BtfNew: %v", err)
	}
	defer BtfFree(table)

	wantBytes, err := os.ReadFile("../testdata/oracle/dump.txt")
	if err != nil {
		t.Fatalf("read dump fixture: %v", err)
	}
	if got, want := dumpAllTypes(t, table), string(wantBytes); got != want {
		reportFirstDiff(t, "raw BTF dump", want, got)
	}
}

func dumpAllTypes(t *testing.T, table *Btf) string {
	t.Helper()

	var out strings.Builder
	dump, err := BtfDumpNew(table, func(format string, args ...any) {
		fmt.Fprintf(&out, format, args...)
	}, nil)
	if err != nil {
		t.Fatalf("BtfDumpNew: %v", err)
	}
	defer BtfDumpFree(dump)

	for id := uint32(1); id < uint32(BtfTypeCnt(table)); id++ {
		if err := BtfDumpDumpType(dump, id); err != nil {
			t.Fatalf("BtfDumpDumpType(%d): %v", id, err)
		}
	}
	return out.String()
}

func TestBtfDumpEmitTypeDecl(t *testing.T) {
	checkBtfDumpDecl(t, "../testdata/oracle/dump-decl.txt", false)
}

func TestBtfDumpEmitTypeDeclStripMods(t *testing.T) {
	checkBtfDumpDecl(t, "../testdata/oracle/dump-decl-strip.txt", true)
}

func checkBtfDumpDecl(t *testing.T, fixture string, stripMods bool) {
	t.Helper()

	table, err := BtfParse("../testdata/progs/dump.bpf.o")
	if err != nil {
		t.Fatalf("BtfParse: %v", err)
	}
	defer BtfFree(table)

	var out strings.Builder
	dump, err := BtfDumpNew(table, func(format string, args ...any) {
		fmt.Fprintf(&out, format, args...)
	}, nil)
	if err != nil {
		t.Fatalf("BtfDumpNew: %v", err)
	}
	defer BtfDumpFree(dump)

	opts := &BtfDumpEmitTypeDeclOpts{FieldName: "field", StripMods: stripMods}
	for id := uint32(1); id < uint32(BtfTypeCnt(table)); id++ {
		switch table.spec.Types[id].Kind {
		case btf.KindVar, btf.KindDatasec, btf.KindFunc, btf.KindDeclTag:
			continue
		}
		if err := BtfDumpEmitTypeDecl(dump, id, opts); err != nil {
			t.Fatalf("BtfDumpEmitTypeDecl(%d): %v", id, err)
		}
		out.WriteString(";\n")
	}

	wantBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatalf("read decl fixture: %v", err)
	}
	if got, want := out.String(), string(wantBytes); got != want {
		reportFirstDiff(t, "declaration", want, got)
	}
}

func reportFirstDiff(t *testing.T, what, want, got string) {
	t.Helper()

	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var wantLine, gotLine string
		if i < len(wantLines) {
			wantLine = wantLines[i]
		}
		if i < len(gotLines) {
			gotLine = gotLines[i]
		}
		if wantLine != gotLine {
			t.Fatalf("%s differs at line %d:\nwant: %q\ngot:  %q", what, i+1, wantLine, gotLine)
		}
	}
	t.Fatalf("%s differs", what)
}
