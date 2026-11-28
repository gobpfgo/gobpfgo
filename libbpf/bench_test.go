// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// The benchmarks in this file are the Go half of the suite in bench/:
// bench/bench.c times the same operations with C libbpf, on the same
// fixtures, map and program names, with the same warmup rule. Each benchmark
// runs benchWarmup(b.N) untimed iterations before it resets the timer, as
// bench.c does. The iteration counts come from -test.benchtime, which
// bench/Makefile sets to the counts bench.c uses; see bench/README.md. The
// benchmarks that need bpf() skip with its errno when the kernel refuses it.

const (
	benchKprobeObject = "../testdata/progs/kprobe.bpf.o"
	benchLinkAObject  = "../testdata/progs/link_a.bpf.o"
	benchLinkBObject  = "../testdata/progs/link_b.bpf.o"

	benchMapName    = "counts"
	benchProgName   = "handle_open"
	benchKprobeFunc = "do_sys_openat2"
	benchDumpType   = "task_struct"
)

// benchBTFPath is the BTF that the BTF benchmarks parse, dedup and dump:
// GOBPFGO_BENCH_BTF when set, as `bench btf <path>` takes it, and the kernel
// BTF otherwise.
func benchBTFPath() string {
	if path := os.Getenv("GOBPFGO_BENCH_BTF"); path != "" {
		return path
	}
	return "/sys/kernel/btf/vmlinux"
}

// benchWarmup is the number of untimed iterations before n timed ones: a
// tenth, at least one, the rule of bench.c's warmup_iters.
func benchWarmup(n int) int {
	return max(n/10, 1)
}

// benchFatal fails b with err. When root is set and the kernel refused bpf()
// with EPERM or EACCES, it skips b with the errno instead, as bench.c prints
// it.
func benchFatal(b *testing.B, root bool, err error) {
	b.Helper()

	var errno unix.Errno
	if root && errors.As(err, &errno) && (errno == unix.EPERM || errno == unix.EACCES) {
		b.Skipf("bpf() not permitted: errno %d (%s): %v", int(errno), unix.ErrnoName(errno), err)
	}
	b.Fatal(err)
}

// benchRun runs op benchWarmup(b.N) times, resets the timer and runs it b.N
// times, reporting allocations. root marks an op that needs bpf().
func benchRun(b *testing.B, root bool, op func() error) {
	b.Helper()

	for range benchWarmup(b.N) {
		if err := op(); err != nil {
			benchFatal(b, root, err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := op(); err != nil {
			benchFatal(b, root, err)
		}
	}
}

// benchFileSize returns the summed sizes of paths, for b.SetBytes.
func benchFileSize(b *testing.B, paths ...string) int64 {
	b.Helper()

	var size int64
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			b.Fatal(err)
		}
		size += info.Size()
	}
	return size
}

// benchLoad opens and loads path for the rest of b, skipping b when bpf() is
// not permitted.
func benchLoad(b *testing.B, path string) *BpfObject {
	b.Helper()

	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		b.Fatal(err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		benchFatal(b, true, err)
	}
	b.Cleanup(func() { BpfObjectClose(obj) })
	return obj
}

// BenchmarkObjectOpen opens and closes kprobe.bpf.o, as `bench open` does.
func BenchmarkObjectOpen(b *testing.B) {
	b.SetBytes(benchFileSize(b, benchKprobeObject))
	benchRun(b, false, func() error {
		obj, err := BpfObjectOpenFile(benchKprobeObject, nil)
		if err != nil {
			return err
		}
		BpfObjectClose(obj)
		return nil
	})
}

// BenchmarkObjectLoad opens, loads and closes kprobe.bpf.o, as `bench load`
// does. It needs bpf().
func BenchmarkObjectLoad(b *testing.B) {
	benchRun(b, true, func() error {
		obj, err := BpfObjectOpenFile(benchKprobeObject, nil)
		if err != nil {
			return err
		}
		err = BpfObjectLoad(obj)
		BpfObjectClose(obj)
		return err
	})
}

// benchCountsMap loads kprobe.bpf.o and returns its counts map with the key
// 0 and a value buffer holding 1.
func benchCountsMap(b *testing.B) (*BpfMap, []byte, []byte) {
	b.Helper()

	obj := benchLoad(b, benchKprobeObject)
	m := BpfObjectFindMapByName(obj, benchMapName)
	if m == nil {
		b.Fatalf("map %s not found in %s", benchMapName, benchKprobeObject)
	}
	key := make([]byte, 4)
	value := make([]byte, 8)
	binary.NativeEndian.PutUint64(value, 1)
	return m, key, value
}

// BenchmarkMapLookupElem looks up key 0 of kprobe.bpf.o's counts array, as
// the map-lookup line of `bench map` does. It needs bpf().
func BenchmarkMapLookupElem(b *testing.B) {
	m, key, value := benchCountsMap(b)
	b.SetBytes(int64(len(value)))
	benchRun(b, true, func() error {
		return BpfMapLookupElem(m, key, value, 0)
	})
}

// BenchmarkMapUpdateElem writes 1 to key 0 of kprobe.bpf.o's counts array, as
// the map-update line of `bench map` does. It needs bpf().
func BenchmarkMapUpdateElem(b *testing.B) {
	m, key, value := benchCountsMap(b)
	b.SetBytes(int64(len(value)))
	benchRun(b, true, func() error {
		return BpfMapUpdateElem(m, key, value, BPF_ANY)
	})
}

// BenchmarkBtfParse parses and frees benchBTFPath, as the btf-parse line of
// `bench btf` does.
func BenchmarkBtfParse(b *testing.B) {
	path := benchBTFPath()
	b.SetBytes(benchFileSize(b, path))
	benchRun(b, false, func() error {
		table, err := BtfParse(path)
		if err != nil {
			return err
		}
		BtfFree(table)
		return nil
	})
}

// BenchmarkBtfDedup dedups benchBTFPath, as the btf-dedup line of `bench btf`
// does: every iteration parses the BTF with the timer stopped and times only
// Spec.Dedup, the core of btf__dedup. It reports the type count after dedup,
// which bench.c prints on stderr.
func BenchmarkBtfDedup(b *testing.B) {
	path := benchBTFPath()
	b.SetBytes(benchFileSize(b, path))

	var types int
	dedup := func() {
		table, err := BtfParse(path)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		_, err = table.spec.Dedup(nil)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		types = BtfTypeCnt(table)
		BtfFree(table)
	}

	b.StopTimer()
	for range benchWarmup(b.N) {
		dedup()
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		dedup()
	}
	b.ReportMetric(float64(types), "types")
}

// BenchmarkLinker links link_a.bpf.o and link_b.bpf.o into a temporary file
// and removes it, as `bench linker` does.
func BenchmarkLinker(b *testing.B) {
	out := filepath.Join(b.TempDir(), "linked.bpf.o")
	b.SetBytes(benchFileSize(b, benchLinkAObject, benchLinkBObject))
	benchRun(b, false, func() error {
		l, err := BpfLinkerNew(out, nil)
		if err != nil {
			return err
		}
		for _, input := range []string{benchLinkAObject, benchLinkBObject} {
			if err == nil {
				err = BpfLinkerAddFile(l, input, nil)
			}
		}
		if err == nil {
			err = BpfLinkerFinalize(l)
		}
		BpfLinkerFree(l)
		if uerr := unix.Unlink(out); uerr != nil && err == nil {
			err = uerr
		}
		return err
	})
}

// BenchmarkKprobeAttach attaches kprobe.bpf.o's handle_open to
// do_sys_openat2 in the default mode and destroys the link, as `bench attach`
// does. The object is loaded once, outside the loop. It needs bpf().
func BenchmarkKprobeAttach(b *testing.B) {
	obj := benchLoad(b, benchKprobeObject)
	prog := BpfObjectFindProgramByName(obj, benchProgName)
	if prog == nil {
		b.Fatalf("program %s not found in %s", benchProgName, benchKprobeObject)
	}
	benchRun(b, true, func() error {
		link, err := BpfProgramAttachKprobe(prog, false, benchKprobeFunc)
		if err != nil {
			return err
		}
		BpfLinkDestroy(link)
		return nil
	})
}

// BenchmarkBtfDump dumps task_struct and the types it depends on from
// benchBTFPath with a new dumper per iteration, or every type when the BTF
// has no task_struct, as `bench dump` does. The printf callback formats into
// a reused buffer, as bench.c's does. It reports the dump size, which bench.c
// prints on stderr.
func BenchmarkBtfDump(b *testing.B) {
	table, err := BtfParse(benchBTFPath())
	if err != nil {
		b.Fatal(err)
	}
	var id uint32
	if t := table.spec.Find(benchDumpType, btf.KindStruct); t != nil {
		id = t.ID
	}

	var out []byte
	printf := func(format string, args ...any) {
		out = fmt.Appendf(out, format, args...)
	}
	benchRun(b, false, func() error {
		out = out[:0]
		d, err := BtfDumpNew(table, printf, nil)
		if err != nil {
			return err
		}
		if id != 0 {
			err = BtfDumpDumpType(d, id)
		} else {
			for i := 1; i < BtfTypeCnt(table) && err == nil; i++ {
				err = BtfDumpDumpType(d, uint32(i))
			}
		}
		BtfDumpFree(d)
		return err
	})
	b.ReportMetric(float64(len(out)), "dump-bytes")
}
