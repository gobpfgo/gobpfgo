# Benchmarks

A benchmark suite that times the Go port against C libbpf on the same host and kernel. It covers the operations where the port could cost something. `bench.c` is the C half. It is one binary linked against the pinned libbpf, the way `oracle/Makefile` links the oracle. `libbpf/bench_test.go` is the Go half. Both halves use the same fixtures, the same map and program names, the same warmup rule and the same iteration counts. Nothing here is part of the default build or of `go test ./...`, which never runs benchmarks.

## Requirements

- Linux on x86-64 or arm64, with kernel BTF at `/sys/kernel/btf/vmlinux`. The attach benchmark also needs the kprobe PMU and BPF perf links (5.15 or newer).
- Root for `load`, `map` and `attach`. Without it they print a skip line with the errno on both sides. `open`, `btf`, `linker` and `dump` need no privileges.
- A C compiler, `make`, `pkg-config` and the libelf and zlib development files, as for the oracle.
- A libbpf source checkout at the commit the port pins, `4f05fb0`. The default `LIBBPF=../libbpf` is the Go package when make runs in `bench/`, the same as for the oracle, so always pass the checkout. The build stops with a message if `LIBBPF` is not a libbpf tree.
- The Go toolchain from `go.mod`. The Go half runs with `GOMAXPROCS=1`; `GOGC` defaults to 100 and can be set to `off` for a GC control run.
- `taskset` from util-linux.

## Run

Build the C binary, then run one C run and one Go run, three times, alternating:

```sh
make -C bench LIBBPF=/path/to/libbpf
make -C bench run-all LIBBPF=/path/to/libbpf CPU=2 RUNS=3
```

`run-all` prints the kernel, CPU, governor, compiler, Go and libbpf versions first. It then alternates the two halves so that drift in CPU frequency or host load reaches both alike. `make -C bench run` runs only the C half and `make -C bench run-go` only the Go half, each `RUNS` times. Every benchmark runs in its own process, as root through `SUDO` (default `sudo -n`), pinned to `CPU` with `taskset`. The Go half also runs with `GOMAXPROCS=1` and `GOGC` (default 100; set `GOGC=off` for a control run). `SUDO=` runs unprivileged.

By hand, for the C half from `bench/`:

```sh
sudo taskset -c 2 ./bench open     # or load, map, btf, linker, attach, dump, all
```

For the Go half, build the test binary as your user, so that root never writes to your Go cache. Then run it from `libbpf/`, where the fixture paths resolve. Run each benchmark with the iteration count from the table below:

```sh
go test -c -o bench/build/libbpf.test ./libbpf
cd libbpf
sudo env GOMAXPROCS=1 taskset -c 2 ../bench/build/libbpf.test \
	-test.run '^$' -test.v -test.bench '^BenchmarkObjectOpen$' \
	-test.benchtime 2000x -test.benchmem
```

Compare the two halves only when they run on the same host and kernel, as root for `load`, `map` and `attach`, with `GOMAXPROCS=1` and on the same CPU through `taskset`. Results from different machines, kernels or CPU governors are not comparable. The governor stays as the host has it. `run-all` alternates the halves for that reason. For tighter numbers, set the `performance` governor and use a CPU without load on it or its SMT sibling.

## Benchmarks

| C line | Go benchmark | Iterations | Operation |
| --- | --- | --- | --- |
| `open` | `BenchmarkObjectOpen` | 2000 | `bpf_object__open_file` and `bpf_object__close` of `testdata/progs/kprobe.bpf.o` |
| `load` | `BenchmarkObjectLoad` | 200 | open, `bpf_object__load` and close of `kprobe.bpf.o` (root) |
| `map-lookup` | `BenchmarkMapLookupElem` | 200000 | `bpf_map__lookup_elem` of key 0 in the `counts` array of the loaded `kprobe.bpf.o` (root) |
| `map-update` | `BenchmarkMapUpdateElem` | 200000 | `bpf_map__update_elem` of key 0 to 1 with `BPF_ANY` (root) |
| `btf-parse` | `BenchmarkBtfParse` | 20 | `btf__parse` and `btf__free` of `/sys/kernel/btf/vmlinux` |
| `btf-dedup` | `BenchmarkBtfDedup` | 3 | `btf__dedup` of the parsed vmlinux BTF; Go calls `Spec.Dedup`, the core of `btf__dedup` |
| `linker` | `BenchmarkLinker` | 200 | `bpf_linker__new`, `add_file` of `link_a.bpf.o` and `link_b.bpf.o`, `finalize`, `free`, then unlink of the temporary output |
| `attach` | `BenchmarkKprobeAttach` | 200 | `bpf_program__attach_kprobe` of `handle_open` to `do_sys_openat2` in the default mode and `bpf_link__destroy` (root) |
| `btf-dump` | `BenchmarkBtfDump` | 200 | `btf_dump__new`, `btf_dump__dump_type` of `task_struct` from vmlinux, `btf_dump__free` |

The C binary prints `<name> ns/op <mean>` on stdout, or `<name> skip errno <n> (<text>)`. It prints details on stderr: the type count after dedup and the size of the dump. The Go benchmarks report the same values as the `types` and `dump-bytes` metrics, so a reader can check that both sides did the same work.

Each operation first runs a tenth of its iteration count, at least one, untimed. Then it runs the full count timed. The C half times with `clock_gettime(CLOCK_MONOTONIC)`. The Go half calls `b.ResetTimer` after the warmup and takes its count from `-test.benchtime <n>x`. The Go benchmarks call `b.ReportAllocs`, and `b.SetBytes` where a size means something: the object, BTF or input size, or the map value size.

Some operations time only part of the work:

- `btf-dedup` parses the BTF untimed in every iteration and times only the dedup. The Go side stops the timer around `BtfParse`, so its allocation figures are the dedup's alone.
- `attach` loads the object once, outside the loop. The kernel's kprobe teardown dominates this operation.
- `btf-dump` creates a new dumper per iteration. The printf callback formats into a reused, growing buffer on both sides: `vsnprintf` in C and `fmt.Appendf` in Go. If the BTF has no `task_struct`, both sides dump every type.

## Other BTF

`BTF=<path>` replaces vmlinux in the `btf` and `dump` benchmarks on both sides. Use it when vmlinux cannot be used, for example on a kernel whose BTF has a kind layout section, which `Spec.Dedup` rejects with `EOPNOTSUPP`. The small fallback is the raw `.BTF` section of `kprobe.bpf.o`, which `make build/kprobe.btf` extracts with `llvm-objcopy`:

```sh
make -C bench build/kprobe.btf
make -C bench run-all LIBBPF=/path/to/libbpf BTF=build/kprobe.btf
```

The Makefile passes the path to both halves as `GOBPFGO_BENCH_BTF`. The Go benchmarks read that variable, and `bench btf` and `bench dump` read it when they get no path argument. `kprobe.bpf.o` has no `task_struct`, so `dump` emits every type.
