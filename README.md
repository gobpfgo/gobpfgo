# gobpfgo

<!-- anchors-ok: BSD-2 LGPL-2 | SPDX identifiers, not citations -->

Repository: [gobpfgo/gobpfgo](https://github.com/gobpfgo/gobpfgo).

A pure-Go port of libbpf, close to 1:1 in behavior and API shape, with no cgo and no unsafe.

Status: phase 5. The phase 1 object, map and program path and the attach surface are tested on 5.10 and 6.18: kprobe, kretprobe, tracepoint, uprobe, uretprobe, fentry, fexit, fmod_ret, tp_btf, LSM, raw tracepoint, kprobe multi and perf event links, plus link pin/open and automatic attach. Phase 2 is done: CO-RE covers access specs, field, flexible array, type and enum relocations, vmlinux and split module BTFs, and no-target poison; the BTF type dump and declarators match libbpf's exact text. Phase 3 is complete: the static linker with BTF dedup, USDT, uprobe multi, the ring and perf buffers with libbpf's callback API, the feature/probe matrix, global data, `.kconfig` and `.ksyms` externs, per-CPU data and BTF sanitization. Phase 5 has started with the `bpf` object layer: `Object`, `Program`, `Map` and `Link` wrappers over the core with explicit lifetimes. Skeleton generation is deferred.

## Non-goals

- C ABI or C consumers.
- cgo at any point.
- The `unsafe` package.
- BPF program authoring. BPF programs stay in C and are compiled by clang; gobpfgo loads, relocates and attaches them.
- Windows and non-Linux kernels.

## Layout

```
libbpf/          core package, 1:1 with libbpf
bpf/             thin object layer, built last
internal/sys/    UAPI layouts, bpf(), perf_event_open
internal/elf/    ELF reader
internal/mmap/   mmap and ring memory
cmd/bpfgen/      Go skeleton generator (deferred)
oracle/          C harness for parity tests, never part of go build
```

## Build

```
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
```

## License

LGPL-2.1-only. Derived from libbpf, dual-licensed BSD-2-Clause OR LGPL-2.1; this project elects LGPL-2.1-only. See [NOTICE](NOTICE) and [LICENSE](LICENSE).
