# Parity matrix

<!-- anchors-ok: cmd/bpfgen internal/elf internal/sys internal/btf | package paths, not citations -->

Status values: not started, in progress, parity tested, deferred.

The port tracks libbpf at commit [`4f05fb0`](https://github.com/libbpf/libbpf/commit/4f05fb027a08a8a66d03916cf6a68a91e2c720ea), with `1.9.0` in development.

| Module | libbpf source | Go files | Phase | Status |
|---|---|---|---|---|
| Syscalls and UAPI | `bpf.c`, `libbpf_probes.c` | `internal/sys`, `bpf.go` | 0 | in progress |
| ELF reader | `elf.c` | `internal/elf` | 0 | in progress |
| Object lifecycle | `libbpf.c` | `object.go`, `secdefs.go`, `skeleton.go` | 1 | in progress (open, load) |
| Maps | `libbpf.c` | `map.go`, `bpf_map.go` | 1 | in progress (create, open, load, lookup) |
| Programs | `libbpf.c` | `program.go` | 1 | in progress (open, load) |
| Links and attach | `libbpf.c`, `netlink.c` | `link.go`, `netlink.go` | 1 | in progress (kprobe through tracefs; kprobe multi and perf links not ported) |
| Pinning and reuse | `libbpf.c` | `pin.go` | 1 | not started |
| BTF | `btf.c` | `internal/btf` | 2 | in progress (parser) |
| CO-RE | `relo_core.c`, `btf_relocate.c` | `relo_core.go`, `btf_reloc.go` | 2 | not started |
| BTF to C | `btf_dump.c` | `btf_dump.go` | 2 | not started |
| Linker | `linker.c` | `linker.go` | 3 | not started |
| USDT | `usdt.c` | `usdt.go` | 3 | not started |
| Ring buffer | `ringbuf.c` | `ringbuf.go` | 3 | not started |
| Features and probes | `features.c`, `libbpf_probes.c` | `features.go`, `probes.go` | 3 | not started |
| Zip objects | `zip.c` | `zip.go` | 3 | not started |
| Program line info | `bpf_prog_linfo.c` | `line_info.go` | 3 | not started |
| Light skeleton | `gen_loader.c` | `gen_loader.go` | 4 | deferred |
| Object layer | not applicable | `bpf/` | 5 | not started |
| Skeleton generator | not applicable | `cmd/bpfgen` | 5 | not started |

## Parity tests

The oracle tiers, scenarios and update rules live in [TESTING.md](TESTING.md).

| Area | Oracle | Status |
|---|---|---|
| Object and map metadata after open | C harness JSON | parity tested (kprobe object) |
| `BPF_MAP_CREATE` layout and attribute bytes | C harness JSON | parity tested |
| BTF load layout and DATASEC fixup | C harness JSON + root load | parity tested |
| Object load (BTF, maps, programs) | root load test | parity tested (kprobe object, 6.18) |
| ELF sections, symbols and relocations | checked-in `kprobe.bpf.o` | structural test |
| Loaded map and program metadata | C harness JSON (root) | parity tested (root info comparison) |
| kprobe attach and program output | C harness JSON (root) + root test | parity tested (kprobe object, 6.18) |
| Syscall transcript after load | `LD_PRELOAD` interposer or strace parser | not started |
| CO-RE fixups | libbpf internal harness | not started |
| `btf_dump` text | exact text diff | not started |
| 5.10 and newer | VM matrix | not started |

The C oracle lives in `oracle/`, is built out of tree, and is never part of `go build`.
