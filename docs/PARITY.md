# Parity matrix

<!-- anchors-ok: cmd/bpfgen internal/elf internal/sys | package paths, not citations -->

Status values: not started, in progress, parity tested, deferred.

The port tracks libbpf at commit [`4f05fb0`](https://github.com/libbpf/libbpf/commit/4f05fb027a08a8a66d03916cf6a68a91e2c720ea), with `1.9.0` in development.

| Module | libbpf source | Go files | Phase | Status |
|---|---|---|---|---|
| Syscalls and UAPI | `bpf.c`, `libbpf_probes.c` | `internal/sys`, `bpf.go` | 0 | not started |
| ELF reader | `elf.c` | `internal/elf` | 0 | not started |
| Object lifecycle | `libbpf.c` | `object.go`, `secdefs.go`, `skeleton.go` | 1 | not started |
| Maps | `libbpf.c` | `map.go` | 1 | not started |
| Programs | `libbpf.c` | `program.go` | 1 | not started |
| Links and attach | `libbpf.c`, `netlink.c` | `link.go`, `netlink.go` | 1 | not started |
| Pinning and reuse | `libbpf.c` | `pin.go` | 1 | not started |
| BTF | `btf.c` | `btf.go` | 2 | not started |
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
| Object and map metadata after open | C harness JSON | not started |
| Syscall transcript after load | `LD_PRELOAD` interposer or strace parser | not started |
| CO-RE fixups | libbpf internal harness | not started |
| `btf_dump` text | exact text diff | not started |
| Old kernels | VM matrix | not started |

The C oracle lives in `oracle/`, is built out of tree, and is never part of `go build`.
