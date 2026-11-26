# Parity matrix

<!-- anchors-ok: cmd/bpfgen internal/elf internal/sys internal/btf | package paths, not citations -->

Status values: not started, in progress, parity tested, deferred.

The port tracks libbpf at commit [`4f05fb0`](https://github.com/libbpf/libbpf/commit/4f05fb027a08a8a66d03916cf6a68a91e2c720ea), with `1.9.0` in development.

| Module | libbpf source | Go files | Phase | Status |
|---|---|---|---|---|
| Syscalls and UAPI | `bpf.c`, `libbpf_probes.c` | `internal/sys`, `bpf.go` | 0 | in progress |
| ELF reader | `elf.c` | `internal/elf` | 0 | in progress |
| Object lifecycle | `libbpf.c` | `object.go`, `sec.go`, `skeleton.go` | 1 | in progress (open, load) |
| Maps | `libbpf.c` | `map.go`, `bpf_map.go` | 1 | in progress (create, open, load, lookup) |
| Programs | `libbpf.c` | `program.go` | 1 | in progress (open, load) |
| Links and attach | `libbpf.c`, `netlink.c` | `link.go`, `attach.go`, `perf.go`, `elf_func.go`, `attach_btf.go` | 1 | parity tested (kprobe, kretprobe, tracepoint, uprobe, uretprobe, fentry, fexit, LSM, raw tracepoint, kprobe multi, perf event and auto attach); fmod_ret and tp_btf use the same tracing path and are ported but not fixture-tested; cgroup, netns, XDP, iter, freplace, sockmap, uprobe multi, kprobe session and USDT not started |
| Pinning and reuse | `libbpf.c` | `pin.go`, `reuse.go`, `link.go` | 1 | parity tested (map, program, object and link pin/unpin; map reuse) |
| BTF | `btf.c` | `internal/btf` | 2 | parity tested (parser, split module merge, alignment; typed-data printer separate) |
| CO-RE | `relo_core.c`, `btf_relocate.c` | `relo_core.go`, `btf_reloc.go` | 2 | parity tested (access specs, field/flexible array/type/enum relocations, vmlinux and split module BTFs, no-target poison; `TYPE_MATCHES` rejected like libbpf's normal path) |
| BTF to C | `btf_dump.c` | `btf_dump.go`, `btf_dump_def.go`, `btf_dump_decl.go` | 2 | parity tested (type definitions and declarators, exact text; typed-data printer not started) |
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
| Attach types and program output | C harness JSON (`attach` scenario) + root table test | parity tested (kprobe, kretprobe, tracepoint, uprobe, uretprobe, fentry, fexit, raw tracepoint, kprobe multi, LSM and cookie; 6.18, 5.10 with kprobe multi and cookie skipping) |
| Perf event link and ioctl attach | root test + cookie case | parity tested (6.18 link with cookie; every kernel ioctl path) |
| Link pin, open and unpin | root link test on bpffs | parity tested (5.10 and 6.18) |
| Link update | root test | in progress (syscall layout checked; no tested link type supports update) |
| Map, program and object pinning | root pin test on bpffs | parity tested (5.10 and 6.18) |
| Map reuse | root reuse test | parity tested (5.10 and 6.18) |
| Syscall transcript after load | `LD_PRELOAD` interposer or strace parser | not started |
| CO-RE access spec | C harness JSON (`core` scenario) | parity tested (field, type and enum specs) |
| CO-RE relocation | C harness JSON (`core-reloc` scenario) | parity tested (field, type, enum and flexible array, synthetic target) |
| CO-RE load path | live kernel BTF + root load test | parity tested (`pt_regs.sp`, 5.10 and 6.18) |
| CO-RE module BTFs | synthetic module candidate + split merge test | parity tested (5.10 and 6.18) |
| CO-RE missing target | guarded load test | parity tested (`core_missing.bpf.o`, 5.10 and 6.18) |
| `btf_dump` type and declaration text | exact text diff (`dump`, `dump-decl`, `dump-decl-strip`) | parity tested (type zoo; 5.10 and 6.18) |
| `btf_dump` typed data | exact text diff | not started |
| 5.10 and newer | VM matrix | parity tested (5.10.0-46-cloud-amd64 and 6.18.63-3-lts; arm64 not run) |

The C oracle lives in `oracle/`, is built out of tree, and is never part of `go build`.
