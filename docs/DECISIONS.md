# Decisions

<!-- anchors-ok: BSD-2 LGPL-2 encoding/binary internal/sys sync/atomic internal/mmap | SPDX identifiers and package paths, not citations -->

Irreversible choices, with context and consequences. A new decision supersedes an older one only with a new dated entry.

## D-001: Project name is gobpfgo

2026-11-26. The repository and module are named `gobpfgo`. The core package remains `libbpf` because it mirrors the C library; the object layer is package `bpf`.

## D-002: LGPL-2.1-only

2026-11-26. The library is licensed LGPL-2.1-only, elected from libbpf's BSD-2-Clause OR LGPL-2.1 dual license. Go links statically, so an application that uses gobpfgo must satisfy LGPL-2.1 section 6, which in practice means it must be LGPL-compatible or ship relinkable artifacts. Dependencies must be license-compatible; Apache-2.0 is not compatible with LGPL-2.1-only, so flag it before adding one.

## D-003: No unsafe

2026-11-26. The library does not import `unsafe`. UAPI attribute structs are serialized into `[]byte` with `encoding/binary`; BTF is parsed into Go values; mmap memory is read through `[]byte`. The one unavoidable address conversion for the `bpf()` syscall is isolated in `internal/sys/addr.go` and uses `reflect.ValueOf(buf).Pointer()` with `runtime.KeepAlive`. If the operator rejects `reflect` as well, the alternative is a per-architecture assembly stub. Accepted after the cost comparison: explicit `encoding/binary` writes plus the `reflect` address helper; an `unsafe` overlay and reflect struct marshaling are rejected.

## D-004: Pure-Go dependencies

2026-11-26. Existing pure-Go packages may be used when they save substantial code, for example netlink. Every dependency must build with `CGO_ENABLED=0`, be actively maintained, be pinned, and carry a license compatible with LGPL-2.1-only. Standard library first, `golang.org/x/sys` second, third-party last.

## D-005: Naming

2026-11-26. Functions and types are CamelCase with `Bpf` and `Btf` prefixes. UAPI constants keep their exact C spelling. Nullable C strings use `*string`; required strings use `string`; buffers use `[]byte`.

## D-006: Pull-request workflow

2026-11-26. Every change is a branch plus a pull request. Commits go to the PR branch so CI runs. "Commit the pull request" is read as pushing commits to it, not merging. Merge requires an explicit instruction; the global "never merge the operator's own PR" rule still stands until the operator says otherwise.

## D-007: Two layers

2026-11-26. The core `libbpf` package is the 1:1 port, with libbpf's lifecycle and naming. The `bpf` package is a thin object layer over it, built last. A method in `bpf` may only forward a core call plus naming, lifetime or error context.

## D-008: Repository and module path

2026-11-26. The repository is [`gobpfgo/gobpfgo`](https://github.com/gobpfgo/gobpfgo) under the `gobpfgo` organization, public, and the module path is `github.com/gobpfgo/gobpfgo`. The personal account is not used for the module path.

## D-009: The agent merges its own PRs and continues

2026-11-26. The operator authorized the agent to open, approve where possible, and merge its own PRs one at a time after CI is green, fix CI failures, and continue until a decision needs the operator. GitHub rejects self-approval, so the agent merges without an approval when branch protection allows it. The merge method is rebase and merge, matching [`#1`](https://github.com/gobpfgo/gobpfgo/pull/1); the branch is deleted after merge. This is a project-specific exception to the global never-merge rule.

## D-010: Kernel floor is 5.10

2026-11-26. The port targets Linux 5.10 and newer. 5.10 is old enough for the fleet and recent enough to skip the 4.9-era fallbacks. The feature-probe matrix starts at 5.10; the VM tier covers 5.10, 6.x and latest; libbpf's 4.9-only fallbacks are not ported unless a consumer needs them. This is a deliberate deviation from libbpf's 4.9 floor, recorded in [DEVIATIONS.md](DEVIATIONS.md).

## D-011: Provenance in file metadata, godocs for Go behavior

2026-11-26. The libbpf source, commit and symbol list live in `libbpf-source`, `libbpf-commit` and `libbpf-symbols` comments at the top of each file. Godocs describe what the Go API does, its ownership, errors and limits; they do not say "mirrors X" or repeat the C symbol. The API map generator reads the metadata. Original files use `gobpfgo-origin: original`; a reimplementation of a C module uses both tags.

## D-012: kprobe attach uses the tracefs path

2026-11-26. The kprobe attach writes a `kprobe_events` entry and opens one tracepoint perf event with `pid=-1, cpu=0`, then attaches the program with `PERF_EVENT_IOC_SET_BPF`. libbpf's modern path uses the kprobe perf PMU, whose `config1` is a pointer to the function name; forming that pointer needs `unsafe` or a second reflect address helper, and D-003 keeps the address conversion in one place. The tracefs path is libbpf's legacy mode, works on the 5.10 floor, and keeps the link lifecycle in Go. The cost is that tracefs must be mounted and writable, and `BpfLinkFD` returns the perf event descriptor rather than a BPF link descriptor. Recorded in [DEVIATIONS.md](DEVIATIONS.md) item 15.

## D-013: Project renamed to gobpfgo

2026-11-26. The project, GitHub organization, repository, module path and provenance tag are `gobpfgo`; this supersedes the initial `golbpfgo` name. D-001 and D-008 are amended to the current name. The core package stays `libbpf`, because that names the C library the port follows, not this project.

## D-014: The test object targets the 5.10 BPF ISA

2026-11-26. The kprobe test object is compiled with `-mcpu=v1` so the checked-in fixture loads on the 5.10 floor. The default clang target emits the `BPF_ATOMIC` fetch-add encoding, which 5.10 rejects as reserved fields. The load test compares the verifier and JIT lengths exactly only on the kernel that produced the fixture and requires them to be nonzero elsewhere.

## D-015: Uprobe attach uses the tracefs path

2026-11-26. Uprobe and uretprobe attach write a `uprobe_events` entry and open one tracepoint perf event, the same legacy path as D-012. The uprobe perf PMU takes the binary path in `config1`, a userspace pointer, which the no-unsafe rule keeps out of the API. The cost is that `ref_ctr_offset` and `BpfCookie` return `EOPNOTSUPP` and tracefs must be writable. Recorded in [DEVIATIONS.md](DEVIATIONS.md) item 18.

## D-016: Kprobe multi symbols are resolved by the kernel

2026-11-26. `BpfProgramAttachKprobeMulti` passes its symbol names to `BPF_LINK_CREATE` in the `kprobe_multi.syms` array and lets the kernel resolve them. libbpf's userspace pattern matching over `available_filter_functions`, including wildcards and duplicate detection, is not ported. Exact names are the supported form until a consumer needs patterns. Recorded in [DEVIATIONS.md](DEVIATIONS.md) item 19.

## D-017: BTF dump covers C declarations, not typed data

2026-11-26. The dump port implements `btf_dump__new`, `btf_dump__dump_type` and `btf_dump__emit_type_decl`, which produce the C declarations and the exact text `bpftool btf dump format c` relies on. The typed-data pretty-printer `btf_dump__dump_type_data` is a separate value formatter and is not ported; `BtfDump` emits types only. The output is compared byte for byte against the C library on a type-zoo object.

## D-018: Core stays a 1:1 libbpf port; higher-level concepts come later

2026-11-26. The operator wants the core `libbpf` package to translate the C library's API and behavior first, including the callback-based ring and perf buffers, with no channels or other higher-level abstractions in the core. Higher-level concepts are built on top in the `bpf` layer or by the consumer later. A channel adapter would allocate per event and add a backpressure policy that libbpf does not have; it is a convenience, not the core contract.

## D-019: Ring buffer positions use per-architecture acquire/release assembly

2026-11-26. The ring buffer reads the producer position with acquire semantics and stores the consumer position with release semantics, like `smp_load_acquire` and `smp_store_release` in the C library. `sync/atomic` needs a `*uint64`, which a mmap `[]byte` cannot provide without `unsafe`, so `internal/sys` has two tiny assembly stubs: a plain load/store on amd64 (TSO) and `LDAR`/`STLR` on arm64. This keeps the no-unsafe rule and the exact memory ordering; the cost is one small assembly file per architecture.

## Open decisions

None. The `reflect` address helper is accepted in D-003.

