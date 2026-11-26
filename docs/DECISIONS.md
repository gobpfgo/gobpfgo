# Decisions

<!-- anchors-ok: BSD-2 LGPL-2 encoding/binary | SPDX identifiers and a package path, not citations -->

Irreversible choices, with context and consequences. A new decision supersedes an older one only with a new dated entry.

## D-001: Project name is golbpfgo

2026-11-26. The repository and module are named `golbpfgo`. The core package remains `libbpf` because it mirrors the C library; the object layer is package `bpf`.

## D-002: LGPL-2.1-only

2026-11-26. The library is licensed LGPL-2.1-only, elected from libbpf's BSD-2-Clause OR LGPL-2.1 dual license. Go links statically, so an application that uses golbpfgo must satisfy LGPL-2.1 section 6, which in practice means it must be LGPL-compatible or ship relinkable artifacts. Dependencies must be license-compatible; Apache-2.0 is not compatible with LGPL-2.1-only, so flag it before adding one.

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

2026-11-26. The repository is [`golbpfgo/golbpfgo`](https://github.com/golbpfgo/golbpfgo) under the `golbpfgo` organization, public, and the module path is `github.com/golbpfgo/golbpfgo`. The personal account is not used for the module path.

## D-009: The agent merges its own PRs and continues

2026-11-26. The operator authorized the agent to open, approve where possible, and merge its own PRs one at a time after CI is green, fix CI failures, and continue until a decision needs the operator. GitHub rejects self-approval, so the agent merges without an approval when branch protection allows it. The merge method is rebase and merge, matching [`#1`](https://github.com/golbpfgo/golbpfgo/pull/1); the branch is deleted after merge. This is a project-specific exception to the global never-merge rule.

## D-010: Kernel floor is 5.10

2026-11-26. The port targets Linux 5.10 and newer. 5.10 is old enough for the fleet and recent enough to skip the 4.9-era fallbacks. The feature-probe matrix starts at 5.10; the VM tier covers 5.10, 6.x and latest; libbpf's 4.9-only fallbacks are not ported unless a consumer needs them. This is a deliberate deviation from libbpf's 4.9 floor, recorded in [DEVIATIONS.md](DEVIATIONS.md).

## Open decisions

None. The `reflect` address helper is accepted in D-003.

