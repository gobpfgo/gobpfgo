# golbpfgo agent rules

<!-- anchors-ok: LGPL-2 encoding/binary internal/sys | SPDX identifiers and package paths, not citations -->

Binding for every change in this repository. Read this file before touching anything.

## Session start

Read, in this order:

1. [PROGRESS.md](PROGRESS.md)
2. [docs/PREFERENCES.md](docs/PREFERENCES.md)
3. [docs/DECISIONS.md](docs/DECISIONS.md)
4. [docs/STYLE.md](docs/STYLE.md)
5. [docs/TESTING.md](docs/TESTING.md)
6. [docs/PARITY.md](docs/PARITY.md)

Then check `git status` and run `CGO_ENABLED=0 go test ./...`.

## What this is

golbpfgo is a pure-Go port of libbpf, close to 1:1 in behavior and API shape. The core package `libbpf` mirrors the C library with free functions over opaque types. The `bpf` package is a thin object layer over the core and is built last.

## Hard constraints

- No cgo. `CGO_ENABLED=0 go build ./...` must pass.
- No `unsafe` import. UAPI structs are serialized into `[]byte` with `encoding/binary`; BTF is parsed into Go types; mmap data is read through `[]byte`. The single syscall address helper lives in `internal/sys` and is documented in [docs/DECISIONS.md](docs/DECISIONS.md).
- No cilium/ebpf code, tests or generated files. Design ideas only, recorded in [docs/DECISIONS.md](docs/DECISIONS.md).
- The libbpf checkout at `../libbpf` is read-only reference. Never modify it.
- LGPL-2.1-only. Every Go file carries the SPDX header. Dependencies must be license-compatible; flag Apache-2.0 before adding one.
- No AI attribution in commits or pull requests.
- Only claim checks that were run.

## Workflow

Every change goes through a pull request:

1. Create a branch from `main`: `slice/<phase>-<name>`.
2. Open a pull request immediately, as a draft when the slice is not ready.
3. Commit and push to the PR branch so CI runs. "Commit the pull request" means push commits to it; it does not mean merge.
4. Merge only when the operator says merge and the required checks are green.

Never push directly to `main`. Never force-push a branch you do not own. One vertical slice per PR: code, tests, oracle diff, docs.

Commit subjects use `libbpf:`, `bpf:`, `sys:`, `elf:`, `btf:`, `bpfgen:`, `docs:` or `ci:` followed by an imperative summary of at most 72 characters. The body says why, wrapped at 72. No markdown headings in a commit message.

The PR body follows `.github/pull_request_template.md` and stays short: what changed and why, the libbpf C reference, the checks actually run, and any parity gap or deviation.

## Learning rule

When the operator corrects a choice, append a dated entry to [docs/PREFERENCES.md](docs/PREFERENCES.md) in the same change, update the affected document, and apply the rule from then on. Never re-litigate a recorded preference. If a correction contradicts a recorded decision, update [docs/DECISIONS.md](docs/DECISIONS.md) with the new date and rationale.

## Definition of done

A ported symbol is done when:

- the Go code exists and builds with `CGO_ENABLED=0`;
- the doc comment names the C symbol and source file;
- there is a unit test;
- there is an oracle parity test where the behavior is observable;
- [docs/API-MAP.md](docs/API-MAP.md) carries its status;
- any divergence is in [docs/DEVIATIONS.md](docs/DEVIATIONS.md).

A phase is done when:

- `CGO_ENABLED=0 go build ./...` passes;
- `go vet ./...` and the configured linters pass;
- `CGO_ENABLED=0 go test ./...` passes;
- integration tests pass on at least one kernel;
- [docs/PARITY.md](docs/PARITY.md) and [PROGRESS.md](PROGRESS.md) are current;
- an independent review pass has been run.

## No invention

The C source is the specification. If its behavior is unclear, write an oracle test before implementing. Do not fill gaps with what seems reasonable.
