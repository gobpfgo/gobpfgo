# Progress

<!-- anchors-ok: LGPL-2 internal/sys | an SPDX identifier and a package path, not citations -->

## 2026-11-26

Phase 0: contract and bootstrap.

Done:

- Repository and module path set to [`golbpfgo/golbpfgo`](https://github.com/golbpfgo/golbpfgo) and `github.com/golbpfgo/golbpfgo`.
- Project named `golbpfgo`.
- License set to LGPL-2.1-only.
- No-unsafe policy recorded.
- Pure-Go dependency policy recorded.
- Naming contract recorded.
- Pull-request workflow recorded.
- Oracle-based parity testing plan written in [docs/TESTING.md](docs/TESTING.md).
- Contract documents written: [AGENTS.md](AGENTS.md), [docs/PREFERENCES.md](docs/PREFERENCES.md), [docs/DECISIONS.md](docs/DECISIONS.md), [docs/STYLE.md](docs/STYLE.md), [docs/TESTING.md](docs/TESTING.md), [docs/PARITY.md](docs/PARITY.md), [docs/API-MAP.md](docs/API-MAP.md), [docs/DEVIATIONS.md](docs/DEVIATIONS.md).
- Module skeleton and CI workflow written locally.

Next:

- Create `golbpfgo/golbpfgo` and open the bootstrap pull request with these documents, the module skeleton, CI and the PR template.
- Generate the full API map from the libbpf headers.
- Build the C oracle harness and its first two scenarios: `layout` and `attr`.
- Start the first vertical slice: `internal/sys`, ELF reader, minimal BTF, kprobe open/load/attach.

Open:

- Kernel floor: 4.9 or 5.10.
- Whether the `reflect` address helper is acceptable, or assembly is preferred.
- Whether "commit the pull request" means push commits to the PR branch, as recorded, or merge.
- Merge method: squash or merge commit.
