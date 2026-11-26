# Preferences

<!-- anchors-ok: LGPL-2 encoding/binary internal/sys | SPDX identifiers and package paths, not citations -->

Rules learned from the operator. Newest last. Every entry carries the date, the correction, the rule that follows, and the documents it changed. The agent appends here when corrected, and the rule applies from then on.

## 2026-11-26

- **Name.** The project is `golbpfgo`, not `go-libbpf`. Use `golbpfgo` in the module path, README, docs, branch names and PR titles.
- **License.** LGPL-2.1-only. Every Go file starts with `SPDX-License-Identifier: LGPL-2.1-only`. Dependencies must be compatible; prefer MIT, BSD and ISC, and flag Apache-2.0 before adding one.
- **No unsafe.** Do not import `unsafe`. Serialize UAPI structs into `[]byte` with `encoding/binary`; parse BTF into Go types; read mmap rings through `[]byte`. The only address conversion for a syscall lives in `internal/sys` and is documented in [DECISIONS.md](DECISIONS.md).
- **Dependencies.** Prefer existing pure-Go packages when they fit. No cgo, at any point. Pin versions with `go.mod` and `go.sum`, and check the license before adding.
- **Naming.** CamelCase for functions and types; UAPI constants exactly as in the kernel headers (`BPF_MAP_TYPE_RINGBUF`, `BTF_KIND_STRUCT`). [API-MAP.md](API-MAP.md) is the decoder ring.
- **UAPI encoding.** Explicit fixed-offset `encoding/binary` writes for UAPI structs; one `reflect` call only for the syscall buffer address. No `unsafe`, no reflect struct marshaling, no `binary.Write` on structs.
- **Kernel floor.** Target Linux 5.10 and newer. Do not spend time on 4.9-era fallbacks.
- **C formatting.** Use the repository [`.clang-format`](../.clang-format): 4-column tabs, attached braces, no include sorting, no wrapping below 1000 columns, aligned consecutive assignments. Put one blank line before and after a control block. C only; Go stays gofmt.
- **Pull requests.** Every change starts with a pull request. Open it early, commit to its branch, and let CI run before the merge.
- **Merge and continue.** The agent may merge its own PRs one at a time after CI is green, fix failing CI, and move to the next slice without asking, until a decision needs the operator. GitHub rejects self-approval; merge without it when branch protection allows, using rebase and merge. The operator authorized this on 2026-11-26.
- **Learning.** This file is the log. A correction is not complete until it is written here and in the affected document.

## Entry template

```
## YYYY-MM-DD

- **Topic.** What was corrected. The rule that follows.
- **Affected docs.** Files updated.
```
