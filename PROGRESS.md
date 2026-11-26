# Progress

<!-- anchors-ok: LGPL-2 internal/sys internal/elf internal/btf oracle oracle/build | an SPDX identifier and package paths, not citations -->

## 2026-11-26

Phase 0: syscalls, ELF, BTF and object open.

Done:

- Bootstrap merged: contract, CI and PR template in `main`.
- [`#2`](https://github.com/golbpfgo/golbpfgo/pull/2) merged: `BPF_MAP_CREATE` layout and attribute oracle, `internal/sys`, `libbpf.BpfMapCreate`.
- [`#3`](https://github.com/golbpfgo/golbpfgo/pull/3) merged: the agent may merge its own green PRs and continue.
- [`#4`](https://github.com/golbpfgo/golbpfgo/pull/4) merged: the ELF reader and the kprobe test object.
- [`#5`](https://github.com/golbpfgo/golbpfgo/pull/5) merged: the BTF wire parser.
- [`#6`](https://github.com/golbpfgo/golbpfgo/pull/6) merged: object open and the open oracle.
- `internal/elf`: sections, symbols, relocations, program sections, `.maps`, `.BTF` and `.BTF.ext`.
- `internal/btf`: header, type table, string table, all type kinds and `SizeOf`.
- `oracle`: `layout`, `attr` and `open`; `open` links the pinned libbpf built from a copy under `oracle/build`.
- `libbpf.BpfObjectOpenFile`, `BpfObjectOpenMem`, the map and program metadata accessors, and the SEC table for the kprobe path.
- The open test compares the object name, map fields and program fields with `testdata/oracle/open.json`.
- Kernel floor set to 5.10. The 4.9-era fallbacks are out of scope.

Next:

- Load and kprobe attach.
- The host disables unprivileged BPF, but passwordless `sudo -n` works, so the load-only fixture can be generated with `sudo`.

Open:

- None for the load slice. The 5.10 VM tier comes after load and attach.
