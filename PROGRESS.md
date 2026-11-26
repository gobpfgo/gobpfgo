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
- `oracle/load.c` loads the kprobe object with the pinned libbpf under `sudo` and writes `testdata/oracle/load.json`: map id 716, program id 300, 18 xlated instructions, 100 jited bytes.
- Kernel floor set to 5.10. The 4.9-era fallbacks are out of scope.

Next:

- Go load path: BTF load, map create with the BTF ids, map-FD relocation, program load, and the loaded info comparison.
- Kprobe attach after load.

Open:

- The 5.10 VM tier comes after load and attach.
