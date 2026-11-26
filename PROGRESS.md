# Progress

<!-- anchors-ok: LGPL-2 internal/sys internal/elf internal/btf oracle oracle/build | an SPDX identifier and package paths, not citations -->

## 2026-11-26

Phase 0 done: syscalls, ELF, BTF, object open and the test harness.

Done:

- Bootstrap merged: contract, CI and PR template in `main`.
- [`#2`](https://github.com/golbpfgo/golbpfgo/pull/2) merged: `BPF_MAP_CREATE` layout and attribute oracle, `internal/sys`, `libbpf.BpfMapCreate`.
- [`#3`](https://github.com/golbpfgo/golbpfgo/pull/3) merged: the agent may merge its own green PRs and continue.
- [`#4`](https://github.com/golbpfgo/golbpfgo/pull/4) merged: the ELF reader and the kprobe test object.
- [`#5`](https://github.com/golbpfgo/golbpfgo/pull/5) merged: the BTF wire parser.
- [`#6`](https://github.com/golbpfgo/golbpfgo/pull/6) merged: object open and the open oracle.
- [`#7`](https://github.com/golbpfgo/golbpfgo/pull/7) merged: the kernel floor is 5.10.
- [`#8`](https://github.com/golbpfgo/golbpfgo/pull/8) merged: the load oracle, generated under `sudo`.
- [`#9`](https://github.com/golbpfgo/golbpfgo/pull/9) merged: the C clang-format rules and the CI format gate.
- [`#10`](https://github.com/golbpfgo/golbpfgo/pull/10) merged: provenance metadata in file headers and real godocs.
- [`#11`](https://github.com/golbpfgo/golbpfgo/pull/11) merged: the BTF load path and DATASEC fixup.
- [`#12`](https://github.com/golbpfgo/golbpfgo/pull/12) merged: the object load path (BTF, maps, programs).
- The loaded map and program info matches `load.json`: map `counts`, program `handle_open`, 18 xlated instructions and 100 jited bytes.
- The oracle is now one binary with `layout`, `attr`, `open` and `load` subcommands. A small JSON writer owns the formatting; the layout, attr and open fixtures are unchanged and the load ids were regenerated.
- `internal/elf`: sections, symbols, relocations, program sections, `.maps`, `.BTF` and `.BTF.ext`.
- `internal/btf`: header, type table, string table, all type kinds and `SizeOf`.
- `oracle`: `layout`, `attr`, `open` and `load`; the linked scenarios build the pinned libbpf under `oracle/build`.
- `libbpf.BpfObjectOpenFile`, `BpfObjectOpenMem`, the map and program metadata accessors, and the SEC table for the kprobe path.
- The open test compares the object name, map fields and program fields with `testdata/oracle/open.json`.
- The load fixture records map id 716, program id 300, 18 xlated instructions and 100 jited bytes on 6.18.
- File provenance now lives in the `libbpf-source`, `libbpf-commit` and `libbpf-symbols` headers; godocs describe the Go API.

Next: phase 1, in progress.

- BTF load, map create with the BTF ids, the map-FD relocation, the program load and the loaded info comparison are done; the root load test passes.
- Next: the kprobe attach.

Open:

- The 5.10 VM tier comes after load and attach.
