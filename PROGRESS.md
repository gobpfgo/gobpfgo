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
- `internal/elf`: sections, symbols, relocations, program sections, `.maps`, `.BTF` and `.BTF.ext`.
- `internal/btf`: header, type table, string table, all type kinds and `SizeOf`.
- `oracle`: `layout`, `attr` and `open`; `open` links the pinned libbpf built from a copy under `oracle/build`.
- `libbpf.BpfObjectOpenFile`, `BpfObjectOpenMem`, the map and program metadata accessors, and the SEC table for the kprobe path.
- The open test compares the object name, map fields and program fields with `testdata/oracle/open.json`.

Next:

- Load and kprobe attach.
- The load oracle needs a privileged kernel: this host returns `EPERM` for `bpf_map_create`. A root or `CAP_BPF` host, or a privileged VM or container, is needed to generate the load fixture.

Open:

- Kernel floor: 4.9 or 5.10.
- Privileged test environment for the load and attach fixtures.
