# Progress

<!-- anchors-ok: LGPL-2 internal/sys internal/elf | an SPDX identifier and package paths, not citations -->

## 2026-11-26

Phase 0: syscalls and ELF.

Done:

- Bootstrap merged: contract, CI and PR template in `main`.
- [`#2`](https://github.com/golbpfgo/golbpfgo/pull/2) merged: `BPF_MAP_CREATE` layout and attribute oracle, `internal/sys`, `libbpf.BpfMapCreate`.
- [`#3`](https://github.com/golbpfgo/golbpfgo/pull/3) merged: the agent may merge its own green PRs and continue.
- `internal/elf`: sections, symbols, relocations, program sections, `.maps`, `.BTF` and `.BTF.ext`.
- `testdata/progs/`: the kprobe source, its Makefile and the checked-in `kprobe.bpf.o`.
- The ELF test checks the machine, license, map and BTF sections, the `handle_open` symbol and the `counts` map relocation.

Next:

- BTF parser.
- The `open` oracle scenario against the real libbpf.
- `BpfObjectOpenMem` and object metadata comparison.

Open:

- Kernel floor: 4.9 or 5.10.
