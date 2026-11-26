# Progress

<!-- anchors-ok: LGPL-2 internal/sys internal/elf | an SPDX identifier and package paths, not citations -->

## 2026-11-26

Phase 0: syscalls and oracle started.

Done:

- Bootstrap merged: contract, CI and PR template in `main`.
- `oracle/` C harness with the `layout` and `attr` scenarios.
- Golden fixtures `testdata/oracle/layout.json` and `attr.json` for `BPF_MAP_CREATE`, generated from the libbpf UAPI headers at [`4f05fb0`](https://github.com/libbpf/libbpf/commit/4f05fb027a08a8a66d03916cf6a68a91e2c720ea).
- `internal/sys`: map create attribute serializer, `bpf()` wrapper and the documented `reflect` address helper.
- `libbpf.BpfMapCreate`, mirroring `bpf_map_create()` in `src/bpf.c`.
- Layout and attribute parity tests pass. The privileged map-create test skips on this host with `EPERM`.

Next:

- `internal/elf`: sections, symbols, relocations, `.maps`, `.BTF`, `.BTF.ext`.
- Minimal BTF parser and the `open` oracle scenario.
- `BpfObjectOpenMem` and object metadata comparison against libbpf.

Open:

- Kernel floor: 4.9 or 5.10.
- Merge method: squash or merge commit.
