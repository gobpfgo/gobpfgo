# Progress

<!-- anchors-ok: LGPL-2 internal/sys internal/elf internal/btf oracle oracle/build kprobe/do_sys_openat2 | an SPDX identifier, package paths and a section name, not citations -->

## 2026-11-26

Phase 0 done: syscalls, ELF, BTF, object open and the test harness.

Done:

- Bootstrap merged: contract, CI and PR template in `main`.
- [`#2`](https://github.com/gobpfgo/gobpfgo/pull/2) merged: `BPF_MAP_CREATE` layout and attribute oracle, `internal/sys`, `libbpf.BpfMapCreate`.
- [`#3`](https://github.com/gobpfgo/gobpfgo/pull/3) merged: the agent may merge its own green PRs and continue.
- [`#4`](https://github.com/gobpfgo/gobpfgo/pull/4) merged: the ELF reader and the kprobe test object.
- [`#5`](https://github.com/gobpfgo/gobpfgo/pull/5) merged: the BTF wire parser.
- [`#6`](https://github.com/gobpfgo/gobpfgo/pull/6) merged: object open and the open oracle.
- [`#7`](https://github.com/gobpfgo/gobpfgo/pull/7) merged: the kernel floor is 5.10.
- [`#8`](https://github.com/gobpfgo/gobpfgo/pull/8) merged: the load oracle, generated under `sudo`.
- [`#9`](https://github.com/gobpfgo/gobpfgo/pull/9) merged: the C clang-format rules and the CI format gate.
- [`#10`](https://github.com/gobpfgo/gobpfgo/pull/10) merged: provenance metadata in file headers and real godocs.
- [`#11`](https://github.com/gobpfgo/gobpfgo/pull/11) merged: the BTF load path and DATASEC fixup.
- [`#12`](https://github.com/gobpfgo/gobpfgo/pull/12) merged: the object load path (BTF, maps, programs).
- The loaded map and program info matches `load.json`: map `counts`, program `handle_open`, 18 xlated instructions and 100 jited bytes.
- The oracle is now one binary with `layout`, `attr`, `open`, `load` and `attach` subcommands. A small JSON writer owns the formatting; the layout, attr and open fixtures are unchanged and the load ids were regenerated.
- `internal/elf`: sections, symbols, relocations, program sections, `.maps`, `.BTF` and `.BTF.ext`.
- `internal/btf`: header, type table, string table, all type kinds and `SizeOf`.
- `oracle`: `layout`, `attr`, `open`, `load` and `attach`; the linked scenarios build the pinned libbpf under `oracle/build`.
- `libbpf.BpfObjectOpenFile`, `BpfObjectOpenMem`, the map and program metadata accessors, and the SEC table for the kprobe path.
- The open test compares the object name, map fields and program fields with `testdata/oracle/open.json`.
- The load fixture records the loaded map and program info on 6.18; the map and program ids are ephemeral.
- File provenance now lives in the `libbpf-source`, `libbpf-commit` and `libbpf-symbols` headers; godocs describe the Go API.
- The project, module path, GitHub owner and provenance tag are renamed `gobpfgo` ([`#17`](https://github.com/gobpfgo/gobpfgo/pull/17)); the C oracle map names and the tracefs event prefix follow.

Next: phase 1, in progress.

- BTF load, map create with the BTF ids, the map-FD relocation, the program load and the loaded info comparison are done; the root load test passes.
- `BpfMapLookupElem` reads a map element; the `BPF_MAP_LOOKUP_ELEM` layout comes from the test object.
- `BpfProgramAttachKprobe` creates a tracefs kprobe event, attaches the program with a perf event, and removes both on detach. The root attach test proves the program increments `counts` on a real `do_sys_openat2` call.
- The test object now targets `kprobe/do_sys_openat2`, the function the `openat` path reaches.
- The 5.10 tier passes on Debian 11 with kernel `5.10.0-46-cloud-amd64`: the full root and unprivileged suites, including object load, map lookup and kprobe attach.
- The test object is compiled with `-mcpu=v1`, because the 5.10 verifier rejects the newer `BPF_ATOMIC` fetch-add encoding. The load test compares xlated and jited lengths exactly only on the fixture kernel and requires them nonzero elsewhere.
- `BpfMapSetPinPath`, `BpfMapPin`, `BpfMapUnpin` and `BpfMapIsPinned` pin and unpin a loaded map on bpffs; `BpfProgramPin` and `BpfProgramUnpin` do the same for a program. The root test pins and unpins both on 5.10 and 6.18 ([`#20`](https://github.com/gobpfgo/gobpfgo/pull/20)).
- `BpfObjectPinMaps`, `BpfObjectUnpinMaps`, `BpfObjectPinPrograms`, `BpfObjectUnpinPrograms`, `BpfObjectPin` and `BpfObjectUnpin` pin and unpin the whole object under one directory. The root test covers the object path on 5.10 and 6.18.
- Next: map reuse.

Open:

- The arm64 half of the 5.10 tier has not run.
- kprobe multi links and the perf link path are not ported; kprobe attach uses the tracefs interface.
- Map reuse is not ported.
