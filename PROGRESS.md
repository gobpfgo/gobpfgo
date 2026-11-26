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

Phase 1, in progress.

- BTF load, map create with the BTF ids, the map-FD relocation, the program load and the loaded info comparison are done; the root load test passes.
- `BpfMapLookupElem` reads a map element; the `BPF_MAP_LOOKUP_ELEM` layout comes from the test object.
- `BpfProgramAttachKprobe` creates a tracefs kprobe event, attaches the program with a perf event, and removes both on detach. The root attach test proves the program increments `counts` on a real `do_sys_openat2` call.
- The test object now targets `kprobe/do_sys_openat2`, the function the `openat` path reaches.
- The 5.10 tier passes on Debian 11 with kernel `5.10.0-46-cloud-amd64`: the full root and unprivileged suites, including object load, map lookup and kprobe attach.
- The test object is compiled with `-mcpu=v1`, because the 5.10 verifier rejects the newer `BPF_ATOMIC` fetch-add encoding. The load test compares xlated and jited lengths exactly only on the fixture kernel and requires them nonzero elsewhere.
- `BpfMapSetPinPath`, `BpfMapPin`, `BpfMapUnpin` and `BpfMapIsPinned` pin and unpin a loaded map on bpffs; `BpfProgramPin` and `BpfProgramUnpin` do the same for a program. The root test pins and unpins both on 5.10 and 6.18 ([`#20`](https://github.com/gobpfgo/gobpfgo/pull/20)).
- `BpfObjectPinMaps`, `BpfObjectUnpinMaps`, `BpfObjectPinPrograms`, `BpfObjectUnpinPrograms`, `BpfObjectPin` and `BpfObjectUnpin` pin and unpin the whole object under one directory. The root test covers the object path on 5.10 and 6.18 ([`#21`](https://github.com/gobpfgo/gobpfgo/pull/21)).
- `BpfMapReuseFD` makes an object map use an existing kernel map. The load path skips creating it, the relocation resolves maps by ELF symbol after the reused name replaces the object name, and the root test proves the program increments the reused map on 5.10 and 6.18 ([`#22`](https://github.com/gobpfgo/gobpfgo/pull/22)).

Phase 2, in progress.

- `internal/btf.ParseExt` reads the `.BTF.ext` CO-RE records; `ParseCoreSpec` resolves field, type and enum access specs against the local BTF, matching libbpf's spec for the test object (`0:1`, bit offset 32, two accessors). The `core` oracle scenario checks it and runs in CI and on 5.10 ([`#23`](https://github.com/gobpfgo/gobpfgo/pull/23)).
- `CalcCoreRelo` matches a field access against a target BTF and computes the local and target values; `patchCoreInsn` rewrites the load instruction. The `core-reloc` oracle scenario matches libbpf when `second` moves from offset 4 to 8 in the target ([`#24`](https://github.com/gobpfgo/gobpfgo/pull/24)).
- The load path parses `.BTF.ext`, finds the target type in `/sys/kernel/btf/vmlinux`, applies the field relocation, and loads `core_kernel.bpf.o` with the kernel `pt_regs.sp` offset patched. The root test passes on 5.10 and 6.18 ([`#25`](https://github.com/gobpfgo/gobpfgo/pull/25)).
- The `core-reloc` oracle now covers field offsets, type ids, type existence, type size and enum values; the engine adds type/enum target matching and 64-bit immediate patching. The Go result and patched instructions match libbpf on 5.10 and 6.18 ([`#26`](https://github.com/gobpfgo/gobpfgo/pull/26)).
- Flexible array elements resolve in both the local spec and the target; the `core_flex.values[0]` relocation matches libbpf (offset 4 to 8) on 5.10 and 6.18 ([`#27`](https://github.com/gobpfgo/gobpfgo/pull/27)).
- The load path searches vmlinux and the split module BTFs, merges module types with the vmlinux base, detects ambiguous candidates, and poisons instructions with no target instead of failing the load. `core_missing.bpf.o` loads because the poisoned access is guarded, and `TestLoadKernelBTFs` verifies the split merge. CO-RE is done for libbpf's normal path on 5.10 and 6.18. `TYPE_MATCHES` is rejected, matching libbpf.s normal `bpf_core_parse_spec` ([`#28`](https://github.com/gobpfgo/gobpfgo/pull/28)).
- Next: BTF dump, the remaining phase 2 item.

Open:

- The arm64 half of the 5.10 tier has not run.
- kprobe multi links and the perf link path are not ported; kprobe attach uses the tracefs interface.
- Link pinning and the remaining attach types are not ported.
- BTF dump and the remaining CO-RE `TYPE_MATCHES` kind (rejected by libbpf's normal path) are not ported.
