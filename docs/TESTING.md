# Testing against libbpf

The port is correct only when it does what libbpf does. Source similarity is not enough. Every observable behavior gets an oracle test: the same scenario runs through the C library and through gobpfgo, and the results are compared.

## The oracle

`oracle/` is a single C binary with `layout`, `attr`, `open`, `load` and `attach` subcommands. The output goes through a small JSON writer in `json.c`; the scenarios live in `layout.c`, `attr.c`, `open.c`, `load.c` and `attach.c`, and the shared metadata and UAPI field block live in `oracle.c`. The `open`, `load` and `attach` scenarios link the libbpf commit recorded in [NOTICE](../NOTICE).

Scenarios:

| Scenario | What the oracle prints |
|---|---|
| `layout` | `sizeof` and `offsetof` for every UAPI field used by the port |
| `attr` | the serialized bytes of a `bpf_attr` for a known input |
| `open` | object name, map specs, program specs, BTF type summary |
| `load` | loaded map and program info |
| `attach` | object, program and function, and whether the program counted a real call |
| `core` | every CO-RE fixup: instruction index, kind, spec, access string, old and new value |
| `dump` | the exact `btf_dump` text |
| `usdt` | provider, name, arguments, semaphore offset |
| `linker` | linked object metadata and section layout |
| `ringbuf` | event bytes and order |
| `probe` | map and program type support on the running kernel |

The oracle is development-only. Tests consume checked-in JSON and never need C, clang or libbpf.

`layout` covers `BPF_MAP_CREATE`, `BPF_MAP_LOOKUP_ELEM`, `BPF_BTF_LOAD` and `BPF_PROG_LOAD`; `attr` covers `BPF_MAP_CREATE`. `open`, `load` and `attach` are implemented for the kprobe object and are linked against the pinned libbpf. `load` and `attach` have oracle fixtures generated with `sudo`.

The BTF load test, the object load test, the kprobe attach test, the pin test and the reuse test run under root and skip with `EPERM`; the DATASEC fixup, the attribute layouts and the loaded info comparison run in CI. The root object load test compares the map info and the program info with `load.json`. The root attach test attaches `handle_open` to `do_sys_openat2`, opens a file, and requires the `counts` map to increase, so a link that never fires fails the test. The pin test creates a temporary directory on bpffs, pins and unpins the map and program, and removes the directory; it skips when bpffs is unavailable.

The loaded xlated instruction count and jited length are verifier and JIT outputs. The test compares them exactly on the kernel that produced `load.json` and requires them to be nonzero on any other kernel; the map geometry, BTF ids and program type are compared everywhere. The test object is compiled with `-mcpu=v1`, because the 5.10 verifier rejects the newer `BPF_ATOMIC` fetch-add encoding.

The ELF reader has structural tests against the checked-in `kprobe.bpf.o`. The `open` scenario compares that same object with libbpf.

The BTF parser has a structural test against the same object: type kinds, strings, the `counts` map definition and the `handle_open` prototype.

## Tiers

| Tier | Runs | Needs | Covers |
|---|---|---|---|
| 0 | every PR | nothing beyond Go | serialization bytes, ELF parse, BTF parse, CO-RE fixups, `btf_dump` text, linker, USDT, layout constants |
| 1 | main and nightly | a Linux kernel, root or `CAP_BPF` | open, load, attach, link types, pinning, ring buffer, perf events, syscall transcript |
| 2 | nightly or manual | VMs | kernels 5.10, 6.x and latest; amd64 and arm64 |

Tier 0 is the bulk of the suite, because most parity is data in and data out. Tier 1 proves the syscalls. Tier 2 proves the old-kernel fallbacks.

Tier 2 is running on Debian 11 with kernel `5.10.0-46-cloud-amd64` and on the 6.18 host. The full root and unprivileged suites pass on both. The arm64 half has not run.

## What gets compared

- **Layout.** The Go offset and size constants must equal the `layout` scenario. This catches a UAPI change before any syscall is made.
- **Attributes.** The Go serializer's bytes must equal the `attr` scenario, field by field.
- **Object metadata.** Map and program names, types, key and value sizes, max entries, flags, BTF IDs and pin paths must match after open.
- **Syscalls.** The command order and every attribute field must match after load. File descriptors, map IDs, program IDs, PIDs and timestamps are normalized away; everything else is compared.
- **CO-RE.** The fixup list must match exactly. This is the strongest check that the relocation engine is the same.
- **Text.** `btf_dump` output is compared byte for byte.
- **Errors.** The errno and the failing operation are compared. Kernel log text is compared only on selected lines, because it changes between kernel versions.

## Fixtures and updates

- Fixtures are our own C programs, compiled with clang and checked in as `.o` plus source. Do not copy kernel selftest code.
- Pure tests use a checked-in target BTF blob. Integration tests use the running kernel's BTF.
- Golden JSON records the libbpf commit and the kernel version it came from.
- `-update` is allowed only with a stated reason. CI fails when a golden file differs from the generated output.
- A libbpf update regenerates the oracle in a dedicated PR. The diff is the behavior change to port.

## Fuzzing

Go fuzz targets cover ELF, BTF and CO-RE inputs. Where the oracle can express the same input, the fuzz target compares the Go result with the C result, not just success or failure.

## Rules

- No ported behavior without an oracle scenario.
- No mock of libbpf. The oracle is the real library.
- Compare data, not just "no error".
- If the oracle cannot express a behavior, write a narrower C harness rather than skipping the test.
- A phase is not done until its scenarios are green in the tier that can run them.
