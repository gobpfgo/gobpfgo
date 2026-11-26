# Testing against libbpf

The port is correct only when it does what libbpf does. Source similarity is not enough. Every observable behavior gets an oracle test: the same scenario runs through the C library and through gobpfgo, and the results are compared.

## The oracle

`oracle/` is a single C binary with `layout`, `attr`, `open`, `load`, `attach`, `core` and `core-reloc` subcommands. The output goes through a small JSON writer in `json.c`; the scenarios live in `layout.c`, `attr.c`, `open.c`, `load.c`, `attach.c` and `core.c`, and the shared metadata and UAPI field block live in `oracle.c`. The linked scenarios use the libbpf commit recorded in [NOTICE](../NOTICE).

Scenarios:

| Scenario | What the oracle prints |
|---|---|
| `layout` | `sizeof` and `offsetof` for every UAPI field used by the port |
| `attr` | the serialized bytes of a `bpf_attr` for a known input |
| `open` | object name, map specs, program specs, BTF type summary |
| `load` | loaded map and program info |
| `attach` | one case per attach type: kind, object, program, target, retprobe and cookie flags, whether libbpf supports it, and whether the program counted a real call or received the cookie |
| `core` | CO-RE access specs: section, instruction, kind, access string, bit offset and accessors |
| `core-reloc` | the field, type, enum or flexible array target match, resolved values and the patched instruction |
| `dump` | the exact `btf_dump` text for every type in the object |
| `dump-decl` | the exact `btf_dump__emit_type_decl` text for every non-variable type |
| `dump-decl-strip` | the same declarations with `strip_mods` set |
| `usdt` | provider, name, arguments, semaphore offset |
| `linker` | linked object metadata and section layout |
| `ringbuf` | event bytes and order |
| `probe` | map and program type support on the running kernel |

The oracle is development-only. Tests consume checked-in JSON and never need C, clang or libbpf.

`layout` covers `BPF_MAP_CREATE`, `BPF_MAP_LOOKUP_ELEM`, `BPF_BTF_LOAD`, `BPF_PROG_LOAD`, `BPF_LINK_CREATE`, `BPF_LINK_UPDATE` and `BPF_RAW_TRACEPOINT_OPEN`; `attr` covers `BPF_MAP_CREATE`. `open` and `load` run on the kprobe object; `attach` runs all attach fixtures and is linked against the pinned libbpf. `dump`, `dump-decl` and `dump-decl-strip` run on `dump.bpf.o`, a type zoo that is never loaded. `load` and `attach` have oracle fixtures generated with `sudo`; the dump fixtures are unprivileged.

The BTF load test, the object load test, the attach table, the perf event attach, the auto attach, the link pin and update tests, the pin test, the reuse test, the CO-RE load test and the missing-target load test run under root and skip with `EPERM`; the DATASEC fixup, the attribute layouts, the loaded info comparison, the CO-RE spec and relocation tests and the split module merge test run in CI. The root object load test compares the map info and the program info with `load.json`. The root attach table loads one object per case, attaches the program, triggers the event, and requires the map to change, so a link that never fires fails the test; the uprobe and uretprobe cases attach to `uprobeTarget` in the test binary and call it. The perf event ioctl test attaches a tracepoint perf event without the link path. The link pin test pins an fentry link, destroys the original descriptor, reopens the link from bpffs, proves it still fires, and unpins it. The link update test replaces a tracepoint program on a perf link and skips when the kernel link type does not implement update. The pin test creates a temporary directory on bpffs, pins and unpins the map and program, and removes the directory; it skips when bpffs is unavailable.

On 5.10 the kprobe multi and cookie cases skip because the kernel lacks the link types, and the LSM case skips because the BPF LSM is not in the active LSM list. The fentry, fexit and LSM attaches use the raw tracepoint open fallback on that kernel, which the table exercises.

The 5.10 VM has `CONFIG_BPF_LSM=y`, but its boot `lsm=` list does not include `bpf`, so an LSM program attaches and its hook never runs. After rebooting it with `lsm=lockdown,capability,yama,apparmor,tomoyo,bpf`, check that `/sys/kernel/security/lsm` contains `bpf`, then run `sudo go test -v -run 'TestBpfProgramAttachTypes/lsm' ./libbpf`; the case should count a real `file_open` call instead of skipping.

The loaded xlated instruction count and jited length are verifier and JIT outputs. The test compares them exactly on the kernel that produced `load.json` and requires them to be nonzero on any other kernel; the map geometry, BTF ids and program type are compared everywhere. The test object is compiled with `-mcpu=v1`, because the 5.10 verifier rejects the newer `BPF_ATOMIC` fetch-add encoding.

The ELF reader has structural tests against the checked-in `kprobe.bpf.o`. The `open` scenario compares that same object with libbpf.

The BTF parser has a structural test against the same object: type kinds, strings, the `counts` map definition and the `handle_open` prototype.

The BTF dump test parses `dump.bpf.o` with `BtfParse` and again as raw `.BTF` with `BtfNew`, dumps every type id, and compares the exact text with `dump.txt`. The declaration tests call `BtfDumpEmitTypeDecl` for every non-variable type, once normally and once with `strip_mods`, and compare with `dump-decl.txt` and `dump-decl-strip.txt`. The fixture covers structs, unions, enums, enum64, signed and one-byte enums, bitfields, packed and flexible structs, anonymous members, arrays, function pointers, typedefs, forward declarations, type tags and declaration tags.

## Tiers

| Tier | Runs | Needs | Covers |
|---|---|---|---|
| 0 | every PR | nothing beyond Go | serialization bytes, ELF parse, BTF parse, CO-RE fixups, `btf_dump` text, linker, USDT, layout constants |
| 1 | main and nightly | a Linux kernel, root or `CAP_BPF` | open, load, every attach type, link pin/open/update, pinning, ring buffer, perf events, syscall transcript |
| 2 | nightly or manual | VMs | kernels 5.10, 6.x and latest; amd64 and arm64 |

Tier 0 is the bulk of the suite, because most parity is data in and data out. Tier 1 proves the syscalls. Tier 2 proves the old-kernel fallbacks.

Tier 2 is running on Debian 11 with kernel `5.10.0-46-cloud-amd64` and on the 6.18 host. The full root and unprivileged suites pass on both. The arm64 half has not run.

## What gets compared

- **Layout.** The Go offset and size constants must equal the `layout` scenario. This catches a UAPI change before any syscall is made.
- **Attributes.** The Go serializer's bytes must equal the `attr` scenario, field by field.
- **Object metadata.** Map and program names, types, key and value sizes, max entries, flags, BTF IDs and pin paths must match after open.
- **Syscalls.** The command order and every attribute field must match after load. File descriptors, map IDs, program IDs, PIDs and timestamps are normalized away; everything else is compared.
- **CO-RE access spec, relocation and load path.** The access spec, the target match, the resolved values and the patched instruction must match for fields, flexible array elements, types and enum values. The `core-reloc` scenario covers the engine with a synthetic target; the load tests check the live kernel `pt_regs.sp` offset, the guarded missing-target poison, module candidates and the split module merge on 5.10 and 6.18.
- **Text.** `btf_dump` type definitions and `emit_type_decl` declarators are compared byte for byte, including whitespace, indentation, padding fields and attributes.
- **Attach types.** The C harness and the Go table load the same objects, attach the same program to the same target, trigger it, and compare the map result: a count, or the cookie the program read with `bpf_get_attach_cookie`. The cases cover kprobe, kretprobe, tracepoint, uprobe, uretprobe, fentry, fexit, raw tracepoint, kprobe multi, kretprobe multi, LSM and the cookie path.
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
