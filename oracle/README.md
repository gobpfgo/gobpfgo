# Oracle

The C harness that produces the golden files under `testdata/oracle/`. It is one binary with the subcommands below and links the pinned libbpf for the `open`, `load`, `attach`, `core`, `core-reloc`, `ringbuf`, `perfbuf`, `probe` and `linker` scenarios. Tests consume the checked-in JSON and never build this directory.

## Scenarios

- `layout` prints the UAPI struct sizes and field offsets used by the port.
- `attr` prints the serialized bytes of a `bpf_attr` for a known input.
- `open <object>` opens the object with libbpf and prints its maps and programs.
- `load <object>` loads the object with libbpf and prints the loaded map and program info. It needs root or `CAP_BPF`.
- `attach <object>` loads the object, attaches `handle_open` to `do_sys_openat2`, opens `/dev/null` and reads the `counts` map. It fails unless the program incremented the counter. It needs root or `CAP_BPF`.
- `core <object>` parses the object's `.BTF` and `.BTF.ext` with libbpf, resolves each CO-RE access spec against the local BTF, and prints the section, instruction, kind, access string, bit offset and accessors.
- `core-reloc <object> <target>` takes the local CO-RE record and a target BTF, resolves the field, flexible array element, type or enum value against the target with libbpf, and prints the local and target values plus the patched instruction.
- `ringbuf <object>` attaches a ring buffer writer, polls the ring and prints the sample bytes.
- `perfbuf <object>` attaches a perf event array writer, polls the per-CPU buffers and prints the sample bytes, loss count and buffer count.
- `probe` runs the program, map and helper probes and prints the result for each case.
- `linker <object>` links the object alone into a temporary `linked.bpf.o` with `bpf_linker__new`, `bpf_linker__add_file`, `bpf_linker__finalize` and `bpf_linker__free`, opens the result with `bpf_object__open_file`, and prints the object name, the maps, the programs and every section's name, type, flags and size, sorted by name.

## Layout

- `json.c` and `json.h` are a small JSON writer that owns commas, indentation and escaping.
- `oracle.c` and `oracle.h` hold the shared metadata and the UAPI field block.
- `layout.c`, `attr.c`, `open.c`, `load.c`, `attach.c`, `core.c`, `ringbuf.c`, `perfbuf.c`, `probe.c` and `linker.c` are the scenarios.
- `main.c` dispatches the subcommands.

## Regenerate

```sh
make -C oracle fixtures
```

This writes `layout.json`, `attr.json`, `open.json`, `core.json` and `core-reloc.json`.

```sh
make -C oracle linker-fixture
```

This writes `linker.json` and needs no privileges.

```sh
make -C oracle load-fixture
make -C oracle attach-fixture
make -C oracle ringbuf-fixture
make -C oracle perfbuf-fixture
make -C oracle probe-fixture
```

These run the `load`, `attach`, `ringbuf`, `perfbuf` and `probe` scenarios under `sudo -n`. The map and program ids in `load.json` change per run; the Go test compares the stable fields. Review the diff before committing: a change here is a change in the kernel ABI, in the pinned libbpf headers or in the loaded metadata.
