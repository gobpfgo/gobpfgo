# Oracle

The C harness that produces the golden files under `testdata/oracle/`. It is one binary with seven subcommands and links the pinned libbpf for the `open`, `load`, `attach`, `core` and `core-reloc` scenarios. Tests consume the checked-in JSON and never build this directory.

## Scenarios

- `layout` prints the UAPI struct sizes and field offsets used by the port.
- `attr` prints the serialized bytes of a `bpf_attr` for a known input.
- `open <object>` opens the object with libbpf and prints its maps and programs.
- `load <object>` loads the object with libbpf and prints the loaded map and program info. It needs root or `CAP_BPF`.
- `attach <object>` loads the object, attaches `handle_open` to `do_sys_openat2`, opens `/dev/null` and reads the `counts` map. It fails unless the program incremented the counter. It needs root or `CAP_BPF`.
- `core <object>` parses the object's `.BTF` and `.BTF.ext` with libbpf, resolves each CO-RE access spec against the local BTF, and prints the section, instruction, kind, access string, bit offset and accessors.
- `core-reloc <object> <target>` takes the local CO-RE record and a target BTF, resolves the field against the target with libbpf, and prints the local and target values plus the patched instruction.

## Layout

- `json.c` and `json.h` are a small JSON writer that owns commas, indentation and escaping.
- `oracle.c` and `oracle.h` hold the shared metadata and the UAPI field block.
- `layout.c`, `attr.c`, `open.c`, `load.c`, `attach.c` and `core.c` are the scenarios.
- `main.c` dispatches the subcommands.

## Regenerate

```sh
make -C oracle fixtures
```

This writes `layout.json`, `attr.json`, `open.json`, `core.json` and `core-reloc.json`.

```sh
make -C oracle load-fixture
make -C oracle attach-fixture
```

These run the `load` and `attach` scenarios under `sudo -n`. The map and program ids in `load.json` change per run; the Go test compares the stable fields. Review the diff before committing: a change here is a change in the kernel ABI, in the pinned libbpf headers or in the loaded metadata.
