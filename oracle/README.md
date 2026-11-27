# Oracle

The C harness that produces the golden files under `testdata/oracle/`. It is one binary with the subcommands below and links the pinned libbpf for the `open`, `load`, `attach`, `core`, `core-reloc`, `ringbuf`, `perfbuf`, `probe`, `linker`, `linfo`, `zip` and `usdt` scenarios. Tests consume the checked-in JSON and never build this directory.

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
- `linfo` builds synthetic `struct bpf_prog_info` values with line info, jited line info, jited symbols and function lengths, passes each to `bpf_prog_linfo__new`, and prints the input, the constructor errno and the result of `bpf_prog_linfo__lfind` for every instruction offset up to one past the last record and of `bpf_prog_linfo__lfind_addr_func` for address 0, each jited address and the byte before it and the largest address, for every `nr_skip` and function index. A result is the index of the returned record or the negative errno. It needs no privileges.
- `zip` builds small synthetic zip archives in memory, some with one header field patched, writes each to a temporary file, and opens it with libbpf's internal `zip_archive_open` and `zip_archive_find_entry`. It prints the archive bytes, the name looked up, the open and lookup errnos and the entry's compression, name, data offset, length and bytes. The cases cover several members, extra fields and comments, an archive comment, duplicate names, compressed members, encrypted and data-descriptor flags in the central directory and in the local header, out-of-bounds and wrapping sizes, truncated, empty and multi-disk archives. It needs no privileges.
- `usdt <binary>` reads the USDT notes of a host binary with libbpf's own `parse_usdt_note` and `parse_usdt_spec`, which are static in `usdt.c`, so `usdt.c` here compiles the pinned copy of that file into the oracle. It prints three lists. `probes` has the provider, name, argument spec, location, base and semaphore of every note in the binary and the parsed spec: type, size, sign, value or offset, register offsets, scale and bit shift of each argument. `note_cases` builds small x86-64 ELF images with crafted `.note.stapsdt` sections, writes each to a temporary file and runs the checks and the note loop of `collect_usdt_targets` on it: it prints the image bytes, the errno and notes of listing every note, and the errno and locations of looking one probe up. The cases cover malformed records, owner names, alignment, truncation, the order of a spec error and a note error, and missing, compressed, non-note and oversized sections. `spec_cases` parses argument specs for x86-64 and arm64. libbpf compiles only the host's argument parser, so the x86-64 results come from libbpf and the scenario must run on x86-64; the arm64 cases use a transcription of libbpf's aarch64 `parse_usdt_arg` with the same `sscanf` patterns. Inputs on which libbpf reads an uninitialized length are left out. It needs no privileges.
- `linker <object>...` links the objects, in order, into a temporary `linked.bpf.o` with `bpf_linker__new`, one `bpf_linker__add_file` per object, `bpf_linker__finalize` and `bpf_linker__free`. It opens the result with `bpf_object__open_file` and libelf and prints the object name, the maps, the programs, every section sorted by name and the symbol table. A section has its name, type, flags, size and alignment, the hex contents of a code or data section other than `.BTF` and `.BTF.ext`, and the entries of a relocation section with each symbol named the way readelf names it.

## Layout

- `json.c` and `json.h` are a small JSON writer that owns commas, indentation and escaping.
- `oracle.c` and `oracle.h` hold the shared metadata and the UAPI field block.
- `layout.c`, `attr.c`, `open.c`, `load.c`, `attach.c`, `core.c`, `ringbuf.c`, `perfbuf.c`, `probe.c`, `linker.c`, `linfo.c`, `zip.c` and `usdt.c` are the scenarios. `usdt_notes.c` and `usdt_notes.h` build the crafted ELF images of the `usdt` scenario.
- `main.c` dispatches the subcommands.

## Regenerate

```sh
make -C oracle fixtures
```

This writes `layout.json`, `attr.json`, `open.json`, the `dump` texts, `core.json`, `core-reloc.json`, `linfo.json` and `zip.json`.

```sh
make -C oracle linker-fixture
```

This writes `linker.json` for `kprobe.bpf.o` alone, `linker-merge.json` for `link_a.bpf.o` then `link_b.bpf.o`, `linker-merge-reverse.json` for the opposite order, and `linker-text.json` for `link_text_a.bpf.o` and `link_text_b.bpf.o`, whose `.text` subprograms merge. It needs no privileges.

```sh
make -C testdata/progs usdt_target
make -C oracle usdt-fixture
```

This rebuilds the USDT target with the host C compiler and writes `usdt.json`. It needs an x86-64 host and no privileges. The fixture binary is checked in; rebuild it only on purpose, because a different compiler can choose different operands.

```sh
make -C oracle load-fixture
make -C oracle attach-fixture
make -C oracle ringbuf-fixture
make -C oracle perfbuf-fixture
make -C oracle probe-fixture
```

These run the `load`, `attach`, `ringbuf`, `perfbuf` and `probe` scenarios under `sudo -n`. The map and program ids in `load.json` change per run; the Go test compares the stable fields. Review the diff before committing: a change here is a change in the kernel ABI, in the pinned libbpf headers or in the loaded metadata.
