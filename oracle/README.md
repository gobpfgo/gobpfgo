# Oracle

The C harness that produces the golden files under `testdata/oracle/`. It is one binary with the subcommands below and links the pinned libbpf for the `open`, `load`, `attach`, `core`, `core-reloc`, `ringbuf`, `perfbuf`, `probe`, `linker`, `dedup`, `linfo`, `zip`, `usdt`, `kconfig` and `subprog` scenarios. Tests consume the checked-in JSON and never build this directory.

## Scenarios

- `layout` prints the UAPI struct sizes and field offsets used by the port.
- `attr` prints the serialized bytes of a `bpf_attr` for a known input.
- `open <object>` opens the object with libbpf and prints its maps and programs. For an object with `.kconfig` externs it also prints the `.kconfig` DATASEC after open: its size and each variable's name, offset, size and linkage, in BTF order.
- `load <object>` loads the object with libbpf and prints the loaded map and program info. It needs root or `CAP_BPF`.
- `attach <object>` loads the object, attaches `handle_open` to `do_sys_openat2`, opens `/dev/null` and reads the `counts` map. It fails unless the program incremented the counter. It needs root or `CAP_BPF`.
- `core <object>` parses the object's `.BTF` and `.BTF.ext` with libbpf, resolves each CO-RE access spec against the local BTF, and prints the section, instruction, kind, access string, bit offset and accessors.
- `core-reloc <object> <target>` takes the local CO-RE record and a target BTF, resolves the field, flexible array element, type or enum value against the target with libbpf, and prints the local and target values plus the patched instruction.
- `ringbuf <object>` attaches a ring buffer writer, polls the ring and prints the sample bytes.
- `perfbuf <object>` attaches a perf event array writer, polls the per-CPU buffers and prints the sample bytes, loss count and buffer count.
- `probe` runs the program, map and helper probes and prints the result for each case.
- `dedup <object>...` runs `btf__dedup`. For each object it parses the `.BTF` and `.BTF.ext` with `btf__parse_elf`, dedups the BTF with the `.BTF.ext` in the options, and prints both sections after dedup as hex; this path rebuilds the string table. It then builds a table of synthetic cases from scratch with `btf__new_empty` and the `btf__add_*` calls, which keep the string table, and prints each case's BTF before dedup, the dedup errno and the BTF after dedup. The cases cover duplicate integers and floats, enum forward declarations, the candidate order of libbpf's hash table before and after it grows, self-referencing structs, forward declarations resolved by a type graph comparison or by a unique name, ambiguous and mismatched declarations, unions, bitfields and anonymous members, modifier, typedef, tag, prototype, function and array chains, variables and data sections, declaration tags, identical arrays within one struct, a typedef cycle and a reference loop. It needs no privileges.
- `linfo` builds synthetic `struct bpf_prog_info` values with line info, jited line info, jited symbols and function lengths, passes each to `bpf_prog_linfo__new`, and prints the input, the constructor errno and the result of `bpf_prog_linfo__lfind` for every instruction offset up to one past the last record and of `bpf_prog_linfo__lfind_addr_func` for address 0, each jited address and the byte before it and the largest address, for every `nr_skip` and function index. A result is the index of the returned record or the negative errno. It needs no privileges.
- `zip` builds small synthetic zip archives in memory, some with one header field patched, writes each to a temporary file, and opens it with libbpf's internal `zip_archive_open` and `zip_archive_find_entry`. It prints the archive bytes, the name looked up, the open and lookup errnos and the entry's compression, name, data offset, length and bytes. The cases cover several members, extra fields and comments, an archive comment, duplicate names, compressed members, encrypted and data-descriptor flags in the central directory and in the local header, out-of-bounds and wrapping sizes, truncated, empty and multi-disk archives. It needs no privileges.
- `usdt <binary>` reads the USDT notes of a host binary with libbpf's own `parse_usdt_note` and `parse_usdt_spec`, which are static in `usdt.c`, so `usdt.c` here compiles the pinned copy of that file into the oracle. It prints three lists. `probes` has the provider, name, argument spec, location, base and semaphore of every note in the binary and the parsed spec: type, size, sign, value or offset, register offsets, scale and bit shift of each argument. `note_cases` builds small x86-64 ELF images with crafted `.note.stapsdt` sections, writes each to a temporary file and runs the checks and the note loop of `collect_usdt_targets` on it: it prints the image bytes, the errno and notes of listing every note, and the errno and locations of looking one probe up. The cases cover malformed records, owner names, alignment, truncation, the order of a spec error and a note error, and missing, compressed, non-note and oversized sections. `spec_cases` parses argument specs for x86-64 and arm64. libbpf compiles only the host's argument parser, so the x86-64 results come from libbpf and the scenario must run on x86-64; the arm64 cases use a transcription of libbpf's aarch64 `parse_usdt_arg` with the same `sscanf` patterns. Inputs on which libbpf reads an uninitialized length are left out. It needs no privileges.
- `kconfig <object>` resolves the `.kconfig` externs of `kconfig_types.bpf.o` for a table of config texts. Each case is a few lines put in front of a base config that sets every `CONFIG_` extern, so libbpf never reads the host's kernel config. The object is opened with the text as `bpf_object_open_opts.kconfig` and loaded through a generated loader (`bpf_object__gen_loader`), which runs libbpf's extern resolution without creating anything in the kernel. It prints the base, and per case the lines, the load errno and the `.kconfig` map's initial value. It needs no privileges.
- `subprog <object>...` opens one object, or links several in order with `bpf_linker` into a temporary `linked.bpf.o` and opens that, and loads it through a generated loader (`bpf_object__gen_loader`), which runs libbpf's relocation without creating anything in the kernel. It prints the load errno, the map names in map index order and, for every main program, its name, section, instruction count, final instructions with the called `.text` subprograms appended and the calls relocated, and the function and line records from `bpf_program__func_info` and `bpf_program__line_info`. The generated loader refers to maps by index, with `BPF_PSEUDO_MAP_IDX` and `BPF_PSEUDO_MAP_IDX_VALUE` loads. It needs no privileges.
- `linker <object>...` links the objects, in order, into a temporary `linked.bpf.o` with `bpf_linker__new`, one `bpf_linker__add_file` per object, `bpf_linker__finalize` and `bpf_linker__free`. It opens the result with `bpf_object__open_file` and libelf and prints the object name, the maps, the programs, every section sorted by name and the symbol table. When `bpf_object__open_file` rejects the linked object, as it does for an extern no input defined, it prints `open_errno` instead of the object name, maps and programs. A section has its name, type, flags, size and alignment, the hex contents of a code, data, `.BTF` or `.BTF.ext` section, and the entries of a relocation section with each symbol named the way readelf names it.
- `linker-kconfig <config> <object>...` does what `linker` does, then opens the linked object again with `<config>` as `bpf_object_open_opts.kconfig` and loads it through a generated loader, as the `kconfig` scenario does, and prints a `kconfig` object with the config, the load errno and the `.kconfig` map's initial value. `LINUX_KERNEL_VERSION` comes from the kernel that ran the oracle, which the `kernel` field records. It needs no privileges.

## Layout

- `json.c` and `json.h` are a small JSON writer that owns commas, indentation and escaping.
- `oracle.c` and `oracle.h` hold the shared metadata and the UAPI field block.
- `layout.c`, `attr.c`, `open.c`, `load.c`, `attach.c`, `core.c`, `ringbuf.c`, `perfbuf.c`, `probe.c`, `linker.c`, `dedup.c`, `linfo.c`, `zip.c`, `usdt.c`, `kconfig.c` and `subprog.c` are the scenarios. `usdt_notes.c` and `usdt_notes.h` build the crafted ELF images of the `usdt` scenario.
- `main.c` dispatches the subcommands.

## Regenerate

```sh
make -C oracle fixtures
```

This writes `layout.json`, `attr.json`, `open.json`, `open-global-data.json`, `open-kconfig.json`, `open-kconfig-types.json`, `kconfig.json`, the `dump` texts, `core.json`, `core-reloc.json`, `linfo.json`, `zip.json` and `dedup.json`, whose objects are listed in `DEDUP_OBJECTS` in the Makefile.

```sh
make -C oracle linker-fixture
```

This writes `linker.json` for `kprobe.bpf.o` alone, `linker-merge.json` for `link_a.bpf.o` then `link_b.bpf.o`, `linker-merge-reverse.json` for the opposite order, `linker-text.json` for `link_text_a.bpf.o` and `link_text_b.bpf.o`, whose `.text` subprograms merge, `linker-extern.json` and `linker-extern-reverse.json` for `link_extern_a.bpf.o`, whose `.extern` variable and function `link_extern_b.bpf.o` defines, linked in each order, `linker-extern-weak.json` for `link_extern_weak.bpf.o` then `link_extern_b.bpf.o`, which leaves two weak externs unresolved, `linker-extern-unresolved.json` for `link_extern_a.bpf.o` alone, `linker-kconfig.json` for `kconfig.bpf.o` alone and `linker-kconfig-merge.json` and `linker-kconfig-merge-reverse.json` for `kconfig.bpf.o` and `link_kconfig.bpf.o`, which share `.kconfig` externs, linked in each order, all three with their `.kconfig` value resolved from `LINKER_KCONFIG` in the Makefile, `linker-ksyms.json` for `link_ksyms.bpf.o` alone and `linker-kconfig-ksyms.json` for `kconfig.bpf.o` then `link_ksyms.bpf.o`, whose `.ksyms` externs pass through, `linker-map-extern.json` and `linker-map-extern-reverse.json` for `link_map_extern.bpf.o`, whose extern map `link_map_def.bpf.o` defines, linked in each order, and `linker-map-extern-unresolved.json` for `link_map_extern.bpf.o` alone. It needs no privileges.

```sh
make -C oracle subprog-fixture
```

This writes `subprog.json` for `subprog.bpf.o`, `subprog-callback.json` for `subprog_callback.bpf.o`, `subprog-link-text.json` and `subprog-link-text-reverse.json` for `link_text_a.bpf.o` and `link_text_b.bpf.o` linked in each order, and `subprog-link-extern.json` and `subprog-link-extern-reverse.json` for `link_extern_a.bpf.o` and `link_extern_b.bpf.o` linked in each order. It needs no privileges.

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
