# Deviations from libbpf

<!-- anchors-ok: cmd/bpfgen | a package path, not a citation -->

Every intentional difference from the C library. The list is part of the contract; adding to it requires a decision entry in [DECISIONS.md](DECISIONS.md).

1. **Errors.** C returns a negative errno or a pointer plus errno. Go returns `error` with `*libbpf.Error`; `Errno` preserves the exact code.
2. **Nullable strings.** C uses `const char *` with NULL meaning default or absent. Go uses `*string` where the distinction matters, `string` otherwise.
3. **No C ABI.** No `libbpf.map`, symbol versioning, `sizeof` or struct-layout contract. The library is for Go callers only.
4. **Macros.** `LIBBPF_OPTS` becomes `New*Opts` with `Sz`; `bpf_object__for_each_program` becomes `BpfObjectForEachProgram`; documented helpers replace macros.
5. **Print callback.** C's varargs `libbpf_print_fn_t` becomes a formatted hook; the core formats before calling it.
6. **No unsafe.** UAPI structs are serialized; BTF is parsed; mmap is read through byte slices. The ring buffer hot path pays for bounds checks and decoding.
7. **Skeleton generation.** `bpftool gen skeleton` is not part of libbpf; `cmd/bpfgen` emits Go skeletons with the same fields and mmap layout.
8. **BPF-side headers.** `bpf_helpers.h`, `bpf_tracing.h`, `bpf_core_read.h`, `bpf_endian.h` and `usdt.bpf.h` are clang macros, not library code. BPF programs remain C compiled by clang; the port loads and manages them.
9. **Address conversion.** The `bpf()` syscall needs a pointer to the serialized attribute buffer. `internal/sys/addr.go` is the only place that obtains it, without importing `unsafe`.
10. **Skeleton structs.** The C skeleton is generated per object by bpftool. The Go skeleton is generated per object by `cmd/bpfgen` and uses slices where C uses pointer arrays.
11. **Memory object name.** libbpf derives a pointer-based default name for `bpf_object__open_mem`; the Go port uses `mem` unless `ObjectName` is set.
12. **Accessor names.** `bpf_map__type` and `bpf_program__type` become `BpfMapTypeOf` and `BpfProgramTypeOf`, because `BpfMapType` and `BpfProgType` are the Go type names.
13. **Kernel floor.** libbpf supports 4.9 and newer; golbpfgo targets 5.10 and newer, so 4.9-era fallbacks are not ported.
