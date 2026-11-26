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
13. **Kernel floor.** libbpf supports 4.9 and newer; gobpfgo targets 5.10 and newer, so 4.9-era fallbacks are not ported.
14. **Map element buffer sizes.** libbpf passes the caller's key and value pointers through; the kernel copies the map value size into the value buffer. Go validates that both lengths match the map sizes and returns `EINVAL` instead of letting the kernel write past a short slice.
15. **kprobe attach interface.** libbpf uses the kprobe perf PMU and, when the kernel supports it, a BPF perf link. gobpfgo writes a tracefs `kprobe_events` entry and attaches through a plain perf event with `PERF_EVENT_IOC_SET_BPF`, the path libbpf calls legacy. The kprobe PMU takes a userspace function-name pointer, which the no-unsafe rule keeps out of the API. `BpfLinkFD` returns the perf event descriptor, not a BPF link descriptor. The attach behavior is the same; tracefs write access is required.
16. **Map pin path strings.** libbpf stores a NULL pin path when a map has none and can store an empty string; Go stores a string, so both read as an empty `BpfMapPinPath`. `BpfMapSetPinPath(nil)` clears the stored path, and pinning an empty path still fails with `EINVAL`.
17. **Link detach and destroy.** `bpf_link__detach` calls `BPF_LINK_DETACH` and keeps the descriptor; `BpfLinkDetach` disables and closes the descriptors and removes the tracefs event the link owns, and `BpfLinkDestroy` only frees the Go object. `BpfLinkFD` returns -1 after `BpfLinkDetach`. A pinned link survives either call, and `BpfLinkDestroy` does not unpin it, matching libbpf.
18. **Uprobe attach interface.** `BpfProgramAttachUprobe` uses the tracefs `uprobe_events` path and a plain perf event, like the kprobe path in item 15. `RefCtrOffset` and `BpfCookie` return `EOPNOTSUPP`; libbpf's uprobe PMU path needs a userspace path pointer, and the ref counter is only supported there. The tracefs event fires for the pid and CPU the perf event selects.
19. **Kprobe multi symbols.** `BpfProgramAttachKprobeMulti` passes exact symbol names to the kernel through the `kprobe_multi.syms` array and accepts explicit addresses. libbpf's wildcard pattern matching over `available_filter_functions` and its duplicate detection are not ported. Wildcard patterns return `ENOENT` or `EINVAL` from the kernel. The link type needs kernel 5.18 or newer.
20. **Tracing attach on older kernels.** fentry, fexit, fmod_ret and LSM use `BPF_LINK_CREATE` when the kernel accepts it. On kernels that only attach tracing programs through `BPF_RAW_TRACEPOINT_OPEN` with a NULL name (5.10 among them), the call falls back to that command, matching libbpf. The returned descriptor is still a BPF link. A nonzero `BpfCookie` requires the link path and returns the kernel error otherwise.
21. **Attach targets in modules.** The BTF attach target is resolved in vmlinux only. `fentry/module:function` and the other `module:function` forms return `ENOTSUP`; module BTF ids and their kernel descriptors are not resolved yet.
22. **Link update.** `BpfLinkUpdateProgram` calls `BPF_LINK_UPDATE` and is layout checked. On the tested kernels only XDP links implement update, and this slice does not attach XDP, so the successful update path is unexercised; other link types return `EINVAL`.
