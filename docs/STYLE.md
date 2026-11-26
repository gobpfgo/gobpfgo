# Style

<!-- anchors-ok: LGPL-2 cmd/bpfgen encoding/binary internal/elf internal/mmap internal/sys testdata/oracle | SPDX identifiers and package paths, not citations -->

These rules are binding. The core is boring Go that mirrors boring C. If a reviewer cannot put the Go function next to the C function and follow both, the Go function is wrong.

## Layout

- The core package is `libbpf`. One C module maps to one Go file or a small set, recorded in [API-MAP.md](API-MAP.md).
- `internal/sys` owns the UAPI attribute layouts, `bpf()` and `perf_event_open`.
- `internal/elf` owns ELF parsing.
- `internal/mmap` owns mmap and ring memory.
- `bpf` is the thin object layer and imports only the core and the standard library.
- `cmd/bpfgen` is a command; the library never imports it.
- Files are named for the C module or the concept, never `utils.go`.

## Naming

| C | Go |
|---|---|
| `struct bpf_object` | `BpfObject` |
| `bpf_object__open_file` | `BpfObjectOpenFile` |
| `bpf_map__lookup_elem` | `BpfMapLookupElem` |
| `btf__add_struct` | `BtfAddStruct` |
| `ring_buffer__consume_n` | `RingBufferConsumeN` |
| `struct bpf_object_open_opts` | `BpfObjectOpenOpts` |
| `enum bpf_map_type` | `BpfMapType` |
| `BPF_MAP_TYPE_RINGBUF` | `BPF_MAP_TYPE_RINGBUF` |

- Go initialisms follow Go style: `ID`, `FD`, `CPU`, `BTF`, `PID`. C fields map to `BtfID`, `MapID`, `KeySize`.
- Unexported helpers may keep a C-like name with a lowercase first letter, for example `bpfObjectOpenFile`, when they mirror an internal C function.
- Do not invent shorter names for libbpf concepts. If the C library calls it `expected_attach_type`, the Go field is `ExpectedAttachType`.

## Types

| C | Go |
|---|---|
| `__u8`, `__u16`, `__u32`, `__u64` | `uint8`, `uint16`, `uint32`, `uint64` |
| `__s8`, `__s16`, `__s32`, `__s64` | `int8`, `int16`, `int32`, `int64` |
| `size_t` | `uintptr` |
| `bool` | `bool` |
| `const char *`, required | `string` |
| `const char *`, nullable | `*string` |
| `void *`, buffer | `[]byte` |
| function pointer | named func type |
| bitfield | integer plus accessors |
| C enum | named integer type plus exact constants |

- No Go struct is overlaid on kernel memory. UAPI attributes are serialized with `encoding/binary`; readback structs are decoded field by field.
- Use named offset constants for every field, for example `bpfAttrMapCreateOffMapType`. Do not scatter integer offsets.
- Bitfields become an underlying integer plus accessor methods. Document the bit positions next to the accessors.
- Arrays inside a C struct become fixed-size Go arrays or slices with an explicit length, never a pointer plus a separate cast.

## Errors

- No panics in library code. Errors are values.
- `libbpf.Error{Op, Errno, Path, Log}`; `Unwrap` returns `Errno`, so `errors.Is(err, unix.EINVAL)` works.
- Wrap with `%w`; check with `errors.Is`.
- Return `error` instead of a negative errno. This is the one API divergence; the errno is preserved exactly.
- A load failure captures the kernel log in `Error.Log` and also exposes it through the object.

## Ownership

- `Close` and `Destroy` are explicit, idempotent and documented. No finalizers.
- A child (`BpfProgram`, `BpfMap`, `BpfLink`) does not own its object; closing the object invalidates children.
- After close, methods return `ErrClosed`.
- The object layer mirrors the core lifetime and adds no hidden state.

## No unsafe

- No `unsafe` import anywhere.
- UAPI attributes: allocate `[]byte`, write at named offsets with `binary.NativeEndian`, pass the slice.
- BTF: parse the wire format into Go values; accessors return values, not pointers into the buffer.
- mmap: `unix.Mmap` returns `[]byte`; read with `binary.NativeEndian` at fixed offsets.
- The one address conversion is `internal/sys/addr.go`; it uses `reflect.ValueOf(buf).Pointer()` and `runtime.KeepAlive`. No other file converts a pointer to `uintptr`.
- The no-unsafe check in CI greps for the `unsafe` import and fails the build.

## Determinism

- Iterate programs, maps and links in ELF order. Store a slice plus an optional name index; never range over a Go map when order is observable.
- Map and program creation order must match libbpf.

## Comments

- Exported identifiers: doc comment starting with the name. Describe what the Go API does, its ownership, errors and limits. Do not write "mirrors X" or repeat the C symbol; the provenance lives in the file header.
- Important public functions get a full godoc. Trivial accessors get one sentence.
- Unexported helpers: comment only when the reason is not obvious.
- No commented-out code. No TODO without a phase or issue reference.
- Code comments explain why; the C source explains what.

## Readability

Code is written for humans to read and support. This includes tests, the oracle, tools and CI. Use small functions, named helpers, data tables and the formatter. A quick dump of statements that only its author can follow is a defect, not a shortcut.

## C formatting

The C sources use the repository [`.clang-format`](../.clang-format), copied from the workspace style:

- LLVM base, 4-column tabs, attached braces, no include sorting.
- `ColumnLimit: 1000`, so lines are not wrapped automatically.
- `AlignConsecutiveAssignments: true`.

Run `make format` after editing a C file; CI runs `make format-check`.

Put one blank line before and after a control block when another statement precedes or follows it. clang-format preserves those lines but does not add them.

clang-format does not format Go. The Go files stay with gofmt, and the Go rules above still apply.

## License and provenance headers

Every Go file starts with the SPDX line and a provenance block:

<!-- anchors-ok: go | a code-fence language, not a source snippet -->
```go
// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: <full sha>
// libbpf-symbols: bpf_object__open_file, bpf_object__open_mem
```

`libbpf-source` repeats when a file draws on several C files. `libbpf-symbols`
is a comma-separated list. Files with no libbpf counterpart use:

<!-- anchors-ok: go | a code-fence language, not a source snippet -->
```go
// gobpfgo-origin: original
```

A file that reimplements a C module uses both `gobpfgo-origin` and
`libbpf-source`. The commit is the one recorded in `NOTICE`. The API map
generator reads these tags; do not move the mapping into the godoc.

## Tests

- Table-driven, `t.Parallel` where safe, no network.
- Privileged tests skip unless `LIBBPF_TEST=1`; integration tests carry `//go:build linux && bpf_integration`.
- Oracle output is checked in under `testdata/oracle`; tests never need C, clang or libbpf.
- Golden files update with `-update` and are reviewed.
- Fuzz targets for ELF, BTF and CO-RE.
- `CGO_ENABLED=0 go test ./...` is the default gate.

## Dependencies

- Standard library first, `golang.org/x/sys` second, existing pure-Go modules last.
- Every dependency must build with `CGO_ENABLED=0`, be actively maintained, be pinned in `go.mod`, and be license-compatible with LGPL-2.1-only.
- No dependency for something the standard library already does. No dependency for a single helper function.

## Size

- Files soft limit 800 lines; split by concern and keep the C mapping in the file header.
- Functions soft limit 80 lines; a giant C function becomes an orchestrator plus unexported helpers, each naming the C function and line range.
- No generics in the core; no interfaces used only for mocking.
