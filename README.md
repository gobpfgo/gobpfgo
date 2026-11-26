# gobpfgo

<!-- anchors-ok: BSD-2 LGPL-2 | SPDX identifiers, not citations -->

Repository: [gobpfgo/gobpfgo](https://github.com/gobpfgo/gobpfgo).

A pure-Go port of libbpf, close to 1:1 in behavior and API shape, with no cgo and no unsafe.

Status: phase 2. The phase 1 object, map, program and kprobe attach path is tested on 5.10 and 6.18. CO-RE access specs, field matching and instruction patching are parity tested with a synthetic target; wiring them into the load path comes next.

## Non-goals

- C ABI or C consumers.
- cgo at any point.
- The `unsafe` package.
- BPF program authoring. BPF programs stay in C and are compiled by clang; gobpfgo loads, relocates and attaches them.
- Windows and non-Linux kernels.

## Layout

```
libbpf/          core package, 1:1 with libbpf
bpf/             thin object layer, built last
internal/sys/    UAPI layouts, bpf(), perf_event_open
internal/elf/    ELF reader
internal/mmap/   mmap and ring memory
cmd/bpfgen/      Go skeleton generator
oracle/          C harness for parity tests, never part of go build
docs/            preferences, decisions, style, parity, API map
```

## Build

```
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
```

## Documents

- [AGENTS.md](AGENTS.md) rules for the agent working in this repo
- [docs/PREFERENCES.md](docs/PREFERENCES.md) learned preferences
- [docs/DECISIONS.md](docs/DECISIONS.md) locked decisions
- [docs/STYLE.md](docs/STYLE.md) code style
- [docs/PARITY.md](docs/PARITY.md) module matrix and status
- [docs/TESTING.md](docs/TESTING.md) oracle scenarios and test tiers
- [docs/API-MAP.md](docs/API-MAP.md) C to Go symbol map
- [docs/DEVIATIONS.md](docs/DEVIATIONS.md) intentional differences

## License

LGPL-2.1-only. Derived from libbpf, dual-licensed BSD-2-Clause OR LGPL-2.1; this project elects LGPL-2.1-only. See [NOTICE](NOTICE) and [LICENSE](LICENSE).
