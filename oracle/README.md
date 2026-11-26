# Oracle

The C harness that produces the golden files under `testdata/oracle/`. It is built against the libbpf UAPI headers at the commit recorded in [NOTICE](../NOTICE). Tests consume the checked-in JSON and never build this directory.

## Scenarios

- `layout` prints `sizeof` and `offsetof` for every UAPI field the port uses.
- `attr` prints the bytes of a `bpf_attr` for a known input.
- `open` opens the kprobe object with the real libbpf and prints the object, map and program metadata. It is the first scenario linked against libbpf.
- `load` opens and loads the kprobe object with the real libbpf and prints the loaded map and program info. It needs root or `CAP_BPF`; `make -C oracle load-fixture` uses `sudo -n`.

Later scenarios (`load`, `attach`, `core`, `dump`, `usdt`, `linker`, `ringbuf`, `probe`) link against the real libbpf and are added with the slice that needs them.

The `open` target builds libbpf from a copy under `oracle/build/`, so the libbpf checkout stays read-only.

## Regenerate

```sh
make -C oracle fixtures
```

This writes `testdata/oracle/layout.json`, `attr.json` and `open.json`. The `load` fixture is separate because it needs privileges:

```sh
make -C oracle load-fixture
```

It runs the oracle under `sudo -n` and writes `testdata/oracle/load.json`. Review the diff before committing: a change here is a change in the kernel ABI, in the pinned libbpf headers or in the loaded metadata, and the Go constants must follow.
