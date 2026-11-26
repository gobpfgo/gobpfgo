# Oracle

The C harness that produces the golden files under `testdata/oracle/`. It is built against the libbpf UAPI headers at the commit recorded in [NOTICE](../NOTICE). Tests consume the checked-in JSON and never build this directory.

## Scenarios

- `layout` prints `sizeof` and `offsetof` for every UAPI field the port uses.
- `attr` prints the bytes of a `bpf_attr` for a known input.

Later scenarios (`open`, `load`, `attach`, `core`, `dump`, `usdt`, `linker`, `ringbuf`, `probe`) link against the real libbpf and are added with the slice that needs them.

## Regenerate

```sh
make -C oracle fixtures
```

This writes `testdata/oracle/layout.json` and `testdata/oracle/attr.json`. Review the diff before committing: a change here is a change in the kernel ABI or in the pinned libbpf headers, and the Go constants must follow.
