# SPDX-License-Identifier: LGPL-2.1-only

CLANG_FORMAT ?= clang-format
C_SRCS := oracle/main.c oracle/json.c oracle/oracle.c oracle/layout.c \
	oracle/attr.c oracle/open.c oracle/load.c oracle/attach.c oracle/dump.c \
	oracle/ringbuf.c oracle/core.c \
	testdata/progs/kprobe.bpf.c testdata/progs/core.bpf.c \
	testdata/progs/core_kernel.bpf.c testdata/progs/core_missing.bpf.c \
	testdata/progs/core_module.bpf.c testdata/progs/core_module_target.bpf.c \
	testdata/progs/core_target.c testdata/progs/tracepoint.bpf.c \
	testdata/progs/tracepoint_alt.bpf.c testdata/progs/uprobe.bpf.c \
	testdata/progs/fentry.bpf.c \
	testdata/progs/raw_tp.bpf.c testdata/progs/cookie.bpf.c \
	testdata/progs/kprobe_multi.bpf.c testdata/progs/lsm.bpf.c \
	testdata/progs/dump.bpf.c testdata/progs/ringbuf.bpf.c
C_HDRS := oracle/json.h oracle/oracle.h

.PHONY: format format-check

format:
	$(CLANG_FORMAT) -i $(C_SRCS) $(C_HDRS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(C_SRCS) $(C_HDRS)
