# SPDX-License-Identifier: LGPL-2.1-only

CLANG_FORMAT ?= clang-format
C_SRCS := oracle/main.c oracle/open.c oracle/load.c testdata/progs/kprobe.bpf.c

.PHONY: format format-check

format:
	$(CLANG_FORMAT) -i $(C_SRCS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(C_SRCS)
