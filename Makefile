# SPDX-License-Identifier: LGPL-2.1-only

CLANG_FORMAT ?= clang-format
C_SRCS := oracle/main.c oracle/json.c oracle/oracle.c oracle/layout.c \
	oracle/attr.c oracle/open.c oracle/load.c oracle/attach.c testdata/progs/kprobe.bpf.c
C_HDRS := oracle/json.h oracle/oracle.h

.PHONY: format format-check

format:
	$(CLANG_FORMAT) -i $(C_SRCS) $(C_HDRS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(C_SRCS) $(C_HDRS)
