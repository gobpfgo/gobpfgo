# SPDX-License-Identifier: LGPL-2.1-only

CLANG_FORMAT ?= clang-format
C_SRCS := oracle/main.c oracle/json.c oracle/oracle.c oracle/layout.c \
	oracle/attr.c oracle/open.c oracle/load.c oracle/attach.c oracle/dump.c \
	oracle/ringbuf.c oracle/perfbuf.c oracle/probe.c oracle/linker.c \
	oracle/dedup.c oracle/core.c oracle/linfo.c oracle/zip.c oracle/usdt.c \
	oracle/usdt_notes.c oracle/kconfig.c oracle/subprog.c \
	testdata/progs/kprobe.bpf.c testdata/progs/core.bpf.c \
	testdata/progs/core_kernel.bpf.c testdata/progs/core_missing.bpf.c \
	testdata/progs/core_module.bpf.c testdata/progs/core_module_target.bpf.c \
	testdata/progs/core_target.c testdata/progs/tracepoint.bpf.c \
	testdata/progs/tracepoint_alt.bpf.c testdata/progs/uprobe.bpf.c \
	testdata/progs/fentry.bpf.c \
	testdata/progs/raw_tp.bpf.c testdata/progs/cookie.bpf.c \
	testdata/progs/kprobe_multi.bpf.c testdata/progs/lsm.bpf.c \
	testdata/progs/dump.bpf.c testdata/progs/ringbuf.bpf.c \
	testdata/progs/perfbuf.bpf.c testdata/progs/link_a.bpf.c \
	testdata/progs/link_b.bpf.c testdata/progs/link_text_a.bpf.c \
	testdata/progs/link_text_b.bpf.c testdata/progs/global_data.bpf.c \
	testdata/progs/kconfig.bpf.c testdata/progs/kconfig_types.bpf.c \
	testdata/progs/usdt_target.c testdata/progs/usdt_attach.bpf.c \
	testdata/progs/usdt_loop_target.c testdata/progs/subprog.bpf.c \
	testdata/progs/subprog_callback.bpf.c testdata/progs/link_extern_a.bpf.c \
	testdata/progs/link_extern_b.bpf.c testdata/progs/link_extern_weak.bpf.c \
	testdata/progs/link_kconfig.bpf.c testdata/progs/link_ksyms.bpf.c \
	testdata/progs/link_ksyms_addr.bpf.c testdata/progs/link_ksyms_weak.bpf.c \
	testdata/progs/link_map_extern.bpf.c testdata/progs/link_map_def.bpf.c \
	testdata/progs/subprog_hidden.bpf.c testdata/progs/subprog_arg_ctx.bpf.c \
	testdata/progs/sanitize_type_tag.bpf.c testdata/progs/sanitize_enum64.bpf.c \
	testdata/progs/sanitize_float.bpf.c testdata/progs/percpu.bpf.c \
	testdata/progs/percpu_unused.bpf.c
C_HDRS := oracle/json.h oracle/oracle.h oracle/usdt_notes.h

.PHONY: format format-check

format:
	$(CLANG_FORMAT) -i $(C_SRCS) $(C_HDRS)

format-check:
	$(CLANG_FORMAT) --dry-run --Werror $(C_SRCS) $(C_HDRS)
