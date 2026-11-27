# SPDX-License-Identifier: LGPL-2.1-only

CLANG ?= clang
CC ?= cc
LIBBPF ?= ../../../libbpf

# Keep the debug info independent of the checkout path, so the checked-in
# object is the same no matter where the repository is cloned.
DEBUG_DIR ?= /build/gobpfgo/testdata/progs

# v1 selects the legacy atomic encoding. Newer CPUs emit the BPF_ATOMIC
# fetch-add form, which the 5.10 floor rejects with reserved fields.
BPF_OBJS := kprobe.bpf.o core.bpf.o core_kernel.bpf.o core_missing.bpf.o \
	core_module.bpf.o core_module_target.bpf.o core_target.bpf.o \
	tracepoint.bpf.o tracepoint_alt.bpf.o uprobe.bpf.o fentry.bpf.o \
	raw_tp.bpf.o cookie.bpf.o kprobe_multi.bpf.o lsm.bpf.o dump.bpf.o \
	ringbuf.bpf.o perfbuf.bpf.o link_a.bpf.o link_b.bpf.o \
	link_text_a.bpf.o link_text_b.bpf.o global_data.bpf.o \
	kconfig.bpf.o kconfig_types.bpf.o usdt_attach.bpf.o subprog.bpf.o \
	subprog_callback.bpf.o link_extern_a.bpf.o link_extern_b.bpf.o \
	link_extern_weak.bpf.o link_kconfig.bpf.o link_ksyms.bpf.o \
	link_ksyms_addr.bpf.o link_ksyms_weak.bpf.o \
	link_map_extern.bpf.o link_map_def.bpf.o subprog_hidden.bpf.o \
	subprog_arg_ctx.bpf.o

# A host program with SystemTap SDT probes for the USDT parser. It is built
# with the host compiler, kept unstripped so .note.stapsdt and the symbols
# stay, and is not part of all.
USDT_TARGET := usdt_target

# The USDT attach target runs in the tests, on every kernel tier. It is an
# x86-64 static PIE without a C library, so it does not depend on the host's
# C library version and still loads at a random base. It is not part of all.
USDT_LOOP_TARGET := usdt_loop_target

.PHONY: all clean

all: $(BPF_OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) -O2 -g -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 \
		-fdebug-compilation-dir=$(DEBUG_DIR) \
		-I$(LIBBPF)/include/uapi -I$(LIBBPF)/src \
		-c $< -o $@

core_target.bpf.o: core_target.c
	$(CLANG) -O2 -g -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 \
		-fdebug-compilation-dir=$(DEBUG_DIR) \
		-I$(LIBBPF)/include/uapi -I$(LIBBPF)/src \
		-c $< -o $@

$(USDT_TARGET): usdt_target.c
	$(CC) -O2 -Wall -Wextra -Werror -o $@ $<

$(USDT_LOOP_TARGET): usdt_loop_target.c
	$(CC) -O2 -Wall -Wextra -Werror -fno-stack-protector -nostdlib \
		-static-pie -o $@ $<

clean:
	rm -f $(BPF_OBJS) $(USDT_TARGET) $(USDT_LOOP_TARGET)
