# SPDX-License-Identifier: LGPL-2.1-only

CLANG ?= clang
LIBBPF ?= ../../../libbpf

# Keep the debug info independent of the checkout path, so the checked-in
# object is the same no matter where the repository is cloned.
DEBUG_DIR ?= /build/gobpfgo/testdata/progs

# v1 selects the legacy atomic encoding. Newer CPUs emit the BPF_ATOMIC
# fetch-add form, which the 5.10 floor rejects with reserved fields.
BPF_OBJS := kprobe.bpf.o core.bpf.o core_kernel.bpf.o core_missing.bpf.o \
	core_module.bpf.o core_module_target.bpf.o core_target.bpf.o \
	tracepoint.bpf.o tracepoint_alt.bpf.o uprobe.bpf.o fentry.bpf.o \
	raw_tp.bpf.o cookie.bpf.o kprobe_multi.bpf.o lsm.bpf.o dump.bpf.o

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

clean:
	rm -f $(BPF_OBJS)
