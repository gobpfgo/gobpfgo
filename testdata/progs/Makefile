# SPDX-License-Identifier: LGPL-2.1-only

CLANG ?= clang
LIBBPF ?= ../../../libbpf

# Keep the debug info independent of the checkout path, so the checked-in
# object is the same no matter where the repository is cloned.
DEBUG_DIR ?= /build/gobpfgo/testdata/progs

# v1 selects the legacy atomic encoding. Newer CPUs emit the BPF_ATOMIC
# fetch-add form, which the 5.10 floor rejects with reserved fields.

.PHONY: all clean

all: kprobe.bpf.o core.bpf.o core_kernel.bpf.o core_target.bpf.o

kprobe.bpf.o: kprobe.bpf.c
	$(CLANG) -O2 -g -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 \
		-fdebug-compilation-dir=$(DEBUG_DIR) \
		-I$(LIBBPF)/include/uapi -I$(LIBBPF)/src \
		-c $< -o $@

core.bpf.o: core.bpf.c
	$(CLANG) -O2 -g -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 \
		-fdebug-compilation-dir=$(DEBUG_DIR) \
		-I$(LIBBPF)/include/uapi -I$(LIBBPF)/src \
		-c $< -o $@

core_kernel.bpf.o: core_kernel.bpf.c
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
	rm -f kprobe.bpf.o core.bpf.o core_kernel.bpf.o core_target.bpf.o
