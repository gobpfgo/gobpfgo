# SPDX-License-Identifier: LGPL-2.1-only

CLANG ?= clang
LIBBPF ?= ../../../libbpf

.PHONY: all clean

all: kprobe.bpf.o

kprobe.bpf.o: kprobe.bpf.c
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-I$(LIBBPF)/include/uapi -I$(LIBBPF)/src \
		-c $< -o $@

clean:
	rm -f kprobe.bpf.o
