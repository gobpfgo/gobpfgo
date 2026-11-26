# SPDX-License-Identifier: LGPL-2.1-only

LIBBPF ?= ../libbpf
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += -I$(LIBBPF)/include/uapi -I$(LIBBPF)/include

BUILD := build
ORACLE := $(BUILD)/oracle
OPEN := $(BUILD)/open
LIBBPF_SRC := $(BUILD)/libbpf/src
LIBBPF_OBJ := $(BUILD)/libbpf-obj
LIBBPF_A := $(LIBBPF_OBJ)/libbpf.a

.PHONY: all fixtures clean

all: $(ORACLE)

$(ORACLE): main.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(LIBBPF_A): | $(BUILD)
	rm -rf $(BUILD)/libbpf $(LIBBPF_OBJ)
	mkdir -p $(BUILD)/libbpf
	cp -a $(LIBBPF)/src $(BUILD)/libbpf/src
	cp -a $(LIBBPF)/include $(BUILD)/libbpf/include
	$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(abspath $(LIBBPF_OBJ)) BUILD_STATIC_ONLY=y

$(OPEN): open.c $(LIBBPF_A)
	$(CC) $(CPPFLAGS) -I$(LIBBPF_SRC) -I$(BUILD)/libbpf/include/uapi \
		$(CFLAGS) -o $@ open.c $(LIBBPF_A) \
		$(shell pkg-config --libs libelf zlib)

$(BUILD):
	mkdir -p $@

fixtures: $(ORACLE) $(OPEN)
	mkdir -p ../testdata/oracle
	$(ORACLE) layout > ../testdata/oracle/layout.json
	$(ORACLE) attr > ../testdata/oracle/attr.json
	$(OPEN) ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/open.json

clean:
	rm -rf $(BUILD)
