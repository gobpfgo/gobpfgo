# SPDX-License-Identifier: LGPL-2.1-only

LIBBPF ?= ../libbpf
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += -I$(LIBBPF)/include/uapi -I$(LIBBPF)/include

BUILD := build
ORACLE := $(BUILD)/oracle
ORACLE_SRCS := main.c json.c oracle.c layout.c attr.c open.c load.c attach.c
ORACLE_HDRS := json.h oracle.h
LIBBPF_SRC := $(BUILD)/libbpf/src
LIBBPF_OBJ := $(BUILD)/libbpf-obj
LIBBPF_A := $(LIBBPF_OBJ)/libbpf.a

.PHONY: all fixtures load-fixture attach-fixture clean

all: $(ORACLE)

$(LIBBPF_A): | $(BUILD)
	rm -rf $(BUILD)/libbpf $(LIBBPF_OBJ)
	mkdir -p $(BUILD)/libbpf
	cp -a $(LIBBPF)/src $(BUILD)/libbpf/src
	cp -a $(LIBBPF)/include $(BUILD)/libbpf/include
	$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(abspath $(LIBBPF_OBJ)) BUILD_STATIC_ONLY=y

$(ORACLE): $(ORACLE_SRCS) $(ORACLE_HDRS) $(LIBBPF_A)
	$(CC) $(CPPFLAGS) -I$(LIBBPF_SRC) -I$(BUILD)/libbpf/include/uapi \
		$(CFLAGS) -o $@ $(ORACLE_SRCS) $(LIBBPF_A) \
		$(shell pkg-config --libs libelf zlib)

$(BUILD):
	mkdir -p $@

fixtures: $(ORACLE)
	mkdir -p ../testdata/oracle
	$(ORACLE) layout > ../testdata/oracle/layout.json
	$(ORACLE) attr > ../testdata/oracle/attr.json
	$(ORACLE) open ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/open.json

load-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) load ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/load.json

attach-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) attach ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/attach.json

clean:
	rm -rf $(BUILD)
