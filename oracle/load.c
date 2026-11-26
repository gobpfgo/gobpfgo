// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include "libbpf.h"
#include "bpf.h"
#include "libbpf_version.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static void json_string(const char *s)
{
	const unsigned char *p = (const unsigned char *)(s ? s : "");

	putchar('"');
	for (; *p; p++) {
		switch (*p) {
		case '"':
		case '\\':
			putchar('\\');
			putchar(*p);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		default:
			putchar(*p);
			break;
		}
	}
	putchar('"');
}

static void print_map(struct bpf_map *map)
{
	struct bpf_map_info info = {};
	char name[BPF_OBJ_NAME_LEN];
	__u32 len = sizeof(info);
	int fd = bpf_map__fd(map);

	if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0) {
		fprintf(stderr, "map info %s: %s\n", bpf_map__name(map), strerror(errno));
		exit(1);
	}
	memcpy(name, info.name, sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	printf("    {\"name\": ");
	json_string(name);
	printf(", \"type\": %u", info.type);
	printf(", \"id\": %u", info.id);
	printf(", \"key_size\": %u", info.key_size);
	printf(", \"value_size\": %u", info.value_size);
	printf(", \"max_entries\": %u", info.max_entries);
	printf(", \"map_flags\": %u", info.map_flags);
	printf(", \"btf_key_type_id\": %u", info.btf_key_type_id);
	printf(", \"btf_value_type_id\": %u", info.btf_value_type_id);
	printf("}");
}

static void print_program(struct bpf_program *prog)
{
	struct bpf_prog_info info = {};
	char name[BPF_OBJ_NAME_LEN];
	__u32 len = sizeof(info);
	int fd = bpf_program__fd(prog);

	if (bpf_obj_get_info_by_fd(fd, &info, &len) != 0) {
		fprintf(stderr, "prog info %s: %s\n", bpf_program__name(prog), strerror(errno));
		exit(1);
	}
	memcpy(name, info.name, sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	printf("    {\"name\": ");
	json_string(name);
	printf(", \"type\": %u", info.type);
	printf(", \"id\": %u", info.id);
	printf(", \"section\": ");
	json_string(bpf_program__section_name(prog));
	printf(", \"insn_cnt\": %zu", bpf_program__insn_cnt(prog));
	printf(", \"xlated_insn_cnt\": %u", info.xlated_prog_len / 8);
	printf(", \"jited_prog_len\": %u", info.jited_prog_len);
	printf("}");
}

int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct utsname uts;
	bool first;
	long err;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <object>\n", argv[0]);
		return 2;
	}
	if (uname(&uts) != 0) {
		perror("uname");
		return 1;
	}

	obj = bpf_object__open_file(argv[1], NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", argv[1], strerror((int)-err));
		return 1;
	}

	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "load %s: %s\n", argv[1], strerror(-ret));
		bpf_object__close(obj);
		return 1;
	}

	printf("{\n");
	printf("  \"case\": \"load\",\n");
	printf("  \"libbpf_version\": \"%d.%d.%d\",\n",
	       LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION, 0);
	printf("  \"arch\": ");
	json_string(uts.machine);
	printf(",\n");
	printf("  \"kernel\": ");
	json_string(uts.release);
	printf(",\n");
	printf("  \"object_name\": ");
	json_string(bpf_object__name(obj));
	printf(",\n");

	printf("  \"maps\": [\n");
	first = true;
	for (map = bpf_object__next_map(obj, NULL); map;
	     map = bpf_object__next_map(obj, map)) {
		if (!first)
			printf(",\n");
		print_map(map);
		first = false;
	}
	printf("\n  ],\n");

	printf("  \"programs\": [\n");
	first = true;
	for (prog = bpf_object__next_program(obj, NULL); prog;
	     prog = bpf_object__next_program(obj, prog)) {
		if (!first)
			printf(",\n");
		print_program(prog);
		first = false;
	}
	printf("\n  ]\n");
	printf("}\n");

	bpf_object__close(obj);
	return 0;
}
