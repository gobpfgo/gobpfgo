// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include "libbpf.h"
#include "libbpf_version.h"

#include <stdbool.h>
#include <stdio.h>
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

static const char *base_name(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}

static void print_map(const struct bpf_map *map)
{
	const char *pin = bpf_map__pin_path(map);

	printf("    {\"name\": ");
	json_string(bpf_map__name(map));
	printf(", \"type\": %u", (unsigned int)bpf_map__type(map));
	printf(", \"key_size\": %u", bpf_map__key_size(map));
	printf(", \"value_size\": %u", bpf_map__value_size(map));
	printf(", \"max_entries\": %u", bpf_map__max_entries(map));
	printf(", \"map_flags\": %u", bpf_map__map_flags(map));
	printf(", \"btf_key_type_id\": %u", bpf_map__btf_key_type_id(map));
	printf(", \"btf_value_type_id\": %u", bpf_map__btf_value_type_id(map));
	printf(", \"pin_path\": ");
	json_string(pin);
	printf("}");
}

static void print_program(const struct bpf_program *prog)
{
	printf("    {\"name\": ");
	json_string(bpf_program__name(prog));
	printf(", \"type\": %u", (unsigned int)bpf_program__type(prog));
	printf(", \"expected_attach_type\": %u", (unsigned int)bpf_program__expected_attach_type(prog));
	printf(", \"section\": ");
	json_string(bpf_program__section_name(prog));
	printf(", \"insn_cnt\": %zu", bpf_program__insn_cnt(prog));
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

	printf("{\n");
	printf("  \"case\": \"open\",\n");
	printf("  \"libbpf_version\": \"%d.%d.%d\",\n",
	       LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION, 0);
	printf("  \"arch\": ");
	json_string(uts.machine);
	printf(",\n");
	printf("  \"kernel\": ");
	json_string(uts.release);
	printf(",\n");
	printf("  \"object\": ");
	json_string(base_name(argv[1]));
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
