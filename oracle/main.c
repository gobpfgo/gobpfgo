// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#define LIBBPF_COMMIT "4f05fb027a08a8a66d03916cf6a68a91e2c720ea"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define offsetofend(TYPE, FIELD) \
	(offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))

struct field {
	const char *name;
	size_t offset;
	size_t size;
};

#define F(name) { #name, offsetof(union bpf_attr, name), sizeof(((union bpf_attr *)0)->name) }

static void json_string(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

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

static void print_layout(void)
{
	static const struct field fields[] = {
		F(map_type),
		F(key_size),
		F(value_size),
		F(max_entries),
		F(map_flags),
		F(inner_map_fd),
		F(numa_node),
		F(map_name),
		F(map_ifindex),
		F(btf_fd),
		F(btf_key_type_id),
		F(btf_value_type_id),
		F(btf_vmlinux_value_type_id),
		F(map_extra),
		F(value_type_btf_obj_fd),
		F(map_token_fd),
		F(excl_prog_hash),
		F(excl_prog_hash_size),
	};
	const size_t attr_size = offsetofend(union bpf_attr, excl_prog_hash_size);
	struct utsname uts;
	size_t i;

	if (uname(&uts) != 0) {
		perror("uname");
		exit(1);
	}

	printf("{\n");
	printf("  \"libbpf_commit\": \"%s\",\n", LIBBPF_COMMIT);
	printf("  \"arch\": ");
	json_string(uts.machine);
	printf(",\n");
	printf("  \"kernel\": ");
	json_string(uts.release);
	printf(",\n");
	printf("  \"map_create\": {\n");
	printf("    \"attr_size\": %zu,\n", attr_size);
	printf("    \"fields\": [\n");
	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		printf("      {\"name\": ");
		json_string(fields[i].name);
		printf(", \"offset\": %zu, \"size\": %zu}%s\n",
		       fields[i].offset, fields[i].size,
		       i + 1 == ARRAY_SIZE(fields) ? "" : ",");
	}
	printf("    ]\n");
	printf("  }\n");
	printf("}\n");
}

static void print_attr(void)
{
	const size_t attr_size = offsetofend(union bpf_attr, excl_prog_hash_size);
	const char *name = "golbpfgo-test";
	struct utsname uts;
	union bpf_attr attr;
	size_t i;

	if (uname(&uts) != 0) {
		perror("uname");
		exit(1);
	}

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	for (i = 0; i < sizeof(attr.map_name) - 1 && name[i]; i++)
		attr.map_name[i] = name[i];
	attr.map_name[i] = '\0';
	attr.key_size = 4;
	attr.value_size = 8;
	attr.max_entries = 16;

	printf("{\n");
	printf("  \"case\": \"map_create\",\n");
	printf("  \"arch\": ");
	json_string(uts.machine);
	printf(",\n");
	printf("  \"kernel\": ");
	json_string(uts.release);
	printf(",\n");
	printf("  \"input\": {\n");
	printf("    \"map_type\": %u,\n", attr.map_type);
	printf("    \"name\": ");
	json_string(name);
	printf(",\n");
	printf("    \"key_size\": %u,\n", attr.key_size);
	printf("    \"value_size\": %u,\n", attr.value_size);
	printf("    \"max_entries\": %u,\n", attr.max_entries);
	printf("    \"map_flags\": %u,\n", attr.map_flags);
	printf("    \"btf_fd\": %u,\n", attr.btf_fd);
	printf("    \"btf_key_type_id\": %u,\n", attr.btf_key_type_id);
	printf("    \"btf_value_type_id\": %u,\n", attr.btf_value_type_id);
	printf("    \"btf_vmlinux_value_type_id\": %u,\n", attr.btf_vmlinux_value_type_id);
	printf("    \"inner_map_fd\": %u,\n", attr.inner_map_fd);
	printf("    \"map_extra\": %llu,\n", (unsigned long long)attr.map_extra);
	printf("    \"numa_node\": %u,\n", attr.numa_node);
	printf("    \"map_ifindex\": %u,\n", attr.map_ifindex);
	printf("    \"value_type_btf_obj_fd\": %d,\n", attr.value_type_btf_obj_fd);
	printf("    \"token_fd\": %d,\n", attr.map_token_fd);
	printf("    \"excl_prog_hash_size\": %u\n", attr.excl_prog_hash_size);
	printf("  },\n");
	printf("  \"size\": %zu,\n", attr_size);
	printf("  \"hex\": \"");
	for (i = 0; i < attr_size; i++)
		printf("%02x", ((const unsigned char *)&attr)[i]);
	printf("\"\n");
	printf("}\n");
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s layout|attr\n", argv[0]);
		return 2;
	}

	if (strcmp(argv[1], "layout") == 0)
		print_layout();
	else if (strcmp(argv[1], "attr") == 0)
		print_attr();
	else {
		fprintf(stderr, "unknown scenario: %s\n", argv[1]);
		return 2;
	}

	return 0;
}
