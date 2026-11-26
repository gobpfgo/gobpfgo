// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LINKER_OUTPUT_NAME "linked.bpf.o"

struct linker_section {
	char *name;
	uint32_t type;
	uint64_t flags;
	uint64_t size;
};

struct linker_sections {
	struct linker_section *items;
	size_t count;
};

static int link_object(const char *input, const char *output) {
	struct bpf_linker *linker;
	int err;

	linker = bpf_linker__new(output, NULL);
	if (!linker) {
		fprintf(stderr, "bpf_linker__new %s: %s\n", output, strerror(errno));
		return -1;
	}

	err = bpf_linker__add_file(linker, input, NULL);
	if (err) {
		fprintf(stderr, "bpf_linker__add_file %s: %s\n", input, strerror(-err));
		bpf_linker__free(linker);
		return -1;
	}

	err = bpf_linker__finalize(linker);
	if (err)
		fprintf(stderr, "bpf_linker__finalize %s: %s\n", output, strerror(-err));

	bpf_linker__free(linker);
	return err ? -1 : 0;
}

static int section_append(struct linker_sections *secs, const char *name, const GElf_Shdr *shdr) {
	struct linker_section *items;
	char *copy;

	copy = strdup(name);
	if (!copy)
		return -1;

	items = realloc(secs->items, (secs->count + 1) * sizeof(*items));
	if (!items) {
		free(copy);
		return -1;
	}

	secs->items              = items;
	items[secs->count].name  = copy;
	items[secs->count].type  = shdr->sh_type;
	items[secs->count].flags = shdr->sh_flags;
	items[secs->count].size  = shdr->sh_size;
	secs->count++;
	return 0;
}

static int read_elf_sections(Elf *elf, struct linker_sections *secs) {
	Elf_Scn *scn = NULL;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		fprintf(stderr, "elf_getshdrstrndx: %s\n", elf_errmsg(-1));
		return -1;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		const char *name;
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr)) {
			fprintf(stderr, "gelf_getshdr: %s\n", elf_errmsg(-1));
			return -1;
		}

		name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name || section_append(secs, name, &shdr) != 0) {
			fprintf(stderr, "section %zu: cannot record name\n", elf_ndxscn(scn));
			return -1;
		}
	}

	return 0;
}

static int read_sections(const char *path, struct linker_sections *secs) {
	Elf *elf;
	int err;
	int fd;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "libelf is out of date\n");
		return -1;
	}

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		return -1;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin %s: %s\n", path, elf_errmsg(-1));
		close(fd);
		return -1;
	}

	err = read_elf_sections(elf, secs);
	elf_end(elf);
	close(fd);
	return err;
}

static int section_cmp(const void *a, const void *b) {
	const struct linker_section *sa = a;
	const struct linker_section *sb = b;

	return strcmp(sa->name, sb->name);
}

static void sections_free(struct linker_sections *secs) {
	size_t i;

	for (i = 0; i < secs->count; i++)
		free(secs->items[i].name);
	free(secs->items);
}

static void map_json(struct json *j, const struct bpf_map *map) {
	json_obj_begin_compact(j, NULL);
	json_str(j, "name", bpf_map__name(map));
	json_u32(j, "type", (uint32_t)bpf_map__type(map));
	json_u32(j, "key_size", bpf_map__key_size(map));
	json_u32(j, "value_size", bpf_map__value_size(map));
	json_u32(j, "max_entries", bpf_map__max_entries(map));
	json_obj_end(j);
}

static void program_json(struct json *j, const struct bpf_program *prog) {
	json_obj_begin_compact(j, NULL);
	json_str(j, "name", bpf_program__name(prog));
	json_u32(j, "type", (uint32_t)bpf_program__type(prog));
	json_str(j, "section", bpf_program__section_name(prog));
	json_obj_end(j);
}

static void section_json(struct json *j, const struct linker_section *sec) {
	json_obj_begin_compact(j, NULL);
	json_str(j, "name", sec->name);
	json_u32(j, "type", sec->type);
	json_u64(j, "flags", sec->flags);
	json_u64(j, "size", sec->size);
	json_obj_end(j);
}

static void linker_json(const char *input, struct bpf_object *obj, const struct linker_sections *secs) {
	struct oracle_meta meta = {.case_name = "linker", .version = true};
	struct bpf_program *prog;
	struct bpf_map *map;
	struct json j;
	size_t i;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_str(&j, "object", oracle_basename(input));
	json_str(&j, "output", LINKER_OUTPUT_NAME);
	json_str(&j, "object_name", bpf_object__name(obj));

	json_arr_begin(&j, "maps");
	for (map = bpf_object__next_map(obj, NULL); map; map = bpf_object__next_map(obj, map))
		map_json(&j, map);
	json_arr_end(&j);

	json_arr_begin(&j, "programs");
	for (prog = bpf_object__next_program(obj, NULL); prog; prog = bpf_object__next_program(obj, prog))
		program_json(&j, prog);
	json_arr_end(&j);

	json_arr_begin(&j, "sections");
	for (i = 0; i < secs->count; i++)
		section_json(&j, &secs->items[i]);
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);
}

static int report_linked(const char *input, const char *output) {
	struct linker_sections secs = {0};
	struct bpf_object *obj;
	long err;

	obj = bpf_object__open_file(output, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", output, strerror((int)-err));
		return 1;
	}

	if (read_sections(output, &secs) != 0) {
		sections_free(&secs);
		bpf_object__close(obj);
		return 1;
	}

	qsort(secs.items, secs.count, sizeof(*secs.items), section_cmp);
	linker_json(input, obj, &secs);

	sections_free(&secs);
	bpf_object__close(obj);
	return 0;
}

int oracle_linker(const char *path) {
	char dir[] = "/tmp/gobpfgo-linker-XXXXXX";
	char output[PATH_MAX];
	int ret = 1;

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	snprintf(output, sizeof(output), "%s/%s", dir, LINKER_OUTPUT_NAME);

	if (link_object(path, output) == 0)
		ret = report_linked(path, output);

	unlink(output);
	rmdir(dir);
	return ret;
}
