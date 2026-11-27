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

/* An opened ELF file with its section count, section name table and symbol
 * table.
 */
struct linker_elf {
	int fd;
	Elf *elf;
	size_t shstrndx;
	size_t shnum;
	GElf_Shdr symtab;
	Elf_Data *symbols;
};

/* One section and its name, for sorting by name. */
struct linker_section {
	const char *name;
	Elf_Scn *scn;
};

/* oracle_link_objects links the inputs, in order, into output with libbpf's
 * linker. It returns 0 on success and -1 after printing the failure.
 */
int oracle_link_objects(const char *const *inputs, int count, const char *output) {
	struct bpf_linker *linker;
	int err = 0;
	int i;

	linker = bpf_linker__new(output, NULL);
	if (!linker) {
		fprintf(stderr, "bpf_linker__new %s: %s\n", output, strerror(errno));
		return -1;
	}

	for (i = 0; i < count && !err; i++) {
		err = bpf_linker__add_file(linker, inputs[i], NULL);
		if (err)
			fprintf(stderr, "bpf_linker__add_file %s: %s\n", inputs[i], strerror(-err));
	}

	if (!err) {
		err = bpf_linker__finalize(linker);
		if (err)
			fprintf(stderr, "bpf_linker__finalize %s: %s\n", output, strerror(-err));
	}

	bpf_linker__free(linker);
	return err ? -1 : 0;
}

static int find_symtab(struct linker_elf *le) {
	Elf_Scn *scn = NULL;

	while ((scn = elf_nextscn(le->elf, scn)) != NULL) {
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr) || shdr.sh_type != SHT_SYMTAB)
			continue;

		le->symtab  = shdr;
		le->symbols = elf_getdata(scn, NULL);
		return le->symbols ? 0 : -1;
	}

	fprintf(stderr, "no symbol table\n");
	return -1;
}

static void linker_elf_close(struct linker_elf *le) {
	if (le->elf)
		elf_end(le->elf);
	if (le->fd >= 0)
		close(le->fd);
}

static int linker_elf_open(const char *path, struct linker_elf *le) {
	memset(le, 0, sizeof(*le));
	le->fd = -1;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "libelf is out of date\n");
		return -1;
	}

	le->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (le->fd < 0) {
		perror(path);
		return -1;
	}

	le->elf = elf_begin(le->fd, ELF_C_READ, NULL);
	if (!le->elf || elf_getshdrstrndx(le->elf, &le->shstrndx) != 0 || elf_getshdrnum(le->elf, &le->shnum) != 0) {
		fprintf(stderr, "%s: %s\n", path, elf_errmsg(-1));
		linker_elf_close(le);
		return -1;
	}

	if (find_symtab(le) != 0) {
		linker_elf_close(le);
		return -1;
	}
	return 0;
}

static const char *section_name(const struct linker_elf *le, size_t index) {
	Elf_Scn *scn = elf_getscn(le->elf, index);
	GElf_Shdr shdr;

	if (!scn || !gelf_getshdr(scn, &shdr))
		return NULL;
	return elf_strptr(le->elf, le->shstrndx, shdr.sh_name);
}

/* symbol_label names a symbol the way readelf does: a section symbol by its
 * section, every other symbol by its own name.
 */
static const char *symbol_label(const struct linker_elf *le, const GElf_Sym *sym) {
	if (GELF_ST_TYPE(sym->st_info) == STT_SECTION)
		return section_name(le, sym->st_shndx);
	return elf_strptr(le->elf, le->symtab.sh_link, sym->st_name);
}

static const char *symbol_section(const struct linker_elf *le, const GElf_Sym *sym) {
	if (sym->st_shndx == SHN_UNDEF)
		return "UND";
	if (sym->st_shndx == SHN_ABS)
		return "ABS";
	return section_name(le, sym->st_shndx);
}

static void relocations_json(struct json *j, const struct linker_elf *le, Elf_Scn *scn) {
	Elf_Data *data = elf_getdata(scn, NULL);
	size_t count   = data ? data->d_size / sizeof(Elf64_Rel) : 0;
	size_t i;

	json_arr_begin(j, "relocations");
	for (i = 0; i < count; i++) {
		GElf_Rel rel;
		GElf_Sym sym;

		if (!gelf_getrel(data, (int)i, &rel) || !gelf_getsym(le->symbols, (int)GELF_R_SYM(rel.r_info), &sym))
			continue;

		json_obj_begin_compact(j, NULL);
		json_u64(j, "offset", rel.r_offset);
		json_u32(j, "type", (uint32_t)GELF_R_TYPE(rel.r_info));
		json_str(j, "symbol", symbol_label(le, &sym));
		json_obj_end(j);
	}
	json_arr_end(j);
}

/* section_json prints a section header, the contents of a code, data or BTF
 * section and the entries of a relocation section.
 */
static void section_json(struct json *j, const struct linker_elf *le, const struct linker_section *sec) {
	Elf_Data *data;
	GElf_Shdr shdr;

	if (!gelf_getshdr(sec->scn, &shdr))
		return;

	json_obj_begin_compact(j, NULL);
	json_str(j, "name", sec->name);
	json_u32(j, "type", shdr.sh_type);
	json_u64(j, "flags", shdr.sh_flags);
	json_u64(j, "size", shdr.sh_size);
	json_u64(j, "align", shdr.sh_addralign);

	if (shdr.sh_type == SHT_PROGBITS) {
		data = elf_getdata(sec->scn, NULL);
		json_hex(j, "data", data ? data->d_buf : NULL, data ? data->d_size : 0);
	}
	if (shdr.sh_type == SHT_REL)
		relocations_json(j, le, sec->scn);

	json_obj_end(j);
}

static int section_cmp(const void *a, const void *b) {
	const struct linker_section *sa = a;
	const struct linker_section *sb = b;

	return strcmp(sa->name, sb->name);
}

/* sections_json prints every section but the null one, sorted by name. */
static int sections_json(struct json *j, const struct linker_elf *le) {
	struct linker_section *secs;
	Elf_Scn *scn = NULL;
	size_t count = 0;
	size_t i;

	secs = calloc(le->shnum, sizeof(*secs));
	if (!secs)
		return -1;

	while ((scn = elf_nextscn(le->elf, scn)) != NULL && count < le->shnum) {
		secs[count].scn  = scn;
		secs[count].name = section_name(le, elf_ndxscn(scn));
		if (!secs[count].name) {
			free(secs);
			return -1;
		}
		count++;
	}

	qsort(secs, count, sizeof(*secs), section_cmp);

	json_arr_begin(j, "sections");
	for (i = 0; i < count; i++)
		section_json(j, le, &secs[i]);
	json_arr_end(j);

	free(secs);
	return 0;
}

/* symbols_json prints the symbol table in order, without the null symbol. */
static void symbols_json(struct json *j, const struct linker_elf *le) {
	size_t count = le->symtab.sh_size / sizeof(Elf64_Sym);
	size_t i;

	json_arr_begin(j, "symbols");
	for (i = 1; i < count; i++) {
		GElf_Sym sym;

		if (!gelf_getsym(le->symbols, (int)i, &sym))
			continue;

		json_obj_begin_compact(j, NULL);
		json_str(j, "name", symbol_label(le, &sym));
		json_u32(j, "type", GELF_ST_TYPE(sym.st_info));
		json_u32(j, "bind", GELF_ST_BIND(sym.st_info));
		json_str(j, "section", symbol_section(le, &sym));
		json_u64(j, "value", sym.st_value);
		json_u64(j, "size", sym.st_size);
		json_obj_end(j);
	}
	json_arr_end(j);
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

static void object_json(struct json *j, struct bpf_object *obj) {
	struct bpf_program *prog;
	struct bpf_map *map;

	json_str(j, "object_name", bpf_object__name(obj));

	json_arr_begin(j, "maps");
	for (map = bpf_object__next_map(obj, NULL); map; map = bpf_object__next_map(obj, map))
		map_json(j, map);
	json_arr_end(j);

	json_arr_begin(j, "programs");
	for (prog = bpf_object__next_program(obj, NULL); prog; prog = bpf_object__next_program(obj, prog))
		program_json(j, prog);
	json_arr_end(j);
}

/* report_linked opens the linked object with libbpf and libelf and prints the
 * inputs, the maps and programs, the sections and the symbols.
 */
static int report_linked(const char *const *inputs, int count, const char *output) {
	struct oracle_meta meta = {.case_name = "linker", .version = true};
	struct linker_elf le;
	struct bpf_object *obj;
	struct json j;
	int ret = 0;
	long err;
	int i;

	obj = bpf_object__open_file(output, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", output, strerror((int)-err));
		return 1;
	}
	if (linker_elf_open(output, &le) != 0) {
		bpf_object__close(obj);
		return 1;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_arr_begin(&j, "objects");
	for (i = 0; i < count; i++)
		json_str(&j, NULL, oracle_basename(inputs[i]));
	json_arr_end(&j);
	json_str(&j, "output", LINKER_OUTPUT_NAME);

	object_json(&j, obj);
	if (sections_json(&j, &le) != 0)
		ret = 1;
	symbols_json(&j, &le);

	json_obj_end(&j);
	fputc('\n', stdout);

	linker_elf_close(&le);
	bpf_object__close(obj);
	return ret;
}

int oracle_linker(const char *const *paths, int count) {
	char dir[] = "/tmp/gobpfgo-linker-XXXXXX";
	char output[PATH_MAX];
	int ret = 1;

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	snprintf(output, sizeof(output), "%s/%s", dir, LINKER_OUTPUT_NAME);

	if (oracle_link_objects(paths, count, output) == 0)
		ret = report_linked(paths, count, output);

	unlink(output);
	rmdir(dir);
	return ret;
}
