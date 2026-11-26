// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include "oracle.h"

#include "libbpf.h"
#include "btf.h"
#include "relo_core.h"

#include <linux/bpf.h>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CORE_EXT_MAGIC 0xeb9f

struct core_ext_header {
	uint16_t magic;
	uint8_t version;
	uint8_t flags;
	uint32_t hdr_len;
	uint32_t func_info_off;
	uint32_t func_info_len;
	uint32_t line_info_off;
	uint32_t line_info_len;
	uint32_t core_relo_off;
	uint32_t core_relo_len;
};

struct core_ext_sec {
	uint32_t sec_name_off;
	uint32_t num_info;
};

static int read_section(const char *path, const char *name, unsigned char **data, size_t *size) {
	Elf_Scn *scn = NULL;
	size_t shstrndx;
	Elf *elf;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror(path);
		return -1;
	}
	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "libelf is out of date\n");
		close(fd);
		return -1;
	}
	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin %s: %s\n", path, elf_errmsg(-1));
		close(fd);
		return -1;
	}
	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		fprintf(stderr, "elf_getshdrstrndx %s: %s\n", path, elf_errmsg(-1));
		goto err;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		const char *sname;
		Elf_Data *d;
		GElf_Shdr shdr;

		if (!gelf_getshdr(scn, &shdr))
			continue;
		sname = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!sname || strcmp(sname, name))
			continue;
		d = elf_getdata(scn, NULL);
		if (!d || d->d_size == 0) {
			fprintf(stderr, "%s: empty %s section\n", path, name);
			goto err;
		}
		*data = malloc(d->d_size);
		if (!*data) {
			fprintf(stderr, "malloc %zu: out of memory\n", d->d_size);
			goto err;
		}
		memcpy(*data, d->d_buf, d->d_size);
		*size = d->d_size;
		elf_end(elf);
		close(fd);
		return 0;
	}

	fprintf(stderr, "%s: no %s section\n", path, name);
err:
	elf_end(elf);
	close(fd);
	return -1;
}

static int core_relos(struct json *j, struct btf *btf, const unsigned char *ext, size_t ext_size) {
	const struct core_ext_header *hdr = (const struct core_ext_header *)ext;
	const unsigned char *info, *end, *rec;
	uint32_t rec_size;
	int err;

	if (ext_size < sizeof(*hdr) || hdr->magic != CORE_EXT_MAGIC || hdr->version != 1) {
		fprintf(stderr, "invalid .BTF.ext header\n");
		return -1;
	}
	if (hdr->hdr_len < sizeof(*hdr) || hdr->hdr_len > ext_size) {
		fprintf(stderr, "invalid .BTF.ext header length\n");
		return -1;
	}
	if (hdr->core_relo_off > ext_size - hdr->hdr_len || hdr->core_relo_len > ext_size - hdr->hdr_len - hdr->core_relo_off) {
		fprintf(stderr, ".BTF.ext core section out of bounds\n");
		return -1;
	}

	info = ext + hdr->hdr_len + hdr->core_relo_off;
	end  = info + hdr->core_relo_len;
	if ((size_t)(end - info) < sizeof(rec_size)) {
		fprintf(stderr, ".BTF.ext core section has no record size\n");
		return -1;
	}
	memcpy(&rec_size, info, sizeof(rec_size));
	info += sizeof(rec_size);
	if (rec_size < sizeof(struct bpf_core_relo) || rec_size % 4 != 0) {
		fprintf(stderr, "invalid .BTF.ext core record size %u\n", rec_size);
		return -1;
	}

	json_arr_begin(j, "relos");
	while (info < end) {
		const struct core_ext_sec *sec = (const struct core_ext_sec *)info;
		const char *section;
		uint32_t i;

		if ((size_t)(end - info) < sizeof(*sec)) {
			fprintf(stderr, ".BTF.ext core section header is truncated\n");
			return -1;
		}
		if (sec->num_info == 0 || (size_t)(end - info - sizeof(*sec)) < (uint64_t)sec->num_info * rec_size) {
			fprintf(stderr, ".BTF.ext core records are truncated\n");
			return -1;
		}
		section = btf__name_by_offset(btf, sec->sec_name_off);
		if (!section || !section[0]) {
			fprintf(stderr, ".BTF.ext core section has no name\n");
			return -1;
		}

		rec = info + sizeof(*sec);
		for (i = 0; i < sec->num_info; i++, rec += rec_size) {
			struct bpf_core_relo relo;
			struct bpf_core_spec spec;
			const char *access;
			char buf[512];
			int len, k;

			memcpy(&relo, rec, sizeof(relo));
			err = bpf_core_parse_spec(section, btf, &relo, &spec);
			if (err) {
				fprintf(stderr, "%s: core relocation at insn %u: %d\n", section, relo.insn_off, err);
				return -1;
			}
			access = btf__name_by_offset(btf, relo.access_str_off);
			if (!access)
				access = "";
			len = bpf_core_format_spec(buf, sizeof(buf), &spec);
			if (len < 0) {
				fprintf(stderr, "%s: cannot format core spec\n", section);
				return -1;
			}

			json_obj_begin_compact(j, NULL);
			json_str(j, "section", section);
			json_u32(j, "insn_off", relo.insn_off);
			json_u32(j, "type_id", relo.type_id);
			json_u32(j, "kind", relo.kind);
			json_str(j, "access", access);
			json_u32(j, "root_type_id", spec.root_type_id);
			json_u32(j, "bit_offset", spec.bit_offset);
			json_str(j, "spec", buf);
			json_arr_begin(j, "accessors");
			for (k = 0; k < spec.len; k++) {
				json_obj_begin_compact(j, NULL);
				json_u32(j, "type_id", spec.spec[k].type_id);
				json_u32(j, "idx", spec.spec[k].idx);
				json_str(j, "name", spec.spec[k].name ? spec.spec[k].name : "");
				json_obj_end(j);
			}
			json_arr_end(j);
			json_obj_end(j);
		}
		info += sizeof(*sec) + (uint64_t)sec->num_info * rec_size;
	}
	json_arr_end(j);

	return 0;
}

int oracle_core(const char *path) {
	struct oracle_meta meta = {.case_name = "core", .version = true};
	unsigned char *btf_data = NULL, *ext_data = NULL;
	size_t btf_size = 0, ext_size = 0;
	struct btf *btf;
	struct json j;
	long err;
	int ret = 1;

	if (read_section(path, ".BTF", &btf_data, &btf_size) || read_section(path, ".BTF.ext", &ext_data, &ext_size))
		goto out;

	btf = btf__new(btf_data, (uint32_t)btf_size);
	err = libbpf_get_error(btf);
	if (err) {
		fprintf(stderr, "parse .BTF: %s\n", strerror((int)-err));
		goto out;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object", oracle_basename(path));
	if (core_relos(&j, btf, ext_data, ext_size)) {
		btf__free(btf);
		goto out;
	}
	json_obj_end(&j);
	fputc('\n', stdout);
	btf__free(btf);
	ret = 0;

out:
	free(btf_data);
	free(ext_data);
	return ret;
}
