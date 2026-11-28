// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include "oracle.h"

#include "libbpf.h"
#include "btf.h"
#include "libbpf_internal.h"
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

typedef int (*core_relo_fn)(void *ctx, const char *section, const struct bpf_core_relo *relo);

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

static int walk_core_relos(struct btf *btf, const unsigned char *ext, size_t ext_size, core_relo_fn fn, void *ctx) {
	const struct core_ext_header *hdr = (const struct core_ext_header *)ext;
	const unsigned char *info, *end, *rec;
	uint32_t rec_size;

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

			memcpy(&relo, rec, sizeof(relo));
			if (fn(ctx, section, &relo))
				return -1;
		}
		info += sizeof(*sec) + (uint64_t)sec->num_info * rec_size;
	}

	return 0;
}

struct spec_ctx {
	struct json *j;
	struct btf *btf;
};

static int print_core_relo(void *opaque, const char *section, const struct bpf_core_relo *relo) {
	struct spec_ctx *ctx = opaque;
	struct bpf_core_spec spec;
	const char *access;
	char buf[512];
	int len, i;

	if (bpf_core_parse_spec(section, ctx->btf, relo, &spec)) {
		fprintf(stderr, "%s: core relocation at insn %u\n", section, relo->insn_off);
		return -1;
	}
	access = btf__name_by_offset(ctx->btf, relo->access_str_off);
	if (!access)
		access = "";
	len = bpf_core_format_spec(buf, sizeof(buf), &spec);
	if (len < 0) {
		fprintf(stderr, "%s: cannot format core spec\n", section);
		return -1;
	}

	json_obj_begin_compact(ctx->j, NULL);
	json_str(ctx->j, "section", section);
	json_u32(ctx->j, "insn_off", relo->insn_off);
	json_u32(ctx->j, "type_id", relo->type_id);
	json_u32(ctx->j, "kind", relo->kind);
	json_str(ctx->j, "access", access);
	json_u32(ctx->j, "root_type_id", spec.root_type_id);
	json_u32(ctx->j, "bit_offset", spec.bit_offset);
	json_str(ctx->j, "spec", buf);
	json_arr_begin(ctx->j, "accessors");
	for (i = 0; i < spec.len; i++) {
		json_obj_begin_compact(ctx->j, NULL);
		json_u32(ctx->j, "type_id", spec.spec[i].type_id);
		json_u32(ctx->j, "idx", spec.spec[i].idx);
		json_str(ctx->j, "name", spec.spec[i].name ? spec.spec[i].name : "");
		json_obj_end(ctx->j);
	}
	json_arr_end(ctx->j);
	json_obj_end(ctx->j);
	return 0;
}

int oracle_core(const char *path) {
	struct oracle_meta meta = {.case_name = "core", .version = true};
	unsigned char *btf_data = NULL, *ext_data = NULL;
	size_t btf_size = 0, ext_size = 0;
	struct spec_ctx ctx;
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
	ctx.j   = &j;
	ctx.btf = btf;
	json_arr_begin(&j, "relos");
	if (walk_core_relos(btf, ext_data, ext_size, print_core_relo, &ctx)) {
		btf__free(btf);
		goto out;
	}
	json_arr_end(&j);
	json_obj_end(&j);
	fputc('\n', stdout);
	btf__free(btf);
	ret = 0;

out:
	free(btf_data);
	free(ext_data);
	return ret;
}

struct reloc_ctx {
	struct json *j;
	struct btf *local;
	struct btf *target;
	const char *path;
};

static void json_insn(struct json *j, const char *key, const struct bpf_insn *insn) {
	json_obj_begin_compact(j, key);
	json_u32(j, "code", insn->code);
	json_u32(j, "dst", insn->dst_reg);
	json_u32(j, "src", insn->src_reg);
	json_s32(j, "off", insn->off);
	json_s32(j, "imm", insn->imm);
	json_obj_end(j);
}

static int print_reloc(void *opaque, const char *section, const struct bpf_core_relo *relo) {
	struct reloc_ctx *ctx = opaque;
	const struct btf_type *local_type;
	struct bpf_core_cand cand;
	struct bpf_core_cand_list cands;
	struct bpf_core_spec specs[3] = {};
	struct bpf_core_relo_res res;
	const char *access, *name;
	unsigned char *program = NULL;
	size_t program_size    = 0, insn_idx;
	struct bpf_insn *insns;
	struct bpf_insn orig;
	int target_id, err;

	local_type = btf__type_by_id(ctx->local, relo->type_id);
	if (!local_type) {
		fprintf(stderr, "%s: local type %u not found\n", section, relo->type_id);
		return -1;
	}
	name = btf__name_by_offset(ctx->local, local_type->name_off);
	if (!name || !name[0]) {
		fprintf(stderr, "%s: local type %u is anonymous\n", section, relo->type_id);
		return -1;
	}
	target_id = btf__find_by_name_kind(ctx->target, name, BTF_INFO_KIND(local_type->info));
	if (target_id < 0) {
		fprintf(stderr, "%s: target type %s not found\n", section, name);
		return -1;
	}

	if (read_section(ctx->path, section, &program, &program_size))
		return -1;
	if (relo->insn_off % sizeof(*insns) || relo->insn_off + sizeof(*insns) > program_size) {
		fprintf(stderr, "%s: instruction %u out of bounds\n", section, relo->insn_off);
		free(program);
		return -1;
	}
	insns    = (struct bpf_insn *)program;
	insn_idx = relo->insn_off / sizeof(*insns);
	orig     = insns[insn_idx];

	cand  = (struct bpf_core_cand){.btf = ctx->target, .id = target_id};
	cands = (struct bpf_core_cand_list){.cands = &cand, .len = 1};
	err   = bpf_core_calc_relo_insn(section, relo, 0, ctx->local, &cands, specs, &res);
	if (err) {
		fprintf(stderr, "%s: cannot resolve core relocation: %d\n", section, err);
		free(program);
		return -1;
	}
	err = bpf_core_patch_insn(section, &insns[insn_idx], insn_idx, relo, 0, &res);
	if (err) {
		fprintf(stderr, "%s: cannot patch core relocation: %d\n", section, err);
		free(program);
		return -1;
	}

	access = btf__name_by_offset(ctx->local, relo->access_str_off);
	if (!access)
		access = "";
	json_obj_begin_compact(ctx->j, NULL);
	json_str(ctx->j, "section", section);
	json_u32(ctx->j, "insn_off", relo->insn_off);
	json_u32(ctx->j, "type_id", relo->type_id);
	json_u32(ctx->j, "kind", relo->kind);
	json_str(ctx->j, "access", access);
	json_u32(ctx->j, "target_type_id", target_id);
	json_u64(ctx->j, "orig_val", res.orig_val);
	json_u64(ctx->j, "new_val", res.new_val);
	json_u32(ctx->j, "orig_sz", res.orig_sz);
	json_u32(ctx->j, "new_sz", res.new_sz);
	json_u32(ctx->j, "orig_type_id", res.orig_type_id);
	json_u32(ctx->j, "new_type_id", res.new_type_id);
	json_bool(ctx->j, "validate", res.validate);
	json_bool(ctx->j, "poison", res.poison);
	json_bool(ctx->j, "fail_memsz_adjust", res.fail_memsz_adjust);
	json_insn(ctx->j, "orig_insn", &orig);
	json_insn(ctx->j, "new_insn", &insns[insn_idx]);
	json_obj_end(ctx->j);
	free(program);
	return 0;
}

int oracle_core_reloc(const char *path, const char *target_path) {
	struct oracle_meta meta = {.case_name = "core-reloc", .version = true};
	unsigned char *btf_data = NULL, *ext_data = NULL, *target_data = NULL;
	size_t btf_size = 0, ext_size = 0, target_size = 0;
	struct reloc_ctx ctx;
	struct btf *local, *target;
	struct json j;
	long err;
	int ret = 1;

	if (read_section(path, ".BTF", &btf_data, &btf_size) || read_section(path, ".BTF.ext", &ext_data, &ext_size) || read_section(target_path, ".BTF", &target_data, &target_size))
		goto out;

	local = btf__new(btf_data, (uint32_t)btf_size);
	err   = libbpf_get_error(local);
	if (err) {
		fprintf(stderr, "parse local .BTF: %s\n", strerror((int)-err));
		goto out;
	}
	target = btf__new(target_data, (uint32_t)target_size);
	err    = libbpf_get_error(target);
	if (err) {
		fprintf(stderr, "parse target .BTF: %s\n", strerror((int)-err));
		btf__free(local);
		goto out;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object", oracle_basename(path));
	json_str(&j, "target", oracle_basename(target_path));
	ctx.j      = &j;
	ctx.local  = local;
	ctx.target = target;
	ctx.path   = path;
	json_arr_begin(&j, "relos");
	if (walk_core_relos(local, ext_data, ext_size, print_reloc, &ctx)) {
		btf__free(local);
		btf__free(target);
		goto out;
	}
	json_arr_end(&j);
	json_obj_end(&j);
	fputc('\n', stdout);
	btf__free(local);
	btf__free(target);
	ret = 0;

out:
	free(btf_data);
	free(ext_data);
	free(target_data);
	return ret;
}

/* match_cands is the cached candidate list of one local type. */
struct match_cands {
	bool searched;
	struct bpf_core_cand_list list;
};

struct match_ctx {
	struct json *j;
	struct btf *local;
	struct btf *target;
	const char *path;
	struct match_cands *cache; /* indexed by local type ID */
};

/* find_match_cands fills cands with libbpf's own candidate search on the
 * whole target BTF, as for vmlinux: the types whose name without a ___flavor
 * suffix and kind match the local type.
 */
static int find_match_cands(struct match_ctx *ctx, const struct bpf_core_relo *relo, struct bpf_core_cand_list *cands) {
	struct bpf_core_cand local_cand = {.btf = ctx->local, .id = relo->type_id};
	const struct btf_type *local_type;
	const char *name;

	local_type = btf__type_by_id(ctx->local, relo->type_id);
	name       = btf__name_by_offset(ctx->local, local_type->name_off);
	return bpf_core_add_cands(&local_cand, bpf_core_essential_name_len(name), ctx->target, "target", 1, cands);
}

/* match_cands returns the candidate list of relo's local type. As with the
 * cand_cache of bpf_object__relocate_core, the list is searched once per
 * local type and shared by every relocation of it, which keeps only the
 * candidates that matched. A TYPE_ID_LOCAL relocation has no candidates and
 * neither reads nor fills the cache.
 */
static struct bpf_core_cand_list *match_cands(struct match_ctx *ctx, const struct bpf_core_relo *relo, struct bpf_core_cand_list *none) {
	struct match_cands *entry = &ctx->cache[relo->type_id];
	int err;

	if (relo->kind == BPF_CORE_TYPE_ID_LOCAL)
		return none;

	if (!entry->searched) {
		err = find_match_cands(ctx, relo, &entry->list);
		if (err) {
			fprintf(stderr, "candidate search failed: %d\n", err);
			return NULL;
		}
		entry->searched = true;
	}
	return &entry->list;
}

static void free_match_cache(struct match_cands *cache, uint32_t cnt) {
	uint32_t i;

	if (!cache)
		return;

	for (i = 0; i < cnt; i++)
		free(cache[i].list.cands);
	free(cache);
}

/* json_match_cands prints each candidate with the result of the type match
 * and of the type compatibility check against it: 1, 0 or a negative errno.
 */
static void json_match_cands(struct match_ctx *ctx, uint32_t local_id, const struct bpf_core_cand_list *cands) {
	int i;

	json_arr_begin(ctx->j, "cands");
	for (i = 0; i < cands->len; i++) {
		uint32_t id                 = cands->cands[i].id;
		const struct btf_type *type = btf__type_by_id(ctx->target, id);

		json_obj_begin_compact(ctx->j, NULL);
		json_u32(ctx->j, "type_id", id);
		json_str(ctx->j, "name", btf__name_by_offset(ctx->target, type->name_off));
		json_s32(ctx->j, "match", bpf_core_types_match(ctx->local, local_id, ctx->target, id));
		json_s32(ctx->j, "compat", bpf_core_types_are_compat(ctx->local, local_id, ctx->target, id));
		json_obj_end(ctx->j);
	}
	json_arr_end(ctx->j);
}

/* json_match_result relocates the instruction with res and prints the result
 * and the patched instruction.
 */
static int json_match_result(struct match_ctx *ctx, const char *section, const struct bpf_core_relo *relo, const struct bpf_core_relo_res *res) {
	unsigned char *program = NULL;
	size_t program_size    = 0, insn_idx;
	struct bpf_insn *insns;
	int err;

	if (read_section(ctx->path, section, &program, &program_size))
		return -1;
	if (relo->insn_off % sizeof(*insns) || relo->insn_off + sizeof(*insns) > program_size) {
		fprintf(stderr, "%s: instruction %u out of bounds\n", section, relo->insn_off);
		free(program);
		return -1;
	}
	insns    = (struct bpf_insn *)program;
	insn_idx = relo->insn_off / sizeof(*insns);
	err      = bpf_core_patch_insn(section, &insns[insn_idx], insn_idx, relo, 0, res);
	if (err) {
		fprintf(stderr, "%s: cannot patch core relocation: %d\n", section, err);
		free(program);
		return -1;
	}

	json_u64(ctx->j, "orig_val", res->orig_val);
	json_u64(ctx->j, "new_val", res->new_val);
	json_bool(ctx->j, "validate", res->validate);
	json_bool(ctx->j, "poison", res->poison);
	json_insn(ctx->j, "new_insn", &insns[insn_idx]);
	free(program);
	return 0;
}

static int print_match(void *opaque, const char *section, const struct bpf_core_relo *relo) {
	struct match_ctx *ctx             = opaque;
	struct bpf_core_cand_list none    = {};
	struct bpf_core_spec specs[3]     = {};
	struct bpf_core_relo_res res      = {};
	const struct btf_type *local_type = btf__type_by_id(ctx->local, relo->type_id);
	const char *access                = btf__name_by_offset(ctx->local, relo->access_str_off);
	struct bpf_core_cand_list *cands;
	int err, ret = 0;

	if (!local_type) {
		fprintf(stderr, "%s: local type %u not found\n", section, relo->type_id);
		return -1;
	}
	cands = match_cands(ctx, relo, &none);
	if (!cands)
		return -1;

	json_obj_begin_compact(ctx->j, NULL);
	json_str(ctx->j, "section", section);
	json_u32(ctx->j, "insn_off", relo->insn_off);
	json_u32(ctx->j, "type_id", relo->type_id);
	json_u32(ctx->j, "kind", relo->kind);
	json_str(ctx->j, "access", access ? access : "");
	json_str(ctx->j, "name", btf__name_by_offset(ctx->local, local_type->name_off));
	json_match_cands(ctx, relo->type_id, cands);

	/* bpf_core_calc_relo_insn keeps only the matching candidates, so the
	 * list is printed first.
	 */
	err = bpf_core_calc_relo_insn(section, relo, 0, ctx->local, cands, specs, &res);
	json_s32(ctx->j, "err", err);
	if (!err)
		ret = json_match_result(ctx, section, relo, &res);
	json_obj_end(ctx->j);
	return ret;
}

int oracle_core_match(const char *path, const char *target_path) {
	struct oracle_meta meta = {.case_name = "core-match", .version = true};
	unsigned char *btf_data = NULL, *ext_data = NULL, *target_data = NULL;
	size_t btf_size = 0, ext_size = 0, target_size = 0;
	struct match_ctx ctx;
	struct match_cands *cache = NULL;
	uint32_t cache_cnt        = 0;
	struct btf *local = NULL, *target = NULL;
	struct json j;
	int ret = 1;

	if (read_section(path, ".BTF", &btf_data, &btf_size) || read_section(path, ".BTF.ext", &ext_data, &ext_size) || read_section(target_path, ".BTF", &target_data, &target_size))
		goto out;

	local  = btf__new(btf_data, (uint32_t)btf_size);
	target = btf__new(target_data, (uint32_t)target_size);
	if (libbpf_get_error(local) || libbpf_get_error(target)) {
		fprintf(stderr, "parse .BTF: %s\n", strerror(errno));
		goto out;
	}

	cache_cnt = btf__type_cnt(local);
	cache     = calloc(cache_cnt, sizeof(*cache));
	if (!cache) {
		fprintf(stderr, "calloc: out of memory\n");
		goto out;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object", oracle_basename(path));
	json_str(&j, "target", oracle_basename(target_path));
	ctx = (struct match_ctx){.j = &j, .local = local, .target = target, .path = path, .cache = cache};
	json_arr_begin(&j, "relos");
	if (walk_core_relos(local, ext_data, ext_size, print_match, &ctx))
		goto out;
	json_arr_end(&j);
	json_obj_end(&j);
	fputc('\n', stdout);
	ret = 0;

out:
	free_match_cache(cache, cache_cnt);
	if (!libbpf_get_error(local))
		btf__free(local);
	if (!libbpf_get_error(target))
		btf__free(target);
	free(btf_data);
	free(ext_data);
	free(target_data);
	return ret;
}
