// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "btf.h"
#include "libbpf.h"
#include "libbpf_internal.h"

#include <linux/btf.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * bpf_object__sanitize_btf asks kernel_supports, and so libbpf's global
 * feature cache, about each BTF feature. Without CAP_BPF every probe's
 * BPF_BTF_LOAD fails, every feature is missing, and the scenario shows the
 * copy libbpf would upload to a kernel without any of them: the only
 * feature combination this harness can set. It checks the cache before it
 * sanitizes anything.
 */
static const struct {
	const char *name;
	enum kern_feature_id id;
} sanitize_features[] = {
	{"func", FEAT_BTF_FUNC},
	{"datasec", FEAT_BTF_DATASEC},
	{"global_func", FEAT_BTF_GLOBAL_FUNC},
	{"float", FEAT_BTF_FLOAT},
	{"decl_tag", FEAT_BTF_DECL_TAG},
	{"type_tag", FEAT_BTF_TYPE_TAG},
	{"enum64", FEAT_BTF_ENUM64},
	{"qmark_datasec", FEAT_BTF_QMARK_DATASEC},
	{"layout", FEAT_BTF_LAYOUT},
};

/* add keeps the first error of a sequence of btf__add_* calls and returns the
 * call's result.
 */
static int add(int *err, int ret) {
	if (ret < 0 && !*err)
		*err = ret;
	return ret;
}

/* Every kind and name the sanitizer rewrites, between types it keeps. */
static int build_zoo(struct btf *btf) {
	int err = 0;
	int i32, tag, ptr, p, f32, proto, f, q;

	i32 = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	tag = add(&err, btf__add_type_tag(btf, "user", i32));
	ptr = add(&err, btf__add_ptr(btf, tag));
	add(&err, btf__add_enum(btf, "s", 4));
	add(&err, btf__add_enum_value(btf, "N", -1));
	add(&err, btf__add_enum_value(btf, "P", 1));
	add(&err, btf__add_enum(btf, "e", 4));
	add(&err, btf__add_enum_value(btf, "E", 7));
	add(&err, btf__add_enum64(btf, "w", 8, false));
	add(&err, btf__add_enum64_value(btf, "L", 1));
	add(&err, btf__add_enum64_value(btf, "H", 1ULL << 32));
	add(&err, btf__add_enum64(btf, "w2", 8, true));
	add(&err, btf__add_enum64_value(btf, "M", ~0ULL));
	p = add(&err, btf__add_var(btf, "p", BTF_VAR_STATIC, ptr));
	add(&err, btf__add_datasec(btf, "?.data", 16));
	add(&err, btf__add_datasec_var_info(btf, p, 8, 8));
	add(&err, btf__add_datasec(btf, ".bss", 0));
	add(&err, btf__add_struct(btf, "?x", 0));
	add(&err, btf__add_decl_tag(btf, "tag", p, -1));
	f32 = add(&err, btf__add_float(btf, "float", 4));
	add(&err, btf__add_float(btf, "double", 8));
	proto = add(&err, btf__add_func_proto(btf, i32));
	add(&err, btf__add_func_param(btf, "a", i32));
	add(&err, btf__add_func_param(btf, NULL, ptr));
	f = add(&err, btf__add_func(btf, "f", BTF_FUNC_GLOBAL, proto));
	add(&err, btf__add_func(btf, "g", BTF_FUNC_STATIC, proto));
	add(&err, btf__add_func(btf, "h", BTF_FUNC_EXTERN, proto));
	q = add(&err, btf__add_var(btf, "q", BTF_VAR_GLOBAL_ALLOCATED, i32));
	add(&err, btf__add_datasec(btf, ".data.?y", 12));
	add(&err, btf__add_datasec_var_info(btf, q, 0, 4));
	add(&err, btf__add_datasec_var_info(btf, f, 4, 0));
	add(&err, btf__add_datasec_var_info(btf, f32, 8, 4));
	return err;
}

/* An int, a type tag, an ENUM64 and a '?' DATASEC of a variable. */
static int build_small(struct btf *btf) {
	int err = 0;
	int i32, x;

	i32 = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	add(&err, btf__add_type_tag(btf, "user", i32));
	add(&err, btf__add_enum64(btf, "w", 8, false));
	add(&err, btf__add_enum64_value(btf, "L", 1ULL << 33));
	x = add(&err, btf__add_var(btf, "x", BTF_VAR_STATIC, i32));
	add(&err, btf__add_datasec(btf, "?.data", 4));
	add(&err, btf__add_datasec_var_info(btf, x, 0, 4));
	return err;
}

/* build_small without the ENUM64, so nothing needs the placeholder. */
static int build_small_no_enum64(struct btf *btf) {
	int err = 0;
	int i32, x;

	i32 = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	add(&err, btf__add_type_tag(btf, "user", i32));
	x = add(&err, btf__add_var(btf, "x", BTF_VAR_STATIC, i32));
	add(&err, btf__add_datasec(btf, "?.data", 4));
	add(&err, btf__add_datasec_var_info(btf, x, 0, 4));
	return err;
}

/* A DATASEC between a FLOAT and a TYPE_TAG, whose name a TYPEDEF shares.
 * Its variables refer to a VAR, the FLOAT, void, the TYPE_TAG and a
 * FUNC_PROTO, the last at an offset whose bit offset wraps.
 */
static int build_datasec_struct(struct btf *btf) {
	int err = 0;
	int i32, f32, a;

	i32 = add(&err, btf__add_int(btf, "int", 4, 0));
	f32 = add(&err, btf__add_float(btf, "float", 4));
	a   = add(&err, btf__add_var(btf, "a", BTF_VAR_STATIC, i32));
	add(&err, btf__add_datasec(btf, "?a.b?", 32));
	add(&err, btf__add_datasec_var_info(btf, a, 4, 4));
	add(&err, btf__add_datasec_var_info(btf, f32, 8, 4));
	add(&err, btf__add_datasec_var_info(btf, 0, 12, 0));
	add(&err, btf__add_datasec_var_info(btf, 5, 16, 4));
	add(&err, btf__add_datasec_var_info(btf, 7, 0x20000001, 1));
	add(&err, btf__add_type_tag(btf, "tt", i32));
	add(&err, btf__add_typedef(btf, "?a.b?", i32));
	add(&err, btf__add_func_proto(btf, 0));
	return err;
}

/* A DATASEC that the rewrite renames enum64_placeholder, before or after an
 * ENUM64.
 */
static int build_placeholder_name(struct btf *btf, bool datasec_first) {
	int err = 0;

	if (datasec_first)
		add(&err, btf__add_datasec(btf, "enum64.placeholder", 0));
	add(&err, btf__add_enum64(btf, "w", 8, false));
	add(&err, btf__add_enum64_value(btf, "L", 1));
	if (!datasec_first)
		add(&err, btf__add_datasec(btf, "enum64.placeholder", 0));
	return err;
}

static int build_placeholder_datasec_first(struct btf *btf) {
	return build_placeholder_name(btf, true);
}

static int build_placeholder_enum64_first(struct btf *btf) {
	return build_placeholder_name(btf, false);
}

/*
 * A case builds its types into an empty BTF, with libbpf's kind layout
 * section if add_layout. A nonzero hdr_len rewrites the blob with a header
 * of that many bytes: the first 32, or fewer, of the built header, zero
 * bytes after them but hdr_extra at byte 36, and the sections after it. A
 * nonzero layout_off is written into the header's layout_off field.
 */
struct sanitize_case {
	const char *name;
	int (*build)(struct btf *btf);
	bool add_layout;
	__u32 hdr_len;
	__u8 hdr_extra;
	__u32 layout_off;
};

static const struct sanitize_case sanitize_cases[] = {
	{.name = "zoo", .build = build_zoo},
	{.name = "zoo_layout", .build = build_zoo, .add_layout = true},
	{.name = "small_layout", .build = build_small, .add_layout = true},
	{.name = "layout_off_only", .build = build_small, .layout_off = 4},
	{.name = "hdr_zero_tail", .build = build_small, .hdr_len = 40},
	{.name = "hdr_extra", .build = build_small_no_enum64, .hdr_len = 40, .hdr_extra = 1},
	{.name = "hdr_extra_enum64", .build = build_small, .hdr_len = 40, .hdr_extra = 1},
	{.name = "hdr_extra_layout_enum64", .build = build_small, .add_layout = true, .hdr_len = 40, .hdr_extra = 1},
	{.name = "hdr_short", .build = build_small, .hdr_len = 28, .layout_off = 4},
	{.name = "datasec_struct", .build = build_datasec_struct},
	{.name = "placeholder_datasec_first", .build = build_placeholder_datasec_first},
	{.name = "placeholder_enum64_first", .build = build_placeholder_enum64_first},
};

static void raw_btf_json(struct json *j, const char *key, const struct btf *btf) {
	const void *data;
	__u32 size = 0;

	data = btf__raw_data(btf, &size);
	json_hex(j, key, data, data ? size : 0);
}

/* sanitized_json sanitizes btf for obj and prints the errno and, on
 * success, the copy.
 */
static void sanitized_json(struct json *j, struct bpf_object *obj, struct btf *btf) {
	struct btf *kern = bpf_object__sanitize_btf(obj, btf);
	long err         = IS_ERR(kern) ? PTR_ERR(kern) : 0;

	json_s32(j, "errno", (int32_t)-err);
	if (!err) {
		raw_btf_json(j, "sanitized", kern);
		btf__free(kern);
	}
}

/* reshape returns the BTF of built's blob with the header changes of c. */
static struct btf *reshape(const struct btf *built, const struct sanitize_case *c) {
	struct btf_header *hdr;
	const __u8 *raw;
	struct btf *btf;
	__u32 hdr_len, copy, size = 0;
	__u8 *buf;

	raw = btf__raw_data(built, &size);
	if (!raw || size < sizeof(*hdr))
		return NULL;
	hdr_len = c->hdr_len ? c->hdr_len : sizeof(*hdr);
	copy    = hdr_len < sizeof(*hdr) ? hdr_len : sizeof(*hdr);
	buf     = calloc(1, size - sizeof(*hdr) + hdr_len);
	if (!buf)
		return NULL;

	memcpy(buf, raw, copy);
	memcpy(buf + hdr_len, raw + sizeof(*hdr), size - sizeof(*hdr));
	hdr          = (struct btf_header *)buf;
	hdr->hdr_len = hdr_len;
	if (hdr_len > 36)
		buf[36] = c->hdr_extra;
	if (c->layout_off)
		hdr->layout_off = c->layout_off;

	btf = btf__new(buf, size - sizeof(*hdr) + hdr_len);
	free(buf);
	return IS_ERR(btf) ? NULL : btf;
}

/* case_json builds a synthetic case and prints its BTF and the sanitized
 * copy, or the errno.
 */
static int case_json(struct json *j, struct bpf_object *obj, const struct sanitize_case *c) {
	LIBBPF_OPTS(btf_new_opts, opts, .add_layout = c->add_layout);
	struct btf *built, *btf;
	int err;

	built = btf__new_empty_opts(&opts);
	if (!built) {
		fprintf(stderr, "case %s: btf__new_empty_opts: %s\n", c->name, strerror(errno));
		return -1;
	}
	err = c->build(built);
	if (err) {
		fprintf(stderr, "case %s: build: %s\n", c->name, strerror(-err));
		btf__free(built);
		return -1;
	}

	btf = built;
	if (c->hdr_len || c->layout_off) {
		btf = reshape(built, c);
		btf__free(built);
		if (!btf) {
			fprintf(stderr, "case %s: reshape the header\n", c->name);
			return -1;
		}
	}

	json_obj_begin(j, NULL);
	json_str(j, "name", c->name);
	raw_btf_json(j, "btf", btf);
	sanitized_json(j, obj, btf);
	json_obj_end(j);

	btf__free(btf);
	return 0;
}

/* object_json prints the object BTF after open and its sanitized copy. */
static void object_json(struct json *j, const char *path, struct bpf_object *obj) {
	json_obj_begin(j, NULL);
	json_str(j, "object", oracle_basename(path));
	raw_btf_json(j, "btf", bpf_object__btf(obj));
	sanitized_json(j, obj, bpf_object__btf(obj));
	json_obj_end(j);
}

int oracle_sanitize(const char *const *paths, int count) {
	struct oracle_meta meta = {.case_name = "sanitize", .version = true};
	struct bpf_object **objs;
	struct json j;
	int ret = 0;
	size_t c;
	int i;

	for (c = 0; c < ORACLE_ARRAY_SIZE(sanitize_features); c++) {
		if (feat_supported(NULL, sanitize_features[c].id)) {
			fprintf(stderr, "kernel supports BTF %s: run the sanitize scenario without CAP_BPF\n", sanitize_features[c].name);
			return 1;
		}
	}

	objs = calloc(count, sizeof(*objs));
	if (!objs)
		return 1;
	for (i = 0; i < count; i++) {
		objs[i] = bpf_object__open_file(paths[i], NULL);
		if (!objs[i]) {
			fprintf(stderr, "open %s: %s\n", paths[i], strerror(errno));
			ret = 1;
			goto out;
		}
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_obj_begin(&j, "features");
	for (c = 0; c < ORACLE_ARRAY_SIZE(sanitize_features); c++)
		json_bool(&j, sanitize_features[c].name, false);
	json_obj_end(&j);

	json_arr_begin(&j, "objects");
	for (i = 0; i < count; i++)
		object_json(&j, paths[i], objs[i]);
	json_arr_end(&j);

	json_arr_begin(&j, "cases");
	for (c = 0; c < ORACLE_ARRAY_SIZE(sanitize_cases); c++) {
		if (case_json(&j, objs[0], &sanitize_cases[c]) != 0)
			ret = 1;
	}
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);

out:
	for (i = 0; i < count; i++)
		bpf_object__close(objs[i]);
	free(objs);
	return ret;
}
