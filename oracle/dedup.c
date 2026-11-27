// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "btf.h"
#include "libbpf.h"

#include <linux/btf.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* A synthetic case builds its types into an empty BTF and returns 0 or the
 * first negative error of a btf__add_* call.
 */
struct dedup_case {
	const char *name;
	int (*build)(struct btf *btf);
};

/* add keeps the first error of a sequence of btf__add_* calls and returns the
 * call's result, a type ID or 0 for the member and value adds.
 */
static int add(int *err, int ret) {
	if (ret < 0 && !*err)
		*err = ret;
	return ret;
}

static int case_int_dup(struct btf *btf) {
	int err = 0;

	add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	add(&err, btf__add_int(btf, "int", 4, 0));
	add(&err, btf__add_float(btf, "float", 4));
	add(&err, btf__add_float(btf, "float", 4));
	return err;
}

/* An enum forward declaration before and after the full enum, and an ENUM
 * forward declaration of an ENUM64.
 */
static int case_enum_fwd(struct btf *btf) {
	int err = 0;
	int fwd, full, fwd2, fwd64, full64;

	fwd  = add(&err, btf__add_fwd(btf, "e", BTF_FWD_ENUM));
	full = add(&err, btf__add_enum(btf, "e", 4));
	add(&err, btf__add_enum_value(btf, "A", 1));
	fwd2 = add(&err, btf__add_fwd(btf, "e", BTF_FWD_ENUM));
	add(&err, btf__add_ptr(btf, fwd));
	add(&err, btf__add_ptr(btf, full));
	add(&err, btf__add_ptr(btf, fwd2));

	fwd64  = add(&err, btf__add_fwd(btf, "e64", BTF_FWD_ENUM));
	full64 = add(&err, btf__add_enum64(btf, "e64", 8, false));
	add(&err, btf__add_enum64_value(btf, "B", 1ULL << 40));
	add(&err, btf__add_ptr(btf, fwd64));
	add(&err, btf__add_ptr(btf, full64));
	return err;
}

/* Two different full enums named e, then a forward declaration and a
 * pointer to it. The declaration resolves to the first candidate in hash
 * table order, which depends on whether the table grew between the two
 * enums, and the pointer shows which one.
 */
static int enum_two_full(struct btf *btf, bool grow) {
	int err = 0;
	int fwd;

	add(&err, btf__add_enum(btf, "e", 4));
	add(&err, btf__add_enum_value(btf, "A", 1));
	add(&err, btf__add_enum(btf, "e", 4));
	add(&err, btf__add_enum_value(btf, "B", 2));
	if (grow) {
		add(&err, btf__add_int(btf, "a", 4, 0));
		add(&err, btf__add_int(btf, "b", 4, 0));
	}
	fwd = add(&err, btf__add_fwd(btf, "e", BTF_FWD_ENUM));
	add(&err, btf__add_ptr(btf, fwd));
	return err;
}

static int case_enum_two_full(struct btf *btf) {
	return enum_two_full(btf, false);
}

static int case_enum_two_full_grow(struct btf *btf) {
	return enum_two_full(btf, true);
}

/* struct s { struct s *next; int x; }, emitted by two compilation units. */
static int struct_cycle_cu(struct btf *btf) {
	int err = 0;
	int i, s;

	/* Fields go right after their struct, so the pointer comes last. */
	i = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	s = add(&err, btf__add_struct(btf, "s", 16));
	add(&err, btf__add_field(btf, "next", s + 1, 0, 0));
	add(&err, btf__add_field(btf, "x", i, 64, 0));
	add(&err, btf__add_ptr(btf, s));
	return err;
}

static int case_struct_cycle(struct btf *btf) {
	int err = struct_cycle_cu(btf);

	return err ? err : struct_cycle_cu(btf);
}

/* struct A { struct B *p; } with B a forward declaration in the first unit
 * and a full struct in the second. A third unit defines another struct B, so
 * only the comparison of the two A graphs can resolve the declaration.
 */
static int case_fwd_member(struct btf *btf) {
	int err = 0;
	int i, a, fwd, b;

	fwd = add(&err, btf__add_fwd(btf, "B", BTF_FWD_STRUCT));
	add(&err, btf__add_struct(btf, "A", 8));
	add(&err, btf__add_field(btf, "p", fwd + 2, 0, 0));
	add(&err, btf__add_ptr(btf, fwd));

	i = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	b = add(&err, btf__add_struct(btf, "B", 4));
	add(&err, btf__add_field(btf, "x", i, 0, 0));
	a = add(&err, btf__add_struct(btf, "A", 8));
	add(&err, btf__add_field(btf, "p", a + 1, 0, 0));
	add(&err, btf__add_ptr(btf, b));

	add(&err, btf__add_struct(btf, "B", 4));
	add(&err, btf__add_field(btf, "y", i, 0, 0));
	return err;
}

/* The example of libbpf's dedup documentation: each unit knows one of A and
 * B in full and the other as a forward declaration.
 */
static int case_two_units(struct btf *btf) {
	int err = 0;
	int i, s_fwd, a, b, b_fwd, s, pa, ps, pb;

	/* unit 1: struct S; struct A { int a; struct A *self; struct S *parent; };
	 * struct B; struct S { struct A *a_ptr; struct B *b_ptr; };
	 */
	i     = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	s_fwd = add(&err, btf__add_fwd(btf, "S", BTF_FWD_STRUCT));
	a     = add(&err, btf__add_struct(btf, "A", 24));
	pa    = a + 1;
	ps    = a + 2;
	add(&err, btf__add_field(btf, "a", i, 0, 0));
	add(&err, btf__add_field(btf, "self", pa, 64, 0));
	add(&err, btf__add_field(btf, "parent", ps, 128, 0));
	add(&err, btf__add_ptr(btf, a));
	add(&err, btf__add_ptr(btf, s_fwd));
	b_fwd = add(&err, btf__add_fwd(btf, "B", BTF_FWD_STRUCT));
	s     = add(&err, btf__add_struct(btf, "S", 16));
	add(&err, btf__add_field(btf, "a_ptr", pa, 0, 0));
	add(&err, btf__add_field(btf, "b_ptr", s + 1, 64, 0));
	add(&err, btf__add_ptr(btf, b_fwd));

	/* unit 2: struct S; struct A; struct B { int b; struct B *self;
	 * struct S *parent; }; struct S { struct A *a_ptr; struct B *b_ptr; };
	 */
	i     = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	s_fwd = add(&err, btf__add_fwd(btf, "S", BTF_FWD_STRUCT));
	a     = add(&err, btf__add_fwd(btf, "A", BTF_FWD_STRUCT));
	b     = add(&err, btf__add_struct(btf, "B", 24));
	pb    = b + 1;
	ps    = b + 2;
	add(&err, btf__add_field(btf, "b", i, 0, 0));
	add(&err, btf__add_field(btf, "self", pb, 64, 0));
	add(&err, btf__add_field(btf, "parent", ps, 128, 0));
	add(&err, btf__add_ptr(btf, b));
	add(&err, btf__add_ptr(btf, s_fwd));
	s = add(&err, btf__add_struct(btf, "S", 16));
	add(&err, btf__add_field(btf, "a_ptr", s + 1, 0, 0));
	add(&err, btf__add_field(btf, "b_ptr", pb, 64, 0));
	add(&err, btf__add_ptr(btf, a));
	return err;
}

/* A forward declaration that no type graph links to its struct, resolved by
 * name; one with two candidate structs; and a union declaration of a struct
 * name.
 */
static int case_fwd_names(struct btf *btf) {
	int err = 0;
	int i, fwd;

	i   = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
	fwd = add(&err, btf__add_fwd(btf, "unique", BTF_FWD_STRUCT));
	add(&err, btf__add_ptr(btf, fwd));
	add(&err, btf__add_struct(btf, "unique", 4));
	add(&err, btf__add_field(btf, "u", i, 0, 0));
	add(&err, btf__add_ptr(btf, fwd + 2));

	fwd = add(&err, btf__add_fwd(btf, "twice", BTF_FWD_STRUCT));
	add(&err, btf__add_struct(btf, "twice", 4));
	add(&err, btf__add_field(btf, "u", i, 0, 0));
	add(&err, btf__add_struct(btf, "twice", 8));
	add(&err, btf__add_field(btf, "v", i, 32, 0));
	add(&err, btf__add_ptr(btf, fwd));

	fwd = add(&err, btf__add_fwd(btf, "kind", BTF_FWD_UNION));
	add(&err, btf__add_struct(btf, "kind", 4));
	add(&err, btf__add_field(btf, "u", i, 0, 0));
	add(&err, btf__add_ptr(btf, fwd));
	return err;
}

/* Unions, bitfields, anonymous members and structs that differ only in a
 * member name.
 */
static int case_struct_kinds(struct btf *btf) {
	int err = 0;
	int i, l, n;

	for (n = 0; n < 2; n++) {
		i = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
		l = add(&err, btf__add_int(btf, "long", 8, BTF_INT_SIGNED));
		add(&err, btf__add_union(btf, "u", 8));
		add(&err, btf__add_field(btf, "a", i, 0, 0));
		add(&err, btf__add_field(btf, "b", l, 0, 0));
		add(&err, btf__add_struct(btf, "bits", 4));
		add(&err, btf__add_field(btf, "lo", i, 0, 3));
		add(&err, btf__add_field(btf, "hi", i, 3, 5));
		add(&err, btf__add_struct(btf, NULL, 8));
		add(&err, btf__add_field(btf, NULL, l, 0, 0));
	}
	add(&err, btf__add_struct(btf, "bits", 4));
	add(&err, btf__add_field(btf, "lo", i, 0, 3));
	add(&err, btf__add_field(btf, "high", i, 3, 5));
	return err;
}

/* Modifier, pointer, typedef and tag chains, function prototypes and
 * functions, and arrays, each emitted twice.
 */
static int case_ref_chains(struct btf *btf) {
	int err = 0;
	int i, t, c, v, p, r, proto, n;

	for (n = 0; n < 2; n++) {
		i = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
		t = add(&err, btf__add_typedef(btf, "t", i));
		c = add(&err, btf__add_const(btf, t));
		v = add(&err, btf__add_volatile(btf, c));
		p = add(&err, btf__add_ptr(btf, v));
		r = add(&err, btf__add_restrict(btf, p));
		add(&err, btf__add_type_tag(btf, "tag", r));
		proto = add(&err, btf__add_func_proto(btf, i));
		add(&err, btf__add_func_param(btf, "a", i));
		add(&err, btf__add_func_param(btf, "b", p));
		add(&err, btf__add_func(btf, "f", BTF_FUNC_GLOBAL, proto));
		add(&err, btf__add_func(btf, n ? "g" : "f", BTF_FUNC_STATIC, proto));
		add(&err, btf__add_array(btf, i, t, 4));
		add(&err, btf__add_array(btf, i, i, n ? 5 : 4));
	}
	return err;
}

/* Variables and data sections are never merged, but the types they use
 * are; declaration tags on a struct and on its member are.
 */
static int case_vars_and_tags(struct btf *btf) {
	int err = 0;
	int i, v1, v2, s, n;

	for (n = 0; n < 2; n++) {
		i = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
		s = add(&err, btf__add_struct(btf, "s", 4));
		add(&err, btf__add_field(btf, "a", i, 0, 0));
		add(&err, btf__add_decl_tag(btf, "tag", s, -1));
		add(&err, btf__add_decl_tag(btf, "tag", s, 0));
	}
	v1 = add(&err, btf__add_var(btf, "v", BTF_VAR_GLOBAL_ALLOCATED, i));
	v2 = add(&err, btf__add_var(btf, "v", BTF_VAR_GLOBAL_ALLOCATED, i));
	add(&err, btf__add_datasec(btf, ".data", 8));
	add(&err, btf__add_datasec_var_info(btf, v1, 0, 4));
	add(&err, btf__add_datasec_var_info(btf, v2, 4, 4));
	add(&err, btf__add_datasec(btf, ".data", 8));
	add(&err, btf__add_datasec_var_info(btf, v1, 0, 4));
	return err;
}

/* One unit uses one array type for two members, the other emits two
 * identical arrays; the structs are still equivalent.
 */
static int case_identical_arrays(struct btf *btf) {
	int err = 0;
	int i, arr, arr2, n;

	for (n = 0; n < 2; n++) {
		i    = add(&err, btf__add_int(btf, "int", 4, BTF_INT_SIGNED));
		arr  = add(&err, btf__add_array(btf, i, i, 4));
		arr2 = n ? add(&err, btf__add_array(btf, i, i, 4)) : arr;
		add(&err, btf__add_struct(btf, "s", 32));
		add(&err, btf__add_field(btf, "a", arr, 0, 0));
		add(&err, btf__add_field(btf, "b", arr2, 128, 0));
	}
	return err;
}

/* typedef t *t, a cycle through a typedef, emitted twice. */
static int case_typedef_cycle(struct btf *btf) {
	int err = 0;
	int t, n;

	for (n = 0; n < 2; n++) {
		t = btf__type_cnt(btf);
		add(&err, btf__add_typedef(btf, "t", t + 1));
		add(&err, btf__add_ptr(btf, t));
	}
	return err;
}

/* A pointer and a const that refer to each other, which dedup rejects. */
static int case_ref_loop(struct btf *btf) {
	int err = 0;

	add(&err, btf__add_ptr(btf, 2));
	add(&err, btf__add_const(btf, 1));
	return err;
}

static const struct dedup_case dedup_cases[] = {
	{"int_dup", case_int_dup},
	{"enum_fwd", case_enum_fwd},
	{"enum_two_full", case_enum_two_full},
	{"enum_two_full_grow", case_enum_two_full_grow},
	{"struct_cycle", case_struct_cycle},
	{"fwd_member", case_fwd_member},
	{"two_units", case_two_units},
	{"fwd_names", case_fwd_names},
	{"struct_kinds", case_struct_kinds},
	{"ref_chains", case_ref_chains},
	{"vars_and_tags", case_vars_and_tags},
	{"identical_arrays", case_identical_arrays},
	{"typedef_cycle", case_typedef_cycle},
	{"ref_loop", case_ref_loop},
};

static void raw_btf_json(struct json *j, const char *key, const struct btf *btf) {
	const void *data;
	__u32 size = 0;

	data = btf__raw_data(btf, &size);
	json_hex(j, key, data, data ? size : 0);
}

static void raw_btf_ext_json(struct json *j, const char *key, const struct btf_ext *ext) {
	const void *data = NULL;
	__u32 size       = 0;

	if (ext)
		data = btf_ext__raw_data(ext, &size);
	json_hex(j, key, data, data ? size : 0);
}

/* object_json dedups the .BTF of an object with its .BTF.ext and prints both
 * sections after dedup.
 */
static int object_json(struct json *j, const char *path) {
	LIBBPF_OPTS(btf_dedup_opts, opts);
	struct btf_ext *ext = NULL;
	struct btf *btf;
	int err;

	btf = btf__parse_elf(path, &ext);
	if (!btf) {
		fprintf(stderr, "btf__parse_elf %s: %s\n", path, strerror(errno));
		return -1;
	}

	opts.btf_ext = ext;
	err          = btf__dedup(btf, &opts);

	json_obj_begin(j, NULL);
	json_str(j, "object", oracle_basename(path));
	json_s32(j, "errno", err ? -err : 0);
	if (!err) {
		raw_btf_json(j, "btf", btf);
		raw_btf_ext_json(j, "btf_ext", ext);
	}
	json_obj_end(j);

	btf_ext__free(ext);
	btf__free(btf);
	return 0;
}

/* case_json builds a synthetic case and prints its BTF before and after
 * dedup, or the dedup errno.
 */
static int case_json(struct json *j, const struct dedup_case *c) {
	struct btf *btf;
	int err;

	btf = btf__new_empty();
	if (!btf) {
		fprintf(stderr, "btf__new_empty: %s\n", strerror(errno));
		return -1;
	}

	err = c->build(btf);
	if (err) {
		fprintf(stderr, "case %s: build: %s\n", c->name, strerror(-err));
		btf__free(btf);
		return -1;
	}

	json_obj_begin(j, NULL);
	json_str(j, "name", c->name);
	raw_btf_json(j, "input", btf);
	err = btf__dedup(btf, NULL);
	json_s32(j, "errno", err ? -err : 0);
	if (!err)
		raw_btf_json(j, "output", btf);
	json_obj_end(j);

	btf__free(btf);
	return 0;
}

int oracle_dedup(const char *const *paths, int count) {
	struct oracle_meta meta = {.case_name = "dedup", .version = true};
	struct json j;
	int ret = 0;
	size_t c;
	int i;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_arr_begin(&j, "objects");
	for (i = 0; i < count; i++) {
		if (object_json(&j, paths[i]) != 0)
			ret = 1;
	}
	json_arr_end(&j);

	json_arr_begin(&j, "cases");
	for (c = 0; c < ORACLE_ARRAY_SIZE(dedup_cases); c++) {
		if (case_json(&j, &dedup_cases[c]) != 0)
			ret = 1;
	}
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);
	return ret;
}
