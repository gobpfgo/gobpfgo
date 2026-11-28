// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// Target BTF for the CO-RE type match test. core_match.bpf.c checks local
// flavors of these types against them with bpf_core_type_matches and the
// other type-based relocations. The global variables keep every type in the
// BTF.

enum cm_enum {
	CM_ONE   = 1,
	CM_TWO   = 2,
	CM_THREE = 3,
};

enum cm_enum64 {
	CM64_LOW  = 1,
	CM64_HIGH = 0x100000000ULL,
};

struct cm_inner {
	int a;
	long b;
};

// Declared only, so the target has forward declarations behind pointers.
struct cm_fwd;
union cm_fwd_union;

union cm_union {
	int i;
	long l;
};

typedef unsigned int cm_u32;

struct cm_struct {
	int i;
	cm_u32 u;
	long l;
	const volatile int cv;
	struct cm_inner inner;
	struct cm_inner *inner_ptr;
	struct cm_fwd *fwd_ptr;
	union cm_fwd_union *fwd_union_ptr;
	struct cm_inner *complete_ptr;
	int arr[4];
	int matrix[2][3];
	enum cm_enum e;
	int (*fn)(int, long);
	union {
		int ui;
		long ul;
	};
	struct {
		char c;
		short s;
	} anon_type;
	union cm_union un;
};

typedef struct cm_struct cm_struct_t;
typedef int (*cm_fn_t)(int, long);

// Two candidates for one local type, of different sizes.
struct cm_dup {
	int a;
};

struct cm_dup___v2 {
	int a;
	long b;
};

// Four underscores in a row are not a flavor separator.
struct cm____odd {
	int x;
};

// 32 nested structs take the match one level too deep; 31 do not.
#define CM_NEST(name, n, next) \
	struct name##n { \
		struct name##next m; \
	}

#define CM_NEST_LEAF(name, n) \
	struct name##n { \
		int leaf; \
	}

CM_NEST_LEAF(cm_deep, 31);
CM_NEST(cm_deep, 30, 31);
CM_NEST(cm_deep, 29, 30);
CM_NEST(cm_deep, 28, 29);
CM_NEST(cm_deep, 27, 28);
CM_NEST(cm_deep, 26, 27);
CM_NEST(cm_deep, 25, 26);
CM_NEST(cm_deep, 24, 25);
CM_NEST(cm_deep, 23, 24);
CM_NEST(cm_deep, 22, 23);
CM_NEST(cm_deep, 21, 22);
CM_NEST(cm_deep, 20, 21);
CM_NEST(cm_deep, 19, 20);
CM_NEST(cm_deep, 18, 19);
CM_NEST(cm_deep, 17, 18);
CM_NEST(cm_deep, 16, 17);
CM_NEST(cm_deep, 15, 16);
CM_NEST(cm_deep, 14, 15);
CM_NEST(cm_deep, 13, 14);
CM_NEST(cm_deep, 12, 13);
CM_NEST(cm_deep, 11, 12);
CM_NEST(cm_deep, 10, 11);
CM_NEST(cm_deep, 9, 10);
CM_NEST(cm_deep, 8, 9);
CM_NEST(cm_deep, 7, 8);
CM_NEST(cm_deep, 6, 7);
CM_NEST(cm_deep, 5, 6);
CM_NEST(cm_deep, 4, 5);
CM_NEST(cm_deep, 3, 4);
CM_NEST(cm_deep, 2, 3);
CM_NEST(cm_deep, 1, 2);
CM_NEST(cm_deep, 0, 1);

CM_NEST_LEAF(cm_shallow, 30);
CM_NEST(cm_shallow, 29, 30);
CM_NEST(cm_shallow, 28, 29);
CM_NEST(cm_shallow, 27, 28);
CM_NEST(cm_shallow, 26, 27);
CM_NEST(cm_shallow, 25, 26);
CM_NEST(cm_shallow, 24, 25);
CM_NEST(cm_shallow, 23, 24);
CM_NEST(cm_shallow, 22, 23);
CM_NEST(cm_shallow, 21, 22);
CM_NEST(cm_shallow, 20, 21);
CM_NEST(cm_shallow, 19, 20);
CM_NEST(cm_shallow, 18, 19);
CM_NEST(cm_shallow, 17, 18);
CM_NEST(cm_shallow, 16, 17);
CM_NEST(cm_shallow, 15, 16);
CM_NEST(cm_shallow, 14, 15);
CM_NEST(cm_shallow, 13, 14);
CM_NEST(cm_shallow, 12, 13);
CM_NEST(cm_shallow, 11, 12);
CM_NEST(cm_shallow, 10, 11);
CM_NEST(cm_shallow, 9, 10);
CM_NEST(cm_shallow, 8, 9);
CM_NEST(cm_shallow, 7, 8);
CM_NEST(cm_shallow, 6, 7);
CM_NEST(cm_shallow, 5, 6);
CM_NEST(cm_shallow, 4, 5);
CM_NEST(cm_shallow, 3, 4);
CM_NEST(cm_shallow, 2, 3);
CM_NEST(cm_shallow, 1, 2);
CM_NEST(cm_shallow, 0, 1);

// A chain of 32 pointers takes 33 steps to its int, one more than a match or
// a compatibility check follows; 31 pointers take 32.
struct cm_ptr_deep {
	int ********************************p;
};

struct cm_ptr_ok {
	int *******************************p;
};

typedef int ********************************cm_ptr_deep_t;
typedef int *******************************cm_ptr_ok_t;

struct cm_struct target_struct;
cm_struct_t target_struct_t;
cm_fn_t target_fn;
union cm_union target_union;
enum cm_enum64 target_enum64;
struct cm_dup target_dup;
struct cm_dup___v2 target_dup_v2;
struct cm____odd target_odd;
struct cm_deep0 target_deep;
struct cm_shallow0 target_shallow;
struct cm_ptr_deep target_ptr_deep;
struct cm_ptr_ok target_ptr_ok;
cm_ptr_deep_t target_ptr_deep_t;
cm_ptr_ok_t target_ptr_ok_t;
