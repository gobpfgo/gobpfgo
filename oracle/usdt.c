// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

/*
 * The USDT note and argument parsers are static in libbpf's usdt.c, so this
 * file compiles the pinned copy into the oracle and calls them directly. The
 * angle brackets find it through -I$(LIBBPF_SRC), not this file. Its three
 * exported functions are renamed so they do not clash with the copy in
 * libbpf.a, and the -Wextra warnings libbpf's own build does not enable are
 * silenced for it.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define usdt_manager_new oracle_usdt_manager_new
#define usdt_manager_free oracle_usdt_manager_free
#define usdt_manager_attach_usdt oracle_usdt_manager_attach_usdt
#include <usdt.c>
#undef usdt_manager_new
#undef usdt_manager_free
#undef usdt_manager_attach_usdt
#pragma GCC diagnostic pop

#include "oracle.h"
#include "usdt_notes.h"

#include <elf.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * The scenario has three parts. "probes" lists the notes of the fixture
 * binary and their specs. "note_cases" lists the notes of the crafted ELF
 * images in usdt_notes.c and looks one probe up in each.
 * "spec_cases" parses argument specs for x86-64 and arm64.
 *
 * libbpf compiles one parse_usdt_arg, for the host. The x86-64 results come
 * from that real parser, so the scenario must run on x86-64. The arm64 cases
 * use the transcription of libbpf's aarch64 parser below.
 *
 * Inputs on which libbpf reads an uninitialized length are left out: a
 * pattern whose conversions all match but whose closing delimiter does not,
 * and the size INT_MIN, whose negation overflows. The Go tests cover them.
 */

#define USDT_MAX_NOTES 16

/* arm64 struct user_pt_regs from the kernel UAPI. */
struct oracle_arm64_user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
};

/*
 * calc_pt_regs_off and parse_usdt_arg of libbpf's aarch64 branch, with the
 * same sscanf patterns. libbpf writes the opening bracket as "\[", which GCC
 * reads as "[".
 */
static int arm64_calc_pt_regs_off(const char *reg_name) {
	int reg_num;

	if (sscanf(reg_name, "x%d", &reg_num) == 1) {
		if (reg_num >= 0 && reg_num < 31)
			return offsetof(struct oracle_arm64_user_pt_regs, regs[reg_num]);
	} else if (strcmp(reg_name, "sp") == 0) {
		return offsetof(struct oracle_arm64_user_pt_regs, sp);
	}

	return -ENOENT;
}

static int arm64_parse_usdt_arg(const char *arg_str, struct usdt_arg_spec *arg, int *arg_sz) {
	char reg_name[16];
	int len, reg_off;
	long off;

	if (sscanf(arg_str, " %d @ [ %15[a-z0-9] , %ld ] %n", arg_sz, reg_name, &off, &len) == 3) {
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off  = off;
		reg_off       = arm64_calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ [ %15[a-z0-9] ] %n", arg_sz, reg_name, &len) == 2) {
		arg->arg_type = USDT_ARG_REG_DEREF;
		arg->val_off  = 0;
		reg_off       = arm64_calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else if (sscanf(arg_str, " %d @ %ld %n", arg_sz, &off, &len) == 2) {
		arg->arg_type = USDT_ARG_CONST;
		arg->val_off  = off;
		arg->reg_off  = 0;
	} else if (sscanf(arg_str, " %d @ %15[a-z0-9] %n", arg_sz, reg_name, &len) == 2) {
		arg->arg_type = USDT_ARG_REG;
		arg->val_off  = 0;
		reg_off       = arm64_calc_pt_regs_off(reg_name);
		if (reg_off < 0)
			return reg_off;
		arg->reg_off = reg_off;
	} else {
		return -EINVAL;
	}

	return len;
}

/* parse_usdt_spec over the aarch64 operand parser. */
static int arm64_parse_usdt_spec(struct usdt_spec *spec, const char *args) {
	struct usdt_arg_spec *arg;
	const char *s;
	int arg_sz, len;

	spec->usdt_cookie = 0;
	spec->arg_cnt     = 0;

	s = args;
	while (s[0]) {
		if (spec->arg_cnt >= USDT_MAX_ARG_CNT)
			return -E2BIG;

		arg = &spec->args[spec->arg_cnt];
		len = arm64_parse_usdt_arg(s, arg, &arg_sz);
		if (len < 0)
			return len;

		arg->arg_signed = arg_sz < 0;
		if (arg_sz < 0)
			arg_sz = -arg_sz;

		switch (arg_sz) {
		case 1:
		case 2:
		case 4:
		case 8:
			arg->arg_bitshift = 64 - arg_sz * 8;
			break;
		default:
			return -EINVAL;
		}

		s += len;
		spec->arg_cnt++;
	}

	return 0;
}

static int usdt_parse_spec(const char *arch, const char *args, struct usdt_spec *spec) {
	struct usdt_note note = {.provider = "oracle", .name = "spec", .args = args};

	memset(spec, 0, sizeof(*spec));
	if (strcmp(arch, "arm64") == 0)
		return arm64_parse_usdt_spec(spec, args);

	return parse_usdt_spec(spec, &note, 0);
}

static const char *usdt_arg_type_name(enum usdt_arg_type type) {
	switch (type) {
	case USDT_ARG_CONST:
		return "USDT_ARG_CONST";
	case USDT_ARG_REG:
		return "USDT_ARG_REG";
	case USDT_ARG_REG_DEREF:
		return "USDT_ARG_REG_DEREF";
	case USDT_ARG_SIB:
		return "USDT_ARG_SIB";
	}

	return "USDT_ARG_UNKNOWN";
}

static void usdt_print_spec(struct json *j, const struct usdt_spec *spec) {
	const struct usdt_arg_spec *arg;
	int i;

	json_arr_begin(j, "spec");
	for (i = 0; i < spec->arg_cnt; i++) {
		arg = &spec->args[i];
		json_obj_begin_compact(j, NULL);
		json_str(j, "arg_type", usdt_arg_type_name(arg->arg_type));
		json_u32(j, "size", (64 - arg->arg_bitshift) / 8);
		json_bool(j, "arg_signed", arg->arg_signed);
		json_s64(j, "val_off", (int64_t)arg->val_off);
		json_s32(j, "reg_off", arg->reg_off);
		json_u32(j, "idx_reg_off", arg->idx_reg_off);
		json_u32(j, "scale_bitshift", arg->scale_bitshift);
		json_u32(j, "arg_bitshift", (uint32_t)arg->arg_bitshift);
		json_obj_end(j);
	}
	json_arr_end(j);
}

/* The spec of a note, or an empty one when parsing failed. */
static void usdt_print_parsed_spec(struct json *j, int err, const struct usdt_spec *spec) {
	struct usdt_spec empty = {0};

	json_s32(j, "errno", -err);
	usdt_print_spec(j, err ? &empty : spec);
}

static void usdt_print_note(struct json *j, const struct usdt_note *note) {
	json_str(j, "provider", note->provider);
	json_str(j, "name", note->name);
	json_str(j, "args", note->args);
	json_u64(j, "location", (uint64_t)note->loc_addr);
	json_u64(j, "base", (uint64_t)note->base_addr);
	json_u64(j, "semaphore", (uint64_t)note->sema_addr);
}

/*
 * What usdt_manager_attach_usdt and collect_usdt_targets check before their
 * note loop: elf_open, sanity_check_usdt_elf, the notes section and its type.
 * The .stapsdt.base address is 0 when the section is missing. The caller
 * closes elf_fd on success and on failure.
 */
static int usdt_open(const char *path, struct elf_fd *elf_fd, Elf_Data **data, long *base_addr) {
	GElf_Shdr notes_shdr, base_shdr;
	Elf_Scn *notes_scn, *base_scn;
	GElf_Ehdr ehdr;
	int err;

	*data      = NULL;
	*base_addr = 0;

	err = elf_open(path, elf_fd);
	if (err)
		return err;

	err = sanity_check_usdt_elf(elf_fd->elf, path);
	if (err)
		return err;

	err = find_elf_sec_by_name(elf_fd->elf, USDT_NOTE_SEC, &notes_shdr, &notes_scn);
	if (err)
		return err;

	if (notes_shdr.sh_type != SHT_NOTE || !gelf_getehdr(elf_fd->elf, &ehdr))
		return -EINVAL;

	if (find_elf_sec_by_name(elf_fd->elf, USDT_BASE_SEC, &base_shdr, &base_scn) == 0)
		*base_addr = base_shdr.sh_addr;

	*data = elf_getdata(notes_scn, 0);
	return 0;
}

/* Notes kept by usdt_collect, with the spec of each when it was parsed. */
struct usdt_list {
	struct usdt_note notes[USDT_MAX_NOTES];
	struct usdt_spec specs[USDT_MAX_NOTES];
	int count;
};

/*
 * The note loop of collect_usdt_targets. Every record goes through
 * parse_usdt_note. Without a provider every note is kept; with one, only the
 * matching notes are kept, after parse_usdt_spec, and no match is -ENOENT.
 * The first error ends the loop.
 */
static int usdt_collect(Elf_Data *data, const char *provider, const char *name, struct usdt_list *list) {
	size_t off = 0, name_off, desc_off;
	struct usdt_note *note;
	GElf_Nhdr nhdr;
	int err;

	list->count = 0;
	while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
		if (list->count >= USDT_MAX_NOTES) {
			fprintf(stderr, "usdt: more than %d notes\n", USDT_MAX_NOTES);
			exit(1);
		}

		note = &list->notes[list->count];
		err  = parse_usdt_note(&nhdr, data->d_buf, name_off, desc_off, note);
		if (err)
			return err;

		if (provider && (strcmp(note->provider, provider) != 0 || strcmp(note->name, name) != 0))
			continue;

		if (provider) {
			err = parse_usdt_spec(&list->specs[list->count], note, 0);
			if (err)
				return err;
		}

		list->count++;
	}

	if (provider && list->count == 0)
		return -ENOENT;

	return 0;
}

static int usdt_print_probes(struct json *j, const char *path) {
	struct usdt_list list;
	struct elf_fd elf_fd;
	struct usdt_spec spec;
	Elf_Data *data;
	GElf_Ehdr ehdr;
	long base_addr;
	int err, i;

	err = usdt_open(path, &elf_fd, &data, &base_addr);
	if (!err && (!gelf_getehdr(elf_fd.elf, &ehdr) || ehdr.e_machine != EM_X86_64))
		err = -EINVAL;

	if (!err)
		err = usdt_collect(data, NULL, NULL, &list);

	if (err) {
		fprintf(stderr, "usdt: %s: %s\n", path, strerror(-err));
		elf_close(&elf_fd);
		return 1;
	}

	json_str(j, "file", oracle_basename(path));
	json_u64(j, "stapsdt_base", (uint64_t)base_addr);
	json_arr_begin(j, "probes");
	for (i = 0; i < list.count; i++) {
		json_obj_begin(j, NULL);
		usdt_print_note(j, &list.notes[i]);
		err = parse_usdt_spec(&spec, &list.notes[i], 0);
		usdt_print_parsed_spec(j, err, &spec);
		json_obj_end(j);
	}
	json_arr_end(j);

	elf_close(&elf_fd);
	return 0;
}

/* Lists the notes and looks the probe up, as two separate walks. */
static void usdt_run_note_case(struct json *j, const struct usdt_note_case *c, const struct usdt_image *img, const char *path) {
	struct usdt_list list;
	struct elf_fd elf_fd;
	Elf_Data *data;
	long base_addr;
	int open_err, list_err, find_err, i;

	open_err = usdt_open(path, &elf_fd, &data, &base_addr);
	list_err = open_err ? open_err : usdt_collect(data, NULL, NULL, &list);

	json_obj_begin(j, NULL);
	json_str(j, "name", c->name);
	json_hex(j, "image", img->data, img->len);
	json_s32(j, "errno", -list_err);
	json_u64(j, "stapsdt_base", (uint64_t)base_addr);
	json_arr_begin(j, "notes");
	for (i = 0; !list_err && i < list.count; i++) {
		json_obj_begin_compact(j, NULL);
		usdt_print_note(j, &list.notes[i]);
		json_obj_end(j);
	}
	json_arr_end(j);

	find_err = open_err ? open_err : usdt_collect(data, c->provider, c->probe, &list);
	json_str(j, "lookup_provider", c->provider);
	json_str(j, "lookup_name", c->probe);
	json_s32(j, "find_errno", -find_err);
	json_arr_begin_compact(j, "found");
	for (i = 0; !find_err && i < list.count; i++)
		json_u64(j, NULL, (uint64_t)list.notes[i].loc_addr);
	json_arr_end(j);
	json_obj_end(j);

	elf_close(&elf_fd);
}

static int usdt_print_note_cases(struct json *j) {
	char dir[] = "/tmp/gobpfgo-usdt-XXXXXX";
	char path[PATH_MAX];
	struct usdt_image img;
	int ret = 0;
	size_t i;

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	snprintf(path, sizeof(path), "%s/target", dir);

	json_arr_begin(j, "note_cases");
	for (i = 0; i < usdt_note_case_count && ret == 0; i++) {
		usdt_build_image(&img, &usdt_note_cases[i]);
		ret = usdt_write_image(path, &img);
		if (ret == 0)
			usdt_run_note_case(j, &usdt_note_cases[i], &img, path);
	}
	json_arr_end(j);

	unlink(path);
	rmdir(dir);
	return ret ? 1 : 0;
}

/* Thirteen arm64 operands, one more than a spec may have. */
#define USDT_X013 "8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0 8@x0"

struct usdt_spec_case {
	const char *arch;
	const char *spec;
};

static const struct usdt_spec_case usdt_spec_cases[] = {
	/* x86-64: libbpf's own example, every register name and empty specs. */
	{"amd64", "-4@-1204(%rbp) -4@%edi -8@-1216(%rbp) -8@%r8 -4@$5 -8@%r9 8@%rdx 8@%r10 -4@$-9 -2@%cx -2@%ax -1@%sil"},
	{"amd64", ""},
	{"amd64", "8@%rip -4@%eip"},
	{"amd64", "8@%rax -4@%eax 2@%ax -1@%al"},
	{"amd64", "8@%rbx -4@%ebx 2@%bx -1@%bl"},
	{"amd64", "8@%rcx -4@%ecx 2@%cx -1@%cl"},
	{"amd64", "8@%rdx -4@%edx 2@%dx -1@%dl"},
	{"amd64", "8@%rsi -4@%esi 2@%si -1@%sil"},
	{"amd64", "8@%rdi -4@%edi 2@%di -1@%dil"},
	{"amd64", "8@%rbp -4@%ebp 2@%bp -1@%bpl"},
	{"amd64", "8@%rsp -4@%esp 2@%sp -1@%spl"},
	{"amd64", "8@%r8 -4@%r8d 2@%r8w -1@%r8b"},
	{"amd64", "8@%r9 -4@%r9d 2@%r9w -1@%r9b"},
	{"amd64", "8@%r10 -4@%r10d 2@%r10w -1@%r10b"},
	{"amd64", "8@%r11 -4@%r11d 2@%r11w -1@%r11b"},
	{"amd64", "8@%r12 -4@%r12d 2@%r12w -1@%r12b"},
	{"amd64", "8@%r13 -4@%r13d 2@%r13w -1@%r13b"},
	{"amd64", "8@%r14 -4@%r14d 2@%r14w -1@%r14b"},
	{"amd64", "8@%r15 -4@%r15d 2@%r15w -1@%r15b"},
	/* x86-64 memory references. */
	{"amd64", "-4@-20(%rbp) 8@(%rsp) -8@16(%rsp) 2@+8(%r15)"},
	{"amd64", "1@-96(%rbp,%rax,8) -2@(%rbx,%rcx,4) 4@64(%rsi,%rdi) -8@(%r12,%r13) 8@0(%rsp,%r8,2)"},
	{"amd64", "1@-1(%rbp,%rax,3)"},
	{"amd64", "1@(%rbp,%rax,16)"},
	{"amd64", "1@(%rbp,%xmm0)"},
	{"amd64", "1@-96 ( %rbp , %rax , 8 )"},
	{"amd64", "8@ ( %rsp )"},
	/* x86-64 immediates and number limits. */
	{"amd64", "-4@$-9 8@$5 4@$ 5"},
	{"amd64", "8@$99999999999999999999 -8@$-99999999999999999999"},
	{"amd64", "8@$0x10"},
	{"amd64", "8@$sym"},
	{"amd64", "4294967297@%rax"},
	{"amd64", "99999999999999999999@%rax"},
	/* x86-64 white space. */
	{"amd64", "  8@%rax   -4@$5  "},
	{"amd64", "8 @ %rax"},
	{"amd64", "8@% rax"},
	{"amd64", "- 4@$5"},
	{"amd64", "   "},
	/* x86-64 errors. */
	{"amd64", "3@%rax"},
	{"amd64", "0@%rax"},
	{"amd64", "16@%rax"},
	{"amd64", "8@%rax 3@%rbx"},
	{"amd64", "8@%xmm0"},
	{"amd64", "8@%eflags"},
	{"amd64", "8@%abcdefghijklmnopq"},
	{"amd64", "8@%rax,8@%rbx"},
	{"amd64", "8@rax"},
	{"amd64", "8%rax"},
	{"amd64", "@%rax"},
	{"amd64", "-8@counter(%rip)"},
	{"amd64", USDT_AL13},
	/* arm64 forms. */
	{"arm64", "-4@[sp, 96] -4@[sp] 8@[x29, -12] -8@[x0,8] 4@[ x1 , 16 ]"},
	{"arm64", "4@5 -8@-9 8@99999999999999999999"},
	{"arm64", "-8@x4 8@sp 8@x0 8@x30 -4@x05 8@x5abc 8@x4294967296"},
	{"arm64", ""},
	/* arm64 errors. */
	{"arm64", "8@x31"},
	{"arm64", "8@xzr"},
	{"arm64", "-4@w0"},
	{"arm64", "8@x"},
	{"arm64", "8@pc"},
	{"arm64", "8@[pc]"},
	{"arm64", "8@[x99, 8]"},
	{"arm64", "8@abcdefghijklmnopq"},
	{"arm64", "8@%x0"},
	{"arm64", "3@x0"},
	{"arm64", "-4@%edi"},
	{"arm64", USDT_X013},
};

static void usdt_print_spec_cases(struct json *j) {
	struct usdt_spec spec;
	size_t i;
	int err;

	json_arr_begin(j, "spec_cases");
	for (i = 0; i < ORACLE_ARRAY_SIZE(usdt_spec_cases); i++) {
		err = usdt_parse_spec(usdt_spec_cases[i].arch, usdt_spec_cases[i].spec, &spec);
		json_obj_begin(j, NULL);
		json_str(j, "arch", usdt_spec_cases[i].arch);
		json_str(j, "args", usdt_spec_cases[i].spec);
		usdt_print_parsed_spec(j, err, &spec);
		json_obj_end(j);
	}
	json_arr_end(j);
}

int oracle_usdt(const char *path) {
	struct oracle_meta meta = {.case_name = "usdt", .commit = true};
	struct json j;
	int ret;

#ifndef __x86_64__
	fprintf(stderr, "usdt: run the scenario on x86-64; its specs come from libbpf's x86-64 parser\n");
	return 1;
#endif

	libbpf_set_print(NULL);

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	ret = usdt_print_probes(&j, path);
	if (ret == 0)
		ret = usdt_print_note_cases(&j);

	if (ret == 0)
		usdt_print_spec_cases(&j);

	json_obj_end(&j);
	fputc('\n', stdout);
	return ret;
}
