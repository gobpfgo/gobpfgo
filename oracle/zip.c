// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"
#include "zip.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Each case builds a small archive in memory, optionally patches one field,
 * writes it to a temporary file and looks one name up with zip_archive_open
 * and zip_archive_find_entry. The output carries the archive bytes so the Go
 * test can replay the same file.
 */

#define ZIP_MAX_SIZE 512
#define ZIP_MAX_MEMBERS 4

#define ZIP_LFH_MAGIC 0x04034b50
#define ZIP_CDFH_MAGIC 0x02014b50
#define ZIP_EOCD_MAGIC 0x06054b50
#define ZIP_VERSION 20
#define ZIP_DEFLATE 8

#define ZIP_FLAG_ENCRYPTED (1 << 0)
#define ZIP_FLAG_DATA_DESCRIPTOR (1 << 3)

/* Offsets of the fields the cases patch, from the start of each record. */
#define ZIP_LFH_FLAGS 6
#define ZIP_LFH_COMPRESSED_SIZE 18
#define ZIP_CDFH_FLAGS 8
#define ZIP_EOCD_THIS_DISK 4
#define ZIP_EOCD_CD_DISK 6
#define ZIP_EOCD_CD_RECORDS 8
#define ZIP_EOCD_CD_RECORDS_TOTAL 10
#define ZIP_EOCD_CD_OFFSET 16

#define ZIP_MEMBERS(arr) .members = arr, .member_count = ORACLE_ARRAY_SIZE(arr)

/*
 * One stored member. The extra field and comment are zero bytes; the extra
 * field is written to both headers and the comment to the central directory.
 * The CRC is left zero because the reader never checks it.
 */
struct zip_member {
	const char *name;
	const char *data;
	uint16_t compression;
	uint16_t extra_length;
	uint16_t comment_length;
};

/* An archive image and the offset of every record the patches change. */
struct zip_image {
	uint8_t data[ZIP_MAX_SIZE];
	size_t len;
	size_t lfh[ZIP_MAX_MEMBERS];
	size_t cdfh[ZIP_MAX_MEMBERS];
	size_t eocd;
};

struct zip_case {
	const char *name;
	const char *lookup;
	const struct zip_member *members;
	size_t member_count;
	const char *comment;
	void (*patch)(struct zip_image *img);
};

static void zip_put(struct zip_image *img, const void *src, size_t len) {
	if (img->len + len > sizeof(img->data)) {
		fprintf(stderr, "zip: archive larger than %d bytes\n", ZIP_MAX_SIZE);
		exit(1);
	}

	if (len)
		memcpy(img->data + img->len, src, len);
	img->len += len;
}

static void zip_put_zeros(struct zip_image *img, size_t len) {
	static const uint8_t zeros[ZIP_MAX_SIZE];

	zip_put(img, zeros, len);
}

static uint16_t zip_get_u16(const struct zip_image *img, size_t off) {
	return img->data[off] | img->data[off + 1] << 8;
}

static void zip_set_u16(struct zip_image *img, size_t off, uint16_t v) {
	img->data[off]     = v & 0xff;
	img->data[off + 1] = v >> 8;
}

static void zip_set_u32(struct zip_image *img, size_t off, uint32_t v) {
	zip_set_u16(img, off, v & 0xffff);
	zip_set_u16(img, off + 2, v >> 16);
}

static void zip_put_u16(struct zip_image *img, uint16_t v) {
	zip_put_zeros(img, 2);
	zip_set_u16(img, img->len - 2, v);
}

static void zip_put_u32(struct zip_image *img, uint32_t v) {
	zip_put_zeros(img, 4);
	zip_set_u32(img, img->len - 4, v);
}

/* The fields a local file header and a central directory header share. */
static void zip_put_common(struct zip_image *img, const struct zip_member *m) {
	uint32_t data_len = strlen(m->data);

	zip_put_u16(img, ZIP_VERSION);
	zip_put_u16(img, 0);
	zip_put_u16(img, m->compression);
	zip_put_u32(img, 0);
	zip_put_u32(img, 0);
	zip_put_u32(img, data_len);
	zip_put_u32(img, data_len);
	zip_put_u16(img, strlen(m->name));
	zip_put_u16(img, m->extra_length);
}

static void zip_put_local(struct zip_image *img, const struct zip_member *m) {
	zip_put_u32(img, ZIP_LFH_MAGIC);
	zip_put_common(img, m);
	zip_put(img, m->name, strlen(m->name));
	zip_put_zeros(img, m->extra_length);
	zip_put(img, m->data, strlen(m->data));
}

static void zip_put_central(struct zip_image *img, const struct zip_member *m, uint32_t lfh_offset) {
	zip_put_u32(img, ZIP_CDFH_MAGIC);
	zip_put_u16(img, ZIP_VERSION);
	zip_put_common(img, m);
	zip_put_u16(img, m->comment_length);
	zip_put_u16(img, 0);
	zip_put_u16(img, 0);
	zip_put_u32(img, 0);
	zip_put_u32(img, lfh_offset);
	zip_put(img, m->name, strlen(m->name));
	zip_put_zeros(img, m->extra_length);
	zip_put_zeros(img, m->comment_length);
}

static void zip_put_end(struct zip_image *img, uint16_t records, uint32_t cd_offset, uint32_t cd_size, const char *comment) {
	uint16_t comment_len = comment ? strlen(comment) : 0;

	zip_put_u32(img, ZIP_EOCD_MAGIC);
	zip_put_u16(img, 0);
	zip_put_u16(img, 0);
	zip_put_u16(img, records);
	zip_put_u16(img, records);
	zip_put_u32(img, cd_size);
	zip_put_u32(img, cd_offset);
	zip_put_u16(img, comment_len);
	zip_put(img, comment, comment_len);
}

static void zip_build(struct zip_image *img, const struct zip_case *c) {
	size_t cd_offset, i;

	if (c->member_count > ZIP_MAX_MEMBERS) {
		fprintf(stderr, "zip: case %s has more than %d members\n", c->name, ZIP_MAX_MEMBERS);
		exit(1);
	}

	memset(img, 0, sizeof(*img));
	for (i = 0; i < c->member_count; i++) {
		img->lfh[i] = img->len;
		zip_put_local(img, &c->members[i]);
	}

	cd_offset = img->len;
	for (i = 0; i < c->member_count; i++) {
		img->cdfh[i] = img->len;
		zip_put_central(img, &c->members[i], img->lfh[i]);
	}

	img->eocd = img->len;
	zip_put_end(img, c->member_count, cd_offset, img->len - cd_offset, c->comment);

	if (c->patch)
		c->patch(img);
}

static void patch_empty_file(struct zip_image *img) {
	img->len = 0;
}

static void patch_truncate(struct zip_image *img) {
	img->len--;
}

static void patch_trailing_byte(struct zip_image *img) {
	zip_put_zeros(img, 1);
}

static void patch_this_disk(struct zip_image *img) {
	zip_set_u16(img, img->eocd + ZIP_EOCD_THIS_DISK, 1);
}

static void patch_cd_disk(struct zip_image *img) {
	zip_set_u16(img, img->eocd + ZIP_EOCD_CD_DISK, 1);
}

static void patch_records_total(struct zip_image *img) {
	zip_set_u16(img, img->eocd + ZIP_EOCD_CD_RECORDS_TOTAL, 0xffff);
}

static void patch_zip64_cd_offset(struct zip_image *img) {
	zip_set_u32(img, img->eocd + ZIP_EOCD_CD_OFFSET, 0xffffffff);
}

/* Claim one more central directory record than the archive has. */
static void patch_extra_record(struct zip_image *img) {
	uint16_t records = zip_get_u16(img, img->eocd + ZIP_EOCD_CD_RECORDS) + 1;

	zip_set_u16(img, img->eocd + ZIP_EOCD_CD_RECORDS, records);
	zip_set_u16(img, img->eocd + ZIP_EOCD_CD_RECORDS_TOTAL, records);
}

static void patch_cd_encrypted(struct zip_image *img) {
	zip_set_u16(img, img->cdfh[0] + ZIP_CDFH_FLAGS, ZIP_FLAG_ENCRYPTED);
}

static void patch_cd_data_descriptor(struct zip_image *img) {
	zip_set_u16(img, img->cdfh[0] + ZIP_CDFH_FLAGS, ZIP_FLAG_DATA_DESCRIPTOR);
}

static void patch_local_encrypted(struct zip_image *img) {
	zip_set_u16(img, img->lfh[0] + ZIP_LFH_FLAGS, ZIP_FLAG_ENCRYPTED);
}

static void patch_local_data_descriptor(struct zip_image *img) {
	zip_set_u16(img, img->lfh[0] + ZIP_LFH_FLAGS, ZIP_FLAG_DATA_DESCRIPTOR);
}

static void patch_local_magic(struct zip_image *img) {
	zip_set_u32(img, img->lfh[0], 0);
}

static void patch_local_data_past_end(struct zip_image *img) {
	zip_set_u32(img, img->lfh[0] + ZIP_LFH_COMPRESSED_SIZE, img->len);
}

static void patch_local_size_wraps(struct zip_image *img) {
	zip_set_u32(img, img->lfh[0] + ZIP_LFH_COMPRESSED_SIZE, 0xffffffff);
}

static const struct zip_member one_member[] = {
	{.name = "lib/libone.so", .data = "\177ELF one"},
};

static const struct zip_member several_members[] = {
	{.name = "first.txt", .data = "first"},
	{.name = "dir/second.bin", .data = "second member", .extra_length = 6, .comment_length = 5},
	{.name = "third", .data = ""},
};

static const struct zip_member duplicate_members[] = {
	{.name = "dup.txt", .data = "first copy"},
	{.name = "dup.txt", .data = "second copy"},
};

static const struct zip_member compressed_member[] = {
	{.name = "packed.txt", .data = "stored bytes of a deflated member", .compression = ZIP_DEFLATE},
};

static const struct zip_case zip_cases[] = {
	{.name = "one_member", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member)},
	{.name = "first_of_several", .lookup = "first.txt", ZIP_MEMBERS(several_members)},
	{.name = "extra_field", .lookup = "dir/second.bin", ZIP_MEMBERS(several_members)},
	{.name = "after_extra_and_comment", .lookup = "third", ZIP_MEMBERS(several_members)},
	{.name = "compressed", .lookup = "packed.txt", ZIP_MEMBERS(compressed_member)},
	{.name = "archive_comment", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .comment = "gobpfgo"},
	{.name = "first_duplicate", .lookup = "dup.txt", ZIP_MEMBERS(duplicate_members)},
	{.name = "missing_member", .lookup = "absent", ZIP_MEMBERS(several_members)},
	{.name = "name_prefix", .lookup = "first.tx", ZIP_MEMBERS(several_members)},
	{.name = "name_longer", .lookup = "first.txt.gz", ZIP_MEMBERS(several_members)},
	{.name = "cd_encrypted", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_cd_encrypted},
	{.name = "cd_data_descriptor", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_cd_data_descriptor},
	{.name = "cd_encrypted_duplicate", .lookup = "dup.txt", ZIP_MEMBERS(duplicate_members), .patch = patch_cd_encrypted},
	{.name = "local_encrypted", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_local_encrypted},
	{.name = "local_data_descriptor", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_local_data_descriptor},
	{.name = "local_bad_magic", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_local_magic},
	{.name = "local_data_past_end", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_local_data_past_end},
	{.name = "local_size_wraps", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_local_size_wraps},
	{.name = "extra_cd_record", .lookup = "absent", ZIP_MEMBERS(one_member), .patch = patch_extra_record},
	{.name = "empty_file", .lookup = "absent", .patch = patch_empty_file},
	{.name = "empty_archive", .lookup = "absent"},
	{.name = "truncated", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_truncate},
	{.name = "trailing_byte", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_trailing_byte},
	{.name = "this_disk", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_this_disk},
	{.name = "cd_disk", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_cd_disk},
	{.name = "records_total_mismatch", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_records_total},
	{.name = "zip64_cd_offset", .lookup = "lib/libone.so", ZIP_MEMBERS(one_member), .patch = patch_zip64_cd_offset},
};

static int zip_write(const char *path, const struct zip_image *img) {
	FILE *f = fopen(path, "wb");

	if (!f) {
		perror(path);
		return -1;
	}

	if (fwrite(img->data, 1, img->len, f) != img->len) {
		perror(path);
		fclose(f);
		return -1;
	}

	return fclose(f);
}

static void zip_report_entry(struct json *j, const struct zip_entry *entry) {
	char name[ZIP_MAX_SIZE];

	snprintf(name, sizeof(name), "%.*s", (int)entry->name_length, entry->name);

	json_obj_begin_compact(j, "entry");
	json_u32(j, "compression", entry->compression);
	json_str(j, "name", name);
	json_u32(j, "data_offset", entry->data_offset);
	json_u32(j, "data_length", entry->data_length);
	json_hex(j, "data", entry->data, entry->data_length);
	json_obj_end(j);
}

/* Print the archive and the open and lookup results. Errnos are positive. */
static void zip_run_case(struct json *j, const struct zip_case *c, const struct zip_image *img, const char *path) {
	struct zip_archive *archive;
	struct zip_entry entry;
	long err;

	json_obj_begin(j, NULL);
	json_str(j, "name", c->name);
	json_str(j, "lookup", c->lookup);
	json_hex(j, "archive", img->data, img->len);

	/* zip_archive_open returns the error inside the pointer. */
	archive = zip_archive_open(path);
	err     = libbpf_get_error(archive);
	json_s32(j, "open_errno", -err);
	if (err == 0) {
		err = zip_archive_find_entry(archive, c->lookup, &entry);
		json_s32(j, "find_errno", -err);
		if (err == 0)
			zip_report_entry(j, &entry);
		zip_archive_close(archive);
	}

	json_obj_end(j);
}

int oracle_zip(void) {
	struct oracle_meta meta = {.case_name = "zip", .commit = true};
	char dir[]              = "/tmp/gobpfgo-zip-XXXXXX";
	char path[PATH_MAX];
	struct zip_image img;
	struct json j;
	int ret = 0;
	size_t i;

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	snprintf(path, sizeof(path), "%s/archive.zip", dir);

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_arr_begin(&j, "cases");
	for (i = 0; i < ORACLE_ARRAY_SIZE(zip_cases) && ret == 0; i++) {
		zip_build(&img, &zip_cases[i]);
		ret = zip_write(path, &img);
		if (ret == 0)
			zip_run_case(&j, &zip_cases[i], &img, path);
	}
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);

	unlink(path);
	rmdir(dir);
	return ret ? 1 : 0;
}
