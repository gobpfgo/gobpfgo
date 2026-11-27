// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#ifndef ORACLE_USDT_NOTES_H
#define ORACLE_USDT_NOTES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define USDT_IMAGE_MAX 2048

/* Thirteen operands, one more than a spec may have. */
#define USDT_AL13 "1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al 1@%al"

struct usdt_record;

/*
 * One crafted ELF image: an x86-64 ET_DYN file with a section name table and
 * a .note.stapsdt section built from records and tail bytes. The flags change
 * one property each; the lookup names the probe usdt_collect searches for.
 */
struct usdt_note_case {
	const char *name;
	const struct usdt_record *records;
	size_t record_count;
	const char *tail;
	size_t tail_len;
	bool align8;
	bool progbits;
	bool compressed;
	bool past_eof;
	bool no_notes;
	bool with_base;
	bool relocatable;
	const char *provider;
	const char *probe;
};

struct usdt_image {
	uint8_t data[USDT_IMAGE_MAX];
	size_t len;
};

extern const struct usdt_note_case usdt_note_cases[];
extern const size_t usdt_note_case_count;

void usdt_build_image(struct usdt_image *img, const struct usdt_note_case *c);
int usdt_write_image(const char *path, const struct usdt_image *img);

#endif
