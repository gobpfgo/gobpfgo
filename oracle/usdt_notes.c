// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "usdt_notes.h"

#include "oracle.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The crafted ELF images of the usdt scenario. Each case is an x86-64 ET_DYN
 * file with a section name table and a .note.stapsdt section built from note
 * records and raw tail bytes, plus an optional .stapsdt.base section.
 */

#define USDT_BASE_ADDR 0x2030
#define USDT_LINK_BASE 0x2000

/*
 * One note record. The descriptor is the three addresses and strings_len
 * bytes of strings, cut or zero-extended to descsz bytes.
 */
struct usdt_record {
	const char *owner;
	uint32_t namesz;
	uint32_t type;
	uint64_t addrs[3];
	const char *strings;
	uint32_t strings_len;
	uint32_t descsz;
};

#define USDT_STRINGS(s) .strings = s, .strings_len = sizeof(s) - 1
#define USDT_RECORD(loc, s) {.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {loc, USDT_LINK_BASE, 0}, USDT_STRINGS(s), .descsz = 24 + sizeof(s) - 1}
#define USDT_RECORDS(arr) .records = arr, .record_count = ORACLE_ARRAY_SIZE(arr)

static const struct usdt_record usdt_two_notes[] = {
	USDT_RECORD(0x1000, "gobpfgo\0first\0-4@%edi 8@$5\0"),
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1010, USDT_LINK_BASE, 0x4018}, USDT_STRINGS("gobpfgo\0second\0\0"), .descsz = 24 + 16},
};

static const struct usdt_record usdt_two_sites[] = {
	USDT_RECORD(0x1000, "gobpfgo\0site\0-4@%edi\0"),
	USDT_RECORD(0x1010, "gobpfgo\0other\0\0"),
	USDT_RECORD(0x1020, "gobpfgo\0site\0-8@-16(%rbp)\0"),
};

static const struct usdt_record usdt_colon_args[] = {
	USDT_RECORD(0x1000, "gobpfgo\0colon\0:8@%rax\0"),
};

static const struct usdt_record usdt_owner_mismatch[] = {
	USDT_RECORD(0x1000, "gobpfgo\0first\0\0"),
	{.owner = "stapsdX", .namesz = 8, .type = 3, USDT_STRINGS("gobpfgo\0second\0\0"), .descsz = 24 + 16},
};

static const struct usdt_record usdt_owner_empty[] = {
	{.owner = "", .namesz = 0, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first\0\0"), .descsz = 24 + 15},
};

static const struct usdt_record usdt_owner_prefix[] = {
	{.owner = "sta", .namesz = 3, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first\0\0"), .descsz = 24 + 15},
};

static const struct usdt_record usdt_owner_longer[] = {
	{.owner = "stapsdtX", .namesz = 9, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first\0\0"), .descsz = 24 + 15},
};

static const struct usdt_record usdt_wrong_type[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 1, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first\0\0"), .descsz = 24 + 15},
};

static const struct usdt_record usdt_short_desc[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("p\0"), .descsz = 24 + 2},
};

static const struct usdt_record usdt_provider_unterminated[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo"), .descsz = 24 + 7},
};

static const struct usdt_record usdt_name_missing[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0"), .descsz = 24 + 8},
};

static const struct usdt_record usdt_name_empty[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0\0\0"), .descsz = 24 + 10},
};

static const struct usdt_record usdt_name_unterminated[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first"), .descsz = 24 + 13},
};

static const struct usdt_record usdt_args_missing[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first\0"), .descsz = 24 + 14},
};

/* The spec has no NUL in the descriptor; the record padding ends it. */
static const struct usdt_record usdt_args_in_padding[] = {
	{.owner = "stapsdt", .namesz = 8, .type = 3, .addrs = {0x1000, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0first\0-8@%rax"), .descsz = 24 + 21},
};

/* The first spec fails with E2BIG; the second record has the wrong type. */
static const struct usdt_record usdt_bad_spec_first[] = {
	USDT_RECORD(0x1000, "gobpfgo\0first\0" USDT_AL13 "\0"),
	{.owner = "stapsdt", .namesz = 8, .type = 1, .addrs = {0x1010, USDT_LINK_BASE, 0}, USDT_STRINGS("gobpfgo\0second\0\0"), .descsz = 24 + 16},
};

static const struct usdt_record usdt_descsz_wraps[] = {
	USDT_RECORD(0x1000, "gobpfgo\0first\0\0"),
	{.owner = "stapsdt", .namesz = 8, .type = 3, .descsz = 0xfffffffe},
};

static const struct usdt_record usdt_one_note[] = {
	USDT_RECORD(0x1000, "gobpfgo\0first\0-4@%edi\0"),
};

/* The first bytes of a record header, which does not fit. */
static const char usdt_short_header[] = "\x08\x00\x00\x00\x30\x00";

/* A record whose descriptor runs past the end of the section. */
static const char usdt_short_record[] = "\x08\x00\x00\x00\x40\x00\x00\x00\x03\x00\x00\x00stapsdt\0\x00\x10\x00\x00";

const struct usdt_note_case usdt_note_cases[] = {
	{.name = "two-notes", USDT_RECORDS(usdt_two_notes), .with_base = true, .provider = "gobpfgo", .probe = "first"},
	{.name = "two-sites", USDT_RECORDS(usdt_two_sites), .provider = "gobpfgo", .probe = "site"},
	{.name = "unknown-probe", USDT_RECORDS(usdt_two_notes), .provider = "gobpfgo", .probe = "missing"},
	{.name = "unknown-provider", USDT_RECORDS(usdt_two_notes), .provider = "other", .probe = "first"},
	{.name = "colon-args", USDT_RECORDS(usdt_colon_args), .provider = "gobpfgo", .probe = "colon"},
	{.name = "align8", USDT_RECORDS(usdt_two_notes), .align8 = true, .provider = "gobpfgo", .probe = "second"},
	{.name = "owner-mismatch", USDT_RECORDS(usdt_owner_mismatch), .provider = "gobpfgo", .probe = "first"},
	{.name = "owner-empty", USDT_RECORDS(usdt_owner_empty), .provider = "gobpfgo", .probe = "first"},
	{.name = "owner-prefix", USDT_RECORDS(usdt_owner_prefix), .provider = "gobpfgo", .probe = "first"},
	{.name = "owner-longer", USDT_RECORDS(usdt_owner_longer), .provider = "gobpfgo", .probe = "first"},
	{.name = "wrong-type", USDT_RECORDS(usdt_wrong_type), .provider = "gobpfgo", .probe = "first"},
	{.name = "short-desc", USDT_RECORDS(usdt_short_desc), .provider = "gobpfgo", .probe = "first"},
	{.name = "provider-unterminated", USDT_RECORDS(usdt_provider_unterminated), .provider = "gobpfgo", .probe = "first"},
	{.name = "name-missing", USDT_RECORDS(usdt_name_missing), .provider = "gobpfgo", .probe = "first"},
	{.name = "name-empty", USDT_RECORDS(usdt_name_empty), .provider = "gobpfgo", .probe = "first"},
	{.name = "name-unterminated", USDT_RECORDS(usdt_name_unterminated), .provider = "gobpfgo", .probe = "first"},
	{.name = "args-missing", USDT_RECORDS(usdt_args_missing), .provider = "gobpfgo", .probe = "first"},
	{.name = "args-in-padding", USDT_RECORDS(usdt_args_in_padding), .provider = "gobpfgo", .probe = "first"},
	{.name = "bad-spec-before-bad-note", USDT_RECORDS(usdt_bad_spec_first), .provider = "gobpfgo", .probe = "first"},
	{.name = "bad-note-after-match", USDT_RECORDS(usdt_bad_spec_first), .provider = "gobpfgo", .probe = "second"},
	{.name = "descsz-wraps", USDT_RECORDS(usdt_descsz_wraps), .provider = "gobpfgo", .probe = "first"},
	{.name = "short-header", USDT_RECORDS(usdt_one_note), .tail = usdt_short_header, .tail_len = sizeof(usdt_short_header) - 1, .provider = "gobpfgo", .probe = "first"},
	{.name = "short-record", USDT_RECORDS(usdt_one_note), .tail = usdt_short_record, .tail_len = sizeof(usdt_short_record) - 1, .provider = "gobpfgo", .probe = "first"},
	{.name = "empty-section", .provider = "gobpfgo", .probe = "first"},
	{.name = "no-notes-section", USDT_RECORDS(usdt_one_note), .no_notes = true, .provider = "gobpfgo", .probe = "first"},
	{.name = "progbits-section", USDT_RECORDS(usdt_one_note), .progbits = true, .provider = "gobpfgo", .probe = "first"},
	{.name = "compressed-section", USDT_RECORDS(usdt_one_note), .compressed = true, .provider = "gobpfgo", .probe = "first"},
	{.name = "section-past-eof", USDT_RECORDS(usdt_one_note), .past_eof = true, .provider = "gobpfgo", .probe = "first"},
	{.name = "relocatable", USDT_RECORDS(usdt_one_note), .relocatable = true, .provider = "gobpfgo", .probe = "first"},
};

const size_t usdt_note_case_count = ORACLE_ARRAY_SIZE(usdt_note_cases);

/* The section name table and the offset of each name in it. */
static const char usdt_shstrtab[] = "\0.shstrtab\0.note.stapsdt\0.note.other\0.stapsdt.base";

enum {
	USDT_NAME_SHSTRTAB = 1,
	USDT_NAME_NOTES    = 11,
	USDT_NAME_OTHER    = 25,
	USDT_NAME_BASE     = 37,
};

static void usdt_put(struct usdt_image *img, const void *src, size_t len) {
	if (img->len + len > sizeof(img->data)) {
		fprintf(stderr, "usdt: image larger than %d bytes\n", USDT_IMAGE_MAX);
		exit(1);
	}

	memcpy(img->data + img->len, src, len);
	img->len += len;
}

static void usdt_put_zeros(struct usdt_image *img, size_t len) {
	static const uint8_t zeros[64];

	while (len > 0) {
		size_t n = len < sizeof(zeros) ? len : sizeof(zeros);

		usdt_put(img, zeros, n);
		len -= n;
	}
}

/* Pads the image to a multiple of align from start. */
static void usdt_align(struct usdt_image *img, size_t start, size_t align) {
	size_t used = (img->len - start) % align;

	if (used)
		usdt_put_zeros(img, align - used);
}

static void usdt_put_u32(struct usdt_image *img, uint32_t v) {
	usdt_put(img, &v, sizeof(v));
}

/*
 * Writes one record the way the assembler lays it out: the header, the owner
 * name zero-filled to namesz, padding, the descriptor and padding again. A
 * descsz that does not fit in the image only writes the header.
 */
static void usdt_put_record(struct usdt_image *img, size_t start, size_t align, const struct usdt_record *rec) {
	uint8_t desc[sizeof(rec->addrs) + 128] = {0};
	size_t owner_len                       = strlen(rec->owner);

	usdt_put_u32(img, rec->namesz);
	usdt_put_u32(img, rec->descsz);
	usdt_put_u32(img, rec->type);
	usdt_put(img, rec->owner, owner_len < rec->namesz ? owner_len : rec->namesz);
	if (owner_len < rec->namesz)
		usdt_put_zeros(img, rec->namesz - owner_len);

	usdt_align(img, start, align);
	if (rec->descsz > sizeof(desc))
		return;

	memcpy(desc, rec->addrs, sizeof(rec->addrs));
	if (rec->strings_len)
		memcpy(desc + sizeof(rec->addrs), rec->strings, rec->strings_len);

	usdt_put(img, desc, rec->descsz);
	usdt_align(img, start, align);
}

/* Writes the note section contents and returns their size. */
static size_t usdt_put_notes(struct usdt_image *img, const struct usdt_note_case *c) {
	size_t start = img->len, align = c->align8 ? 8 : 4, i;
	Elf64_Chdr chdr = {.ch_type = ELFCOMPRESS_ZLIB, .ch_size = 64, .ch_addralign = 4};

	if (c->compressed)
		usdt_put(img, &chdr, sizeof(chdr));

	for (i = 0; i < c->record_count; i++)
		usdt_put_record(img, start, align, &c->records[i]);

	if (c->tail_len)
		usdt_put(img, c->tail, c->tail_len);

	return img->len - start;
}

void usdt_build_image(struct usdt_image *img, const struct usdt_note_case *c) {
	Elf64_Ehdr ehdr = {0};
	Elf64_Shdr shdr[4];
	size_t shnum = c->with_base ? 4 : 3;

	memset(shdr, 0, sizeof(shdr));
	memset(img, 0, sizeof(*img));
	img->len = sizeof(ehdr);

	shdr[1].sh_name      = USDT_NAME_SHSTRTAB;
	shdr[1].sh_type      = SHT_STRTAB;
	shdr[1].sh_offset    = img->len;
	shdr[1].sh_size      = sizeof(usdt_shstrtab);
	shdr[1].sh_addralign = 1;
	usdt_put(img, usdt_shstrtab, sizeof(usdt_shstrtab));
	usdt_align(img, 0, 8);

	shdr[2].sh_name      = c->no_notes ? USDT_NAME_OTHER : USDT_NAME_NOTES;
	shdr[2].sh_type      = c->progbits ? SHT_PROGBITS : SHT_NOTE;
	shdr[2].sh_flags     = c->compressed ? SHF_COMPRESSED : 0;
	shdr[2].sh_offset    = img->len;
	shdr[2].sh_size      = usdt_put_notes(img, c);
	shdr[2].sh_addralign = c->align8 ? 8 : 4;
	if (c->past_eof)
		shdr[2].sh_size += 4096;

	if (c->with_base) {
		shdr[3].sh_name      = USDT_NAME_BASE;
		shdr[3].sh_type      = SHT_PROGBITS;
		shdr[3].sh_flags     = SHF_ALLOC;
		shdr[3].sh_addr      = USDT_BASE_ADDR;
		shdr[3].sh_offset    = img->len;
		shdr[3].sh_size      = 1;
		shdr[3].sh_addralign = 1;
		usdt_put_zeros(img, 1);
	}

	usdt_align(img, 0, 8);
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS]   = ELFCLASS64;
	ehdr.e_ident[EI_DATA]    = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_type              = c->relocatable ? ET_REL : ET_DYN;
	ehdr.e_machine           = EM_X86_64;
	ehdr.e_version           = EV_CURRENT;
	ehdr.e_shoff             = img->len;
	ehdr.e_ehsize            = sizeof(ehdr);
	ehdr.e_shentsize         = sizeof(shdr[0]);
	ehdr.e_shnum             = shnum;
	ehdr.e_shstrndx          = 1;
	memcpy(img->data, &ehdr, sizeof(ehdr));
	usdt_put(img, shdr, shnum * sizeof(shdr[0]));
}

int usdt_write_image(const char *path, const struct usdt_image *img) {
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
