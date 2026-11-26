// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include <stdio.h>
#include <string.h>

static void usage(const char *prog) {
	fprintf(stderr, "usage: %s layout|attr|open <object>|load <object>|attach <dir>|core <object>|core-reloc <object> <target>\n", prog);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	if (strcmp(argv[1], "layout") == 0 && argc == 2)
		return oracle_layout();
	if (strcmp(argv[1], "attr") == 0 && argc == 2)
		return oracle_attr();
	if (strcmp(argv[1], "open") == 0 && argc == 3)
		return oracle_open(argv[2]);
	if (strcmp(argv[1], "load") == 0 && argc == 3)
		return oracle_load(argv[2]);
	if (strcmp(argv[1], "attach") == 0 && argc == 3)
		return oracle_attach(argv[2]);
	if (strcmp(argv[1], "core") == 0 && argc == 3)
		return oracle_core(argv[2]);
	if (strcmp(argv[1], "core-reloc") == 0 && argc == 4)
		return oracle_core_reloc(argv[2], argv[3]);

	usage(argv[0]);
	return 2;
}
