// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include "oracle.h"

#include "libbpf_version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

void oracle_meta(struct json *j, const struct oracle_meta *meta) {
	struct utsname uts;
	char version[32];

	if (uname(&uts) != 0) {
		perror("uname");
		exit(1);
	}

	if (meta->case_name)
		json_str(j, "case", meta->case_name);
	if (meta->commit)
		json_str(j, "libbpf_commit", ORACLE_LIBBPF_COMMIT);
	if (meta->version) {
		snprintf(version, sizeof(version), "%d.%d.0", LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
		json_str(j, "libbpf_version", version);
	}

	json_str(j, "arch", uts.machine);
	json_str(j, "kernel", uts.release);
}

void oracle_field_block(struct json *j, const char *name, const struct oracle_field *fields, size_t count, size_t size) {
	size_t i;

	json_obj_begin(j, name);
	json_u64(j, "attr_size", (uint64_t)size);
	json_arr_begin(j, "fields");
	for (i = 0; i < count; i++) {
		json_obj_begin_compact(j, NULL);
		json_str(j, "name", fields[i].name);
		json_u64(j, "offset", (uint64_t)fields[i].offset);
		json_u64(j, "size", (uint64_t)fields[i].size);
		json_obj_end(j);
	}
	json_arr_end(j);
	json_obj_end(j);
}

const char *oracle_basename(const char *path) {
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}
