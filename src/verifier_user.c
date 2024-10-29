/* SPDX-License-Identifier: GPL-2.0-only */

/* Copyright (C) 2022 Microsoft Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "verifier.h"

void
verify_file(char *fname)
{
	int fd = -1;
	unsigned long long size = 0;
	char *buf = NULL;

	if (!fname)
		exit(-1);

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		perror("Open");
		exit(-1);
	}

	size = lseek(fd, 0, SEEK_END);
	printf("File Size: %llu\n", size);

	buf = malloc(size);
	if (!buf) {
		perror("Malloc");
		exit(-1);
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		perror("Seek SET");
		exit(-1);
	}

	if (size != read(fd, buf, size)) {
		perror("Read");
		exit(-1);
	}

	if (inm_verify_change_node_data(buf, size, 1)) {
		printf("Verification failed");
		exit(-1);
	}
}

int
main(int argc, char *argv[])
{
	verify_file(argv[1]);
}
