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

#ifndef _INMAGE_FILESTREAM_H
#define _INMAGE_FILESTREAM_H


#include "involflt-common.h"
#include "filestream_raw.h"


typedef struct _fstream_tag
{
	void *filp;
	void *inode;
	inm_dev_t rdev;
	void *context;
	inm_atomic_t refcnt;
	inm_u32_t fs_flags;
	fstream_raw_hdl_t *fs_raw_hdl;
}fstream_t;

#define FS_FLAGS_BUFIO  1

fstream_t *fstream_ctr(void *ctx);
void fstream_dtr(fstream_t *fs);
void fstream_put(fstream_t *fs);
inm_s32_t fstream_open(fstream_t *fs, char *path, inm_s32_t flags,
	       				inm_s32_t mode);
inm_s32_t fstream_close(fstream_t *fs);
inm_s32_t fstream_get_fsize(fstream_t *fs);
inm_s32_t fstream_open_or_create(fstream_t *fs, char *path,
			inm_s32_t *file_created, inm_u32_t bmap_sz);
inm_s32_t fstream_write(fstream_t *fs, char *buffer, inm_u32_t size,
					inm_u64_t offset);
inm_s32_t fstream_read(fstream_t *fs, char *buffer, inm_u32_t size,
					inm_u64_t offset);
void fstream_enable_buffered_io(fstream_t *fs);
void fstream_disable_buffered_io(fstream_t *fs);
void fstream_sync(fstream_t *fs);
inm_s32_t fstream_map_file_blocks(fstream_t *, inm_u64_t , inm_u32_t, 
					fstream_raw_hdl_t ** );
void fstream_switch_to_raw_mode(fstream_t *, fstream_raw_hdl_t *);
#endif /* _INMAGE_FILESTREAM_H */
