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

#ifndef _INMAGE_FILESTREAM_SEGMENT_MAPPER_H
#define _INMAGE_FILESTREAM_SEGMENT_MAPPER_H

#include "involflt-common.h"

#define BITMAP_FILE_SEGMENT_SIZE (0x1000)

#define MAX_BITMAP_SEGMENT_BUFFERS 0x41 /*65 segments*/

//bitmap operation
#define BITMAP_OP_SETBITS 0
#define BITMAP_OP_CLEARBITS 1
#define BITMAP_OP_INVERTBITS 2

struct _bitmap_api_tag; /* typedef'ed to bitmap_api_t */
struct _volume_bitmap;

typedef struct _fstream_segment_mapper_tag
{
	struct _bitmap_api_tag *bapi;
	inm_u32_t cache_size;
	inm_atomic_t refcnt;
	/* index for buffer cache pages */
	unsigned char **buffer_cache_index;
	struct inm_list_head segment_list;
	inm_u32_t nr_free_buffers;
	inm_u32_t nr_cache_hits;
	inm_u32_t nr_cache_miss;
	inm_u32_t segment_size;
	inm_u64_t starting_offset;

}fstream_segment_mapper_t;

fstream_segment_mapper_t *fstream_segment_mapper_ctr(void);
void fstream_segment_mapper_dtr(fstream_segment_mapper_t *fssm);
fstream_segment_mapper_t *fstream_segment_mapper_get(fstream_segment_mapper_t *fssm);
void fstream_segment_mapper_put(fstream_segment_mapper_t *fssm);
inm_s32_t fstream_segment_mapper_attach(fstream_segment_mapper_t *fssm, struct _bitmap_api_tag *bapi, inm_u64_t offset, inm_u64_t min_file_size, inm_u32_t segment_cache_limit);
inm_s32_t fstream_segment_mapper_detach(fstream_segment_mapper_t *fssm);
inm_s32_t fstream_segment_mapper_read_and_lock(fstream_segment_mapper_t *fssm,
	      inm_u64_t offset, unsigned char **return_iobuf_ptr, inm_u32_t *return_seg_size);
inm_s32_t fstream_segment_mapper_unlock_and_mark_dirty(fstream_segment_mapper_t * fssm, inm_u64_t offset);
inm_s32_t fstream_segment_mapper_unlock(fstream_segment_mapper_t * fssm, inm_u64_t offset);
inm_s32_t fstream_segment_mapper_flush(fstream_segment_mapper_t * fssm, inm_u64_t offset);
inm_s32_t fstream_segment_mapper_sync_flush_all(fstream_segment_mapper_t *fssm);
#endif /* _INMAGE_FILESTREAM_SEGMENT_MAPPER_H */

