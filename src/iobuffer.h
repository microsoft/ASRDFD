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

#ifndef _INMAGE_IOBUFFER_H
#define _INMAGE_IOBUFFER_H

#include "involflt-common.h"

struct _fstream_segment_mapper_tag;
struct _volume_bitmap;

typedef struct _iobuffer_tag
{
	struct inm_list_head list_entry;
	inm_u32_t size;
	unsigned char *buffer;
	inm_u8_t dirty;
	inm_atomic_t locked;
	inm_u64_t starting_offset;
	struct _bitmap_api_tag *bapi;
	struct _fstream_segment_mapper_tag *fssm;
	inm_u32_t fssm_index;
	inm_atomic_t  refcnt;

	inm_kmem_cache_t *iob_obj_cache;	/*object Lookasidelist*/
	inm_kmem_cache_t *iob_data_cache;	/*data Lookaside list*/
	void *allocation_ptr;
}iobuffer_t;

iobuffer_t *iobuffer_ctr(struct _bitmap_api_tag *bapi, inm_u32_t buffer_size, inm_u32_t index);
void iobuffer_dtr(iobuffer_t *iob);
iobuffer_t *iobuffer_get(iobuffer_t *iob);
void iobuffer_put(iobuffer_t *iob);
inm_s32_t iobuffer_sync_read(iobuffer_t *iob);
inm_s32_t iobuffer_sync_flush(iobuffer_t *iob);
void iobuffer_set_fstream(iobuffer_t *iob, fstream_t *fs);
void iobuffer_set_foffset(iobuffer_t *iob, inm_u64_t file_offset);
void iobuffer_set_owner_index(iobuffer_t *iob, inm_u32_t owner_index);
inm_u32_t iobuffer_get_owner_index(iobuffer_t *iob);
inm_s32_t iobuffer_isdirty(iobuffer_t *iob);
inm_s32_t iobuffer_islocked(iobuffer_t *iob);
void iobuffer_setdirty(iobuffer_t *iob);
void iobuffer_lockbuffer(iobuffer_t *iob);
void iobuffer_unlockbuffer(iobuffer_t *iob);

inm_s32_t iobuffer_initialize_memory_lookaside_list(void);
void iobuffer_terminate_memory_lookaside_list(void);

#endif /* _INMAGE_IOBUFFER_H */
