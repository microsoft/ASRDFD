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

#ifndef _INMAGE_SEGMENTED_BITMAP_H
#define _INMAGE_SEGMENTED_BITMAP_H

#include "involflt-common.h"

typedef struct _segmented_bitmap_tag
{
	fstream_segment_mapper_t *fssm;
	inm_u64_t next_search_offset;
	inm_u64_t bits_in_bitmap;
	inm_atomic_t refcnt;
}segmented_bitmap_t;

struct bmap_bit_stats;
segmented_bitmap_t *segmented_bitmap_ctr(fstream_segment_mapper_t *fssm, inm_u64_t bits_in_bitmap);
void segmented_bitmap_dtr(segmented_bitmap_t *sb);
segmented_bitmap_t *segmented_bitmap_get(segmented_bitmap_t *sb);
void segmented_bitmap_put(segmented_bitmap_t *sb);
inm_s32_t segmented_bitmap_process_bitrun(segmented_bitmap_t *sb, inm_u32_t bitsinrun, inm_u64_t bitoffset, inm_s32_t bitmap_operation);
inm_s32_t segmented_bitmap_set_bitrun(segmented_bitmap_t *sb, inm_u32_t bitsinrun, inm_u64_t bitoffset);
inm_s32_t segmented_bitmap_clear_bitrun(segmented_bitmap_t *sb, inm_u32_t bitsinrun, inm_u64_t bitoffset);
inm_s32_t segmented_bitmap_invert_bitrun(segmented_bitmap_t *sb, inm_u32_t bitsinrun, inm_u64_t bitoffset);
inm_s32_t segmented_bitmap_clear_all_bits(segmented_bitmap_t *sb);
inm_s32_t segmented_bitmap_get_first_bitrun(segmented_bitmap_t *sb, inm_u32_t *bitsinrun, inm_u64_t *bitoffset);
inm_s32_t segmented_bitmap_get_next_bitrun(segmented_bitmap_t *sb, inm_u32_t *bitsinrun, inm_u64_t *bitoffset);
inm_u64_t segmented_bitmap_get_number_of_bits_set(segmented_bitmap_t *sb, struct bmap_bit_stats *);
inm_s32_t segmented_bitmap_sync_flush_all(segmented_bitmap_t *sb);
inm_s32_t get_next_bitmap_bitrun(char *bit_buffer, inm_u64_t adjusted_buffer_size, inm_u32_t *search_bit_offset, inm_u32_t *run_length, inm_u32_t *run_offset);


#endif /* _INMAGE_SEGMENTED_BITMAP_H */
