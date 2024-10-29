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

#include "involflt.h"
#include "involflt-common.h"
#include "data-mode.h"
#include "utils.h"
#include "change-node.h"
#include "filestream.h"
#include "iobuffer.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "bitmap_api.h"
#include "VBitmap.h"
#include "work_queue.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "driver-context.h"
#include "involflt_debug.h"
#include "bitmap_operations.h"

segmented_bitmap_t *segmented_bitmap_ctr(fstream_segment_mapper_t *fssm, 
						inm_u64_t bits_in_bitmap)
{
	segmented_bitmap_t *sb = NULL;

	sb = INM_KMALLOC(sizeof(*sb), INM_KM_SLEEP, INM_KERNEL_HEAP);

	if (!sb)
		return NULL;
	
	INM_MEM_ZERO(sb, sizeof(*sb));
	INM_ATOMIC_SET(&sb->refcnt, 1);
	sb->fssm = fssm;
	sb->bits_in_bitmap = bits_in_bitmap;

	return sb;
}

void segmented_bitmap_dtr(segmented_bitmap_t *sb)
{

	INM_BUG_ON(INM_ATOMIC_READ(&sb->refcnt) != 0);

	INM_KFREE(sb, sizeof(*sb), INM_KERNEL_HEAP);
	sb = NULL;
}

segmented_bitmap_t *segmented_bitmap_get(segmented_bitmap_t *sb)
{

	INM_ATOMIC_INC(&sb->refcnt);
	return sb;
}

void segmented_bitmap_put(segmented_bitmap_t *sb)
{
	if (INM_ATOMIC_DEC_AND_TEST(&sb->refcnt))
		segmented_bitmap_dtr(sb);
}

inm_s32_t segmented_bitmap_process_bitrun(segmented_bitmap_t *sb, 
	inm_u32_t bitsinrun, inm_u64_t bitoffset, inm_s32_t bitmap_operation)
{
	inm_s32_t ret = 0;
	unsigned char *bit_buffer = NULL;
	inm_u32_t bit_buffer_byte_size = 0;
	inm_u32_t adjusted_bitsinrun = 0;
	inm_u64_t adjusted_buffer_size = 0;
	inm_u32_t nr_bytes_changed = 0;
	unsigned char *first_byte_changed = NULL;
	inm_u64_t byte_offset = 0;
	inm_u32_t bits_to_process = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	nr_bytes_changed = 0;
	bits_to_process = bitsinrun;

	if (bitoffset + bitsinrun > sb->bits_in_bitmap)
		return EOF_BMAP;


	while(bits_to_process > 0)
	{

		byte_offset = bitoffset / 8;

		ret = fstream_segment_mapper_read_and_lock(sb->fssm, 
				byte_offset, &bit_buffer, 
				&bit_buffer_byte_size);

		if (ret)
			break;

		/* figure out if this run crosses segment boundries or the bitmap end */
		adjusted_buffer_size = min(((inm_u64_t)bit_buffer_byte_size * 8),
				     (sb->bits_in_bitmap - (byte_offset * 8)));

		/* prevent runs that span buffers, hand that in this function */
		adjusted_bitsinrun = (inm_u32_t)min(((inm_u64_t)bits_to_process),
				 (adjusted_buffer_size - (bitoffset % 8)));

		switch(bitmap_operation) {
		case BITMAP_OP_SETBITS:
		ret = SetBitmapBitRun(bit_buffer, 
				  (inm_u32_t)adjusted_buffer_size,
				  adjusted_bitsinrun,
				  (inm_u32_t)(bitoffset%8),
				  &nr_bytes_changed,
				  &first_byte_changed);
		break;

		case BITMAP_OP_CLEARBITS:
		ret = ClearBitmapBitRun(bit_buffer,
				    (inm_u32_t) adjusted_buffer_size,
				    adjusted_bitsinrun,
				    (inm_u32_t) (bitoffset % 8),
				    &nr_bytes_changed,
				    &first_byte_changed);
		break;

		case BITMAP_OP_INVERTBITS:
		ret = InvertBitmapBitRun(bit_buffer,
				     (inm_u32_t) adjusted_buffer_size,
				     adjusted_bitsinrun,
				     (inm_u32_t) (bitoffset % 8),
				     &nr_bytes_changed,
				     &first_byte_changed);
		break;

		default:
		err("Invalid operation code (%d) passed to segmented_bitmap_process_bitrun \n",     
				bitmap_operation);
		return 1;
		}

		if (nr_bytes_changed)
			fstream_segment_mapper_unlock_and_mark_dirty(sb->fssm,
			(byte_offset + (first_byte_changed - bit_buffer)));
		else
			fstream_segment_mapper_unlock(sb->fssm, byte_offset);

		bits_to_process -= adjusted_bitsinrun;
		bitoffset += adjusted_bitsinrun;        
			
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with return status = %d", ret);
	}

	return ret;
}


inm_s32_t segmented_bitmap_set_bitrun(segmented_bitmap_t *sb, 
				inm_u32_t bitsinrun, inm_u64_t bitoffset)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	return segmented_bitmap_process_bitrun(sb, bitsinrun, bitoffset,
				                           BITMAP_OP_SETBITS);
}

inm_s32_t segmented_bitmap_clear_bitrun(segmented_bitmap_t *sb, 
				inm_u32_t bitsinrun, inm_u64_t bitoffset)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	return segmented_bitmap_process_bitrun(sb, bitsinrun, bitoffset,
				                          BITMAP_OP_CLEARBITS);
}

inm_s32_t segmented_bitmap_invert_bitrun(segmented_bitmap_t *sb, 
				inm_u32_t bitsinrun, inm_u64_t bitoffset)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	return segmented_bitmap_process_bitrun(sb, bitsinrun, bitoffset,
				                         BITMAP_OP_INVERTBITS);
}

inm_s32_t segmented_bitmap_clear_all_bits(segmented_bitmap_t *sb)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	return segmented_bitmap_process_bitrun(sb, sb->bits_in_bitmap, 0,
				                          BITMAP_OP_CLEARBITS);
}

inm_s32_t segmented_bitmap_get_first_bitrun(segmented_bitmap_t *sb,
				    inm_u32_t *bitsinrun, inm_u64_t *bitoffset)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	sb->next_search_offset = 0;
	return segmented_bitmap_get_next_bitrun(sb, bitsinrun, bitoffset);    
}

inm_s32_t segmented_bitmap_get_next_bitrun(segmented_bitmap_t *sb,
				    inm_u32_t *bitsinrun, inm_u64_t *bitoffset)
{
	inm_s32_t ret = 0;
	unsigned char *bit_buffer = NULL;
	inm_u32_t bit_buffer_byte_size;
	//inm_u32_t adjusted_bitsinrun;
	inm_u64_t adjusted_buffer_size;
	inm_u64_t byte_offset;
	inm_u32_t search_bit_offset;
	inm_u32_t run_length;
	inm_u32_t run_offset;
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	*bitsinrun = 0;
	*bitoffset = 0;
	run_length = 0;
	run_offset = 0;

	while(sb->next_search_offset < sb->bits_in_bitmap) {
		byte_offset = sb->next_search_offset / 8;
		dbg("bitmap search offset = %llu", byte_offset);
		
		ret = fstream_segment_mapper_read_and_lock(sb->fssm, 
					byte_offset, &bit_buffer, 
					&bit_buffer_byte_size);

		if (ret)
			break;

		search_bit_offset = (inm_u32_t) (sb->next_search_offset % 8);
		adjusted_buffer_size = (inm_u32_t)
		min(((inm_u64_t)bit_buffer_byte_size * 8),
		(sb->bits_in_bitmap - (byte_offset * 8)));

		ret = GetNextBitmapBitRun(bit_buffer, adjusted_buffer_size,
				  &search_bit_offset, 
				  &run_length, &run_offset);

		fstream_segment_mapper_unlock(sb->fssm, byte_offset);

		if (ret)
			break;

		sb->next_search_offset = (byte_offset * 8) + search_bit_offset;
			
		if (run_length > 0) {
			*bitoffset = (byte_offset * 8) + run_offset;
			break;
		}
		
	}

	if (ret == 0) {
		if (run_length > 0) {
			*bitsinrun = run_length;
		} else {
			*bitsinrun = 0;
			*bitoffset = sb->next_search_offset;
			ret = EOF_BMAP;
		}
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret status %d", ret);
	}

	return ret;    
}


inm_s32_t find_bmap_io_pat(char *buf, long long bits_in_bmap, 
				bmap_bit_stats_t *bbsp, int eobmap);

inm_u64_t segmented_bitmap_get_number_of_bits_set(segmented_bitmap_t *sb, 
							bmap_bit_stats_t *bbsp)
{
	inm_s32_t ret = 0;
	unsigned char *bit_buffer = NULL;
	inm_u32_t bit_buffer_byte_size = 0;
	inm_u64_t adjusted_buffer_size = 0;
	inm_u64_t byte_offset = 0;
	inm_u64_t bit_offset = 0;
	inm_u64_t bits_to_process = 0;
	inm_u64_t bits_set = 0;
	inm_u32_t eobmap = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	bits_to_process = sb->bits_in_bitmap;

	while(bits_to_process > 0) {
		byte_offset = bit_offset / 8;

		ret = fstream_segment_mapper_read_and_lock(sb->fssm, 
					byte_offset, &bit_buffer, 
					&bit_buffer_byte_size);

		if (ret)
			break;

		adjusted_buffer_size = min(((inm_u64_t)bit_buffer_byte_size * 8) ,
				   (sb->bits_in_bitmap - (byte_offset * 8)));

		if (bbsp) {
			if ((byte_offset * 8 + 4096) >= sb->bits_in_bitmap) {
				eobmap = 1;
			}
			find_bmap_io_pat(bit_buffer, adjusted_buffer_size, bbsp,
							 eobmap);
			info("bbsp = %d \n", bbsp->bbs_nr_dbs);
		}

		bits_set += (inm_u64_t)find_number_of_bits_set(bit_buffer,
				                         adjusted_buffer_size);

		bits_to_process -= adjusted_buffer_size;
		bit_offset += adjusted_buffer_size;
		fstream_segment_mapper_unlock(sb->fssm,byte_offset);
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %llu", bits_set);
	}

	return bits_set;    
}

inm_s32_t segmented_bitmap_sync_flush_all(segmented_bitmap_t *sb)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	return (fstream_segment_mapper_sync_flush_all(sb->fssm));
}
