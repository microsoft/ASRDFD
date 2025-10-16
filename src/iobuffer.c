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
#include "utils.h"
#include "tunable_params.h"

extern driver_context_t *driver_ctx;

iobuffer_t *iobuffer_ctr(bitmap_api_t *bapi, inm_u32_t buffer_size, 
							inm_u32_t index)
{

	iobuffer_t *iob;
	unsigned char *buffer;

	if(!buffer_size)
		return NULL;

	if (buffer_size == BITMAP_FILE_SEGMENT_SIZE) {
		buffer = INM_MEMPOOL_ALLOC(driver_ctx->dc_bmap_info.iob_data_pool, 
								INM_KM_SLEEP);
		INM_BUG_ON(!buffer);
	} else {
		buffer = (unsigned char *)INM_VMALLOC((unsigned long)buffer_size,
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	}

	if(!buffer)
		return NULL;

	INM_MEM_ZERO(buffer,buffer_size);

	iob = INM_MEMPOOL_ALLOC(driver_ctx->dc_bmap_info.iob_obj_pool, 
							INM_KM_SLEEP);
	INM_BUG_ON(!iob);

	if(!iob)
		return iob;

	INM_MEM_ZERO(iob, sizeof(*iob));

	iob->bapi = bapi;
	iob->buffer = buffer;
	iob->size = buffer_size;
	iob->dirty = 0;
	iob->starting_offset = 0;
	iob->fssm = bapi->fssm;
	iob->fssm_index = index;
	INM_INIT_LIST_HEAD(&iob->list_entry);
	INM_ATOMIC_SET(&iob->refcnt,1);
	INM_ATOMIC_SET(&iob->locked, 0);

	iob->starting_offset = bapi->bitmap_offset + 0;

	return iob;
}

void iobuffer_dtr(iobuffer_t *iob)
{
	if(!iob)
		return;

	if (iob->size == BITMAP_FILE_SEGMENT_SIZE)
		INM_MEMPOOL_FREE(iob->buffer, 
				driver_ctx->dc_bmap_info.iob_data_pool);
	else
		INM_VFREE((void *)iob->buffer, iob->size, INM_KERNEL_HEAP);

	iob->buffer = NULL;
	INM_MEMPOOL_FREE(iob, driver_ctx->dc_bmap_info.iob_obj_pool);
	iob = NULL;
}

iobuffer_t *iobuffer_get(iobuffer_t *iob)
{
	INM_ATOMIC_INC(&iob->refcnt);

	return iob;
}

void iobuffer_put(iobuffer_t *iob)
{
	if (!iob)
		return;

	if (INM_ATOMIC_DEC_AND_TEST(&iob->refcnt))
		iobuffer_dtr(iob);
}

inm_s32_t iobuffer_sync_read(iobuffer_t *iob)
{
	inm_s32_t ret = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (iob->dirty)
		return -EBUSY;
		
	if (INM_ATOMIC_READ(&iob->locked) > 1)
		return -EBUSY;

	ret = fstream_read(iob->bapi->fs, iob->buffer, iob->size, 
						iob->starting_offset);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}

inm_s32_t iobuffer_sync_flush(iobuffer_t *iob)
{
	inm_s32_t ret = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!iob->dirty)
		return 0;

	if (INM_ATOMIC_READ(&iob->locked) > 0)
		return -EBUSY;

	ret = fstream_write(iob->bapi->fs, iob->buffer, iob->size, 
							iob->starting_offset);
	if (!ret)
		iob->dirty = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}

void iobuffer_set_fstream(iobuffer_t *iob, fstream_t *fs)
{
	iob->bapi->fs = fs;        
}

void iobuffer_set_foffset(iobuffer_t *iob, inm_u64_t file_offset)
{
	iob->starting_offset = file_offset;
}

void iobuffer_set_owner_index(iobuffer_t *iob, inm_u32_t owner_index)
{
	iob->fssm_index = owner_index;
}

inm_u32_t iobuffer_get_owner_index(iobuffer_t *iob)
{
	return iob->fssm_index;
}

inm_s32_t iobuffer_isdirty(iobuffer_t *iob)
{
	return (int)iob->dirty;
}

inm_s32_t iobuffer_islocked(iobuffer_t *iob)
{
	return (INM_ATOMIC_READ(&iob->locked) > 0);
}

void iobuffer_setdirty(iobuffer_t *iob)
{
	iob->dirty = 1;
}

void iobuffer_lockbuffer(iobuffer_t *iob)
{
	INM_ATOMIC_INC(&iob->locked);
}

void iobuffer_unlockbuffer(iobuffer_t *iob)
{
	INM_ATOMIC_DEC(&iob->locked);
}

void iobuffer_learn_physical_iofilter(iobuffer_t *iob, struct bio *bio)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}
	if (!iob) {
		info("iob is null");
		return;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

inm_s32_t iobuffer_initialize_memory_lookaside_list(void)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	driver_ctx->dc_bmap_info.iob_obj_cache = INM_KMEM_CACHE_CREATE("iob_obj_cache",
		sizeof(iobuffer_t), 0, INM_SLAB_HWCACHE_ALIGN, NULL, NULL,
	INM_MAX_NR_IO_BUFFER_POOL, INM_MIN_NR_IO_BUFFER_POOL, INM_UNPINNED);
	if (!driver_ctx->dc_bmap_info.iob_obj_cache) {
		err("INM_KMEM_CACHE_CREATE failed to create iob_obj_cache\n");
		goto fail;
	}

	driver_ctx->dc_bmap_info.iob_data_cache = INM_KMEM_CACHE_CREATE("iob_data_cache",
	BITMAP_FILE_SEGMENT_SIZE, 0, INM_SLAB_HWCACHE_ALIGN, NULL, NULL,
	INM_MAX_NR_IO_BUFFER_DATA_POOL, INM_MIN_NR_IO_BUFFER_DATA_POOL, 
	INM_UNPINNED);

	if (!driver_ctx->dc_bmap_info.iob_data_cache) {
		err("INM_KMEM_CACHE_CREATE failed to create iob_data_cache\n");
		goto fail;
	}

	driver_ctx->dc_bmap_info.iob_obj_pool = INM_MEMPOOL_CREATE(\
		PAGE_SIZE/sizeof(iobuffer_t), INM_MEMPOOL_ALLOC_SLAB, 
		INM_MEMPOOL_FREE_SLAB,
		driver_ctx->dc_bmap_info.iob_obj_cache);
	if (!driver_ctx->dc_bmap_info.iob_obj_pool) {
		err("mem pool create failed for iob_obj_pool\n");
		goto fail;
	}
	
	driver_ctx->dc_bmap_info.iob_data_pool = INM_MEMPOOL_CREATE(\
		MAX_BITMAP_SEGMENT_BUFFERS, INM_MEMPOOL_ALLOC_SLAB, 
		INM_MEMPOOL_FREE_SLAB,
		driver_ctx->dc_bmap_info.iob_data_cache);
	if (!driver_ctx->dc_bmap_info.iob_data_pool) {
		err("mem pool create failed for iob_data_pool\n");
		goto fail;
	}

	return 0;
fail:
	if (driver_ctx->dc_bmap_info.iob_obj_pool) {
		INM_MEMPOOL_DESTROY(driver_ctx->dc_bmap_info.iob_obj_pool);
		driver_ctx->dc_bmap_info.iob_obj_pool = NULL;
	}
	if (driver_ctx->dc_bmap_info.iob_data_cache) {
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_bmap_info.iob_data_cache);
		driver_ctx->dc_bmap_info.iob_data_cache = NULL;
	}
	if (driver_ctx->dc_bmap_info.iob_obj_cache) {
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_bmap_info.iob_obj_cache);
		driver_ctx->dc_bmap_info.iob_obj_cache = NULL;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return -ENOMEM;
}

void iobuffer_terminate_memory_lookaside_list(void)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (driver_ctx->dc_bmap_info.iob_obj_cache) {
		if (driver_ctx->dc_bmap_info.iob_obj_pool)
			INM_MEMPOOL_DESTROY(driver_ctx->dc_bmap_info.iob_obj_pool);
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_bmap_info.iob_obj_cache);
		driver_ctx->dc_bmap_info.iob_obj_cache = NULL;
	}

	if (driver_ctx->dc_bmap_info.iob_data_cache) {
		if (driver_ctx->dc_bmap_info.iob_data_pool)
			INM_MEMPOOL_DESTROY(driver_ctx->dc_bmap_info.iob_data_pool);
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_bmap_info.iob_data_cache);
		driver_ctx->dc_bmap_info.iob_data_cache = NULL;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

