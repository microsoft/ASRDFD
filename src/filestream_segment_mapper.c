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

/*
 * File       : filestream_segment_mapper.c
 *
 * Description: This file contains data mode implementation of the
 *              filter driver.
 *
 * Functions defined are
 **fstream_segment_mapper_ctr
 fstream_segment_mapper_dtr
 *fstream_segment_mapper_get
 fstream_segment_mapper_put
 fstream_segment_mapper_detach
 fstream_segment_mapper_sync_flush_all

 *
 */

#include "involflt-common.h"
#include "involflt.h"
#include "data-mode.h"
#include "change-node.h"
#include "filestream.h"
#include "iobuffer.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "bitmap_api.h"
#include "work_queue.h"
#include "driver-context.h"

extern driver_context_t *driver_ctx;
inm_u32_t prime_table[32] = 
{       7,     17,     29,     41,     59,     89,    137,    211,    293,
	449,    673,    997,   1493,   2003,   3001,   4507,   6779,   9311,
	13933,  19819,  29863,  44987,  66973,  90019, 130069, 195127, 301237, 0};


iobuffer_t*
get_iobuffer_cache_ptr(fstream_segment_mapper_t *fssm, inm_u32_t buffer_index)
{
	iobuffer_t *iob = NULL;
	unsigned char **page_ptr = NULL;
	inm_s32_t page_index = (buffer_index*(sizeof(iobuffer_t*))/
						BITMAP_FILE_SEGMENT_SIZE);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered: buffer_index:%d page_index:%d", buffer_index, 
									page_index);
	}
	if (fssm->buffer_cache_index) {
		page_ptr = 
			(unsigned char **)fssm->buffer_cache_index[page_index];
		iob = (iobuffer_t*)page_ptr[buffer_index %
			  (BITMAP_FILE_SEGMENT_SIZE/(sizeof(iobuffer_t*)))];
	}

	dbg("index:%d iob:%p page_ptr:%p", buffer_index, iob, page_ptr);

	return iob;
}


iobuffer_t*
reset_iobuffer_cache_ptr(fstream_segment_mapper_t *fssm, 
				inm_u32_t buffer_index, iobuffer_t *ptr)
{
	inm_s32_t page_index = (buffer_index*(sizeof(iobuffer_t*))/
						BITMAP_FILE_SEGMENT_SIZE);
	iobuffer_t *iob = NULL;
	unsigned char **page_ptr = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered: buffer_index:%d page_index:%d", buffer_index, 
									page_index);
	}

	if (fssm->buffer_cache_index) {
		page_ptr = 
			(unsigned char **)fssm->buffer_cache_index[page_index];
		iob = (iobuffer_t*)page_ptr[buffer_index %
			  (BITMAP_FILE_SEGMENT_SIZE/(sizeof(iobuffer_t*)))];
		page_ptr[buffer_index%(BITMAP_FILE_SEGMENT_SIZE/(sizeof(iobuffer_t*)))] =
		(unsigned char*)ptr;
	}

	dbg("index:%d out iob:%p page_ptr:%p in ptr:%p", buffer_index, iob, 
								page_ptr, ptr);

	return iob;
}

fstream_segment_mapper_t *fstream_segment_mapper_ctr()
{

	fstream_segment_mapper_t *fssm = NULL;

	fssm = (fstream_segment_mapper_t *)INM_KMALLOC(sizeof(*fssm), 
					INM_KM_SLEEP, INM_KERNEL_HEAP);

	if (!fssm)
		return NULL;

	INM_MEM_ZERO(fssm, sizeof(*fssm));
	INM_ATOMIC_SET(&fssm->refcnt, 1);

	return fssm;
}

void fstream_segment_mapper_dtr(fstream_segment_mapper_t *fssm)
{

	inm_s32_t index = 0;
	inm_s32_t npages = 0;
	iobuffer_t *iob;

	if (!fssm)
		return;

	if (fssm->buffer_cache_index)
	{
		for (index = 0; index < fssm->cache_size; index++)
		{
			iob = reset_iobuffer_cache_ptr(fssm, index, NULL);
			dbg("resetting iobuffer:%p", iob);
			iobuffer_put(iob);
		}

		npages = (fssm->cache_size * sizeof(iobuffer_t *))/
						BITMAP_FILE_SEGMENT_SIZE +
		(((fssm->cache_size * sizeof(iobuffer_t *))%BITMAP_FILE_SEGMENT_SIZE)?1:0);
		index = 0;
		while (index != npages) {
			dbg("Freeing buffer page:%p", fssm->buffer_cache_index[index]);
			 INM_KFREE((unsigned char*)fssm->buffer_cache_index[index],
					 BITMAP_FILE_SEGMENT_SIZE,
					 INM_KERNEL_HEAP);
			 fssm->buffer_cache_index[index] = NULL;
			 index++;
		}
		dbg("Freeing buffer index page:%p", fssm->buffer_cache_index);
		INM_KFREE(fssm->buffer_cache_index,BITMAP_FILE_SEGMENT_SIZE, 
							INM_KERNEL_HEAP);
		fssm->buffer_cache_index = NULL;
	}
	INM_KFREE(fssm, sizeof(fstream_segment_mapper_t), INM_KERNEL_HEAP);
	fssm = NULL;
}

fstream_segment_mapper_t *
fstream_segment_mapper_get(fstream_segment_mapper_t * fssm)
{
	INM_ATOMIC_INC(&fssm->refcnt);
	return fssm;
}

void fstream_segment_mapper_put(fstream_segment_mapper_t * fssm)
{
	if (INM_ATOMIC_DEC_AND_TEST(&fssm->refcnt))
		fstream_segment_mapper_dtr(fssm);
}

inm_s32_t fstream_segment_mapper_attach(fstream_segment_mapper_t *fssm,
		bitmap_api_t *bapi, inm_u64_t offset, inm_u64_t min_file_size, 
		inm_u32_t segment_cache_limit)
{
	inm_u64_t _min_file_size = min_file_size;
	inm_s32_t _rc = 1;
	inm_s32_t npages = 0;
	unsigned char **page_ptr = NULL;
	inm_u64_t index = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	fssm->bapi = bapi;
	bapi->fssm = fssm;
	fssm->segment_size = BITMAP_FILE_SEGMENT_SIZE;
	fssm->starting_offset = offset;

	INM_DO_DIV(_min_file_size, fssm->segment_size);
	fssm->cache_size = (inm_u32_t)(_min_file_size + 1);
	npages = (fssm->cache_size * sizeof(iobuffer_t *))/BITMAP_FILE_SEGMENT_SIZE +
	(((fssm->cache_size * sizeof(iobuffer_t *))%BITMAP_FILE_SEGMENT_SIZE)?1:0);
	INM_INIT_LIST_HEAD(&fssm->segment_list);
	fssm->nr_free_buffers = segment_cache_limit;

	/* Index page maintains page pointers in it */
	fssm->buffer_cache_index = (unsigned char **)
	(INM_KMALLOC(BITMAP_FILE_SEGMENT_SIZE, INM_KM_SLEEP, INM_KERNEL_HEAP));

	dbg("Allocated fssm->buffer_cache_index:%p \n ", 
						fssm->buffer_cache_index);

	if (fssm->buffer_cache_index) {
		INM_MEM_ZERO(fssm->buffer_cache_index, 
						BITMAP_FILE_SEGMENT_SIZE);
		page_ptr = fssm->buffer_cache_index;
		while (index != npages) {
			page_ptr[index] = (INM_KMALLOC(BITMAP_FILE_SEGMENT_SIZE,
						INM_KM_SLEEP, INM_KERNEL_HEAP));
			dbg("Allocated buffer cache ptr:%p page_ptr: %p\n",
				page_ptr[index], page_ptr);
			if (!page_ptr[index]) {
				err("Error allocating memory for iobuffer pointers");
				break;
			}
			INM_MEM_ZERO(page_ptr[index], 
						BITMAP_FILE_SEGMENT_SIZE);
			index++;
		}

		/* error ? */
		if (index && index != npages) {
			err("Error allocating memory for iobuffer pointers ");
			/* release incompletely allocated pages */
			do {
				index--;
				info("Freeing buffer page:%p", page_ptr[index]);
				INM_KFREE(page_ptr[index], 
						BITMAP_FILE_SEGMENT_SIZE, 
						INM_KERNEL_HEAP);
				page_ptr[index] = NULL;
			} while (index != 0);

			dbg("Freeing buffer index page:%p", page_ptr);
			INM_KFREE(page_ptr, BITMAP_FILE_SEGMENT_SIZE,
							INM_KERNEL_HEAP);
			page_ptr = NULL;
			fssm->buffer_cache_index =  NULL;
		}
		else
			_rc = 0;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with return status = %d", _rc);
	}

	return _rc;
}


inm_s32_t fstream_segment_mapper_detach(fstream_segment_mapper_t *fssm)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	return 0;
}

inm_s32_t fstream_segment_mapper_read_and_lock(fstream_segment_mapper_t *fssm,
		inm_u64_t offset, unsigned char **return_iobuf_ptr, 
		inm_u32_t *return_seg_size)
{
	inm_s32_t ret = 0;
	iobuffer_t *iob = NULL;
	unsigned char *data_buffer = NULL;
	inm_u32_t data_size = 0;
	inm_u32_t buffer_index = 0;
	//struct inm_list_entry *entry = NULL;
	inm_u64_t _offset = offset;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered\n");
	}

	if (!fssm || !fssm->buffer_cache_index) 
		return -EINVAL;

	INM_DO_DIV(_offset, fssm->segment_size);
	buffer_index = (inm_u32_t)_offset;

	/* first check the cache for the correct buffer */
	if (get_iobuffer_cache_ptr(fssm, buffer_index) == NULL)
	{
		/* it's not in the cache, read it */
		fssm->nr_cache_miss++;

		/* the segment is not in memory, try to bring it in */
		if (fssm->nr_free_buffers)
		{
			/* We can allocate few more ioBuffers */
			iob = iobuffer_ctr(fssm->bapi, fssm->segment_size, 
								buffer_index);

			if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
						info("iob allocation = %p", iob);
			}

			if (iob)
				fssm->nr_free_buffers--;
		}

		if (iob == NULL)
		{
			/* The io buffer at the tail contains the segment which is LRU and
			 * this can be replaced with the required segment
			 */
			iob = inm_list_entry(fssm->segment_list.prev, 
						iobuffer_t, list_entry);
			/* remove from head */
			inm_list_del(&iob->list_entry);
			INM_INIT_LIST_HEAD(&iob->list_entry);

			/* Since we are evacuating this segment from the ioBuffer,
			 * we need to flush it
			 */
			ret = iobuffer_sync_flush(iob);

			if (ret) {
				/* We are unsuccesful in evacuating this segment from the
				 * IOBuffer, so insert this ioBuffer back at the tail of
				 * the list
				 */

				inm_list_add_tail(&iob->list_entry,
							&fssm->segment_list); 
				iob = NULL;
			}

			if (iob) {
				/* Things went right in evacuating the existing segment from
				 * the IOBuffer, erase this segment off from the mapping in
				 * bufferCache, as we will be evacuating this segment
				 */

				reset_iobuffer_cache_ptr(fssm, 
					iobuffer_get_owner_index(iob), NULL);

				/* Reuse this iobuffer for new bufferIndex */
				iobuffer_set_owner_index(iob, buffer_index);
			}            
		}

		if (!iob) {
			ret = -ENOMEM;
		} else {
			iobuffer_set_fstream(iob, fssm->bapi->fs);

			iobuffer_set_foffset(iob, 
				 fssm->starting_offset + (buffer_index * 
					 		fssm->segment_size));

			ret = iobuffer_sync_read(iob);

			if (ret) {
				iobuffer_put(iob);
				iob = NULL;
				fssm->nr_free_buffers++;            
			} else {
				reset_iobuffer_cache_ptr(fssm, buffer_index, 
									iob);
				/* Since this is the segment that is referenced RIGHT NOW,
				 * it will be placed at the head of the list to signify that
				 * it is the Most-Recently referenced segment
				 *
				 *add most recent one to head
				 */
				inm_list_add(&iob->list_entry, 
							&fssm->segment_list);
			}
		}
	} else {
		fssm->nr_cache_hits++;
	}

	if (get_iobuffer_cache_ptr(fssm, buffer_index) != NULL) {
		inm_u64_t _mod = 0;
		iobuffer_t *iob_ptr = NULL;

		/* it's in the cache */
		iob_ptr = get_iobuffer_cache_ptr(fssm, buffer_index);
		data_buffer = iob_ptr->buffer;

		/* make return pointer be at correct byte */
		/* 64bit division is not directly allowed on linux 32bit kernels
		 * data_buffer += (offset % (inm_u64_t) fssm->segment_size);
		 **/
#ifdef INM_LINUX
		_offset = offset;
		_mod = do_div(_offset, fssm->segment_size);
		data_buffer += (inm_u32_t)_mod;
#else
		_mod = (offset % (inm_u64_t) fssm->segment_size);
		_mod = (offset % (inm_u64_t) fssm->segment_size);
		data_buffer += _mod;
#endif

		data_size = (inm_u32_t)(fssm->segment_size - _mod);
		iobuffer_lockbuffer(iob_ptr);
		ret = 0;
	}

	*return_iobuf_ptr = data_buffer;
	*return_seg_size = data_size;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with status %d and buffer = %p", data_size, data_buffer);
	}

	return ret;
}

int
fstream_segment_mapper_unlock_and_mark_dirty(fstream_segment_mapper_t * fssm,
				inm_u64_t offset)
{
	inm_u32_t buffer_index;
	inm_u64_t _offset = offset;
	iobuffer_t *iob = NULL;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DO_DIV(_offset, fssm->segment_size);
	buffer_index = (inm_u32_t)_offset;

	iob = get_iobuffer_cache_ptr(fssm, buffer_index);
	if (iob == NULL)
		return -EINVAL;
	
	iobuffer_setdirty(iob);
	iobuffer_unlockbuffer(iob);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return 0;
}

inm_s32_t fstream_segment_mapper_unlock(fstream_segment_mapper_t * fssm,
						          inm_u64_t offset)
{
	inm_u32_t buffer_index;
	inm_u64_t _offset = offset;
	iobuffer_t *iob = NULL;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DO_DIV(_offset, fssm->segment_size);
	buffer_index = _offset;


	iob = get_iobuffer_cache_ptr(fssm, buffer_index);
	if (iob == NULL)
		return -EINVAL;

	iobuffer_unlockbuffer(iob);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return 0;

}

inm_s32_t fstream_segment_mapper_flush(fstream_segment_mapper_t * fssm,
						         inm_u64_t offset)
{
	inm_s32_t ret = 0;
	inm_u32_t buffer_index;
	inm_u64_t _offset = offset;
	iobuffer_t *iob = NULL;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DO_DIV(_offset, fssm->segment_size);
	buffer_index = _offset;

	iob = get_iobuffer_cache_ptr(fssm, buffer_index);
	if (iob == NULL)
		return EINVAL;
	ret = iobuffer_sync_flush(iob);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with return value = %d", ret);
	}

	return ret;
}

inm_s32_t fstream_segment_mapper_sync_flush_all(fstream_segment_mapper_t * fssm)
{

	inm_s32_t ret = 0, r = 0;
	inm_u32_t buffer_index; 
	iobuffer_t *iob = NULL;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (fssm->buffer_cache_index == NULL)
		return 0;

	/* flush all the iobuffers */
	for (buffer_index = 0; buffer_index < fssm->cache_size; buffer_index++)
	{
		iob = get_iobuffer_cache_ptr(fssm, buffer_index);

		if (!iob)
			continue;

		r = iobuffer_sync_flush(iob);

		if (r)
			ret = r;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}
