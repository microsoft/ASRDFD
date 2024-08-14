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
 * File       : data-mode.c
 *
 * Description: This file contains data mode implementation of the
 *              filter driver.
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
#include "filter_host.h"
#include "metadata-mode.h"
#include "tunable_params.h"
#include "svdparse.h"
#include "db_routines.h"

const inm_s32_t sv_hdr_sz     = (sizeof(SVD_PREFIX) + sizeof(SVD_HEADER1));
const inm_s32_t sv_ts_sz      = (sizeof(SVD_PREFIX) + 
						sizeof(SVD_TIME_STAMP_V2));
const inm_s32_t sv_drtd_sz    = (sizeof(SVD_PREFIX) + sizeof(inm_u64_t));
const inm_s32_t sv_chg_sz     = (sizeof(SVD_PREFIX) + 
						sizeof(SVD_DIRTY_BLOCK_V2));
const inm_s32_t sv_pref_sz	= (3*sizeof(SVD_PREFIX) + sizeof(SVD_HEADER1) +
			   sizeof(SVD_TIME_STAMP_V2) + sizeof(inm_u64_t)) +
			   sizeof(inm_u32_t);
const inm_s32_t sv_const_sz   = (4*sizeof(SVD_PREFIX) + sizeof(SVD_HEADER1) +
			   (2*sizeof(SVD_TIME_STAMP_V2)) + 
			   sizeof(inm_u64_t) + sizeof(inm_u32_t));

/* From data mode perspective, a node is new if it has no data pages */
#define is_new_data_node(node) (inm_list_empty(&node->data_pg_head)? 1 : 0)

static inm_s32_t should_wakeup_worker_alloc(inm_u32_t);
static inm_s32_t is_metadata_due_to_delay_alloc(target_context_t *tcp);
static inm_s32_t set_all_data_mode(void);
extern driver_context_t *driver_ctx;
extern void copy_iovec_data_to_data_pages(inm_wdata_t *, inm_list_head_t *);

/* A framework abstracted in data mode filtering which tells whether to
 * pre-allocate data pages or allocate pages on demand. 
 */
inm_s32_t dynamic_alloc = 0;

data_page_t *get_cur_data_pg(change_node_t *node, inm_s32_t *offset)
{
	INM_BUG_ON(node->cur_data_pg == NULL);

	if( node->cur_data_pg_off == INM_PAGESZ ) {
		*offset = 0;
		node->cur_data_pg = PG_ENTRY(node->cur_data_pg->next.next);
		return node->cur_data_pg;
	} else {
		*offset = node->cur_data_pg_off;
		return node->cur_data_pg;
	}
}


void
update_cur_dat_pg(change_node_t *node, data_page_t *pg, inm_s32_t offset)
{
	INM_BUG_ON(pg == NULL);

	if(offset == INM_PAGESZ) {
		node->cur_data_pg = PG_ENTRY(pg->next.next);
		node->cur_data_pg_off = 0;
	} else {
		node->cur_data_pg = pg;
		node->cur_data_pg_off = offset;
	}
}

static_inline void copy_data_to_data_pages( void *addr, inm_s32_t len,
						change_node_t *node)
{
	data_page_t *pg;
	inm_s32_t pg_offset, pg_free, to_copy, buf_offset = 0, rem = len ;
	char *buf = (char *)addr, *dst;
	inm_s32_t org_pg_offset;

#ifdef TEST_VERIFIER

#define CORRUPTION_EVERY_SECS   120ULL
#define CORRUPTION_EVERY_100NSECS  (CORRUPTION_EVERY_SECS * 10000000)
#define CORRUPTION_OFF_BY       1

	static unsigned int files = 1;
	inm_u64_t now;

#endif 

	pg = get_cur_data_pg(node, &pg_offset);
	pg_free = (INM_PAGESZ - pg_offset);

	org_pg_offset = pg_offset;

	INM_BUG_ON((pg == NULL) || (pg_offset >= INM_PAGESZ) || (pg_free <= 0));

#ifdef TEST_VERIFIER
	if (node->type == NODE_SRC_DATA) {
		get_time_stamp(&now);
		if ((now - driver_ctx->dc_tel.dt_drv_load_time) >
			(files * CORRUPTION_EVERY_100NSECS)) {
			files++;
			/* Make sure we conly corrupt our buffers */
			if (CHANGE_NODE_IS_FIRST_DATA_PAGE(node, pg)) {
				/* First page - Overflow */ 
				pg_offset += CORRUPTION_OFF_BY;
				err("Corrupting Page 0: offset = %d",
						node->stream_len);
			} else if (CHANGE_NODE_IS_LAST_DATA_PAGE(node,
								pg)) {
				/* Last page - Underrun */
				pg_offset -= CORRUPTION_OFF_BY;
				err("Corrupting Page N: offset = %d",
						node->stream_len);
			} else {
				/* Random corruption */
				if (now & 1) 
					pg_offset += CORRUPTION_OFF_BY;
				else
					pg_offset -= CORRUPTION_OFF_BY;
				err("Corrupting DB: offset = %d",
						node->stream_len);
			} 
		}
	} 
#endif

	while(1) {
		to_copy = MIN(pg_free, rem);
		INM_PAGE_MAP(dst, pg->page, KM_SOFTIRQ0);
		memcpy_s((char *)(dst + pg_offset), to_copy,
					(char *)(buf + buf_offset), to_copy);
		INM_PAGE_UNMAP(dst, pg->page, KM_SOFTIRQ0);
	
		pg_free -= to_copy;
		rem -= to_copy;
		buf_offset += to_copy;
		pg_offset += to_copy;

		if(pg_free == 0) {
			pg = PG_ENTRY(pg->next.next);
			pg_offset = 0;
			pg_free = INM_PAGESZ;
					
			if(((void *)pg == (void *)&node->data_pg_head)) {
				/* Detect any under/overrun */
				/* New offset should match old offset + len */
				if (((org_pg_offset + len) & (INM_PAGESZ - 1))
						!= pg_offset) {
					err("Data copy error: Org: %d Len: %d "
						"New: %d Last: 1", 
						org_pg_offset, len, pg_offset);
				}
				/* This is possible when TOLC is copied. So just return. */
				return;
			}	
		}

		if(rem == 0)
			break;
	}

	update_cur_dat_pg(node, pg, pg_offset);
	
	/* Detect any under/overrun */
	/* New offset should match old offset + len */
	pg = get_cur_data_pg(node, &pg_offset);
	if (((org_pg_offset + len) & (INM_PAGESZ - 1)) != pg_offset) {
		err("Data copy error: Org: %d Len: %d New: %d First: %d "
				"Last: %d", 
			org_pg_offset, len, pg_offset,
			CHANGE_NODE_IS_FIRST_DATA_PAGE(node, pg),
			CHANGE_NODE_IS_LAST_DATA_PAGE(node, pg));
	}

}

/*
 * Return 0 for success i.e. there is overflow
 * Return 1 for failure i.e. request can be satisfied
 *                           from tc's reservation
 */
static_inline int
inm_tc_resv_overflow(target_context_t *tgt_ctxt, inm_s32_t num_pages,
					 inm_u32_t *overflow_pages)
{
	inm_u32_t tc_allocated_pages = tgt_ctxt->tc_stats.num_pages_allocated;
	inm_u32_t tc_res_pages = tgt_ctxt->tc_reserved_pages;

	*overflow_pages = 0;

	/*
	 * Calculate overflow_pages
	 * case 1:Complete allocation can be done from tc's reserved pages
	 * case 2:Allocation is split into tc's reserved and dc's un-reserved area
	 * case 3:Complete allocation needs to be done from dc's unreserved pages
	 */
	if (tc_allocated_pages < tc_res_pages) {
		if ((tc_allocated_pages + num_pages) <= tc_res_pages) {
			/* case 1 */
			return 1;
		}
		else {
			/* case 2 */
			*overflow_pages = (tc_allocated_pages + num_pages) -
								tc_res_pages;
		}
	}
	else {
		/* case 3 */
		*overflow_pages = num_pages;
	}

	return 0;
}

void
inm_tc_resv_fill(void)
{
	struct inm_list_head *ptr, *nextptr;
	target_context_t *tgt_ctxt;

	ptr = NULL;
	nextptr = NULL;
	tgt_ctxt= NULL;

	/* 
	 * Allocate page reservations to target contexts if it didnt get pages
	 * earlier
	 */
	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	inm_list_for_each_safe(ptr, nextptr, &driver_ctx->tgt_list) {
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);

		/* If target is undergone for creation or deletion, reservation for
		 * it is not required here.
		 */
		 if (tgt_ctxt->tc_flags & (VCF_VOLUME_DELETING |
					 	VCF_VOLUME_CREATING))
			 continue;

		 volume_lock(tgt_ctxt);

		 /* Make an attempt to reserve pages if target does not have
		  * reservations
		  */
		 if (tgt_ctxt->tc_reserved_pages) {
			 volume_unlock(tgt_ctxt);
			 continue;
		 }

		 /* Not enough pages? */
		 if (inm_tc_resv_add(tgt_ctxt,
					 driver_ctx->dc_vol_data_pool_size)) {
			 volume_unlock(tgt_ctxt);
			 break;
		 }

		 volume_unlock(tgt_ctxt);

	} /* inm_list_for_each_safe */
	INM_UP_READ(&driver_ctx->tgt_list_sem);
}

int
inm_tc_resv_add(target_context_t *tgt_ctxt, inm_u32_t num_pages)
{
	inm_u32_t tc_allocated_pages = tgt_ctxt->tc_stats.num_pages_allocated;
	inm_u32_t num_unres_pages = 0;
	inm_u32_t updated_tc_reserved_pages;
	unsigned long lock_flag = 0;

	if (!num_pages)
		return 1;

	updated_tc_reserved_pages = tgt_ctxt->tc_reserved_pages + num_pages;
	/*
	 * Account currently tc's allocated pages and then evaluate the number
	 * of pages required from dc's unreserved pages
	 * case 1: tc's allocated pages < tc's current reservation
	 * case 2: tc's allocated pages > tc's current reservation and
	 *         tc's allocated pages < tc's new reservation
	 * case 3: tc's allocated pages > tc's new reservation
	 */
	if (tc_allocated_pages <= tgt_ctxt->tc_reserved_pages) {
		/* case 1 */
		num_unres_pages = num_pages;
	}
	else {
		if (tc_allocated_pages < updated_tc_reserved_pages) {
			/* case 2 */
			num_unres_pages = updated_tc_reserved_pages - 
							tc_allocated_pages;
		}
		else {
			/* case 3 */
			num_unres_pages = 0;
		}
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock,
								lock_flag);
	/* Do we have enough unrerved pages? */
	if (driver_ctx->dc_cur_unres_pages < num_unres_pages) {
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
							   lock_flag);
		return 1;
	}
	tgt_ctxt->tc_reserved_pages = updated_tc_reserved_pages;
	driver_ctx->dc_cur_unres_pages -= num_unres_pages;
	driver_ctx->dc_cur_res_pages += num_pages;
	if(driver_ctx->data_flt_ctx.dp_least_free_pgs > num_pages){
		driver_ctx->data_flt_ctx.dp_least_free_pgs -= num_pages;
	} else {
		driver_ctx->data_flt_ctx.dp_least_free_pgs = 0;
	}
	driver_ctx->data_flt_ctx.dp_pages_alloc_free -= num_pages;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
						   lock_flag);

	return 0;
}

int
inm_tc_resv_del(target_context_t *tgt_ctxt, inm_u32_t num_pages)
{
	inm_u32_t tc_allocated_pages = tgt_ctxt->tc_stats.num_pages_allocated;
	inm_u32_t num_unres_pages = 0;
	inm_u32_t updated_tc_reserve_pages;
	unsigned long lock_flag = 0;

	/* On target deinit path, we may have num_pages zero when
	 * target ctx didnt get any reservations
	 */
	if (!num_pages)
		return 0;

	if (num_pages > tgt_ctxt->tc_reserved_pages)
		return 1;
	
	updated_tc_reserve_pages = tgt_ctxt->tc_reserved_pages - num_pages;
	/*
	 * Account currently tc's allocated pages and then evaluate the number
	 * of pages required from dc's unreserved pages
	 * case 1: tc's allocated pages < tc's new reservation
	 * case 2: tc's allocated pages < tc's current reservation and
	 *         tc's allocated pages > tc's new reservation
	 * case 3: tc's allocated pages > tc's new reservation
	 */
	if (tc_allocated_pages <= updated_tc_reserve_pages) {
		/* case 1 */
		num_unres_pages = num_pages;
	}
	else {
		if (tc_allocated_pages < tgt_ctxt->tc_reserved_pages) {
			/* case 2 */
			num_unres_pages = tgt_ctxt->tc_reserved_pages -
							tc_allocated_pages;
		}
		else {
			/* case 3 */
			num_unres_pages = 0;
		}
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
							lock_flag);
	tgt_ctxt->tc_reserved_pages = updated_tc_reserve_pages;
	driver_ctx->dc_cur_unres_pages += num_unres_pages;
	driver_ctx->dc_cur_res_pages -= num_pages;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
						   lock_flag);
	INM_BUG_ON(driver_ctx->dc_cur_unres_pages > 
		(driver_ctx->data_flt_ctx.pages_allocated -
		 driver_ctx->dc_cur_res_pages));
	/* fill reservations for tc's with empty reservations */
	inm_tc_resv_fill();

	return 0;
}

inm_s32_t init_data_flt_ctxt(data_flt_t *data_ctxt)
{
	inm_u32_t num_pages = 0;
	inm_u32_t num_pages_req = 0;
	inm_u32_t nr_pages = 0;
#ifndef INM_AIX
	inm_u32_t gfp_mask = INM_KM_SLEEP|INM_KM_NORETRY;
#else
	inm_u32_t gfp_mask = 0;

#endif
	inm_u32_t total_ram_pgs = 0;
	inm_meminfo_t info;

	INM_SI_MEMINFO(&info);
	total_ram_pgs = info.totalram;

#ifndef INM_DEBUG
	gfp_mask |= INM_KM_NOWARN;
#endif

	INM_INIT_LIST_HEAD(&data_ctxt->data_pages_head);
	INM_INIT_SPIN_LOCK(&data_ctxt->data_pages_lock);
	data_ctxt->pages_allocated = 0;
	data_ctxt->pages_free = 0;

#ifdef CONFIG_HIGHMEM
	gfp_mask |= INM_KM_HIGHMEM;
#endif

	if (!driver_ctx->tunable_params.enable_data_filtering)
		return 0;

	// Fail driver load if 64MB can't be allocated
	num_pages = DEFAULT_DATA_POOL_SIZE_MB;
	num_pages <<= (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
	if(!alloc_data_pages(&data_ctxt->data_pages_head,
		num_pages, &data_ctxt->pages_allocated, gfp_mask)) {
		if(data_ctxt->pages_allocated) {
			free_data_pages(&data_ctxt->data_pages_head);
			data_ctxt->pages_allocated = 0;
		}
		err("Not enough data pages available for filtering");
			return -ENOMEM;
	}
	// Try to allocate 6.25% of total memory
	num_pages_req = driver_ctx->tunable_params.data_pool_size;
	num_pages_req <<= (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
	if (num_pages_req <= num_pages)
		goto init_dc_pages;
	// Do not fail driver load if memory allocation fails here
	if (alloc_data_pages(&data_ctxt->data_pages_head,
		num_pages_req - num_pages,
		&nr_pages, gfp_mask))
		driver_ctx->dc_pool_allocation_completed = 1;
	if(nr_pages)
		data_ctxt->pages_allocated += nr_pages;

init_dc_pages:
	data_ctxt->pages_free = data_ctxt->pages_allocated;
	driver_ctx->dc_cur_unres_pages = data_ctxt->pages_allocated;
	driver_ctx->data_flt_ctx.dp_pages_alloc_free = data_ctxt->pages_allocated;
	INM_BUG_ON(!driver_ctx->tunable_params.percent_change_data_pool_size);
	data_ctxt->dp_nrpgs_slab = (total_ram_pgs *
		driver_ctx->tunable_params.percent_change_data_pool_size) / 100;
	data_ctxt->dp_least_free_pgs = driver_ctx->dc_cur_unres_pages;
	INM_BUG_ON(driver_ctx->dc_cur_unres_pages >
		(driver_ctx->data_flt_ctx.pages_allocated -
		driver_ctx->dc_cur_res_pages));
	recalc_data_file_mode_thres();

	return 0;
}

void free_data_flt_ctxt(data_flt_t *data_ctxt)
{
	free_data_pages(&data_ctxt->data_pages_head);
	data_ctxt->pages_allocated = 0;
	data_ctxt->pages_free = 0;
}

int
add_data_pages(inm_u32_t num_pages)
{
	struct inm_list_head pg_head;
	inm_u32_t pgs_alloced = 0;
	unsigned long lock_flag = 0;
#ifndef INM_AIX
	inm_u32_t gfp_mask = INM_KM_SLEEP|INM_KM_NORETRY;
#else
	inm_u32_t gfp_mask = 0;
#endif

#ifndef INM_DEBUG
	gfp_mask |= INM_KM_NOWARN;
#endif

#ifdef CONFIG_HIGHMEM
	gfp_mask |= INM_KM_HIGHMEM;
#endif
 
	if(!num_pages){
		return 0;
	}
	INM_INIT_LIST_HEAD(&pg_head);	

	alloc_data_pages(&pg_head, num_pages, &pgs_alloced, gfp_mask);

	if (pgs_alloced == 0) {
		return 1;
	}

	/* Update data page pool */
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock,
								lock_flag); 
	inm_list_splice_at_tail(&pg_head,
			&(driver_ctx->data_flt_ctx.data_pages_head));
	driver_ctx->data_flt_ctx.pages_free += pgs_alloced;
	driver_ctx->data_flt_ctx.pages_allocated += pgs_alloced;
	driver_ctx->dc_cur_unres_pages += pgs_alloced;
	driver_ctx->data_flt_ctx.dp_pages_alloc_free += pgs_alloced;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
						   lock_flag);
	if (pgs_alloced != num_pages) {
		return 1;
	}

	INM_BUG_ON(driver_ctx->dc_cur_unres_pages > 
		(driver_ctx->data_flt_ctx.pages_allocated -
		 driver_ctx->dc_cur_res_pages));

	/* fill reservations for tc's with empty reservations */
	inm_tc_resv_fill();
	set_all_data_mode();

	return 0;
}

static inm_s32_t
should_wakeup_worker_alloc(inm_u32_t overflow_pages)
{
	inm_u32_t alloc_limit = 0, temp = 0;
	inm_s32_t ret = 0;

	alloc_limit = MIN(driver_ctx->data_flt_ctx.dp_nrpgs_slab,
			driver_ctx->data_flt_ctx.pages_allocated);	
	alloc_limit = (alloc_limit * MIN_FREE_PAGES_TO_ALLOC_SLAB_PERCENT) / 100;
	if (driver_ctx->dc_cur_unres_pages > overflow_pages) {
		temp = driver_ctx->dc_cur_unres_pages - overflow_pages;
	}
	if(alloc_limit > temp){
		ret = 1;
	}
	return ret;
}
		
int
get_data_pages(target_context_t *tgt_ctxt, struct inm_list_head *head, 
			   inm_s32_t num_pages)
{
	struct inm_list_head *ptr,*hd,*new, lhead;
	inm_s32_t pages_allocated = 0;
	inm_s32_t r = 0;
	unsigned long lock_flag = 0;
	inm_u32_t overflow_pages = 0;
	inm_s32_t wakeup = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered tcPages:%d freePages:%d ReqPages:%d dc_cur_unres_pages:%d",
			tgt_ctxt->tc_stats.num_pages_allocated,
			driver_ctx->data_flt_ctx.pages_free, num_pages,
			driver_ctx->dc_cur_unres_pages);
	}

	INM_BUG_ON(!num_pages);
	INM_BUG_ON(!driver_ctx);

	hd = &(driver_ctx->data_flt_ctx.data_pages_head);

	INM_INIT_LIST_HEAD(&lhead);
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock,
								lock_flag);

	/*
	 * Check if request can be satisfied from tc's reserve pool otherwise
	 * check if overflow pages (pages beyond tc's reservation)
	 * can be allocated dc's unreserved pool
	 */
	if (inm_tc_resv_overflow(tgt_ctxt, num_pages, &overflow_pages)) {
		goto allocate;
	}

	wakeup = should_wakeup_worker_alloc(overflow_pages);
	if (overflow_pages <= driver_ctx->dc_cur_unres_pages) {
		goto allocate;
	}
	else {
		goto unlock_return;
	}

allocate:
	for(ptr = hd->next; ptr != hd;) {
		new = ptr;    
		ptr = ptr->next;
		inm_list_del(new);
		inm_list_add_tail(new, &lhead);
		pages_allocated++;
		driver_ctx->data_flt_ctx.pages_free--;
		if(pages_allocated == num_pages)
			break;
	}
	driver_ctx->dc_cur_unres_pages -= overflow_pages;
	if(driver_ctx->data_flt_ctx.dp_least_free_pgs > overflow_pages){
	   driver_ctx->data_flt_ctx.dp_least_free_pgs -= overflow_pages;
	} else {
	   driver_ctx->data_flt_ctx.dp_least_free_pgs = 0;
	}
	if (pages_allocated != num_pages) {
		/* 
		 * The memory counters dont match due to some bug. Attempt to restore 
		 * sanity to memory counters. The (num_pages - pages_allocated) pages
		 * will be lost forever.
		 */
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
						   lock_flag);
		inm_rel_data_pages(tgt_ctxt, &lhead, pages_allocated);
		/* We are here as we ran out of data pool */
		wakeup = 1;
		/* return error */
		r = 0;
		INM_BUG_ON(pages_allocated != num_pages);
		goto out;
	} else {
		inm_list_splice_at_tail(&lhead, head);
		r = 1;
	}

unlock_return:
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
						   lock_flag);

out:
	 if(wakeup){
		 INM_SPIN_LOCK_IRQSAVE(&(driver_ctx->wqueue.lock), lock_flag);
		 driver_ctx->wqueue.flags |= WQ_FLAGS_REORG_DP_ALLOC;
		 INM_ATOMIC_INC(&(driver_ctx->wqueue.wakeup_event_raised));
		 INM_WAKEUP_INTERRUPTIBLE(&(driver_ctx->wqueue.wakeup_event));
		 INM_COMPLETE(&(driver_ctx->wqueue.new_event_completion));
		 INM_SPIN_UNLOCK_IRQRESTORE(&(driver_ctx->wqueue.lock),
				 				lock_flag);
	 }

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving tcPages:%d freePages:%d ReqPages:%d dc_cur_unres_pages:%d",
			tgt_ctxt->tc_stats.num_pages_allocated,
			driver_ctx->data_flt_ctx.pages_free, num_pages,
			driver_ctx->dc_cur_unres_pages);
	}
	if (!r)
		set_malloc_fail_error(tgt_ctxt);
   
	return r;
}

/*
 * inm_rel_data_pages()
 * @tcp     : target_context_t ptr variable
 * @lhp     : struct inm_list_head ptr variable
 * @nrpgs   : # of pages in the list
 *
 * notes    : adds pages from input list to the global list (driver context)
 *            Caller must decrement tc_stats.num_pages_allocated before
 *            calling this function
 */
int
inm_rel_data_pages(target_context_t *tcp, struct inm_list_head *lhp,
					inm_u32_t nrpgs)
{
	struct inm_list_head *ptr = NULL,*nextptr = NULL;
	inm_u32_t nr_oflow_pgs = 0;
	unsigned long lock_flag = 0;
	inm_s32_t ret = -1;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	inm_tc_resv_overflow(tcp, nrpgs, &nr_oflow_pgs);

	INM_BUG_ON(!driver_ctx);

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);
	inm_list_for_each_safe(ptr, nextptr, lhp) {
		inm_list_del(ptr);
		inm_list_add_tail(ptr, 
				&driver_ctx->data_flt_ctx.data_pages_head);
		driver_ctx->data_flt_ctx.pages_free++;
	}

	if (nr_oflow_pgs) {
		driver_ctx->dc_cur_unres_pages += nr_oflow_pgs;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);
	INM_BUG_ON(driver_ctx->dc_cur_unres_pages > 
		(driver_ctx->data_flt_ctx.pages_allocated -
		 driver_ctx->dc_cur_res_pages));
	ret = 0;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return ret;
}
/* 
 * this function would allocate pages from page head passed to the function
 * returns number of pages allocated
 * There should not be any failure in this function as pages are preallocated
 */
int
inm_get_pages_for_node(change_node_t *chg_node, struct inm_list_head *pg_head, 
						inm_s32_t len)
{
	inm_s32_t bytes_req, new, chg_sz;
	inm_u32_t num_pages;
	inm_u32_t pg_cnt;
	struct inm_list_head *headp, *next_headp;
	struct inm_list_head headp_local;

	new = 0;
	num_pages = 0;
	pg_cnt = 0;
	chg_sz = sv_chg_sz + len;
	headp = NULL;
	next_headp = NULL;

	if(chg_sz > chg_node->data_free)
		bytes_req = (chg_sz - chg_node->data_free);
	else 
		bytes_req = 0;

	if (is_new_data_node(chg_node))
	{
		bytes_req += sv_const_sz;
		new = 1;
	}

	INM_INIT_LIST_HEAD(&headp_local);
	num_pages = bytes_to_pages(bytes_req);
	pg_cnt = num_pages;
	
	/* Allocate pages from pg_head */
	inm_list_for_each_safe(headp, next_headp, pg_head) {
		inm_list_del(headp);
		inm_list_add_tail(headp, &headp_local);
		pg_cnt--;
		if (!pg_cnt)
			break;
	}

	if (bytes_req) {
		inm_list_splice_at_tail(&headp_local,
						&(chg_node->data_pg_head));
		chg_node->data_free += (num_pages * INM_PAGESZ);
		chg_node->changes.num_data_pgs += num_pages;
	}

	if (new) {
		chg_node->cur_data_pg = PG_ENTRY(chg_node->data_pg_head.next);
		chg_node->cur_data_pg_off = sv_pref_sz;
		chg_node->data_free -= sv_const_sz;
	}

	return num_pages;
}

inm_u32_t
inm_split_change_in_data_mode(target_context_t *tgt_ctxt, 
			write_metadata_t *wmd, inm_wdata_t *wdatap)
{
	change_node_t *chg_node = NULL;
	SVD_DIRTY_BLOCK_V2 dblock;
	struct inm_list_head *headp, *next_headp;
	inm_u32_t nr_splits;
	struct inm_list_head pg_head;
	disk_chg_t *disk_chg_ptr = NULL;
	inm_s32_t num_pages, total_num_pages, i;
	struct inm_list_head split_chg_node_list;
	static const SVD_PREFIX db_prefix = {SVD_TAG_DIRTY_BLOCK_DATA_V2, 1, 0};
	int perf_changes = 1;
	int is_barrier_on = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered %u", wmd->length);
	}

	num_pages = 0;
	total_num_pages = 0;

#ifdef INM_QUEUE_RQ_ENABLED
	if ((INM_ATOMIC_READ(&driver_ctx->is_iobarrier_on)) ) {
		is_barrier_on = 1;
		if(!(tgt_ctxt->tc_flags & VCF_IO_BARRIER_ON)) {
			tgt_ctxt->tc_flags |= VCF_IO_BARRIER_ON;
		}

		perf_changes = 0;
	}
#endif
	if (tgt_ctxt->tc_cur_node && (tgt_ctxt->tc_optimize_performance &
		PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) && perf_changes) {
		INM_BUG_ON(!inm_list_empty(&tgt_ctxt->tc_cur_node->nwo_dmode_next));
		do_perf_changes(tgt_ctxt, tgt_ctxt->tc_cur_node, IN_IO_PATH);
	}
   	tgt_ctxt->tc_cur_node = NULL;
   	nr_splits = split_change_into_chg_node(tgt_ctxt, wmd, NODE_SRC_DATA, 
					&split_chg_node_list, wdatap);

 	/*
	 * on error, release half baked change node entries and set volume as out 
	 * of sync
	 */
   	if (INM_UNLIKELY(nr_splits <= 0)) {
		err("Failed to get current change node");
		free_changenode_list(tgt_ctxt, ecSplitIOFailed);
		queue_worker_routine_for_set_volume_out_of_sync(tgt_ctxt,
				ERROR_TO_REG_OUT_OF_MEMORY_FOR_DIRTY_BLOCKS,
				-ENOMEM);
		return 0;
	}
	/* Calculate total bytes of memory required to store current change 
	 * in split nodes
	 */
	inm_list_for_each_safe(headp, next_headp, &split_chg_node_list) {
		chg_node = inm_list_entry(headp, change_node_t, next);
   		disk_chg_ptr = (disk_chg_t*)chg_node->changes.cur_md_pgp;
   		/* change nodes are new hence we need to account 
		 * sv_chg_sz + sv_const_sz */
   		total_num_pages += bytes_to_pages(disk_chg_ptr->length +
						   sv_chg_sz + sv_const_sz);
	}
	INM_INIT_LIST_HEAD(&pg_head);    
	/* Allocate data pages in one go */	
	if (!get_data_pages(tgt_ctxt, &pg_head, total_num_pages)) {
		goto error;
	}

	/* allocate data pages to split io change nodes */
	inm_list_for_each_safe(headp, next_headp, &split_chg_node_list) {
		chg_node = inm_list_entry(headp, change_node_t, next);
   		INM_BUG_ON(chg_node->changes.cur_md_pgp == NULL);
   		disk_chg_ptr = (disk_chg_t*)chg_node->changes.cur_md_pgp;

   		/* Allocate data pages for the current change node */
		num_pages = inm_get_pages_for_node(chg_node, &pg_head, 
			    				disk_chg_ptr->length);
		if (!num_pages) {
			/* should not be here */
			INM_BUG_ON(1);
			goto error;
		}

		/* It is safe to copy data to split io change nodes. We have already
		 * updated offsets of data pages, but that really does not matter in 
		 * case of roll back
		 */
		dblock.Length = disk_chg_ptr->length;
		dblock.ByteOffset = disk_chg_ptr->offset;
		dblock.uiSequenceNumberDelta = disk_chg_ptr->seqno_delta;
		dblock.uiTimeDelta = disk_chg_ptr->time_delta;
		copy_data_to_data_pages((void *)&db_prefix, sizeof(SVD_PREFIX),
			chg_node);
		copy_data_to_data_pages((void *)&dblock,
				sizeof(SVD_DIRTY_BLOCK_V2), chg_node);

		/* update chnage nodes information for data page copy */
		chg_node->data_free  -= (sv_chg_sz);
		chg_node->stream_len += (sv_chg_sz);
		/* Align the data_free to length for copy_bio function
		 * This is a split IO path and copy_biodata_to_data_pages is shared 
		 * by non-split and split IO paths. disk_chg_ptr.length value is
		 * sector (512 bytes) aligned value. For split IO path, we dont want to  
		 * change copy_bio.. functions at this stage and can rely change nodes
		 * data_free member to only copy sector aligned bytes.
		 */
		chg_node->data_free = disk_chg_ptr->length;
	}

	/* On successful allocation, make copy of bio pages and necessary updates
   	 * to the target context and change nodes, otherwise roll back
   	 */

	(*wdatap->wd_copy_wd_to_datapgs)(tgt_ctxt,wdatap, 
						split_chg_node_list.next);

	if (is_barrier_on) {
		goto add_change_node_to_list;
	}

	/* Update change node variables -- data_free and stream_len */
	inm_list_for_each_safe(headp, next_headp, &split_chg_node_list) {
		chg_node = inm_list_entry(headp, change_node_t, next);
   		disk_chg_ptr = (disk_chg_t*)chg_node->changes.cur_md_pgp;

		/* update chnage nodes information for data page copy */
		chg_node->data_free  -= (disk_chg_ptr->length);
		chg_node->stream_len += (disk_chg_ptr->length);
		if (tgt_ctxt->tc_optimize_performance &
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) {
			if (chg_node->wostate != ecWriteOrderStateData &&
				inm_list_empty(&chg_node->nwo_dmode_next)) {
				chg_node->flags |= CHANGE_NODE_IN_NWO_CLOSED;
				inm_list_add_tail(&chg_node->nwo_dmode_next,
						&tgt_ctxt->tc_nwo_dmode_list);
				if (tgt_ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DATA_DRAIN) {
					info("SplitIO Appending chg:%p tgt_ctxt:%p next:%p prev:%p mode:%d",
						chg_node,tgt_ctxt, chg_node->nwo_dmode_next.next,
						chg_node->nwo_dmode_next.prev, chg_node->type);
				}
			}
		}
	}

add_change_node_to_list:
   	/*
	 * Append the split IO change nodes in to target head list of change nodes
	 */
#ifdef INM_QUEUE_RQ_ENABLED
	if (is_barrier_on) {
		inm_list_splice_at_tail(&split_chg_node_list,
			&chg_node->vcptr->tc_non_drainable_node_head);
	}
	else {
		if(!inm_list_empty(&chg_node->vcptr->tc_non_drainable_node_head)) {
			do_perf_changes_all(chg_node->vcptr, IN_IO_PATH);
			chg_node->vcptr->tc_flags &= ~VCF_IO_BARRIER_ON;
			inm_list_splice_at_tail(&chg_node->vcptr->tc_non_drainable_node_head,
				&chg_node->vcptr->tc_node_head);
			INM_INIT_LIST_HEAD(&chg_node->vcptr->tc_non_drainable_node_head);
		}
		inm_list_splice_at_tail(&split_chg_node_list,
					&chg_node->vcptr->tc_node_head);
	}
#else
	inm_list_splice_at_tail(&split_chg_node_list,
					&chg_node->vcptr->tc_node_head);
#endif

	/* Update total number of data pages allocated */
	tgt_ctxt->tc_stats.num_pages_allocated += total_num_pages;

	/* Updates to target context information variables */
	tgt_ctxt->tc_pending_changes += nr_splits;
	tgt_ctxt->tc_cnode_pgs += nr_splits;
	INM_BUG_ON(tgt_ctxt->tc_pending_changes < 0 );
	tgt_ctxt->tc_bytes_pending_changes += wmd->length;
	add_changes_to_pending_changes(tgt_ctxt, tgt_ctxt->tc_cur_wostate,
								nr_splits);

   	/* Queue change node(s) to file thread if required */
	for (i=0; (i<nr_splits && should_write_to_datafile(tgt_ctxt)); i++)
	{
		chg_node = get_change_node_to_save_as_file(tgt_ctxt);
		if(chg_node) {
			queue_chg_node_to_file_thread(tgt_ctxt, chg_node);
			deref_chg_node(chg_node);
		}
	}

	return nr_splits;

error :
	dbg("switching to metadata mode \n");
	set_tgt_ctxt_filtering_mode(tgt_ctxt, FLT_MODE_METADATA, FALSE);

	if(ecWriteOrderStateData == tgt_ctxt->tc_cur_wostate)
	set_tgt_ctxt_wostate(tgt_ctxt, ecWriteOrderStateMetadata, FALSE,
						 ecWOSChangeReasonDChanges);

	/* mark them as metadata change nodes */
	inm_list_for_each_safe(headp, next_headp, &split_chg_node_list) {

		chg_node = inm_list_entry(headp, change_node_t, next);
		chg_node->type = NODE_SRC_METADATA;
		/* If change node on non write order data mode list, then
		 * remove it from that list
		 */
		if (!inm_list_empty(&chg_node->nwo_dmode_next)) {
			inm_list_del_init(&chg_node->nwo_dmode_next);
		}
	   	chg_node->wostate = tgt_ctxt->tc_cur_wostate;
	}
	/*
	 * Append the split IO change nodes in to target head list of change nodes
	 */
	inm_list_splice_at_tail(&split_chg_node_list, 
					&chg_node->vcptr->tc_node_head);

	/* Updates to target context information variables */
	tgt_ctxt->tc_pending_changes += nr_splits;
	tgt_ctxt->tc_cnode_pgs += nr_splits;
	tgt_ctxt->tc_bytes_pending_changes += wmd->length;
	tgt_ctxt->tc_pending_md_changes += nr_splits;
	tgt_ctxt->tc_bytes_pending_md_changes += wmd->length;
	add_changes_to_pending_changes(tgt_ctxt, tgt_ctxt->tc_cur_wostate,
							nr_splits);
	return 0;
}

void
save_data_in_data_mode_normal(target_context_t *tgt_ctxt,
			write_metadata_t *wmd, inm_wdata_t *wdatap)
{
	inm_u32_t num_pages = 0;
	struct inm_list_head pg_head;
	change_node_t *chg_node = NULL;
	inm_s32_t bytes_req, chg_sz, new = 0;
	SVD_DIRTY_BLOCK_V2 dblock;
	static const SVD_PREFIX db_prefix = {SVD_TAG_DIRTY_BLOCK_DATA_V2, 1, 0};
	inm_tsdelta_t ts_delta;
	char *map_addr;
	inm_s32_t ret;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}

	ret = inm_xm_mapin(tgt_ctxt, wdatap, &map_addr);
	if(ret){
	dbg("switching to metadata mode \n");
	set_tgt_ctxt_filtering_mode(tgt_ctxt, FLT_MODE_METADATA, FALSE);

	if(ecWriteOrderStateData == tgt_ctxt->tc_cur_wostate)
		set_tgt_ctxt_wostate(tgt_ctxt, ecWriteOrderStateMetadata, FALSE,
					 ecWOSChangeReasonUnInitialized);

	if (save_data_in_metadata_mode(tgt_ctxt, wmd, wdatap))
			err("save_data_in_metadata_mode failed");

	return;
	}

	dblock.ByteOffset = wmd->offset;
	dblock.Length = wmd->length;
	chg_sz = (sv_chg_sz + dblock.Length);

	chg_node = get_change_node_to_update(tgt_ctxt, wdatap, &ts_delta); 
	if(!chg_node) {
		err("Failed to get current change node");
	queue_worker_routine_for_set_volume_out_of_sync(tgt_ctxt,
				ERROR_TO_REG_OUT_OF_MEMORY_FOR_DIRTY_BLOCKS,
				-ENOMEM);
	inm_xm_det(wdatap, map_addr);
		return;
	}

	if(chg_sz > chg_node->data_free)
		bytes_req = (chg_sz - chg_node->data_free);
	else
		bytes_req = 0;

	if(is_new_data_node(chg_node)) {
		bytes_req += sv_const_sz;
		new = 1;
	}

	INM_INIT_LIST_HEAD(&pg_head);    
	num_pages = bytes_to_pages(bytes_req);
	
	if (bytes_req && !get_data_pages(tgt_ctxt, &pg_head, num_pages)) {
		inm_xm_det(wdatap, map_addr);
		inm_claim_metadata_page(tgt_ctxt, chg_node, wdatap);
		dbg("switching to metadata mode \n");
		set_tgt_ctxt_filtering_mode(tgt_ctxt, FLT_MODE_METADATA, FALSE);

		if(ecWriteOrderStateData == tgt_ctxt->tc_cur_wostate)
			set_tgt_ctxt_wostate(tgt_ctxt, ecWriteOrderStateMetadata, FALSE,
						 ecWOSChangeReasonDChanges);

		if (save_data_in_metadata_mode(tgt_ctxt, wmd, wdatap)) {
			err("save_data_in_metadata_mode failed");		
		}
		return;
	}

	if(bytes_req) {
		inm_list_splice_at_tail(&pg_head, &(chg_node->data_pg_head));
		chg_node->data_free += (num_pages * INM_PAGESZ);
		tgt_ctxt->tc_stats.num_pages_allocated += num_pages;
		chg_node->changes.num_data_pgs += num_pages;
	}

	if(new) {
		chg_node->cur_data_pg = PG_ENTRY(chg_node->data_pg_head.next);
		chg_node->cur_data_pg_off = sv_pref_sz;
		chg_node->data_free -= sv_const_sz;
	}

	if (chg_node->wostate != ecWriteOrderStateData) {
		ts_delta.td_time = 0;
		ts_delta.td_seqno = 0;
	}
	dblock.uiTimeDelta = ts_delta.td_time;
	dblock.uiSequenceNumberDelta = ts_delta.td_seqno;
	update_change_node(chg_node, wmd, &ts_delta);
	copy_data_to_data_pages((void *)&db_prefix, sizeof(SVD_PREFIX), 
								chg_node);
	copy_data_to_data_pages((void *)&dblock, sizeof(SVD_DIRTY_BLOCK_V2), 
								chg_node);

#ifdef INM_AIX
	inm_copy_buf_data_to_datapgs(wdatap, &chg_node->next, map_addr);
#else
	INM_BUG_ON(!wdatap->wd_copy_wd_to_datapgs);
	(*wdatap->wd_copy_wd_to_datapgs)(tgt_ctxt, wdatap, &chg_node->next);
#endif
	inm_xm_det(wdatap, map_addr);
	chg_node->data_free -= chg_sz;
	chg_node->stream_len += (sv_chg_sz + dblock.Length);

	tgt_ctxt->tc_pending_changes++;
	INM_BUG_ON(tgt_ctxt->tc_pending_changes < 0 );
	tgt_ctxt->tc_bytes_pending_changes += dblock.Length;
	add_changes_to_pending_changes(tgt_ctxt, chg_node->wostate, 1);

	if(should_write_to_datafile(tgt_ctxt)) {
	chg_node = get_change_node_to_save_as_file(tgt_ctxt);
	if(chg_node) {
		queue_chg_node_to_file_thread(tgt_ctxt, chg_node);
		deref_chg_node(chg_node);
	}
	}	
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	
	
}

void save_data_in_data_mode(target_context_t *tgt_ctxt, write_metadata_t *wmd,
				inm_wdata_t *wdatap)
{
	inm_u32_t nr_changeNodes;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered %u", wmd->length);
	}

	/* split the IO larger than MAX_DATA_SIZE_PER_DATA_MODE_CHANGE_NODE */
	if ( (sv_const_sz + sv_chg_sz + wmd->length) >
		driver_ctx->tunable_params.max_data_sz_dm_cn) {
#ifdef INM_AIX
		dbg("switching to metadata mode due to split I/O of length %d\n", 
								wmd->length);
		set_tgt_ctxt_filtering_mode(tgt_ctxt, FLT_MODE_METADATA, FALSE);
		if(ecWriteOrderStateData == tgt_ctxt->tc_cur_wostate)
			set_tgt_ctxt_wostate(tgt_ctxt, ecWriteOrderStateMetadata, 
					FALSE, ecWOSChangeReasonUnInitialized);

		if (save_data_in_metadata_mode(tgt_ctxt, wmd, wdatap))
			err("save_data_in_metadata_mode failed");

		tgt_ctxt->tc_nr_spilt_io_data_mode++;
#else
		if (wdatap->wd_flag & INM_WD_WRITE_OFFLOAD) {
			err("Offload write greater than change node size %llu:%u", 
				wmd->offset, wmd->length);
			queue_worker_routine_for_set_volume_out_of_sync(tgt_ctxt,
				ERROR_TO_REG_UNSUPPORTED_IO, -EOPNOTSUPP);
			INM_BUG_ON(wdatap->wd_flag & INM_WD_WRITE_OFFLOAD);
		} else {
		nr_changeNodes = inm_split_change_in_data_mode(tgt_ctxt, wmd,
				 	wdatap);
		if (!nr_changeNodes)
			err("Memory allocation failure\n");
		}
#endif
	}
	else {
		save_data_in_data_mode_normal(tgt_ctxt, wmd, wdatap);
	}
	is_metadata_due_to_delay_alloc(tgt_ctxt);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}

}

/* This gets called when driver detects that drainer is going down. */
void data_mode_cleanup_for_s2_exit()
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

 	 
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	
}

void finalize_data_stream(change_node_t *node)
{
	SVD_PREFIX prefix;
	SVD_HEADER1 hdr;
	SVD_TIME_STAMP_V2 svd_ts;
	inm_u64_t drtd_chgs;
	inm_u32_t endian_tag = 0;
	
	INM_BUG_ON(inm_list_empty(&node->data_pg_head));

	prefix.Flags = 0;
	prefix.count = 1;
	memcpy_s(&svd_ts, sizeof(STREAM_REC_HDR_4B), 
		(void *)&node->changes.start_ts, sizeof(STREAM_REC_HDR_4B));
   
	/* Write TOLC. */
	prefix.tag = SVD_TAG_TIME_STAMP_OF_LAST_CHANGE_V2;
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), node);
	svd_ts.ullSequenceNumber = node->changes.end_ts.ullSequenceNumber;
	svd_ts.TimeInHundNanoSecondsFromJan1601 =
			node->changes.end_ts.TimeInHundNanoSecondsFromJan1601;
	copy_data_to_data_pages(&svd_ts, sizeof(SVD_TIME_STAMP_V2), node);
	node->stream_len += sv_ts_sz;

	/* Reset the pointers to start of the data page. */
	update_cur_dat_pg(node, PG_ENTRY(node->data_pg_head.next), 0);

	/*Write Endian string */
	 if (inm_is_little_endian()) {
		 endian_tag = SVD_TAG_LEFORMAT;
	 } else {
		 endian_tag = SVD_TAG_BEFORMAT;
	 }
	 copy_data_to_data_pages(&endian_tag, sizeof(endian_tag), node);
	 node->stream_len += sizeof(endian_tag);

	/* Write SVD_HEADER1 */
	prefix.tag = SVD_TAG_HEADER1;
	INM_MEM_ZERO(&hdr, sizeof(SVD_HEADER1));
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), node);
	copy_data_to_data_pages(&hdr, sizeof(SVD_HEADER1), node);
	node->stream_len += sv_hdr_sz;

	/* Write TOFC */
	prefix.tag = SVD_TAG_TIME_STAMP_OF_FIRST_CHANGE_V2;
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), node);
	svd_ts.ullSequenceNumber = node->changes.start_ts.ullSequenceNumber;
	svd_ts.TimeInHundNanoSecondsFromJan1601 = 
		node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;
	copy_data_to_data_pages(&svd_ts, sizeof(SVD_TIME_STAMP_V2), node);

	node->stream_len += sv_ts_sz;

	/* Write DRTD changes */
	prefix.tag = SVD_TAG_LENGTH_OF_DRTD_CHANGES;
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), node);
	drtd_chgs = get_drtd_len(node);
	copy_data_to_data_pages(&drtd_chgs, sizeof(inm_u64_t), node);   
	node->stream_len += sv_drtd_sz;

	node->flags |= CHANGE_NODE_DATA_STREAM_FINALIZED;	
	if (verify_change_node_file(node))
		err("File bad on finalize");
}

void recalc_data_file_mode_thres(void)
{
	unsigned long lock_flag;
	inm_u32_t free_pages_thres = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);
	free_pages_thres =
	(((driver_ctx->data_flt_ctx.pages_allocated -
		driver_ctx->dc_cur_res_pages)*
	(driver_ctx->tunable_params.free_percent_thres_for_filewrite)) / 100);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
						   lock_flag);
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.free_pages_thres_for_filewrite = free_pages_thres;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
}

inm_s32_t add_tag_in_stream_mode(tag_volinfo_t *tag_volinfop,
	tag_info_t *tag_buf, inm_s32_t num_tags, tag_guid_t *tag_guid, 
	inm_s32_t index)
{
	target_context_t *ctxt = tag_volinfop->ctxt;
	change_node_t *chg_node = NULL;
	inm_s32_t bytes_req = 0;
	inm_u32_t num_pages = 0;
	struct inm_list_head pg_head;
	SVD_PREFIX prefix;
	SVD_HEADER1 hdr;
	SVD_TIME_STAMP_V2 svd_ts;
	inm_s32_t idx = 0;
	inm_u32_t endian_tag = 0, status = 1;
#ifdef INM_AIX
	inm_wdata_t wdata;
#endif

	dbg("Issuing tag in stream mode");

	prefix.Flags = 0;
	prefix.count = 1;

	if(tag_buf->tag_len == 0){
		if(tag_guid)
			tag_guid->status[index] = STATUS_FAILURE;
		return 1;
	}

	INM_INIT_LIST_HEAD(&pg_head);

	bytes_req += (sizeof(endian_tag) + sv_hdr_sz + (2 * sv_ts_sz));

	while(idx < num_tags) {
		bytes_req += (sizeof(SVD_PREFIX) + tag_buf->tag_len);
		idx++;   
	}
	idx = 0;

	num_pages = bytes_to_pages(bytes_req);

	if(!get_data_pages(ctxt, &pg_head, num_pages)) {
		set_tgt_ctxt_filtering_mode(ctxt, FLT_MODE_METADATA, FALSE);
		if(ecWriteOrderStateData == ctxt->tc_cur_wostate)
			set_tgt_ctxt_wostate(ctxt, ecWriteOrderStateMetadata, FALSE,
					 ecWOSChangeReasonUnInitialized);
		is_metadata_due_to_delay_alloc(ctxt);
		status = 0;
		goto out_err;
	}

#ifdef INM_AIX
	INM_MEM_ZERO(&wdata, sizeof(inm_wdata_t));
	wdata.wd_chg_node = tag_volinfop->chg_node;
	wdata.wd_meta_page = tag_volinfop->meta_page;
	chg_node = get_change_node_for_usertag(ctxt, &wdata, 
						TAG_COMMIT_NOT_PENDING);
	tag_volinfop->chg_node = wdata.wd_chg_node;
	tag_volinfop->meta_page = wdata.wd_meta_page;
#else
	chg_node = get_change_node_for_usertag(ctxt, NULL, 
						TAG_COMMIT_NOT_PENDING);
#endif
	if(!chg_node) {
		inm_rel_data_pages(ctxt, &pg_head, num_pages);
		err("Failed to get change node for adding tag");
		status = 0;
		goto out_err;
	}

	inm_list_splice_at_tail(&pg_head, &(chg_node->data_pg_head));
	chg_node->data_free += (num_pages * INM_PAGESZ);
	ctxt->tc_stats.num_pages_allocated += num_pages;
	chg_node->changes.num_data_pgs += num_pages;

	update_cur_dat_pg(chg_node, PG_ENTRY(chg_node->data_pg_head.next), 0);

	/* Write Endian string */
	 if (inm_is_little_endian()) {
		 endian_tag = SVD_TAG_LEFORMAT;
	 } else {
		 endian_tag = SVD_TAG_BEFORMAT;
	 }
	 copy_data_to_data_pages(&endian_tag, sizeof(endian_tag), chg_node);
	 chg_node->stream_len += sizeof(endian_tag);

	/* Copy SVD_HEADER1 */
	prefix.tag = SVD_TAG_HEADER1;
	INM_MEM_ZERO(&hdr, sizeof(SVD_HEADER1));
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), chg_node);
	copy_data_to_data_pages(&hdr, sizeof(SVD_HEADER1), chg_node);
	chg_node->stream_len += sv_hdr_sz;

	/* Copy TOFC */
	prefix.tag = SVD_TAG_TIME_STAMP_OF_FIRST_CHANGE_V2;
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), chg_node);
	memcpy_s(&svd_ts.Header, sizeof(STREAM_REC_HDR_4B),
	(void *)&chg_node->changes.start_ts.Header, sizeof(STREAM_REC_HDR_4B));
	svd_ts.TimeInHundNanoSecondsFromJan1601 =
	chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;
	svd_ts.ullSequenceNumber =
	chg_node->changes.start_ts.ullSequenceNumber;
	copy_data_to_data_pages(&svd_ts, sizeof(SVD_TIME_STAMP_V2), chg_node);

	chg_node->stream_len += sv_ts_sz;

	while(idx < num_tags) {
		/* Copy Tag */
		prefix.tag = SVD_TAG_USER;
		prefix.Flags = tag_buf->tag_len;
		copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), chg_node);
		copy_data_to_data_pages(&tag_buf->tag_name[0], 
						tag_buf->tag_len, chg_node);
		chg_node->stream_len += (sizeof(SVD_PREFIX) + tag_buf->tag_len);

		tag_buf++;
		idx++;
	}

	/* Copy TOLC */
	prefix.tag = SVD_TAG_TIME_STAMP_OF_LAST_CHANGE_V2;
	copy_data_to_data_pages(&prefix, sizeof(SVD_PREFIX), chg_node);
	svd_ts.TimeInHundNanoSecondsFromJan1601 =
	chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601;
	svd_ts.ullSequenceNumber =
	chg_node->changes.end_ts.ullSequenceNumber;
	copy_data_to_data_pages(&svd_ts, sizeof(SVD_TIME_STAMP_V2), chg_node);

	chg_node->stream_len += sv_ts_sz;

	chg_node->flags |= CHANGE_NODE_DATA_STREAM_FINALIZED;
	chg_node->flags |= CHANGE_NODE_TAG_IN_STREAM;

	if(tag_guid){
		tag_guid->status[index] = STATUS_PENDING;
		chg_node->tag_status_idx = index;
	}

	chg_node->tag_guid = tag_guid;
	dbg("Tag Issued Successfully to volume %s", ctxt->tc_guid);
	goto out;
out_err:
	if(tag_guid)
		tag_guid->status[index] = STATUS_FAILURE;
out:
	return status;
}

static inm_s32_t
is_metadata_due_to_delay_alloc(target_context_t *tcp)
{
	inm_u32_t data_pool_size = 0;
	unsigned long lock_flag;
	inm_s32_t ret = 0;

	if(tcp->tc_cur_mode != FLT_MODE_METADATA){
		goto out;
	}
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
		data_pool_size = driver_ctx->tunable_params.data_pool_size;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	data_pool_size <<= (MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);
	if(driver_ctx->data_flt_ctx.pages_allocated < data_pool_size){
		ret = 1;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);

out:
	if(ret){
		INM_ATOMIC_INC(&(tcp->tc_stats.metadata_trans_due_to_delay_alloc));
	}
	return ret;
}

static inm_s32_t
set_all_data_mode(void)
{
	inm_list_head_t *ptr = NULL, *nextptr = NULL;
	target_context_t *tcp = NULL;
	inm_s32_t ret = 0;

	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	inm_list_for_each_safe(ptr, nextptr,  &driver_ctx->tgt_list) {
		tcp = inm_list_entry(ptr, target_context_t, tc_list);
		if(tcp && tcp->tc_cur_mode == FLT_MODE_METADATA){
			set_tgt_ctxt_filtering_mode(tcp, FLT_MODE_DATA, FALSE);
		}
		tcp = NULL;
	}
	INM_UP_READ(&driver_ctx->tgt_list_sem);
	return ret;
}
