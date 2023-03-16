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
 * File       : change-node.c
 *
 * Description: change node implementation.
 */

#include "involflt-common.h"
#include "involflt.h"
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
#include "change-node.h"
#include "tunable_params.h"
#include "driver-context.h"
#include "file-io.h"
#include "utils.h"
#include "involflt_debug.h"
#include "metadata-mode.h"
#include "db_routines.h"
#include "telemetry-types.h"
#include "telemetry.h"
#include "verifier.h"

extern void finalize_data_stream(change_node_t *);
extern driver_context_t *driver_ctx;

int print_dblk_filename(change_node_t *chg_node);
void print_change_node_off_length(change_node_t *chg_node);
inm_s32_t verify_change_node(change_node_t *chg_node);

/*
 * change_node_drain_barrier_set
 *
 * Marks a change node as drain barrier. 
 */
static inline void
change_node_drain_barrier_set(target_context_t *ctxt, change_node_t *chg_node)
{
	INM_BUG_ON(ctxt->tc_cur_wostate != ecWriteOrderStateData);
	chg_node->flags |= CHANGE_NODE_DRAIN_BARRIER;
}


/*
 * change_node_drain_barrier_clear
 *
 * Remove the barrier flag from change node
 */
static inline void
change_node_drain_barrier_clear(change_node_t *chg_node)
{
	INM_BUG_ON(!IS_CHANGE_NODE_DRAIN_BARRIER(chg_node));
	chg_node->flags &= ~CHANGE_NODE_DRAIN_BARRIER;
}

/*
 * commit_tag_for_one_volume
 *
 * Commit tag for one volume by removing the drain barrier on tag node
 */
inm_s32_t
commit_usertag(target_context_t *ctxt)
{
	inm_list_head_t *ptr = NULL;
	inm_list_head_t *next = NULL;
	change_node_t   *chg_node = NULL;
	int             commit = 0;

	volume_lock(ctxt);
   
	inm_list_for_each_safe(ptr, next, &ctxt->tc_node_head) {
		chg_node = inm_list_entry(ptr, change_node_t, next);
		if (chg_node->type == NODE_SRC_TAGS &&
			IS_CHANGE_NODE_DRAIN_BARRIER(chg_node)) {
			dbg("Commit CN %p", chg_node);
			change_node_drain_barrier_clear(chg_node);
			commit = 1;
			break;
		}
	}

	volume_unlock(ctxt);

	if (!commit) {
		err("Could not find change node to commit");
		return -1;
	} else {
		dbg("%p committed", chg_node);
		return 0;
	}
}

/*
 * revoke_tag_for_one_volume
 *
 * Revoke tag for one volume by removing the change node from db list
 */
void
revoke_usertag(target_context_t *ctxt, int timedout)
{
	inm_list_head_t *ptr = NULL;
	inm_list_head_t *next = NULL;
	change_node_t   *chg_node = NULL;
	change_node_t   *revoke = NULL;

	volume_lock(ctxt);
	inm_list_for_each_safe(ptr, next, &ctxt->tc_node_head) {
		chg_node = inm_list_entry(ptr, change_node_t, next);
		if (chg_node->type == NODE_SRC_TAGS &&
			IS_CHANGE_NODE_DRAIN_BARRIER(chg_node)) {
			dbg("revoke tag %p", chg_node);
			inm_list_del(&chg_node->next);
			change_node_drain_barrier_clear(chg_node);
			/* 
			 * Since this is only supported on async tags
			 * there is no need to update tag status tag_guid
			 */
			revoke = chg_node;
			break;
		}
	}
	volume_unlock(ctxt);

	if (revoke) {
		dbg("%p revoked", chg_node);
		telemetry_log_tag_history(revoke, ctxt, ecTagStatusRevoked, 
				              timedout ? ecRevokeTimeOut : 
					      ecRevokeCommitIOCTL, 
				              ecMsgTagRevoked);
		commit_change_node(chg_node);
	} else {
		err("Could not find change node to revoke");
	}
}

inm_s32_t init_change_node(change_node_t *node, inm_s32_t from_pool,
		inm_s32_t flag, inm_wdata_t *wdatap)
{
	inm_page_t *pgp = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	INM_ATOMIC_SET(&node->ref_cnt, 0);
	node->type = NODE_SRC_UNDEFINED;
	node->wostate = ecWriteOrderStateUnInitialized;
	node->flags = 0;	
	node->transaction_id = 0;
#ifdef INM_AIX
	if(!node->mutext_initialized)
	INM_INIT_SEM(&node->mutex);	
#else
	INM_INIT_SEM(&node->mutex);	
#endif
	INM_INIT_LIST_HEAD(&node->next);
	INM_INIT_LIST_HEAD(&node->nwo_dmode_next);
	INM_INIT_LIST_HEAD(&node->data_pg_head);
	node->cur_data_pg = NULL;
	node->cur_data_pg_off = -1;
	node->data_free = 0;	
	node->mapped_address = 0;
	node->mapped_thread = NULL;
	node->data_file_name = NULL;    
	node->data_file_size = 0;	
	node->stream_len = 0;

	FILL_STREAM_HEADER(&node->changes.start_ts,
		   STREAM_REC_TYPE_TIME_STAMP_TAG, sizeof(TIME_STAMP_TAG_V2));
	FILL_STREAM_HEADER(&node->changes.end_ts,
		   STREAM_REC_TYPE_TIME_STAMP_TAG, sizeof(TIME_STAMP_TAG_V2));

	get_time_stamp_tag(&node->changes.start_ts);


	/* keeping end time stamp, same as the start time stamp */
	node->changes.end_ts.ullSequenceNumber =
	node->changes.start_ts.ullSequenceNumber;
	node->changes.end_ts.TimeInHundNanoSecondsFromJan1601 =
	node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;

	INM_INIT_LIST_HEAD(&node->changes.md_pg_list);
	pgp = get_page_from_page_pool(from_pool, flag, wdatap);
	if (!pgp) {
		err("Failed to get the metadata page from the pool");
		return 0;
	}
	inm_list_add_tail(&pgp->entry, &node->changes.md_pg_list);
	node->changes.cur_md_pgp = pgp->cur_pg;
	node->changes.num_data_pgs = 0;
	node->changes.bytes_changes = 0;
	node->changes.change_idx = 0;
	node->vcptr = NULL;
	node->seq_id_for_split_io = 1;
	INM_ATOMIC_INC(&driver_ctx->stats.pending_chg_nodes);

	node->tag_guid = NULL;
	node->cn_hist = NULL;
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return 1;
}

change_node_t *
inm_alloc_change_node(inm_wdata_t *wdatap, unsigned flags)
{
	change_node_t *node = NULL;

#ifndef INM_AIX
	if(wdatap && wdatap->wd_chg_node){
		node = wdatap->wd_chg_node;
		wdatap->wd_chg_node = (change_node_t *) node->next.next;
		node->next.next = NULL;
	}else{
		node = INM_KMALLOC(sizeof(change_node_t), flags, INM_KERNEL_HEAP);
		if (node)
			INM_MEM_ZERO(node, sizeof(change_node_t));
	}
#else
	if(!wdatap || !wdatap->wd_chg_node){
		node = INM_KMALLOC(sizeof(change_node_t), flags, INM_KERNEL_HEAP);
		if(node){
			if(INM_PIN(node, sizeof(change_node_t))){
				INM_KFREE(node, sizeof(change_node_t),
								INM_KERNEL_HEAP);
				node = NULL;
			}else
				node->mutext_initialized = 0;
		}
	}else{
		node = wdatap->wd_chg_node;
		wdatap->wd_chg_node = NULL;
	}
#endif
	return node;
}

void inm_free_change_node(change_node_t *node)
{
#ifndef INM_AIX
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	if (node->flags & CHANGE_NODE_ALLOCED_FROM_POOL) {
		unsigned long lock_flag = 0;

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_chdnodes_alloced);
		inm_list_add_tail(&node->next, &driver_ctx->dc_chdnodes_list);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock,
								lock_flag);
	} else
		INM_KFREE(node, sizeof(change_node_t), INM_KERNEL_HEAP);
#else
	INM_KFREE(node, sizeof(change_node_t), INM_KERNEL_HEAP);
#endif
#else
	INM_UNPIN(node, sizeof(change_node_t));
	INM_KFREE(node, sizeof(change_node_t), INM_KERNEL_HEAP);
#endif
}

change_node_t *get_change_node_to_update(target_context_t *tgt_ctxt,
		inm_wdata_t *wdatap, inm_tsdelta_t *ts_delta)
{
	change_node_t *node = tgt_ctxt->tc_cur_node;
	change_node_t *recent_cnode = NULL;
	struct inm_list_head *ptr;
	int perf_changes = 1;
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	int is_barrier_on = 0;
#endif

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	/*
	 * Check if the current change node is matching with the filter mode.
	 * If not create a new change node and set its type corresponding to
	 * the filter mode. However if the change_idx of the node is 0 it means
	 * we have a freshly allocated node and it can used, no need for
	 * allocation. At present we have no limit on the number of changes in
	 * data-mode change node while the meta-data-mode node is limited by
	 * MAX_CHANGE_INFOS_PER_PAGE.
	 */
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	if ((INM_ATOMIC_READ(&driver_ctx->is_iobarrier_on)) ) {
		is_barrier_on = 1;
		perf_changes = 0;
		if(!(tgt_ctxt->tc_flags & VCF_IO_BARRIER_ON)) {
			node = NULL;
			tgt_ctxt->tc_flags |= VCF_IO_BARRIER_ON;
			tgt_ctxt->tc_cur_node = NULL;
			goto alloc_chg_node;
		}
	}
#endif
	switch(tgt_ctxt->tc_cur_mode) {
	case FLT_MODE_DATA:
		if(node){
			if(node->type != NODE_SRC_DATA)
				node = (!node->changes.change_idx) ? 
					(node->type = NODE_SRC_DATA, node) : NULL;
			else if(node->wostate != tgt_ctxt->tc_cur_wostate)
				node = (!node->changes.change_idx) ? node : NULL;

			if(node){
				inm_s32_t chg_sz = (sv_chg_sz + wdatap->wd_cplen);

				if((node->stream_len + sv_const_sz + chg_sz) >
						driver_ctx->tunable_params.max_data_sz_dm_cn) {
					tgt_ctxt->tc_cur_node = NULL;
					node = NULL;
					goto alloc_chg_node;
				}

				node->wostate = tgt_ctxt->tc_cur_wostate;
			}
		}
		break;

	default:
		if (!node) {
			break;
		}

		if (node->type == NODE_SRC_DATA)
			node = (!node->changes.change_idx) ?
				(node->type = NODE_SRC_METADATA, node) : NULL;
		else if(node->wostate != tgt_ctxt->tc_cur_wostate)
			node = (!node->changes.change_idx) ? node : NULL;

		if(!node)
			break;

		node->wostate = tgt_ctxt->tc_cur_wostate;

		if (node->changes.change_idx == (MAX_CHANGE_INFOS_PER_PAGE)) {
			node = NULL;
		}
		break;
	}

	if(!node)
		goto alloc_chg_node;

	/* deltas will bump up the global seq no. by one per io */
	inm_get_ts_and_seqno_deltas(node, ts_delta);
	if (ts_delta->td_oflow) {
		tgt_ctxt->tc_cur_node = NULL;
		node = NULL;
		goto alloc_chg_node;
	}

	if (node && node->changes.change_idx > 0 &&
		(node->changes.change_idx %
		 	(MAX_CHANGE_INFOS_PER_PAGE)) == 0) {
		/* md page is full, and allocate new one */
		inm_page_t *pgp = NULL;

		pgp = get_page_from_page_pool(1, INM_KM_NOSLEEP, wdatap);
		if (!pgp) {
			return NULL;
		}
		inm_list_add_tail(&pgp->entry, &node->changes.md_pg_list);
		node->changes.cur_md_pgp = pgp->cur_pg;
		tgt_ctxt->tc_cnode_pgs++;
	}

alloc_chg_node:

	/* There exist no matching change node to update or
	 * current change node is filled up
	 */
	if (!node) {
		/* Now see if we can put the oldest data mode change node
		 * without write order on a separate list
		 */
		if ((tgt_ctxt->tc_optimize_performance &
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) &&
			!inm_list_empty(&tgt_ctxt->tc_node_head) &&
			perf_changes == 1) {
			ptr = tgt_ctxt->tc_node_head.prev;
			recent_cnode = (change_node_t *)inm_list_entry(ptr,
							change_node_t, next);
			do_perf_changes(tgt_ctxt, recent_cnode, IN_IO_PATH);
		}
		node = inm_alloc_change_node(wdatap, INM_KM_NOSLEEP);
		if (!node)
			return NULL;

		if(!init_change_node(node, 1, INM_KM_NOSLEEP, wdatap)) {
			inm_free_change_node(node);
			return NULL;
		}

		/* change node belongs to either data mode or
		 * meta data mode dirty block
		 * but not combination of both the modes 
		 */

		switch(tgt_ctxt->tc_cur_mode) {
		case FLT_MODE_DATA:
			node->type = NODE_SRC_DATA;
			break;

		default:
			node->type = NODE_SRC_METADATA;
			break;
		}

		node->wostate = tgt_ctxt->tc_cur_wostate;
		ref_chg_node(node);
		node->transaction_id = 0;

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
		if (is_barrier_on) {
			inm_list_add_tail(&node->next,
					&tgt_ctxt->tc_non_drainable_node_head);
		} else {
			if(!inm_list_empty(&tgt_ctxt->tc_non_drainable_node_head)) {
				do_perf_changes_all(tgt_ctxt, IN_IO_PATH);
				tgt_ctxt->tc_flags &= ~VCF_IO_BARRIER_ON;
				inm_list_splice_at_tail(&tgt_ctxt->tc_non_drainable_node_head,
		 			&tgt_ctxt->tc_node_head);
				INM_INIT_LIST_HEAD(&tgt_ctxt->tc_non_drainable_node_head);
			}
			inm_list_add_tail(&node->next, &tgt_ctxt->tc_node_head);
		}
#else
		inm_list_add_tail(&node->next, &tgt_ctxt->tc_node_head);
#endif
		tgt_ctxt->tc_nr_cns++;
		tgt_ctxt->tc_cur_node = node;
		node->vcptr = tgt_ctxt;
		tgt_ctxt->tc_cnode_pgs++;

		inm_get_ts_and_seqno_deltas(node, ts_delta);
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return node;
}


void do_perf_changes(target_context_t *tgt_ctxt, change_node_t *recent_cnode,
		int path)
{
	if (recent_cnode && recent_cnode->type == NODE_SRC_DATA &&
		recent_cnode->wostate != ecWriteOrderStateData &&
		recent_cnode != tgt_ctxt->tc_pending_confirm &&
		inm_list_empty(&recent_cnode->nwo_dmode_next)) {
		close_change_node(recent_cnode, path);
		inm_list_add_tail(&recent_cnode->nwo_dmode_next,
				          &tgt_ctxt->tc_nwo_dmode_list);
		if (tgt_ctxt->tc_optimize_performance &
						PERF_OPT_DEBUG_DATA_DRAIN) {
			info("Appending chg:%p to tgt_ctxt:%p next:%p prev:%p "
				"mdoe:%d", recent_cnode,tgt_ctxt,
				recent_cnode->nwo_dmode_next.next,
				recent_cnode->nwo_dmode_next.prev,
				recent_cnode->type);
		}
	}
}

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
void do_perf_changes_all(target_context_t *tgt_ctxt, int path)
{
	inm_list_head_t *ptr = NULL, *nextptr = NULL;
	change_node_t *cnode = NULL;

	inm_list_for_each_safe(ptr, nextptr,
				&tgt_ctxt->tc_non_drainable_node_head) {
		cnode = inm_list_entry(ptr, change_node_t, next);
		if ((tgt_ctxt->tc_optimize_performance &
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) &&
			tgt_ctxt->tc_cur_node != cnode) {
			do_perf_changes(tgt_ctxt, cnode, path);
		}

	}
}
void move_chg_nodes_to_drainable_queue(void)
{
	inm_list_head_t *ptr = NULL, *nextptr = NULL;
	target_context_t *tgt_ctxt = NULL;

	INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	inm_list_for_each_safe(ptr, nextptr,  &driver_ctx->tgt_list) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		volume_lock(tgt_ctxt);

		if (tgt_ctxt->tc_flags & VCF_IO_BARRIER_ON) {
			tgt_ctxt->tc_flags &= ~VCF_IO_BARRIER_ON;

			if(!inm_list_empty(&tgt_ctxt->tc_non_drainable_node_head)) {
				do_perf_changes_all(tgt_ctxt, IN_IOCTL_PATH);
				inm_list_splice_at_tail(&tgt_ctxt->tc_non_drainable_node_head,
						&tgt_ctxt->tc_node_head);
				INM_INIT_LIST_HEAD(&tgt_ctxt->tc_non_drainable_node_head);
			}
		}

		volume_unlock(tgt_ctxt);
	}
	INM_UP_WRITE(&driver_ctx->tgt_list_sem);
}

#endif

void
close_change_node(change_node_t *chg_node, inm_u32_t path)
{
	target_context_t *tgt_ctxt;
	inm_s32_t i, md_idx, count = 0;
	disk_chg_t *chg = NULL;
	inm_page_t *pgp = NULL;
	struct inm_list_head *ptr;
	
	if (!chg_node)
		return;
	tgt_ctxt = chg_node->vcptr;
	INM_BUG_ON(chg_node->flags & CHANGE_NODE_IN_NWO_CLOSED);
	INM_BUG_ON(!tgt_ctxt);
	INM_BUG_ON(!(tgt_ctxt->tc_optimize_performance &
			(PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO)));
	/* no need to close metadata change node until it gets drained */
	if (path != IN_GET_DB_PATH &&
		chg_node->type == NODE_SRC_METADATA) {
		return;
	}

	/*
	 * Performance effort -
	 * Always drain data mode change node if any except the active one
	 * Otherwise metadata change node with tweaked start,end TS & deltas 
	 * As we are bumping up the start seq number of a metadata
	 * change node while draining, it may clash with the active change
	 * nodes start sequence number, so then we would see OOD issue
	 * Solution - Close non write order data mode change always with
	 *            current start and end time with zero deltas
	 * PS - Change node with write order is always closed, so this fn
	 * should not be called for it.
	 */

	if (chg_node->wostate == ecWriteOrderStateData)
		return;
	if (tgt_ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DATA_DRAIN) {
		info("Closing chg:%p to tgt_ctxt:%p next:%p prev:%p mode:%d "
			"path:%d", chg_node, tgt_ctxt,
			chg_node->nwo_dmode_next.next,
			chg_node->nwo_dmode_next.prev, chg_node->type, path);
	}
	chg_node->flags |= CHANGE_NODE_IN_NWO_CLOSED;
	switch (chg_node->type) {
		case NODE_SRC_DATA:
			/* Apply global time stamps in non write order mode */
			get_time_stamp_tag(&chg_node->changes.start_ts);
			memcpy_s(&chg_node->changes.end_ts,
					sizeof(TIME_STAMP_TAG_V2),
					&chg_node->changes.start_ts,
					sizeof(TIME_STAMP_TAG_V2));
			break;
		case NODE_SRC_METADATA:
			
			/* set start and end time stamp to current timestamp */
			get_time_stamp_tag(&chg_node->changes.start_ts);
			chg_node->changes.start_ts.ullSequenceNumber =
				tgt_ctxt->tc_PrevEndSequenceNumber + 1;

			/* split IOs in metadata mode no meaning and atomicity
			 * could be * lost if partial split IOs make it to
			 * bitmap
			 */
			if (chg_node->flags &
					KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK) {
				chg_node->flags &=
					~(KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK);
				chg_node->seq_id_for_split_io = 1;
			}

			memcpy_s(&chg_node->changes.end_ts,
					sizeof(TIME_STAMP_TAG_V2),
					&chg_node->changes.start_ts,
					sizeof(TIME_STAMP_TAG_V2));
			/* Tweak the time stamp and seq deltas in all
			 * changes
			 */
			__inm_list_for_each(ptr,
					&chg_node->changes.md_pg_list) {
				pgp = inm_list_entry(ptr, inm_page_t, entry);
				i = 0;
				while (i < MAX_CHANGE_INFOS_PER_PAGE) {
				    md_idx = count %
					    	(MAX_CHANGE_INFOS_PER_PAGE);
				    chg = (disk_chg_t *) ((char *)pgp->cur_pg +
				          (sizeof(disk_chg_t) * md_idx));
				    chg->seqno_delta = 0;
				    chg->time_delta = 0;
				    i++;
				    count++;
				    if (count ==
						chg_node->changes.change_idx) {
				    	break;
				    }
				}
			}
			break;
		case NODE_SRC_TAGS:
			/* control may come here for tag tracked with page i
			 * alloc failure
			 */
			break;
		default:
			err("Invalid change node type while closing a change "
				"node:%p", chg_node);
			INM_BUG_ON(1);
			break;
	}
}

/* Caller is responsible to hold the target context lock. */
change_node_t *get_oldest_change_node(target_context_t *tgt_ctxt,
				                      inm_s32_t *status)
{
	struct inm_list_head *ptr;
	change_node_t *chg_node;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	tgt_ctxt->tc_tel.tt_getdb++;

	if(INM_UNLIKELY(tgt_ctxt->tc_pending_confirm || 
		inm_list_empty(&tgt_ctxt->tc_node_head))) {
		if (INM_UNLIKELY(tgt_ctxt->tc_pending_confirm))
			tgt_ctxt->tc_tel.tt_revertdb++;
		return tgt_ctxt->tc_pending_confirm;
	}

	ptr = tgt_ctxt->tc_node_head.next;

	chg_node = (change_node_t *)inm_list_entry(ptr, change_node_t, next);
	if (chg_node == tgt_ctxt->tc_cur_node) {
		tgt_ctxt->tc_cur_node = NULL;
	}

	if (chg_node) {
		if (IS_CHANGE_NODE_DRAIN_BARRIER(chg_node)) {
			dbg("Drain Barrier, returning EAGAIN");
			tgt_ctxt->tc_flags |= VCF_DRAIN_BARRIER;
			*status = INM_EAGAIN;
			return NULL;
		} else {
			if (!chg_node->transaction_id) {
				chg_node->transaction_id =
						++tgt_ctxt->tc_transaction_id;
			}
			tgt_ctxt->tc_pending_confirm = chg_node;
			tgt_ctxt->tc_flags &= ~VCF_DRAIN_BARRIER;
			get_tgt_ctxt(tgt_ctxt);
		}
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return chg_node;
}

/**
 * FUNCTION NAME: get_oldest_change_node_pref_datamode
 * 
 * DESCRIPTION : Get the data mode change first then metadata changes
 *               Preferably get non write order data mode change or
 *               get metadata change node by tweaking the time stamps
 *               and sequence number
 * 
 * return value :    change_node_t *   - for success
 *                   NULL              - for failure
**/
change_node_t *
get_oldest_change_node_pref_datamode(target_context_t *tgt_ctxt, 
				                     inm_s32_t *status)
{
	struct inm_list_head *ptr;
	change_node_t *chg_node = NULL;
	struct inm_list_head *oldest_ptr = NULL;

#if (defined(IDEBUG) || defined(IDEBUG_META))
	info("entered");
#endif	

	tgt_ctxt->tc_tel.tt_getdb++;

	/*
	 * In case, change node was already mapped to user space and for some
	 * reason agent did not commit, died then came back for get db,
	 * give it tc_pending_confirm change node OR
	 * if change node list is empty then tc_pending_confirm would be NULL
	 * i.e. tso file case
	 */
	if (INM_UNLIKELY(tgt_ctxt->tc_pending_confirm || 
		inm_list_empty(&tgt_ctxt->tc_node_head))) {
		if (INM_UNLIKELY(tgt_ctxt->tc_pending_confirm))
			tgt_ctxt->tc_tel.tt_revertdb++;
		return tgt_ctxt->tc_pending_confirm;
	}

	/* Walk through real change node list to drain write order changes as 
	 * it is
	 */
	if (!inm_list_empty(&tgt_ctxt->tc_node_head)) {
		oldest_ptr = tgt_ctxt->tc_node_head.next;
		chg_node = (change_node_t *)inm_list_entry(oldest_ptr,
							change_node_t, next);
		if (chg_node) {
			if (chg_node->wostate == ecWriteOrderStateData) {
				if (tgt_ctxt->tc_optimize_performance &
						PERF_OPT_DEBUG_DATA_DRAIN) {
				info("Drain wo chgnode  from tc_node_head "
					"chg_node:%p tc_cur_node:%p",
				    	chg_node, tgt_ctxt->tc_cur_node);
				}
				INM_BUG_ON(chg_node->type ==
							NODE_SRC_METADATA);
			}
			else {
				if (chg_node->type == NODE_SRC_DATA ||
				    chg_node->type == NODE_SRC_DATAFILE ||
				    /*Tag page alloc failure*/
				    chg_node->type == NODE_SRC_TAGS) {
				    if (tgt_ctxt->tc_optimize_performance &
						PERF_OPT_DEBUG_DATA_DRAIN) {
				    	info("Drain chg node from tc_node_head"
						" chg_node:%p mode:%d"
						" tc_cur_node:%p", chg_node,
						chg_node->type,
						tgt_ctxt->tc_cur_node);
				    }
				} else {
					chg_node = NULL;
				}
			}
		}
	}

	/*
	 * Currently we support drain barrier only for wostate=DATA
	 * so there is no need to check nwo_list below for drain barrier 
	 * change node. We can check and return here.
	 */
	if (chg_node) {
		if (IS_CHANGE_NODE_DRAIN_BARRIER(chg_node)) {
			dbg("Drain Barrier, returning EAGAIN");
			tgt_ctxt->tc_flags |= VCF_DRAIN_BARRIER;
			*status = INM_EAGAIN;
			return NULL;
		}
	} else {
		/* Haven't found the candidate for draining yet ?
		 * Look up the nwo data mode list or metadata change nodes
		 */
		/* Walk though the non write order mode data mode change node
		 * list
		 */
		if (!inm_list_empty(&tgt_ctxt->tc_nwo_dmode_list)) {
			ptr = tgt_ctxt->tc_nwo_dmode_list.next;
			chg_node = (change_node_t *)inm_list_entry(ptr, 
							change_node_t,
							nwo_dmode_next);
			INM_BUG_ON(chg_node->type != NODE_SRC_DATA &&
				       chg_node->type != NODE_SRC_DATAFILE);
			if (tgt_ctxt->tc_optimize_performance &
						PERF_OPT_DEBUG_DATA_DRAIN) {
				info("Draining chgnode from nwo list chg_node:"
					"%p next:%p prev:%p mode:%d",
					chg_node, chg_node->nwo_dmode_next.next,
					chg_node->nwo_dmode_next.prev,
					chg_node->type);
			}
		}
		if (!chg_node) {
			/*
			 * Always fabricate transaction id, start_ts and end_ts
			 * of a meta data change node as we are not modifying
			 * them for non write order data mode change node list
			 */
			chg_node = (change_node_t *)inm_list_entry(oldest_ptr,
						change_node_t, next);
			if (!chg_node) {
				err("Empty change node list tc_mode:%d",
						tgt_ctxt->tc_cur_wostate);
				goto ret;
			}
			INM_BUG_ON(chg_node->type != NODE_SRC_METADATA);
			if (chg_node != tgt_ctxt->tc_cur_node &&
				!(chg_node->flags &
						CHANGE_NODE_IN_NWO_CLOSED)) {
				close_change_node(chg_node, IN_GET_DB_PATH);
			}
			if (tgt_ctxt->tc_optimize_performance &
						PERF_OPT_DEBUG_DATA_DRAIN) {
				dbg("Draining change node in chg_node:%p mode:"
				    "%d delta ts:%llu seq:%llu"
				    "tc_cur_node:%p", chg_node,chg_node->type,
				    chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601 -
				    chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
				    chg_node->changes.end_ts.ullSequenceNumber -
				    chg_node->changes.start_ts.ullSequenceNumber,
				    tgt_ctxt->tc_cur_node);
			}
		}
	}
	INM_BUG_ON(!chg_node);
	if (chg_node == tgt_ctxt->tc_cur_node) {
		close_change_node(chg_node, IN_GET_DB_PATH);
		if (tgt_ctxt->tc_optimize_performance &
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) {
			INM_BUG_ON(!inm_list_empty(&chg_node->nwo_dmode_next));
			if (chg_node->type == NODE_SRC_DATA &&
				chg_node->wostate != ecWriteOrderStateData) {
				inm_list_add_tail(&chg_node->nwo_dmode_next,   
					&tgt_ctxt->tc_nwo_dmode_list);
				if (tgt_ctxt->tc_optimize_performance & 
						PERF_OPT_DEBUG_DATA_DRAIN) {
				    info("Appending tc_cur_node chg:%p to "
					 "tgt_ctxt:%p next:%p prev:%p mode:%d",
				         chg_node,tgt_ctxt,
					 chg_node->nwo_dmode_next.next,
				         chg_node->nwo_dmode_next.prev,
					 chg_node->type);
				}
			}
		}
		tgt_ctxt->tc_cur_node = NULL;
	}
	tgt_ctxt->tc_pending_confirm = chg_node;
	tgt_ctxt->tc_flags &= ~VCF_DRAIN_BARRIER;

	get_tgt_ctxt(tgt_ctxt);
	if (!chg_node->transaction_id) {
		chg_node->transaction_id = ++tgt_ctxt->tc_transaction_id;
	}

ret:
#if (defined(IDEBUG) || defined(IDEBUG_META))
	info("leaving ret:%p", chg_node);
#endif	

	return chg_node;
}

/* Assumes target context lock is held. */
change_node_t *get_change_node_for_usertag(target_context_t *tgt_ctxt, 
		inm_wdata_t *wdatap, int commit_pending)
{
	change_node_t *chg_node = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	if (commit_pending &&
		tgt_ctxt->tc_cur_wostate != ecWriteOrderStateData) {
		err("Tagging without write order state data");
		return NULL;
	}
	
	if (tgt_ctxt->tc_cur_node && (tgt_ctxt->tc_optimize_performance &
		PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO)) {
		INM_BUG_ON(!inm_list_empty(&tgt_ctxt->tc_cur_node->nwo_dmode_next));
		if (tgt_ctxt->tc_cur_node->type == NODE_SRC_DATA &&
			tgt_ctxt->tc_cur_node->wostate != 
						ecWriteOrderStateData) {
			close_change_node(tgt_ctxt->tc_cur_node,
							IN_IOCTL_PATH);
			inm_list_add_tail(&tgt_ctxt->tc_cur_node->nwo_dmode_next,   
				              &tgt_ctxt->tc_nwo_dmode_list);
			if (tgt_ctxt->tc_optimize_performance &
						PERF_OPT_DEBUG_DATA_DRAIN) {
				info("Appending chg:%p to tgt_ctxt:%p next:%p "
				     "prev:%p mode:%d",
				     tgt_ctxt->tc_cur_node,tgt_ctxt,
				     tgt_ctxt->tc_cur_node->nwo_dmode_next.next,
				     tgt_ctxt->tc_cur_node->nwo_dmode_next.prev,
				     tgt_ctxt->tc_cur_node->type);
			}
		}
	}
	chg_node = inm_alloc_change_node(wdatap, INM_KM_NOSLEEP);
	if (!chg_node)
		return NULL;

	if(!init_change_node(chg_node, 1, INM_KM_NOSLEEP, wdatap)) {
	inm_free_change_node(chg_node);
		return NULL;
	}

	if (commit_pending) {
		tgt_ctxt->tc_flags |= VCF_TAG_COMMIT_PENDING;
		change_node_drain_barrier_set(tgt_ctxt, chg_node);
		dbg("CN %p commit pending", chg_node);
	}
	
	chg_node->type = NODE_SRC_TAGS;
	chg_node->wostate = tgt_ctxt->tc_cur_wostate;

	ref_chg_node(chg_node);
	chg_node->transaction_id = 0;
	++tgt_ctxt->tc_nr_cns;
	inm_list_add_tail(&chg_node->next, &tgt_ctxt->tc_node_head);
	chg_node->vcptr = tgt_ctxt;
	tgt_ctxt->tc_cnode_pgs++;

	/* Set cur_node in target context to NULL, so new changes would result
	 * in allocation of new change node.
	 */
	tgt_ctxt->tc_cur_node = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return chg_node;
}

void inm_free_metapage(inm_page_t *pgp)
{
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	if (pgp->flags & METAPAGE_ALLOCED_FROM_POOL) {
		unsigned long lock_flag = 0;

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_metapages_alloced);
		inm_list_add_tail(&pgp->entry, &driver_ctx->page_pool);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock,
								lock_flag);
	}
#else
	INM_UNPIN(pgp->cur_pg, INM_PAGESZ);
	INM_FREE_PAGE(pgp->cur_pg, INM_KERNEL_HEAP);
	pgp->cur_pg = NULL;
	INM_UNPIN(pgp, sizeof(inm_page_t));
	INM_KFREE(pgp, sizeof(inm_page_t), INM_KERNEL_HEAP);
#endif
}

void cleanup_change_node(change_node_t *chg_node)
{
	struct inm_list_head *curp = NULL, *nxtp = NULL;
	inm_page_t *pgp = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	


	/* If change node on non write order data mode list, then
	 * remove it from that list
	 */
	if (!inm_list_empty(&chg_node->nwo_dmode_next)) {
		inm_list_del_init(&chg_node->nwo_dmode_next);
	}
	chg_node->changes.cur_md_pgp = NULL;
	inm_list_for_each_safe(curp, nxtp, &chg_node->changes.md_pg_list) {
		inm_list_del(curp);
		pgp = inm_list_entry(curp, inm_page_t, entry);
		inm_free_metapage(pgp);
		chg_node->vcptr->tc_cnode_pgs--;
	}
	INM_DESTROY_SEM(&chg_node->mutex);
	inm_free_change_node(chg_node);
	INM_ATOMIC_DEC(&driver_ctx->stats.pending_chg_nodes);
 
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	
}

void cleanup_change_nodes(struct inm_list_head *hd, 
				          etTagStateTriggerReason reason)
{
	struct inm_list_head *ptr, *cur;
	change_node_t *chg_node;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	for( ptr = hd->next; ptr != hd; ) {
		cur = ptr;
		ptr = ptr->next;
		inm_list_del(cur);
		chg_node = inm_list_entry(cur, change_node_t, next);

		if (chg_node->type == NODE_SRC_TAGS)
			telemetry_log_tag_history(chg_node, chg_node->vcptr,
				ecTagStatusDropped, reason, ecMsgTagDropped);
		
		if (chg_node->tag_guid) {
			chg_node->tag_guid->status[chg_node->tag_status_idx] = 
								STATUS_DELETED;
			INM_WAKEUP_INTERRUPTIBLE(&chg_node->tag_guid->wq);
			chg_node->tag_guid = NULL;
		}
		commit_change_node(chg_node);
	}
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	
}

void free_changenode_list(target_context_t *ctxt, 
				          etTagStateTriggerReason reason)
{
	struct inm_list_head *clist = NULL, *ptr = NULL, *nextptr = NULL;
	change_node_t *cnode = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	clist = &ctxt->tc_node_head;
	ctxt->tc_pending_confirm = NULL;
	inm_list_for_each_safe(ptr, nextptr,  &ctxt->tc_node_head)
	{           
		cnode = inm_list_entry(ptr, change_node_t, next);
		inm_list_del(ptr);
		   
		switch(cnode->type) {
		case NODE_SRC_DATAFILE:
		case NODE_SRC_DATA:
		case NODE_SRC_METADATA:
		
		/* If change node on non write order data mode list, then
		 * remove it from that list
		 */
		if (!inm_list_empty(&cnode->nwo_dmode_next)) {
			inm_list_del_init(&cnode->nwo_dmode_next);
		}

		INM_BUG_ON(ctxt->tc_pending_changes < 
					(cnode->changes.change_idx));
		ctxt->tc_pending_changes -= (cnode->changes.change_idx);
		if (cnode->type == NODE_SRC_METADATA) {
			ctxt->tc_pending_md_changes -=
						(cnode->changes.change_idx);
			ctxt->tc_bytes_pending_md_changes -=
						(cnode->changes.bytes_changes);
		}
		ctxt->tc_bytes_pending_changes -= cnode->changes.bytes_changes;
		subtract_changes_from_pending_changes(ctxt, cnode->wostate,
						cnode->changes.change_idx);
		dbg("queuing changenode cleanup worker routine for cnode %p\n",
			       				cnode);
		queue_changenode_cleanup_worker_routine(cnode, reason);
		break;
		
		case NODE_SRC_TAGS:
		queue_changenode_cleanup_worker_routine(cnode, reason);
		break;

		default:
		break;
		}
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

void changenode_cleanup_routine(wqentry_t *wqe)
{
	change_node_t *cnode = NULL;
	etTagStateTriggerReason reason;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}
	
	if (!wqe) 
		return;

	cnode = (change_node_t *)wqe->context;

	if (cnode->type == NODE_SRC_TAGS) {
		reason = (etTagStateTriggerReason)wqe->extra1;
		telemetry_log_tag_history(cnode, cnode->vcptr, 
				                  ecTagStatusDropped, 
				                  reason, ecMsgTagDropped);
	}

	put_work_queue_entry(wqe);
	commit_change_node(cnode);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

}

inm_s32_t queue_changenode_cleanup_worker_routine(change_node_t *cnode, 
	                              etTagStateTriggerReason reason)
{
	wqentry_t *wqe = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	wqe = alloc_work_queue_entry(INM_KM_NOSLEEP);

	if (!wqe)
		return 1;

	wqe->witem_type = WITEM_TYPE_VOLUME_UNLOAD; 
	wqe->context = cnode;
	wqe->work_func = changenode_cleanup_routine;
	wqe->extra1 = (inm_u32_t)reason;

	dbg("queuing work queue entry for changenode %p cleanup \n", cnode);
	add_item_to_work_queue(&driver_ctx->wqueue, wqe);
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return 0;
	
}

/* This function assumes target context lock is held. */
change_node_t *get_change_node_to_save_as_file(target_context_t *ctxt)
{
	struct inm_list_head *ptr = ctxt->tc_node_head.prev;
	change_node_t *node = NULL;
	data_file_flt_t *flt_ctxt = &ctxt->tc_dfm;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	if(INM_ATOMIC_READ(&flt_ctxt->terminating))
		return NULL;

	if (ctxt->tc_stats.dfm_bytes_to_disk >= ctxt->tc_data_to_disk_limit) {
		return NULL;
	}

	if (ptr) {
		/* This is to ignore the current change node. */
		ptr = ptr->prev;
		if (!ptr)
			return NULL;
	} else {
		return NULL;
	}
	
	while(ptr != &ctxt->tc_node_head) {
		node = inm_list_entry(ptr, change_node_t, next);
		if ((node->type == NODE_SRC_DATA) &&
		   (0 == (node->flags &
			(CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE | 
			CHANGE_NODE_FLAGS_ERROR_IN_DATA_WRITE | 
			CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2)))) {

			node->flags |= CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE;
			ref_chg_node(node);
			return node;	
		}
		ptr = ptr->prev;		
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return NULL;
}

inm_page_t *
get_page_from_page_pool(inm_s32_t alloc_from_page_pool, inm_s32_t flag,
							inm_wdata_t *wdatap)
{
	inm_page_t *pg = NULL;
#ifndef INM_AIX
	unsigned long lock_flag = 0;
#endif
 
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	
 
#ifndef INM_AIX
	if(alloc_from_page_pool) {
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
	if(inm_list_empty(&driver_ctx->page_pool)) {
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
		INM_ATOMIC_INC(&driver_ctx->dc_nr_metapage_allocs_failed);
#endif
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock,
								lock_flag);
		goto alloc_fresh;
	}
	pg = inm_list_entry(driver_ctx->page_pool.next, inm_page_t, entry);  
	inm_list_del(&pg->entry);

	/* Decrement the number of free change nodes in the list. */
	driver_ctx->dc_res_cnode_pgs--;
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	INM_ATOMIC_DEC(&driver_ctx->dc_nr_metapages_alloced);
	INM_ATOMIC_INC(&driver_ctx->dc_nr_metapages_alloced_from_pool);
	wake_up_interruptible(&driver_ctx->dc_alloc_thread_waitq);
#endif
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, lock_flag); 
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}
  
	return pg;
	}

alloc_fresh:
	pg = (inm_page_t *) INM_KMALLOC(sizeof(inm_page_t), flag,
							INM_KERNEL_HEAP);
	if (pg) {
		pg->cur_pg = (unsigned long *) __INM_GET_FREE_PAGE(flag,
							INM_KERNEL_HEAP);
		if (!pg->cur_pg) {
			err("page alloc failed");
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			pg = NULL;
		}
	} else {
		err("inm_page_t alloc failed");
	}
#else
	if(!wdatap || !wdatap->wd_meta_page){
		pg = (inm_page_t *)INM_KMALLOC(sizeof(inm_page_t), flag,
								INM_KERNEL_HEAP);
		if(!pg)
			goto out;

		if(INM_PIN(pg, sizeof(inm_page_t))){
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			pg = NULL;
			goto out;
		}

		INM_MEM_ZERO(pg, sizeof(inm_page_t));
		INM_INIT_LIST_HEAD(&pg->entry);
		pg->cur_pg = (unsigned long *) __INM_GET_FREE_PAGE(flag,
								INM_KERNEL_HEAP);
		if (!pg->cur_pg) {
			err("page alloc failed");
			INM_UNPIN(pg, sizeof(inm_page_t));
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			pg = NULL;
			goto out;
		}

		if(INM_PIN(pg->cur_pg, INM_PAGESZ)){
			INM_FREE_PAGE(pg->cur_pg, INM_KERNEL_HEAP);
			INM_UNPIN(pg, sizeof(inm_page_t));
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			pg = NULL;
			goto out;
		}
	}else{
		pg = wdatap->wd_meta_page;
		INM_BUG_ON(!pg);
		wdatap->wd_meta_page = NULL;
	}
out:
#endif
	INM_BUG_ON(!pg);
   
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving with fresh allocation");
	}	

	return pg;
}

void print_chg_info(change_node_t *cnp, unsigned short idx)
{
	disk_chg_t *dcp = NULL;
	if (cnp->type == NODE_SRC_TAGS)
		return;

	idx = (idx % (MAX_CHANGE_INFOS_PER_PAGE));
	dcp = (disk_chg_t *)((char *)cnp->changes.cur_md_pgp +
			                    (sizeof(disk_chg_t) * idx));
	info("cnode = %p type  = %d", cnp, cnp->type);
	info("start ts = %llu , start seq = %llu ",
		 cnp->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
		 cnp->changes.start_ts.ullSequenceNumber);
	info("end ts = %llu , end seq = %llu",
		 cnp->changes.end_ts.TimeInHundNanoSecondsFromJan1601,
		 cnp->changes.end_ts.ullSequenceNumber);
	info("chg # = %u, off = %llu , len = %u , td = %u, sd = %u ", idx + 1,
		 dcp->offset, dcp->length,dcp->time_delta, dcp->seqno_delta);
	info("==============================================================");
}


void update_change_node(change_node_t *chg_node,
				        struct _write_metadata_tag *wmd,
			inm_tsdelta_t *tdp)
{
	inm_s32_t md_idx = chg_node->changes.change_idx % 
						(MAX_CHANGE_INFOS_PER_PAGE);
	disk_chg_t *chg = (disk_chg_t *) ((char *)chg_node->changes.cur_md_pgp +
					(sizeof(disk_chg_t) * md_idx));

	/* common code for data and metadata mode */
	chg->offset = wmd->offset;
	chg->length = wmd->length;
	chg->seqno_delta = tdp->td_seqno;
	chg->time_delta = tdp->td_time;
	/* last ts : time = start time + time delta of last change,
		 seqno = start seq + seq nr delta of last change */
	chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601 =
		(chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601 +
		 						tdp->td_time);
	chg_node->changes.end_ts.ullSequenceNumber =
		(chg_node->changes.start_ts.ullSequenceNumber + tdp->td_seqno);
	chg_node->changes.bytes_changes += chg->length;

	chg_node->changes.change_idx++;
}

static_inline void
copy_metadata_to_udirty(UDIRTY_BLOCK_V2 *udirty, change_node_t *chg_node)
{
	inm_s32_t _num_chgs = chg_node->changes.change_idx;
	inm_s32_t _cur_chg = 0;
	disk_chg_t *_chg = NULL;

	while(_cur_chg < _num_chgs) {
		_chg = (disk_chg_t *)((char *)chg_node->changes.cur_md_pgp +
				  (sizeof(disk_chg_t) * _cur_chg));
	udirty->ChangeOffsetArray[_cur_chg] = _chg->offset;
	udirty->ChangeLengthArray[_cur_chg] = _chg->length;
	udirty->TimeDeltaArray[_cur_chg] = _chg->time_delta;
	udirty->SequenceNumberDeltaArray[_cur_chg] = _chg->seqno_delta;
		_cur_chg++;
	}
}

int
copy_chg_node_to_udirty(struct _target_context *ctxt,
		change_node_t *chg_node, UDIRTY_BLOCK_V2 *udirty,
		inm_devhandle_t *filp)
{
	inm_s32_t bytes;
	inm_s32_t status = 0;
	inm_u64_t ts_in_usec;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	udirty->uHdr.Hdr.ulFlags = 0;
	udirty->uHdr.Hdr.uliTransactionID = chg_node->transaction_id;
	udirty->uHdr.Hdr.cChanges = chg_node->changes.change_idx;
	udirty->uHdr.Hdr.ulicbChanges = chg_node->changes.bytes_changes;
	udirty->uHdr.Hdr.ulSequenceIDforSplitIO =
						chg_node->seq_id_for_split_io;
	udirty->uHdr.Hdr.ulTotalChangesPending = ctxt->tc_pending_changes -
		udirty->uHdr.Hdr.cChanges;
	udirty->uHdr.Hdr.ulicbTotalChangesPending =
					(ctxt->tc_bytes_pending_changes -
		 			udirty->uHdr.Hdr.ulicbChanges);
	udirty->uHdr.Hdr.liOutOfSyncTimeStamp = 0;
	udirty->uHdr.Hdr.ulOutOfSyncErrorCode = 0;
	udirty->uHdr.Hdr.ulBufferSize = INM_PAGESZ;
	udirty->uHdr.Hdr.usNumberOfBuffers = chg_node->changes.num_data_pgs;

	ctxt->tc_tso_file = 0;

	INM_MEM_ZERO(udirty->uTagList.BufferForTags, UDIRTY_BLOCK_TAGS_SIZE);

	FILL_STREAM_HEADER_4B(&udirty->uTagList.TagList.TagStartOfList,
		STREAM_REC_TYPE_START_OF_TAG_LIST, sizeof(STREAM_REC_HDR_4B));
	FILL_STREAM_HEADER_4B(&udirty->uTagList.TagList.TagPadding,
		STREAM_REC_TYPE_PADDING, sizeof(STREAM_REC_HDR_4B));
	FILL_STREAM_HEADER_4B(&udirty->uTagList.TagList.TagEndOfList,
		STREAM_REC_TYPE_END_OF_TAG_LIST, sizeof(STREAM_REC_HDR_4B));
	FILL_STREAM_HEADER(&udirty->uTagList.TagList.TagDataSource,
		STREAM_REC_TYPE_DATA_SOURCE, sizeof(DATA_SOURCE_TAG));

	memcpy_s(&udirty->uTagList.TagList.TagTimeStampOfFirstChange,
				sizeof(TIME_STAMP_TAG_V2),
				&chg_node->changes.start_ts,
			       	sizeof(TIME_STAMP_TAG_V2));
	memcpy_s(&udirty->uTagList.TagList.TagTimeStampOfLastChange,
				sizeof(TIME_STAMP_TAG_V2),
				&chg_node->changes.end_ts,
				sizeof(TIME_STAMP_TAG_V2));

	if (chg_node->flags & KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK) {
		if (chg_node->flags & KDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE) {
			udirty->uHdr.Hdr.ulFlags |=
				UDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE;
		} else if (chg_node->flags &
				KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE) {
			udirty->uHdr.Hdr.ulFlags |=
				UDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE;
		} else if (chg_node->flags &
				KDIRTY_BLOCK_FLAG_END_OF_SPLIT_CHANGE) {
			udirty->uHdr.Hdr.ulFlags |=
				UDIRTY_BLOCK_FLAG_END_OF_SPLIT_CHANGE;
		}
	}

	ctxt->tc_CurrEndTimeStamp =
		chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601;
	ctxt->tc_CurrEndSequenceNumber =
			chg_node->changes.end_ts.ullSequenceNumber;
	ctxt->tc_CurrSequenceIDforSplitIO = chg_node->seq_id_for_split_io;

	udirty->uHdr.Hdr.ullPrevEndTimeStamp = ctxt->tc_PrevEndTimeStamp;
	udirty->uHdr.Hdr.ullPrevEndSequenceNumber = 
				ctxt->tc_PrevEndSequenceNumber;
	udirty->uHdr.Hdr.ulPrevSequenceIDforSplitIO = 
				ctxt->tc_PrevSequenceIDforSplitIO;

	/* Set the write order state */
	udirty->uHdr.Hdr.eWOState = chg_node->wostate;
	/* validate dirty block time stamps */
	if ((!(udirty->uHdr.Hdr.ullPrevEndTimeStamp <=
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.TimeInHundNanoSecondsFromJan1601 &&
		udirty->uHdr.Hdr.ullPrevEndSequenceNumber <=
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.ullSequenceNumber &&
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.TimeInHundNanoSecondsFromJan1601 <=
		udirty->uTagList.TagList.TagTimeStampOfLastChange.TimeInHundNanoSecondsFromJan1601 &&
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.ullSequenceNumber <=
		udirty->uTagList.TagList.TagTimeStampOfLastChange.ullSequenceNumber) ||
		verify_change_node(chg_node)) &&
		(udirty->uHdr.Hdr.ullPrevEndTimeStamp != -1)) {
		err("*** Out of order differential file ***");
		print_dblk_filename(chg_node);
		if (!ctxt->tc_resync_required) {
			queue_worker_routine_for_set_volume_out_of_sync(ctxt,
						ERROR_TO_REG_OOD_ISSUE, 1);
		}
	}

	/* data buffers are required to map only in data mode */
	switch (chg_node->type) {
	case NODE_SRC_TAGS:
		if(0 == (chg_node->flags & CHANGE_NODE_TAG_IN_STREAM)) {
			udirty->uTagList.TagList.TagDataSource.ulDataSource =
				INVOLFLT_DATA_SOURCE_META_DATA;
			udirty->uHdr.Hdr.ppBufferArray = NULL;
			bytes = ((unsigned char *)&udirty->uTagList.TagList.TagEndOfList -
				     (unsigned char *)udirty->uTagList.BufferForTags);
			memcpy_s(&udirty->uTagList.TagList.TagEndOfList,
					(UDIRTY_BLOCK_TAGS_SIZE - bytes),
			chg_node->changes.cur_md_pgp,
					(UDIRTY_BLOCK_TAGS_SIZE - bytes));
			break;
		}
		/* Fall through to map tag in stream mode */
		/* GCC 7 requires the following marker comment to not print a
		 * warning fall through
		 */

	case NODE_SRC_DATA:
		if(0 == (chg_node->flags &
					CHANGE_NODE_DATA_STREAM_FINALIZED)) {
			finalize_data_stream(chg_node);
		}

		udirty->uTagList.TagList.TagDataSource.ulDataSource =
						INVOLFLT_DATA_SOURCE_DATA;
		udirty->uHdr.Hdr.ulFlags |= UDIRTY_BLOCK_FLAG_SVD_STREAM;
#ifdef INM_AIX
	do{
		inm_u32_t stream_len = udirty->uHdr.Hdr.ulcbChangesInStream;

		udirty->uHdr.Hdr.ulcbChangesInStream = chg_node->stream_len;
		if(chg_node->stream_len > stream_len){
			status = INM_EINVAL;
			goto out;
		}

		chg_node->mapped_address = udirty->uHdr.Hdr.ppBufferArray;
	}while(0);
#else
		udirty->uHdr.Hdr.ulcbChangesInStream = chg_node->stream_len;
#endif

		chg_node->flags |= CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2;
		ref_chg_node(chg_node);
		volume_unlock(ctxt);
		status = map_change_node_to_user(chg_node, filp);
		volume_lock(ctxt);
		if(status) {
#ifndef INM_AIX
			udirty->uHdr.Hdr.ppBufferArray = (void **)NULL;
#endif
			chg_node->flags &= 
				~CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2;
		} else {
#ifndef INM_AIX
			udirty->uHdr.Hdr.ppBufferArray =
					(void **)chg_node->mapped_address;
#endif
		}
		deref_chg_node(chg_node);
		break;
	case NODE_SRC_METADATA:
		copy_metadata_to_udirty(udirty, chg_node);
		udirty->uTagList.TagList.TagDataSource.ulDataSource =
						INVOLFLT_DATA_SOURCE_META_DATA;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("udirty block of type meta data change node \n");
	}
		break;
	case NODE_SRC_DATAFILE:
		INM_BUG_ON(!chg_node->data_file_name);
		udirty->uTagList.TagList.TagDataSource.ulDataSource =
			INVOLFLT_DATA_SOURCE_DATA;
		udirty->uHdr.Hdr.ulFlags |= UDIRTY_BLOCK_FLAG_DATA_FILE;
		strcpy_s((char *)udirty->uTagList.DataFile.FileName,
					UDIRTY_BLOCK_MAX_FILE_NAME,
					chg_node->data_file_name);
		udirty->uTagList.DataFile.usLength =
			strlen((char *)udirty->uTagList.DataFile.FileName);
		break;

	default:
		dbg("unknown change node type \n");
		break;
	}

	GET_TIME_STAMP_IN_USEC(ts_in_usec);
	if (ctxt->tc_dbwait_event_ts_in_usec) {
		collect_latency_stats(&ctxt->tc_dbwait_notify_latstat,
		(ts_in_usec - ctxt->tc_dbwait_event_ts_in_usec));
		ctxt->tc_dbwait_event_ts_in_usec = 0;
	}
	if (chg_node->type) {
		inm_u64_t last_ts;

		last_ts  = chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601;
		chg_node->dbret_ts_in_usec = ts_in_usec;
		INM_DO_DIV(last_ts, 10);
		collect_latency_stats(&ctxt->tc_dbret_latstat, 
						(ts_in_usec - last_ts));
	}

	if (ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DBLK_FILENAME) {
		print_dblk_filename(chg_node);
	}
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)) {
		info("leaving");
	}

#ifdef INM_AIX
out:
#endif
	return status;
}

static_inline void copy_ts_to_udirty(target_context_t *ctxt,
			     UDIRTY_BLOCK_V2 *udirty, inm_devhandle_t *filp)
{
	udirty->uHdr.Hdr.ulFlags = UDIRTY_BLOCK_FLAG_TSO_FILE;
	udirty->uHdr.Hdr.uliTransactionID = ++ctxt->tc_transaction_id;

	udirty->uHdr.Hdr.cChanges = 0;
	udirty->uHdr.Hdr.ulicbChanges = 0;
	udirty->uHdr.Hdr.ulSequenceIDforSplitIO = 1;
	udirty->uHdr.Hdr.ulTotalChangesPending = 0;
	udirty->uHdr.Hdr.ulicbTotalChangesPending = 0;
	udirty->uHdr.Hdr.liOutOfSyncTimeStamp = 0;
	udirty->uHdr.Hdr.ulOutOfSyncErrorCode = 0;
	udirty->uHdr.Hdr.ppBufferArray = NULL;

	ctxt->tc_tso_file = 1;
	ctxt->tc_tso_trans_id = udirty->uHdr.Hdr.uliTransactionID;

	FILL_STREAM_HEADER_4B(&udirty->uTagList.TagList.TagStartOfList,
		STREAM_REC_TYPE_START_OF_TAG_LIST, sizeof(STREAM_REC_HDR_4B));
	FILL_STREAM_HEADER_4B(&udirty->uTagList.TagList.TagPadding,
		STREAM_REC_TYPE_PADDING, sizeof(STREAM_REC_HDR_4B));
	FILL_STREAM_HEADER_4B(&udirty->uTagList.TagList.TagEndOfList,
		STREAM_REC_TYPE_END_OF_TAG_LIST, sizeof(STREAM_REC_HDR_4B));
	FILL_STREAM_HEADER(&udirty->uTagList.TagList.TagDataSource,
		STREAM_REC_TYPE_DATA_SOURCE, sizeof(DATA_SOURCE_TAG));
	FILL_STREAM_HEADER(&udirty->uTagList.TagList.TagTimeStampOfFirstChange,
		STREAM_REC_TYPE_TIME_STAMP_TAG, sizeof(TIME_STAMP_TAG_V2));
	FILL_STREAM_HEADER(&udirty->uTagList.TagList.TagTimeStampOfLastChange,
		STREAM_REC_TYPE_TIME_STAMP_TAG, sizeof(TIME_STAMP_TAG_V2));

	udirty->uTagList.TagList.TagTimeStampOfFirstChange.ullSequenceNumber = 0;
	udirty->uTagList.TagList.TagTimeStampOfLastChange.ullSequenceNumber = 0;
	get_time_stamp_tag(&udirty->uTagList.TagList.TagTimeStampOfFirstChange);
	get_time_stamp_tag(&udirty->uTagList.TagList.TagTimeStampOfLastChange);

	ctxt->tc_CurrEndTimeStamp = udirty->uTagList.TagList.TagTimeStampOfLastChange.TimeInHundNanoSecondsFromJan1601;
	ctxt->tc_CurrEndSequenceNumber = udirty->uTagList.TagList.TagTimeStampOfLastChange.ullSequenceNumber;
	ctxt->tc_CurrSequenceIDforSplitIO = 1;
 
	udirty->uHdr.Hdr.ullPrevEndTimeStamp = ctxt->tc_PrevEndTimeStamp;
	udirty->uHdr.Hdr.ullPrevEndSequenceNumber = 
					ctxt->tc_PrevEndSequenceNumber;
	udirty->uHdr.Hdr.ulPrevSequenceIDforSplitIO = 
					ctxt->tc_PrevSequenceIDforSplitIO;

	/* validate timestamps of TSO file */
	if (!(udirty->uHdr.Hdr.ullPrevEndTimeStamp <=
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.TimeInHundNanoSecondsFromJan1601 &&
		udirty->uHdr.Hdr.ullPrevEndSequenceNumber <
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.ullSequenceNumber &&
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.TimeInHundNanoSecondsFromJan1601 <=
		udirty->uTagList.TagList.TagTimeStampOfLastChange.TimeInHundNanoSecondsFromJan1601 &&
		udirty->uTagList.TagList.TagTimeStampOfFirstChange.ullSequenceNumber <=
		udirty->uTagList.TagList.TagTimeStampOfLastChange.ullSequenceNumber &&
		udirty->uHdr.Hdr.ulPrevSequenceIDforSplitIO <=
		ctxt->tc_CurrSequenceIDforSplitIO) &&
		(udirty->uHdr.Hdr.ullPrevEndTimeStamp != -1)) {
		err("*** Out of order differential tso file ***");
		err("TSO File Previous TS:%llu Seq:%llu Start TS:%llu Seq:%llu End TS:%llu Seq:%llu",
			udirty->uHdr.Hdr.ullPrevEndTimeStamp,
			udirty->uHdr.Hdr.ullPrevEndSequenceNumber,
			udirty->uTagList.TagList.TagTimeStampOfFirstChange.TimeInHundNanoSecondsFromJan1601,
			udirty->uTagList.TagList.TagTimeStampOfFirstChange.ullSequenceNumber,
			udirty->uTagList.TagList.TagTimeStampOfLastChange.TimeInHundNanoSecondsFromJan1601,
			udirty->uTagList.TagList.TagTimeStampOfLastChange.ullSequenceNumber);
		if (!ctxt->tc_resync_required) {
			queue_worker_routine_for_set_volume_out_of_sync(ctxt,
						ERROR_TO_REG_OOD_ISSUE, 2);
		}
	}

	/* Set the write order state. In case of tso file, the write order
	 * state can be DATA if bitmap read is complete. Otherwise use the
	 * current * write order state.
	 */
	if(ctxt->tc_bp && ctxt->tc_bp->volume_bitmap && 
			(ecVBitmapStateReadCompleted == 
			 	ctxt->tc_bp->volume_bitmap->eVBitmapState))
	udirty->uHdr.Hdr.eWOState = ecWriteOrderStateData;
	else
	udirty->uHdr.Hdr.eWOState = ctxt->tc_cur_wostate;

	switch(ctxt->tc_cur_mode) {
	case FLT_MODE_DATA:
		udirty->uTagList.TagList.TagDataSource.ulDataSource =
		INVOLFLT_DATA_SOURCE_DATA;
		break;
	case FLT_MODE_METADATA:
		udirty->uTagList.TagList.TagDataSource.ulDataSource =
		INVOLFLT_DATA_SOURCE_META_DATA;
		break;
	default:
		udirty->uTagList.TagList.TagDataSource.ulDataSource =
		INVOLFLT_DATA_SOURCE_UNDEFINED;
		dbg("unknown filtering mode %d\n", ctxt->tc_cur_mode);
		break;
	}
}

int
fill_udirty_block(target_context_t *ctxt, UDIRTY_BLOCK_V2 *udirty, 
				  inm_devhandle_t *filp)
{
	int32_t witem_type = WITEM_TYPE_UNINITIALIZED;
	struct inm_list_head lh;
	change_node_t *chg_node = NULL;
	inm_s32_t status = 0;    

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	INM_INIT_LIST_HEAD(&lh);
	volume_lock(ctxt);
	ctxt->tc_flags |= VCF_VOLUME_IN_GET_DB;
	
	if (ctxt->tc_optimize_performance & 
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) {
		/* Preferably get non write order data mode change or
		 * get metadata change node by tweaking the time stamps
		 * and sequence number
		 */
		chg_node = get_oldest_change_node_pref_datamode(ctxt, &status);
	}
	else {
		INM_BUG_ON(!inm_list_empty(&ctxt->tc_nwo_dmode_list));
		chg_node = get_oldest_change_node(ctxt, &status);
	}
	if (INM_LIKELY(chg_node)) {
		ref_chg_node(chg_node);
		status = copy_chg_node_to_udirty(ctxt, chg_node, udirty, filp);
		if (status) {
			deref_chg_node(chg_node);
		}
	} else {
		if (status)
			goto out;
		else {
			if (ctxt->tc_flags & VCF_IO_BARRIER_ON) {
				dbg("Drain Barrier due the pending list of i"
				"change nodes is non-empty, returning EAGAIN")
				status = INM_EAGAIN;
				goto out;
			}
			/* No changes, but lets simply return the timestamp. */ 
			copy_ts_to_udirty(ctxt, udirty, filp);
		}
	}

	INM_BUG_ON_TMP(ctxt);

	if(FLT_MODE_METADATA == ctxt->tc_cur_mode){
	if (is_data_filtering_enabled_for_this_volume(ctxt) &&
		(driver_ctx->service_state == SERVICE_RUNNING) &&
		can_switch_to_data_filtering_mode(ctxt)){

		/* switch to data filtering mode */
		set_tgt_ctxt_filtering_mode(ctxt, FLT_MODE_DATA, FALSE);
		dbg("switched to data mode \n");
	}
	}

	switch (ctxt->tc_cur_wostate) {
	case ecWriteOrderStateMetadata:
	if (is_data_filtering_enabled_for_this_volume(ctxt) && 
		(driver_ctx->service_state == SERVICE_RUNNING) && 
		can_switch_to_data_wostate(ctxt)){ 

		/* switch to data write order state */ 
		set_tgt_ctxt_wostate(ctxt, ecWriteOrderStateData, FALSE,
				             ecWOSChangeReasonUnInitialized);
			dbg("switched to data write order state\n");
	}
	break;

	case ecWriteOrderStateData:
	case ecWriteOrderStateBitmap:
	if (ctxt->tc_bp->volume_bitmap &&
		(ctxt->tc_pending_changes 
		 < driver_ctx->tunable_params.db_low_water_mark_while_service_running) && 
		 !(ctxt->tc_flags & VCF_VOLUME_IN_BMAP_WRITE)) {
			switch (ctxt->tc_bp->volume_bitmap->eVBitmapState) {
			
			case ecVBitmapStateReadPaused:
				witem_type = WITEM_TYPE_CONTINUE_BITMAP_READ;
				break;
			
			case ecVBitmapStateOpened:
			case ecVBitmapStateAddingChanges:
				witem_type = WITEM_TYPE_START_BITMAP_READ;
				break;
	
			default:
				witem_type = WITEM_TYPE_UNINITIALIZED;
		break;
			}
			
			if (witem_type)
				add_vc_workitem_to_list(witem_type, ctxt, 0, 
								FALSE, &lh);
	}
	break;

	case ecWriteOrderStateRawBitmap:
	if (!(ctxt->tc_flags & VCF_VOLUME_IN_BMAP_WRITE))
			add_vc_workitem_to_list(WITEM_TYPE_START_BITMAP_READ,
							ctxt, 0, FALSE, &lh);
	break;
	 
	default:
		dbg("unknown mode\n");
		break;
	}

	volume_unlock(ctxt);
	if (!inm_list_empty(&lh)) {
		wqentry_t *wqe = NULL;
		struct inm_list_head *ptr = NULL, *nextptr = NULL;
		
		inm_list_for_each_safe(ptr, nextptr, &lh) {
			wqe = inm_list_entry(ptr, wqentry_t, list_entry);
			inm_list_del(&wqe->list_entry);
			process_vcontext_work_items(wqe);
			put_work_queue_entry(wqe);
		}
	}
	add_resync_required_flag(udirty, ctxt);

	volume_lock(ctxt);
out:
	ctxt->tc_flags &= ~VCF_VOLUME_IN_GET_DB;
	volume_unlock(ctxt);
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return status;
}

void commit_change_node(change_node_t *chg_node) 
{
	target_context_t *tgt_ctxt = NULL;
	struct inm_list_head *curp = NULL, *nxtp = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	INM_DOWN(&chg_node->mutex);

	if(chg_node->flags & CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE) {
	chg_node->flags &= ~CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE;
	}

	tgt_ctxt = chg_node->vcptr;

	INM_BUG_ON_TMP(tgt_ctxt);
	INM_BUG_ON(chg_node->flags & CHANGE_NODE_COMMITTED);

	switch(chg_node->type) {
	case NODE_SRC_TAGS:
	case NODE_SRC_DATA:
	
	/* Check if this node is being cleaned up while the data pages are
	 * mapped
	 */
	volume_lock(tgt_ctxt);

	if(INM_UNLIKELY(tgt_ctxt->tc_pending_confirm == chg_node)) {
		volume_unlock(tgt_ctxt);
		INM_UP(&chg_node->mutex);
		return;
	} else {
		volume_unlock(tgt_ctxt);
		/* current->mm could be NULL if this func. gets called from 
		 * flt_release() when drainer exits. As drainer is exiting, so unmap is
		 * not applicable. Otherwise if current->mm is valid then we
		 * must unmap the change node
		 */
#ifndef INM_AIX
		if (INM_CURPROC ==  chg_node->mapped_thread && INM_PROC_ADDR)
			unmap_change_node(chg_node);
#endif
	

		chg_node->mapped_address = 0;
		chg_node->mapped_thread = NULL;
		volume_lock(tgt_ctxt);
		tgt_ctxt->tc_stats.num_pages_allocated -=
			chg_node->changes.num_data_pgs;
		inm_rel_data_pages(tgt_ctxt, &chg_node->data_pg_head,
				           chg_node->changes.num_data_pgs);
		INM_INIT_LIST_HEAD(&chg_node->data_pg_head);
		chg_node->changes.num_data_pgs = 0;
		volume_unlock(tgt_ctxt);
	}

	chg_node->changes.num_data_pgs = 0;
	break;

	case  NODE_SRC_DATAFILE:
	INM_BUG_ON(!chg_node->data_file_name);
	if(0 != inm_unlink_datafile(tgt_ctxt, chg_node->data_file_name)) {
		err("Data File Mode: Unlink Failed For %s", 
		chg_node->data_file_name);
	}
	else {
		dbg("Data File Mode: Unlink Succeeded For %s", 
		chg_node->data_file_name);
		volume_lock(tgt_ctxt);
		tgt_ctxt->tc_stats.dfm_bytes_to_disk -=
						chg_node->data_file_size;
		INM_ATOMIC_DEC(&tgt_ctxt->tc_stats.num_dfm_files_pending);	
		volume_unlock(tgt_ctxt);
	}
		
	INM_KFREE(chg_node->data_file_name, INM_PATH_MAX, INM_KERNEL_HEAP);
	chg_node->data_file_name = NULL;
	chg_node->data_file_size = 0;
	break;

	default:
	break;
	}
	
	/* early free, will help to reuse the mem quickly*/
	inm_list_for_each_safe(curp, nxtp, &chg_node->changes.md_pg_list) {
		inm_page_t *pgp = inm_list_entry(curp, inm_page_t, entry);

		inm_list_del(curp);
		inm_free_metapage(pgp);
		tgt_ctxt->tc_cnode_pgs--;
	}
	chg_node->changes.cur_md_pgp = NULL;
 
	chg_node->flags |= CHANGE_NODE_COMMITTED;
	volume_lock(tgt_ctxt);
	tgt_ctxt->tc_nr_cns--;
	volume_unlock(tgt_ctxt);
	INM_UP(&chg_node->mutex);
	if (tgt_ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DATA_DRAIN) {
		info("commit - chg_node:%p next:%p prev:%p mode:%d closed:%d",
			chg_node, chg_node->nwo_dmode_next.next, 
			chg_node->nwo_dmode_next.prev,
			chg_node->type, 
			(chg_node->flags & CHANGE_NODE_IN_NWO_CLOSED));
	}
	deref_chg_node(chg_node);
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	inm_alloc_pools();
#else
	balance_page_pool(INM_KM_SLEEP, 0);
#endif

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

}

inm_s32_t
perform_commit(target_context_t *ctxt, COMMIT_TRANSACTION *commit, 
			   inm_devhandle_t *filp)
{
	inm_s32_t err = 0;
	change_node_t *chg_node = NULL;
	inm_u32_t is_tag = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_BUG_ON(ctxt->tc_pending_confirm && ctxt->tc_tso_file);

	if (ctxt->tc_pending_confirm) {
		if (ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DBLK_INFO) {
			print_chg_info(ctxt->tc_pending_confirm,
		           ctxt->tc_pending_confirm->changes.change_idx-1);
		}
		if (ctxt->tc_optimize_performance &
					PERF_OPT_DEBUG_DBLK_CHANGES) {
			print_change_node_off_length(ctxt->tc_pending_confirm);
		}
	}

	if (commit->ulFlags &
			COMMIT_TRANSACTION_FLAG_RESET_RESYNC_REQUIRED_FLAG) {
		reset_volume_out_of_sync(ctxt);
	}
	volume_lock(ctxt);
	ctxt->tc_tel.tt_commitdb++;
	get_time_stamp(&(ctxt->tc_s2_latency_base_ts));

	chg_node = ctxt->tc_pending_confirm;
	if (chg_node && chg_node->type) {
		inm_u64_t ts_in_usec;

		GET_TIME_STAMP_IN_USEC(ts_in_usec);
		ctxt->tc_tel.tt_commitdb_time = ts_in_usec * 10;
		collect_latency_stats(&ctxt->tc_dbcommit_latstat,
		(ts_in_usec - chg_node->dbret_ts_in_usec));
	}
	if (chg_node && (commit->ulTransactionID ==
					chg_node->transaction_id)) {
		ctxt->tc_pending_confirm = NULL;
		/* If change node on non write order data mode list, then
		 * remove it from that list
		 */
		if (!inm_list_empty(&chg_node->nwo_dmode_next)) {
			inm_list_del_init(&chg_node->nwo_dmode_next);
		}

		if (chg_node->type == NODE_SRC_TAGS) {
			is_tag = 1;
			ref_chg_node(chg_node);
		}

		if (is_tag && ((chg_node->flags & CHANGE_NODE_FAILBACK_TAG) ||
			(chg_node->flags & CHANGE_NODE_BLOCK_DRAIN_TAG))) {
			INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
			if (ctxt->tc_tag_commit_status) {
				ctxt->tc_tag_commit_status->TagInsertionTime =
				           TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(ctxt->tc_CurrEndTimeStamp);
				ctxt->tc_tag_commit_status->TagSequenceNumber = 
						ctxt->tc_CurrEndSequenceNumber;

				info("The tag is drained for disk %s, dirty "
					"block = %p, TagInsertionTime = %llu, "
					"TagSequenceNumber = %llu", 
					ctxt->tc_guid, chg_node,
					ctxt->tc_tag_commit_status->TagInsertionTime,
					ctxt->tc_tag_commit_status->TagSequenceNumber);
			}
			INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
			set_tag_drain_notify_status(ctxt, TAG_STATUS_COMMITTED,
						DEVICE_STATUS_SUCCESS);
			if (chg_node->flags & CHANGE_NODE_BLOCK_DRAIN_TAG) {
				ctxt->tc_flags |= VCF_DRAIN_BLOCKED;
			}
		}

		put_tgt_ctxt(ctxt);
		
		ctxt->tc_prev_transaction_id = chg_node->transaction_id;
		ctxt->tc_PrevEndTimeStamp = ctxt->tc_CurrEndTimeStamp;
		ctxt->tc_PrevEndSequenceNumber = 
					ctxt->tc_CurrEndSequenceNumber;
		ctxt->tc_PrevSequenceIDforSplitIO =
					ctxt->tc_CurrSequenceIDforSplitIO;
		get_rpo_timestamp(ctxt, IOCTL_INMAGE_COMMIT_DIRTY_BLOCKS_TRANS,
								chg_node);

		if (chg_node->tag_guid) {
			chg_node->tag_guid->status[chg_node->tag_status_idx] =
							STATUS_COMMITED;
			INM_WAKEUP_INTERRUPTIBLE(&chg_node->tag_guid->wq);
			chg_node->tag_guid = NULL;
		}

		/* not an orphan node */
		if ((chg_node->flags & CHANGE_NODE_ORPHANED) == 0) {
			INM_BUG_ON(ctxt->tc_pending_changes <
					(chg_node->changes.change_idx));
			ctxt->tc_pending_changes -=
						(chg_node->changes.change_idx);
			if (chg_node->type == NODE_SRC_METADATA) {
				ctxt->tc_pending_md_changes -=
						(chg_node->changes.change_idx);
				ctxt->tc_bytes_pending_md_changes -= 
				    (chg_node->changes.bytes_changes);
			}
			ctxt->tc_bytes_pending_changes -=
					chg_node->changes.bytes_changes;
			ctxt->tc_commited_changes +=
					(chg_node->changes.change_idx);
			ctxt->tc_bytes_commited_changes +=
					chg_node->changes.bytes_changes;
			subtract_changes_from_pending_changes(ctxt,
						chg_node->wostate,
						chg_node->changes.change_idx);

			update_cx_session_with_committed_bytes(ctxt,
					chg_node->changes.bytes_changes);
			if (ctxt->tc_bytes_pending_changes <=
					CX_SESSION_PENDING_BYTES_THRESHOLD) {
				close_disk_cx_session(ctxt,
					CX_CLOSE_PENDING_BYTES_BELOW_THRESHOLD);
			}

			inm_list_del(&chg_node->next);
			deref_chg_node(chg_node);

			if (ecWriteOrderStateData != ctxt->tc_cur_wostate) {
				if (is_data_filtering_enabled_for_this_volume(ctxt) &&
					(driver_ctx->service_state ==
				     			SERVICE_RUNNING) &&
					can_switch_to_data_wostate(ctxt)) {
 
					// switch to data write order state
					set_tgt_ctxt_wostate(ctxt,
						ecWriteOrderStateData, FALSE,
						ecWOSChangeReasonUnInitialized);
					dbg("switched to data write order state");
				} else if (ecWriteOrderStateBitmap == ctxt->tc_cur_wostate) {
					if (ctxt->tc_bp && ctxt->tc_bp->volume_bitmap &&
						(ecVBitmapStateReadCompleted == 
						 	ctxt->tc_bp->volume_bitmap->eVBitmapState)) {
						if ((driver_ctx->service_state == SERVICE_RUNNING) &&
								!ctxt->tc_pending_wostate_bm_changes &&
								!ctxt->tc_pending_wostate_rbm_changes) {
							set_tgt_ctxt_wostate(ctxt,
								ecWriteOrderStateMetadata, 
								FALSE, 
								ecWOSChangeReasonMDChanges);
							dbg("switched to metadata write order state\n");
						}
					}
				}
			}
		}
		volume_unlock(ctxt);
		
		if (is_tag) {
			telemetry_log_tag_history(chg_node, ctxt, 
					ecTagStatusTagCommitDBSuccess,
				        ecNotApplicable,
					ecMsgTagCommitDBSuccess);

			ctxt->tc_tel.tt_prev_tag_ts =
						ctxt->tc_PrevEndTimeStamp;
			ctxt->tc_tel.tt_prev_tag_seqno =
						ctxt->tc_PrevEndSequenceNumber;
			
			deref_chg_node(chg_node);
		}

		ctxt->tc_tel.tt_prev_ts = ctxt->tc_PrevEndTimeStamp;
		ctxt->tc_tel.tt_prev_seqno = ctxt->tc_PrevEndSequenceNumber;

		commit_change_node(chg_node);
	} else if (ctxt->tc_tso_file) {
		if (commit->ulTransactionID == ctxt->tc_tso_trans_id) {
			ctxt->tc_PrevEndTimeStamp = ctxt->tc_CurrEndTimeStamp;
			ctxt->tc_PrevEndSequenceNumber =
						ctxt->tc_CurrEndSequenceNumber;
			ctxt->tc_PrevSequenceIDforSplitIO =
					ctxt->tc_CurrSequenceIDforSplitIO;
			ctxt->tc_tel.tt_prev_ts =
						ctxt->tc_PrevEndTimeStamp;
			ctxt->tc_tel.tt_prev_seqno =
						ctxt->tc_PrevEndSequenceNumber;
			get_rpo_timestamp(ctxt,
					IOCTL_INMAGE_COMMIT_DIRTY_BLOCKS_TRANS,
					NULL);
		}

		volume_unlock(ctxt);
	} else {
		err = INM_EFAULT;
		ctxt->tc_tel.tt_commitdb_failed++;
		volume_unlock(ctxt);
	}
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return err;
}

void balance_page_pool(inm_s32_t alloc_flag, int quit) {
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	inm_s32_t threshold = 1024;
#else
	inm_s32_t threshold = 256;
#endif
	inm_page_t *pg = NULL;
	unsigned long lock_flag = 0;


	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	while (driver_ctx->dc_res_cnode_pgs < threshold) {
		pg = (inm_page_t *) INM_KMALLOC(sizeof(inm_page_t), alloc_flag, 
							INM_KERNEL_HEAP);
		INM_BUG_ON(!pg);
		if(INM_PIN(pg, sizeof(inm_page_t))){
			INM_KFREE(pg, sizeof(*pg), INM_KERNEL_HEAP);
			return;
		}
		INM_MEM_ZERO(pg, sizeof(inm_page_t));
		pg->cur_pg = (unsigned long *)__INM_GET_FREE_PAGE(alloc_flag, 
							INM_KERNEL_HEAP);
		if (!pg->cur_pg) {
		INM_UNPIN(pg, sizeof(inm_page_t));
			INM_KFREE(pg, sizeof(*pg), INM_KERNEL_HEAP);
			return;
		}

		if(INM_PIN(pg->cur_pg, INM_PAGESZ)){
			INM_FREE_PAGE(pg->cur_pg, INM_KERNEL_HEAP);
			INM_UNPIN(pg, sizeof(inm_page_t));
			INM_KFREE(pg, sizeof(*pg), INM_KERNEL_HEAP);
			return;
		}

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
		driver_ctx->dc_res_cnode_pgs ++;
		inm_list_add_tail(&pg->entry, &driver_ctx->page_pool);
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
		pg->flags = METAPAGE_ALLOCED_FROM_POOL;
		INM_ATOMIC_INC(&driver_ctx->dc_nr_metapages_alloced);
#endif
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock,
								lock_flag);

		if (quit)
			break;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return;
}

#ifndef INM_AIX
int
map_change_node_to_user(change_node_t *chg_node,
				        inm_devhandle_t *idhp)
{
	inm_addr_t addr = 0;
	void *saved_ptr;
	inm_s32_t len = 0;
	inm_s32_t status = 0, ret = 0;
	inm_u32_t off = 0;

	INM_DOWN(&chg_node->mutex);

	len = pages_to_bytes(chg_node->changes.num_data_pgs);
	if(!len) {
		status = -EINVAL;
		goto rel_mutex;
	}

	/* If change node mapped already, do nothing, previously mapped address
	 * can be returned to drainer.
	 */
	if(chg_node->mapped_thread) {
		dbg("Returning already mapped address: 0x%ld", 
						chg_node->mapped_address);
		goto rel_mutex;
	}

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}


	saved_ptr = idhp->private_data;
	INM_FILL_MMAP_PRIVATE_DATA(idhp, chg_node);
	ret = INM_DO_STREAM_MAP(idhp, off, len, addr, INM_MMAP_PROT_FLAGS,
			 INM_MMAP_MAPFLAG);

	if (ret) {
		err("INM_DO_STREAM_MAP() failed with err = %d", ret);
	}

	idhp->private_data = saved_ptr;
	if (IS_ERR((void *)addr)) {
		err("Mapping Failed, err %ld \n", addr);
		status = -ENOMEM;
		goto rel_mutex;
	}

	dbg("Mapping to User Address: 0x%p, len: %d\n", (void *)addr, len);

	chg_node->mapped_thread = INM_CURPROC;
	chg_node->mapped_address = addr;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

rel_mutex:
	INM_UP(&chg_node->mutex);

	return status;
}
#else
int
map_change_node_to_user(change_node_t *chg_node, inm_devhandle_t *idhp)
{
	inm_s32_t len = chg_node->stream_len, to_copy, status = 0;;
	struct inm_list_head *ptr, *hd;
	data_page_t *page;
	void *user_buf;

	INM_DOWN(&chg_node->mutex);
	user_buf = (void *)chg_node->mapped_address;

	hd =&(chg_node->data_pg_head);
	for(ptr = hd->next; ptr != hd; ptr = ptr->next) {
		page = inm_list_entry(ptr, data_page_t, next);
		to_copy = MIN(len, INM_PAGESZ);
		if(INM_COPYOUT(user_buf, page->page, to_copy)){
			err("copy to user failed in get_db");
			status = INM_EFAULT;
			goto rel_mutex;
		}
		user_buf += to_copy;
		len -= to_copy;
	}

	INM_BUG_ON(len);
rel_mutex:
	INM_UP(&chg_node->mutex);
	return status;
}
#endif

void
print_change_node_off_length(change_node_t *chg_node)
{
	unsigned short index = 0, i;
	inm_s32_t md_idx;
	disk_chg_t *chg = NULL;
	if (!chg_node || (chg_node->type != NODE_SRC_DATA &&
		chg_node->type != NODE_SRC_DATAFILE &&
		chg_node->type != NODE_SRC_METADATA)) {
		return;
		
	}
	index = chg_node->changes.change_idx;
	info("Printing change info trans_id:%lld start seq:%llu change node:%d"
		" splcnt:%u", chg_node->transaction_id,
		chg_node->changes.start_ts.ullSequenceNumber,
		chg_node->type, chg_node->seq_id_for_split_io);
	index = index%(MAX_CHANGE_INFOS_PER_PAGE);
	if  (chg_node->changes.cur_md_pgp) {
		for (i=0; i<index; i++) {
			 md_idx = i % (MAX_CHANGE_INFOS_PER_PAGE);
			 chg = (disk_chg_t *) ((char *)chg_node->changes.cur_md_pgp +
						(sizeof(disk_chg_t) * md_idx));
			 info("Index:%u offset:%llu length:%u td:%u sd:%u\n",
				 i, chg->offset, chg->length, chg->time_delta,
				 chg->seqno_delta);
		}
	}
	info("Printing change info trans_id:%lld end seq:%llu\n",
		chg_node->transaction_id,
		chg_node->changes.end_ts.ullSequenceNumber);

}

int
print_dblk_filename(change_node_t *chg_node)
{

	if (chg_node->flags & (KDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE |
		KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE)) {
		if (ecWriteOrderStateData == chg_node->wostate) {
			info("%lld:pre_completed_diff_type_%d_P%llu_%llu_S%llu_%llu_E%llu_%llu_WC%u.dat",
				chg_node->transaction_id,
				chg_node->type,chg_node->vcptr->tc_PrevEndTimeStamp,
				chg_node->vcptr->tc_PrevEndSequenceNumber,
				chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.start_ts.ullSequenceNumber,
				chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.end_ts.ullSequenceNumber,
				chg_node->seq_id_for_split_io);
		}
		else {
			info("%lld pre_completed_diff_type_%d_P%llu_%llu_S%llu_%llu_E%llu_%llu_MC%u.dat",
				chg_node->transaction_id,
				chg_node->type,chg_node->vcptr->tc_PrevEndTimeStamp,
				chg_node->vcptr->tc_PrevEndSequenceNumber,
				chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.start_ts.ullSequenceNumber,
				chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.end_ts.ullSequenceNumber,
				chg_node->seq_id_for_split_io);
		}
	} else {
		if (ecWriteOrderStateData == chg_node->wostate) {
			info("%lld pre_completed_diff_type_%d_P%llu_%llu_S%llu_%llu_E%llu_%llu_WE%u.dat",
				chg_node->transaction_id,
				chg_node->type,chg_node->vcptr->tc_PrevEndTimeStamp,
				chg_node->vcptr->tc_PrevEndSequenceNumber,
				chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.start_ts.ullSequenceNumber,
				chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.end_ts.ullSequenceNumber,
				chg_node->seq_id_for_split_io);
		}
		else {
			info("%lld pre_completed_diff_type_%d_P%llu_%llu_S%llu_%llu_E%llu_%llu_ME%u.dat",
				chg_node->transaction_id,
				chg_node->type,chg_node->vcptr->tc_PrevEndTimeStamp,
				chg_node->vcptr->tc_PrevEndSequenceNumber,
				chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.start_ts.ullSequenceNumber,
				chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601,
				chg_node->changes.end_ts.ullSequenceNumber,
				chg_node->seq_id_for_split_io);
		}
	}	
	return 0;
}

inm_s32_t
verify_change_node(change_node_t *chg_node)
{
	target_context_t *tgt_ctxt;
	inm_s32_t i, md_idx;
	disk_chg_t *chg = NULL;
	inm_page_t *pgp = NULL;
	struct inm_list_head *ptr;
	
	if (!chg_node)
		return 0;
	tgt_ctxt = chg_node->vcptr;
	INM_BUG_ON(!tgt_ctxt);

	if (chg_node->type == NODE_SRC_TAGS) {
		return 0;
	}
	if (chg_node->changes.change_idx) {
		i = 0;
		pgp = NULL;
		__inm_list_for_each(ptr, &chg_node->changes.md_pg_list) {
			pgp = inm_list_entry(ptr, inm_page_t, entry);
			i += MAX_CHANGE_INFOS_PER_PAGE;
			if (i >= chg_node->changes.change_idx)
				break;
		}
		if (!pgp) {
			err("offset length page empty!");
			return 1;
		}
		md_idx = ((chg_node->changes.change_idx-1) %
						(MAX_CHANGE_INFOS_PER_PAGE));
		chg = (disk_chg_t *)((char *)pgp->cur_pg +
				                     (sizeof(disk_chg_t) * md_idx));
		if (((chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601 + chg->time_delta)
			!= chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601) ||
			((chg_node->changes.start_ts.ullSequenceNumber + chg->seqno_delta) !=
			chg_node->changes.end_ts.ullSequenceNumber))
			return 1;

	}
	return 0;
}

inm_s32_t
change_node_unmap_page_buffer(void *map)
{
	return 0;
}

char *
change_node_map_dm_page_to_buffer(change_node_t *cnode)
{
	char *buf = driver_ctx->dc_verifier_area;
	inm_u32_t bufsz = driver_ctx->tunable_params.max_data_sz_dm_cn;
	inm_s32_t len = cnode->stream_len;
	inm_s32_t to_copy = 0;
	inm_s32_t error = 0;
	struct inm_list_head *ptr = NULL;
	struct inm_list_head *hd = &(cnode->data_pg_head);
	data_page_t *page;
	char *src = NULL;

	if (!buf) {
		error = -ENOMEM;
		goto out;
	}

	if (len > bufsz) {
		error = -EFBIG;
		goto out;
	}

	for(ptr = hd->next; ptr != hd; ptr = ptr->next) {
		page = inm_list_entry(ptr, data_page_t, next);
		
		to_copy = MIN(len, INM_PAGESZ);

		INM_PAGE_MAP(src, page->page, KM_SOFTIRQ0);
		memcpy_s(buf, bufsz, src, to_copy);
		INM_PAGE_UNMAP(src, page->page, KM_SOFTIRQ0);
		
		buf += to_copy;
		bufsz -= to_copy;
		len -= to_copy;
	}

	INM_BUG_ON(len);

out:
	if (error)
		return ERR_PTR(error);
	else
		return  driver_ctx->dc_verifier_area;
}

inm_s32_t
verify_change_node_file(change_node_t *cnode)
{
	static inm_s32_t error_logged = 0; /* log once on failure */
	inm_s32_t error = 0;
	inm_irqflag_t flag = 0;
	char *buf = NULL;

	if (!driver_ctx->dc_verifier_on) 
		return 0;

	switch(cnode->type) {
		case NODE_SRC_DATA: 
			INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_verifier_lock,
									flag);

			buf = change_node_map_dm_page_to_buffer(cnode);
			if (IS_ERR(buf)) {
				if (!error_logged) {
				    err("Cannot map for verification");
				    error_logged = 1;
				}
				error = PTR_ERR(buf);
			} else {
				error_logged = 0; /* mapping successful */
				error = inm_verify_change_node_data(buf,
						cnode->stream_len, 0);
				change_node_unmap_page_buffer(buf);
			}

			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_verifier_lock,
									flag);
			break;

		default:            
			error = 0;
			break;
	}

	return error;
}

