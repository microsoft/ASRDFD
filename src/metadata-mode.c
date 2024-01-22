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
#include "involflt_debug.h"
#include "driver-context.h"
#include "db_routines.h"
#include "metadata-mode.h"
#include "tunable_params.h"

extern driver_context_t *driver_ctx;

#define COALESCE_ARRAY_LENGTH   10
inm_u64_t coalesce_array[10];

void
update_coalesce_array(inm_u64_t length)
{
	inm_u16_t i = 0;

	/*  Just for verification purpose, we keep track of top 10 Coalesced changes.
	 *  None of them should exceed DriverContext.MaxCoalescedMetaDataChangeSize
	 */
	for (i = 0; i < COALESCE_ARRAY_LENGTH; i++) {
		if (coalesce_array[i] < length) {
			coalesce_array[i] = length;
			break;
		}
	}
	return;
}

inm_u64_t
coalesce_metadata_change(target_context_t *vcptr, write_metadata_t *wmd, 
	inm_s32_t data_source,  change_node_t *chg_node, inm_u32_t *add_length)
{
	inm_u64_t ret = 1;
	inm_u16_t md_idx = 0;
	disk_chg_t *chg = NULL;
	inm_u32_t sub_offset = 0;
	
	if (data_source != NODE_SRC_METADATA || 
		(chg_node && (chg_node->changes.change_idx == 0))) {
		/*
		 * Coalescing applies only to metadata mode
		 * For coealescingm, we need atleast one change in change node
		 */
		return ret;
	}

	md_idx = chg_node->changes.change_idx % (MAX_CHANGE_INFOS_PER_PAGE);
	chg = (disk_chg_t *) ((char *)chg_node->changes.cur_md_pgp +
					(sizeof(disk_chg_t) * (md_idx-1)));

	*add_length = 0;
	/* Check for overlapping IOs: */
	if ((chg->offset <= wmd->offset)) {
		if ((chg->offset + chg->length) >= wmd->offset) {
			if ((chg->offset + chg->length) < 
						(wmd->offset + wmd->length)) {
				*add_length = ((wmd->offset + wmd->length) -
				               (chg->offset + chg->length));
			}
			ret = 0;
		}
	}
	else  {
		if ((wmd->offset + wmd->length) >= chg->offset) {
			if ((wmd->offset + wmd->length) < 
						(chg->offset + chg->length)) {
				*add_length = chg->offset - wmd->offset;
				sub_offset = chg->offset - wmd->offset;
			}
			else {
				*add_length = (wmd->offset+wmd->length)-
						(chg->offset+chg->length) + 
						(chg->offset-wmd->offset);
				sub_offset = chg->offset - wmd->offset;
			}
			ret = 0;
		}
	}
	if (!ret && ((chg->length + *add_length) <=
		driver_ctx->tunable_params.max_sz_md_coalesce)) {
		chg->length += *add_length;
		chg->offset -= sub_offset;
		update_coalesce_array(chg->length);
		
		if (vcptr->tc_optimize_performance & 
					PERF_OPT_DEBUG_COALESCED_CHANGES) {
		info("Adjacent entry: offset:%llu length:%u end offset:%llu td:%u sd:%u\n",
			chg->offset, chg->length,(chg->offset + chg->length),
			chg->time_delta, chg->seqno_delta);
		info("Incoming entry: offset:%llu length:%u end offset:%llu",
			wmd->offset, wmd->length, (wmd->offset + wmd->length));
		info("Final entry : offset:%llu length:%u end offset:%llu tsd:%u seqd:%u\n",
			chg->offset, chg->length, (chg->offset + chg->length),
			chg->time_delta, chg->seqno_delta);
		}
	}
	else {
		ret = 1;
	}

	return ret;
}

inm_u32_t
split_change_into_chg_node(target_context_t *vcptr, write_metadata_t *wmd,
	 inm_s32_t data_source, struct inm_list_head *split_chg_list_hd, 
	 inm_wdata_t *wdatap) 
{
	unsigned long max_data_sz_per_chg_node = 0;
	inm_u32_t nr_splits = 0;
	change_node_t *chg_node = NULL;
	inm_tsdelta_t ts_delta;
	inm_u64_t time = 0, nr_seq = 0;
	unsigned long remaining_length = wmd->length;
	write_metadata_t wmd_local; 
	
	if (data_source != NODE_SRC_DATA && data_source != NODE_SRC_METADATA) {
		dbg("Invalid mode in switch case %s:%i", __FILE__, __LINE__);
		return 0;
	}

	if (data_source == NODE_SRC_DATA) {
		/* MAX_DATA_SIZE_PER_DATA_MODE_CHANGE_NODE value needs to be 
		 * stored in tunable param.
		 */
		max_data_sz_per_chg_node = 
			driver_ctx->tunable_params.max_data_sz_dm_cn - \
			sv_chg_sz - sv_const_sz;
	}
	else {
		max_data_sz_per_chg_node =
			driver_ctx->tunable_params.\
			max_data_size_per_non_data_mode_drty_blk;
	}
	
	INM_MEM_ZERO(&ts_delta, sizeof(ts_delta));
	INM_INIT_LIST_HEAD(split_chg_list_hd);
	wmd_local.offset = wmd->offset; 

	while(remaining_length) {
		chg_node = inm_alloc_change_node(wdatap, INM_KM_NOSLEEP);
		if (!chg_node) {
			info("change node is null");
			return 0;
		}
		if(!init_change_node(chg_node, 1, INM_KM_NOSLEEP, wdatap)) {
		inm_free_change_node(chg_node);
			return 0;
		}

		ref_chg_node(chg_node);
		chg_node->type = data_source;
		chg_node->wostate = vcptr->tc_cur_wostate;
		chg_node->vcptr = vcptr;
		chg_node->transaction_id = 0;
		inm_list_add_tail(&chg_node->next, split_chg_list_hd);
		
		INM_BUG_ON(remaining_length & ~SECTOR_SIZE_MASK);
		wmd_local.length = min(max_data_sz_per_chg_node, 
							remaining_length);
		wmd_local.length = wmd_local.length & SECTOR_SIZE_MASK;

		update_change_node(chg_node, &wmd_local, &ts_delta);
		chg_node->flags |= KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE;
	
		/* copy the time stamp related info from the first change node 
		 * as it should * be the same for all split ones.
		 */
		if (!nr_splits) {
			time = chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;
			nr_seq = chg_node->changes.start_ts.ullSequenceNumber;
		} else {
			chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601 = time;
			chg_node->changes.start_ts.ullSequenceNumber = nr_seq;
			chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601 = time;
			chg_node->changes.end_ts.ullSequenceNumber = nr_seq;
			dbg("time and seq # for chg node = %p \n", chg_node);
		}	
		nr_splits++;
		chg_node->seq_id_for_split_io = nr_splits;
	
		wmd_local.offset += wmd_local.length;
		remaining_length -= wmd_local.length;
	}

	if (!nr_splits)
		return 0;

	chg_node = inm_list_entry(split_chg_list_hd->next, change_node_t, next);
	chg_node->flags |= KDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE;
	chg_node->flags &= ~KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE;

	chg_node = inm_list_entry(split_chg_list_hd->prev, change_node_t, next);
	chg_node->flags |= KDIRTY_BLOCK_FLAG_END_OF_SPLIT_CHANGE;
	chg_node->flags &= ~KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE;

	return nr_splits;
}

inm_s32_t
add_metadata(target_context_t *vcptr, change_node_t *chg_node,
	 write_metadata_t *wmd, inm_s32_t data_source, inm_wdata_t *wdatap)
{
	unsigned long max_data_sz_per_chg_node =
	driver_ctx->tunable_params.max_data_size_per_non_data_mode_drty_blk;
	inm_s64_t avail_space = 0;
	inm_u32_t nr_splits = 0;
	inm_u32_t add_length = 0;

	inm_tsdelta_t ts_delta;
	struct inm_list_head split_chg_list_hd;

	/* Allocate change nodes for split io */
	if (max_data_sz_per_chg_node < wmd->length) {
#ifdef INM_AIX
	dbg("I/O is greater than %d in metadata mode, actual I/O size is %d",
			max_data_sz_per_chg_node, wmd->length);
	queue_worker_routine_for_set_volume_out_of_sync(vcptr, 
				ERROR_TO_REG_IO_SIZE_64MB_METADATA, 0);
	return 0;
#endif

		if (vcptr->tc_cur_node && (vcptr->tc_optimize_performance &
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO)) {
			INM_BUG_ON(!inm_list_empty(&vcptr->tc_cur_node->nwo_dmode_next));
			if (vcptr->tc_cur_node->type == NODE_SRC_DATA &&
				vcptr->tc_cur_node->wostate != ecWriteOrderStateData) {
				close_change_node(vcptr->tc_cur_node, IN_IO_PATH);
				inm_list_add_tail(&vcptr->tc_cur_node->nwo_dmode_next,   
				                  &vcptr->tc_nwo_dmode_list);
				if (vcptr->tc_optimize_performance & 
						PERF_OPT_DEBUG_DATA_DRAIN) {
				    info("Appending chg:%p to tgt_ctxt:%p next:%p prev:%p mode:%d",
				        vcptr->tc_cur_node,vcptr, 
					vcptr->tc_cur_node->nwo_dmode_next.next,
				        vcptr->tc_cur_node->nwo_dmode_next.prev, 
					vcptr->tc_cur_node->type);
				}
			}
		}
		vcptr->tc_cur_node = NULL;
		nr_splits = split_change_into_chg_node(vcptr, wmd, data_source,
				                   &split_chg_list_hd, wdatap);
		if (nr_splits) {
			inm_list_splice_at_tail(&split_chg_list_hd,
						&vcptr->tc_node_head);
			vcptr->tc_pending_changes += nr_splits;
			vcptr->tc_pending_md_changes += nr_splits;
			vcptr->tc_bytes_pending_md_changes += wmd->length;
			INM_BUG_ON(vcptr->tc_pending_changes < 0 );
			vcptr->tc_bytes_pending_changes += wmd->length;
			vcptr->tc_cnode_pgs += nr_splits;
			add_changes_to_pending_changes(vcptr, 
					vcptr->tc_cur_wostate, nr_splits);
		}
		return nr_splits;
	}

	chg_node = get_change_node_to_update(vcptr, wdatap, &ts_delta);
	if (chg_node &&
		chg_node->changes.change_idx < (MAX_CHANGE_INFOS_PER_PAGE))
		avail_space = max_data_sz_per_chg_node - 
					chg_node->changes.bytes_changes;

	if (avail_space < wmd->length) {
		vcptr->tc_cur_node = NULL;
		chg_node = get_change_node_to_update(vcptr, wdatap, &ts_delta);
		if (!chg_node) {
			info("change node is null");
			return -ENOMEM;
		}
	}

	nr_splits++;
	/* Check if we can coalesce the metadata change with previous one */
	if ((vcptr->tc_optimize_performance & PERF_OPT_METADATA_COALESCE) &&
		!coalesce_metadata_change(vcptr, wmd, data_source, chg_node, 
								&add_length)) {
		vcptr->tc_bytes_pending_changes += add_length;
		chg_node->changes.bytes_changes += add_length;
		vcptr->tc_bytes_pending_md_changes += add_length;
	}
	else {
		update_change_node(chg_node, wmd, &ts_delta);
		vcptr->tc_pending_changes++;
		if (chg_node->type == NODE_SRC_METADATA) {
			vcptr->tc_pending_md_changes++;
			vcptr->tc_bytes_pending_md_changes += wmd->length;
		}
		INM_BUG_ON(vcptr->tc_pending_changes < 0 );
		vcptr->tc_bytes_pending_changes += wmd->length;
		add_changes_to_pending_changes(vcptr, chg_node->wostate, 
								nr_splits);
	}

	return nr_splits;
}

inm_s32_t save_data_in_metadata_mode(target_context_t *tgt_ctxt,
				   write_metadata_t *wmd, inm_wdata_t *wdatap)

{
	change_node_t *change_node = NULL;
	inm_s32_t _rc = 0;

	/* check for valid inputs */
	if (!tgt_ctxt || !wmd)
		 return -EINVAL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered tcPages:%d dc_cur_res_pages:%d ",
			tgt_ctxt->tc_stats.num_pages_allocated, 
			driver_ctx->dc_cur_res_pages);
	}
#define vcptr    tgt_ctxt

	/* initialize the target context mode to bitmap, if it is in uninitialized
	 * state 
	 */
	if (!tgt_ctxt->tc_cur_mode) {
		tgt_ctxt->tc_cur_mode = FLT_MODE_METADATA;
		tgt_ctxt->tc_stats.st_mode_switch_time = 
						INM_GET_CURR_TIME_IN_SEC;
	}

	if (!tgt_ctxt->tc_cur_wostate) {
		tgt_ctxt->tc_cur_wostate = ecWriteOrderStateBitmap;
		tgt_ctxt->tc_stats.st_wostate_switch_time = 
						INM_GET_CURR_TIME_IN_SEC;
	}

	if (add_metadata(tgt_ctxt, change_node, wmd, 
					NODE_SRC_METADATA, wdatap) < 0) {
		err("Memory pool : out of memory %s\n", tgt_ctxt->tc_guid);

		free_changenode_list(tgt_ctxt, ecNonPagedPoolLimitHitMDMode);
	 
		/* send notification to the service process */
		/* No need to clear dbnotify event here, since the service
		 * waits for 30 secs, the control returns with failure
		 */

		queue_worker_routine_for_set_volume_out_of_sync(vcptr,
				ERROR_TO_REG_OUT_OF_MEMORY_FOR_DIRTY_BLOCKS,
				-ENOMEM);
		err("Allocation of change node failed \n");
	}

	/* check the target context counters against with WATERMARK thresholds
	 * if it meets the requirements then wake up service thread
	 */

	/*
	 * Switch to bitmap after evaluating following set of conditions
	 * Condition:1 Valid HWM value is set
	 * Condition:2 Total changes in metadata mode have crossed HWM
	 * Condition:3 Service is not shutdown
	 */
	if ((driver_ctx->tunable_params.db_high_water_marks[driver_ctx->service_state]) &&
		(tgt_ctxt->tc_pending_md_changes >=
		 (driver_ctx->tunable_params.db_high_water_marks[driver_ctx->service_state])) &&
		(!driver_ctx->sys_shutdown)) {

		/*wakeup service thread*/
		if (!(vcptr->tc_flags & VCF_VOLUME_STACKED_PARTIALLY) && 
					!vcptr->tc_bp->bmap_busy_wait) {
			INM_ATOMIC_INC(&driver_ctx->service_thread.wakeup_event_raised);
			INM_WAKEUP_INTERRUPTIBLE(&driver_ctx->service_thread.wakeup_event);
			INM_COMPLETE(&driver_ctx->service_thread._new_event_completion);
			vcptr->tc_bp->bmap_busy_wait = TRUE;
		}
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving tcPages:%d dc_cur_res_pages:%d ",
			tgt_ctxt->tc_stats.num_pages_allocated, 
			driver_ctx->dc_cur_res_pages);
	}
#undef vcptr
	return _rc;
}

inm_s32_t add_tag_in_non_stream_mode(tag_volinfo_t *tag_volinfop, 
		                     tag_info_t *tag_buf, inm_s32_t num_tags, 
		                     tag_guid_t *tag_guid, inm_s32_t index, 
		                     int commit_pending, tag_history_t *hist)
{
	target_context_t *ctxt = tag_volinfop->ctxt;
	inm_s32_t status = 0, padtaglen = 0, hdrlen = 0, idx = 0;
	change_node_t *chg_node = NULL;
	char *pg = NULL;
	inm_s32_t tag_idx = 0;
	tag_info_t *tag_ptr = tag_buf;
#ifdef INM_AIX
	inm_wdata_t wdata;
#endif
	TAG_COMMIT_STATUS *tag_status = NULL;

	/* Whether to freeze or not should be an option in future. No problem
	 * in ensuring fs consistency also. So, the current approach also
	 * seem to be fine.
	 */
	dbg("Issuing tag in non-stream mode");
	dbg("Num inflight IOs while taking tag %d\n", 
				INM_ATOMIC_READ(&ctxt->tc_nr_in_flight_ios));

#ifdef INM_AIX
	INM_MEM_ZERO(&wdata, sizeof(inm_wdata_t));
	wdata.wd_chg_node = tag_volinfop->chg_node;
	wdata.wd_meta_page = tag_volinfop->meta_page;
	chg_node = get_change_node_for_usertag(ctxt, &wdata, commit_pending);
	tag_volinfop->chg_node = wdata.wd_chg_node;
	tag_volinfop->meta_page = wdata.wd_meta_page;
#else
	chg_node = get_change_node_for_usertag(ctxt, NULL, commit_pending);
#endif
	if(!chg_node) {
		status = -ENOMEM;
		err("Failed to get change node for adding tag");
		goto unlock_exit;
	}

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
	if (INM_ATOMIC_READ(&driver_ctx->is_iobarrier_on)) {
		memcpy_s(&chg_node->changes.start_ts, 
			sizeof(TIME_STAMP_TAG_V2),
			&driver_ctx->dc_crash_tag_timestamps, 
			sizeof(TIME_STAMP_TAG_V2));
		memcpy_s(&chg_node->changes.end_ts, sizeof(TIME_STAMP_TAG_V2),
				&chg_node->changes.start_ts, 
				sizeof(TIME_STAMP_TAG_V2));
	}
#endif

	INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	if (driver_ctx->dc_tag_drain_notify_guid &&
		!INM_MEM_CMP(driver_ctx->dc_cp_guid,
				     driver_ctx->dc_tag_drain_notify_guid,
				     GUID_LEN)) {
		if (driver_ctx->dc_tag_commit_notify_flag & 
					TAG_COMMIT_NOTIFY_BLOCK_DRAIN_FLAG) {
			chg_node->flags |= CHANGE_NODE_BLOCK_DRAIN_TAG;
		}
		else {
			chg_node->flags |= CHANGE_NODE_FAILBACK_TAG;
		}
		tag_status = ctxt->tc_tag_commit_status;
	}
	INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);

	/*
	 * set write order state to data here, because tag is not a change
	 */
	chg_node->wostate = ecWriteOrderStateData;

	pg = (char *)chg_node->changes.cur_md_pgp;

	while(tag_idx < num_tags) {
		padtaglen = ALIGN((tag_ptr->tag_len + sizeof(unsigned short)), 
			  sizeof(inm_u32_t));
		hdrlen = (padtaglen + sizeof(STREAM_REC_HDR_4B)) < 0xFF ?
		sizeof(STREAM_REC_HDR_4B) : sizeof(STREAM_REC_HDR_8B);

		if((idx + hdrlen + padtaglen) > INM_PAGESZ) {
			err("Exceeded Maximum tag size per change node");
			status = -ENOMEM;
			inm_list_del(&chg_node->next);
			deref_chg_node(chg_node);
			goto unlock_exit;		
		}

		FILL_STREAM_HEADER((pg + idx), 
				STREAM_REC_TYPE_USER_DEFINED_TAG,
				(hdrlen + padtaglen));
		idx += hdrlen;
		*(unsigned short *)(pg + idx) = tag_ptr->tag_len;
		idx += sizeof(unsigned short);
		if (memcpy_s((pg + idx), tag_ptr->tag_len, tag_ptr->tag_name,
			                                   tag_ptr->tag_len)) {
			status = INM_EFAULT;
			inm_list_del(&chg_node->next);
			deref_chg_node(chg_node);
			goto unlock_exit;
		}

		idx -= sizeof(unsigned short);
		idx += padtaglen;

		tag_idx++; 	
	tag_ptr++;
	}

	/* Append end of tag list stream. */
	FILL_STREAM_HEADER_4B((pg + idx), STREAM_REC_TYPE_END_OF_TAG_LIST,
			  sizeof(STREAM_REC_HDR_4B));
	if(tag_guid){
	tag_guid->status[index] = STATUS_PENDING;
	chg_node->tag_status_idx = index;
	}

	if (tag_status) {
		info("The failback tag is inserted for disk %s, dirty block = %p",
			  ctxt->tc_guid, chg_node);
		set_tag_drain_notify_status(ctxt, TAG_STATUS_INSERTED,
			                            DEVICE_STATUS_SUCCESS);
	}

	chg_node->tag_guid = tag_guid;
	chg_node->cn_hist = hist;

	dbg("Tag Issued Successfully to volume %s", ctxt->tc_guid);
	goto out;
unlock_exit:
	if(tag_guid)
	tag_guid->status[index] = STATUS_FAILURE;

	if (tag_status)
		set_tag_drain_notify_status(ctxt, TAG_STATUS_INSERTION_FAILED,
			                            DEVICE_STATUS_SUCCESS);
out:
	return status;
}

