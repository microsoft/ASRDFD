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
#include "work_queue.h"
#include "utils.h"
#include "filestream.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "VBitmap.h"
#include "change-node.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "data-mode.h"
#include "driver-context.h"
#include "file-io.h"
#include "osdep.h"
#include "telemetry-types.h"
#include "telemetry.h"

extern driver_context_t *driver_ctx;

#define TELEMETRY_DEFAULT_TAG_GUID "TAG_GUID_UNINITIALIZED"

void
telemetry_set_dbs(inm_u64_t *state, inm_u64_t flag)
{
	inm_irqflag_t lock_flag;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_tel.dt_dbs_slock, lock_flag);
	*state |= flag;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_tel.dt_dbs_slock, 
								lock_flag);
}

void
telemetry_clear_dbs(inm_u64_t *state, inm_u64_t flag)
{
	inm_irqflag_t lock_flag;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_tel.dt_dbs_slock, lock_flag);
	*state &= ~flag;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_tel.dt_dbs_slock, 
								lock_flag);
}

inm_u64_t
telemetry_get_dbs(target_context_t *tgt_ctxt, inm_s32_t tag_status,
				  etTagStateTriggerReason reason)
{
	inm_u64_t dbs = 0;
	inm_irqflag_t lock_flag;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_tel.dt_dbs_slock, lock_flag);
	dbs = driver_ctx->dc_tel.dt_blend;
	if (tgt_ctxt)
		dbs |= tgt_ctxt->tc_tel.tt_blend;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_tel.dt_dbs_slock, 
								lock_flag);

	if (tgt_ctxt &&
		tag_status == ecTagStatusDropped) {

		switch (reason) {
			case ecBitmapWrite:
			dbs |= DBS_BITMAP_WRITE;
			break;

			case ecFilteringStopped:
			dbs |= DBS_FILTERING_STOPPED;
			break;

			case ecClearDiffs:
			dbs |= DBS_CLEAR_DIFFERENTIALS;
			break;
			
			case ecNonPagedPoolLimitHitMDMode:
			dbs |= DBS_NPPOOL_LIMIT_HIT_MD_MODE;
			break;

			case ecSplitIOFailed:
			dbs |= DBS_SPLIT_IO_FAILED;
			break;

			case ecOrphan:
			dbs |= DBS_ORPHAN;
			break;

			default:
			err("Invalid reason %d for dropped tag", reason);
			break;
		}
	}

	return (dbs | TEL_FLAGS_SET_BY_DRIVER);
}

void
telemetry_tag_stats_record(target_context_t *tgt_ctxt, tgt_stats_t *stats)
{
	stats->ts_pending = tgt_ctxt->tc_bytes_pending_changes;
	stats->ts_tracked_bytes = tgt_ctxt->tc_bytes_tracked; 
	stats->ts_drained_bytes = tgt_ctxt->tc_bytes_commited_changes;
	stats->ts_getdb = tgt_ctxt->tc_tel.tt_getdb;
	stats->ts_commitdb = tgt_ctxt->tc_tel.tt_commitdb;
	stats->ts_revertdb = tgt_ctxt->tc_tel.tt_revertdb;
	stats->ts_commitdb_failed = tgt_ctxt->tc_tel.tt_commitdb_failed;
	stats->ts_nwlb1 = tgt_ctxt->tc_dbcommit_latstat.ls_freq[0]; 
	stats->ts_nwlb2 = tgt_ctxt->tc_dbcommit_latstat.ls_freq[1]; 
	stats->ts_nwlb3 = tgt_ctxt->tc_dbcommit_latstat.ls_freq[2] +
				      tgt_ctxt->tc_dbcommit_latstat.ls_freq[3];
	stats->ts_nwlb4 = tgt_ctxt->tc_dbcommit_latstat.ls_freq[4] +
				      tgt_ctxt->tc_dbcommit_latstat.ls_freq[5] +
				      tgt_ctxt->tc_dbcommit_latstat.ls_freq[6];
	stats->ts_nwlb5 = tgt_ctxt->tc_dbcommit_latstat.ls_freq[7] +
				      tgt_ctxt->tc_dbcommit_latstat.ls_freq[8];
}
 
inm_u64_t
telemetry_get_wostate(target_context_t *tgt_ctxt)
{
	inm_u64_t wo_state = 0;

	wo_state |= tgt_ctxt->tc_prev_wostate;
	wo_state = wo_state << 2;
	wo_state |= tgt_ctxt->tc_cur_wostate;
	wo_state = wo_state << 2;
	wo_state |= tgt_ctxt->tc_cur_mode;

	wo_state |= TEL_FLAGS_SET_BY_DRIVER;

	return wo_state;
}

inm_u64_t
telemetry_md_capture_reason(target_context_t *tgt_ctxt)
{
	return TEL_FLAGS_SET_BY_DRIVER;
}

void
telemetry_tag_common_put(tag_telemetry_common_t *tag_common)
{
	if (INM_ATOMIC_DEC_AND_TEST(&tag_common->tc_refcnt))
		INM_KFREE(tag_common, sizeof(tag_telemetry_common_t), 
							INM_KERNEL_HEAP);
}

void
telemetry_tag_common_get(tag_telemetry_common_t *tag_common)
{
	INM_ATOMIC_INC(&tag_common->tc_refcnt);
}

tag_telemetry_common_t *
telemetry_tag_common_alloc(inm_s32_t ioctl_cmd)
{
	tag_telemetry_common_t *tag_common = NULL;
   
	get_time_stamp(&(driver_ctx->dc_tel.dt_last_tag_request_time));

	tag_common = INM_KMALLOC(sizeof(tag_telemetry_common_t), INM_KM_SLEEP, 
				             INM_KERNEL_HEAP);
	if (!tag_common)
		goto out;

	INM_MEM_ZERO(tag_common, sizeof(tag_telemetry_common_t));

	switch (ioctl_cmd) {
		case IOCTL_INMAGE_IOBARRIER_TAG_VOLUME:
			tag_common->tc_type = ecTagLocalCrash;
			sprintf_s(tag_common->tc_guid, 
				sizeof(tag_common->tc_guid), "%s",
				TELEMETRY_DEFAULT_TAG_GUID);
			break;

		default:
			INM_BUG_ON(ioctl_cmd);
			INM_KFREE(tag_common, sizeof(tag_telemetry_common_t), 
				      INM_KERNEL_HEAP);
			tag_common = NULL;
			break;
	}

	if (tag_common) {
		tag_common->tc_ioctl_cmd = ioctl_cmd;
		tag_common->tc_req_time = 
				driver_ctx->dc_tel.dt_last_tag_request_time;
		INM_ATOMIC_SET(&tag_common->tc_refcnt, 0);
		telemetry_tag_common_get(tag_common);
	}

out:
	return tag_common;
}

void
telemetry_tag_history_free(tag_history_t *tag_hist)
{
	target_context_t *tgt_ctxt = (target_context_t *)tag_hist->th_tgt_ctxt;

	telemetry_tag_common_put(tag_hist->th_tag_common);
	INM_KFREE(tag_hist, sizeof(tag_history_t), INM_KERNEL_HEAP);
	put_tgt_ctxt(tgt_ctxt);
}
	
tag_history_t *
telemetry_tag_history_alloc(target_context_t *tgt_ctxt,
					tag_telemetry_common_t *tag_common)
{
	tag_history_t *tag_hist = NULL;

	tag_hist = INM_KMALLOC(sizeof(tag_history_t), INM_KM_SLEEP,
				           INM_KERNEL_HEAP);
	if (tag_hist) {
		INM_MEM_ZERO(tag_hist, sizeof(tag_history_t));
		get_tgt_ctxt(tgt_ctxt);
		telemetry_tag_common_get(tag_common);
		tag_hist->th_tag_common = tag_common;
		tag_hist->th_tgt_ctxt = tgt_ctxt;
	}

	return tag_hist;
}


void
telemetry_tag_history_record(target_context_t *tgt_ctxt, 
						 tag_history_t *tag_hist)
{
	get_time_stamp(&tag_hist->th_insert_time);
	tag_hist->th_prev_tag_time = tgt_ctxt->tc_tel.tt_prev_tag_time;
	tag_hist->th_prev_succ_tag_time = 
				tgt_ctxt->tc_tel.tt_prev_succ_tag_time;

	tag_hist->th_tag_status = 0;
	tag_hist->th_blend = telemetry_get_dbs(tgt_ctxt, ecTagStatusMaxEnum, 
				                           ecNotApplicable);
	tag_hist->th_tag_state = ecTagStatusInsertSuccess;
	tag_hist->th_commit_time = 0;       /* Not implemented */
	tag_hist->th_drainbarr_time = 0;    /* Not implemented */
	tag_hist->th_prev_succ_stats = tgt_ctxt->tc_tel.tt_prev_succ_stats;
	tag_hist->th_prev_stats = tgt_ctxt->tc_tel.tt_prev_stats;

	telemetry_tag_stats_record(tgt_ctxt, &tag_hist->th_cur_stats);

	/* update target telemetry last and last succ ts/stats */
	tgt_ctxt->tc_tel.tt_prev_tag_time = 
					tag_hist->th_tag_common->tc_req_time;
	tgt_ctxt->tc_tel.tt_prev_stats = tag_hist->th_cur_stats;

	tgt_ctxt->tc_tel.tt_prev_succ_tag_time = 
				        tag_hist->th_tag_common->tc_req_time;
	tgt_ctxt->tc_tel.tt_prev_succ_stats = tag_hist->th_cur_stats;

	return;	
}

void
telemetry_nwo_stats_record(target_context_t *tgt_ctxt, 
				           etWriteOrderState cur_state,
				           etWriteOrderState new_state,
				           etWOSChangeReason reason)
{
	non_wo_stats_t *nwo = &tgt_ctxt->tc_tel.tt_nwo;

	nwo->nws_old_state = cur_state; 
	nwo->nws_new_state = new_state;
	nwo->nws_change_time = tgt_ctxt->tc_stats.st_wostate_switch_time *
				           HUNDREDS_OF_NANOSEC_IN_SECOND; 
	/* Following pending changes should be in bytes */
	nwo->nws_meta_pending = tgt_ctxt->tc_pending_md_changes; 
	nwo->nws_bmap_pending = 
			tgt_ctxt->tc_bp->num_changes_queued_for_writing; 
	nwo->nws_data_pending = tgt_ctxt->tc_pending_changes; 
	nwo->nws_nwo_secs = tgt_ctxt->tc_stats.num_secs_in_wostate[cur_state]; 
	nwo->nws_reason = reason; 
	nwo->nws_mem_alloc = 
			tgt_ctxt->tc_stats.num_pages_allocated * PAGE_SIZE; 
	nwo->nws_mem_reserved = tgt_ctxt->tc_reserved_pages * PAGE_SIZE; 
	nwo->nws_mem_free = driver_ctx->dc_cur_unres_pages * PAGE_SIZE; 
	nwo->nws_free_cn = 0; 
	nwo->nws_used_cn = tgt_ctxt->tc_nr_cns; 
	nwo->nws_max_used_cn = 0; 
	nwo->nws_blend = telemetry_get_dbs(tgt_ctxt, ecTagStatusMaxEnum, 
				                       ecNotApplicable);
	nwo->nws_np_alloc = 0; 
	nwo->nws_np_limit_time = 0; 
	nwo->nws_np_alloc_fail = 0; 
}

void
telemetry_check_time_jump(void)
{
	static inm_u64_t prev_time = 0;
	inm_u64_t cur_time = 0;
	inm_u64_t diff_time = 0;

	get_time_stamp(&cur_time);

	if (prev_time) {
	   /* Expected time */
	   prev_time += TELEMETRY_MSEC_TO_100NSEC(
			   		TELEMETRY_FILE_REFRESH_INTERVAL);

	   diff_time = (cur_time > prev_time) ?  
				    cur_time - prev_time :
				    prev_time - cur_time;

	   update_cx_with_time_jump(cur_time, prev_time);

	   if (diff_time > TELEMETRY_ACCEPTABLE_TIME_JUMP_THRESHOLD) {
		   driver_ctx->dc_tel.dt_time_jump_exp = prev_time;
		   driver_ctx->dc_tel.dt_time_jump_cur = cur_time;
	   }
	}

	prev_time = cur_time;
}
