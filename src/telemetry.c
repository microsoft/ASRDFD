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
#include "telemetry-exception.h"

extern driver_context_t *driver_ctx;

static inm_sem_t tel_mutex;         /* Log one file at a time               */
static inm_spinlock_t tel_slock;    /* Record list manipulation             */
static flt_timer_t tel_timer;       /* Refresh files/throttle at interval   */
wqentry_t *tel_wqe = NULL;          /* Worker thread work item              */

static inm_u64_t tel_event_seq = 1; /* Cur seq no. Indicate holes in logs   */
static inm_u64_t tel_file_seq = 0;  /* File seq number                      */

static char *tel_fname = NULL;      /* Current file name                    */

typedef struct tel_rec {
	inm_list_head_t tr_head;        /* Record list                          */
	inm_u64_t       tr_seq;         /* Event Seq num                        */
	inm_u32_t       tr_len;         /* Length of buffer used                */
	inm_s32_t       tr_written;     /* Bytes written in single iteration    */
	char            tr_buf[0];      /* Log buffer                           */
} tel_rec_t;
static inm_list_head_t tel_list;    /* Record List                          */
static int tel_nrecs = 0;

static int tel_init = 0;
static int tel_shutdown = 0;        /* Indicated telemetry shutdown         */

#define TELEMETRY_FILE_NR_MAX           12
#define TELEMETRY_FILE_NAME_PREFIX      "/var/log/involflt_telemetry_completed_"
#define TELEMETRY_FILE_NAME_SUFFIX      ".log"

#define TELEMETRY_REC_SIZE              PAGE_SIZE
#define TELEMETRY_REC_BUF_SIZE          (TELEMETRY_REC_SIZE - sizeof(tel_rec_t))
#define TELEMETRY_REC_NR_MAX_PER_VOL    16      /* 1 hour of recs per vol   */

#define TELEMETRY_REC_CUR(l)    		                                    \
	(inm_list_entry(inm_list_last(l), tel_rec_t, tr_head))

#define TELEMETRY_REC_CUR_BUF(l)    	((TELEMETRY_REC_CUR(l))->tr_buf)
#define TELEMETRY_REC_CUR_LEN(l)		((TELEMETRY_REC_CUR(l))->tr_len)
#define TELEMETRY_REC_CUR_WRITTEN(l)	((TELEMETRY_REC_CUR(l))->tr_written)
#define TELEMETRY_REC_CUR_SEQ(l)		((TELEMETRY_REC_CUR(l))->tr_seq)

#define TELEMETRY_REC_PREFIX            "{\"Map\":{"
#define TELEMETRY_REC_SUFFIX            "}}\n"

/* Log format is "{"Map":{"K1":"V1","K2":"V2",....,"KN":"VN"}}\n" */
#define TELEMETRY_LOG(l, fmt, arg...)                                       			\
	do {                                                                    		\
		if (inm_list_empty(l))                                              		\
			break;                                                          	\
				                                                            	\
		TELEMETRY_REC_CUR_WRITTEN(l) =							\
			sprintf_s(TELEMETRY_REC_CUR_BUF(l) + TELEMETRY_REC_CUR_LEN(l),		\
				      TELEMETRY_REC_BUF_SIZE - TELEMETRY_REC_CUR_LEN(l), 	\
				      fmt, ## arg);                                         	\
				                                                            	\
		dbg("Written %d bytes", TELEMETRY_REC_CUR_WRITTEN(l));              		\
		if (TELEMETRY_REC_CUR_WRITTEN(l) == -1)                             		\
			telemetry_rec_alloc(l, NOT_IN_IO_PATH);                                 \
		else                                                                		\
			TELEMETRY_REC_CUR_LEN(l) += TELEMETRY_REC_CUR_WRITTEN(l);       	\
				                                                            	\
	} while (!inm_list_empty(l) &&                                          		\
			 TELEMETRY_REC_CUR_LEN(l) == 0) /* New record added to the list */                

#define TELEMETRY_LOG_PREFIX(l) TELEMETRY_LOG(l, "%s", TELEMETRY_REC_PREFIX)

/* go back and write over comma after last key:value pair */
#define TELEMETRY_LOG_SUFFIX(l)					\
	do {                                                    \
		if (inm_list_empty(l))                          \
			break;                                  \
				                                \
		TELEMETRY_REC_CUR_LEN(l)--;			\
		TELEMETRY_LOG(l, "%s", TELEMETRY_REC_SUFFIX);	\
	} while(0)

#define TELEMETRY_LOG_KV(l, k, v, f) TELEMETRY_LOG(l, "\"%s\":\""f"\",", k, v)   

#define TELEMETRY_LOG_ULL(l, k, v)   TELEMETRY_LOG_KV(l, k, v, "%llu")
#define TELEMETRY_LOG_UL(l, k, v)    TELEMETRY_LOG_KV(l, k, v, "%lu")
#define TELEMETRY_LOG_UINT(l, k, v)  TELEMETRY_LOG_KV(l, k, v, "%u")
#define TELEMETRY_LOG_INT(l, k, v)   TELEMETRY_LOG_KV(l, k, v, "%d")
#define TELEMETRY_LOG_STR(l, k, v)   TELEMETRY_LOG_KV(l, k, v, "%s")
#define TELEMETRY_LOG_WTIME(l, k, v)                                        \
	TELEMETRY_LOG_KV(l, k, ((v != 0) ? (v + TELEMETRY_WTIME_OFF) : v), "%llu")

static void telemetry_refresh_timeout(wqentry_t *unused);

static
void telemetry_cleanup(void)
{
	wqentry_t *tmp_wqe = NULL;
	char *tmp_fname = NULL;

	dbg("Free telemetry memory");

	INM_SPIN_LOCK(&tel_slock);
	/* If the work queue entry is no longer queued with worker thread */
	if (tel_wqe &&
		tel_wqe->flags != WITEM_TYPE_TELEMETRY_FLUSH) {
		tmp_wqe = tel_wqe;
		tel_wqe = NULL;

		tmp_fname = tel_fname;
		tel_fname = NULL;
	}
	INM_SPIN_UNLOCK(&tel_slock);

	if (tmp_wqe) 
		put_work_queue_entry(tmp_wqe);

	if (tmp_fname)
		free_path_memory(&tmp_fname);
	
}

static inline inm_u64_t
telemetry_next_event_id(void)
{
	inm_u64_t event_id = 0;
	
	INM_SPIN_LOCK(&tel_slock);
	event_id = tel_event_seq++;
	INM_SPIN_UNLOCK(&tel_slock);

	return event_id;
}
	
static void
telemetry_log_rec_drop(inm_s32_t errno, inm_u64_t start, inm_u64_t end)
{
	dbg("Telemetry: Dropped(%d) => %llu - %llu", errno, start, end);
}

static void
telemetry_free_rec(tel_rec_t *rec) 
{
	INM_SPIN_LOCK(&tel_slock);
	tel_nrecs--;
	INM_SPIN_UNLOCK(&tel_slock);

	dbg("Free %p", rec);
	INM_FREE_PAGE(rec, INM_KERNEL_HEAP);
}

/* Free record list */
static void
telemetry_free_rec_list(inm_list_head_t *tel_data)
{
	inm_list_head_t *cur = NULL;
	inm_list_head_t *next = NULL;
	tel_rec_t *rec = NULL;
		
	inm_list_for_each_safe(cur, next, tel_data) {
		rec = inm_list_entry(cur, tel_rec_t, tr_head);
		inm_list_del_init(cur);
		telemetry_free_rec(rec);
	}
}

static tel_rec_t *
__telemetry_rec_alloc(inm_u64_t event_id, int path) 
{
	int alloc = 0;
	void *tel_buf = NULL;
	tel_rec_t *rec = NULL;
	static int mem_throttled = 0;
	inm_s32_t alloc_flag;

	INM_SPIN_LOCK(&tel_slock);
	if (tel_nrecs < 
		(driver_ctx->total_prot_volumes * 
		 		TELEMETRY_REC_NR_MAX_PER_VOL)) {
		tel_nrecs++;
		alloc = 1;
		if (mem_throttled) {
			info("Telemetry: memory unthrottled");
			mem_throttled = 0;
		}
	} else {
		if (!mem_throttled) {
			info("Telemetry: memory throttled");
			mem_throttled = 1;
		}
	}
	INM_SPIN_UNLOCK(&tel_slock);

	if (alloc) {
		alloc_flag = INM_KM_SLEEP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) && !defined(SLES15SP3)
		if (path == IN_IOBARRIER_PATH)
			alloc_flag = INM_KM_NOIO;
#endif
		tel_buf = (void *)__INM_GET_FREE_PAGE(alloc_flag,
							INM_KERNEL_HEAP);
		if (!tel_buf) {
			err("Error allocating telemetry buffer");
			INM_SPIN_LOCK(&tel_slock);
			tel_nrecs--;
			INM_SPIN_UNLOCK(&tel_slock);
		} else {
			rec = (tel_rec_t *)tel_buf;

			INM_INIT_LIST_HEAD(&(rec->tr_head));
			rec->tr_seq = event_id;
			rec->tr_len = 0;
			rec->tr_written = 0;
		}
	}

	return rec;
}

static inm_s32_t 
telemetry_rec_alloc(inm_list_head_t *rec_list, int path)
{
	inm_s32_t error = 0;
	tel_rec_t *rec = NULL;
	inm_u64_t event_id = 0;

	if (!tel_init) {
		err("Telemetry request before telemetry service initialised");
		return -EPERM;
	}

	if (inm_list_empty(rec_list)) {
		event_id = telemetry_next_event_id();
	} else {
		event_id = TELEMETRY_REC_CUR_SEQ(rec_list);
	}
	
	rec = __telemetry_rec_alloc(event_id, path);
	if (!rec) {
		telemetry_free_rec_list(rec_list);
		telemetry_log_rec_drop(error, event_id, event_id);
		error = -ENOMEM;
		goto out;
	}

	dbg("Allocate %p", rec);

	inm_list_add_tail(&rec->tr_head, rec_list);

out:
	return error;	
}

static void
telemetry_queue_rec(inm_list_head_t *rec_list)
{
	INM_SPIN_LOCK(&tel_slock);
	inm_list_splice_init(rec_list, &tel_list);
	INM_SPIN_UNLOCK(&tel_slock);
}

/* start the timer */
static void
start_tel_timer(void)
{
	if (!tel_shutdown)
		start_timer(&tel_timer, TELEMETRY_FILE_REFRESH_INTERVAL, 
				    telemetry_refresh_timeout);
}

/*
 * Check for throttling telemetry if files are not being drained
 */
static int
telemetry_throttled(void)
{
	void *temp_fhdl;
	static int tel_throttled = 0;

	if (tel_file_seq >= TELEMETRY_FILE_NR_MAX) {
		sprintf_s(tel_fname, INM_PATH_MAX, "%s%llu%s", 
				  TELEMETRY_FILE_NAME_PREFIX,
				  (tel_file_seq - TELEMETRY_FILE_NR_MAX + 1),
				  TELEMETRY_FILE_NAME_SUFFIX);
		dbg("Telemetry: Checking for old file: %s", tel_fname);

		if (flt_open_file(tel_fname, O_RDONLY, &temp_fhdl)) {
			flt_close_file(temp_fhdl);
		   
			if (!tel_throttled) {
				info("Telemetry: Throttled");
			}
			
			tel_throttled =  1;
		} else {
			if (tel_throttled) {
				info("Telemetry: Unthrottled");
			}

			tel_throttled = 0;
		}
	}
	
	return tel_throttled;
}

/*
 * Check for throttle and get a new file handle
 */
static inm_s32_t
telemetry_refresh_file(void **phdl)
{
	inm_s32_t error = 0;
	void *hdl = NULL;

	INM_DOWN(&tel_mutex);

	if (!tel_fname) {
		INM_BUG_ON(!tel_fname);
		goto out;
	}

	if (telemetry_throttled()) {
		error = -EMFILE;
		goto out;
	}

	tel_file_seq++;
	sprintf_s(tel_fname, INM_PATH_MAX, "%s%llu%s", 
			TELEMETRY_FILE_NAME_PREFIX,
			tel_file_seq, TELEMETRY_FILE_NAME_SUFFIX);

	dbg("Telemetry: New file = %s", tel_fname);
	if (!flt_open_file(tel_fname, O_RDWR | O_CREAT | O_TRUNC, &hdl)) {
		err("Telemetry: File open failed: %s", tel_fname);
		error = -EIO;
		tel_file_seq--;
		hdl = NULL;
	}

out:
	INM_UP(&tel_mutex);

	*phdl = hdl;
	return error;
}

/* Take each record and write to the file handle */
static inm_s32_t
telemetry_write_data(void *tel_hdl, inm_list_head_t *tel_data)
{
	inm_s32_t error = 0;
	inm_list_head_t *cur = NULL;
	inm_list_head_t *next = NULL;
	tel_rec_t *rec = NULL;
	inm_s32_t write_succeeded = 0;
	inm_u64_t offset = 0;
	inm_u32_t written = 0;

	inm_list_for_each_safe(cur, next, tel_data) {
		rec = inm_list_entry(cur, tel_rec_t, tr_head);
		
		dbg("Telemetry: Logging event = %llu len = %d",
			rec->tr_seq, rec->tr_len);
		
		write_succeeded = flt_write_file(tel_hdl, rec->tr_buf, offset,
			                         rec->tr_len, &written);
		if (!write_succeeded ||         /* Failed           */
			written != rec->tr_len) {   /* Partial write    */
				error = -EIO;
				break;
		}

		offset += written;
	}

	flt_close_file(tel_hdl);

	return error;
}

/*
 * Get a new file handle and write telemetry data to it
 */
static inm_s32_t
telemetry_flush_data(inm_list_head_t *tel_data)
{
	inm_s32_t error = 0;
	void *tel_fhdl = NULL;
	inm_u64_t start_seqno = 0;
	inm_u64_t end_seqno = 0;
	tel_rec_t *rec = NULL;

	if (inm_list_empty(tel_data))
		goto out;

	error = telemetry_refresh_file(&tel_fhdl);
	if (!error)
		error = telemetry_write_data(tel_fhdl, tel_data);

	if (error) {
		if (error != -EMFILE) /* Not throttled */
			err("Error writing telemetry log");

		rec = inm_list_entry(inm_list_first(tel_data), tel_rec_t, 
								tr_head);
		start_seqno = rec->tr_seq;

		rec = inm_list_entry(inm_list_last(tel_data), tel_rec_t, 
								tr_head);
		end_seqno = rec->tr_seq;

		telemetry_log_rec_drop(error, start_seqno, end_seqno);
	}

	telemetry_free_rec_list(tel_data);

out:
	if (tel_shutdown)
		telemetry_cleanup();

	return error;
}

/*
 * Telemetry flush worker routine
 */
static void
telemetry_flush_worker(wqentry_t *wqe)
{
	inm_list_head_t temp;

	INM_INIT_LIST_HEAD(&temp);
	
	/* 
	 * Grab all pending records into temp
	 * and mark the work item as free so further
	 * worker thread telemetry offloads can be queued
	 */
	INM_SPIN_LOCK(&tel_slock);
	wqe->flags = WITEM_TYPE_UNINITIALIZED;
	inm_list_replace_init(&tel_list, &temp);
	INM_SPIN_UNLOCK(&tel_slock);
	
	telemetry_flush_data(&temp);
}

/*
 * Queue telemetry flush work item to worker thread
 */
static void
telemetry_offload_flush_to_worker(void)
{
	INM_SPIN_LOCK(&tel_slock);
	/* We only queue one telemetry flush work item */
	if (tel_wqe &&
		tel_wqe->flags != WITEM_TYPE_TELEMETRY_FLUSH) {
		tel_wqe->flags = WITEM_TYPE_TELEMETRY_FLUSH;
		tel_wqe->context = NULL;
		tel_wqe->work_func = telemetry_flush_worker;

		add_item_to_work_queue(&driver_ctx->wqueue, tel_wqe);
	}
	INM_SPIN_UNLOCK(&tel_slock);
}

/*
 * Timeout callback for telemetry timer. Since barrier/freeze 
 * timeout is handled by timer thread, we offload writing telemetry 
 * data to worker thread. 
 */
static void
telemetry_refresh_timeout(wqentry_t *unused)
{
	telemetry_offload_flush_to_worker();
	telemetry_check_time_jump();
	start_tel_timer();
}

static inm_s32_t
telemetry_log_end(inm_list_head_t *rec_list)
{
	inm_s32_t error = 0;

	/* Telemetry should shutdown after all tags have been dropped/drained */
	INM_BUG_ON(tel_shutdown);

	TELEMETRY_LOG_SUFFIX(rec_list);
	
	if (inm_list_empty(rec_list))
		error = -ENOMEM;
	else
		telemetry_queue_rec(rec_list);

	return error;
}

static inm_s32_t
telemetry_log_start(inm_list_head_t *rec_list, int path)
{
	inm_s32_t error = 0;
	inm_u64_t ltime = 0;

	INM_INIT_LIST_HEAD(rec_list);

	error = telemetry_rec_alloc(rec_list, path);
	if (error)
		goto out;

	/* 
	 * This time should be wrt unix epoch as it is 
	 * interpreted by event collector 
	 */
	get_time_stamp(&ltime);

	TELEMETRY_LOG_PREFIX(rec_list);
	TELEMETRY_LOG_ULL(rec_list, "EventRecId", 
					TELEMETRY_REC_CUR_SEQ(rec_list));
	TELEMETRY_LOG_ULL(rec_list, "SrcLoggerTime", ltime);

out:
	return error;
}

void
telemetry_log_drop_error(inm_s32_t error)
{
	inm_u64_t event_id = 0;
	
	event_id = telemetry_next_event_id();
	telemetry_log_rec_drop(error, event_id, event_id);
}

#if defined(TELEMETRY)
inm_s32_t
telemetry_log_tag_history(change_node_t *chg_node, 
				          target_context_t *ctxt,
				          etTagStatus status, 
				          etTagStateTriggerReason reason, 
				          etMessageType msg)
{
	inm_s32_t error = 0;
	tag_history_t *tag_hist = NULL;
	tag_telemetry_common_t *tag_common = NULL;
	inm_list_head_t rec_list;
	inm_list_head_t *recs = &rec_list;
	inm_u64_t state = 0;
	tgt_stats_t *stats = NULL;
	non_wo_stats_t *nwo = NULL;
	exception_buf_t *excbuf = NULL;

	if (!chg_node) {
		err("NULL change node");
		INM_BUG_ON(!chg_node);
		goto out;
	}

	tag_hist = chg_node->cn_hist;
	if (!tag_hist)
		goto out;

	if (!ctxt) {
		telemetry_log_drop_error(-ENODEV);
		goto out;
	}

	tag_common = tag_hist->th_tag_common;

	error = telemetry_log_start(recs, NOT_IN_IO_PATH);
	if (error) 
		goto out;

	excbuf = telemetry_get_exception();
	TELEMETRY_LOG_STR(recs, "CustomJson", excbuf->eb_buf);
	telemetry_put_exception(excbuf);

	/* Tag Data */
	state = telemetry_get_dbs(ctxt, status, reason);

	TELEMETRY_LOG_WTIME(recs, "TagRqstTime", tag_common->tc_req_time);
	TELEMETRY_LOG_UINT(recs, "TagType", tag_common->tc_type);
	TELEMETRY_LOG_STR(recs, "TagMarkerGUID", tag_common->tc_guid);
	TELEMETRY_LOG_UINT(recs, "NumOfTotalDisk", tag_common->tc_ndisks);
	TELEMETRY_LOG_UINT(recs, "NumOfProtectdDisk", 
						tag_common->tc_ndisks_prot);
	TELEMETRY_LOG_UINT(recs, "NumOfTaggedDisk", 
						tag_common->tc_ndisks_tagged);
	TELEMETRY_LOG_INT(recs, "IoctlCode", tag_common->tc_ioctl_cmd);
	TELEMETRY_LOG_INT(recs, "TagStatus", tag_hist->th_tag_status);
	TELEMETRY_LOG_INT(recs, "GlobalIoctlStatus", 
						tag_common->tc_ioctl_status);
	TELEMETRY_LOG_ULL(recs, "PrevTagEndTS", ctxt->tc_tel.tt_prev_tag_ts);
	TELEMETRY_LOG_ULL(recs, "PrevTagEndSeq", 
					ctxt->tc_tel.tt_prev_tag_seqno);
	TELEMETRY_LOG_ULL(recs, "PrevCommittedTS", ctxt->tc_tel.tt_prev_ts);
	TELEMETRY_LOG_ULL(recs, "PrevCommittedSeq", 
					ctxt->tc_tel.tt_prev_seqno);
	TELEMETRY_LOG_ULL(recs, "TagEndTS", 
		chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601);
	TELEMETRY_LOG_ULL(recs, "TagEndSeq", 
			        chg_node->changes.end_ts.ullSequenceNumber);
	TELEMETRY_LOG_WTIME(recs, "TagInsertTime", tag_hist->th_insert_time);
	TELEMETRY_LOG_WTIME(recs, "TagCompleteTime", 0ULL); /* commit/revoke */
	TELEMETRY_LOG_WTIME(recs, "TimeJumpDetectedTS", 
			                driver_ctx->dc_tel.dt_time_jump_exp);
	TELEMETRY_LOG_WTIME(recs, "TimeJumpedTS", 
			                driver_ctx->dc_tel.dt_time_jump_cur);
	TELEMETRY_LOG_STR(recs, "DiskIdentity", ctxt->tc_pname);
	TELEMETRY_LOG_STR(recs, "DiskName", ctxt->tc_guid);
	TELEMETRY_LOG_ULL(recs, "DiskBlendedState", state);
	TELEMETRY_LOG_UINT(recs, "TagState", status);

	/* Previous tag replication stats */
	stats = &tag_hist->th_prev_stats;

	TELEMETRY_LOG_WTIME(recs, "LastTagInsertTime", 
				     tag_hist->th_prev_tag_time);
	TELEMETRY_LOG_ULL(recs, "PendChgPrev", stats->ts_pending);
	TELEMETRY_LOG_ULL(recs, "ChurnPrev", stats->ts_tracked_bytes);       
	TELEMETRY_LOG_ULL(recs, "DrainDBCountPrev", stats->ts_getdb);
	TELEMETRY_LOG_ULL(recs, "RevertDBCountPrev", stats->ts_revertdb);
	TELEMETRY_LOG_ULL(recs, "CommitDBCountPrev", stats->ts_commitdb);
	TELEMETRY_LOG_ULL(recs, "DrainDataPrevInBytes", 
						stats->ts_drained_bytes);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt1Prev", stats->ts_nwlb1);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt2Prev", stats->ts_nwlb2);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt3Prev", stats->ts_nwlb3);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt4Prev", stats->ts_nwlb4);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt5Prev", stats->ts_nwlb5);
	TELEMETRY_LOG_ULL(recs, "CommitDbFailPrev", stats->ts_commitdb_failed);
	
	/* Current replication stats */
	/* Update the prev stats to current stats */
	stats = &tag_hist->th_cur_stats;
	
	TELEMETRY_LOG_ULL(recs, "PendChgOnInsert", stats->ts_pending);
	TELEMETRY_LOG_ULL(recs, "ChurnCurr", stats->ts_tracked_bytes);       
	TELEMETRY_LOG_ULL(recs, "DrainDBCountCurr", stats->ts_getdb);
	TELEMETRY_LOG_ULL(recs, "RevertDBCountCurr", stats->ts_revertdb);
	TELEMETRY_LOG_ULL(recs, "CommitDBCountCurr", stats->ts_commitdb);
	TELEMETRY_LOG_ULL(recs, "DrainDataCurr", stats->ts_drained_bytes);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt1Curr", stats->ts_nwlb1);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt2Curr", stats->ts_nwlb2);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt3Curr", stats->ts_nwlb3);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt4Curr", stats->ts_nwlb4);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt5Curr", stats->ts_nwlb5);
	TELEMETRY_LOG_ULL(recs, "CommitDbFailCurr", stats->ts_commitdb_failed);
	
	/* Prev successful tag stats */
	stats = &tag_hist->th_prev_succ_stats;
	
	/* If successful commit, generate current stats and give */
	if (status == ecTagStatusTagCommitDBSuccess)
		telemetry_tag_stats_record(ctxt, stats);

	TELEMETRY_LOG_ULL(recs, "PendChgToCmp", stats->ts_pending);
	TELEMETRY_LOG_ULL(recs, "ChurnToCmp", stats->ts_tracked_bytes);       
	TELEMETRY_LOG_ULL(recs, "DrainDBCountCmp", stats->ts_getdb);
	TELEMETRY_LOG_ULL(recs, "RevertDBCountCmp", stats->ts_revertdb);
	TELEMETRY_LOG_ULL(recs, "CommitDBCountCmp", stats->ts_commitdb);
	TELEMETRY_LOG_ULL(recs, "DrainDataToCmp", stats->ts_drained_bytes);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt1ToCmp", stats->ts_nwlb1);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt2ToCmp", stats->ts_nwlb2);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt3ToCmp", stats->ts_nwlb3);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt4ToCmp", stats->ts_nwlb4);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt5ToCmp", stats->ts_nwlb5);
	TELEMETRY_LOG_ULL(recs, "CommitDbFailToCmp", stats->ts_commitdb_failed);

	/* Generic info */
	state = telemetry_get_wostate(ctxt);

	TELEMETRY_LOG_WTIME(recs, "LastSuccessInsertTime", 
					tag_hist->th_prev_succ_tag_time);
	TELEMETRY_LOG_ULL(recs, "WoFlags", state);
	TELEMETRY_LOG_UL(recs, "CountWOSToMD", 
	 ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateMetadata]);
	TELEMETRY_LOG_UL(recs, "CountWOSToMDUser", 
	 ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateMetadata]);
	TELEMETRY_LOG_UL(recs, "CountWOSToBitmap", 
		ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateBitmap]);
	TELEMETRY_LOG_UL(recs, "CountWOSToBitmapUser", 
	ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateBitmap]);
	TELEMETRY_LOG_WTIME(recs, "LastWoTime", 
				        ctxt->tc_stats.st_wostate_switch_time *
				        HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_ULL(recs, "MDChangesPending", 
				        ctxt->tc_bytes_pending_md_changes);
	TELEMETRY_LOG_WTIME(recs, "DiffSyncThrottleStartTS", 
				        ctxt->tc_tel.tt_ds_throttle_start);
	TELEMETRY_LOG_WTIME(recs, "DiffSyncThrottleEndTS", 
				        ctxt->tc_tel.tt_ds_throttle_stop);
	TELEMETRY_LOG_WTIME(recs, "FirstGetDbTimeOnDrainBlk", 0ULL);
	TELEMETRY_LOG_ULL(recs, "GetDbLatencyCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "WaitDbLatencyCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "DispatchIrpCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "PageFileIoCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "NullFileObjCnt", 0ULL);

	/* Non WO State stats */
	nwo = &ctxt->tc_tel.tt_nwo;
	state = telemetry_md_capture_reason(ctxt);

	TELEMETRY_LOG_UINT(recs, "NonWoSReason", nwo->nws_reason);
	TELEMETRY_LOG_ULL(recs, "MetaDataCaptureReason", state);
	TELEMETRY_LOG_ULL(recs, "DiskStatusFlagsNonWo", nwo->nws_blend);
	TELEMETRY_LOG_UINT(recs, "NonPagePoolAlloc", nwo->nws_np_alloc);
	TELEMETRY_LOG_WTIME(recs, "LastNPLimitHitTime", 
						nwo->nws_np_limit_time);
	TELEMETRY_LOG_UINT(recs, "NonPagePoolAllocFail", 
						nwo->nws_np_alloc_fail);
	TELEMETRY_LOG_UINT(recs, "MemAllocDevCntxt", nwo->nws_mem_alloc);
	TELEMETRY_LOG_UINT(recs, "MemResDevCntxt", nwo->nws_mem_reserved);
	TELEMETRY_LOG_UINT(recs, "MemFreeDevCntxt", nwo->nws_mem_free);
	TELEMETRY_LOG_UINT(recs, "GlobalFreeDbCount", nwo->nws_free_cn);
	TELEMETRY_LOG_UINT(recs, "GlobalLockedDbCount", nwo->nws_used_cn);
	TELEMETRY_LOG_UINT(recs, "MaxLockedDb", nwo->nws_max_used_cn);
	TELEMETRY_LOG_UINT(recs, "NewWoState", nwo->nws_new_state);
	TELEMETRY_LOG_UINT(recs, "OldStateDuration", nwo->nws_nwo_secs);
	TELEMETRY_LOG_WTIME(recs, "SysTimeAtWOSChange", nwo->nws_change_time);

	/* Generic info */
	TELEMETRY_LOG_UINT(recs, "LastResyncError", 
					ctxt->tc_hist.ths_osync_err);
	TELEMETRY_LOG_WTIME(recs, "LastResyncTime",ctxt->tc_hist.ths_osync_ts *
				                HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_WTIME(recs, "ResyncStartTime", 
						ctxt->tc_tel.tt_resync_start);
	TELEMETRY_LOG_WTIME(recs, "ResyncEndTime", ctxt->tc_tel.tt_resync_end);
	TELEMETRY_LOG_WTIME(recs, "ClearDiffTime", 
					ctxt->tc_hist.ths_clrdiff_ts *
				        HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_WTIME(recs, "StartFilterKrnlTime", 
				        ctxt->tc_hist.ths_start_flt_ts *
				        HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_WTIME(recs, "DevCntxtCreateTime", 
						ctxt->tc_tel.tt_create_time);
	TELEMETRY_LOG_WTIME(recs, "LastDrainDbTime", 
						ctxt->tc_tel.tt_getdb_time);
	TELEMETRY_LOG_WTIME(recs, "LastCommitDbTime", 
						ctxt->tc_tel.tt_commitdb_time);
	TELEMETRY_LOG_WTIME(recs, "DrvLoadTime", 
					driver_ctx->dc_tel.dt_drv_load_time);
	TELEMETRY_LOG_UINT(recs, "DevContextFlags", ctxt->tc_flags);
	TELEMETRY_LOG_WTIME(recs, "LastS2Start",
				        driver_ctx->dc_tel.dt_s2_start_time);
	TELEMETRY_LOG_WTIME(recs, "LastS2Stop", 
					driver_ctx->dc_tel.dt_s2_stop_time);
	TELEMETRY_LOG_WTIME(recs, "LastSVStart", 
				     driver_ctx->dc_tel.dt_svagent_start_time);
	TELEMETRY_LOG_WTIME(recs, "LastSVStop", 
				      driver_ctx->dc_tel.dt_svagent_stop_time);
	TELEMETRY_LOG_UINT(recs, "MemAllocFailCount", 
				      driver_ctx->stats.num_malloc_fails);
	TELEMETRY_LOG_UINT(recs, "MessageType", 
					msg | TELEMETRY_LINUX_MSG_TYPE);

	error = telemetry_log_end(recs);

out:
	if (tag_hist)
		telemetry_tag_history_free(tag_hist);

	return error;

}

inm_s32_t
telemetry_log_tag_failure(target_context_t *ctxt, 
				          tag_telemetry_common_t *tag_common,
				          inm_s32_t tag_error,
				          etMessageType msg)
{
	inm_s32_t error = 0;
	inm_list_head_t rec_list;
	inm_list_head_t *recs = &rec_list;
	inm_u64_t state = 0;
	tgt_stats_t *stats = NULL;
	non_wo_stats_t *nwo = NULL;
	inm_u64_t curtime = 0;
	exception_buf_t *excbuf = NULL;
	
	if (!tag_common)
		goto out;

	error = telemetry_log_start(recs, IN_IOBARRIER_PATH);
	if (error) 
		goto out;

	excbuf = telemetry_get_exception();
	TELEMETRY_LOG_STR(recs, "CustomJson", excbuf->eb_buf);
	telemetry_put_exception(excbuf);

	get_time_stamp(&curtime);

	/* Tag Data */
	state = telemetry_get_dbs(ctxt, ecTagStatusInsertFailure, 
							ecNotApplicable);

	TELEMETRY_LOG_WTIME(recs, "TagRqstTime", tag_common->tc_req_time);
	TELEMETRY_LOG_UINT(recs, "TagType", tag_common->tc_type);
	TELEMETRY_LOG_STR(recs, "TagMarkerGUID", tag_common->tc_guid);
	TELEMETRY_LOG_UINT(recs, "NumOfTotalDisk", tag_common->tc_ndisks);
	TELEMETRY_LOG_UINT(recs, "NumOfProtectdDisk", 
						tag_common->tc_ndisks_prot);
	TELEMETRY_LOG_UINT(recs, "NumOfTaggedDisk", 
						tag_common->tc_ndisks_tagged);
	TELEMETRY_LOG_INT(recs, "IoctlCode", tag_common->tc_ioctl_cmd);
	TELEMETRY_LOG_INT(recs, "TagStatus", tag_error);
	TELEMETRY_LOG_INT(recs, "GlobalIoctlStatus", 
						tag_common->tc_ioctl_status);
	TELEMETRY_LOG_ULL(recs, "PrevTagEndTS", ctxt->tc_tel.tt_prev_tag_ts);
	TELEMETRY_LOG_ULL(recs, "PrevTagEndSeq", 
					ctxt->tc_tel.tt_prev_tag_seqno);
	TELEMETRY_LOG_WTIME(recs, "TagInsertTime", curtime);
	TELEMETRY_LOG_WTIME(recs, "TimeJumpDetectedTS", 
				          driver_ctx->dc_tel.dt_time_jump_exp);
	TELEMETRY_LOG_WTIME(recs, "TimeJumpedTS", 
				          driver_ctx->dc_tel.dt_time_jump_cur);
	TELEMETRY_LOG_STR(recs, "DiskIdentity", ctxt->tc_pname);
	TELEMETRY_LOG_STR(recs, "DiskName", ctxt->tc_guid);
	TELEMETRY_LOG_ULL(recs, "DiskBlendedState", state);
	TELEMETRY_LOG_ULL(recs, "TagState", 
					(inm_u64_t)ecTagStatusInsertFailure);

	/* Previous tag replication stats */
	stats = &ctxt->tc_tel.tt_prev_stats;

	TELEMETRY_LOG_WTIME(recs, "LastTagInsertTime", 
				     ctxt->tc_tel.tt_prev_tag_time);
	TELEMETRY_LOG_ULL(recs, "PendChgPrev", stats->ts_pending);
	TELEMETRY_LOG_ULL(recs, "ChurnPrev", stats->ts_tracked_bytes);       
	TELEMETRY_LOG_ULL(recs, "DrainDBCountPrev", stats->ts_getdb);
	TELEMETRY_LOG_ULL(recs, "RevertDBCountPrev", stats->ts_revertdb);
	TELEMETRY_LOG_ULL(recs, "CommitDBCountPrev", stats->ts_commitdb);
	TELEMETRY_LOG_ULL(recs, "DrainDataPrevInBytes", 
						stats->ts_drained_bytes);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt1Prev", stats->ts_nwlb1);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt2Prev", stats->ts_nwlb2);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt3Prev", stats->ts_nwlb3);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt4Prev", stats->ts_nwlb4);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt5Prev", stats->ts_nwlb5);
	TELEMETRY_LOG_ULL(recs, "CommitDbFailPrev", stats->ts_commitdb_failed);
	
	/* Current replication stats */
	/* Update the prev stats to current stats */
	ctxt->tc_tel.tt_prev_tag_time = curtime;
	telemetry_tag_stats_record(ctxt, stats); 
	
	TELEMETRY_LOG_ULL(recs, "PendChgOnInsert", stats->ts_pending);
	TELEMETRY_LOG_ULL(recs, "ChurnCurr", stats->ts_tracked_bytes);       
	TELEMETRY_LOG_ULL(recs, "DrainDBCountCurr", stats->ts_getdb);
	TELEMETRY_LOG_ULL(recs, "RevertDBCountCurr", stats->ts_revertdb);
	TELEMETRY_LOG_ULL(recs, "CommitDBCountCurr", stats->ts_commitdb);
	TELEMETRY_LOG_ULL(recs, "DrainDataCurr", stats->ts_drained_bytes);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt1Curr", stats->ts_nwlb1);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt2Curr", stats->ts_nwlb2);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt3Curr", stats->ts_nwlb3);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt4Curr", stats->ts_nwlb4);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt5Curr", stats->ts_nwlb5);
	TELEMETRY_LOG_ULL(recs, "CommitDbFailCurr", stats->ts_commitdb_failed);
	
	/* Prev successful tag stats */
	stats = &ctxt->tc_tel.tt_prev_succ_stats;

	TELEMETRY_LOG_ULL(recs, "PendChgToCmp", stats->ts_pending);
	TELEMETRY_LOG_ULL(recs, "ChurnToCmp", stats->ts_tracked_bytes);       
	TELEMETRY_LOG_ULL(recs, "DrainDBCountCmp", stats->ts_getdb);
	TELEMETRY_LOG_ULL(recs, "RevertDBCountCmp", stats->ts_revertdb);
	TELEMETRY_LOG_ULL(recs, "CommitDBCountCmp", stats->ts_commitdb);
	TELEMETRY_LOG_ULL(recs, "DrainDataToCmp", stats->ts_drained_bytes);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt1ToCmp", stats->ts_nwlb1);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt2ToCmp", stats->ts_nwlb2);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt3ToCmp", stats->ts_nwlb3);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt4ToCmp", stats->ts_nwlb4);
	TELEMETRY_LOG_ULL(recs, "NwLatBckt5ToCmp", stats->ts_nwlb5);
	TELEMETRY_LOG_ULL(recs, "CommitDbFailToCmp", 
						stats->ts_commitdb_failed);

	/* Generic info */
	state = telemetry_get_wostate(ctxt);

	TELEMETRY_LOG_WTIME(recs, "LastSuccessInsertTime", 
					ctxt->tc_tel.tt_prev_succ_tag_time);
	TELEMETRY_LOG_ULL(recs, "WoFlags", state);
	TELEMETRY_LOG_UL(recs, "CountWOSToMD", 
	ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateMetadata]);
	TELEMETRY_LOG_UL(recs, "CountWOSToMDUser",
	ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateMetadata]);
	TELEMETRY_LOG_UL(recs, "CountWOSToBitmap", 
	  ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateBitmap]);
	TELEMETRY_LOG_UL(recs, "CountWOSToBitmapUser", 
	 ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateBitmap]);
	TELEMETRY_LOG_WTIME(recs, "LastWoTime", 
				        ctxt->tc_stats.st_wostate_switch_time *
				        HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_ULL(recs, "MDChangesPending",
				        ctxt->tc_bytes_pending_md_changes); 
	TELEMETRY_LOG_WTIME(recs, "DiffSyncThrottleStartTS", 
				        ctxt->tc_tel.tt_ds_throttle_start);
	TELEMETRY_LOG_WTIME(recs, "DiffSyncThrottleEndTS", 
				        ctxt->tc_tel.tt_ds_throttle_stop);
	TELEMETRY_LOG_WTIME(recs, "FirstGetDbTimeOnDrainBlk", 0ULL);
	TELEMETRY_LOG_ULL(recs, "GetDbLatencyCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "WaitDbLatencyCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "DispatchIrpCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "PageFileIoCnt", 0ULL);
	TELEMETRY_LOG_ULL(recs, "NullFileObjCnt", 0ULL);

  	/* Non WO State stats */
	nwo = &ctxt->tc_tel.tt_nwo;
	state = telemetry_md_capture_reason(ctxt);

	TELEMETRY_LOG_UINT(recs, "NonWoSReason", nwo->nws_reason);
	TELEMETRY_LOG_ULL(recs, "MetaDataCaptureReason", state);
	TELEMETRY_LOG_ULL(recs, "DiskStatusFlagsNonWo", nwo->nws_blend);
	TELEMETRY_LOG_UINT(recs, "NonPagePoolAlloc", nwo->nws_np_alloc);
	TELEMETRY_LOG_WTIME(recs, "LastNPLimitHitTime", 
						nwo->nws_np_limit_time);
	TELEMETRY_LOG_UINT(recs, "NonPagePoolAllocFail", 
						nwo->nws_np_alloc_fail);
	TELEMETRY_LOG_UINT(recs, "MemAllocDevCntxt", nwo->nws_mem_alloc);
	TELEMETRY_LOG_UINT(recs, "MemResDevCntxt", nwo->nws_mem_reserved);
	TELEMETRY_LOG_UINT(recs, "MemFreeDevCntxt", nwo->nws_mem_free);
	TELEMETRY_LOG_UINT(recs, "GlobalFreeDbCount", nwo->nws_free_cn);
	TELEMETRY_LOG_UINT(recs, "GlobalLockedDbCount", nwo->nws_used_cn);
	TELEMETRY_LOG_UINT(recs, "MaxLockedDb", nwo->nws_max_used_cn);
	TELEMETRY_LOG_UINT(recs, "NewWoState", nwo->nws_new_state);
	TELEMETRY_LOG_UINT(recs, "OldStateDuration", nwo->nws_nwo_secs);
	TELEMETRY_LOG_WTIME(recs, "SysTimeAtWOSChange", nwo->nws_change_time);

	/* Generic info */
	TELEMETRY_LOG_UINT(recs, "LastResyncError", 
						ctxt->tc_hist.ths_osync_err);
	TELEMETRY_LOG_WTIME(recs, "LastResyncTime",ctxt->tc_hist.ths_osync_ts *
				                HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_WTIME(recs, "ResyncStartTime", 
						ctxt->tc_tel.tt_resync_start);
	TELEMETRY_LOG_WTIME(recs, "ResyncEndTime", ctxt->tc_tel.tt_resync_end);
	TELEMETRY_LOG_WTIME(recs, "ClearDiffTime", 
					ctxt->tc_hist.ths_clrdiff_ts *
				        HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_WTIME(recs, "StartFilterKrnlTime", 
				        ctxt->tc_hist.ths_start_flt_ts *
				        HUNDREDS_OF_NANOSEC_IN_SECOND);
	TELEMETRY_LOG_WTIME(recs, "DevCntxtCreateTime", 
						ctxt->tc_tel.tt_create_time);
	TELEMETRY_LOG_WTIME(recs, "LastDrainDbTime", 
						ctxt->tc_tel.tt_getdb_time);
	TELEMETRY_LOG_WTIME(recs, "LastCommitDbTime", 
						ctxt->tc_tel.tt_commitdb_time);
	TELEMETRY_LOG_WTIME(recs, "DrvLoadTime", 
					driver_ctx->dc_tel.dt_drv_load_time);
	TELEMETRY_LOG_UINT(recs, "DevContextFlags", ctxt->tc_flags);
	TELEMETRY_LOG_WTIME(recs, "LastS2Start",
				        driver_ctx->dc_tel.dt_s2_start_time);
	TELEMETRY_LOG_WTIME(recs, "LastS2Stop", 
					driver_ctx->dc_tel.dt_s2_stop_time);
	TELEMETRY_LOG_WTIME(recs, "LastSVStart", 
				     driver_ctx->dc_tel.dt_svagent_start_time);
	TELEMETRY_LOG_WTIME(recs, "LastSVStop", 
				      driver_ctx->dc_tel.dt_svagent_stop_time);
	TELEMETRY_LOG_UINT(recs, "MemAllocFailCount", 
				      driver_ctx->stats.num_malloc_fails);
	TELEMETRY_LOG_UINT(recs, "MessageType", 
					msg | TELEMETRY_LINUX_MSG_TYPE);

	error = telemetry_log_end(recs);

out:
	return error;
}

inm_s32_t
telemetry_log_ioctl_failure(tag_telemetry_common_t *tag_common,
				inm_s32_t tag_error, etMessageType msg)
{
	inm_s32_t error = 0;
	inm_u64_t state = 0;
	inm_list_head_t rec_list;
	inm_list_head_t *recs = &rec_list;
	exception_buf_t *excbuf = NULL;
	
	if (!tag_common)
		goto out;

	error = telemetry_log_start(recs, IN_IOCTL_PATH);
	if (error)
		goto out;

	excbuf = telemetry_get_exception();
	TELEMETRY_LOG_STR(recs, "CustomJson", excbuf->eb_buf);
	telemetry_put_exception(excbuf);

	state = telemetry_get_dbs(NULL, ecTagStatusIOCTLFailure, 
							ecNotApplicable);

	TELEMETRY_LOG_WTIME(recs, "TagRqstTime", tag_common->tc_req_time);
	TELEMETRY_LOG_UINT(recs, "TagType", tag_common->tc_type);
	TELEMETRY_LOG_STR(recs, "TagMarkerGUID", tag_common->tc_guid);
	TELEMETRY_LOG_UINT(recs, "NumOfTotalDisk", tag_common->tc_ndisks);
	TELEMETRY_LOG_UINT(recs, "NumOfProtectdDisk", 
						tag_common->tc_ndisks_prot);
	TELEMETRY_LOG_UINT(recs, "NumOfTaggedDisk", 
						tag_common->tc_ndisks_tagged);
	TELEMETRY_LOG_INT(recs, "IoctlCode", tag_common->tc_ioctl_cmd);
	TELEMETRY_LOG_INT(recs, "GlobalIoctlStatus", tag_error);
	TELEMETRY_LOG_WTIME(recs, "TimeJumpDetectedTS", 
				          driver_ctx->dc_tel.dt_time_jump_exp);
	TELEMETRY_LOG_WTIME(recs, "TimeJumpedTS", 
				          driver_ctx->dc_tel.dt_time_jump_cur);
	TELEMETRY_LOG_ULL(recs, "DiskBlendedState", state);
	TELEMETRY_LOG_ULL(recs, "TagState", 
					(inm_u64_t)ecTagStatusIOCTLFailure);
	TELEMETRY_LOG_UINT(recs, "MessageType", 
					msg | TELEMETRY_LINUX_MSG_TYPE);
	
	error = telemetry_log_end(recs);

out:
	return error;
}

#ifdef INM_FLT_TEST

/* Need some space for prefix and suffix */
char tbuf[TELEMETRY_REC_BUF_SIZE - 1024];
#define TELEMETRY_TEST_PAGES    3

/*
 * This test is intended to run without any protections 
 * enabled and on driver load
 */
void
telemetry_log_multi_page_test(void)
{
	inm_s32_t error = 0;
	inm_list_head_t rec_list;
	inm_list_head_t *recs = &rec_list;
	char x = 'a';
	int i = TELEMETRY_TEST_PAGES;

	driver_ctx->total_prot_volumes = 1;

	error = telemetry_log_start(recs);
	if (error)
		goto out;

	while (i--) {
		memset(tbuf, x++, sizeof(tbuf) - 1); 
		tbuf[sizeof(tbuf) - 1] = '\0';
		TELEMETRY_LOG_STR(recs, "KEY", tbuf);
	}

	error = telemetry_log_end(recs);

	driver_ctx->total_prot_volumes = 0;

	telemetry_offload_flush_to_worker();

out:
	return;
}
	
#endif

void
telemetry_shutdown(void)
{
	if (!tel_init) {
		err("Telemetry not initialized");
		INM_BUG_ON(!tel_init);
		return;
	}

	/* 
	 * dont allow any further timers
	 */
	tel_shutdown = 1;
	/* 
	 * Force a timeout which should queue all pending writes
	 * to worker thread 
	 */
	force_timeout(&tel_timer);
	/* 
	 * If timer was not started while force timeout was called, 
	 * explicitly queue all pending
	 */
	telemetry_offload_flush_to_worker();
}

inm_s32_t
telemetry_init(void)
{
	int error = 0;

	INM_INIT_LIST_HEAD(&tel_list);
	INM_INIT_SEM(&tel_mutex);
	INM_INIT_SPIN_LOCK(&tel_slock);
	tel_shutdown = 0;

	tel_wqe = alloc_work_queue_entry(INM_KM_SLEEP);
	if (!tel_wqe) {
		err("Error allocating telemetry work queue entry");
		error = -ENOMEM;
		goto out;
	}

	if (!get_path_memory(&tel_fname)) {
		err("Error allocating telemetry file name buffer");
		put_work_queue_entry(tel_wqe);
		error = -ENOMEM;
		goto out;
	}

	start_tel_timer();

	info("involflt telemetry initialsed");

	tel_init = 1;

#ifdef INM_FLT_TEST
	telemetry_log_multi_page_test();
#endif

out:
	return error;
}
#else
inm_s32_t
telemetry_log_tag_history(change_node_t *chg_node, 
				          target_context_t *ctxt,
				          etTagStatus status, 
				          etTagStateTriggerReason reason, 
				          etMessageType msg)
{

	return 0;
}

inm_s32_t
telemetry_log_tag_failure(target_context_t *ctxt, 
				          tag_telemetry_common_t *tag_common,
				          inm_s32_t tag_error,
				          etMessageType msg)
{
	return 0;
}

inm_s32_t
telemetry_log_ioctl_failure(tag_telemetry_common_t *tag_common,
				inm_s32_t tag_error, etMessageType msg)
{
	return 0;
}

void
telemetry_shutdown(void)
{
	return;
}

inm_s32_t
telemetry_init(void)
{
	return 0;
}
#endif

