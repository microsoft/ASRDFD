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
 * File       : db_routines.c
 *
 * Description: This file contains data mode implementation of the
 *              filter driver.
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
#include "errlog.h"
#include "work_queue.h"
#include "db_routines.h"
#include "tunable_params.h"
#include "filter_host.h"
#include "telemetry-types.h"
#include "telemetry.h"

extern driver_context_t *driver_ctx;

char *ErrorToRegErrorDescriptionsA[ERROR_TO_REG_MAX_ERROR + 1] = {
	"--%#x--",
	"Out of NonPagedPool for dirty blocks %#x",
	"Bit map read failed with Status %#x",
	"Bit map write failed with Status %#x",
	"Bit map open failed with Status %#x",
	"Bit map open failed and could not write changes %#x",
	"Out Of Bound IO on source volume with Status %#x",
	"The I/O is spanning across multiple partitions/volumes %#x",
	"See server message log for errors %#x",
	"Out of memory while allocating work queue item. Status %#x",
	"Write via IO control path - format/label change %#x",
	"Vendor specific CDB error Status:%#x",
	"Forced resync due to error injection Status:%#x",
	"AT IO error %#x",
	"AT device list is bad. Status:%#x",
	"Out of memory while allocating IO info structure %#x",
	"New path added to source device(s) %#x",
	"System crashed or not cleanly shutdown %#x",
	"PT IO cancel failed %#x",
	"Out of order issue detected on source %#x",
	"I/O is greater than 64MB in metadata mode %#x",
	"Bitmap device object not found %#x",
	"Failed to learn bitmap header blkmap %#x",
	"Failed to flush changes to bitmap file %#x",
	"Failed to protect root disk in initrd %#x"
};


inm_s32_t set_volume_out_of_sync(target_context_t *vcptr,
			   inm_u64_t out_of_sync_error_code,
			   inm_s32_t status_to_log)
{
	
	inm_s32_t _rc = 0;
	inm_s32_t flag = TRUE;
	TIME_STAMP_TAG_V2 time_stamp;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!vcptr) 
		return -EINVAL;

	if ((vcptr->tc_flags & VCF_IGNORE_BITMAP_CREATION) &&
		(LINVOLFLT_ERR_BITMAP_FILE_CREATED == out_of_sync_error_code))
		return _rc;

	if (INM_IN_INTERRUPT()) {
		_rc = queue_worker_routine_for_set_volume_out_of_sync(vcptr, 
				out_of_sync_error_code, status_to_log);
		return _rc;
	}

	if (out_of_sync_error_code == LINVOLFLT_ERR_LOST_SYNC_SYSTEM_CRASHED) {
		out_of_sync_error_code = ERROR_TO_REG_UNCLEAN_SYS_SHUTDOWN;
	}

	err("Resync Required (%s -> %s): %llu, %d, %d, %llu", 
		vcptr->tc_pname, vcptr->tc_guid, 
		out_of_sync_error_code, status_to_log, 
		vcptr->tc_flags & VCF_IGNORE_BITMAP_CREATION,
		vcptr->tc_out_of_sync_time_stamp);

	telemetry_set_dbs(&vcptr->tc_tel.tt_blend, DBS_DRIVER_RESYNC_REQUIRED);

	vcptr->tc_resync_required = TRUE;
	vcptr->tc_out_of_sync_err_code = out_of_sync_error_code;
	vcptr->tc_nr_out_of_sync++;
	get_time_stamp_tag(&time_stamp);
	vcptr->tc_out_of_sync_time_stamp = 
				time_stamp.TimeInHundNanoSecondsFromJan1601;
	vcptr->tc_out_of_sync_err_status = status_to_log;
	vcptr->tc_hist.ths_nr_osyncs++;
	vcptr->tc_hist.ths_osync_err = out_of_sync_error_code;
	vcptr->tc_hist.ths_osync_ts = vcptr->tc_out_of_sync_time_stamp;
	INM_DO_DIV(vcptr->tc_hist.ths_osync_ts, HUNDREDS_OF_NANOSEC_IN_SECOND);

	set_int_vol_attr(vcptr, VolumeResyncRequired, flag);
	set_int_vol_attr(vcptr, VolumeOutOfSyncErrorCode, 
					vcptr->tc_out_of_sync_err_code);
	set_int_vol_attr(vcptr, VolumeOutOfSyncErrorStatus, status_to_log);
	set_int_vol_attr(vcptr, VolumeOutOfSyncCount, 
					vcptr->tc_nr_out_of_sync);
	set_longlong_vol_attr(vcptr, VolumeOutOfSyncTimestamp, 
					vcptr->tc_out_of_sync_time_stamp);
	if (vcptr->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
	volume_lock(vcptr);
		vcptr->tc_flags |= VCF_MIRRORING_PAUSED;
	volume_unlock(vcptr);
		INM_WAKEUP(&(((host_dev_ctx_t *)(vcptr->tc_priv))->resync_notify));
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return _rc;
}

void set_volume_out_of_sync_worker_routine(wqentry_t *wqe) {
	target_context_t *vcptr = NULL;
	inm_s64_t out_of_sync_error_code = INM_EINVAL;
	inm_s32_t status = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!wqe) {
		info("\n invalid work queue entry \n");
		return;
	}


	vcptr = (target_context_t *) wqe->context;
	out_of_sync_error_code = wqe->extra1;
	status = wqe->extra2;
	put_work_queue_entry(wqe);

	set_volume_out_of_sync(vcptr, out_of_sync_error_code, status);
	put_tgt_ctxt(vcptr);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return;
}

inm_s32_t queue_worker_routine_for_set_volume_out_of_sync(target_context_t *vcptr,
			    int64_t out_of_sync_error_code, inm_s32_t status)
{
	wqentry_t *wqe = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!vcptr) {
		return -EINVAL;
	}

	vcptr->tc_resync_required = TRUE;
	vcptr->tc_out_of_sync_err_code = out_of_sync_error_code;
	vcptr->tc_nr_out_of_sync++;

	wqe = alloc_work_queue_entry(INM_KM_NOSLEEP);
	if (!wqe) {
		telemetry_set_dbs(&vcptr->tc_tel.tt_blend, DBS_DRIVER_RESYNC_REQUIRED);
		info("failed to allocate work queue entry\n");
		return -ENOMEM;
	}

	get_tgt_ctxt(vcptr);
	wqe->context = vcptr;
	wqe->extra1 = out_of_sync_error_code;
	wqe->extra2 = status;
	wqe->work_func = set_volume_out_of_sync_worker_routine;
		
	add_item_to_work_queue(&driver_ctx->wqueue , wqe);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
	return 0;
}

inm_s32_t stop_filtering_device(target_context_t *vcptr, 
		inm_s32_t lock_acquired, volume_bitmap_t **vbmap_ptr)
{
	inm_s32_t status = 0;
	volume_bitmap_t *vbmap = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!vcptr) {
		info("vcptr is null");
		return -EINVAL;
	}

	if (!lock_acquired)
		volume_lock(vcptr);

	if(vcptr->tc_filtering_disable_required)
		vcptr->tc_flags |= VCF_FILTERING_STOPPED;

	get_time_stamp(&(vcptr->tc_tel.tt_stop_flt_time)); 
	
	vbmap = vcptr->tc_bp->volume_bitmap;
	
	vcptr->tc_bp->volume_bitmap = NULL;

	set_tgt_ctxt_wostate(vcptr, ecWriteOrderStateUnInitialized, FALSE,
					ecWOSChangeReasonUnInitialized);

	vcptr->tc_prev_mode = FLT_MODE_UNINITIALIZED;
	vcptr->tc_cur_mode = FLT_MODE_UNINITIALIZED;
	vcptr->tc_prev_wostate = ecWriteOrderStateUnInitialized;
	vcptr->tc_cur_wostate = ecWriteOrderStateUnInitialized;

	if (!lock_acquired)
		volume_unlock(vcptr);

	if (vbmap) {
		if (!lock_acquired) {
			close_bitmap_file(vbmap, TRUE);
		} else {
			if (vbmap_ptr)
				*vbmap_ptr = vbmap;
		}
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}

void orphandata_and_move_commit_pending_changenode_to_main_queue(target_context_t *vcptr)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!vcptr) {
		info("vcptr is null");
		return;
	}

	if (!vcptr->tc_pending_confirm) {
		dbg("pending_confirm is null ");
		return;
	}

	vcptr->tc_pending_confirm = NULL;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

void
add_resync_required_flag(UDIRTY_BLOCK_V2 *udb, target_context_t *vcptr)
{
	unsigned long sync_err = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!vcptr) {
		info("vcptr is null");
		return;
	}
	INM_DOWN(&vcptr->tc_resync_sem);

	if (vcptr->tc_resync_required) {
		vcptr->tc_resync_indicated = TRUE;
		vcptr->tc_nr_out_of_sync_indicated = vcptr->tc_nr_out_of_sync;
		udb->uHdr.Hdr.ulFlags |= UDIRTY_BLOCK_FLAG_VOLUME_RESYNC_REQUIRED;
		udb->uHdr.Hdr.ulOutOfSyncCount = vcptr->tc_nr_out_of_sync;
		udb->uHdr.Hdr.liOutOfSyncTimeStamp = vcptr->tc_out_of_sync_time_stamp;
		udb->uHdr.Hdr.ulOutOfSyncErrorCode = vcptr->tc_out_of_sync_err_code;

		sync_err = vcptr->tc_out_of_sync_err_code;

		if (sync_err > (ERROR_TO_REG_MAX_ERROR)) {
			sync_err = ERROR_TO_REG_DESCRIPTION_IN_EVENT_LOG;
	}

	snprintf((char *)&udb->uHdr.Hdr.ErrorStringForResync[0],
				UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE,
				ErrorToRegErrorDescriptionsA[sync_err],
				vcptr->tc_out_of_sync_err_status);
		dbg("Resync error string:%s", (char *)&udb->uHdr.Hdr.ErrorStringForResync);
	} else {
		udb->uHdr.Hdr.ErrorStringForResync[0]='\0';
	}
	INM_UP(&vcptr->tc_resync_sem);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}


void reset_volume_out_of_sync(target_context_t *vcptr) {

	inm_s32_t nil=0;
	inm_s32_t null_str[]={0};

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (vcptr && !vcptr->tc_resync_required)
		return;

	INM_DOWN(&vcptr->tc_resync_sem);

	if (vcptr->tc_nr_out_of_sync_indicated >= vcptr->tc_nr_out_of_sync) {
		/* No resync was set between resync indication and acking the resync action */
		telemetry_clear_dbs(&vcptr->tc_tel.tt_blend,
						DBS_DRIVER_RESYNC_REQUIRED);
		vcptr->tc_resync_required = FALSE;
		vcptr->tc_nr_out_of_sync = 0;
		vcptr->tc_out_of_sync_time_stamp = 0;
		vcptr->tc_out_of_sync_err_code = 0;
		vcptr->tc_out_of_sync_err_status = 0;

		set_int_vol_attr(vcptr, VolumeResyncRequired, 
					vcptr->tc_resync_required);
		set_int_vol_attr(vcptr, VolumeOutOfSyncErrorCode, 
					vcptr->tc_out_of_sync_err_code);
		set_int_vol_attr(vcptr, VolumeOutOfSyncErrorStatus, 
					vcptr->tc_out_of_sync_err_status);
		set_int_vol_attr(vcptr, VolumeOutOfSyncCount, 
					vcptr->tc_nr_out_of_sync);
		set_string_vol_attr(vcptr, VolumeOutOfSyncErrorDescription, 
					(char *)null_str);
		set_int_vol_attr(vcptr, VolumeOutOfSyncTimestamp, nil);
	} else {
		vcptr->tc_nr_out_of_sync -= vcptr->tc_nr_out_of_sync_indicated;
		set_int_vol_attr(vcptr, VolumeOutOfSyncCount, 
					vcptr->tc_nr_out_of_sync);
	}
	 
	vcptr->tc_resync_indicated = FALSE;
	INM_UP(&vcptr->tc_resync_sem);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return;
}
