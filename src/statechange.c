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
#include "filter_host.h"
#include "statechange.h"

extern driver_context_t *driver_ctx;

#define SERVICE_STATE_CHAGNE_THREAD_TIMEOUT     1000 /*  clock ticks */

inm_s32_t create_service_thread()
{
	
	inm_pid_t pid;
	inm_s32_t err = 0;

	INM_INIT_COMPLETION(&driver_ctx->service_thread._completion);
	/* notificaions for new event */
	INM_INIT_COMPLETION(&driver_ctx->service_thread._new_event_completion);
	driver_ctx->service_state = SERVICE_NOTSTARTED;
	INM_INIT_WAITQUEUE_HEAD(&driver_ctx->service_thread.wakeup_event);
	INM_INIT_WAITQUEUE_HEAD(&driver_ctx->service_thread.shutdown_event);

	INM_ATOMIC_SET(&driver_ctx->service_thread.wakeup_event_raised, 0);
	INM_ATOMIC_SET(&driver_ctx->service_thread.shutdown_event_raised, 0);

#ifdef INM_LINUX
	pid = INM_KERNEL_THREAD(service_thread_task, 
			service_state_change_thread, NULL, 0, "inmsvcd");
#else
	pid = INM_KERNEL_THREAD(service_state_change_thread, NULL, 0, 
								"inmsvcd");
#endif
	if (pid >= 0) {
		info("kernel thread with pid = %d has created", pid);
		driver_ctx->service_thread.initialized = 1;
	}
	
	err = (driver_ctx->service_thread.initialized == 0) ? 1 : 0;    

	return err;
}

void destroy_service_thread()
{

	if (driver_ctx->service_thread.initialized)
	{
		driver_ctx->flags |= DC_FLAGS_SERVICE_STATE_CHANGED;
		INM_ATOMIC_INC(&driver_ctx->service_thread.shutdown_event_raised);
		INM_WAKEUP(&driver_ctx->service_thread.shutdown_event);
		INM_COMPLETE(&driver_ctx->service_thread._new_event_completion);
		INM_WAIT_FOR_COMPLETION(&driver_ctx->service_thread._completion);     
		INM_KTHREAD_STOP(service_thread_task);

		INM_DESTROY_COMPLETION(&driver_ctx->service_thread._completion);
		INM_DESTROY_COMPLETION(&driver_ctx->service_thread._new_event_completion);
		driver_ctx->service_thread.initialized = 0;
	}
}

inm_s32_t process_volume_state_change(target_context_t *tgt_ctxt, 
		struct inm_list_head *lhptr, inm_s32_t statechanged)
{

	inm_s32_t success = 1;
	inm_s32_t work_item_type = 0;
	inm_s32_t open_bitmap = FALSE;

#define vcptr     tgt_ctxt

	dbg("In process_volume_state_change() volume:%s\n",tgt_ctxt->tc_guid);
	if (tgt_ctxt->tc_dev_state == DEVICE_STATE_OFFLINE) {
		dbg("process_volume_state_change():: device marked OFFLINE \n");
		INM_BUG_ON(1);

		success = add_vc_workitem_to_list(WITEM_TYPE_VOLUME_UNLOAD, 
							tgt_ctxt, 0, 0, lhptr);
		dbg("Added target context work item ... \n");        
		remove_tc_from_dc(tgt_ctxt);

		return success;
	}

#define __IS_FLAG_SET(_flag)    (vcptr->tc_flags & (_flag))
	if (__IS_FLAG_SET(VCF_FILTERING_STOPPED))
		return success;

	/* CASE 1: bitmap file has to be opened */
	if (__IS_FLAG_SET(VCF_OPEN_BITMAP_REQUESTED)) {
		success = add_vc_workitem_to_list(WITEM_TYPE_OPEN_BITMAP,
					               vcptr, 0, FALSE, lhptr);
		if (!success)
			return success;
	}
	 
	/* CASE 2: check for GUID */
	if (__IS_FLAG_SET(VCF_GUID_OBTAINED)) {
	/* No GUID ?? then No bitmap */
		return success;
	}
	 
#define _HIGH_WATER_MARK(_state)    \
		driver_ctx->tunable_params.db_high_water_marks[(_state)]
#define _LOW_WATER_MARK            \
		driver_ctx->tunable_params.db_low_water_mark_while_service_running
	switch (driver_ctx->service_state) {

	case SERVICE_NOTSTARTED:
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			info("service has not started \n");
		}
		if (_HIGH_WATER_MARK(SERVICE_NOTSTARTED) && 
			!__IS_FLAG_SET(VCF_BITMAP_WRITE_DISABLED) &&
			(vcptr->tc_pending_changes >= 
			 	_HIGH_WATER_MARK(SERVICE_NOTSTARTED))) {
			
			work_item_type = WITEM_TYPE_BITMAP_WRITE;
			open_bitmap = TRUE;
		}
		break;
		
	case SERVICE_RUNNING: 
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			info("SERVICE_RUNNING");
		}
		/* RANGE 1:     service state changed 
		 *        LOW_WATER_MARK exists
		 *        change pending < LOW_WATER_MARK
		 **/
		if (statechanged && _LOW_WATER_MARK &&
		!__IS_FLAG_SET(VCF_BITMAP_READ_DISABLED) &&
		(vcptr->tc_pending_changes < _LOW_WATER_MARK)) {

			work_item_type = WITEM_TYPE_START_BITMAP_READ;
			open_bitmap = TRUE;
			break;
		} 

		/* RANGE 2:     HIGH_WATER_MARK exist
		 *        enabled BITMAP WRITE
		 *        Number of metadata changes  >= HIGH_WATER_MARK changes
		 **/
		if (_HIGH_WATER_MARK(SERVICE_RUNNING) &&
			!__IS_FLAG_SET(VCF_BITMAP_WRITE_DISABLED) &&
			(vcptr->tc_pending_md_changes >= 
			_HIGH_WATER_MARK(SERVICE_RUNNING))) {

			work_item_type = WITEM_TYPE_BITMAP_WRITE;
			open_bitmap = TRUE;
			break;
		}

		/* RANGE 3:     LOW_WATER_MARK exist
		 *        enabled BITMAP READ
		 *        change pending < LOW_WATER_MARK
		 **/
		if (_LOW_WATER_MARK && 
			!__IS_FLAG_SET(VCF_BITMAP_READ_DISABLED) &&
			(vcptr->tc_pending_changes < _LOW_WATER_MARK)) {
		

			if (!vcptr->tc_bp->volume_bitmap) {
				work_item_type = WITEM_TYPE_START_BITMAP_READ;
				open_bitmap = TRUE;
			} else {
				switch (vcptr->tc_bp->volume_bitmap->eVBitmapState) {
				case ecVBitmapStateOpened:
				case ecVBitmapStateAddingChanges:
					work_item_type = 
						WITEM_TYPE_START_BITMAP_READ;
					open_bitmap = FALSE;
					break;
				case ecVBitmapStateReadPaused:
					work_item_type = 
						WITEM_TYPE_CONTINUE_BITMAP_READ;
					open_bitmap = FALSE;
				default:
					break;
				}
			}
		}
		break;

	case SERVICE_SHUTDOWN:
		/* service is shutdown, move all pending changes to bitmap */
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			info("SERVICE_SHUTDOWN ");
		}
		if (statechanged) {
			if (vcptr->tc_cur_wostate != 
						ecWriteOrderStateRawBitmap)
				set_tgt_ctxt_wostate(vcptr, 
					ecWriteOrderStateBitmap, TRUE,
					eCWOSChangeReasonServiceShutdown);
			if (!__IS_FLAG_SET(VCF_BITMAP_WRITE_DISABLED)) {
				work_item_type = WITEM_TYPE_BITMAP_WRITE;
				open_bitmap = TRUE;
			}
			break;
		}

		if (_HIGH_WATER_MARK(SERVICE_SHUTDOWN) &&
			!__IS_FLAG_SET(VCF_BITMAP_WRITE_DISABLED) &&
			(vcptr->tc_pending_changes >= 
			 		_HIGH_WATER_MARK(SERVICE_SHUTDOWN))) {
		
			work_item_type = WITEM_TYPE_BITMAP_WRITE;
			open_bitmap = TRUE;
			break;
		}
		break;

	default:
		INM_BUG_ON(0);
		break;
	}

	if (work_item_type != WITEM_TYPE_UNINITIALIZED) {
		success = add_vc_workitem_to_list(work_item_type, vcptr, 0,
				                      open_bitmap, lhptr);
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			info("work item queued ");
		}
	}
	return success;
}

int service_state_change_thread(void *context)
{

	long timeout_val = SERVICE_STATE_CHAGNE_THREAD_TIMEOUT;
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	target_context_t *tgt_ctxt = NULL;
	inm_s32_t service_state_changed = 0;
	struct inm_list_head workq_list_head;
	wqentry_t *wqeptr = NULL;
	inm_s32_t shutdown_event, wakeup_event;
	   
	INM_DAEMONIZE("inmsvcd");
	INM_INIT_LIST_HEAD(&workq_list_head);

	while (1) {

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("waiting for new event completion in service thread \n");
	}

	INM_WAIT_FOR_COMPLETION_INTERRUPTIBLE(&driver_ctx->service_thread._new_event_completion);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("service thread received new event completion notification \n");
	}

	wakeup_event = INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(
		driver_ctx->service_thread.wakeup_event,
		INM_ATOMIC_READ(&driver_ctx->service_thread.wakeup_event_raised),
		timeout_val);

	shutdown_event = !wakeup_event &&
		INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(
		driver_ctx->service_thread.shutdown_event,
		INM_ATOMIC_READ(&driver_ctx->service_thread.shutdown_event_raised),
		timeout_val);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("looping in service thread\n");
	}

	if (shutdown_event) {
		INM_ATOMIC_DEC(&driver_ctx->service_thread.shutdown_event_raised);
		info("shutdown event is received by service thread");
		break;
	}
	if (!wakeup_event) {
		info(" wakeup event is not received ");
		continue;
	}

	INM_ATOMIC_DEC(&driver_ctx->service_thread.wakeup_event_raised);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("received wakeup event in service thread\n");
	}

	if (driver_ctx->sys_shutdown) {
		wqentry_t *wqe = NULL;
			   
		wqe = alloc_work_queue_entry(INM_KM_SLEEP);
		wqe->witem_type =  WITEM_TYPE_SYSTEM_SHUTDOWN;
		add_item_to_work_queue(&driver_ctx->wqueue, wqe);
	}

	INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	service_state_changed = 
		(driver_ctx->flags & DC_FLAGS_SERVICE_STATE_CHANGED);

	if (service_state_changed) {
		driver_ctx->flags &= ~DC_FLAGS_SERVICE_STATE_CHANGED;
	}

	inm_list_for_each_safe(ptr, nextptr,  &driver_ctx->tgt_list) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if(tgt_ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)){
			tgt_ctxt = NULL;
			continue;
		}

		volume_lock(tgt_ctxt);
		if (tgt_ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP) {
			dbg("call process_volume_state_change ctx %p\n", 
								tgt_ctxt);
			process_volume_state_change(tgt_ctxt,
							&workq_list_head,
					                service_state_changed);
		}
		volume_unlock(tgt_ctxt);
	}
	INM_UP_WRITE(&driver_ctx->tgt_list_sem);

	inm_list_for_each_safe(ptr, nextptr,  &workq_list_head) {
		wqeptr = inm_list_entry(ptr, wqentry_t, list_entry);
		inm_list_del(&wqeptr->list_entry);
		process_vcontext_work_items(wqeptr);
		put_work_queue_entry(wqeptr);
	}
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("received shutdown event in service thread\n");
	}
	INM_COMPLETE_AND_EXIT(&driver_ctx->service_thread._completion, 0);
	return 0;
}
