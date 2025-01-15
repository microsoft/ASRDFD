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
#include "file-io.h"
#include "iobuffer.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "bitmap_api.h"
#include "VBitmap.h"
#include "work_queue.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "driver-context.h"
#include "tunable_params.h"

#define WORKER_THREAD_TIMEOUT 1000 /* clock ticks */

extern driver_context_t *driver_ctx;
static inm_s32_t reorg_datapool(inm_u32_t);
static int reorganize_datapool(void);
#ifdef INM_LINUX
extern inm_s32_t driver_state;
#endif

int 
timer_worker(void *context)
{
	workq_t *work_q = &driver_ctx->dc_tqueue;
	long timeout_val = WORKER_THREAD_TIMEOUT;
	inm_irqflag_t lock_flag = 0;
	struct inm_list_head workq_list_head;
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	wqentry_t *wqeptr = NULL;
	inm_s32_t shutdown_event, wakeup_event;
	
	INM_DAEMONIZE("inmtmrd");
	
	timeout_val = INM_MSECS_TO_JIFFIES(INM_MSEC_PER_SEC);
	
	while (1) {
		dbg("Sleeping");
		INM_WAIT_FOR_COMPLETION_INTERRUPTIBLE(&work_q->new_event_completion);
		dbg("Awoken");
		INM_INIT_LIST_HEAD(&workq_list_head);

		wakeup_event = 
			INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(work_q->wakeup_event,
					   INM_ATOMIC_READ(&work_q->wakeup_event_raised),
					   timeout_val);            

		shutdown_event = (wakeup_event == 0) &&
			INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(work_q->shutdown_event,
					   INM_ATOMIC_READ(&work_q->shutdown_event_raised),
					   INM_MSECS_TO_JIFFIES(5));

		if (shutdown_event > 0) {
			dbg("Recieved shutdown event");
			INM_ATOMIC_DEC(&work_q->shutdown_event_raised);
			work_q->flags |= WQ_FLAGS_THREAD_SHUTDOWN;
			break;
		}

		if (wakeup_event) {
			dbg("Recieved wakeup for timer");
			INM_ATOMIC_DEC(&work_q->wakeup_event_raised);
			INM_SPIN_LOCK_IRQSAVE(&work_q->lock, lock_flag);
			inm_list_replace_init(&work_q->worker_queue_head, 
			                       &workq_list_head);
			INM_SPIN_UNLOCK_IRQRESTORE(&work_q->lock, lock_flag);

		  	inm_list_for_each_safe(ptr, nextptr, &workq_list_head) {
				wqeptr = inm_list_entry(ptr, wqentry_t, list_entry);
				if (wqeptr->flags & WITEM_TYPE_TIMEOUT) {
					inm_list_del_init(ptr);
					if (wqeptr && wqeptr->work_func)
						wqeptr->work_func(wqeptr);
					else
						dbg("timeout without work item");
				} else {
					err("unknown wqe type : %u", wqeptr->flags);
					INM_BUG_ON(!(wqeptr->flags & WITEM_TYPE_TIMEOUT));
				}
			}
		} 
	}

	dbg("Timer thread dying");
	INM_COMPLETE_AND_EXIT(&work_q->worker_thread_completion, 0); 
}

inm_s32_t init_work_queue(workq_t *work_q, int (*worker_thread_function)(void *))
{
	inm_pid_t pid;
	inm_s32_t err = 0;
	struct task_struct *thread_task = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (work_q == NULL)
		return -ENOMEM;

	INM_MEM_ZERO(work_q, sizeof(*work_q));

	INM_INIT_SPIN_LOCK(&work_q->lock);
	INM_INIT_LIST_HEAD(&work_q->worker_queue_head);
	INM_INIT_WAITQUEUE_HEAD(&work_q->wakeup_event);
	INM_INIT_WAITQUEUE_HEAD(&work_q->shutdown_event);
	INM_ATOMIC_SET(&work_q->wakeup_event_raised, 0);
	INM_ATOMIC_SET(&work_q->shutdown_event_raised, 0);
	INM_INIT_COMPLETION(&work_q->worker_thread_completion);
	INM_INIT_COMPLETION(&work_q->new_event_completion);

	if (worker_thread_function == NULL)
		worker_thread_function = generic_worker_thread_function;
	
	work_q->worker_thread_routine = worker_thread_function;

#ifdef INM_LINUX
	pid = INM_KERNEL_THREAD(thread_task, worker_thread_function, work_q, sizeof(work_q), "inmwrkrd");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	work_q->task = thread_task;
#endif
#else
	pid = INM_KERNEL_THREAD(worker_thread_function, work_q, sizeof(work_q), "inmwrkrd");
#endif
	if (pid >= 0) {
		info ("worker thread with pid = %d  has created", pid);
		work_q->worker_thread_initialized = 1;
		INM_COMPLETE(&work_q->new_event_completion);
	}

	err = work_q->worker_thread_initialized == 0 ? pid : 0;    

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", err);
	}

	return err;

}

void cleanup_work_queue(workq_t *work_q)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (work_q == NULL || work_q->worker_thread_initialized == 0)
		return;

	INM_ATOMIC_INC(&work_q->shutdown_event_raised);
	INM_WAKEUP_INTERRUPTIBLE(&work_q->shutdown_event);
	INM_COMPLETE(&work_q->new_event_completion);

	INM_WAIT_FOR_COMPLETION(&work_q->worker_thread_completion);
	INM_KTHREAD_STOP(work_q->task);

	INM_DESTROY_COMPLETION(&work_q->worker_thread_completion);
	INM_DESTROY_COMPLETION(&work_q->new_event_completion);
	work_q->worker_thread_initialized = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return;
}

void init_work_queue_entry(wqentry_t *wqe)
{
	INM_MEM_ZERO(wqe, sizeof(*wqe));
	INM_ATOMIC_SET(&wqe->refcnt, 1);
	INM_INIT_LIST_HEAD(&wqe->list_entry);
}

wqentry_t *alloc_work_queue_entry(inm_u32_t gfpmask)
{
	wqentry_t *wqe = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	wqe = (wqentry_t *)INM_KMEM_CACHE_ALLOC(driver_ctx->wq_entry_pool, gfpmask);
	if (!wqe)
		return NULL;

	init_work_queue_entry(wqe);

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return wqe;
}

void cleanup_work_queue_entry(wqentry_t *wqe)
{

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	INM_KMEM_CACHE_FREE(driver_ctx->wq_entry_pool, wqe);

	wqe = NULL;
  
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return;
}

/*reference work queue entry - increment refcnt*/
void get_work_queue_entry(wqentry_t *wqe)
{
	INM_ATOMIC_INC(&wqe->refcnt);
	return;
}


/*dereference work queue entry - decrement refcnt*/
void put_work_queue_entry(wqentry_t *wqe)
{
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	if (INM_ATOMIC_DEC_AND_TEST(&wqe->refcnt))
		cleanup_work_queue_entry(wqe);

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return;
}

inm_s32_t add_item_to_work_queue(workq_t *work_q, wqentry_t *wq_entry)
{
	inm_s32_t r = 0;
	unsigned long lock_flag = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (work_q == NULL || work_q->worker_thread_initialized == 0)
		return 1;

	INM_SPIN_LOCK_IRQSAVE(&work_q->lock, lock_flag);

	if (work_q->flags & WQ_FLAGS_THREAD_SHUTDOWN) {
		r = 1;
	} else {
		inm_list_add_tail(&wq_entry->list_entry, &work_q->worker_queue_head);
		work_q->flags |= WQ_FLAGS_THREAD_WAKEUP;
		INM_ATOMIC_INC(&work_q->wakeup_event_raised);
		INM_WAKEUP_INTERRUPTIBLE(&work_q->wakeup_event);
		INM_COMPLETE(&work_q->new_event_completion);
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&work_q->lock, lock_flag);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", r);
	}

	return r;
}

int generic_worker_thread_function(void *context)
{
	workq_t *work_q = &driver_ctx->wqueue;

	long timeout_val = WORKER_THREAD_TIMEOUT;
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	struct inm_list_head workq_list_head;
	wqentry_t *wqeptr = NULL;
	inm_s32_t shutdown_event, wakeup_event;
	inm_irqflag_t lock_flag = 0;
	inm_u64_t prev_ts_100nsec = 0, cur_ts_100nsec = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DAEMONIZE("inmwrkrd");

	timeout_val = INM_MSECS_TO_JIFFIES(INM_MSEC_PER_SEC);
	while (1) {
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			dbg("waiting for new event completion in worker thread \n");
		}
		INM_WAIT_FOR_COMPLETION(&work_q->new_event_completion);
		INM_INIT_LIST_HEAD(&workq_list_head);

		wakeup_event = 
			INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(work_q->wakeup_event,
					   INM_ATOMIC_READ(&work_q->wakeup_event_raised),
					   timeout_val);            

		shutdown_event = (wakeup_event == 0) &&
			INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(work_q->shutdown_event,
					   INM_ATOMIC_READ(&work_q->shutdown_event_raised),
					   timeout_val);

		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			dbg("worker thread wakeup_event %d shutdown_event %d \n", wakeup_event,
						  shutdown_event);
		}
		if (shutdown_event > 0) {
			INM_ATOMIC_DEC(&work_q->shutdown_event_raised);
			work_q->flags |= WQ_FLAGS_THREAD_SHUTDOWN;
			break;
		}

		/* if reorg_datapool() is called only if there is not wakeup_event then reorg
		 * may not get a chance for a long time if a lot of work item has to processed.
		 */

		reorganize_datapool();
		if (!wakeup_event) {
			inm_flush_ts_and_seqno_to_file(FALSE);
			INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
			if(!(driver_ctx->dc_flags & SYS_CLEAN_SHUTDOWN) && 
					!(driver_ctx->dc_flags & SYS_UNCLEAN_SHUTDOWN) &&
					driver_state & DRV_LOADED_FULLY) {
				INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);
				if(inm_flush_clean_shutdown(UNCLEAN_SHUTDOWN))
					driver_ctx->dc_flags |= SYS_UNCLEAN_SHUTDOWN;
				}else
					INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);

				INM_COMPLETE(&work_q->new_event_completion);
#ifdef INM_AIX
				do{
					inm_s32_t flag;

					INM_SPIN_LOCK(&logger->log_buffer_lock, flag);
					if(logger->log_buffer_count >= LOG_THRESHOLD){
						INM_SPIN_UNLOCK(&logger->log_buffer_lock, flag);
						inm_flush_log_file();
						INM_SPIN_LOCK(&logger->log_buffer_lock, flag);
					}
					INM_SPIN_UNLOCK(&logger->log_buffer_lock, flag);
				}while(0);
#endif
			continue;
		}

		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			dbg("received wakeup event in worker thread\n");
			dbg("worker thread wakeup_event_raised %d ", work_q->wakeup_event_raised);
		}
		INM_ATOMIC_DEC(&work_q->wakeup_event_raised);

		INM_SPIN_LOCK_IRQSAVE(&work_q->lock, lock_flag);
		inm_list_for_each_safe(ptr, nextptr, &work_q->worker_queue_head) {
			wqeptr = inm_list_entry(ptr, wqentry_t, list_entry);
			inm_list_del_init(ptr);
			inm_list_add_tail(&wqeptr->list_entry,&workq_list_head);
		}
		INM_SPIN_UNLOCK_IRQRESTORE(&work_q->lock, lock_flag);

		get_time_stamp(&prev_ts_100nsec);
		inm_list_for_each_safe(ptr, nextptr,  &workq_list_head) {
			wqeptr = inm_list_entry(ptr, wqentry_t, list_entry);
			inm_list_del(&wqeptr->list_entry);
			/* flush time stamp and seq no*/
			get_time_stamp(&cur_ts_100nsec);
			if ((cur_ts_100nsec - prev_ts_100nsec) >= HUNDREDS_OF_NANOSEC_IN_SECOND) {
				inm_flush_ts_and_seqno_to_file(FALSE);
				INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
				if (!(driver_ctx->dc_flags & SYS_CLEAN_SHUTDOWN) && 
				 !(driver_ctx->dc_flags & SYS_UNCLEAN_SHUTDOWN) &&
				 driver_state & DRV_LOADED_FULLY) {
					INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);
					if(inm_flush_clean_shutdown(UNCLEAN_SHUTDOWN))
						driver_ctx->dc_flags |= SYS_UNCLEAN_SHUTDOWN;
				}else
				INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);

				prev_ts_100nsec = cur_ts_100nsec;
			}

			if (wqeptr->witem_type == WITEM_TYPE_SYSTEM_SHUTDOWN) {
				put_work_queue_entry(wqeptr);
				INM_COMPLETE(&driver_ctx->shutdown_completion);
				info("received sys shutdown message\n");
				continue;
			}

			if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
				dbg("processing wqe in workq");
				dbg("work queue entry = %p", wqeptr);
				dbg("work item type = %d, refcnt = %d",
					((bitmap_work_item_t *) wqeptr->context)->eBitmapWorkItem,
					INM_ATOMIC_READ(&wqeptr->refcnt));
			}
			if (wqeptr->work_func)
				wqeptr->work_func(wqeptr);
		}
	}
	info("received shutdown event in worker thread\n");
	inm_close_ts_and_seqno_file();
	INM_COMPLETE_AND_EXIT(&work_q->worker_thread_completion, 0); 
	return 0;
}

static int reorganize_datapool()
{
	int req_pages = 0;
	int num_pages = 0;
	int ret = 0;

	if (driver_ctx->dc_pool_allocation_completed)
		return 0;
	req_pages = driver_ctx->tunable_params.data_pool_size;
	req_pages <<= (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
	INM_BUG_ON((req_pages) < (driver_ctx->data_flt_ctx.pages_allocated));
	num_pages = req_pages - driver_ctx->data_flt_ctx.pages_allocated;
	if (num_pages > 0) {
		ret = add_data_pages(num_pages);
		if (ret == 0)
			driver_ctx->dc_pool_allocation_completed = 1;
	}
	return ret;
}
#define SAMPLE_WINDOW 0xa		   /* 10 sampling for rate of comsumption of pages*/

#define INM_REORG_WAITING_TIME_SEC  2

static inm_s32_t reorg_datapool(inm_u32_t reorg_flag)
{
#ifdef INM_AIX
	struct timestruc_t now;
#else
	inm_timespec now;
#endif
	static inm_u64_t recored_time;
	static inm_u64_t prev_dcr_time;
	inm_u64_t thrshld_time = driver_ctx->tunable_params.time_reorg_data_pool_sec;
	inm_u32_t cur_prot_vols = 0;
	static inm_u32_t prev_prot_vols;
	static inm_u32_t last_free_pages;
	inm_u32_t least_free_pages = 0;
	inm_u32_t expect_free = 0;
	inm_u32_t cur_free_pages = 0;
	inm_u32_t cur_allocd_pages;
	inm_u32_t alloc_limit = 0;
	inm_u32_t slab_nrpgs = 0;
	inm_u32_t data_pool_size = 0;
	static inm_u32_t index;
	static inm_u32_t *rate_array;
	inm_u32_t diff_sec = 0;
	inm_u32_t reorg = 0;
	inm_s32_t nr_pages = 0;
	inm_u32_t nr_slabs = 0;
	inm_u32_t default_dp_pages =(DEFAULT_DATA_POOL_SIZE_MB << (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT)); 
	inm_irqflag_t lock_flag;
	inm_s32_t rate = 0;
	inm_s32_t i = 0;
	inm_u32_t alloc_always = (reorg_flag & WQ_FLAGS_REORG_DP_ALLOC);
 	inm_s32_t ret = 0;
	inm_u32_t factor = 0;

	INM_GET_CURRENT_TIME(now);
	if(!recored_time){
		INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
		cur_prot_vols = driver_ctx->host_prot_volumes;
		INM_UP_READ(&(driver_ctx->tgt_list_sem));

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
		if(driver_ctx->dc_flags & DRV_DUMMY_LUN_CREATED){
			cur_prot_vols--;
		}
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);
		last_free_pages = driver_ctx->dc_cur_unres_pages;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);

		prev_prot_vols = cur_prot_vols;
		recored_time = now.tv_sec;
		index = 0;
		rate_array = INM_KMALLOC(sizeof(inm_u32_t) * SAMPLE_WINDOW, INM_KM_SLEEP, INM_KERNEL_HEAP);
		INM_MEM_ZERO(rate_array, sizeof(inm_u32_t) * SAMPLE_WINDOW);
		prev_dcr_time = now.tv_sec;
	}

	/* Right now dp_wait_time is not a tunable so we can access it without taking
	* data_pages_lock. If it happen to be tunable then we need  to take the lock.
	*/
	diff_sec = now.tv_sec - recored_time;
	if(diff_sec >= thrshld_time || alloc_always){
		INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
		cur_prot_vols = driver_ctx->host_prot_volumes;
		INM_UP_READ(&(driver_ctx->tgt_list_sem));
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
		if(driver_ctx->dc_flags & DRV_DUMMY_LUN_CREATED){
			cur_prot_vols--;
		}
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);
		slab_nrpgs = driver_ctx->data_flt_ctx.dp_nrpgs_slab;
		cur_free_pages = driver_ctx->dc_cur_unres_pages;
		cur_allocd_pages = driver_ctx->data_flt_ctx.pages_allocated;
		least_free_pages = driver_ctx->data_flt_ctx.dp_least_free_pgs;
		last_free_pages += (driver_ctx->data_flt_ctx.dp_pages_alloc_free);
		driver_ctx->data_flt_ctx.dp_pages_alloc_free = 0;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
		data_pool_size = driver_ctx->tunable_params.data_pool_size;
		factor = driver_ctx->tunable_params.time_reorg_data_pool_factor;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
		data_pool_size <<= (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);

		/* if rate of consumption of free pages are negative that means it releasing pages
		* so we can make rate is zero because release extra free pages are handled saparately
		*/
		if (last_free_pages > cur_free_pages) {
			rate = last_free_pages - cur_free_pages;
		} else {
			rate = 0;
		}
		if(diff_sec && rate){
			/* The following 2 line of code is doing below stuff:
			* rate = (last_free_pages - cur_free_pages + diff_sec - 1) / diff_sec; 
			*/
			rate += diff_sec - 1;
			rate /= diff_sec;
		}

		rate_array[index++] = rate;
		index = ((index) % SAMPLE_WINDOW);

		/*
		* its very unlikely that alloc_always is one and cur_prot_vols are zero,
		* For now not allocating any pages if cur_prot_vols are zero even if alloc_always 
		* is set.
		*/

		if(!cur_prot_vols){
			if(prev_prot_vols){
				nr_pages = cur_allocd_pages - default_dp_pages;
				if(nr_pages > 0){
					delete_data_pages(nr_pages);
				}
			}
			goto reorg_done;
		}
		if(!prev_prot_vols || alloc_always){
			if(cur_allocd_pages > data_pool_size){
				goto reorg_done;
			}
			nr_pages = data_pool_size - cur_allocd_pages;
			nr_pages = MIN(slab_nrpgs, nr_pages);
			dbg("reconfig to allocate %u pages, alloc_always is %u, prev_prot volumes %u",
							nr_pages, alloc_always, prev_prot_vols);
			ret = add_data_pages(nr_pages);
			goto reorg_done;
		}
		/* below try to ave the rate over SAMPLE_WINDOW iteration.
		* for first SAMPLE_WINDOW time it will miscalculate rate
		* but for first 2 * SAMPLE_WINDOW sec not much will happen
		* in boottime loading as well as loading of drv when system 
		* up and running.
		*/

		rate = 0;
		for (i = 0; i < SAMPLE_WINDOW; i++){
			rate += rate_array[i];
		}
		rate = ((rate + SAMPLE_WINDOW - 1)/SAMPLE_WINDOW);
		/*
		* extrapolating free page consumption for twice of thrshld_time
		* because we not wakeup in exactly in thrshld_time time in on a
		* very busy system and it is harmless on idle systems.
		*/

		expect_free = cur_prot_vols * rate * 2 * thrshld_time;
		expect_free /= prev_prot_vols;
		expect_free = cur_free_pages - expect_free;
		alloc_limit = MIN(slab_nrpgs, cur_allocd_pages);
		alloc_limit = (alloc_limit * MIN_FREE_PAGES_TO_ALLOC_SLAB_PERCENT) / 100;
		if(expect_free <= alloc_limit){
			if(!(cur_allocd_pages < data_pool_size)){
				goto reorg_done;
			}
			nr_pages = data_pool_size - cur_allocd_pages;
			nr_pages = MIN(slab_nrpgs, nr_pages);
			dbg("reconfig to allocate %u pages", nr_pages);
			ret = add_data_pages(nr_pages);
			reorg = 1;
		} else {
			if(now.tv_sec - prev_dcr_time > 2 * factor * thrshld_time){
				if(least_free_pages > ((slab_nrpgs * MIN_FREE_PAGES_TO_FREE_LAST_WHOLE_SLAB_PERCENT) /100)){
					dbg("reconfig to delete the pages cur_unres pgs %u, cur_res pgs %u", driver_ctx->dc_cur_unres_pages, driver_ctx->dc_cur_res_pages);
					nr_pages = nr_slabs;
					if((cur_allocd_pages - nr_pages) < default_dp_pages){
						nr_pages = cur_allocd_pages - default_dp_pages;
					}
					delete_data_pages(nr_pages);
					reorg = 1;
				}
				prev_dcr_time = now.tv_sec;
				INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);
				driver_ctx->data_flt_ctx.dp_least_free_pgs = driver_ctx->dc_cur_unres_pages;
				INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);
				
			}else {
				if(now.tv_sec - prev_dcr_time < factor * thrshld_time){
					goto reorg_done;
				}
				if(least_free_pages >= (slab_nrpgs * 2)){
					dbg("reconfig to delete the pages");
					nr_slabs = (least_free_pages/slab_nrpgs) - 1;
					nr_pages = nr_slabs * slab_nrpgs;
					if((cur_allocd_pages - nr_pages) < default_dp_pages){
						nr_pages = cur_allocd_pages - default_dp_pages;
					}
					delete_data_pages(nr_pages);
					prev_dcr_time = now.tv_sec;
					INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);
					driver_ctx->data_flt_ctx.dp_least_free_pgs = driver_ctx->dc_cur_unres_pages;
					INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);

					reorg = 1;
				}
			}
		}
reorg_done:
		prev_prot_vols = cur_prot_vols;
		INM_GET_CURRENT_TIME(now);
		recored_time = now.tv_sec;
		last_free_pages = cur_free_pages;
		if(reorg){
			recalc_data_file_mode_thres();
		}
	}
	return ret;
}

inm_s32_t wrap_reorg_datapool()
{
	return reorganize_datapool();
}
