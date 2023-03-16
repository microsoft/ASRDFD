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

#ifndef _INMAGE_WORK_QUEUE_H
#define _INMAGE_WORK_QUEUE_H

#include "involflt-common.h"

#define WQ_FLAGS_THREAD_SHUTDOWN        0x00000001
#define WQ_FLAGS_THREAD_WAKEUP          0x00000002
#define WQ_FLAGS_REORG_DP_ALLOC         0x00000004

#define MIN_FREE_PAGES_TO_FREE_LAST_WHOLE_SLAB_PERCENT 190
#define MIN_FREE_PAGES_TO_ALLOC_SLAB_PERCENT 10

#define WQE_FLAGS_THREAD_SHUTDOWN       0x00000001

typedef struct _workq {
	 struct inm_list_head worker_queue_head;
	 inm_completion_t new_event_completion;
	 inm_wait_queue_head_t wakeup_event;
	 inm_wait_queue_head_t shutdown_event;
	 inm_atomic_t wakeup_event_raised;
	 inm_atomic_t shutdown_event_raised;
	 int (*worker_thread_routine)(void *);
	 inm_spinlock_t lock;
	 inm_u32_t flags;
	 inm_s32_t worker_thread_initialized;
	 inm_completion_t worker_thread_completion;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	 struct task_struct *task;
#endif
} workq_t;


typedef struct _wqentry {
	 struct inm_list_head list_entry;    
	 void (* work_func)(struct _wqentry *);
	 void *context;
	 inm_atomic_t  refcnt;
	 inm_u32_t  witem_type;
	 inm_u32_t flags;
	 inm_u32_t extra1;
	 inm_u32_t extra2;
} wqentry_t;
	 

enum {
	 WITEM_TYPE_UNINITIALIZED = 0,
	 WITEM_TYPE_OPEN_BITMAP = 1,
	 WITEM_TYPE_BITMAP_WRITE = 2,
	 WITEM_TYPE_START_BITMAP_READ = 3,
	 WITEM_TYPE_CONTINUE_BITMAP_READ = 4,
	 WITEM_TYPE_VOLUME_UNLOAD = 5,
	 WITEM_TYPE_SYSTEM_SHUTDOWN = 6,
	 WITEM_TYPE_TIMEOUT = 7,
	 WITEM_TYPE_TELEMETRY_FLUSH = 8,
};

typedef struct flt_timer {
	 struct _wqentry ft_task;
	 inm_timer_t     ft_timer;
} flt_timer_t;

typedef void (*timeout_t)(wqentry_t *);

inm_s32_t force_timeout(flt_timer_t *timer);
inm_s32_t end_timer(flt_timer_t *timer);
void start_timer(flt_timer_t *timer, int timeout_ms, timeout_t callback);

inm_s32_t init_work_queue(workq_t *work_q, int (*worker_thread_function)(void *));
void cleanup_work_queue(workq_t *work_q);
void init_work_queue_entry(wqentry_t *wqe);
wqentry_t *alloc_work_queue_entry(inm_u32_t gfpmask);
void cleanup_work_queue_entry(wqentry_t *wqe);
void get_work_queue_entry(wqentry_t *wqe);
void put_work_queue_entry(wqentry_t *wqe);
inm_s32_t add_item_to_work_queue(workq_t *work_q, wqentry_t *wq_entry);
int generic_worker_thread_function(void *context);
int timer_worker(void *context);
inm_s32_t wrap_reorg_datapool(void);
#endif /* _INMAGE_WORK_QUEUE_H */
