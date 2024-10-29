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

#ifndef _INMAGE_VOLUME_BITMAP_H_
#define _INMAGE_VOLUME_BITMAP_H_

#ifdef LCW_TEST
#pragma message "LCW Test Mode"
#define INM_BMAP_DEFAULT_DIR_DEPRECATED "/mnt/tmp/x"
/* For last chance writes testing, allow creating file in custom location */
#define INM_BMAP_ALLOW_DEPRECATED(fname)    (TRUE)
#else
#define INM_BMAP_DEFAULT_DIR_DEPRECATED "/root"
/* Allow deprecated path for existing protections */
#define INM_BMAP_ALLOW_DEPRECATED(fname)    (file_exists(fname))
#endif

#define VOLUME_BITMAP_FLAGS_WAITING_FOR_SETBITS_WORKITEM_LIST_EMPTY_NOTIFICATION    0x0001
#define VOLUME_BITMAP_FLAGS_HAS_VOLUME_LETTER                                       0x0002
#define VOLUME_LETTER_IN_CHARS          2

#define STATUS_MORE_PROCESSING_REQUIRED 0xfff1
#define EOF_BMAP                        (1)

#include "bitmap_api.h"
#include "inm_utypes.h"

typedef enum _etVBitmapState {
	ecVBitmapStateUnInitialized = 0,
	/* Set to this state as soon as the bitmap is opened. */
	ecVBitmapStateOpened = 1,
	/* Set to this state when worker routine is queued for first read. */
	ecVBitmapStateReadStarted = 2,
	ecVBitmapStateReadPaused = 3,
	ecVBitmapStateAddingChanges = 4,
	ecVBitmapStateReadCompleted = 5,
	ecVBitmapStateClosed = 6,
	ecVBitmapStateReadError = 7,
	ecVBitmapStateInternalError = 8
} etVBitmapState;

struct _target_context;
struct _wqentry;

/* This structure is used for bitmap mode */
typedef struct _volume_bitmap {
	 struct inm_list_head  list_entry;     /* link all bitmaps to dc */
	 inm_atomic_t          refcnt;
	 inm_u64_t    flags;
	 inm_u64_t    reserved;
	 etVBitmapState    eVBitmapState;

	 struct _target_context *volume_context;
	 inm_sem_t         sem;

	 struct inm_list_head  work_item_list;
	 inm_spinlock_t    lock;

	 struct inm_list_head  set_bits_work_item_list;
	 inm_completion_t set_bits_work_item_list_empty_notification;
	 char              volume_GUID[GUID_SIZE_IN_CHARS + 1];
	 char              volume_letter[VOLUME_LETTER_IN_CHARS + 1];
	 inm_u64_t    segment_cache_limit;

	 bitmap_api_t  *bitmap_api;
	 inm_u32_t       bitmap_skip_writes;
} volume_bitmap_t;

typedef enum _etBitmapWorkItem
{
	 ecBitmapWorkItemNotInitialized = 0,
	 ecBitmapWorkItemStartRead,
	 ecBitmapWorkItemContinueRead,
	 ecBitmapWorkItemClearBits,
	 ecBitmapWorkItemSetBits,
} etBitmapWorkItem;

typedef struct _bitmap_work_item {
	 struct inm_list_head list_entry;
	 inm_atomic_t         refcnt;
	 inm_ull64_t         changes;
	 inm_u64_t         nr_bytes_changed_data;
	 etBitmapWorkItem eBitmapWorkItem;
	 volume_bitmap_t  *volume_bitmap;
	 bitruns_t        bit_runs;
} bitmap_work_item_t;

void queue_worker_routine_for_start_bitmap_read(volume_bitmap_t *volume_bitmap);

void queue_worker_routine_for_continue_bitmap_read(volume_bitmap_t *volume_bitmap);

void continue_bitmap_read(bitmap_work_item_t *bmap_witem, inm_s32_t mutex_acquired);

void request_service_thread_to_open_bitmap(struct _target_context *vcptr);

volume_bitmap_t *open_bitmap_file(struct _target_context *vcptr, inm_s32_t *status);

void close_bitmap_file(volume_bitmap_t *volume_bitmap, inm_s32_t clear_bitmap);

void wait_for_all_writes_to_complete(volume_bitmap_t *volume_bitmap);

inm_s32_t get_volume_bitmap_granularity(struct _target_context *vcptr,
	                               inm_u64_t*bitmap_granularity);

void queue_worker_routine_for_continue_bitmap_read(volume_bitmap_t *vbmap);
void continue_bitmap_read_worker_routine(struct _wqentry *wqe);

void write_bitmap_completion(bitmap_work_item_t *bmap_witem);
void bitmap_write_worker_routine(struct _wqentry *wqe);

void start_bitmap_read_worker_routine(struct _wqentry *wqe);
void write_bitmap_completion_callback(bitruns_t *bitruns);
void write_bitmap_completion_worker_routine(struct _wqentry *wqep);
void read_bitmap_completion_callback(bitruns_t *bit_runs);
void read_bitmap_completion_worker_routine(struct _wqentry *wqe);
void read_bitmap_completion(bitmap_work_item_t *bmap_witem);
volume_bitmap_t *allocate_volume_bitmap(void);


void get_volume_bitmap(volume_bitmap_t *volume_bitmap);

void put_volume_bitmap(volume_bitmap_t *volume_bitmap);

/* function prototypes for bitmap work items */
bitmap_work_item_t * allocate_bitmap_work_item(inm_u32_t);
void cleanup_work_item(bitmap_work_item_t *bm_witem);

void get_bitmap_work_item(bitmap_work_item_t *);
void put_bitmap_work_item(bitmap_work_item_t *);

const char * get_volume_bitmap_state_string(etVBitmapState);
inm_s32_t add_metadata_in_change_node(struct inm_list_head *node_hd, change_node_t change_node,
	                             inm_u64_t chg_offset,
	                             inm_u32_t chg_length);

inm_s32_t can_open_bitmap_file(struct _target_context *vcptr, inm_s32_t lose_changes);
void set_bitmap_open_fail_due_to_loss_of_changes(struct _target_context *vcptr,
	                                              inm_s32_t lock_acquired);
void set_bitmap_open_error(struct _target_context *vcptr, inm_s32_t lock_acquired,
	                        inm_s32_t status);
struct _wqentry;
inm_s32_t queue_worker_routine_for_bitmap_write(struct _target_context *, inm_u64_t,
	volume_bitmap_t *, struct inm_list_head *, struct _wqentry *, bitmap_work_item_t *);
void log_bitmap_open_success_event(struct _target_context *vcptr);
inm_s32_t inmage_flt_save_all_changes(struct _target_context *vcptr, inm_s32_t wait_required,
	                             inm_s32_t op_type);
void flush_and_close_bitmap_file(struct _target_context *vcptr);
void fill_bitmap_filename_in_volume_context(struct _target_context *vcptr);
struct _target_context *get_tc_using_dev(inm_dev_t rdev);
inm_s32_t move_rawbitmap_to_bmap(struct _target_context *vcptr, inm_s32_t force);

void process_vcontext_work_items(struct _wqentry *wqeptr);
inm_s32_t add_vc_workitem_to_list(inm_u32_t witem_type, struct _target_context *vcptr,
	                         inm_u32_t extra1, inm_u8_t open_bitmap,
	                         struct inm_list_head *lhptr);

#endif /* _INMAGE_VOLUME_BITMAP_H_ */

