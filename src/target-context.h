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

#ifndef LINVOLFLT_TARGET_CONTEXT_H
#define LINVOLFLT_TARGET_CONTEXT_H
#include "involflt-common.h" 
#include "filter.h"
#include "telemetry-types.h"

typedef enum _devstate_t {
	DEVICE_STATE_INITIALIZED = 0,
	DEVICE_STATE_ONLINE = 1,
	DEVICE_STATE_OFFLINE = 2,
	DEVICE_STATE_SHUTDOWN = 3,
} devstate_t;

typedef struct __target_statistics {
	inm_s32_t num_malloc_fails; /* handles memomory allocation failures */
	inm_u32_t num_pages_allocated;  /* tracks # of pages allocated for current target */
	inm_u32_t num_pgs_in_dfm_queue; /* Number of pages queued to data file thread. */
	inm_u64_t dfm_bytes_to_disk;
	inm_atomic_t num_dfm_files;
	inm_atomic_t num_dfm_files_pending;
	inm_atomic_t num_tags_dropped;
	inm_atomic_t metadata_trans_due_to_delay_alloc;

#define MAX_FLT_MODES 3
	/* filtering statistics */

	/* counter for # of times switched to each mode */
	long num_change_to_flt_mode[MAX_FLT_MODES];

	/* counter for time(in secs) spent in each flt mode */
	long num_secs_in_flt_mode[MAX_FLT_MODES];
	inm_s64_t st_mode_switch_time;

#define MAX_WOSTATE_MODES 5

	/* counter for # of times switched to each write order state */
	long num_change_to_wostate[MAX_WOSTATE_MODES];
	
	/* counter for # of times switched to each write order state */
	long num_change_to_wostate_user[MAX_WOSTATE_MODES];

	/* counter for time(in secs) spent in each write order state */
	long num_secs_in_wostate[MAX_WOSTATE_MODES];
	inm_s64_t st_wostate_switch_time;

	/* meta data statistics */
	long num_change_metadata_flt_mode_on_user_req;
#define MAX_NR_IO_BUCKETS	16
	inm_atomic_t io_pat_reads[MAX_NR_IO_BUCKETS];	/* read io pattern */
	inm_atomic_t io_pat_writes[MAX_NR_IO_BUCKETS];	/* write io pattern */
	inm_u64_t    tc_write_io_rcvd;
	inm_u64_t    tc_write_io_rcvd_bytes;
	inm_atomic_t tc_write_cancel;
	inm_u64_t    tc_write_cancel_rcvd_bytes;
} tc_stats_t;

struct tgt_hist_stats {
	inm_u64_t ths_start_flt_ts;			/* start filtering time */
	inm_u64_t ths_clrdiff_ts;			/* time of last clear diffs */
	inm_u32_t ths_nr_clrdiffs;			/* # times clear diffs issued */
	inm_u32_t ths_reserved;
	inm_u32_t ths_nr_osyncs;			/* # times resync marked */
	inm_u32_t ths_osync_err;			/* last osync err code */
	inm_u64_t ths_osync_ts;			/* last osync time */
	inm_u64_t ths_clrstats_ts;			/* last time clear stats issued */
};

typedef struct tgt_hist_stats tgt_hist_stats_t;
	
/* bitmap related declrations */
typedef struct bitmap_info  {
	char            bitmap_file_name[INM_NAME_MAX + 1]; /* UNICODE string */
	unsigned long   bitmap_granularity;
	unsigned long   bitmap_offset;
	volume_bitmap_t *volume_bitmap;

	inm_u32_t        num_bitmap_open_errors;
	inm_u32_t        num_bitmap_clear_errors;
	inm_u32_t        num_bitmap_read_errors;
	inm_u32_t        num_bitmap_write_errors;

	inm_u64_t        num_changes_queued_for_writing;
	inm_u64_t        num_byte_changes_queued_for_writing;
	inm_u64_t        num_of_times_bitmap_written;

	inm_u64_t        num_changes_read_from_bitmap;
	inm_u64_t        num_byte_changes_read_from_bitmap;
	inm_u64_t        num_of_times_bitmap_read;

	inm_u64_t        num_changes_written_to_bitmap;
	inm_u64_t        num_byte_changes_written_to_bitmap;
	inm_u64_t        nr_bytes_in_bmap;
	inm_u32_t        bmap_busy_wait;
	char            bitmap_dir_name[INM_NAME_MAX + 1]; /* UNICODE string */
} bitmap_info_t; 

struct create_delete_wait
{
	struct completion wait;
	struct inm_list_head list;
};

typedef struct _mirror_vol_entry
{
	struct inm_list_head next;
	char                 tc_mirror_guid[INM_GUID_LEN_MAX];
	inm_block_device_t  *mirror_dev;
	inm_u64_t vol_error;
	inm_u64_t vol_count;    
	inm_u64_t vol_byte_written;    
	inm_u64_t vol_io_issued;    
	inm_u64_t vol_io_succeeded;    
	inm_u64_t vol_io_skiped;    
	inm_u64_t vol_flags;    
	inm_s32_t vol_state;
	inm_atomic_t vol_ref;
	void      *vol_private;
} mirror_vol_entry_t;

#define INM_VOL_ENTRY_ALIVE  0x1
#define INM_VOL_ENTRY_DEAD   0x2
#define INM_VOL_ENTRY_FREED  0x4
#define INM_VOL_ENTRY_TRY_ONLINE  0x8

#define	INM_PT_LUN	0x1
#define	INM_AT_LUN	0x2

/* INM_BUG_ON(1) there because we never drop last ref on the volume entry
 *  instead we call free_mirror_list to close the device and free the entry
 *  in target_context_release().
 */

#define INM_DEREF_VOL_ENTRY(vol_entry, tcp)									\
{														\
	if(tcp->tc_dev_type == FILTER_DEV_MIRROR_SETUP && INM_ATOMIC_DEC_AND_TEST(&(vol_entry->vol_ref))){	\
		dbg("deleting vol_entry for %s",vol_entry->tc_mirror_guid);					\
		INM_BUG_ON(1);											\
		volume_lock(tcp);										\
		inm_list_del(&(vol_entry->next));								\
		volume_unlock(tcp);										\
		INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t), INM_KERNEL_HEAP);				\
		vol_entry = NULL;										\
	}													\
}

#define INM_REF_VOL_ENTRY(vol_entry)	INM_ATOMIC_INC(&(vol_entry->vol_ref))


/* structure for latency distribution */
#define INM_LATENCY_DIST_BKT_CAPACITY	12
#define INM_LATENCY_LOG_CAPACITY	12
struct inm_latency_stats {
	inm_u64_t	ls_bkts[INM_LATENCY_DIST_BKT_CAPACITY];
	inm_u32_t	ls_freq[INM_LATENCY_DIST_BKT_CAPACITY];
	inm_u32_t	ls_freq_used_bkt;
	inm_u32_t	ls_nr_avail_bkts;
	inm_u64_t	ls_init_min_max;
	inm_u64_t	ls_log_buf[INM_LATENCY_LOG_CAPACITY];
	inm_u64_t	ls_log_min;
	inm_u64_t	ls_log_max;
	inm_u32_t	ls_log_idx;
};
typedef struct inm_latency_stats inm_latency_stats_t;

/* Maintains Disk level CX session */
typedef struct _disk_cx_session {
	inm_u64_t    dcs_flags; /* Flags */
	inm_u64_t    dcs_start_ts; /* CX session start time */
	inm_u64_t    dcs_end_ts; /* CX session end time */
	inm_u64_t    dcs_base_secs_ts; /* This is the base time to calculate 1s
	                                  intervals */
	inm_u64_t    dcs_tracked_bytes; /* Bytes tracked */
	inm_u64_t    dcs_drained_bytes; /* Bytes drained */
	inm_u64_t    dcs_tracked_bytes_per_second; /* Bytes tracked every second */
	inm_u64_t    dcs_churn_buckets[DEFAULT_NR_CHURN_BUCKETS]; /* Churn
	                                                             buckets */
	inm_u64_t    dcs_first_nw_failure_ts; /* First network failure time in this
	                                         CX session */
	inm_u64_t    dcs_last_nw_failure_ts; /* Last network failure time in this
	                                        CX session */
	inm_u64_t    dcs_last_nw_failure_error_code; /* Error code for last network
	                                                failure */
	inm_u64_t    dcs_nr_nw_failures; /* Number of network failures */
	inm_u64_t    dcs_max_peak_churn; /* Max peak churn */
	inm_u64_t    dcs_first_peak_churn_ts; /* Time of first peak churn */
	inm_u64_t    dcs_last_peak_churn_ts; /* Time of first peak churn */
	inm_u64_t    dcs_excess_churn; /* Excess churn on top of peak churn */
	inm_u64_t    dcs_max_s2_latency; /* S2 latency */
	inm_u64_t    dcs_nth_cx_session; /* CS session number */
	inm_list_head_t dcs_list;
	disk_cx_stats_info_t *dcs_disk_cx_stats_info;
} disk_cx_session_t;

#define DCS_CX_SESSION_STARTED 0x01
#define DCS_CX_SESSION_ENDED   0x02

/* Reasos for closing CX session at disk level */
enum {
	CX_CLOSE_PENDING_BYTES_BELOW_THRESHOLD = 1,
	CX_CLOSE_STOP_FILTERING_ISSUED,
	CX_CLOSE_DISK_REMOVAL,
};

/* There will be one instance of this structure per involflt target. New
 * instance of this structure is created while stacking operation. It holds
 * target specific information.
 */
typedef struct _target_context {
	struct inm_list_head tc_list; /* links all targets, head in driver-context     */
	inm_u32_t        tc_flags;    /* Indicated if the volume is read-only etc.     */
	inm_sem_t        tc_sem;
	inm_u32_t        refcnt;     /* Using reference counting infrastructe 
	                                 provided by sysfs interface.                  */
	void            (*release)(void *); 

	flt_mode        dummy_tc_cur_mode;  /* Current filtering mode for this target. */
	flt_mode        dummy_tc_prev_mode; /* previous filtering mode for this target */
	devstate_t      dummy_tc_dev_state;
	inm_spinlock_t  tc_lock;            /* lock to protect change list             */
	inm_spinlock_t  tc_tunables_lock;

	/* spin lock function pointers */
	void          (*tc_lock_fn)(struct _target_context *);
	void          (*tc_unlock_fn)(struct _target_context *);

	unsigned long   tc_lock_flag;
	change_node_t  *tc_cur_node;
	struct inm_list_head tc_node_head;
	struct inm_list_head tc_non_drainable_node_head;
	struct inm_list_head tc_nwo_dmode_list; /*link all non write order data changes */

	inm_wait_queue_head_t tc_waitq;

	/* Data File Mode Support */
	data_file_flt_t tc_dfm;

	inm_u32_t       tc_nr_cns;
	inm_s64_t       tc_bytes_tracked;
	inm_s64_t       tc_pending_changes;
	inm_s64_t       tc_pending_md_changes;
	inm_s64_t       tc_bytes_pending_md_changes;
	inm_s64_t       tc_pending_wostate_data_changes;
	inm_s64_t       tc_pending_wostate_md_changes;
	inm_s64_t       tc_pending_wostate_bm_changes;
	inm_s64_t       tc_pending_wostate_rbm_changes;
	inm_s64_t       tc_bytes_pending_changes;
	inm_s64_t       tc_bytes_coalesced_changes;
	inm_s64_t       tc_bytes_overlap_changes;
	inm_s64_t       tc_cnode_pgs;
	inm_s64_t       tc_commited_changes;
	inm_s64_t       tc_bytes_commited_changes;    
	inm_s64_t       tc_transaction_id;
	inm_s64_t       tc_prev_transaction_id;
	change_node_t  *tc_pending_confirm;
	inm_u32_t       tc_db_notify_thres;
	inm_u64_t       tc_data_to_disk_limit;
	char           *tc_data_log_dir;

	tc_stats_t      tc_stats;    /* statistics info */

	char           *tc_datafile_dir_name;

	/* Reserved pages from data pool */
	inm_u32_t       tc_reserved_pages;

	// sync flags
	inm_s32_t       tc_resync_required;
	inm_s32_t       tc_resync_indicated; /* ResyncRequired flag sent to user mode 
	                                      * process */
	unsigned long   tc_nr_out_of_sync;
	unsigned long   tc_out_of_sync_err_code;
	inm_u64_t       tc_out_of_sync_time_stamp;
	unsigned long   tc_out_of_sync_err_status;
	unsigned long   tc_nr_out_of_sync_indicated;
	inm_device_t    tc_dev_type; 
	void           *tc_priv;  /* points to host_dev_ctx/fabric_dev_ctx */  
	bitmap_info_t  *tc_bp;        /* non-NULL if bitmap is enabled (default) */
	/* ideally guid should be moved to device specific data structure, but
	 * sysfs assumes this to be in here, so leaving it in here for now.
	 */
	char            tc_guid[INM_GUID_LEN_MAX];
	tgt_hist_stats_t tc_hist;
	flt_mode        tc_cur_mode; /* Current filtering mode for this target. */
	flt_mode        tc_prev_mode; /* previous filtering mode for this target */
	etWriteOrderState        tc_cur_wostate;
	etWriteOrderState        tc_prev_wostate;
	devstate_t      tc_dev_state;
	inm_completion_t exit;
	struct inm_list_head cdw_list;
	inm_sem_t       cdw_sem; /* Lock to protect the above list */

	/* mirror setup data strucutres */
	struct inm_list_head tc_src_list;
	struct inm_list_head tc_dst_list;
	mirror_vol_entry_t *tc_vol_entry;
	
	char           *tc_mnt_pt;
	inm_s32_t       tc_filtering_disable_required;
	inm_u64_t	    tc_CurrEndSequenceNumber;
	inm_u64_t       tc_CurrEndTimeStamp;
	inm_u32_t       tc_CurrSequenceIDforSplitIO;
	inm_u64_t       tc_PrevEndSequenceNumber;
	inm_u64_t       tc_PrevEndTimeStamp;
	inm_u32_t       tc_PrevSequenceIDforSplitIO;
	inm_u64_t       tc_rpo_timestamp;
	inm_s32_t       tc_tso_file;
	inm_s64_t       tc_tso_trans_id;
	char            tc_pname[INM_GUID_LEN_MAX];
	inm_u64_t       tc_dev_startoff;
	inm_atomic_t    tc_async_bufs_pending;
	inm_atomic_t    tc_async_bufs_processed;
	inm_atomic_t    tc_async_bufs_write_pending;
	inm_atomic_t    tc_async_bufs_write_processed;
	inm_u64_t       tc_nr_requests_queued;
	inm_u64_t       tc_nr_bufs_queued_to_thread;
	inm_u64_t       tc_nr_bufs_processed_by_thread;
	inm_u64_t       tc_nr_processed_queued_bufs;
	inm_u64_t       tc_nr_ddwrites_called;
	inm_atomic_t    tc_nr_bufs_pending;
	inm_atomic_t    tc_nr_bufs_processed;
	inm_atomic_t    tc_mixedbufs;
	inm_atomic_t    tc_read_buf_first;
	inm_atomic_t    tc_write_buf_first;
	int 	    tc_more_done_set;
	int 	    tc_nr_bufs_submitted_gr_than_one;
	inm_u64_t	    tc_nr_spilt_io_data_mode;
	inm_u64_t	    tc_nr_xm_mapin_failures;
	inm_wait_queue_head_t tc_wq_in_flight_ios;
	inm_atomic_t    tc_nr_in_flight_ios;
	UDIRTY_BLOCK_V2 *tc_db_v2;
	inm_u64_t       tc_dbwait_event_ts_in_usec;
	inm_latency_stats_t tc_dbwait_notify_latstat;
	inm_latency_stats_t tc_dbret_latstat;
	inm_latency_stats_t tc_dbcommit_latstat;
	inm_u32_t       tc_optimize_performance;
	target_telemetry_t tc_tel;
	inm_sem_t       tc_resync_sem;
	disk_cx_session_t tc_disk_cx_session;
	inm_u64_t       tc_s2_latency_base_ts;
	TAG_COMMIT_STATUS *tc_tag_commit_status;
	inm_atomic_t    tc_nr_chain_bios_submitted;
	inm_atomic_t    tc_nr_chain_bios_pending;
	inm_atomic_t    tc_nr_completed_in_child_stack;
	inm_atomic_t    tc_nr_completed_in_own_stack;
#if (defined REQ_OP_WRITE_ZEROES || defined OL7UEK5)
	inm_atomic_t    tc_nr_write_zero_bios;
#endif
} target_context_t;

#define volume_lock(ctx) 						\
do { 									\
	INM_BUG_ON(((target_context_t *)ctx)->tc_lock_fn == NULL); 	\
	((target_context_t *)ctx)->tc_lock_fn((target_context_t *)ctx); \
} while (0)

#define volume_unlock(ctx) 							\
do { 										\
	INM_BUG_ON(((target_context_t *)ctx)->tc_unlock_fn == NULL); 		\
	((target_context_t *)ctx)->tc_unlock_fn((target_context_t *)ctx); 	\
} while (0)

/* flags */
#define VCF_FILTERING_STOPPED        0x00000001
#define VCF_READ_ONLY                0x00000002
#define VCF_DATA_MODE_DISABLED       0x00000004
#define VCF_DATA_FILES_DISABLED      0x00000008
#define VCF_OPEN_BITMAP_FAILED       0x00000010
#define VCF_VOLUME_TO_BE_FROZEN      0x00000020
#define VCF_VOLUME_IN_GET_DB         0x00000040
#define VCF_VOLUME_IN_BMAP_WRITE     0x00000080
#define VCF_VOLUME_INITRD_STACKED    0x00000100
#define VCF_VOLUME_BOOTTIME_STACKED  0x00000200
#define VCF_VOLUME_LETTER_OBTAINED   0x00000400
#define VCF_CV_FS_UNMOUNTED          0x00000800
#define VCF_OPEN_BITMAP_REQUESTED    0x00001000
#define VCF_BITMAP_READ_DISABLED     0x00002000
#define VCF_BITMAP_WRITE_DISABLED    0x00004000
#define VCF_VOLUME_DELETING          0x00008000
#define VCF_VOLUME_CREATING          0x00010000
#define VCF_FULL_DEV                 0x00020000
#define VCF_FULL_DEV_PARTITION       0x00040000
#define VCF_VOLUME_LOCKED            0x00080000
#define VCF_IGNORE_BITMAP_CREATION   0x00100000
#define VCF_DATAFILE_DIR_CREATED     0x00200000
#define VCF_VOLUME_FROZEN_SYS_SHUTDOWN  0x00800000
#define VCF_MIRRORING_PAUSED         0x01000000
#define	VCF_VOLUME_STACKED_PARTIALLY 0x02000000
#define	VCF_TAG_COMMIT_PENDING       0x04000000
#define	VCF_ROOT_DEV                 0x08000000
#define VCF_DRAIN_BARRIER            0x10000000
#define VCF_IN_NWO                   0x20000000
#define VCF_DRAIN_BLOCKED            0x40000000
#define VCF_IO_BARRIER_ON            0x80000000

#define MAX_BITMAP_OPEN_ERRORS_TO_STOP_FILTERING    0x0040
/* exponential back off 1, 2, 4, 8, 16, 32, 64,128 */

#define MAX_DELAY_FOR_BITMAP_FILE_OPEN_IN_SECONDS   300 // 5 * 60 Sec = 5 Minutes
#define MIN_DELAY_FOR_BIMTAP_FILE_OPEN_IN_SECONDS   1   // 1 second


//miscellenous constants
//parameters save all function
enum {
	INM_NO_OP = 0,
	INM_STOP_FILTERING = 1,
	INM_SYSTEM_SHUTDOWN = 2,
	INM_UNSTACK = 3,
};

#define is_target_read_only(ctx) (((target_context_t *)ctx)->tc_flags & \
	                VCF_READ_ONLY)
#define is_target_filtering_disabled(ctx) (((target_context_t *)ctx)->tc_flags & \
	                VCF_FILTERING_STOPPED)
#define is_target_being_frozen(ctx) (((target_context_t *)ctx)->tc_flags & \
	                VCF_VOLUME_TO_BE_FROZEN)
#define is_target_mirror_paused(ctx) (((target_context_t *)ctx)->tc_flags & \
	                VCF_MIRRORING_PAUSED)
#define is_target_tag_commit_pending(ctx) (((target_context_t *)ctx)->tc_flags & \
	                VCF_TAG_COMMIT_PENDING)
#define is_target_drain_barrier_on(ctx) (((target_context_t *)ctx)->tc_flags & \
	                VCF_DRAIN_BARRIER)

#define is_target_enabled_for_data_filtering(ctx)    \
	 (!(((target_context_t *) ctx)->tc_flags & VCF_DATA_MODE_DISABLED))
	
/* ( !((target_context_t *) ctx)->tc_flags & VCF_DATA_MODE_DISABLED) || \
 *     (driver_context->service_supports_data_filtering) || \
 *     (driver_context->enable_data_filtering)) ? 1 : 0
 **/

#define __should_wakeup_s2(ctx) 					\
	    (((((target_context_t *)ctx)->tc_bytes_pending_changes >= 	\
	    ((target_context_t *)ctx)->tc_db_notify_thres) || 		\
	    (((((target_context_t *)ctx)->tc_pending_changes - 		\
	      ((target_context_t *)ctx)->tc_pending_md_changes) > 0) && \
	     (((target_context_t *)ctx)->tc_pending_md_changes > 0)) || \
	    ((((target_context_t *)ctx)->tc_pending_md_changes >= 	\
	      MAX_CHANGE_INFOS_PER_PAGE))) ? 1 : 0)

#define should_wakeup_s2(ctx) 				\
	    (!is_target_drain_barrier_on(ctx) &&	\
	     __should_wakeup_s2(ctx) ? 1 : 0)

#define should_wakeup_s2_ignore_drain_barrier(ctx) __should_wakeup_s2(ctx)

#define should_wait_for_db(ctx) 					\
	    (!is_target_drain_barrier_on(ctx) &&                     	\
	    ((((target_context_t *)ctx)->tc_bytes_pending_changes >= 	\
	    ((target_context_t *)ctx)->tc_db_notify_thres) || 		\
	    (((((target_context_t *)ctx)->tc_pending_changes - 		\
	      ((target_context_t *)ctx)->tc_pending_md_changes) > 0) && \
	     (((target_context_t *)ctx)->tc_pending_md_changes > 0)) || \
	    ((((target_context_t *)ctx)->tc_pending_md_changes >= 	\
	      MAX_CHANGE_INFOS_PER_PAGE))) ? 0 : 1)

#define should_wakeup_monitor_thread(vm_cx_sess, get_cx_notify) 	\
	(((!(vm_cx_sess->vcs_flags & VCS_CX_PRODUCT_ISSUE) &&       	\
	     (get_cx_notify->ullMinConsecutiveTagFailures <=        	\
	        vm_cx_sess->vcs_num_consecutive_tag_failures)) ||   	\
	        vm_cx_sess->vcs_timejump_ts) ? 1 : 0)

target_context_t *target_context_ctr(void);
void target_context_dtr(target_context_t *);
inm_s32_t tgt_ctx_spec_init(target_context_t *, inm_dev_extinfo_t *);
inm_s32_t tgt_ctx_common_init(target_context_t *, struct inm_dev_extinfo *);
void tgt_ctx_common_deinit(target_context_t *);
void tgt_ctx_spec_deinit(target_context_t *);
int check_for_tc_state(target_context_t *, int);
void wake_up_tc_state(target_context_t *);
target_context_t *get_tgt_ctxt_from_uuid_locked(char *);
target_context_t *get_tgt_ctxt_from_device_name_locked(char *);
target_context_t *get_tgt_ctxt_from_scsiid_locked(char *);
target_context_t *get_tgt_ctxt_from_scsiid(char *);
target_context_t *get_tgt_ctxt_from_uuid(char *);
target_context_t *get_tgt_ctxt_from_uuid_nowait(char *);
target_context_t *get_tgt_ctxt_from_uuid_nowait_locked(char *);
target_context_t *get_tgt_ctxt_from_name_nowait(char *id);
target_context_t *get_tgt_ctxt_from_name_nowait_locked(char *id);
void target_context_release(target_context_t *);
inm_s32_t stack_host_dev(target_context_t *ctx, inm_dev_extinfo_t *dinfo);
target_context_t * get_tgt_ctxt_persisted_name_nowait_locked(char *);

static_inline void get_tgt_ctxt(target_context_t *ctxt)
{
	INM_ATOMIC_INC(&(ctxt)->refcnt);
}

static_inline void put_tgt_ctxt(target_context_t *ctxt)
{
	if (INM_ATOMIC_DEC_AND_TEST(&(ctxt->refcnt))) {
		dbg("put_tgt_ctxt- target context ref count:%d", ctxt->refcnt);
			if(ctxt->release){
				ctxt->release(ctxt);
		}
	}
}

inm_s32_t can_switch_to_data_filtering_mode(target_context_t *);
inm_s32_t can_switch_to_data_wostate(target_context_t *);

inm_s32_t set_tgt_ctxt_filtering_mode(target_context_t *tgt_ctxt,
				flt_mode filtering_mode, inm_s32_t service_initiated);
inm_s32_t set_tgt_ctxt_wostate(target_context_t *, etWriteOrderState, inm_s32_t,
	                           etWOSChangeReason);

void set_malloc_fail_error(target_context_t * tgt_ctxt);

void volume_lock_irqsave(target_context_t *);
void volume_unlock_irqrestore(target_context_t *);
void volume_lock_bh(target_context_t *);
void volume_unlock_bh(target_context_t *);

inm_s32_t is_data_filtering_enabled_for_this_volume(target_context_t *vcptr);
void fs_freeze_volume(target_context_t *, struct inm_list_head *head);
void thaw_volume(target_context_t *, struct inm_list_head *head);
inm_s32_t inm_dev_guid_cmp(target_context_t *, char *);
inm_dev_t inm_dev_id_get(target_context_t *);
inm_dev_t inm_dev_id_get(target_context_t *);
inm_u64_t inm_dev_size_get(target_context_t *);
void tgt_ctx_force_soft_remove(target_context_t *);
void target_forced_cleanup(target_context_t *);
inm_s32_t filter_guid_name_val_get(char *, char *);
inm_s32_t filter_ctx_name_val_set(target_context_t *, char *, int);
void inm_do_clear_stats(target_context_t *tcp);
inm_s32_t inm_validate_tc_devattr(target_context_t *tcp, inm_dev_info_t *dip);

char *get_volume_override(target_context_t *vcptr);
void start_notify_completion(void);
inm_u32_t get_data_source(target_context_t *);
void do_clear_diffs(target_context_t *tgt_ctxt);
void add_changes_to_pending_changes(target_context_t *, etWriteOrderState, inm_u32_t);
void subtract_changes_from_pending_changes(target_context_t *, etWriteOrderState, inm_u32_t);
void collect_latency_stats(inm_latency_stats_t *lat_stp, inm_u64_t time_in_usec);
void retrieve_volume_latency_stats(target_context_t *, VOLUME_LATENCY_STATS *);

inm_u64_t get_rpo_timestamp(target_context_t *ctxt, inm_u32_t flag,
	                        struct _change_node *pending_confirm);
void inm_tc_reserv_init(target_context_t *ctx, int vol_lock);
void update_cx_session(target_context_t *ctxt, inm_u32_t nr_bytes);
void end_cx_session(void);
void update_cx_with_tag_failure(void);
void update_cx_with_tag_success(void);
void update_cx_with_s2_latency(target_context_t *ctxt);
void update_cx_with_time_jump(inm_u64_t cur_time, inm_u64_t prev_time);
void close_disk_cx_session(target_context_t *ctxt, int reason_code);
void update_cx_session_with_committed_bytes(target_context_t *ctxt, inm_s32_t committed_bytes);
void update_cx_product_issue(int flag);
void reset_s2_latency_time(void);
void add_disk_sess_to_dc(target_context_t *ctxt);
void remove_disk_sess_from_dc(target_context_t *ctxt);
void volume_lock_all_close_cur_chg_node(void);
void volume_unlock_all(void);
#endif
