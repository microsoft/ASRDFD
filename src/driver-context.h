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

#ifndef LINVOLFLT_DRIVER_CONTEXT_H
#define LINVOLFLT_DRIVER_CONTEXT_H

#include "inm_utypes.h"
#include "telemetry-types.h"

#define DC_FLAGS_BITMAP_WORK_ITEM_POOL_INIT      0x00004000
#define DC_FLAGS_WORKQUEUE_ENTRIES_POOL_INIT     0x00000400
#define DC_FLAGS_SERVICE_STATE_CHANGED           0x00001000
#define DC_FLAGS_TARGET_MODULE_REGISTERED        0x00020000
#define DC_FLAGS_SYSTEM_SHUTDOWN                 0x00100000
#define DC_FLAGS_INVOLFLT_LOAD                   0x00200000
#define DC_FLAGS_REBOOT_MODE                     0x00400000

typedef struct __dc_statistics {
	inm_u32_t num_malloc_fails;
	inm_atomic_t pending_chg_nodes;
} dc_stats_t;


typedef struct __dc_tunable_params {
	/* thresholds */
	inm_u32_t db_high_water_marks[MAX_SERVICE_STATES];
	inm_u32_t db_low_water_mark_while_service_running;
	inm_u32_t db_topurge_when_high_water_mark_is_reached;
	inm_u32_t max_data_pages_per_target;
	inm_s32_t free_percent_thres_for_filewrite;
	inm_s32_t volume_percent_thres_for_filewrite;
	inm_s32_t free_pages_thres_for_filewrite;
	inm_u32_t max_data_size_per_non_data_mode_drty_blk;
	inm_s32_t enable_data_filtering;
	inm_s32_t enable_data_filtering_for_new_volumes;
	inm_s32_t enable_data_file_mode;
	inm_s32_t enable_data_file_mode_for_new_volumes;
	inm_u64_t data_to_disk_limit;
	inm_s32_t db_notify;
	inm_u32_t data_pool_size;        	/* in terms of MB */
	inm_u32_t max_data_pool_percent; 	/* in terms of %age */
	inm_u32_t volume_data_pool_size; 	/* in terms of MB */
	char data_file_log_dir[INM_PATH_MAX];
	inm_u32_t max_data_sz_dm_cn;		/* max data size that a change node can hold in data mode*/
	inm_u32_t max_sz_md_coalesce;		/* max coalesce size for a change */
	inm_u32_t percent_change_data_pool_size;
	inm_u32_t time_reorg_data_pool_sec;
	inm_u32_t time_reorg_data_pool_factor;
	inm_u32_t vacp_iobarrier_timeout;
	inm_u32_t fs_freeze_timeout;
	inm_u32_t vacp_app_tag_commit_timeout;
	inm_u32_t enable_recio;
	inm_u32_t stable_pages;
	inm_u32_t enable_chained_io;
} dc_tune_params_t;

typedef struct __kernel_thread_t {
	inm_s32_t initialized;
	inm_atomic_t wakeup_event_raised;
	inm_atomic_t shutdown_event_raised;

	inm_wait_queue_head_t wakeup_event;
	inm_wait_queue_head_t shutdown_event;

	inm_completion_t _completion;
	inm_completion_t _new_event_completion;
} kernel_thread_t;

struct drv_ctx_host_info {
	/* This list maintains list of request queue structures that we modified
	 * its make request function.
	 */
	struct inm_list_head        rq_list;
	inm_spinlock_t          rq_list_lock;
#ifndef INM_AIX
	inm_kmem_cache_t        *bio_info_cache;
#endif
	inm_kmem_cache_t        *mirror_bioinfo_cache;
#ifdef INM_AIX
	inm_kmem_cache_t        *data_file_node_cache;
#endif
};

struct drv_ctx_fabric_info {
	void    *target_priv;
};

struct drv_ctx_bmap_info {
	struct inm_list_head head_for_volume_bitmaps;
	inm_kmem_cache_t    *iob_obj_cache;	/*iobuffer object Lookasidelist*/
	inm_kmem_cache_t    *iob_data_cache;	/*iobuffer data Lookaside list*/
	inm_mempool_t       *iob_obj_pool;
	inm_mempool_t       *iob_data_pool;
	inm_kmem_cache_t    *bitmap_work_item_pool;
	inm_u32_t        max_bitmap_buffer_memory;
	inm_u32_t        current_bitmap_buffer_memory;
	inm_u32_t        bitmap_512K_granularity_size;
	unsigned long    num_volume_bitmaps;
	iobuffer_t      write_filtering_obj;
};

#ifdef INM_AIX
typedef struct _queue_buf_thread {
	inm_atomic_t		qbt_pending;
	inm_completion_t	qbt_exit;
	inm_completion_t	qbt_completion;
}inm_queue_buf_thread_t;

typedef struct _inm_cdb_dev_entry{
	struct inm_list_head  this_entry;
	char cdb_devname[INM_GUID_LEN_MAX];
	struct file *cdb_fp;
} inm_cdb_dev_entry_t;
#endif

/* Maintains VM level CX session */
typedef struct _vm_cx_session {
	/* Flags */
	inm_u64_t    vcs_flags;
	/* Transaction ID */
	inm_u64_t    vcs_transaction_id;
	/* Number of disk CX sessions */
	inm_u64_t    vcs_num_disk_cx_sess;
	/* CX session start time */
	inm_u64_t    vcs_start_ts;
	/* CX session end time */
	inm_u64_t    vcs_end_ts;
	/* This is the base time to calculate 1s intervals */
	inm_u64_t    vcs_base_secs_ts;
	/* Bytes tracked */
	inm_u64_t    vcs_tracked_bytes;
	/* Bytes drained */
	inm_u64_t    vcs_drained_bytes;
	/* Bytes tracked every second */
	inm_u64_t    vcs_tracked_bytes_per_second;
	/* Churn buckets */
	inm_u64_t    vcs_churn_buckets[DEFAULT_NR_CHURN_BUCKETS];
	/* Disk level supported peak churn */
	inm_u64_t    vcs_default_disk_peak_churn;
	/* VM level supported peak churn */
	inm_u64_t    vcs_default_vm_peak_churn;
	/* Max peak churn */
	inm_u64_t    vcs_max_peak_churn;
	/* Time of first peak churn */
	inm_u64_t    vcs_first_peak_churn_ts;
	/* Time of first peak churn */
	inm_u64_t    vcs_last_peak_churn_ts;
	/* Excess churn on top of peak churn */
	inm_u64_t    vcs_excess_churn;
	/* Number of consecutive tag failres observed */
	inm_u64_t    vcs_num_consecutive_tag_failures;
	/* Time Jump timestamp */
	inm_u64_t    vcs_timejump_ts;
	/* Time Jump in msec */
	inm_u64_t    vcs_max_jump_ms;
	/* Drainer latency */
	inm_u64_t    vcs_max_s2_latency;
	/* CS session number */
	inm_u32_t    vcs_nth_cx_session;
} vm_cx_session_t;

#define VCS_CX_SESSION_STARTED 0x0001
#define VCS_CX_SESSION_ENDED   0x0002
#define VCS_CX_S2_EXIT         0x0004
#define VCS_CX_SVAGENT_EXIT    0x0008
#define VCS_CX_TAG_FAILURE     0x0010
#define VCS_CX_PRODUCT_ISSUE   0x0020
#define VCS_CX_TIME_JUMP_FWD   0x0040
#define VCS_CX_TIME_JUMP_BWD   0x0080
#define VCS_CX_UNSUPPORTED_BIO 0x0100

#define VCS_NUM_CONSECTIVE_TAG_FAILURES_ALLOWED 3

#define DISK_LEVEL_SUPPORTED_CHURN (25 * 1024 * 1024) /* 25MB */
#define VM_LEVEL_SUPPORTED_CHURN   (50 * 1024 * 1024) /* 50MB */

#define FORWARD_TIMEJUMP_ALLOWED  180000  /* in msecs = 3 mins */
#define BACKWARD_TIMEJUMP_ALLOWED 3600000 /* in msecs = 60 mins */

#define DC_AT_INTO_INITING   0x1
#define DC_AT_INTO_INITED   0x2

/* This structure holds generic information about involflt target. There will
 * be one instance of this structure created and initialized during involflt
 * module load.
 */
typedef struct _driver_context {
	/* This lock is used to synchronize access to tgt_list structure. */
	inm_rwsem_t tgt_list_sem;
#ifdef INM_AIX
	inm_spinlock_t tgt_list_lock;
#endif

	/* Doubly linked list of target context. One target context created
	 * per filter target and target specific information is stored here.
	 */
	struct inm_list_head tgt_list;
	
	/* service state */
	svc_state_t service_state;
	inm_s32_t s2_started;

	/* This points to number of volumes that are being tracked currently */
	inm_u16_t total_prot_volumes;
	inm_u16_t host_prot_volumes;
	inm_u16_t mirror_prot_volumes;

	/* This structure hold information specific to data mode filtering. */
	data_flt_t data_flt_ctx;

	inm_dev_t flt_dev;
	inm_cdev_t flt_cdev;

	inm_spinlock_t tunables_lock;
	dc_tune_params_t tunable_params;

	/* per io time stamp, seqno file names */
	char driver_time_stamp[INM_PATH_MAX];
	void *driver_time_stamp_handle;

	char driver_time_stamp_seqno[INM_PATH_MAX];
	void *driver_time_stamp_seqno_handle;

	char driver_time_stamp_buf[NUM_CHARS_IN_LONGLONG + 1 ];

	/* 6.25% of system memory */
	inm_u32_t default_data_pool_size_mb;
	/* Total unreserved pages for the driver context */
	inm_u32_t dc_cur_unres_pages;
	/* Mark if data pool allocation is complete */
	int dc_pool_allocation_completed;
	/* Total reserved pages for target contexts */
	inm_u32_t dc_cur_res_pages;
	/* Page reservations for new volume context based on tunable*/
	inm_u32_t dc_vol_data_pool_size;

	dc_stats_t stats;    /* statistics info */

	/* service thread */
	kernel_thread_t service_thread;

	/* This lock is used to synchronize access to various logging events
	 * and statistic info
	 **/
	inm_spinlock_t log_lock;

	/* there is a check in metadata mode, for the follwoing flag */
	inm_u8_t enable_data_filtering;
	/* bitmap mode */
	inm_dev_t root_dev;
#ifdef INM_AIX
	struct file *root_filp;
#endif
	inm_u32_t sys_shutdown;
	/* to keep track of allocation of buffers */
	inm_u32_t flags;

	inm_kmem_cache_t *wq_entry_pool;
	workq_t wqueue;

	inm_u32_t service_supports_data_filtering;
	inm_u32_t enable_data_files;
	inm_pid_t     sentinal_pid;
	inm_pid_t     svagent_pid;
	inm_devhandle_t *svagent_idhp;
	inm_devhandle_t *sentinal_idhp;

	/* Data Structures to maintain unique timestamps across all volumes. */
	inm_spinlock_t time_stamp_lock;
	inm_u64_t last_time_stamp;
	inm_u64_t last_time_stamp_seqno;

	/* reserved memory pool */
	inm_spinlock_t page_pool_lock;
	struct inm_list_head page_pool;
	inm_u32_t dc_res_cnode_pgs;
	
	/* shutdown related data */
	inm_completion_t shutdown_completion;

	/* Binary semaphore to serialize issuing tags */
	inm_sem_t tag_sem;	
	struct drv_ctx_host_info  dc_host_info;
	struct drv_ctx_fabric_info   dc_fabric_info;
	struct drv_ctx_bmap_info    dc_bmap_info;

	/* lock to protect a_ops list */
#ifdef INM_QUEUE_RQ_ENABLED
	inm_spinlock_t dc_inmaops_lock;		/* lock to protect a_ops list */
#else 	
	inm_rwsem_t dc_inmaops_sem;
#endif	
	/* inma_ops list for handling recursive writes */
	/* list of duplicated address space operations */
	struct inm_list_head dc_inma_ops_list;
	inm_atomic_t	involflt_refcnt;
	inm_u32_t		clean_shutdown;
	inm_u32_t           unclean_shutdown;
	inm_u32_t		dc_flags;
	inm_spinlock_t	clean_shutdown_lock;
	inm_rwsem_t tag_guid_list_sem;
	struct inm_list_head tag_guid_list;
#ifdef INM_SOLARIS
	inm_dev_open_t dev_major_open;
#else
	inm_dc_at_lun_info_t dc_at_lun;
#endif
#ifdef INM_AIX
	inm_sem_t dc_mxs_sem;	
	struct inm_list_head dc_mxs_list;
	inm_queue_buf_thread_t dc_qbt;
	pid_t		   dc_qbt_pid;
#endif
	inm_spinlock_t	recursive_writes_meta_list_lock;
	inm_list_head_t	recursive_writes_meta_list;

	/* freeze volume list, head of freeze volume list*/
	struct inm_list_head freeze_vol_list;

	/* To protect freeze_vol_list */
	inm_sem_t         dc_freezevol_mutex;
	
	/* flag to maintain the state of driver with io barrier */
	inm_atomic_t      is_iobarrier_on;
	/* Consistency Point State      */
	inm_u32_t         dc_cp;
	/* App/Crash consistency guid   */
	char              dc_cp_guid[GUID_LEN];
	/* To sync App/Crash consstency */
	inm_sem_t         dc_cp_mutex;
	workq_t           dc_tqueue;
	driver_telemetry_t dc_tel;
	/* Last Chance Writes */
	inma_ops_t        *dc_lcw_aops;
	void              *dc_lcw_rhdl;
	int               dc_lcw_rflag;

	struct _target_context *dc_root_disk;

	/* CX related */
	vm_cx_session_t dc_vm_cx_session;
	inm_spinlock_t  dc_vm_cx_session_lock;
	unsigned long   dc_vm_cx_session_lock_flag;
	inm_u16_t       total_prot_volumes_in_nwo;
	inm_u64_t       dc_disk_level_supported_churn;
	inm_u64_t       dc_vm_level_supported_churn;
	inm_u64_t       dc_nth_cx_session;
	inm_u64_t       dc_transaction_id;
	inm_wait_queue_head_t dc_vm_cx_session_waitq;
	inm_list_head_t dc_disk_cx_stats_list;
	inm_list_head_t dc_disk_cx_sess_list;
	inm_u16_t       dc_num_disk_cx_stats;
	inm_u16_t       dc_num_consecutive_tags_failed;
	inm_u64_t       dc_max_fwd_timejump_ms;
	inm_u64_t       dc_max_bwd_timejump_ms;
	inm_u16_t       dc_wokeup_monitor_thread;
	inm_u32_t       dc_verifier_on;
	inm_spinlock_t  dc_verifier_lock;
	char            *dc_verifier_area;
	inm_spinlock_t  dc_tag_commit_status;
	inm_atomic_t    dc_nr_tag_commit_status_pending_disks;
	inm_atomic_t    dc_tag_commit_status_failed;
	inm_wait_queue_head_t dc_tag_commit_status_waitq;
	inm_u16_t       dc_wokeup_tag_drain_notify_thread;
	char            *dc_tag_drain_notify_guid;
	inm_u32_t       dc_tag_commit_notify_flag;
#ifdef INM_QUEUE_RQ_ENABLED
	inm_completion_t dc_alloc_thread_started;
	inm_wait_queue_head_t dc_alloc_thread_waitq;
	inm_completion_t dc_alloc_thread_exit;
	struct task_struct *dc_alloc_thread_task;
	inm_atomic_t     dc_nr_bioinfo_allocs_failed;
	inm_atomic_t     dc_nr_chgnode_allocs_failed;
	inm_atomic_t     dc_nr_metapage_allocs_failed;
	inm_atomic_t     dc_alloc_thread_quit;
	inm_atomic_t     dc_nr_bioinfo_alloced;
	inm_atomic_t     dc_nr_chdnodes_alloced;
	inm_atomic_t     dc_nr_metapages_alloced;
	inm_atomic_t     dc_nr_bioinfo_alloced_from_pool;
	inm_atomic_t     dc_nr_chgnodes_alloced_from_pool;
	inm_atomic_t     dc_nr_metapages_alloced_from_pool;
	inm_list_head_t  dc_bioinfo_list;
	inm_list_head_t  dc_chdnodes_list;
	TIME_STAMP_TAG_V2 dc_crash_tag_timestamps;
#endif
} driver_context_t; 

void lock_inmaops(bool write, unsigned long* lock_flag);
void unlock_inmaops(bool write, unsigned long* lock_flag);


#define INM_CP_NONE                 0
#define INM_CP_APP_ACTIVE           1
#define INM_CP_CRASH_ACTIVE         2
#define INM_CP_TAG_COMMIT_PENDING   4
#define INM_CP_SHUTDOWN             8

#define SYS_UNCLEAN_SHUTDOWN	0x1
#define SYS_CLEAN_SHUTDOWN	0x2
#define DRV_MIRROR_NOT_SUPPORT  0x4
#define DRV_DUMMY_LUN_CREATED   0x8

inm_s32_t init_driver_context(void);
void free_driver_context(void);
void add_tc_to_dc(struct _target_context *);
void remove_tc_from_dc(struct _target_context *);
void inm_svagent_exit(void); 
void inm_s2_exit(void);

/* global pool management */
inm_s32_t alloc_cache_pools(void);
inm_s32_t dealloc_cache_pools(void);
void balance_page_pool(int, int);

#endif
