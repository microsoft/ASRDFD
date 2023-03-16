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

#ifndef _TEL_TYPES_H
#define _TEL_TYPES_H

#define TELEMETRY_SEC_TO_100NSEC(tsec)  (tsec * HUNDREDS_OF_NANOSEC_IN_SECOND)
#define TELEMETRY_MSEC_TO_100NSEC(tsec) (tsec * 10000ULL)

#define TELEMETRY_WTIME_OFF             116444736000000000ULL
#define TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(t)                         \
	  ((t != 0) ? ((t) + TELEMETRY_WTIME_OFF) : (t))

#define TELEMETRY_FMT1601_TIMESTAMP_FROM_SEC(tsec)                          \
	    TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(TELEMETRY_SEC_TO_100NSEC(tsec))

#define TELEMETRY_FILE_REFRESH_INTERVAL 300000  /* in msecs = 5 mins */
#define TELEMETRY_ACCEPTABLE_TIME_JUMP  180000  /* in msecs = 3 mins */
#define TELEMETRY_ACCEPTABLE_TIME_JUMP_THRESHOLD                            \
	    TELEMETRY_MSEC_TO_100NSEC(TELEMETRY_ACCEPTABLE_TIME_JUMP)


typedef enum _etTagStateTriggerReason {
	ecNotApplicable = 1,
	ecBitmapWrite,                      /* Dropped due to bitmap write      */
	ecFilteringStopped,                 /* Dropped as stop filtering issued */
	ecClearDiffs,                       /* Dropped as clear diffs issued    */
	ecNonPagedPoolLimitHitMDMode,       /* Dropped as no metadata pages     */
	ecChangesQueuedToTempQueue,         /* Not Used                         */
	ecRevokeTimeOut,                    /* Tag revoked on timeout           */
	ecRevokeCancelIrpRoutine,           /* Tag revoked on user request      */
	ecRevokeCommitIOCTL,                /* Not Used                         */
	ecRevokeLocalCrash,                 /* Not Used                         */
	ecRevokeDistrubutedCrashCleanupTag, /* Not Used                         */
	ecRevokeDistrubutedCrashInsertTag,  /* Not Used                         */
	ecRevokeDistrubutedCrashReleaseTag, /* Not Used                         */
	ecRevokeAppTagInsertIOCTL,          /* Not Used                         */
	ecSplitIOFailed,                    /* LIN: splitting large io failed   */
	ecOrphan,                           /* LIN: Orphan dropped on drainer exit   */
} etTagStateTriggerReason;

typedef enum _etTagType {
	ecTagNone = 0,
	ecTagLocalCrash,
	ecTagDistributedCrash,
	ecTagLocalApp,
	ecTagDistributedApp,
} etTagType;

typedef enum _etTagStatus {
	ecTagStatusCommited = 0,            /* Successful state                 */
	ecTagStatusPending = 1,             /* Initialized                      */
	ecTagStatusDeleted = 2,             /* Deleted due to StopFlt or ClrDif */
	ecTagStatusDropped = 3,             /* Dropped due to Bitmap writes     */
	ecTagStatusInvalidGUID = 4,         /* Invalig GUID                     */
	ecTagStatusFilteringStopped = 5,    /* Device filtering is stopped      */
	ecTagStatusUnattempted = 6,         /* Tag unattempted for any reason   */
	ecTagStatusFailure = 7,             /* Any error e.g. mem alloc failure */
	ecTagStatusRevoked = 8,             /* Multi phase revoke               */
	ecTagStatusInsertFailure = 9,       /* Tag Insert Failure               */
	ecTagStatusInsertSuccess = 10,      /* Tag Insert Success               */
	ecTagStatusIOCTLFailure = 11,       /* Tag IOCTL failure                */
	ecTagStatusTagCommitDBSuccess = 12, /* Tag committed as part of drain   */
	ecTagStatusTagNonDataWOS = 13,
	ecTagStatusTagDataWOS = 14,
	ecTagStatusMaxEnum
} etTagStatus;

#define TELEMETRY_LINUX_MSG_TYPE    0x60000000

typedef enum _etMessageType {
	ecMsgUninitialized = 1,
	ecMsgCCInputBufferMismatch,
	ecMsgCCInvalidTagInputBuffer,
	ecMsgCompareExchangeTagStateFailure,
	ecMsgValidateAndBarrierFailure,
	ecMsgTagVolumeInSequenceFailure,
	ecMsgInputZeroTimeOut,
	ecMsgAllFilteredDiskFlagNotSet,
	ecMsgInFlightIO,
	ecMsgTagIrpCancelled,
	ecMsgInValidTagProtocolState,
	ecMsgTagInsertFailure = 15,
	ecMsgTagCommitDBSuccess,
	ecMsgTagRevoked,
	ecMsgTagDropped,
	ecMsgPreCheckFailure,
	ecMsgAppInputBufferMismatch,
	ecMsgAppInvalidTagInputBuffer,
	ecMsgAppUnexpectedFlags,
	ecMsgAppInvalidInputDiskNum,
	ecMsgAppOutputBufferTooSmall,
	ecMsgAppTagInfoMemAllocFailure,
	ecMsgAppDeviceNotFound,
	ecMsgStatusNoMemory,
	ecMsgStatusUnexpectedPrecheckFlags,
} etMessageType;

typedef enum _etWOSChangeReason {
	ecWOSChangeReasonUnInitialized = 0,
	eCWOSChangeReasonServiceShutdown = 1,
	ecWOSChangeReasonBitmapChanges = 2,
	ecWOSChangeReasonBitmapNotOpen = 3,
	ecWOSChangeReasonBitmapState = 4,
	ecWOSChangeReasonCaptureModeMD = 5,
	ecWOSChangeReasonMDChanges = 6,
	ecWOSChangeReasonDChanges = 7,
	ecWOSChangeReasonDontPageFault = 8,
	ecWOSChangeReasonPageFileMissed = 9,
	ecWOSChangeReasonExplicitNonWO = 10,
	ecWOSChangeReasonUnsupportedBIO = 11,
} etWOSChangeReason;

typedef enum _etTagProtocolPhase {
	HoldWrites = 1,
	InsertTag,
	ReleaseWrites,
	CommitTag
} etTagProtocolPhase;

/* Used by driver and target context to represent a blended state   */
#define DBS_DIFF_SYNC_THROTTLE          0x0000000000000001  /* Disk         */
#define DBS_SERVICE_STOPPED             0x0000000000000002  /* Driver       */
#define DBS_S2_STOPPED                  0x0000000000000004  /* Driver       */
#define DBS_DRIVER_NOREBOOT_MODE        0x0000000000000008  /* Driver       */
#define DBS_DRIVER_RESYNC_REQUIRED      0x0000000000000010  /* Disk         */
#define DBS_FILTERING_STOPPED_BY_USER   0x0000000000000020  /* Disk         */
#define DBS_FILTERING_STOPPED_BY_KERNEL 0x0000000000000040  /* Disk         */
#define DBS_FILTERING_STOPPED           0x0000000000000080  /* Disk         */
#define DBS_CLEAR_DIFFERENTIALS         0x0000000000000100  /* Disk         */
#define DBS_BITMAP_WRITE                0x0000000000000200  /* Disk         */
#define DBS_NPPOOL_LIMIT_HIT_MD_MODE    0x0000000000000400  /* NA           */
#define DBS_MAX_NONPAGED_POOL_LIMIT_HIT 0x0000000000000800  /* NA           */
#define DBS_LOW_MEMORY_CONDITION        0x0000000000001000  /* NA           */
#define DBS_SPLIT_IO_FAILED		0x0000000000002000  /* NEW          */
#define DBS_ORPHAN			0x0000000000004000  /* NEW          */
// Reserved Fields
#define DBS_TAG_REVOKE_TIMEOUT          0x0000000000010000
#define DBS_TAG_REVOKE_CANCELIRP        0x0000000000020000
#define DBS_TAG_REVOKE_COMMITIOCTL      0x0000000000040000
#define DBS_TAG_REVOKE_LOCALCC          0x0000000000080000
#define DBS_TAG_REVOKE_DCCLEANUPTAG     0x0000000000100000
#define DBS_TAG_REVOKE_DCINSERTIOCTL    0x0000000000200000
#define DBS_TAG_REVOKE_DCRELEASEIOCTL   0x0000000000400000
#define DBS_TAG_REVOKE_APPINSERTIOCTL   0x0000000000800000

#define TEL_FLAGS_SET_BY_DRIVER         0x0400000000000000


/* 
 * Global driver telemetry data: DRIVER_TELEMETRY	
 */
typedef struct driver_telemetry {
	inm_spinlock_t  dt_dbs_slock;               /* Disk Blended State lock  */
	inm_u64_t       dt_blend;		    /* Blended State            */
	inm_u64_t	dt_drv_load_time;	    /* Driver Load Time		*/
	inm_u64_t	dt_svagent_start_time;	    
	inm_u64_t	dt_svagent_stop_time;		
	inm_u64_t	dt_s2_start_time;		    
	inm_u64_t	dt_s2_stop_time;		    
	inm_u64_t	dt_last_tag_request_time;   /* Last Crash* tag req time */
	int             dt_persistent_dir_created;
	inm_u64_t       dt_timestamp_in_persistent_store;
	inm_u64_t       dt_seqno_in_persistent_store;
	inm_u64_t       dt_unstack_all_time;
	inm_u64_t       dt_time_jump_exp;           /* Exp time in case of jump */
	inm_u64_t       dt_time_jump_cur;           /* Act time in case of jump */
} driver_telemetry_t;

/*
 * Stats when moving to non wo statenm_list_splice_init: NON_WOSTATE_STATS
 */
typedef struct non_wo_stats {
	etWriteOrderState   nws_old_state;	    /* Old State		*/
	etWriteOrderState   nws_new_state;	    /* New State		*/
	inm_u64_t	    nws_change_time;	    /* Transition time		*/
	inm_u64_t	    nws_meta_pending;	    /* Metadata changes pending	*/
	inm_u64_t	    nws_bmap_pending;	    /* Bitmap changes pending	*/
	inm_u64_t	    nws_data_pending;	    /* Data changes pending	*/
	inm_u32_t	    nws_nwo_secs;	    /* Time in old state        */
	etWOSChangeReason   nws_reason;		    /* Reason for changes	*/
	inm_u32_t           nws_mem_alloc;	    /* Pages allocated          */
	inm_u32_t           nws_mem_reserved;       /* Pages reserved           */
	inm_u32_t           nws_mem_free;           /* Remaining unreserved pool*/
	inm_u32_t           nws_free_cn;            /* Free change nodes == 0   */
	inm_u32_t           nws_used_cn;            /* Allocated change nodes   */
	inm_u32_t           nws_max_used_cn;        /* Max change nodes == 0    */
	inm_u64_t           nws_blend;              /* Disk blended state       */
	inm_u32_t           nws_np_alloc;           /* NA                       */
	inm_u64_t 			nws_np_limit_time;      /* NA           */
	inm_u32_t           nws_np_alloc_fail;      /* NA                       */
} non_wo_stats_t;

/*
 * Replication stats snapshot at tag insert: TAG_DISK_REPLICATION_STATS
 */
typedef struct tgt_stats {
	inm_u64_t       ts_pending;		/* Pending Changes		*/
	inm_u64_t       ts_tracked_bytes;	/* Bytes tracked		*/
	inm_u64_t       ts_getdb;		/* Dirty Blocks drained		*/
	inm_u64_t       ts_drained_bytes;    	/* Bytes drained		*/
	inm_u64_t       ts_commitdb;		/* Dirty blocks committed	*/
	inm_u64_t       ts_revertdb;		/* Dirty blocks reverted	*/
	inm_u64_t       ts_nwlb1; 		/* Network latency <=150ms	*/
	inm_u64_t       ts_nwlb2;     		/* Network latency <=250ms	*/
	inm_u64_t       ts_nwlb3;	     	/* Network latency <=500ms	*/
	inm_u64_t       ts_nwlb4; 		/* Network latency <=1sec	*/
	inm_u64_t       ts_nwlb5; 		/* Network latency > 1sec	*/
	inm_u64_t       ts_commitdb_failed;	/* Commit DB failed		*/
} tgt_stats_t;

/*
 * Per disk telemetry data: DISK_TELEMETRY
 */
#define TELEMETRY_THROTTLE_IN_PROGRESS    0xffffffffffffffffULL

typedef struct target_telemetry {
	inm_u64_t	tt_getdb; 				/* Dirty blocks drained		*/
	inm_u64_t	tt_commitdb;				/* Drity blocks committed	*/
	inm_u64_t	tt_commitdb_failed;			/* Dirty blocks commit fail 	*/
	inm_u64_t	tt_revertdb; 				/* Resent pending confirm	*/
	inm_u64_t	tt_user_stop_flt_time;			/* Stop flt by user time	*/
	inm_u64_t	tt_prev_tag_time; 			/* Last succ/fail tag time	*/
	inm_u64_t	tt_prev_succ_tag_time;			/* Last success tag time	*/
	inm_u64_t	tt_blend;	    			/* Disk blended state DBS_* 	*/
	tgt_stats_t	tt_prev_succ_stats;			/* Previous succ tag stats	*/
	tgt_stats_t	tt_prev_stats;				/* Previous tag stats		*/
	non_wo_stats_t	tt_nwo;					/* Non write order stats	*/ 
	inm_u64_t       tt_resync_start;            		/* Resync start time        	*/
	inm_u64_t       tt_resync_end;              		/* Resync end time          	*/
	inm_u64_t       tt_getdb_time;              		/* Last get_db time         	*/
	inm_u64_t       tt_commitdb_time;           		/* Last commit_db time      	*/
	inm_u64_t       tt_create_time;             		/* tgt_ctxt create time     	*/
	inm_u64_t       tt_prev_ts;                 		/* Prev commited cn ts      	*/
	inm_u64_t       tt_prev_seqno;              		/* Prev commited cn seq no  	*/
	inm_u64_t       tt_prev_tag_ts;             		/* Prev tag ts              	*/
	inm_u64_t       tt_prev_tag_seqno;          		/* Prev tag seq num         	*/
	inm_u64_t       tt_ds_throttle_start;       		/* Diff sync throttle start 	*/
	inm_u64_t       tt_ds_throttle_stop;        		/* Diff sync throttle stop  	*/
	inm_u64_t       tt_stop_flt_time;           		/* Stop flt time            	*/
	inm_u64_t       tt_start_flt_time_by_user;  		/* User start filtering time	*/
} target_telemetry_t;

/*
 * Global tag telemetry data: TAG_TELEMETRY_COMMON
 */
typedef struct tag_telemetry_common {
	atomic_t	tc_refcnt;                      /* Ref Count            */
	inm_u16_t       tc_ndisks;		        /* Num disks            */
	inm_u16_t       tc_ndisks_prot; 	        /* Num protected disks  */
	inm_u64_t       tc_req_time;                    /* Tag ioctl time       */
	char            tc_guid[GUID_SIZE_IN_CHARS + 1];/* Tag guid             */
	inm_s32_t       tc_ioctl_cmd;                	/* Tag ioctl Called     */
	inm_s32_t       tc_ioctl_status;               	/* Ioctl status         */
	inm_u32_t       tc_ndisks_tagged; 		/* Number disks tagged  */
	etTagType       tc_type;                        /* Tag type             */
} tag_telemetry_common_t;

/*
 * Per disk successful tag telemetry data: TAG_HISTORY
 */
typedef struct tag_history {
	tag_telemetry_common_t *th_tag_common;          /* Common data          */
	inm_u64_t              th_insert_time;          /* Insert time          */
	inm_u64_t              th_prev_tag_time;        /* Prev tag time        */
	inm_u64_t              th_prev_succ_tag_time;   /* Prev succ tag time   */
	inm_s32_t              th_tag_status;           /* Per disk status      */
	inm_u64_t              th_blend;                /* Blended state        */
	inm_u64_t              th_tag_state;            /* Tag state            */
	inm_u64_t              th_commit_time;          /* Tag commit time      */
	inm_u64_t              th_drainbarr_time;       /* Drain barrier time   */
	tgt_stats_t            th_prev_succ_stats;      /* Prev succ tag stats  */ 
	tgt_stats_t            th_prev_stats;           /* Prev tag stats       */
	tgt_stats_t            th_cur_stats;            /* Current stats        */
	void                   *th_tgt_ctxt;
} tag_history_t;

#endif

