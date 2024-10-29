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

#ifndef _INMAGE_TUNABLE_PARAMS_H
#define _INMAGE_TUNABLE_PARAMS_H

#include "involflt-common.h"

/* Memory quotas in percentage based on total data pool size */
#define DEFAULT_DATA_POOL_SIZE_MB                       0x40    /* in MB, 64MB */
#define DEFAULT_MAX_DATA_POOL_PERCENTAGE                0x32    /* in %age(50i%) */
#define DEFAULT_VOLUME_DATA_POOL_SIZE_MB                                    \
	         ((2 * DEFAULT_MAX_DATA_SZ_PER_CHANGE_NODE) >> MEGABYTE_BIT_SHIFT)
#define DEFAULT_DB_HIGH_WATERMARK_SERVICE_NOT_STARTED   0x2000  /* 8K Changes */
#define DEFAULT_DB_LOW_WATERMARK_SERVICE_RUNNING        0x4000  /* 16K Changes */
#define DEFAULT_DB_HIGH_WATERMARK_SERVICE_RUNNING       0x10000 /* 64K Changes */
#define DEFAULT_DB_HIGH_WATERMARK_SERVICE_SHUTDOWN      0x0800  /* 2K Changes */
#define DEFAULT_DB_TO_PURGE_HIGH_WATERMARK_REACHED      0x2000  /* 8K */
#define DEFAULT_FREE_THRESHOLD_FOR_FILEWRITE		0x14
#define DEFAULT_VOLUME_THRESHOLD_FOR_FILEWRITE		0x28
#define DEFAULT_VOLUME_DATA_TO_DISK_LIMIT_IN_MB		0x100   /* 256MB */
#define DEFAULT_VOLUME_DATALOG_DIR 			"/usr/local/InMage/Vx/ApplicationData"
#define DEFAULT_MAX_DATA_PAGES_PER_TARGET		0x2000  /*8192 pages */
#define DEFAULT_SEQNO					0x0
#define DEFAULT_TIME_STAMP_VALUE			0x0
#define PERSISTENT_SEQNO_THRESHOLD			0x400   /*1024 */
#define RELOAD_TIME_SEQNO_JUMP_COUNT			0xF4240	/*1 million */
#define INM_INCR_DPS_LIMIT_ON_APP			2048
#define INM_DEFAULT_DPS_APPLIANCE_DRV			2       /* To make 1/4 that is 25% of total size */
#define INM_DEFAULT_VOLUME_MXS				0x40000	/* Max tranfer size of a device for aix */

#define DEFAULT_MAX_DATA_SIZE_PER_NON_DATA_MODE_DIRTY_BLOCK   (64 * 1024 * 1024)    /*in KBytes = 64MB */
#define DEFAULT_MAX_COALESCED_METADATA_CHANGE_SIZE      0x100000 /* 1MB */
#define DEFAULT_PERCENT_CHANGE_DATA_POOL_SIZE           0x5
#define DEFAULT_REORG_THRSHLD_TIME_SEC 0xa /* 10 sec */
#define DEFAULT_REORG_THRSHLD_TIME_FACTOR 0x3

/* bitmap related constants */
#define DEFAULT_MAXIMUM_BITMAP_BUFFER_MEMORY 	(0x100000 * 65)	/*65 MBytes*/

#define DEFAULT_BITMAP_512K_GRANULARITY_SIZE	(512)


/* The last bucket has to be always zero. */
#define VC_DEFAULT_IO_SIZE_BUCKET_0     0x200    /* 512 */
#define VC_DEFAULT_IO_SIZE_BUCKET_1     0x400    /* 1K */
#define VC_DEFAULT_IO_SIZE_BUCKET_2     0x800    /* 2K */
#define VC_DEFAULT_IO_SIZE_BUCKET_3     0x1000   /* 4K */
#define VC_DEFAULT_IO_SIZE_BUCKET_4     0x2000   /* 8K */
#define VC_DEFAULT_IO_SIZE_BUCKET_5     0x4000   /* 16K */
#define VC_DEFAULT_IO_SIZE_BUCKET_6     0x10000  /* 64K */
#define VC_DEFAULT_IO_SIZE_BUCKET_7     0x40000  /* 256K */
#define VC_DEFAULT_IO_SIZE_BUCKET_8     0x100000 /* 1M */
#define VC_DEFAULT_IO_SIZE_BUCKET_9     0x400000 /* 4M */
#define VC_DEFAULT_IO_SIZE_BUCKET_10    0x800000 /* 8M */
#define VC_DEFAULT_IO_SIZE_BUCKET_11    0x0      /* > 8M */

#define DEFAULT_LOG_DIRECTORY_VALUE         "/root/InMageVolumeLogs"

void init_driver_tunable_params(void);
inm_u32_t get_data_page_pool_mb(void);

/* Be careful when modifying this. Ensure this directory gets created in sysfs_involflt_init()
 */

struct volume_attribute {
	struct attribute attr;
	inm_s32_t (*show)(target_context_t *, char *);
	inm_s32_t (*store)(target_context_t *, char *, const char *, inm_s32_t);
	char *file_name;
	void (*read)(target_context_t *, char *);
};

#define VOLUME_ATTR(_struct_name, _name, _mode, _show, _store, _read)					\
struct volume_attribute _struct_name = {								\
	.attr = { .name = _name, .mode = _mode},          						\
	.show = (inm_s32_t (*)(target_context_t *, char *)) _show, 				\
	.store = (inm_s32_t (*)(target_context_t *, char *, const char *, inm_s32_t)) _store,	\
	.file_name = _name,                							\
	.read =(void (*)(target_context_t *, char *)) _read,  					\
}

/* Sysfs definitions for common objects
 */
#define COMMON_ATTR_NAME "common"

struct common_attribute {
	struct attribute attr;
	inm_s32_t (*show)(char *);
	inm_s32_t (*store)(const char *, const char *, size_t);
	char *file_name;
	inm_s32_t (*read)(char *);
};

#define COMMON_ATTR(_struct_name, _name, _mode, _show, _store, _read)			\
struct common_attribute _struct_name = {    						\
	     .attr = { .name = _name, .mode = _mode},          				\
	     .show = (inm_s32_t(*)(char*)) _show,        				\
	     .store = (inm_s32_t (*)(const char *, const char *, size_t)) _store,    	\
	     .file_name = _name,                					\
	     .read = (inm_s32_t (*)(char *)) _read,                    			\
}

#ifndef _TARGET_VOLUME_CTX
#define _TARGET_VOLUME_CTX
#define TARGET_VOLUME_DIRECT_IO     0x00000001
typedef struct initiator_node {
	struct inm_list_head init_list;
	char *initiator_wwpn;       /* Can be FC wwpn or iSCSI iqn name */
	inm_u64_t timestamp;        /* Last IO timestamp */
} initiator_node_t;

typedef struct target_volume_ctx
{
	target_context_t *vcptr;
	inm_u32_t bsize;
	inm_u64_t nblocks;
	inm_u32_t virt_id;
	inm_atomic_t remote_volume_refcnt;
	/* keep track of last write that the initiaitor has performed. */
	char initiator_name[MAX_INITIATOR_NAME_LEN];
	char pt_guid[INM_GUID_LEN_MAX];
	inm_u32_t flags;
	struct inm_list_head init_list; /* list of "initiator_list_t" */
} target_volume_ctx_t;
#endif  /*_TARGET_VOLUME_CTX */

struct _inm_attribute;
inm_s32_t sysfs_involflt_init(void);
inm_s32_t sysfs_init_volume(target_context_t *, char *pname);
void load_driver_params(void);
void load_volume_params(target_context_t *ctxt);
void is_filtering_disabled_for_path(char *, int);
int set_int_vol_attr(target_context_t *, enum volume_params_idx , int);
void set_string_vol_attr(target_context_t *, enum volume_params_idx , char *);
void set_longlong_vol_attr(target_context_t *, enum volume_params_idx , inm_s64_t );
void set_unsignedlonglong_vol_attr(target_context_t *, enum volume_params_idx, inm_u64_t);
inm_s32_t read_value_from_file(char *, inm_s32_t *);
inm_s32_t write_vol_attr(target_context_t * ctxt, const char *file_name, void *buf, inm_s32_t len);
inm_s32_t inm_write_guid_attr(char *tc_guid, enum volume_params_idx index, inm_s32_t len);
inm_s32_t common_get_set_attribute_entry(struct _inm_attribute *);
inm_s32_t volume_get_set_attribute_entry(struct _inm_attribute *inm_attr);
inm_s32_t mirror_dst_id_get(target_context_t *ctxt, char *uuid);
inm_s32_t mirror_dst_id_set(target_context_t *ctxt, char *uuid);
inm_u64_t filter_full_disk_flags_get(target_context_t *ctxt);
ssize_t wrap_common_attr_store(inm_u32_t, const char *, size_t);
inm_s32_t inm_is_upgrade_pname(char *actual, char *upgrade);

/* Performance optmization levels & debugging info */
#define DEFAULT_PERFORMANCE_OPTMIZATION                     0x00000007
#define PERF_OPT_DATA_MODE_CAPTURE_WITH_BITMAP              0x00000001
#define PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO        0x00000002
#define PERF_OPT_METADATA_COALESCE                          0x00000004
#define PERF_OPT_DEBUG_DBLK_FILENAME                        0x00000008
#define PERF_OPT_DEBUG_DATA_DRAIN                           0x00000010
#define PERF_OPT_DEBUG_DBLK_INFO                            0x00000020
#define PERF_OPT_DEBUG_DBLK_CHANGES                         0x00000040
#define PERF_OPT_DEBUG_COALESCED_CHANGES                    0x00000080

#endif /* _INMAGE_TUNABLE_PARAMS_H */
