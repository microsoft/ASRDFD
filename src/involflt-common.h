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

#ifndef LINVOLFLT_COMMON_H
#define LINVOLFLT_COMMON_H

#include "osdep.h"
#include "safecapismajor.h"

/* KGDB couldn't handle inlined functions correctly. So, when KGDB is enabled, then inline
 * functions are treated as normal functions.
 */
#ifndef static_inline
#ifdef CONFIG_KGDB
# define static_inline    static __attribute__ ((__unused__))
#else
#define static_inline static inline
#endif
#endif

#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC    1000L
#endif
/*
  #define ALLOC_CAN_WAIT_FLAG    INM_KM_SLEEP
  #define ALLOC_CANT_WAIT_FLAG    INM_KM_NOSLEEP
*/
#define MAX_TARGET_NAME_LENGTH    256
#define NUM_CHARS_IN_INTEGER      10
#define NUM_CHARS_IN_LONGLONG     20
#define PERSISTENT_DIR "/etc/vxagent/involflt"

#define DRIVER_NAME "involflt"

#define FALSE   0
#define TRUE    1

	
/* bitmap related constants */
#define MAX_LOG_PATHNAME        (0x200)
#define LOG_FILE_NAME_PREFIX    "InMage-"
#define LOG_FILE_NAME_SUFFIX    ".VolumeLog"

#define GIGABYTES		(1024*1024*1024)
#define MEGABYTES		(0x100000)	/*1024*1024*/
#define KILOBYTES		(0x400)		/*1024*/
#define THIRTY_TWO_K_SIZE	(0x8000)
#define SIXTEEN_K_SIZE		(0x4000)
#define EIGHT_K_SIZE		(0x2000)
#define FOUR_K_SIZE		(0x1000)

#define MEGABYTE_BIT_SHIFT    (0x14) /* 20 bits */

#define ERROR_TO_REG_OUT_OF_MEMORY_FOR_DIRTY_BLOCKS 	0x0001
#define VCF_GUID_OBTAINED	(0x00000200)
#define DEFAULT_DB_NOTIFY_THRESHOLD	DEFAULT_MAX_DATA_SZ_PER_CHANGE_NODE
#define CX_SESSION_PENDING_BYTES_THRESHOLD \
	                     (2 * DEFAULT_MAX_DATA_SZ_PER_CHANGE_NODE) /* 8MB */

#define TAG_VOLUME_MAX_LENGTH 	256 
#define TAG_MAX_LENGTH   	256

/*flag values to pass to the driver*/
#define TAG_VOLUME_INPUT_FLAGS_ATOMIC_TO_VOLUME_GROUP 0x0001
#define TAG_FS_CONSISTENCY_REQUIRED                   0x0002
#define TAG_FS_FROZEN_IN_USERSPACE                    0x0004

struct _tag_info
{
	char tag_name[TAG_MAX_LENGTH];
	unsigned short tag_len;
};

typedef struct _tag_info tag_info_t;

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef INM_MAX
#define INM_MAX(a,b) (((a) > (b)) ? (a) : (b))
#endif

struct _target_context;
#define GIGABYTES           (1024*1024*1024)
#define MEGABYTES           (0x100000)  /* (1024*1024) */
#define KILOBYTES           (0x400)     /* (1024) */

#define FIVE_TWELVE_K_SIZE      (0x80000)
#define TWO_FIFTY_SIX_K_SIZE    (0x40000)
#define ONE_TWENTY_EIGHT_K_SIZE (0x20000)
#define SIXTY_FOUR_K_SIZE   (0x10000)
#define THIRTY_TWO_K_SIZE   (0x8000)
#define SIXTEEN_K_SIZE      (0x4000)
#define EIGHT_K_SIZE        (0x2000)
#define FOUR_K_SIZE         (0x1000)

#define INM_SECTOR_SIZE         512
#define INM_SECTOR_SHIFT        9

#define SINGLE_MAX_WRITE_LENGTH     0x10000     /* (64 KBytes) */
#define MAX_LOG_PATHNAME            (0x200)

#define MAX_NAME_LEN         NAME_MAX   /*255*/
#define MAX_UUID_LEN          128

#define MAX_NR_FS_BLKS_IN_16K	32

#define INM_DEV_BSIZE  512
#define INM_DEV_BSZ_SHIFT 9

static_inline int inm_is_little_endian(void)
{
	inm_u32_t val = 0xabcdef;
	inm_uchar *cp = (inm_uchar *)&val;

	if ((*cp & 0xff) == 0xef) {
		return (1);
	} else {
		return (0);
	}
}

#ifdef INM_DEBUG
#define INM_BUG_ON_TMP(vcptr) \
	if (vcptr->dummy_tc_cur_mode > 0 || vcptr->dummy_tc_dev_state > 0) {                \
	        info("Involflt driver bug %p tc_mode:%u,tc_pmode:%u tc_devst:%u tc_mode1:%u tc_pmode1:%u tc_devst1:%u", vcptr, vcptr->tc_cur_mode, vcptr->tc_prev_mode, vcptr->tc_dev_state,vcptr->dummy_tc_cur_mode, vcptr->dummy_tc_prev_mode, vcptr->dummy_tc_dev_state);                                                 \
	    INM_BUG_ON(1);                                                                      \
	}
#else
#define INM_BUG_ON_TMP(vcptr)
#endif

#define ASYNC_TAG       0
#define SYNC_TAG        1
 
typedef struct tag_guid
{
	struct inm_list_head        tag_list;
	inm_wait_queue_head_t       wq;
	inm_s32_t                   *status;
	char                        *guid;
	inm_u16_t                   guid_len;
	inm_u16_t                   num_vols;
}tag_guid_t;

#define INM_SCSI_VENDOR_ID_SIZE        	10
#define IMPOSSIBLE_SCSI_STATUS         	0xff
#define PAGE_0                          0
#define PAGE_80                         0x80
#define PAGE_83                         0x83
#define VENDOR_LENGTH                   8
#define MODEL_LENGTH                    16

#define WRITE_CANCEL_CDB                0xC0
#define WRITE_CANCEL_CDB_LEN            16
#define VACP_CDB                        0xC2
#define VACP_CDB_LEN                    6
#define HEARTBEAT_CDB                   0xC5
#define HEARTBEAT_CDB_LEN               6

typedef struct disk_cx_stats_info {
	inm_list_head_t        dcsi_list;
	int                    dcsi_valid;
	DEVICE_CXFAILURE_STATS dcsi_dev_cx_stats;
} disk_cx_stats_info_t;

#endif
