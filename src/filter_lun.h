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

#ifndef _INMAGE_FILTER_TARGET_H_
#define _INMAGE_FILTER_TARGET_H_

#include "change-node.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "driver-context.h"
#include <linux/types.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include "emd.h"

struct _change_node;
struct _volume_context;

#define VOLUME_FILTERING_DISABLED_ATTR "VolumeFilteringDisabled"
#define AT_LUN_TYPE "LunType"
#define AT_BLOCK_SIZE "BlockSize"
//#define isdigit(n)    ((n) >= '0' && (n) <= '9')

#define INM_SECTORS_PER         	63
#define DEF_SECTORS             	56
#define DEF_HEADS               	255
#define MODES_ENSE_BUF_SZ       	256
#define DBD                             0x08    /* disable block descriptor */
#define WP                              0x80    /* write protect */
#define DPOFUA                          0x10    /* DPOFUA bit */
#define WCE                             0x04    /* write cache enable */
#define BYTE                            8

#ifndef _TARGET_VOLUME_CTX
#define _TARGET_VOLUME_CTX
#define TARGET_VOLUME_DIRECT_IO     0x00000001
typedef struct initiator_node {
	struct inm_list_head init_list;
	char *initiator_wwpn;		/* Can be FC wwpn or iSCSI iqn name */
	inm_u64_t timestamp;		/* Last IO timestamp */
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
	/* list of "initiator_node_t" */
	struct inm_list_head init_list;
} target_volume_ctx_t;
#endif  /*_TARGET_VOLUME_CTX */

target_volume_ctx_t *alloc_target_volume_context(void);
inm_s32_t  register_filter_target(void);
inm_s32_t unregister_filter_target(void);
inm_s32_t register_bypass_target(void);
inm_s32_t unregister_bypass_target(void);
inm_s32_t init_emd(void);
void exit_emd(void);
void copy_iovec_data_to_data_pages(inm_wdata_t *, struct inm_list_head *);
inm_s32_t process_at_lun_delete(struct file *, void __user *);

static inline void
update_initiator(target_volume_ctx_t* tvcptr,
	             char *iname)
{
	strncpy_s(tvcptr->initiator_name, MAX_INITIATOR_NAME_LEN, iname,
			MAX_INITIATOR_NAME_LEN - 1);
	tvcptr->initiator_name[MAX_INITIATOR_NAME_LEN - 1] = '\0';
	return;
}

inm_s32_t filter_lun_create(char*, inm_u64_t, inm_u32_t, inm_u64_t);
inm_s32_t filter_lun_delete(char*);
inm_s32_t get_at_lun_last_write_vi(char*,char*);
inm_s32_t get_at_lun_last_host_io_timestamp(AT_LUN_LAST_HOST_IO_TIMESTAMP *);
inm_s32_t get_lun_query_data(inm_u32_t ,inm_u32_t*,LunData*);

#ifdef SV_FABRICLUN_PERSISTENCE
void fabric_set_volume_name(char*,char*);
void fabric_recreate_at_lun(char*);
inm_s32_t fabric_read_persistent_attr(char* fname, char* fabric_attr,
				void **buf, inm_s32_t len, int* bytes_read);
inm_s32_t volume_filter_disabled(char*, int*);
inm_s32_t read_at_lun_block_size(char*, inm_u64_t*);
inm_s32_t read_at_lun_type(char*,LunType*);
#endif /* SV_FABRICLUN_PERSISTENCE */
inm_s32_t inm_validate_fabric_vol(target_context_t *tcp,
					inm_dev_info_t const *dip);
#endif /* _INMAGE_FILTER_TARGET_H_ */
