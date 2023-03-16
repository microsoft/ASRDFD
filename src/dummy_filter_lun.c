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
#include "utils.h"
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
#include "data-mode.h"
#include "driver-context.h"
#include "metadata-mode.h"
#include "statechange.h"
#include "driver-context.h"
#include "filter_lun.h"
#include <linux/uio.h>
#include <linux/ctype.h>
#include <linux/seq_file.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0) && !defined SET_INM_QUEUE_FLAG_STABLE_WRITE
#include <asm/kmap_types.h>
#endif
#include "file-io.h"
#include "target-context.h"

struct scst_cmd {
	void *not_used;
};

struct scst_dev_type {
	void *not_used;
};

struct scst_proc_data {
	void *not_used;
};

/* dummy file to resolve the scst defined symbols */
/* scst_single_seq_open */
inm_s32_t scst_single_seq_open(struct inode *inode, struct file *file)
{
	return -EINVAL;
}

/* scst_set_cmd_error */
void scst_set_cmd_error_status(struct scst_cmd *cmd, inm_s32_t status)
{
	return;
}

/* __scst_register_virtual_dev_driver */
inm_s32_t __scst_register_virtual_dev_driver(struct scst_dev_type *dev_type,
	const char *version)
{
	return -EINVAL;
}

/* scst_set_busy */
void scst_set_busy(struct scst_cmd *cmd)
{
	return;
}

/* scst_sbc_generic_parse */
inm_s32_t scst_sbc_generic_parse(struct scst_cmd *cmd,
	inm_s32_t (*get_block_shift)(struct scst_cmd *cmd))
{
	return -EINVAL;
}

/* scst_register_virtual_device */
inm_s32_t scst_register_virtual_device(struct scst_dev_type *dev_handler,
	const char *dev_name)
{
	return -EINVAL;
}

/* scst_unregister_virtual_device */
void scst_unregister_virtual_device(inm_s32_t id, unsigned int flag)
{
	return;
}

/* scst_unregister_virtual_dev_driver */
void scst_unregister_virtual_dev_driver(struct scst_dev_type *dev_type)
{
	return;
}

/* scst_set_resp_data_len */
void scst_set_resp_data_len(struct scst_cmd *cmd, inm_s32_t resp_data_len)
{
	return;
}

/* scst_create_proc_entry */
struct proc_dir_entry *scst_create_proc_entry(struct proc_dir_entry * root,
	const char *name, struct scst_proc_data *pdata)
{
	return NULL;
}

void scst_set_cmd_error(struct scst_cmd *cmd, inm_s32_t key, inm_s32_t asc,
				inm_s32_t ascq)
{
	return;
}

inm_s32_t register_filter_target()
{
	return 0;
}

inm_s32_t unregister_filter_target()
{
	return 0;
}

inm_s32_t get_lun_query_data(inm_u32_t i, inm_u32_t *ip, LunData *ldp)
{
	return 0;
}

inm_s32_t fabric_volume_init(target_context_t ctx, inm_dev_info_t *dev_info)
{
	return 0;
}


inm_s32_t filter_lun_delete(char *s)
{
	return 0;
}

inm_s32_t get_at_lun_last_write_vi(char* uuid, char *initiator_name)
{
	return 0;
}

inm_s32_t
get_at_lun_last_host_io_timestamp(AT_LUN_LAST_HOST_IO_TIMESTAMP *timestamp)
{
	return 0;
}

inm_s32_t filter_lun_create(char* uuid, inm_u64_t nblks, inm_u32_t bsize,
				inm_u64_t startoff)
{
	return 0;
}

inm_s32_t fabric_volume_deinit(target_context_t *ctx)
{
	return 0;
}

void
copy_iovec_data_to_data_pages(inm_wdata_t *wdatap,
				struct inm_list_head *listhdp)
{
	return;
}

int
inm_validate_fabric_vol(target_context_t *tcp,
			const inm_dev_info_t *dip)
{
	return (0);
}
inm_s32_t 
process_at_lun_create(struct file *filp, void __user *arg)
{
	return(0);
}

inm_s32_t 
process_at_lun_last_write_vi(struct file *filp, void __user *arg)
{
	return(0);
}

inm_s32_t 
process_at_lun_last_host_io_timestamp(struct file *filp, void __user *arg)
{
	return(0);
}

inm_s32_t 
process_at_lun_query(struct file *filp, void __user *arg)
{
	return(0);
}

inm_s32_t 
process_at_lun_delete(struct file *filp, void __user *arg)
{
	return(0);
}

int emd_unregister_virtual_device(int dev_id)
{
	return -1;
}

