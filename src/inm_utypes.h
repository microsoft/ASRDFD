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

#ifndef INM_UTYPES_H
#define	INM_UTYPES_H 

#include <linux/wait.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include "inm_types.h"
#include "inm_list.h"

typedef struct cdev             inm_cdev_t;
typedef dev_t                   inm_dev_t;
typedef pid_t                   inm_pid_t;
typedef unsigned long		inm_addr_t;


typedef struct sysinfo		inm_sysinfo_t;
typedef struct file 		inm_filehandle_t;
typedef struct sysinfo 		inm_meminfo_t;
typedef struct bio		inm_buf_t;

struct drv_open{
	const struct block_device_operations *orig_dev_ops;
	struct block_device_operations mod_dev_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) || defined(RHEL9_4) || defined(SLES15SP6)
	int (*orig_drv_open)(struct gendisk *disk, blk_mode_t mode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	int (*orig_drv_open)(struct block_device *bdev, fmode_t mode);
#else
	int (*orig_drv_open)(struct inode *inode, struct file *filp);
#endif
	inm_atomic_t    nr_in_flight_ops;
	int status;
};

typedef struct drv_open inm_dev_open_t;

typedef struct _inm_dc_at_lun_info{
	inm_spinlock_t dc_at_lun_list_spn;
	struct inm_list_head dc_at_lun_list;
	inm_dev_open_t dc_at_drv_info;
	inm_u32_t dc_at_lun_info_flag;
}inm_dc_at_lun_info_t;

#endif /* INM_UTYPES_H */
