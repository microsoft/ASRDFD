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
#include "file-io.h"
#include "metadata-mode.h"
#include "statechange.h"
#include "db_routines.h"
#include "filter_host.h"
#include "filter_lun.h"
#include "errlog.h"
#include <scsi/scsi_host.h>
#include <scsi/scsi_eh.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
#include <scsi/scsi_request.h>
#endif

#include <linux/mount.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30) && \
		LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35))
#include <linux/smp_lock.h>
#endif
#include <linux/reboot.h>

#include "ioctl.h"
#include "tunable_params.h"
#include "telemetry-types.h"
#include "telemetry.h"
#include "last_chance_writes.h"
#include "flt_bio.h"
#include "distro.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0) || defined SLES12 || \
		defined SLES15
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0) || defined SLES12 || \
		defined SLES15 && !defined(SLES15SP6)
#include <linux/slab_def.h>
#endif
#endif

extern driver_context_t *driver_ctx;

atomic_t inm_flt_memprint;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0) || defined(RHEL9_4) || defined(SLES15SP6)
static int
inm_sd_open(struct gendisk *disk, blk_mode_t mode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static int inm_sd_open(struct block_device *bdev, fmode_t mode);
#else
static int inm_sd_open(struct inode *inode, struct file *filp);
#endif

static inm_s32_t inm_one_AT_cdb_send(inm_block_device_t *, unsigned char *,
					inm_u32_t, inm_s32_t,
					unsigned char *, inm_u32_t);
static dc_at_vol_entry_t *alloc_dc_vol_entry(void);
static void free_dc_vol_entry(dc_at_vol_entry_t *at_vol_entry);

#ifdef IDEBUG_MIRROR_IO
extern inm_s32_t inject_atio_err;
extern inm_s32_t inject_ptio_err;
extern inm_s32_t inject_vendorcdb_err;
extern inm_s32_t clear_vol_entry_err;
#endif


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
static inm_s32_t queue_request_scsi(inm_block_device_t *, unsigned char *,
			inm_u32_t , inm_s32_t , unsigned char *, inm_u32_t );
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
static inm_s32_t process_sense_info(char *sense);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
struct task_struct *service_thread_task;
#endif

#ifdef INM_LINUX
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
inm_super_block_t *freeze_bdev(inm_block_device_t *);
void thaw_bdev(inm_block_device_t *, inm_super_block_t *);
#endif
#endif

flt_timer_t cp_timer;

void inm_fvol_list_thaw_on_timeout(wqentry_t *not_used);

inm_s32_t iobarrier_issue_tag_all_volume(tag_info_t *tag_list, int nr_tags, 
						int commit_pending, 
						tag_telemetry_common_t *);
inm_s32_t iobarrier_add_volume_tags(tag_volinfo_t *tag_volinfop,
					tag_info_t *tag_info_listp,
					int nr_tags,
					int commit_pending,
					tag_telemetry_common_t *);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
inm_s64_t
inm_current_kernel_time_secs(void)
{
	inm_timespec ts;

	INM_GET_CURRENT_TIME(ts);

	return ts.tv_sec;
}
#endif

inline int
_inm_xm_mapin(struct _target_context *tgt_ctxt, void *wdatap, 
			 char **map_addr)
{
	return 0;
}

void freeze_volumes(inm_s32_t vols, tag_volinfo_t *vol_list)
{
	inm_s32_t num_vols = 0;

	while (num_vols < vols) {
		if (vol_list->ctxt) {
			fs_freeze_volume(vol_list->ctxt, &vol_list->head);
		}
		num_vols++;
		vol_list++;
	}
}

void unfreeze_volumes(inm_s32_t vols, tag_volinfo_t *vol_list)
{
	inm_s32_t num_vols = 0;

	while (num_vols < vols) {
		if (vol_list->ctxt) {
			thaw_volume(vol_list->ctxt, &vol_list->head);
		}
		num_vols++;
		vol_list++;
	}
}

void lock_volumes(inm_s32_t vols, tag_volinfo_t *vol_list)
{
	inm_s32_t num_vols = 0;

	while(num_vols < vols) {
		if(vol_list->ctxt) {
			INM_SPIN_LOCK_IRQSAVE(&vol_list->ctxt->tc_lock,
					vol_list->ctxt->tc_lock_flag);
		}
		num_vols++;
		vol_list++;
	}
}

void unlock_volumes(inm_s32_t vols, tag_volinfo_t *vol_list)
{
	while(vols > 0) {
		vols--;
		if(vol_list[vols].ctxt) {
			INM_SPIN_UNLOCK_IRQRESTORE(&vol_list[vols].ctxt->tc_lock,
					vol_list[vols].ctxt->tc_lock_flag);
		}
	}
}

#ifdef INM_HANDLE_FOR_BDEV_ENABLED
inm_s32_t
is_rootfs_ro(void)
{
	int retval = 0;
	inm_block_device_t *bdevp = NULL;
	struct bdev_handle *handle = NULL;

	/* check whether root file system is in read only mode */
	handle = inm_bdevhandle_open_by_devnum(driver_ctx->root_dev, FMODE_READ);
	if (IS_ERR(handle))
		return 0;
	bdevp = handle->bdev;
	if (bdev_read_only(bdevp)) {
		dbg("root is read only file system \n");
		retval = 1;
	}
	close_bdev_handle(handle);
	return retval;
}

#else
inm_s32_t
is_rootfs_ro(void)
{
	int retval = 0;
	inm_block_device_t *bdevp = NULL;

		/* check whether root file system is in read only mode */
		bdevp = inm_open_by_devnum(driver_ctx->root_dev, FMODE_READ);
		if (!IS_ERR(bdevp)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
			if (bdev_read_only(bdevp)) {
				dbg("root is read only file system \n");
				retval = 1;
			}
#else
			inm_super_block_t *sbp = get_super(bdevp);
			if (sbp) {
#define INM_FS_RDONLY 1
				if (sbp->s_flags & INM_FS_RDONLY) {
					dbg("root is read only file system \n");
					retval = 1;
				}
				drop_super(sbp);
			}
#endif
			close_bdev(bdevp, FMODE_READ);
		}
	return retval;
}
#endif

inm_u64_t
get_bmfile_granularity(target_context_t *vcptr)
{
	char *buffer = NULL;
	inm_u32_t read = 0;
	void *hdl = NULL;
	inm_u64_t ret = 0;
	logheader_t *hdr = NULL;

	if (!vcptr || !vcptr->tc_bp || !vcptr->tc_bp->bitmap_file_name) {
		dbg("Unable to get bitmap granularity from bitmap file");
		ret = 0;
		return ret;
	}

	if (!flt_open_file(vcptr->tc_bp->bitmap_file_name, O_RDONLY, &hdl)) {
		dbg("Unable to open bitmap granularity from bitmap file");
		return ret;
	}

	buffer = (char *)INM_KMALLOC(INM_SECTOR_SIZE, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!buffer) {
		dbg("Unable to allocate memory while getting bitmap file "
				"granularity from file");
		goto close_return;
	}

	if (flt_read_file(hdl, buffer, 0, INM_SECTOR_SIZE,
					(inm_s32_t *) &read)) {
		hdr = (logheader_t*)buffer;
		ret = hdr->bitmap_granularity;
	}

	flt_close_file(hdl);

	if (buffer) {
		INM_KFREE(buffer, INM_SECTOR_SIZE, INM_KERNEL_HEAP);
		buffer=NULL;
	}
	dbg("Bitmap granularity : %llu",ret);

	return ret;

close_return:
	flt_close_file(hdl);

	return ret;

}

inm_s32_t
dev_validate(inm_dev_extinfo_t *dev_info, host_dev_ctx_t **hdcp)
{
	inm_s32_t ret = 0;
	struct block_device *bdev;
	struct inm_list_head *ptr = NULL,*nextptr = NULL;
	mirror_vol_entry_t *vol_entry;
	host_dev_t *hdc_dev = NULL;
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	struct bdev_handle *handle = NULL;
#endif

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("dev_validate: entered");
	}

	*hdcp = (host_dev_ctx_t *) INM_KMALLOC(sizeof(host_dev_ctx_t),
		       			INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!(*hdcp))
		return 1;

	INM_MEM_ZERO(*hdcp, sizeof(host_dev_ctx_t));
	INM_INIT_LIST_HEAD(&((*hdcp)->hdc_dev_list_head));
	INM_INIT_WAITQUEUE_HEAD(&((*hdcp)->resync_notify));

	switch (dev_info->d_type) {
		case FILTER_DEV_HOST_VOLUME:
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
		handle = inm_bdevhandle_open_by_dev_path(dev_info->d_guid, FMODE_READ);
		if (handle) {
			bdev = handle->bdev;
#else
		bdev = open_by_dev_path(dev_info->d_guid, 0); /* open by device path */
		if (bdev) {
#endif
			hdc_dev = (host_dev_t*)INM_KMALLOC(sizeof(host_dev_t),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
			INM_MEM_ZERO(hdc_dev, sizeof(host_dev_t));
			if (hdc_dev) {
				hdc_dev->hdc_dev = bdev->bd_inode->i_rdev;
				hdc_dev->hdc_disk_ptr = bdev->bd_disk;
				inm_list_add_tail(&hdc_dev->hdc_dev_list,
					&((*hdcp)->hdc_dev_list_head));
			}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
				if (bdev->bd_part) {
				    (*hdcp)->hdc_start_sect = bdev->bd_part->start_sect;
				    (*hdcp)->hdc_actual_end_sect = ((bdev->bd_part->start_sect +
				                              bdev->bd_part->nr_sects) - 1);
				} else {
				    (*hdcp)->hdc_start_sect = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
					(*hdcp)->hdc_end_sect = bdev->bd_disk->part0.nr_sects;
#else
					(*hdcp)->hdc_actual_end_sect = bdev->bd_disk->capacity - 1;
#endif
				}
#else
			(*hdcp)->hdc_start_sect = get_start_sect(bdev);
			(*hdcp)->hdc_actual_end_sect = (*hdcp)->hdc_start_sect +
					get_capacity(bdev->bd_disk) - 1;
#endif
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
			close_bdev_handle(handle);
#else
			close_bdev(bdev, FMODE_READ);
#endif
			return ret;
		}
		ret = INM_EINVAL;
		err("dev_validate: Failed to open the device by path");
		inm_free_host_dev_ctx(*hdcp);
		break;

		case FILTER_DEV_MIRROR_SETUP:
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
		handle = inm_bdevhandle_open_by_dev_path(dev_info->d_guid, FMODE_READ);
		if (handle) {
			bdev = handle->bdev;
#else
		bdev = open_by_dev_path(dev_info->d_guid, 0); /* open by device path */
		if (bdev) {
#endif
			inm_list_for_each_safe(ptr, nextptr, dev_info->src_list) {
				vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);
				if (vol_entry->mirror_dev) {
					if (!(*hdcp)->hdc_end_sect) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
						if (bdev->bd_part) {
							(*hdcp)->hdc_start_sect =
								vol_entry->mirror_dev->bd_part->start_sect;
							(*hdcp)->hdc_actual_end_sect =
								((vol_entry->mirror_dev->bd_part->start_sect +
								vol_entry->mirror_dev->bd_part->nr_sects) - 1);
						} else {
							(*hdcp)->hdc_start_sect = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
							(*hdcp)->hdc_actual_end_sect = 
								vol_entry->mirror_dev->bd_disk->part0.nr_sects;
#else
							(*hdcp)->hdc_actual_end_sect = 
								vol_entry->mirror_dev->bd_disk->capacity - 1;
#endif
						}
#else
						(*hdcp)->hdc_start_sect = get_start_sect(vol_entry->mirror_dev);
						(*hdcp)->hdc_end_sect = get_capacity(vol_entry->mirror_dev->bd_disk);
#endif
					}
					hdc_dev = (host_dev_t*)INM_KMALLOC(sizeof(host_dev_t),
				                                       INM_KM_SLEEP, INM_KERNEL_HEAP);
					INM_MEM_ZERO(hdc_dev, sizeof(host_dev_t));
					if (hdc_dev) {
						hdc_dev->hdc_dev = vol_entry->mirror_dev->bd_inode->i_rdev;
						hdc_dev->hdc_disk_ptr = vol_entry->mirror_dev->bd_disk;
						inm_list_add_tail(&hdc_dev->hdc_dev_list,
								  &((*hdcp)->hdc_dev_list_head));
					}
				} else {
					ret = INM_EINVAL;
					err("dev_validate: Failed to open the device by path");
					break;
				}
			}
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
			close_bdev_handle(handle);
#else
			close_bdev(bdev, FMODE_READ);
#endif
		} else {
			ret = INM_EINVAL;
			err("dev_validate: Failed to open the device by path");
		}
		if (!ret) {
			return ret;
		}
		err("dev_validate: Failed to open the device by path");
		inm_free_host_dev_ctx(*hdcp);
		break;

		case FILTER_DEV_FABRIC_LUN:
		inm_free_host_dev_ctx(*hdcp);
		*hdcp = NULL;
		return ret;

		default:
		ret = INM_EINVAL;
		inm_free_host_dev_ctx(*hdcp);
	}

	return ret;
}

inm_s32_t flt_release(struct inode *inode, struct file *filp)
{
	target_context_t *tgt_ctxt = NULL;

	if (driver_ctx->svagent_idhp == filp) {
		inm_svagent_exit();
	} else if (driver_ctx->sentinal_idhp == filp) {
		inm_s2_exit();
	} else {
		tgt_ctxt =  (target_context_t *)filp->private_data;

		if (tgt_ctxt) {
			put_tgt_ctxt(tgt_ctxt);
			filp->private_data = NULL;
		}
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			dbg("\nthread %u (%s) killed\n", current->pid,
				       		current->comm);
		}
	}

	return 0;
}

target_context_t *get_tgt_ctxt_from_kobj(struct kobject *kobj)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;
	host_dev_ctx_t *hdcp;
	struct inm_list_head *hptr;
	host_dev_t *hdc_dev = NULL;

retry:
	for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
	ptr = ptr->next) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if(check_for_tc_state(tgt_ctxt, 0)){
			tgt_ctxt = NULL;
			goto retry;
		}

		/*
		 * This case in not valid for MIRROR setup as there could be multiple
		 * protected device name to a LUN and one of the name is deleting then
		 * it would be invalid to stop the mirroring on all other devices.
		 * Even more disaster is that a stop filtering process will be done on
		 * mirror device.
		 */

		if (tgt_ctxt->tc_dev_type == FILTER_DEV_HOST_VOLUME) {
			hdcp = (host_dev_ctx_t *) tgt_ctxt->tc_priv;
			__inm_list_for_each(hptr, &hdcp->hdc_dev_list_head) {
				hdc_dev = inm_list_entry(hptr, host_dev_t,
								hdc_dev_list);
				if (kobj == hdc_dev->hdc_disk_kobj_ptr) {
					break;
				}
				hdc_dev = NULL;
			}
			if (hdc_dev) {
				get_tgt_ctxt(tgt_ctxt);
				break;
			}
		}
		tgt_ctxt = NULL;
	}

	return tgt_ctxt;
}

/* tgt_list_sem need to be held by the caller. */
target_context_t *get_tgt_ctxt_from_bio(struct bio *bio)
{
	struct inm_list_head *ptr, *hptr;
	target_context_t *tgt_ctxt = NULL;
	host_dev_ctx_t *hdcp;
	host_dev_t *hdc_dev = NULL;
	sector_t end_sector;
	int found = 0;

	for(ptr = driver_ctx->tgt_list.next;
		ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if (tgt_ctxt->tc_dev_type == FILTER_DEV_HOST_VOLUME ||
			tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			hdcp = (host_dev_ctx_t *) tgt_ctxt->tc_priv;

			__inm_list_for_each(hptr, &hdcp->hdc_dev_list_head) {
				hdc_dev = inm_list_entry(hptr, host_dev_t,
					   			hdc_dev_list);
				if (hdc_dev->hdc_disk_ptr == INM_BUF_DISK(bio))
					break;
				hdc_dev = NULL;
			}
			if (hdc_dev && (hdc_dev->hdc_disk_ptr == INM_BUF_DISK(bio))) {
				end_sector = INM_BUF_SECTOR(bio) + ((INM_BUF_COUNT(bio) + 511) >> 9) - 1;
				if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG_MIRROR_IO)){
					info("get_tgt %s (start:%llu end:%llu) "
						"hdc_start:%llu hdc_end:%llu rw:%d bi_rw:%d",
						tgt_ctxt->tc_guid, 
						(long long unsigned int)INM_BUF_SECTOR(bio), 
						(long long unsigned int)end_sector,
						(long long unsigned int)hdcp->hdc_start_sect, 
						(long long unsigned int)hdcp->hdc_end_sect, 
						(int)(inm_bio_is_write(bio)),
						(int)(inm_bio_rw(bio)));
				}

				if ((INM_BUF_SECTOR(bio) >= hdcp->hdc_start_sect) &&
						(end_sector <= hdcp->hdc_end_sect)) {
					found = 1;
				}

				if (tgt_ctxt->tc_flags & 
						(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)) {
					tgt_ctxt = NULL;
					if (found) break; else continue;
				}
				if (found) break;

				if (tgt_ctxt->tc_flags & VCF_FULL_DEV) {
					/* hdc_actual_end_sect contains the latest size of disk 
					 * extracted from gendisk. if the IO is beyond the latest
					 * size, we assume the disk is resized and mark for resync.
					 */
					volume_lock(tgt_ctxt);
					if (end_sector > hdcp->hdc_actual_end_sect) {
						queue_worker_routine_for_set_volume_out_of_sync(tgt_ctxt,
								ERROR_TO_REG_INVALID_IO, -EINVAL);
						/* Update actual_end_sect to new size so no 
						 * further resyncs are queued 
						 */
						hdcp->hdc_actual_end_sect = 
						get_capacity(hdc_dev->hdc_disk_ptr) - 1;

						err("%s: Resize: Expected: %llu, New: %llu",
							tgt_ctxt->tc_guid, (inm_u64_t)hdcp->hdc_end_sect, 
							(inm_u64_t)hdcp->hdc_actual_end_sect);
					}
					volume_unlock(tgt_ctxt);
				} else {
					if (((INM_BUF_SECTOR(bio) >= hdcp->hdc_start_sect) &&
						(INM_BUF_SECTOR(bio) <= hdcp->hdc_end_sect) &&
						(end_sector > hdcp->hdc_end_sect)) || /* Right Overlap */
						((INM_BUF_SECTOR(bio) < hdcp->hdc_start_sect) &&
						(end_sector >= hdcp->hdc_start_sect) &&
						(end_sector <= hdcp->hdc_end_sect)) ||/* left Overlap */
						((INM_BUF_SECTOR(bio) < hdcp->hdc_start_sect) &&
						(end_sector > hdcp->hdc_end_sect)) || /* Super Set    */
						((INM_BUF_SECTOR(bio) > hdcp->hdc_end_sect) &&
						(INM_BUF_SECTOR(bio) <= hdcp->hdc_actual_end_sect))) {

						err("Unable to handle the spanning I/O across multiple "
							"partitions/volumes");
						queue_worker_routine_for_set_volume_out_of_sync(tgt_ctxt,
								ERROR_TO_REG_INVALID_IO, -EINVAL);
					}
				}
			}
		}
		tgt_ctxt = NULL;
	}

	return tgt_ctxt;
}


/*
 * Convert a device path to a dev_t.
 */
inm_s32_t convert_path_to_dev(const char *path, inm_dev_t *dev)
{
	inm_s32_t r = 0;
	inm_lookup_t nd;
	struct inode *inode = NULL;

	if ((r = inm_path_lookup(path, LOOKUP_FOLLOW, &nd)))
		return r;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	inode = nd.path.dentry->d_inode;
#else
	inode = nd.dentry->d_inode;
#endif
	if (!inode) {
		r = -ENOENT;
		goto out;
	}

	if (!S_ISBLK(inode->i_mode)) {
		r = -ENOTBLK;
		goto out;
	}

	*dev = inode->i_rdev;
	dbg("dev %s i_ino %lu i_rdev %u",path, inode->i_ino, inode->i_rdev);

out:
	inm_path_release(&nd);
	return r;
}

#ifdef INM_HANDLE_FOR_BDEV_ENABLED
struct bdev_handle *
inm_bdevhandle_open_by_dev_path(char *path, int mode)
{
	inm_dev_t dev = 0;
	struct bdev_handle *handle;

	if(!path)
		return NULL;

	handle = bdev_open_by_path(path, mode, NULL, NULL);
	if (IS_ERR(handle))
		return NULL;

	return handle;
}

#else
inm_block_device_t *
open_by_dev_path_v2(char *path, int mode)
{
	inm_dev_t dev = 0;
	inm_block_device_t *bdev;

	if(!path)
		return NULL;

	if(convert_path_to_dev((const char *)path, &dev))
		return NULL;

	bdev = inm_open_by_devnum(dev, mode);
	if(IS_ERR(bdev))
		return NULL;

	return bdev;
}


/* returns bdev ptr using path */
inm_block_device_t *
open_by_dev_path(char *path, int mode)
{
	inm_dev_t dev = 0;
	inm_block_device_t *bdev;

	if(!path)
		return NULL;

	if(convert_path_to_dev((const char *)path, &dev))
		return NULL;

	bdev = inm_open_by_devnum(dev, mode == 0 ? FMODE_READ : FMODE_WRITE);
	if(IS_ERR(bdev))
		return NULL;

	return bdev;
}
#endif

/* Generic api to allocate pages. It is the responsibility of the caller to 
 * acquire relevant locks to protect the head from getting corrupted due to 
 * parallel access to the list. This function returns success even if it has 
 * allocated one page and could not allocate more. It is the responsibility of 
 * the callers to check for actual_nr_pages and release those if not sufficient.
 */
inm_s32_t alloc_data_pages(struct inm_list_head *head, inm_u32_t nr_pages, 
			 inm_u32_t *actual_nr_pages, inm_s32_t flags)
{
	data_page_t *page = NULL;

	/* Do basic checks on the requested number of pages.
	 */

	*actual_nr_pages = 0;
	while (*actual_nr_pages < nr_pages ) {

		page = (data_page_t *)INM_KMALLOC(sizeof(*page), INM_KM_SLEEP,
							INM_KERNEL_HEAP);
		if(!page)
			break;

		page->page = INM_ALLOC_MAPPABLE_PAGE(flags);
		if(!page->page)
			break;

		INM_SET_PAGE_RESERVED(page->page);

		inm_list_add_tail(&page->next, head);
		(*actual_nr_pages)++;
	}

	if((*actual_nr_pages) == 0)
		return 0;

	info("Data Mode Init: Allocated pages %d Page size %ld", 
				*actual_nr_pages, INM_PAGESZ);
	return 1;
}

void free_data_pages(struct inm_list_head *head)
{
	struct inm_list_head *ptr;
	data_page_t *entry;
	inm_s32_t num_pages = 0;

	if(head == NULL)
		return;

	for(ptr = head->next; ptr != head;) {
		entry = inm_list_entry(ptr, data_page_t, next);
		ptr = ptr->next;
		inm_list_del(&entry->next);
		INM_CLEAR_PAGE_RESERVED(entry->page);
		INM_FREE_MAPPABLE_PAGE(entry->page, INM_KERNEL_HEAP);
		INM_KFREE(entry, sizeof(data_page_t), INM_KERNEL_HEAP);
		num_pages++;
	}

	info("Data Mode Unint: Freed Data Pages: %d\n", num_pages);
}

void
delete_data_pages(inm_u32_t num_pages)
{
	struct inm_list_head *ptr,*hd,*nextptr;
	unsigned long lock_flag = 0;
	data_page_t *entry;

	if(!num_pages){
		return;
	}
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock,
						lock_flag);

	hd = &(driver_ctx->data_flt_ctx.data_pages_head);

	/* 
	 * Check to see if num_pages can be reclaimed from 
	 * dc's unreserve pages
	 */
	if (num_pages > driver_ctx->dc_cur_unres_pages) {
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
				               lock_flag);
		return;
	}
	inm_list_for_each_safe(ptr, nextptr, hd) {
		entry = inm_list_entry(ptr, data_page_t, next);
		inm_list_del(ptr);
		INM_CLEAR_PAGE_RESERVED(entry->page);
		__INM_FREE_PAGE(entry->page);
		INM_KFREE(entry, sizeof(data_page_t), INM_KERNEL_HEAP);
		driver_ctx->data_flt_ctx.pages_free--;
		driver_ctx->data_flt_ctx.pages_allocated--;
		driver_ctx->dc_cur_unres_pages--;
		driver_ctx->data_flt_ctx.dp_pages_alloc_free--;
		num_pages--;
		if (!num_pages)
			break;
	}
	if(driver_ctx->data_flt_ctx.dp_least_free_pgs > num_pages){
		driver_ctx->data_flt_ctx.dp_least_free_pgs -= num_pages;
	} else {
		driver_ctx->data_flt_ctx.dp_least_free_pgs = 0;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
				           lock_flag);
}

inm_dev_t
inm_dev_id_get(target_context_t *ctx)
{
	host_dev_ctx_t  *hdcp;
	inm_block_device_t *bdev;
	inm_dev_t    devid = 0;
	host_dev_t *hdc_dev = NULL;
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	struct bdev_handle *handle = NULL;
#endif

	switch(ctx->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
		hdcp = ctx->tc_priv;
		/*
		 * If the target_context is completely initialized use hdcp else
		 * open the dev.
		 */
		if (hdcp) {
			INM_BUG_ON(!(&hdcp->hdc_dev_list_head));
			hdc_dev = inm_list_entry(hdcp->hdc_dev_list_head.next,
						host_dev_t, hdc_dev_list);
			return hdc_dev->hdc_dev;
		}
		else {
			/* crash in debug build if target context is without devt */
			INM_BUG_ON(1);
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
			handle = inm_bdevhandle_open_by_dev_path(ctx->tc_guid, FMODE_READ);
			if (handle) {
				bdev = handle->bdev;
				devid = bdev->bd_inode->i_rdev;
				close_bdev_handle(handle);
#else
			bdev = open_by_dev_path(ctx->tc_guid, 0);
			if (bdev) {
				devid = bdev->bd_inode->i_rdev;
				close_bdev(bdev, FMODE_READ);
#endif
				return devid;
			}
			else {
				return -ENODEV;
			}
		}
		break;

	case FILTER_DEV_FABRIC_LUN:
		/*
		 * since MAJOR/MINOR macros are used on the ret value, it does not seem
		 * appropriate to return virtid of the LUN.
		 */
		return 0;
		break;

	default:
		break;
	}
	return 0;
}

inm_s32_t
inm_get_mirror_dev(mirror_vol_entry_t *vol_entry)
{
	inm_s32_t ret = 1;

	if(!vol_entry)
		goto out;

	if((vol_entry->vol_flags & INM_AT_LUN) &&
			!find_dc_at_lun_entry(vol_entry->tc_mirror_guid)){
		info("%s AT lun is not masked, failing the mirroring IOCTL",
					vol_entry->tc_mirror_guid);
		ret = -ENXIO;
		goto out;
	}
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	vol_entry->mirror_handle = inm_bdevhandle_open_by_dev_path(
		vol_entry->tc_mirror_guid, FMODE_WRITE);
	if (vol_entry->mirror_handle) {
		vol_entry->mirror_dev = vol_entry->mirror_handle->bdev;
	}
	else {
#else
	vol_entry->mirror_dev = open_by_dev_path(vol_entry->tc_mirror_guid, 1);
	if (!vol_entry->mirror_dev || !vol_entry->mirror_dev->bd_disk) {
#endif
		err("Failed to open the volume:%s mirror_dev:%p",
		vol_entry->tc_mirror_guid, vol_entry->mirror_dev);
		vol_entry->mirror_dev = NULL;
		goto out;
	}

	ret = 0;

out:
	return ret;
}

void
inm_free_mirror_dev(mirror_vol_entry_t *vol_entry)
{
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	if (vol_entry->mirror_handle) {
		close_bdev_handle(vol_entry->mirror_handle);
		vol_entry->mirror_handle = NULL;
#else
	if (vol_entry->mirror_dev) {
		close_bdev(vol_entry->mirror_dev, FMODE_WRITE);
#endif
		vol_entry->mirror_dev = NULL;
	}
}

inm_dev_t
inm_get_dev_t_from_path(const char *pathp)
{
	inm_dev_t rdev = 0;
	inm_block_device_t *bdevp = NULL;
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	struct bdev_handle *handle = NULL;
#endif
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered path:%s", pathp);
	}
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	handle = inm_bdevhandle_open_by_dev_path((char *)pathp, FMODE_READ);
	if (handle) {
		bdevp = handle->bdev;
		rdev = bdevp->bd_inode->i_rdev;
		close_bdev_handle(handle);
	}
#else
	bdevp = open_by_dev_path((char *)pathp, 0);
	if (bdevp) {
		rdev = bdevp->bd_inode->i_rdev;
		close_bdev(bdevp, FMODE_READ);
	}
#endif
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving path:%s rdev:%d", pathp,rdev);
	}
	return (rdev);
}

inm_u64_t
inm_dev_size_get(target_context_t *ctx)
{
	host_dev_ctx_t		*hdcp;
	target_volume_ctx_t	*tvcptr;

	switch(ctx->tc_dev_type) {
		 case FILTER_DEV_HOST_VOLUME:
		 case FILTER_DEV_MIRROR_SETUP:
			 hdcp = ctx->tc_priv;
			 return (inm_u64_t) (hdcp->hdc_volume_size);
		 break;

		case FILTER_DEV_FABRIC_LUN:
			tvcptr = ctx->tc_priv;
			return (inm_u64_t) ((tvcptr->nblocks) * (tvcptr->bsize));
		break;

		default:
			break;
	}
	return 0;
}

void inm_scst_unregister(target_context_t *tgt_ctxt)
{
	target_volume_ctx_t *vtgtctx_ptr = tgt_ctxt->tc_priv;

	emd_unregister_virtual_device(vtgtctx_ptr->virt_id);
	vtgtctx_ptr->vcptr = NULL;
}

int inm_path_lookup_parent(const char *name, inm_lookup_t *nd)
{

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
	return path_lookup(name, LOOKUP_PARENT, nd);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	return kern_path(name, LOOKUP_PARENT, &nd->path);
#else
	return kern_path_parent(name, nd);
#endif
#endif
}

int inm_path_lookup(const char *name, unsigned int flags, inm_lookup_t *nd)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
	return path_lookup(name, flags | LOOKUP_FOLLOW, nd);
#else
	return kern_path(name, flags | LOOKUP_FOLLOW, &nd->path);
#endif
}

void inm_path_release(inm_lookup_t *nd)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	path_put(&nd->path);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	dput(nd->path.dentry);
	if (nd->path.mnt) {
		nd->path.mnt->mnt_expiry_mark = 0;
		mntput_no_expire(nd->path.mnt);
	}
#else
	path_release(nd);
#endif
#endif
}

void
replace_sd_open(void)
{
	driver_ctx->dc_at_lun.dc_at_drv_info.mod_dev_ops.open = inm_sd_open;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0) || defined(RHEL9_4) || defined(SLES15SP6)
static int
inm_sd_open(struct gendisk *disk, blk_mode_t mode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static int
inm_sd_open(struct block_device *bdev, fmode_t mode)
#else
static int
inm_sd_open(struct inode *inode, struct file *filp)
#endif
{
	 inm_s32_t err = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0) && !defined(RHEL9_4) && !defined(SLES15SP6)
	 struct gendisk *disk = NULL;
#endif
	 struct scsi_device *sdp = NULL;

	 if(is_AT_blocked()){
		 err = -EACCES;
		 goto out;
	 }
	 INM_ATOMIC_INC(&(driver_ctx->dc_at_lun.dc_at_drv_info.nr_in_flight_ops));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0) || defined(RHEL9_4) || defined(SLES15SP6)
	 err = driver_ctx->dc_at_lun.dc_at_drv_info.orig_drv_open(disk, mode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	 err = driver_ctx->dc_at_lun.dc_at_drv_info.orig_drv_open(bdev, mode);
#else
	 err = driver_ctx->dc_at_lun.dc_at_drv_info.orig_drv_open(inode, filp);
#endif
	 if(!err) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0) && !defined(RHEL9_4) && !defined(SLES15SP6)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
		disk = bdev->bd_disk;
#else
		disk = inode->i_bdev->bd_disk;
#endif
#endif
		/* For pseudo devices like emc powerpath may not populate
		 * gendisk->driverfs_dev structure, so we can exclude such
		 * devices from being checked
		 */
		if (disk && inm_get_parent_dev(disk)) {
			sdp = to_scsi_device(inm_get_parent_dev(disk));
			dbg("InMage util to open AT VendorID:%s",
				(sdp->vendor)?(sdp->vendor):("NULL"));
			INM_BUG_ON(strncmp(sdp->vendor, "InMage  ",
							strlen("InMage  ")));
		}
	 }
	 INM_ATOMIC_DEC(&(driver_ctx->dc_at_lun.dc_at_drv_info.nr_in_flight_ops));

out:
	return err;
}

/* validate the file and return its type */
inm_s32_t
validate_file(char *pathp, inm_s32_t *type)
{
	inm_s32_t r = 0;
	inm_lookup_t nd;
	struct inode *inode = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered fname:%s", pathp);
	}

	if ((r = inm_path_lookup(pathp, LOOKUP_FOLLOW, &nd)))
		return r;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	inode = nd.path.dentry->d_inode;
#else
	inode = nd.dentry->d_inode;
#endif
	if (!inode) {
		r = -ENOENT;
		goto out;
	}

	*type = inode->i_mode;

out:
	inm_path_release(&nd);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving fname:%s ret:%d", pathp, r);
	}
	return r;
}

void inm_rel_dev_resources(target_context_t *ctx, host_dev_ctx_t *hdcp)
{
	struct inm_list_head *ptr = NULL;
	host_dev_t *hdc_dev = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered - releasing device resources");
	}
	__inm_list_for_each(ptr, &hdcp->hdc_dev_list_head) {
		hdc_dev = inm_list_entry(ptr, host_dev_t, hdc_dev_list);

		if (hdc_dev->hdc_fops)
			unregister_disk_change_notification(ctx, hdc_dev);

		if (hdc_dev->hdc_req_q_ptr)
			put_qinfo(hdc_dev->hdc_req_q_ptr);
		hdc_dev->hdc_req_q_ptr = NULL;
	}

	if (hdcp->hdc_bio_info_pool) {
		INM_MEMPOOL_DESTROY(hdcp->hdc_bio_info_pool);
		hdcp->hdc_bio_info_pool = NULL;
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving - done releasing device resources");
	}
}

#if defined(IDEBUG_MIRROR_IO)
extern inm_s32_t inject_vendorcdb_err;
#endif

inm_s32_t
inm_all_AT_cdb_send(target_context_t *tcp, unsigned char *cmd, inm_u32_t cmdlen,
	 inm_s32_t rw, unsigned char *buf, inm_u32_t buflen, inm_u32_t flag)
{

	mirror_vol_entry_t *vol_entry = NULL;
	mirror_vol_entry_t *prev_vol_entry = NULL;
	inm_block_device_t *bdev = NULL;
	struct inm_list_head *ptr, *nextptr;
	inm_s32_t error = 0;

	volume_lock(tcp);
	prev_vol_entry = tcp->tc_vol_entry;
	INM_REF_VOL_ENTRY(prev_vol_entry);
	volume_unlock(tcp);
	bdev = prev_vol_entry->mirror_dev;
	error = inm_one_AT_cdb_send(bdev, cmd, cmdlen, rw, buf, buflen);

#if (defined(INJECT_ERR))
	error = 1;
#endif

	if (!error){
		goto out;
	}
	volume_lock(tcp);

restart:
	inm_list_for_each_safe(ptr, nextptr, &tcp->tc_dst_list) {
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		if (vol_entry->vol_error) {
			vol_entry = NULL;
			continue;
		}
		INM_REF_VOL_ENTRY(vol_entry);
		volume_unlock(tcp);
		bdev = vol_entry->mirror_dev;
		if(prev_vol_entry){
			prev_vol_entry->vol_error = 1;
			INM_DEREF_VOL_ENTRY(prev_vol_entry, tcp);
			prev_vol_entry = NULL;
		}
		error = inm_one_AT_cdb_send(bdev, cmd, cmdlen, rw, buf, buflen);
#if defined(IDEBUG_MIRROR_IO)
		if (inject_vendorcdb_err) {
			error = 1;
			inject_vendorcdb_err = 0;
		}
#endif
		volume_lock(tcp);
		if (!error) {
			tcp->tc_vol_entry = vol_entry;
			break;
		}
		vol_entry->vol_error = 1;
		prev_vol_entry = vol_entry;
	 	vol_entry = NULL;
		goto restart;
	}
	volume_unlock(tcp);

out:
	if(prev_vol_entry){
		INM_DEREF_VOL_ENTRY(prev_vol_entry, tcp);
	}
	if(vol_entry){
		INM_DEREF_VOL_ENTRY(vol_entry, tcp);
	}
#if (defined(INJECT_ERR))
	error = 1;
#endif
	return error;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
static inm_s32_t
inm_one_AT_cdb_send(inm_block_device_t *bdev, unsigned char *cmd,
	inm_u32_t cmdlen, inm_s32_t rw, unsigned char *buf, inm_u32_t buflen)
{
	return 0;
}
#else
static inm_s32_t
inm_one_AT_cdb_send(inm_block_device_t *bdev, unsigned char *cmd,
	inm_u32_t cmdlen, inm_s32_t rw, unsigned char *buf, inm_u32_t buflen)
{
	struct gendisk *bd_disk = NULL;
	struct request *rq = NULL;
	struct request_queue *q = NULL;
	char sense[SCSI_SENSE_BUFFERSIZE];
	inm_s32_t error = 0;

	if (!bdev){
		error = 2;
		goto out;
	}
	bd_disk = bdev->bd_disk;
	if(!bd_disk){
		error = 3;
		goto out;
	}
	if(buflen){
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
		rq = NULL;
		error = queue_request_scsi(bdev, cmd, cmdlen, rw, buf, buflen);
		goto out;
#endif
   }

	q = bd_disk->queue;
	if(!q){
		error = 4;
		goto out;
	}


	rq = blk_get_request(q, rw, __GFP_WAIT);
	if(!rq){
		error = 7;
		goto out;
	}

	rq->cmd_len = cmdlen;
	memcpy_s(rq->cmd, cmdlen, cmd, cmdlen);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	rq->data = buf;
	rq->data_len = buflen;
#endif
	memset(sense, 0, sizeof(sense));
	rq->sense_len = 0;
	rq->sense = sense;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	rq->cmd_type |= REQ_TYPE_BLOCK_PC;
#else
	rq->flags |= REQ_BLOCK_PC | REQ_SPECIAL;
#endif
	if (buflen){
		rq->timeout = INM_WRITE_SCSI_TIMEOUT;
	} else {
		rq->timeout = INM_CNTL_SCSI_TIMEOUT;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,13)
	if (buflen &&  blk_rq_map_kern(q, rq, buf, buflen, __GFP_WAIT)){
		 goto out;
	}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
	blk_execute_rq(q, bd_disk, rq);
#else
	blk_execute_rq(q, bd_disk, rq, 0);
#endif
	error = rq->errors;
	if( error ){
		dbg("error in blk_execute_rq error %d",error);
		if(rq->sense_len){
			process_sense_info(rq->sense);
		} else {
			info("no sense available");
		}
	}

out:
	dbg("exiting send cmd %c with %d", cmd[0], error);
	if (rq){
		blk_put_request(rq);
	}
	return error;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
static inm_s32_t
process_sense_info(char *sense)
{
/* SLES9 2.6.5 does support following function, structures */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 7)
/* 
 * RH7 has kabi bump for scsi_normalize_sense from 7.0 
 * and 7.2 because of which driver does not load.
 */
	return 0;
#else
	struct scsi_sense_hdr sshdr;
	if (!scsi_normalize_sense(sense, SCSI_SENSE_BUFFERSIZE, &sshdr)) {
		info("CDB sense header's fields are");
		info("response_code 0x%x, sense_key 0x%x, asc 0x%x, \
			ascq 0x%x, byte4 0x%x, byte5 0x%x, byte6 0x%x, \
			additional_length 0x%x",
			sshdr.response_code, sshdr.sense_key, sshdr.asc,
			sshdr.ascq, sshdr.byte4, sshdr.byte5, sshdr.byte6,
			sshdr.additional_length);
	} else {
		info("failed to send MODE SELECT, no sense available");
	}
#endif /* RH7 */
#endif
	return 0;
}
#endif

inm_s32_t
try_reactive_offline_AT_path(target_context_t *tcp, unsigned char *cmd,
		inm_u32_t cmdlen, inm_s32_t rw, unsigned char *buf,
		inm_u32_t buflen, inm_u32_t flag)
{

	mirror_vol_entry_t *vol_entry = NULL;
	inm_block_device_t *bdev = NULL;
	struct inm_list_head *ptr, *nextptr;
	inm_s32_t error = 1;
	inm_s32_t ret = 0;

restart:
	volume_lock(tcp);
	inm_list_for_each_safe(ptr, nextptr, &(tcp->tc_dst_list)) {
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		if (!vol_entry->vol_error || (vol_entry->vol_state & INM_VOL_ENTRY_TRY_ONLINE)) {
			vol_entry = NULL;
			continue;
		}
		INM_REF_VOL_ENTRY(vol_entry);
		vol_entry->vol_state |= INM_VOL_ENTRY_TRY_ONLINE;
		volume_unlock(tcp);
		bdev = vol_entry->mirror_dev;
		ret = inm_one_AT_cdb_send(bdev, cmd, cmdlen, rw, buf, buflen);

#if (defined(IDEBUG_MIRROR_IO))
		if(clear_vol_entry_err){
			ret = 0;
		}
#endif
		if (!ret) {
			vol_entry->vol_error = 0;
			error = 0;
		}
		INM_DEREF_VOL_ENTRY(vol_entry, tcp);
		goto restart;
	}
	inm_list_for_each_safe(ptr, nextptr, &(tcp->tc_dst_list)) {
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		vol_entry->vol_state &= ~INM_VOL_ENTRY_TRY_ONLINE;
	}
	volume_unlock(tcp);

#if (defined(IDEBUG_MIRROR_IO))
	clear_vol_entry_err = 0;
#endif

#if (defined(INJECT_ERR))
	error = 1;
#endif
   return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
static inm_s32_t
queue_request_scsi(inm_block_device_t *bdev, unsigned char *cmd, inm_u32_t cmdlen,
				   inm_s32_t rw, unsigned char *buf, inm_u32_t buflen)
{
	struct gendisk *bd_disk = NULL;
	char sense[SCSI_SENSE_BUFFERSIZE];
	struct scsi_device *sdp = NULL;
	struct scsi_request *scsi_rq = NULL;
	inm_s32_t error = 0;

	bd_disk = bdev->bd_disk;
	if(!bd_disk || !bd_disk->driverfs_dev){
		goto out;
	}

	sdp = to_scsi_device(bd_disk->driverfs_dev);
	if(!sdp){
		goto out;
	}
	scsi_rq = scsi_allocate_request(sdp, GFP_KERNEL);
	if(!scsi_rq){
		goto out;
	}
	scsi_rq->sr_data_direction = DMA_TO_DEVICE;
	scsi_wait_req(scsi_rq, cmd, buf, buflen, INM_WRITE_SCSI_TIMEOUT, 1);
	error = scsi_rq->sr_result;

out:
	if (scsi_rq){
		scsi_release_request(scsi_rq);
	}
	scsi_rq = NULL;
	return error;

}
#endif

void
inm_dma_flag(target_context_t *tcp, inm_u32_t *flag)
{

	inm_block_device_t *bdev = NULL;
	struct gendisk *bd_disk = NULL;
	struct scsi_device *sdp = NULL;
	struct Scsi_Host *shost = NULL;

	*flag = 0;
	if (!tcp) {
		goto out;
	}
	bdev = (tcp->tc_vol_entry->mirror_dev);
	if (!bdev) {
		goto out;
	}
	bd_disk = bdev->bd_disk;
	if (!bd_disk ||
		!inm_get_parent_dev(bd_disk)) {
		goto out;
	}

	sdp = to_scsi_device(inm_get_parent_dev(bd_disk));
	if(!sdp){
		goto out;
	}
	shost = sdp->host;
	if(!shost){
		goto out;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	*flag = ((shost->unchecked_isa_dma) ? GFP_DMA : GFP_KERNEL);
#else
	*flag = GFP_KERNEL;
#endif

out:
   return;
}

void
print_AT_stat(target_context_t *tcp, char *page, inm_s32_t *len)
{
	mirror_vol_entry_t *vol_entry = NULL;
	struct inm_list_head *ptr, *hd, *nextptr;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		dbg("entered with tcp %p, page %p, len %p len %d",tcp, page, len, *len);
	}
	if(tcp->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
	   (*len) += sprintf((page+(*len)), "AT name, #IO issued, #successful \
			   IOs, #No of Byte written, Status, no of ref \n");
	   volume_lock(tcp);
	   hd = &(tcp->tc_dst_list);
	   inm_list_for_each_safe(ptr, nextptr, hd){
		   vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		   (*len) += sprintf((page+(*len)), "%s, %llu, %llu, %llu, %s,\
				 %u\n", vol_entry->tc_mirror_guid,
				 vol_entry->vol_io_issued,
				 vol_entry->vol_io_succeeded,
				 vol_entry->vol_byte_written,
				 vol_entry->vol_error?"offline":"online",
				 INM_ATOMIC_READ(&(vol_entry->vol_ref)));
	   }
	   volume_unlock(tcp);
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		dbg("exiting");
	}
}

#ifdef INM_HANDLE_FOR_BDEV_ENABLED
struct bdev_handle *
inm_bdevhandle_open_by_devnum(dev_t dev, unsigned mode)
{
	return bdev_open_by_dev(dev, mode, NULL, NULL);
}
#else
struct block_device *
inm_open_by_devnum(dev_t dev, unsigned mode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) || defined(RHEL9_4) || defined(SLES15SP6)
	return blkdev_get_by_dev(dev, mode, NULL, NULL);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	return blkdev_get_by_dev(dev, mode, NULL);
#else
	return open_by_devnum(dev, mode);
#endif
}
#endif

void free_tc_global_at_lun(struct inm_list_head *dst_list)
{
	struct inm_list_head local_at_list;
	struct inm_list_head *cur = NULL;
	mirror_vol_entry_t *vol_entry = NULL;
	dc_at_vol_entry_t *dc_vol_entry = NULL;

	dbg("enteded in free_tc_global_at_lun");
	INM_INIT_LIST_HEAD(&(local_at_list));
	INM_SPIN_LOCK(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn));
	for (cur = dst_list->next; !(cur == dst_list); cur = cur->next){
		vol_entry = inm_container_of(cur, mirror_vol_entry_t, next);
		dc_vol_entry = find_dc_at_lun_entry(vol_entry->tc_mirror_guid);
		if(!dc_vol_entry)
			continue;
		inm_list_del(&dc_vol_entry->dc_at_this_entry);
		inm_list_add(&(dc_vol_entry->dc_at_this_entry), &local_at_list);
	}
	INM_SPIN_UNLOCK(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn));
	while (!inm_list_empty(&local_at_list)) {
		dc_vol_entry =  inm_container_of(local_at_list.next,
					dc_at_vol_entry_t, dc_at_this_entry);
		inm_list_del(&(dc_vol_entry->dc_at_this_entry));
		free_dc_vol_entry(dc_vol_entry);
	}
	dbg("exiting from free_tc_global_at_lun");
}

inm_s32_t
process_block_at_lun(inm_devhandle_t *handle, void * arg)
{
	inm_s32_t ret = 0;
	inm_s32_t err = 0;
	dc_at_vol_entry_t *dc_vol_entry = NULL;
	dc_at_vol_entry_t *chk_dc_vol_entry = NULL;
	inm_at_lun_reconfig_t *at_lun_reconf = NULL;
	struct gendisk *disk = NULL;
	struct scsi_device *sdp = NULL;

	at_lun_reconf = (inm_at_lun_reconfig_t *)
			INM_KMALLOC(sizeof(inm_at_lun_reconfig_t),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!at_lun_reconf) {
		err = 1;
		goto out;
	}
	INM_MEM_ZERO(at_lun_reconf, sizeof(inm_at_lun_reconfig_t));
	if (INM_COPYIN(at_lun_reconf, (inm_at_lun_reconfig_t *) arg,
		sizeof(inm_at_lun_reconfig_t))) {
		err("copyin failed\n");
		ret = INM_EFAULT;
		goto out;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("%s process_block_at_lun for lun name %s",
		(at_lun_reconf->flag & ADD_AT_LUN_GLOBAL_LIST)? "add":"del",
		at_lun_reconf->atdev_name);
	}
	if (at_lun_reconf->flag & ADD_AT_LUN_GLOBAL_LIST) {
		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
			info("Add dc_at_blocking_entry ioctl for for %s",
						at_lun_reconf->atdev_name);
			INM_BUG_ON(at_lun_reconf->flag & DEL_AT_LUN_GLOBAL_LIST);
		}
		dc_vol_entry =  alloc_dc_vol_entry();
		if (!dc_vol_entry) {
			err = INM_ENOMEM;
			goto out;
		}
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
		err = INM_EINVAL;
		goto out;
#else
		if (!(dc_vol_entry->dc_at_dev=open_by_dev_path(at_lun_reconf->atdev_name,
							FMODE_WRITE))) {
			err("Fail to open AT LUN device %s",
						at_lun_reconf->atdev_name);
			err = INM_EINVAL;
			goto out;
		}
#endif
		disk = dc_vol_entry->dc_at_dev->bd_disk;
		/* For pseudo devices like emc powerpath may not populate
		 * gendisk->driverfs_dev structure, so we can exclude such
		 * devices from being checked
		 */
		if (disk && inm_get_parent_dev(disk)) {
			sdp = to_scsi_device(inm_get_parent_dev(disk));
			/* Not a InMage AT Lun ? */
			if (strncmp(sdp->vendor, "InMage  ", strlen("InMage  "))) {
				if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
					info("Entry is not an InMage AT device %s vendor:[%s]",
					    at_lun_reconf->atdev_name,
					    (sdp->vendor)?(sdp->vendor):"NULL");
				}
				err = INM_EINVAL;
				goto out;
			}
		}
		else {
			if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
				info("Entry without driverfs_dev is not an InMage AT \
					device %s", at_lun_reconf->atdev_name);
			}
			err = INM_EINVAL;
			goto out;
		}
		if (dc_vol_entry->dc_at_dev->bd_disk->fops ==
			&(driver_ctx->dc_at_lun.dc_at_drv_info.mod_dev_ops)) {
			/* Could come here for disk partition*/
			dbg("Device %s already masked ",
						at_lun_reconf->atdev_name);
#ifndef INM_HANDLE_FOR_BDEV_ENABLED
			close_bdev(dc_vol_entry->dc_at_dev, FMODE_WRITE);
#endif
			dc_vol_entry->dc_at_dev = NULL;
			INM_KFREE(dc_vol_entry, sizeof(dc_at_vol_entry_t),
							INM_KERNEL_HEAP);
			err = INM_EEXIST;
			goto out1;
		}
		strcpy_s(dc_vol_entry->dc_at_name, INM_GUID_LEN_MAX,
						at_lun_reconf->atdev_name);
		dc_vol_entry->dc_at_dev->bd_disk->fops =
			&(driver_ctx->dc_at_lun.dc_at_drv_info.mod_dev_ops);
		INM_SPIN_LOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
								flag);
		chk_dc_vol_entry = find_dc_at_lun_entry(at_lun_reconf->atdev_name);
		if (chk_dc_vol_entry) {
			INM_BUG_ON(strcmp(chk_dc_vol_entry->dc_at_name,
						at_lun_reconf->atdev_name));
			INM_SPIN_UNLOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
									flag);
			if (IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
				dbg("Entry already exist for device %s",
						at_lun_reconf->atdev_name);
			}
#ifndef INM_HANDLE_FOR_BDEV_ENABLED
			close_bdev(dc_vol_entry->dc_at_dev, FMODE_WRITE);
#endif
			dc_vol_entry->dc_at_dev = NULL;
			INM_KFREE(dc_vol_entry, sizeof(dc_at_vol_entry_t),
							INM_KERNEL_HEAP);
			err = INM_EEXIST;
			goto out1;
		}
		inm_list_add_tail(&dc_vol_entry->dc_at_this_entry,
				&(driver_ctx->dc_at_lun.dc_at_lun_list));
		INM_SPIN_UNLOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
								flag);
	} else {
		INM_BUG_ON(!(at_lun_reconf->flag & DEL_AT_LUN_GLOBAL_LIST));
		dbg("deleting dc_at_blocking_entry ioctl for for %s",
			       			at_lun_reconf->atdev_name);
		INM_BUG_ON(at_lun_reconf->flag & ADD_AT_LUN_GLOBAL_LIST);
		INM_SPIN_LOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
								flag);
		dc_vol_entry = find_dc_at_lun_entry(at_lun_reconf->atdev_name);
		if (!dc_vol_entry) {
			INM_SPIN_UNLOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
								flag);
			info("lun is not blocked but still got unblocked \
				called, device name %s",
			       	at_lun_reconf->atdev_name);
			goto out;
		}
		inm_list_del(&dc_vol_entry->dc_at_this_entry);
		INM_SPIN_UNLOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
								flag);
		free_dc_vol_entry(dc_vol_entry);
		dc_vol_entry=NULL;
	}
out:
	if (err && dc_vol_entry) {
		free_dc_vol_entry(dc_vol_entry);
	}
out1:
	if (at_lun_reconf) {
		INM_KFREE(at_lun_reconf, sizeof(inm_at_lun_reconfig_t),
							INM_KERNEL_HEAP);
	}
	dbg("exiting from  process_block_at_lun");
	return err;
}

void
free_all_at_lun_entries()
{
	inm_list_head_t *ptr = NULL, *nextptr = NULL;
	inm_list_head_t llist;
	dc_at_vol_entry_t *at_vol_entry = NULL;

	dbg("entered free_all_at_lun_entries");
	INM_INIT_LIST_HEAD(&llist);
	INM_SPIN_LOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
							lock_flag);
	inm_list_replace_init(&(driver_ctx->dc_at_lun.dc_at_lun_list),
							&llist);
	INM_SPIN_UNLOCK_WRAPPER(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn),
							lock_flag);
	inm_list_for_each_safe(ptr, nextptr, &llist) {
		at_vol_entry =  inm_container_of(ptr,
						dc_at_vol_entry_t,
						dc_at_this_entry);
		free_dc_vol_entry(at_vol_entry);
	}
	dbg("exiting from free_all_at_lun_entries");
	return;
}

static void
free_dc_vol_entry(dc_at_vol_entry_t *at_vol_entry)
{
	if (at_vol_entry->dc_at_dev) {
		if (at_vol_entry->dc_at_dev->bd_disk &&
			(at_vol_entry->dc_at_dev->bd_disk->fops ==
			&(driver_ctx->dc_at_lun.dc_at_drv_info.mod_dev_ops))) {
			at_vol_entry->dc_at_dev->bd_disk->fops =
			driver_ctx->dc_at_lun.dc_at_drv_info.orig_dev_ops;
		}
#ifndef INM_HANDLE_FOR_BDEV_ENABLED
		close_bdev(at_vol_entry->dc_at_dev, FMODE_READ);
#endif
		at_vol_entry->dc_at_dev = NULL;
	}
	INM_KFREE(at_vol_entry, sizeof(dc_at_vol_entry_t), INM_KERNEL_HEAP);
	at_vol_entry = NULL;
}

static dc_at_vol_entry_t*
alloc_dc_vol_entry()
{
	dc_at_vol_entry_t *at_vol_entry = NULL;
	at_vol_entry = (dc_at_vol_entry_t *)
			INM_KMALLOC(sizeof(dc_at_vol_entry_t),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!at_vol_entry){
		goto out;
	}
	INM_MEM_ZERO(at_vol_entry, sizeof(dc_at_vol_entry_t));
	INM_INIT_LIST_HEAD(&at_vol_entry->dc_at_this_entry);
out:
	return at_vol_entry;
}

/*
 *This func should be called with dc_at_lun_list_spn lock held.
 */
dc_at_vol_entry_t *
find_dc_at_lun_entry(char *devname)
{
	inm_list_head_t *ptr = NULL, *nextptr = NULL;
	dc_at_vol_entry_t *at_vol_entry = NULL;

	inm_list_for_each_safe(ptr, nextptr,
			&(driver_ctx->dc_at_lun.dc_at_lun_list)) {
		at_vol_entry =  inm_container_of(ptr,
					dc_at_vol_entry_t,
					dc_at_this_entry);
		if(!strcmp(at_vol_entry->dc_at_name, devname)){
			break;
		}
		at_vol_entry = NULL;
	}
	return at_vol_entry;
}

void *inm_kmalloc(size_t size, int flags)
{
	void *ptr = NULL;
	ptr = kmalloc(size, flags);
	if(ptr) {
		atomic_add(size, &inm_flt_memprint);
	}
	return ptr;
}

void inm_kfree(size_t size,const void * objp)
{
	if(objp) {
		atomic_sub(size, &inm_flt_memprint);
	}
	kfree(objp);
}

void *inm_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *ptr = NULL;
	ptr = kmem_cache_alloc(cachep,flags);
#ifdef CONFIG_SLAB
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))
	if(ptr) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,13))
		atomic_add(cachep->size, &inm_flt_memprint);
#else
		atomic_add(cachep->buffer_size, &inm_flt_memprint);
#endif
	}
#endif
#endif
		return ptr;
}

void inm_kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
#ifdef CONFIG_SLAB
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))
	if(objp) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,13))
		atomic_sub(cachep->size, &inm_flt_memprint);
#else
		atomic_sub(cachep->buffer_size, &inm_flt_memprint);
#endif
	}
#endif
#endif
	kmem_cache_free(cachep, objp);
}

void *inm_mempool_alloc(inm_mempool_t *pool, gfp_t gfp_mask)
{
	void *ptr = mempool_alloc(pool, gfp_mask);

#ifdef CONFIG_SLAB
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))
	struct kmem_cache *cachep;
	if(ptr) {
		if (pool->pool_data) {
			cachep = pool->pool_data;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,13))
			atomic_add(cachep->size, &inm_flt_memprint);
#else
			atomic_add(cachep->buffer_size, &inm_flt_memprint);
#endif
		}
	}
#endif
#endif
	return ptr;
}

void inm_mempool_free(void *element, inm_mempool_t *pool)
{
#ifdef CONFIG_SLAB
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32))
	struct kmem_cache *cachep = NULL;
	if(element){
		if(pool->pool_data) {
			cachep = pool->pool_data;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,13))
			atomic_sub(cachep->size, &inm_flt_memprint);
#else
			atomic_sub(cachep->buffer_size, &inm_flt_memprint);
#endif
		}
	}
#endif
#endif
	mempool_free(element, pool);
}

void *inm_vmalloc(unsigned long size)
{
	void *ptr = NULL;
	ptr = vmalloc(size);
	if(ptr) {
		atomic_add(size, &inm_flt_memprint);
	}
	return ptr;
}

void inm_vfree(const void *addr, unsigned long size)
{
	if(addr) {
		atomic_sub(size, &inm_flt_memprint);
	}
	vfree(addr);
}

struct page *inm_alloc_page(gfp_t gfp_mask)
{
	struct page *ptr = NULL;
	ptr = alloc_page(gfp_mask);
	if(ptr) {
		atomic_add(PAGE_SIZE, &inm_flt_memprint);
	}
	return ptr;
}

void __inm_free_page(struct page *page)
{
	if(page) {
		atomic_sub(PAGE_SIZE, &inm_flt_memprint);
	}
	__free_page(page);
}

void inm_free_page(unsigned long addr)
{
	if(addr) {
		atomic_sub(PAGE_SIZE, &inm_flt_memprint);
	}
	free_page((unsigned long)addr);
}

unsigned long __inm_get_free_page(gfp_t gfp_mask)
{
	unsigned long addr = (unsigned long)NULL;
	addr =  __get_free_page(gfp_mask);
	if(addr) {
		atomic_add(PAGE_SIZE, &inm_flt_memprint);
	}
	return addr;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
void
post_timeout_task_to_wthread(inm_timer_t *timer)
{
	flt_timer_t *flt_timer = inm_container_of(timer, flt_timer_t,
							ft_timer);
	add_item_to_work_queue(&driver_ctx->dc_tqueue, &flt_timer->ft_task);
}
#else
void
post_timeout_task_to_wthread(unsigned long wqtask)
{
	add_item_to_work_queue(&driver_ctx->dc_tqueue, (wqentry_t *)wqtask);
}
#endif

inm_s32_t
force_timeout(flt_timer_t *timer)
{
	if (timer->ft_task.flags == WITEM_TYPE_TIMEOUT) {
		dbg("Force timeout");
		mod_timer(&timer->ft_timer, jiffies);
		return 0;
	} else {
		return -EINVAL;
	}
}

inm_s32_t
end_timer(flt_timer_t *timer)
{
	if (timer->ft_task.flags == WITEM_TYPE_TIMEOUT) {
		dbg("Shutting down the timer");
		del_timer_sync(&timer->ft_timer);
		timer->ft_task.flags = WITEM_TYPE_UNINITIALIZED;
		return 0;
	} else {
		return -EINVAL;
	}
}

void
start_timer(flt_timer_t *timer, int timeout_ms, timeout_t callback)
{
	init_work_queue_entry(&timer->ft_task);

	timer->ft_task.flags = WITEM_TYPE_TIMEOUT;
	timer->ft_task.work_func = callback;
	timer->ft_task.context = NULL;

	dbg("Starting cp timer with %d ms timeout at %lu", timeout_ms,
					jiffies);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
	timer_setup(&timer->ft_timer, post_timeout_task_to_wthread, 0);
#else
	init_timer(&timer->ft_timer);
	timer->ft_timer.function = post_timeout_task_to_wthread;
	timer->ft_timer.data = (unsigned long)&timer->ft_task;
#endif

	timer->ft_timer.expires = jiffies + INM_MSECS_TO_JIFFIES(timeout_ms);
	add_timer(&timer->ft_timer);
}

inm_s32_t
end_cp_timer(void)
{
	if (driver_ctx->dc_cp != INM_CP_NONE) {
		INM_BUG_ON(driver_ctx->dc_cp != INM_CP_NONE);
		return -EINVAL;
	}

	INM_MEM_ZERO(driver_ctx->dc_cp_guid, sizeof(driver_ctx->dc_cp_guid));

	return end_timer(&cp_timer);
}

void
start_cp_timer(int timeout_ms, timeout_t callback)
{
	dbg("Starting timer -> %d ms", timeout_ms);
	start_timer(&cp_timer, timeout_ms, callback);
}

/*
 * COMMIT/REVOKE TAGS
 */
/*
 * commit_tags_v2
 *
 * Function to commit/revoke tags for multiple volumes. The volumes are
 * fetched tgt_list and checked for pending comit
 *
 */
inm_s32_t
commit_tags_v2(char *tag_guid, TAG_COMMIT_STATUS_T commit, int timedout)
{
	inm_s32_t     error = 0;
	inm_list_head_t *cur = NULL;
	inm_list_head_t *next= NULL;
	target_context_t *tgt_ctxt = NULL;
	int tag_committed = 0;

	INM_DOWN(&driver_ctx->dc_cp_mutex);

	dbg("Commit tag: flag = %d and timeout = %d", commit, timedout);

	if (INM_MEM_CMP(driver_ctx->dc_cp_guid, tag_guid,     /* Tag Matches  */
				    sizeof(driver_ctx->dc_cp_guid))) {
		err("Tag guid mismatch");
		error = -EINVAL;
		goto out;
	}

	/*
	 * We check for absolute value and not bit to confirm
	 * volume has been unquiesced before commiting the tag
	 * Also prevents deadlock with create and remove barrier
	 */
	if (driver_ctx->dc_cp != INM_CP_TAG_COMMIT_PENDING) {
		dbg("no commit pending");
		error = -EINVAL;
		goto out;
	}

	error = INM_TAG_SUCCESS;

	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));

	inm_list_for_each_safe(cur, next, &driver_ctx->tgt_list) {
		tgt_ctxt = inm_list_entry(cur, target_context_t, tc_list);
		tag_committed = 0;
		if (is_target_tag_commit_pending(tgt_ctxt)) {

			if (commit == TAG_COMMIT) {
				dbg("Committing tag");
				/* if COMMIT fails, mark return a partial */
				if (commit_usertag(tgt_ctxt))
				    error = INM_TAG_PARTIAL;
				else
				    tag_committed = 1;
			} else {
				dbg("Revoking tag");
				revoke_usertag(tgt_ctxt, timedout);
			}

			tgt_ctxt->tc_flags &= ~VCF_TAG_COMMIT_PENDING;

			if (tag_committed || /* Committed */
			       	/* Changes   */
				should_wakeup_s2_ignore_drain_barrier(tgt_ctxt))
				INM_WAKEUP_INTERRUPTIBLE(&tgt_ctxt->tc_waitq);
		}
	}

	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	driver_ctx->dc_cp &= ~INM_CP_TAG_COMMIT_PENDING;
	INM_BUG_ON(driver_ctx->dc_cp != INM_CP_NONE);

	dbg("New cp state = %d", driver_ctx->dc_cp);

	INM_MEM_ZERO(driver_ctx->dc_cp_guid, sizeof(driver_ctx->dc_cp_guid));

	if (!timedout) {
		if (end_cp_timer())
			err("Cannot stop timer");
	}

out:
	INM_UP(&driver_ctx->dc_cp_mutex);
	return error ;
}

/*
 * Actual function to freeze a given volume for a given timeout value.
 * Input: freeze_vol structure.
 * Output: 0 if succeded.
 *
 */
static inm_s32_t
process_freeze_volume(freeze_info_t *freeze_vol)
{
	inm_list_head_t *ptr = NULL, *nextptr = NULL;
	freeze_vol_info_t *freeze_ele = NULL;
	freeze_vol_info_t *freeze_vinfo = NULL;
	int ret = 0;

	dbg ("entered process_freeze_volume");

	dbg ("Freezing %s", freeze_vol->vol_info->vol_name);

	/* check if the volume is already frozen */

	/* lock freezevol mutex while accessing the list */
	/* Note that dc_cp_mutex is already held by caller here - beware of lock nesting */
	INM_DOWN(&driver_ctx->dc_freezevol_mutex);

	/* iterate over the freeze link list */
	inm_list_for_each_safe(ptr, nextptr, &driver_ctx->freeze_vol_list) {
		freeze_ele = inm_list_entry(ptr, freeze_vol_info_t,
							freeze_list_entry);
		if(freeze_ele) {
			if(!strcmp(freeze_ele->vol_name,
				       freeze_vol->vol_info->vol_name)) {
				dbg ("the volume [%s] is already frozen",
							freeze_ele->vol_name);
				ret = -1;
				goto out;
			}
		}
		freeze_ele = NULL;
	}

	freeze_vinfo =
	  (freeze_vol_info_t *) INM_KMALLOC (sizeof (freeze_vol_info_t),
				 		INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!freeze_vinfo)
	{
		err ("Failed to allocate the freeze_vol_info_t object");
		ret = -1;
		goto out;
	}
	INM_MEM_ZERO (freeze_vinfo, sizeof (freeze_vol_info_t));

	strcpy_s (freeze_vinfo->vol_name, TAG_VOLUME_MAX_LENGTH,
		       			freeze_vol->vol_info->vol_name);

	/* open by device path */
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	freeze_vinfo->handle = inm_bdevhandle_open_by_dev_path(freeze_vinfo->vol_name,
						FMODE_READ | FMODE_WRITE);
	if (freeze_vinfo->handle)
	{
		freeze_vinfo->bdev = freeze_vinfo->handle->bdev;
	}
	else
	{
		info ("failed to open block device file %s", freeze_vinfo->vol_name);
#else
	freeze_vinfo->bdev = open_by_dev_path_v2 (freeze_vinfo->vol_name,
						FMODE_READ | FMODE_WRITE);
	if (!(freeze_vinfo->bdev))
	{
		info ("failed to open block device %s", freeze_vinfo->vol_name);
#endif
		if (freeze_vinfo)
		{
			INM_KFREE (freeze_vinfo, sizeof (freeze_vol_info_t),
				                             INM_KERNEL_HEAP);
			freeze_vinfo = NULL;
		}
		ret = -1;
		goto out;
	}

	if (inm_freeze_bdev(freeze_vinfo->bdev, freeze_vinfo->sb)) {
		info (" failed to freeze block device %s",
						freeze_vinfo->vol_name);
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
		close_bdev_handle(freeze_vinfo->handle);
		freeze_vinfo->handle = NULL;
#else
		close_bdev (freeze_vinfo->bdev, FMODE_READ | FMODE_WRITE);
#endif
		freeze_vinfo->bdev = NULL;
		freeze_vinfo->sb = NULL;
		if (freeze_vinfo)
		{
			INM_KFREE (freeze_vinfo, sizeof (freeze_vol_info_t),
							INM_KERNEL_HEAP);
			freeze_vinfo = NULL;
		}
		ret = -1;
		goto out;
	}


	/* insert the node inside the freeze volume list */
	inm_list_add_tail (&freeze_vinfo->freeze_list_entry,
				       &driver_ctx->freeze_vol_list);

	ret = 0;

out:
	if (ret) {
		freeze_vol->vol_info->status |= STATUS_FREEZE_FAILED;
	} else {
		freeze_vol->vol_info->status |= STATUS_FREEZE_SUCCESS;
	}

	INM_UP(&driver_ctx->dc_freezevol_mutex);

	dbg ("leaving process_freeze_volume");
	return ret;
}

/*
 * IOCTL function to freeze a set of given volume for a given timeout value.
 * Input: handle, arg
 * Output: 0 if all succeded.
 *
 */
inm_s32_t
process_freeze_volume_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
{
	freeze_info_t *freeze_vol = NULL;
	int ret = 0;
	int numvol = 0;
	int no_of_vol_freeze_done = 0;
	inm_u32_t fs_freeze_timeout = 0;
	unsigned long lock_flag = 0;

	dbg("entered process_freeze_volume_ioctl");

	if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				                  sizeof(freeze_info_t))) {
		err("Read access violation for freeze_info_t");
		ret = -EFAULT;
	   goto out;
	}

	freeze_vol = (freeze_info_t *)INM_KMALLOC(sizeof(freeze_info_t),
				         INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!freeze_vol) {
		err("INM_KMALLOC failed to allocate memory for freeze_info_t");
		ret = -ENOMEM;
		goto out;
	}
	if(INM_COPYIN(freeze_vol, arg, sizeof(freeze_info_t))) {
		err("INM_COPYIN failed");
		ret = -EFAULT;
		goto out_err;
	}

	if(freeze_vol->nr_vols <= 0) {
		err("Freeze Input Failed: Number of volumes can't be zero or \
							negative");
		ret = -EINVAL;
		goto out_err;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	fs_freeze_timeout = driver_ctx->tunable_params.fs_freeze_timeout;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

	if(freeze_vol->timeout <= 0 ||
	   freeze_vol->timeout > fs_freeze_timeout) {
		err("Freeze Input Failed: Invalid timeout value");
		ret = -EINVAL;
		goto out_err;
	}

	arg = freeze_vol->vol_info;
	freeze_vol->vol_info = NULL;

	/* allocate a buffer and reuse to store the volume info for a set of volumes */
	freeze_vol->vol_info = (volume_info_t *)INM_KMALLOC(
					 sizeof(*freeze_vol->vol_info),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!freeze_vol->vol_info) {
		err("INM_KMALLOC failed to allocate memory for volume_info_t");
		ret = -ENOMEM;
		goto out;
	}

	INM_DOWN (&(driver_ctx->dc_cp_mutex));

	if (driver_ctx->dc_cp != INM_CP_APP_ACTIVE &&
		driver_ctx->dc_cp != INM_CP_NONE) {
		dbg("CP active -> %d", driver_ctx->dc_cp);
		ret = -EAGAIN;
		goto out_unlock;
	}

	 /* If some fs were frozen earlier, match the guid */
	if (driver_ctx->dc_cp != INM_CP_NONE) {
		INM_BUG_ON(driver_ctx->dc_cp != INM_CP_APP_ACTIVE);
		if (INM_MEM_CMP(driver_ctx->dc_cp_guid, freeze_vol->tag_guid,
				        sizeof(driver_ctx->dc_cp_guid))) {
			err("GUID mismatch");
			ret = -EINVAL;
			goto out_unlock;
		}
	}

	/* iterate over the given volume list */
	for ( numvol = 0; numvol < freeze_vol->nr_vols; numvol++) {

		/* mem set the buffer before using it */
		INM_MEM_ZERO(freeze_vol->vol_info, sizeof(volume_info_t));

		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				sizeof(*freeze_vol->vol_info))) {
			err("Read access violation for freeze_info_t");
			ret = -EFAULT;
			break;
		}

		if(INM_COPYIN(freeze_vol->vol_info, arg,
					sizeof(*freeze_vol->vol_info))) {
			err("INM_COPYIN failed");
			ret = -EFAULT;
			break;
		}

		/* process the freeze volume list */
		freeze_vol->vol_info->vol_name[TAG_VOLUME_MAX_LENGTH - 1] = '\0';
		ret = process_freeze_volume(freeze_vol);
		if(ret) {
			err("Failed to freeze the volume %s\n",
					freeze_vol->vol_info->vol_name);
		} else {
			no_of_vol_freeze_done++;
		}
		if(INM_COPYOUT(arg, freeze_vol->vol_info,
					sizeof(*freeze_vol->vol_info))) {
			err("copy to user failed for freeze volume status");
			ret = INM_EFAULT;
			break;
		}

		arg += sizeof(*freeze_vol->vol_info);
	}

	if (no_of_vol_freeze_done == freeze_vol->nr_vols) {
		ret = 0;
	} else {
		if (!ret)
			ret = -1;
	}

	if (no_of_vol_freeze_done) {
		/* If first freeze ioctl, copy the guid and start timer */
		if (driver_ctx->dc_cp == INM_CP_NONE) {
			driver_ctx->dc_cp |= INM_CP_APP_ACTIVE;
			dbg("First freeze");
			dbg("New cp state = %d", driver_ctx->dc_cp);
			memcpy_s(&driver_ctx->dc_cp_guid,
					sizeof(driver_ctx->dc_cp_guid),
					freeze_vol->tag_guid,
					sizeof(freeze_vol->tag_guid));
			start_cp_timer(freeze_vol->timeout,
				           inm_fvol_list_thaw_on_timeout);
		} else {
			INM_BUG_ON(driver_ctx->dc_cp != INM_CP_APP_ACTIVE);
			dbg("Already marked for APP_CP");
		}
	}

out_unlock:
	INM_UP (&(driver_ctx->dc_cp_mutex));

out:
	if(freeze_vol) {
		if (freeze_vol->vol_info) {
			INM_KFREE(freeze_vol->vol_info, sizeof(volume_info_t),
							INM_KERNEL_HEAP);
			freeze_vol->vol_info = NULL;
		}
		INM_KFREE(freeze_vol, sizeof(freeze_info_t), INM_KERNEL_HEAP);
		freeze_vol = NULL;
	}
	dbg("leaving process_freeze_volume_ioctl");

	return ret;

out_err:
	freeze_vol->vol_info = NULL;
	goto out;
}

/*
 * The actual function which does thaw on a given volume.
 * Input: thaw_info_t
 * Output: 0 if success.
 */
static inm_s32_t
process_thaw_volume(thaw_info_t *thaw_vol)
{

	inm_list_head_t      *ptr = NULL, *nextptr = NULL;
	freeze_vol_info_t    *freeze_ele = NULL;
	int ret;

	dbg("entered process_thaw_volume");
	dbg("Thawing %s", thaw_vol->vol_info->vol_name);

	/* take the freezevol lock to ensure thaw proceeds without blocking for dc_cp_mutex */
	INM_DOWN(&(driver_ctx->dc_freezevol_mutex));

	/* iterate over the freeze link list */
	inm_list_for_each_safe(ptr, nextptr, &driver_ctx->freeze_vol_list) {
		freeze_ele = inm_list_entry(ptr, freeze_vol_info_t,
							freeze_list_entry);
		if(freeze_ele &&
		   (!strcmp(freeze_ele->vol_name,
			    		thaw_vol->vol_info->vol_name))) {
			dbg("the volume to thaw is [%s]\n",
						thaw_vol->vol_info->vol_name);
			/*
			 * found element inside the freeze link list
			 * delete entry from freeze link list
			 */

			inm_list_del(&freeze_ele->freeze_list_entry);

			/*
			 * thaw the bdev, not checking the return value
			 * because in older kernel version return type is void
			 */

			inm_thaw_bdev(freeze_ele->bdev, freeze_ele->sb);
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
			close_bdev_handle (freeze_ele->handle);
			freeze_ele->handle = NULL;
#else
			close_bdev (freeze_ele->bdev, FMODE_READ | FMODE_WRITE);
#endif
			freeze_ele->bdev = NULL;
			freeze_ele->sb = NULL;
			INM_KFREE(freeze_ele, sizeof(freeze_vol_info_t),
							INM_KERNEL_HEAP);
			freeze_ele = NULL;
			ptr = NULL;
			nextptr = NULL;
			ret = 0;
			goto out;
		}
		freeze_ele = NULL;
	}
	ret = -1;
out:
	if (ret) {
		thaw_vol->vol_info->status |= STATUS_THAW_FAILED;
	} else {
		thaw_vol->vol_info->status |= STATUS_THAW_SUCCESS;
	}

	if (inm_list_empty(&driver_ctx->freeze_vol_list)) {
		dbg("All volume thawed");
		driver_ctx->dc_cp &= ~INM_CP_APP_ACTIVE;
		dbg("New cp state = %d", driver_ctx->dc_cp);
		if (driver_ctx->dc_cp == INM_CP_NONE)
			end_cp_timer();
	}

	INM_UP(&(driver_ctx->dc_freezevol_mutex));

	dbg("leaving process_thaw_volume");
	return ret;
}

/*
 * IOCTL function which does thaw on set of given volumes
 * Input: handle, arg
 * Ouput: 0 if all succeded
 *
 */
inm_s32_t
process_thaw_volume_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
{

	thaw_info_t *thaw_vol = NULL;
	int ret = 0;
	int numvol = 0;
	int no_vol_thaw_done = 0;

	dbg("entered process_unfreeze_volume_ioctl");

	if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				                   sizeof(thaw_info_t))) {
		err("Read access violation for thaw_info_t");
		ret = -EFAULT;
		goto out;
	}

	thaw_vol = (thaw_info_t *)INM_KMALLOC(sizeof(thaw_info_t),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!thaw_vol) {
		err("INM_KMALLOC failed to allocate memory for thaw_info_t");
		ret = -ENOMEM;
		goto out;
	}

	if(INM_COPYIN(thaw_vol, arg, sizeof(thaw_info_t))) {
		err("INM_COPYIN failed");
		ret = -EFAULT;
		goto out_err;
	}

	if(thaw_vol->nr_vols <= 0) {
		err("Thaw Input Failed: Number of volumes can't be zero or \
							negative");
		ret = -EINVAL;
		goto out_err;
	}

	arg = thaw_vol->vol_info;
	thaw_vol->vol_info = NULL;

	/* allocate a buffer and reuse to store volume info for a set of
	 * volumes
	 */
	thaw_vol->vol_info = (volume_info_t *)INM_KMALLOC(
					sizeof(volume_info_t),
					INM_KM_SLEEP, INM_KERNE:_HEAP);
	if(!thaw_vol->vol_info) {
		err("INM_KMALLOC failed to allocate memory for volume_info_t");
		ret = -ENOMEM;
		goto out;
	}

	/* take the lock */
	INM_DOWN(&(driver_ctx->dc_cp_mutex));

	if (!(driver_ctx->dc_cp & INM_CP_APP_ACTIVE)) {
		err("Thaw without freeze");
		ret = -EINVAL;
		goto out_unlock;
	}

	if (INM_MEM_CMP(driver_ctx->dc_cp_guid, thaw_vol->tag_guid,
				    sizeof(driver_ctx->dc_cp_guid))) {
		err("Invalid thaw guid");
		ret = -EINVAL;
		goto out_unlock;
	}

	for (numvol = 0; numvol < thaw_vol->nr_vols; numvol++) {

		/* mem set the buffer before using it */
		INM_MEM_ZERO(thaw_vol->vol_info, sizeof(volume_info_t));

		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				          sizeof(*thaw_vol->vol_info))) {
			err("Read access violation for volume_info_t");
			ret = -EFAULT;
			goto out_unlock;
		}

		if(INM_COPYIN(thaw_vol->vol_info, arg,
					sizeof(*thaw_vol->vol_info))) {
			err("INM_COPYIN failed");
			ret = -EFAULT;
			goto out_unlock;
		}

		/* process the freeze volume list */
		thaw_vol->vol_info->vol_name[TAG_VOLUME_MAX_LENGTH - 1] = '\0';

		ret = process_thaw_volume(thaw_vol);
		if(ret) {
			dbg("Fail to Thaw the volume %s\n",
				       thaw_vol->vol_info->vol_name);
		} else {
			no_vol_thaw_done++;
		}
		if(INM_COPYOUT(arg, thaw_vol->vol_info,
					sizeof(*thaw_vol->vol_info))) {
			err("copy to user failed for thaw volume status");
			ret = INM_EFAULT;
			goto out_unlock;
		}

		arg += sizeof(*thaw_vol->vol_info);
	}

	if (no_vol_thaw_done == thaw_vol->nr_vols) {
		ret = 0;
	} else {
		ret = -1;
	}

out_unlock:
	/* release the lock */
	INM_UP(&(driver_ctx->dc_cp_mutex));

out:
	if(thaw_vol) {
		if (thaw_vol->vol_info) {
			INM_KFREE(thaw_vol->vol_info, sizeof(volume_info_t),
							INM_KERNEL_HEAP);
			thaw_vol->vol_info = NULL;
		}
		INM_KFREE(thaw_vol, sizeof(thaw_info_t), INM_KERNEL_HEAP);
		thaw_vol = NULL;
	}

	dbg("leaving process_unfreeze_volume_ioctl");
	return ret;

out_err:
	thaw_vol->vol_info = NULL;
	goto out;
}


/*
 * Function monitors the freeze volume list and thaw if someone timedout.
 */
void
inm_fvol_list_thaw_on_timeout(wqentry_t *not_used)
{
	inm_list_head_t      *ptr = NULL, *nextptr = NULL;
	freeze_vol_info_t    *freeze_ele = NULL;

	err("Starting timeout procedure at %lu", jiffies);

	/* take the freezevol lock to ensure thaw proceeds without blocking for dc_cp_mutex */
	INM_DOWN(&(driver_ctx->dc_freezevol_mutex));

	/* iterate over the global freeze link list*/
	inm_list_for_each_safe(ptr, nextptr, &driver_ctx->freeze_vol_list){
		freeze_ele = inm_list_entry(ptr, freeze_vol_info_t,
							freeze_list_entry);
		if(freeze_ele){
			err("thaw the volume [%s]\n", freeze_ele->vol_name);
			/* thaw the volume using bdev and sb present in link
			 * list
			 */
			inm_thaw_bdev(freeze_ele->bdev, freeze_ele->sb);
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
			close_bdev_handle (freeze_ele->handle);
			freeze_ele->handle = NULL;
#else
			close_bdev (freeze_ele->bdev, FMODE_READ | FMODE_WRITE);
#endif
			freeze_ele->bdev = NULL;
			freeze_ele->sb = NULL;
			inm_list_del(&freeze_ele->freeze_list_entry);
			INM_KFREE(freeze_ele, sizeof(freeze_vol_info_t),
							INM_KERNEL_HEAP);
			freeze_ele = NULL;
		}
	}

	/* release freezevol mutex before acquiring dc_cp_mutex to avoid any nesting issues */
	INM_UP(&(driver_ctx->dc_freezevol_mutex));

	INM_DOWN(&(driver_ctx->dc_cp_mutex));

	driver_ctx->dc_cp &= ~INM_CP_APP_ACTIVE;

	/* release the lock */
	INM_UP(&(driver_ctx->dc_cp_mutex));

	commit_tags_v2(driver_ctx->dc_cp_guid, TAG_REVOKE, 1);

	dbg("leaving inm_fvol_list_thaw_on_timeout");
	return;
}

#ifndef INITRD_MODE
inm_s32_t
process_init_driver_fully(inm_devhandle_t *handle, void * arg)
{
	inm_irqflag_t flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, flag);
	driver_ctx->dc_flags |= DC_FLAGS_REBOOT_MODE;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, flag);

	return 0;
}
#else
extern inm_s32_t driver_state;
extern inm_s32_t get_root_info(void);
inm_s32_t
process_init_driver_fully(inm_devhandle_t *handle, void * arg)
{
	inm_s32_t			state;
	inm_irqflag_t flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, flag);
	state = driver_state;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, flag);

	if (!(state & DRV_LOADED_PARTIALLY))
		return 0;

	/* Read the common tunables */
	init_driver_tunable_params();

	sysfs_involflt_init();
	get_root_info();

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, flag);
	driver_state &= ~DRV_LOADED_PARTIALLY;
	driver_state |= DRV_LOADED_FULLY;
	driver_ctx->dc_flags |= DC_FLAGS_REBOOT_MODE;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, flag);

	if(driver_ctx->clean_shutdown)
		inm_flush_clean_shutdown(UNCLEAN_SHUTDOWN);

	telemetry_init();

	info("Initialized the involflt module successfully");
	return 0;
}
#endif

/*
 * function to add tag to given volume
 * when iobarrier is on
 */
inm_s32_t
iobarrier_add_volume_tags(tag_volinfo_t *tag_volinfop,
				          tag_info_t *tag_info_listp,
					  int nr_tags, 
				          int commit_pending, 
				          tag_telemetry_common_t *tag_common)
{
	int index = 0;
	int ret = -1;
	target_context_t *ctxt = tag_volinfop->ctxt;
	tag_history_t *tag_hist = NULL;

	if (ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
		inm_form_tag_cdb(ctxt, tag_info_listp, nr_tags);
		goto out;
	}

	if (tag_common)
		tag_hist = telemetry_tag_history_alloc(ctxt, tag_common);

	volume_lock(ctxt);

	/*
	 * add tags only in metadata mode, to save the data pages.
	 */
	ret = add_tag_in_non_stream_mode(tag_volinfop, tag_info_listp, nr_tags, 
				NULL, index, commit_pending, tag_hist);
	if (!ret){
		if (commit_pending) {
			driver_ctx->dc_cp |= INM_CP_TAG_COMMIT_PENDING;
			dbg("New cp state = %d", driver_ctx->dc_cp);
		}

		if (tag_common) {
			if (tag_hist)
				telemetry_tag_history_record(ctxt, tag_hist);
			else
				telemetry_log_drop_error(-ENOMEM);
		}
	}

	volume_unlock(ctxt);

	if (ret && tag_hist)
		telemetry_tag_history_free(tag_hist);

	INM_WAKEUP_INTERRUPTIBLE(&ctxt->tc_waitq);

out:
   return ret;
}


/*
 * function to issue tags for all protected volume
 * when iobarrier is on i.e. already holding lock tgt_list_sem.
 */
inm_s32_t
iobarrier_issue_tag_all_volume(tag_info_t *tag_list, int nr_tags, 
			int commit_pending, tag_telemetry_common_t *tag_common)
{
	int ret = 0;
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;
	tag_volinfo_t *tag_volinfop = NULL;
	int vols_tagged = 0;
	inm_s32_t error = 0;
	int tag_not_issued = 0;
	TAG_COMMIT_STATUS *tag_status = NULL;

	dbg("entered iobarrier_issue_tag_all_volume");

	tag_volinfop = (tag_volinfo_t *)INM_KMALLOC(sizeof(tag_volinfo_t),
					INM_KM_NOSLEEP, INM_KERNEL_HEAP);
	if(!tag_volinfop) {
		err("TAG Input Failed: INM_KMALLOC failed for tag_volinfo_t");
		return -ENOMEM;
	}
	INM_MEM_ZERO(tag_volinfop, sizeof(tag_volinfo_t));

	for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
						ptr = ptr->next) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if(tgt_ctxt) {
			if(tgt_ctxt->tc_flags & (VCF_VOLUME_CREATING |
							VCF_VOLUME_DELETING)){
				tgt_ctxt = NULL;
				continue;
			}

			get_tgt_ctxt(tgt_ctxt);
			if(tgt_ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP &&
			   tgt_ctxt->tc_cur_wostate != ecWriteOrderStateData) {
				dbg("the volume is not in Write Order State Data");
				/* Non WO state takes precedence over other errors */
				tag_not_issued = 1;
				error = -EPERM;
				ret = -EPERM;

				INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
				if (driver_ctx->dc_tag_drain_notify_guid &&
				    !INM_MEM_CMP(driver_ctx->dc_cp_guid,
				                 driver_ctx->dc_tag_drain_notify_guid,
				                 GUID_LEN)) {
					tag_status = tgt_ctxt->tc_tag_commit_status;
					info("The disk %s is in non write order \
						    state", tgt_ctxt->tc_guid);
				}
				INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);

				if (tag_status)
					set_tag_drain_notify_status(tgt_ctxt, TAG_STATUS_INSERTION_FAILED,
				                            DEVICE_STATUS_NON_WRITE_ORDER_STATE);
				goto tag_fail;
			}
			if(is_target_filtering_disabled(tgt_ctxt)) {
				if (!error)
					error = -ENODEV;
				ret = -ENODEV;
				goto tag_fail;
			}

			tag_volinfop->ctxt = tgt_ctxt;
			ret = iobarrier_add_volume_tags(tag_volinfop, tag_list,
					nr_tags, commit_pending, tag_common);
			if (ret) {
				dbg("failed to issue tag");
				if (!error)
					error = ret;

				goto tag_fail;
			} else {
				vols_tagged++;
				if (tag_common)
					tag_common->tc_ndisks_tagged = vols_tagged;
			}

tag_fail:
			if (ret) {
				if (tag_common) {
					tag_common->tc_ioctl_status = (vols_tagged ?
				            INM_TAG_PARTIAL : INM_TAG_FAILED);

					telemetry_log_tag_failure(tgt_ctxt,
						    tag_common, ret,
						    ecMsgTagInsertFailure);
				}

				ret = 0;
			}

			put_tgt_ctxt(tgt_ctxt);
			tgt_ctxt = NULL;
			tag_volinfop->ctxt = NULL;
		}
	}

	if (tag_not_issued)
		update_cx_with_tag_failure();

	if (vols_tagged) {
		if (error) {
			dbg("Partial tag");
			ret = INM_TAG_PARTIAL;
		} else {
			ret = INM_TAG_SUCCESS;
		}
	} else {
		ret = error;
	}

	if (tag_common)
		tag_common->tc_ioctl_status = ret;

	if (tag_volinfop) {
		if (tgt_ctxt) {
			put_tgt_ctxt(tgt_ctxt);
			tgt_ctxt = NULL;
			tag_volinfop->ctxt = NULL;
		}
		INM_KFREE(tag_volinfop, sizeof(tag_volinfo_t),
							INM_KERNEL_HEAP);
		tag_volinfop = NULL;
	}

	dbg("leaving iobarrier_issue_tag_all_volume");
	return ret;
}

/*
 * barrier_all_timeout
 *
 * Rollback barrier on timeout
 */
void
barrier_all_timeout(wqentry_t *not_used)
{
	err("Starting timeout procedure at %lu", jiffies);
	/* take the lock*/
	remove_io_barrier_all(driver_ctx->dc_cp_guid,
				          sizeof(driver_ctx->dc_cp_guid));
	commit_tags_v2(driver_ctx->dc_cp_guid, TAG_REVOKE, 1);
	return;
}

/*
 * revoke_tags_timeout
 *
 * Revoke tags on timeout
 */
void
revoke_tags_timeout(wqentry_t *not_used)
{
	err("Starting revoke tags timeout procedure at %lu", jiffies);
	commit_tags_v2(driver_ctx->dc_cp_guid, TAG_REVOKE, 1);
	return;
}

/*
 * process ioctl to:
 *  --Create IO barrier.
 *  --Issue TAG for all or protected volumes those are in data mode.
 *    each volume will have all the tag of tag list.
 *  --remove IO barrier.
 */
inm_s32_t
process_iobarrier_tag_volume_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
{
	tag_info_t_v2 *tag_vol = NULL;
	int ret = 0;
	int numvol = 0;
	int no_of_vol_tags_done = 0;
	inm_s32_t error = 0;
	tag_info_t *tag_list = NULL;
	tag_telemetry_common_t *tag_common = NULL;
	etMessageType msg = ecMsgUninitialized;
	int tag_failed = 0;
	int commit_pending;
	int tag_commit_required = 0;
	int is_root_disk_drain_barrier_set = 0;
	int tag_all_volumes = 0;

	dbg("entered process_iobarrier_tag_volume_ioctl");

	tag_common = telemetry_tag_common_alloc(IOCTL_INMAGE_IOBARRIER_TAG_VOLUME);

	if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				                   sizeof(tag_info_t_v2))) {
		err("Read access violation for tag_info_t_v2");
		ret = -EFAULT;
		msg = ecMsgCCInputBufferMismatch;
		goto out;
	}

	tag_vol = (tag_info_t_v2 *)INM_KMALLOC(sizeof(tag_info_t_v2),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!tag_vol) {
		err("INM_KMALLOC failed to allocate memory for tag_info_t_v2");
		ret = -ENOMEM;
		msg = ecMsgCCInputBufferMismatch;
		goto out;
	}

	if(INM_COPYIN(tag_vol, arg, sizeof(tag_info_t_v2))) {
		err("INM_COPYIN failed");
		ret = -EFAULT;
		msg = ecMsgCCInputBufferMismatch;
		goto out_err;
	}

	if(tag_vol->nr_tags <= 0) {
		err("Tag Input Failed: number of tags can't be zero or negative");
		ret = -EINVAL;
		msg = ecMsgCCInvalidTagInputBuffer;
		goto out_err;
	}

	if(tag_vol->timeout < 0) {
		err("Tag Input Failed: timeout of tags can't be negative");
		ret = -EINVAL;
		msg = ecMsgCCInvalidTagInputBuffer;
		goto out_err;
	}

	arg = tag_vol->tag_names;
	tag_vol->tag_names = NULL;

	tag_vol->tag_names = (tag_names_t *)INM_KMALLOC(tag_vol->nr_tags *
					sizeof(tag_names_t),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!tag_vol->tag_names) {
		err("INM_KMALLOC failed to allocate memory for tag_names_t");
		ret = -ENOMEM;
		msg = ecMsgCCInputBufferMismatch;
		goto out_err;
	}

	if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				     tag_vol->nr_tags * sizeof(tag_names_t))) {
		err("Read access violation for tag_names_t");
		ret = -EFAULT;
		msg = ecMsgCCInputBufferMismatch;
		goto out_err_vol;
	}

	if(INM_COPYIN(tag_vol->tag_names, arg,
				tag_vol->nr_tags * sizeof(tag_names_t))) {
		err("INM_COPYIN failed");
		ret = -EFAULT;
		msg = ecMsgCCInputBufferMismatch;
		goto out_err_vol;
	}

	if (tag_common) {
		inm_get_tag_marker_guid(tag_vol->tag_names[0].tag_name, 
				 tag_vol->tag_names[0].tag_len,
				 tag_common->tc_guid,
				 sizeof(tag_common->tc_guid));
		tag_common->tc_guid[sizeof(tag_common->tc_guid) - 1] = '\0';
		dbg("Tag Marker GUID = %s", tag_common->tc_guid);
	}

	/* now build the tag list which will be use for set of given volumes */
	tag_list = build_tag_vol_list(tag_vol, &error);
	if(error || !tag_list) {
		err("build tag volume list failed for the volume");
		ret = error;
		msg = ecMsgCCInvalidTagInputBuffer;
		goto out_err_vol;
	}

	arg = tag_vol->vol_info;
	tag_vol->vol_info = NULL;

	/*
	 * first create IO Barrier, followed by issue a tag and than
	 * remove io barrier at last before returning to this ioctl call
	 */

	INM_DOWN(&driver_ctx->dc_cp_mutex);

	if (driver_ctx->dc_cp != INM_CP_NONE) {
		dbg("Consistency Point already active");
		ret = -EAGAIN;
		msg = ecMsgCompareExchangeTagStateFailure;
		goto unlock_cp_mutex;
	}

	dbg("creating io barrier\n");
	INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));
#ifdef INM_QUEUE_RQ_ENABLED
	volume_lock_all_close_cur_chg_node();
#endif
	INM_ATOMIC_SET(&driver_ctx->is_iobarrier_on, 1);
#ifdef INM_QUEUE_RQ_ENABLED
	get_time_stamp_tag(&driver_ctx->dc_crash_tag_timestamps);
	volume_unlock_all();
#endif
	dbg("created io barrier\n");
	if (tag_common) {
		tag_common->tc_ndisks = driver_ctx->total_prot_volumes;
		tag_common->tc_ndisks_prot = driver_ctx->total_prot_volumes;
	}

	/* get list of all the protected volumes if the below falg is set */
	if ((tag_vol->flags & TAG_ALL_PROTECTED_VOLUME_IOBARRIER) ==
				          TAG_ALL_PROTECTED_VOLUME_IOBARRIER) {
		tag_all_volumes = 1;
		dbg("issuing tag to all volumes");
		memcpy_s(&driver_ctx->dc_cp_guid,
				sizeof(driver_ctx->dc_cp_guid),
				tag_vol->tag_guid, sizeof(tag_vol->tag_guid));
		ret = iobarrier_issue_tag_all_volume(tag_list,
						tag_vol->nr_tags, 
						TAG_COMMIT_NOT_PENDING, 
						tag_common);
		INM_MEM_ZERO(driver_ctx->dc_cp_guid,
					sizeof(driver_ctx->dc_cp_guid));
		if(ret) {
			dbg("Failed to tag all the volume\n");
			msg = ecMsgTagVolumeInSequenceFailure;
		} else
			update_cx_with_tag_success();
		goto remove_io_barrier;
	}

	if(tag_vol->nr_vols <= 0) {
		err("Tag Input Failed: Number of volumes can't be zero or \
							negative");
		ret = -EINVAL;
		goto remove_io_barrier;
	}

	/* alloc a buffer and reuse it to store the volume info for a set of volumes */
	tag_vol->vol_info = (volume_info_t *)INM_KMALLOC(
					 sizeof(volume_info_t),
					 INM_KM_NOSLEEP, INM_KERNEL_HEAP);

	if(!tag_vol->vol_info) {
		err("INM_KMALLOC failed to allocate memory for volume_info_t");
		ret = -EFAULT;
		goto remove_io_barrier;
	}

	if (!driver_ctx->dc_root_disk) {
		info("Failed to get root disk details from driver context");
	}

	for(numvol = 0; numvol < tag_vol->nr_vols; numvol++) {

		/* mem set the buffer before using it */
		INM_MEM_ZERO(tag_vol->vol_info, sizeof(volume_info_t));

		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				          sizeof(*tag_vol->vol_info))) {
			err("Read access violation for volume_info_t");
			ret = -EFAULT;
			break;
		}

		if(INM_COPYIN(tag_vol->vol_info, arg,
						sizeof(*tag_vol->vol_info))) {
			err("INM_COPYIN failed");
			ret = -EFAULT;
			break;
		}

		/* process the tag volume list */
		tag_vol->vol_info->vol_name[TAG_VOLUME_MAX_LENGTH - 1] = '\0';
		commit_pending = TAG_COMMIT_NOT_PENDING;
		if (tag_vol->vol_info->flags & TAG_DISK_DRAIN_BARRIER) {
			commit_pending = TAG_COMMIT_PENDING;
			tag_commit_required = 1;
			if (driver_ctx->dc_root_disk) {
				if (strcmp(driver_ctx->dc_root_disk->tc_guid,
					tag_vol->vol_info->vol_name)) {
					info ("Drain barrier is set for non root disk : %s, "
						"root disk : %s", tag_vol->vol_info->vol_name,
						driver_ctx->dc_root_disk->tc_guid);
				}
				else {
					is_root_disk_drain_barrier_set = 1;
				}
			}
		}

		ret = process_tag_volume(tag_vol, tag_list,
						commit_pending);
		if(ret) {
			if (ret == INM_EAGAIN)
				tag_failed = 1;

			dbg("Failed to tag the volume\n");
		} else {
			no_of_vol_tags_done++;
		}

		if(!INM_ACCESS_OK(VERIFY_WRITE, (void __INM_USER *)arg,
						sizeof(*tag_vol->vol_info))) {
			err("write access verification failed");
			ret = INM_EFAULT;
			break;
		}

		if(INM_COPYOUT(arg, tag_vol->vol_info,
						sizeof(*tag_vol->vol_info))) {
			err("copy to user failed for freeze volume status");
			ret = INM_EFAULT;
			break;
		}
		arg += sizeof(*tag_vol->vol_info);
	}

	if (driver_ctx->dc_root_disk &&
		(is_root_disk_drain_barrier_set == 0)) {
		info ("Drain barrier not set for os disk : %s",
			driver_ctx->dc_root_disk->tc_guid);
	}

	if (tag_failed)
		update_cx_with_tag_failure();

	if (no_of_vol_tags_done) {
		if(no_of_vol_tags_done ==  tag_vol->nr_vols) {
			dbg("Tagged all volumes");
			update_cx_with_tag_success();
			ret = INM_TAG_SUCCESS;
		} else {
			err("Volumes partially tagged");
			ret = INM_TAG_PARTIAL;
		}
	} else {
		/* else ret should have errno set */
		err("Cannot tag any volume");
	}

	dbg("no_of_vol_tags_done [%d], no of volumes [%d]",
					no_of_vol_tags_done,tag_vol->nr_vols);

remove_io_barrier:
	/* 
	 * to handle single node crash consistency 
	 * remove io barrier at last before returning to this ioctl call
	 */
	dbg("removing io barrier\n");
	INM_ATOMIC_SET(&driver_ctx->is_iobarrier_on, 0);
	INM_UP_WRITE(&(driver_ctx->tgt_list_sem));
#ifdef INM_QUEUE_RQ_ENABLED
	move_chg_nodes_to_drainable_queue();
#endif
	dbg("removed io barrier");

	if (tag_commit_required) {
        /*
         * starting timer only if crash tag is succesfully inserted
         * for any disk where drain barrier is set
         */
		if (driver_ctx->dc_cp == INM_CP_TAG_COMMIT_PENDING) {
			memcpy_s(&driver_ctx->dc_cp_guid,
					sizeof(driver_ctx->dc_cp_guid),
					tag_vol->tag_guid, sizeof(tag_vol->tag_guid));
			start_cp_timer(tag_vol->timeout, revoke_tags_timeout);
		}
	}
	else if (!tag_all_volumes) {
		info("No volumes passed with drain barrier flag set");
	}

unlock_cp_mutex:
	INM_UP(&driver_ctx->dc_cp_mutex);

out:

	if(tag_list) {
		INM_KFREE(tag_list, tag_vol->nr_tags * sizeof(tag_info_t),
				 			INM_KERNEL_HEAP);
		tag_list = NULL;
	}

	if(tag_vol) {
		if(tag_vol->vol_info) {
			INM_KFREE(tag_vol->vol_info, sizeof(volume_info_t),
							INM_KERNEL_HEAP);
			tag_vol->vol_info = NULL;
		}
		if(tag_vol->tag_names) {
			INM_KFREE(tag_vol->tag_names,
					tag_vol->nr_tags * sizeof(tag_names_t),
					INM_KERNEL_HEAP);
			tag_vol->tag_names = NULL;
		}
		INM_KFREE(tag_vol, sizeof(tag_info_t_v2), INM_KERNEL_HEAP);
		tag_vol = NULL;
	}

	if (tag_common) {
		if (ret < 0)
			telemetry_log_ioctl_failure(tag_common, ret, msg);

		telemetry_tag_common_put(tag_common);
	}

	dbg("leaving process_tag_volume_ioctl");
	return ret;

out_err_vol:
		tag_vol->vol_info = NULL;
		goto out;

out_err:
		tag_vol->vol_info = NULL;
		tag_vol->tag_names = NULL;
		goto out;
}

/*
 * BARRIER
 */

/*
 * remove_io_barrier_all
 *
 * Checks if barrier is on and verifies the GUID to check if 
 * barrier created by same context and then remove barrier 
 * on all volumes by unlocking tgt_sem_list
 */
inm_s32_t
remove_io_barrier_all(char *tag_guid, inm_s32_t tag_guid_len)
{
	inm_s32_t error = 0;

	INM_DOWN(&driver_ctx->dc_cp_mutex);

	dbg("removing io barrier\n");

	if (driver_ctx->dc_cp & INM_CP_CRASH_ACTIVE) {

		dbg("crash consistency on");
		/*
		 * Match the GUID of the request with that of create
		 */
		if (!INM_MEM_CMP(driver_ctx->dc_cp_guid, tag_guid,
				         sizeof(driver_ctx->dc_cp_guid))) {
			dbg("Guid matched, removing barrier");
			INM_UP_WRITE(&(driver_ctx->tgt_list_sem));
			INM_ATOMIC_SET(&driver_ctx->is_iobarrier_on, 0);
#ifdef INM_QUEUE_RQ_ENABLED
			move_chg_nodes_to_drainable_queue();
#endif
			driver_ctx->dc_cp &= ~INM_CP_CRASH_ACTIVE;
			dbg("New cp state = %d", driver_ctx->dc_cp);
			if (driver_ctx->dc_cp == INM_CP_NONE)
				end_cp_timer();
		} else {
			err("Invalid remove barrier guid");
			error = -EINVAL;
		}
	} else {
		err("Barrier not active");
		error = -EINVAL;
	}

	INM_UP(&driver_ctx->dc_cp_mutex);

	return error;
}

/*
 * create_io_barrier_all
 *
 * Checks if no other CP is on. Copies GUID for new txn
 * and creates barrier by taking a write lock on tgt_list_sem
 */
inm_s32_t
create_io_barrier_all(char *tag_guid, inm_s32_t tag_guid_len, int timeout_ms)
{
	inm_s32_t error = 0;
	target_context_t *tgt_ctxt = NULL;
	inm_list_head_t *cur = NULL;
	inm_list_head_t *next= NULL;
	inm_u32_t vacp_iobarrier_timeout = 0;
	unsigned long lock_flag = 0;

	dbg("creating io barrier");

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	vacp_iobarrier_timeout = driver_ctx->tunable_params.vacp_iobarrier_timeout;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

	if (timeout_ms == 0 || 
			timeout_ms > vacp_iobarrier_timeout)
		return -EINVAL;

	INM_DOWN(&driver_ctx->dc_cp_mutex);

	if (driver_ctx->dc_cp == INM_CP_NONE) {
		/* Stop all IO */
		INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));

		if (!driver_ctx->total_prot_volumes) {
			dbg("No protected volumes");
			error = -ENODEV;
			goto out_err;
		}

		inm_list_for_each_safe(cur, next, &driver_ctx->tgt_list) {
			tgt_ctxt = inm_list_entry(cur, target_context_t,
								tc_list);
			if (tgt_ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP &&
				tgt_ctxt->tc_cur_wostate !=
						ecWriteOrderStateData) {
				dbg("Volume not in write order state");
				update_cx_with_tag_failure();
				error = -EPERM;
				goto out_err;
			}
		}
#ifdef INM_QUEUE_RQ_ENABLED
		volume_lock_all_close_cur_chg_node();
#endif
		INM_ATOMIC_SET(&driver_ctx->is_iobarrier_on, 1);
#ifdef INM_QUEUE_RQ_ENABLED
		get_time_stamp_tag(&driver_ctx->dc_crash_tag_timestamps);
		volume_unlock_all();
#endif
		memcpy_s(&driver_ctx->dc_cp_guid,
				sizeof(driver_ctx->dc_cp_guid),
				tag_guid, tag_guid_len);
		dbg("Num inflight IOs while taking barrier %d\n",
			INM_ATOMIC_READ(&tgt_ctxt->tc_nr_in_flight_ios));

		driver_ctx->dc_cp = INM_CP_CRASH_ACTIVE;

		start_cp_timer(timeout_ms, barrier_all_timeout);
		dbg("created io barrier\n");
		dbg("New cp state = %d", driver_ctx->dc_cp);

	} else {
		err("Barrier already present");
		error = -EAGAIN;
	}

out:
	INM_UP(&driver_ctx->dc_cp_mutex);
	return error;

out_err:
	INM_UP_WRITE(&(driver_ctx->tgt_list_sem));
	goto out;

}

inm_s32_t
process_create_iobarrier_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
{
	flt_barrier_create_t *bcreate = NULL;
	inm_s32_t error = 0;

	dbg("Create Barrier IOCTL");

	if( !INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
			                   sizeof(flt_barrier_create_t)) ) {
		err("Read access violation for flt_barrier_create_t");
		error = -EFAULT;
		goto out;
	}

	bcreate = (flt_barrier_create_t *)
			INM_KMALLOC(sizeof(flt_barrier_create_t),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if( !bcreate ) {
		err("INM_KMALLOC failed to allocate memory for \
					flt_barrier_create_t");
		error = -ENOMEM;
		goto out;
	}

	if( INM_COPYIN(bcreate, arg, sizeof(flt_barrier_create_t)) ) {
		err("INM_COPYIN failed");
		error = -EFAULT;
		goto out;
	}

	error = create_io_barrier_all(bcreate->fbc_guid,
				sizeof(bcreate->fbc_guid),
				bcreate->fbc_timeout_ms);
	if( error )
		err("Create barrier failed - %d", error);

out:
	if( bcreate )
		INM_KFREE(bcreate, sizeof(flt_barrier_create_t),
					INM_KERNEL_HEAP);

	return error;
}

inm_s32_t
process_remove_iobarrier_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
{
	flt_barrier_remove_t *bremove = NULL;
	inm_s32_t error = 0;

	dbg("Remove Barrier IOCTL");

	if( !INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
					sizeof(flt_barrier_remove_t)) ) {
		err("Read access violation for flt_barrier_remove_t");
		error = -EFAULT;
		goto out;
	}

	bremove = (flt_barrier_remove_t *)
			INM_KMALLOC(sizeof(flt_barrier_remove_t),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	if( !bremove ) {
		err("INM_KMALLOC failed to allocate memory for \
						flt_barrier_remove_t");
		error = -ENOMEM;
		goto out;
	}

	if( INM_COPYIN(bremove, arg, sizeof(flt_barrier_remove_t)) ) {
		err("INM_COPYIN failed");
		error = -EFAULT;
		goto out;
	}

	error = remove_io_barrier_all(bremove->fbr_guid,
					sizeof(bremove->fbr_guid));
	if( error )
		err("Remove barrier failed - %d", error);

out:
	if( bremove )
		INM_KFREE(bremove, sizeof(flt_barrier_remove_t),
							INM_KERNEL_HEAP);

	return error;
}


/*
 * process_commit_revert_tag_ioctl
 *
 * process ioctl to commit/revert tag issued earlier
 *
 */
inm_s32_t
process_commit_revert_tag_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
{
	inm_s32_t error = 0;
	flt_tag_commit_t *commit = NULL;

	dbg("Commit Tag IOCTL");

	if (!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				                   sizeof(*commit))) {
		err("Read access violation for commit");
		error = -EFAULT;
		goto out;
	}

	commit = INM_KMALLOC(sizeof(*commit), INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!commit) {
		error = -ENOMEM;
		goto out;
	}

	if (INM_COPYIN(commit, arg, sizeof(*commit))) {
		err("copyin failed\n");
		error = -EFAULT;
		goto out;
	}

	error = commit_tags_v2(commit->ftc_guid, commit->ftc_flags, 0);

	if( error )
		err("Commit/Revoke (%d) tags failed - %d", 
			commit->ftc_flags, error);

out:
	if (commit)
		INM_KFREE(commit, sizeof(*commit), INM_KERNEL_HEAP);

	return error;
}

#ifdef INM_HANDLE_FOR_BDEV_ENABLED
inm_s32_t
freeze_root_dev(void)
{
	inm_s32_t error = 0;
	inm_block_device_t *rbdev;
	inm_super_block_t *rsb;
	struct bdev_handle *handle;

	dbg("Freezing root");
	if (!driver_ctx->root_dev)
		return -ENODEV;

	handle = inm_bdevhandle_open_by_devnum(driver_ctx->root_dev, FMODE_READ);
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
	}
	else {
		rbdev = handle->bdev;
		error = inm_freeze_bdev(rbdev, rsb);
		if (!error)
			inm_thaw_bdev(rbdev, rsb);
		close_bdev_handle(handle);
	}

	return error;
}

#else
inm_s32_t
freeze_root_dev(void)
{
	inm_s32_t error = 0;
	inm_block_device_t *rbdev;
	inm_super_block_t *rsb;

	dbg("Freezing root");
	if (!driver_ctx->root_dev)
		return -ENODEV;

	rbdev = inm_open_by_devnum(driver_ctx->root_dev, FMODE_READ);
	if (!IS_ERR(rbdev)) {
		error = inm_freeze_bdev(rbdev, rsb);
		if (!error)
			inm_thaw_bdev(rbdev, rsb);
		close_bdev(rbdev, FMODE_READ);
	} else {
		error = PTR_ERR(rbdev);
	}

	return error;
}
#endif

struct device *
inm_get_parent_dev(struct gendisk *bd_disk)
{
	if (!bd_disk)
		return NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)) || defined SLES12SP3
	return (disk_to_dev(bd_disk))->parent;
#else
	return bd_disk->driverfs_dev;
#endif

}

inm_s32_t
inm_reboot_handler(struct notifier_block *nblock, unsigned long code_unused,
				   void *unused)
{
	err("Got reboot notification");
	INM_KFREE(nblock, sizeof(struct notifier_block), INM_KERNEL_HEAP);
	lcw_flush_changes();
	return 0;
}

inm_s32_t
__inm_register_reboot_notifier(struct notifier_block **nb)
{
	struct notifier_block *nblock = NULL;
	inm_s32_t error = 0;

	nblock = INM_KMALLOC(sizeof(struct notifier_block), INM_KM_SLEEP,
				         INM_KERNEL_HEAP);
	if (!nblock) {
		error = -ENOMEM;
		err("Cannot registered for reboot notification");
	} else {
		nblock->notifier_call = inm_reboot_handler;
		nblock->next = NULL;
		nblock->priority = 10;

		*nb = nblock;

		error = register_reboot_notifier(nblock);
		info("Registered for reboot notification");
	}

	return error;
}

inm_s32_t
__inm_unregister_reboot_notifier(struct notifier_block **nb)
{
	struct notifier_block *nblock = *nb;

	*nb = NULL;
	info("Unregistered reboot notification");
	return unregister_reboot_notifier(nblock);
}

inm_s32_t
inm_register_reboot_notifier(int reboot_notify)
{
	static struct notifier_block *nblock = NULL;

	/* we only support single reboot notification */
	if (reboot_notify) {
		if (nblock)
			return 0;
		return __inm_register_reboot_notifier(&nblock);
	} else {
		if (!nblock)
			return 0;
		return __inm_unregister_reboot_notifier(&nblock);
	}
}

void
log_console(const char *fmt, ...)
{
	char buf[256];
	va_list args;

	if (fmt) {
		va_start(args, fmt);
		vsnprintf(buf, sizeof(buf), fmt, args);
		va_end(args);

		buf[sizeof(buf) - 1] = '\0';

		write_to_file("/dev/console", buf, sizeof(buf), NULL);
	}
}

void
inm_blkdev_name(inm_bio_dev_t *bdev, char *name)
{
#if defined(RHEL9_2) || defined(RHEL9_3) || defined(RHEL9_4) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	snprintf(name, INM_BDEVNAME_SIZE, "%pg", bdev);
#else
	bdevname(bdev, name);
#endif
}

inm_s32_t
inm_blkdev_get(inm_bio_dev_t *bdev)
{
#ifdef INM_HANDLE_FOR_BDEV_ENABLED
	return (IS_ERR(bdev_open_by_dev(bdev->bd_dev,
			FMODE_READ | FMODE_WRITE, NULL, NULL)) ? 1: 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0) || defined(RHEL9_4) || defined(SLES15SP6)
	return (IS_ERR(blkdev_get_by_dev(bdev->bd_dev,
			BLK_OPEN_READ | BLK_OPEN_WRITE, NULL, NULL)) ? 1 : 0);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	return (IS_ERR(blkdev_get_by_dev(bdev->bd_dev,
				FMODE_READ | FMODE_WRITE, NULL)) ? 1 : 0);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38))
	return blkdev_get(bdev, FMODE_READ | FMODE_WRITE, NULL);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19))
	return blkdev_get(bdev, FMODE_READ | FMODE_WRITE);
#else
	return blkdev_get(bdev, FMODE_READ | FMODE_WRITE, 0);
#endif
}
