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
#include "tunable_params.h"
#include "db_routines.h"
#include "filter.h"
#include "filter_host.h"
#include "osdep.h"
#include "telemetry-types.h"
#include "telemetry.h"
#include "errlog.h"

#ifdef INM_LINUX
#include "filter_lun.h"
#endif

#define MIN_INFOS_POOL_NUMBER 256

extern driver_context_t *driver_ctx;
#ifdef IDEBUG_MIRROR_IO
extern inm_s32_t inject_atio_err;
extern inm_s32_t inject_ptio_err;
extern inm_s32_t inject_vendorcdb_err;
extern inm_s32_t clear_vol_entry_err;
#endif

#ifdef INM_LINUX
extern inm_s32_t driver_state;
#endif


void do_stop_filtering(target_context_t *);
extern void gen_bmaphdr_fname(char *volume_name, char *bhfname);
extern inm_s32_t dev_validate(inm_dev_extinfo_t *, host_dev_ctx_t **);
static void mv_stale_entry_to_dead_list(target_context_t *, 
						struct inm_list_head *,
						struct inm_list_head *, 
						struct inm_list_head *);
static inm_s32_t inm_deref_all_vol_entry_list(struct inm_list_head *, 
						target_context_t *);
static void inm_mirror_done(inm_mirror_bufinfo_t *mbufinfo);
static mirror_vol_entry_t * inm_get_healthy_vol_entry(target_context_t *tcp);
static inm_mirror_atbuf * inm_freg_atbuf(inm_mirror_atbuf *atbuf_wrap);
static inm_mirror_atbuf * inm_alloc_atbuf_wrap(inm_mirror_bufinfo_t *mbufinfo);
static void inm_map_abs_off_ln(inm_buf_t *, target_context_t *, inm_u64_t *);

inm_s32_t
isrootdev(target_context_t *vcptr)
{
	int isroot = 0;

	volume_lock(vcptr);

	if (vcptr->tc_flags & VCF_ROOT_DEV)
		isroot = 1;

	volume_unlock(vcptr);

	return isroot;
}

void
init_volume_fully(target_context_t *tgt_ctxt, inm_dev_extinfo_t *dev_info)
{
		info("Initialising %s fully", tgt_ctxt->tc_guid);

		if (strncmp(tgt_ctxt->tc_pname, dev_info->d_pname, 
							INM_GUID_LEN_MAX)) {
			/* Root disk persistent name is different */
			info("Updating %s pname: %s", tgt_ctxt->tc_guid, 
							dev_info->d_pname);
			strcpy_s(tgt_ctxt->tc_pname, INM_GUID_LEN_MAX, 
							dev_info->d_pname);
		}

		/* Check for bmap file in deprecated path */
		fill_bitmap_filename_in_volume_context(tgt_ctxt);

		/* Read the tunables for this protected volume */
		load_volume_params(tgt_ctxt);

		volume_lock(tgt_ctxt);
		tgt_ctxt->tc_flags &= ~VCF_VOLUME_STACKED_PARTIALLY;
		volume_unlock(tgt_ctxt);
}   
	
int
do_volume_stacking(inm_dev_extinfo_t *dev_info)
{
	target_context_t *ctx, *tgt_ctx = NULL;
	host_dev_ctx_t *hdcp = NULL;
	mirror_vol_entry_t *vol_entry = NULL;
	inm_s32_t err = -1;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("do_volume_stacking: entered");
	}

	ctx = target_context_ctr();
	if (!ctx) {
		err = INM_ENOMEM;
		err("failed to alloc space for target context");
		return err;
	}

	if ((err = dev_validate(dev_info, &hdcp))) {
	   err("Failed to validate the device with error %d\n", err);
	   target_context_dtr(ctx);
	   return err;
	}

retry:
	INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));

	/* check if sysfs entry with the same d_guid/scsi id has already added to sysfs
	 * This is required to break out from Double stacking retry loop
	 */
	switch(dev_info->d_type) {
		case FILTER_DEV_HOST_VOLUME:
		case FILTER_DEV_FABRIC_LUN:
			tgt_ctx = get_tgt_ctxt_from_uuid_locked(dev_info->d_guid);
			/* Another disk with same persistent name is not protected */
			if (!tgt_ctx) {
				tgt_ctx = get_tgt_ctxt_from_name_nowait_locked(dev_info->d_pname);
				if (tgt_ctx)
					put_tgt_ctxt(tgt_ctx);
			}
		break;

		case FILTER_DEV_MIRROR_SETUP:
			tgt_ctx = get_tgt_ctxt_from_scsiid_locked(dev_info->d_src_scsi_id);
		break;

		default: err("Invalid case for filter dev type:%d",
					 		dev_info->d_type);
	}

	if (!tgt_ctx) {
		ctx->tc_priv = hdcp;
		INM_INIT_LIST_HEAD(&ctx->tc_list);
		INM_INIT_LIST_HEAD(&ctx->tc_nwo_dmode_list);
		INM_INIT_LIST_HEAD(&ctx->cdw_list);
		INM_INIT_SEM(&ctx->cdw_sem);
		ctx->tc_dev_type = dev_info->d_type;
		strcpy_s(ctx->tc_guid, INM_GUID_LEN_MAX, dev_info->d_guid);
		INM_INIT_LIST_HEAD(&(ctx->tc_src_list));
		INM_INIT_LIST_HEAD(&(ctx->tc_dst_list));
		switch (ctx->tc_dev_type) {
			case FILTER_DEV_FABRIC_LUN:
			case FILTER_DEV_HOST_VOLUME:
				strcpy_s(ctx->tc_pname, INM_GUID_LEN_MAX, 
							dev_info->d_pname);
				break;
			case FILTER_DEV_MIRROR_SETUP:
				strcpy_s(ctx->tc_pname, INM_GUID_LEN_MAX, dev_info->d_src_scsi_id);
				/* check for boot time stacking ioctl for mirror setup */
				if (dev_info->d_flags & MIRROR_VOLUME_STACKING_FLAG) {
					INM_BUG_ON(inm_list_empty(dev_info->src_list));
					INM_BUG_ON(inm_list_empty(dev_info->dst_list));
					list_change_head(&ctx->tc_src_list, 
							dev_info->src_list);
					list_change_head(&ctx->tc_dst_list, 
							dev_info->dst_list);
					dev_info->src_list = &ctx->tc_src_list;
					dev_info->dst_list = &ctx->tc_dst_list;
					/* Get the first entry in the list and set it as tcp mirror_dev */
					vol_entry = inm_list_entry(ctx->tc_dst_list.next,
							mirror_vol_entry_t,
							next);
					INM_BUG_ON(!vol_entry);
					ctx->tc_vol_entry = vol_entry;
					INM_BUG_ON(!(ctx->tc_vol_entry));
				}
				   break;
			default:
				err("invalid filter dev type:%d",
							ctx->tc_dev_type);
		}
		ctx->tc_flags = VCF_FILTERING_STOPPED | VCF_VOLUME_CREATING;
#ifdef INM_LINUX
		if (driver_state & DRV_LOADED_PARTIALLY) {
			ctx->tc_flags |= VCF_VOLUME_STACKED_PARTIALLY;
			ctx->tc_flags |= VCF_VOLUME_INITRD_STACKED;
		}
#endif
		INM_INIT_WAITQUEUE_HEAD(&ctx->tc_waitq);
		INM_TRY_MODULE_GET();
		add_tc_to_dc(ctx);
		INM_UP_WRITE(&(driver_ctx->tgt_list_sem));

		if ((err = tgt_ctx_common_init(ctx, dev_info))) {
			if (err == INM_EEXIST) {
				dbg("Double stacking failed for %s\n", 
							dev_info->d_guid);
				INM_DELAY(3*INM_HZ);
				goto retry;
			}
			return err;
		}


		   if((err = tgt_ctx_spec_init(ctx, dev_info))) {
				free_data_file_flt_ctxt(ctx);
				put_tgt_ctxt(ctx);
				return err;
		   }

	volume_lock(ctx);
	ctx->tc_flags &= ~VCF_VOLUME_CREATING;
	if (dev_info->d_flags & HOST_VOLUME_STACKING_FLAG) {
		ctx->tc_flags |= VCF_VOLUME_BOOTTIME_STACKED;

#ifdef INITRD_MODE
			/* If any disk is not protected in initrd and then protected at
			 * boot time stacking stage, needs to be marked for resync.
			 */
			if ((driver_state & DRV_LOADED_FULLY) &&
					!(ctx->tc_flags & 
					VCF_VOLUME_INITRD_STACKED)) {
				err("The disk %s is not protected in initrd", 
								ctx->tc_guid);
				queue_worker_routine_for_set_volume_out_of_sync(ctx,
						ERROR_TO_REG_UNCLEAN_SYS_BOOT,
						LINVOLFLT_ERR_IN_SYNC);
			}
#endif
		}

		ctx->tc_flags |= VCF_IN_NWO;
		volume_unlock(ctx);

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);
		add_disk_sess_to_dc(ctx);
		driver_ctx->total_prot_volumes_in_nwo++;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);

		INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));
		if(!(dev_info->d_flags & (MIRROR_VOLUME_STACKING_FLAG | 
					HOST_VOLUME_STACKING_FLAG))){
			ctx->tc_dev_startoff = dev_info->d_startoff;
		}
		wake_up_tc_state(ctx);
		INM_UP_WRITE(&(driver_ctx->tgt_list_sem));

		info("Stacked: %s -> %s", dev_info->d_pname, dev_info->d_guid);
		err = 0;
	} else {
		/* get_tgt_ctxt_from_uuid_locked() returns without reference */
		get_tgt_ctxt(tgt_ctx);
		INM_UP_WRITE(&(driver_ctx->tgt_list_sem));

		if (tgt_ctx->tc_flags & VCF_VOLUME_STACKED_PARTIALLY) {
			if (driver_state & DRV_LOADED_FULLY)
				init_volume_fully(tgt_ctx, dev_info);
			err = 0;
		} else {
			if ((err = inm_validate_tc_devattr(tgt_ctx, 
						(inm_dev_info_t *)dev_info))) {
				if ((err = inm_is_upgrade_pname(tgt_ctx->tc_pname, 
								dev_info->d_pname))) {
					err("Existing: %s -> %s, Requested %s -> %s",
						tgt_ctx->tc_pname, tgt_ctx->tc_guid, 
						dev_info->d_pname, dev_info->d_guid);
				} else {
					dbg("PNAME: %s == %s",tgt_ctx->tc_pname, 
								dev_info->d_pname);
				}
			} else {
				dbg("Volume Stacking already done for %s\n", 
								dev_info->d_guid);
				err = 0;
			}
		}

		put_tgt_ctxt(tgt_ctx);
		target_context_dtr(ctx);
		inm_free_host_dev_ctx(hdcp);
	}

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("do_volume_stacking: leaving err:%d", err);
	}
	return err;
}

/* driver state */
extern inm_s32_t inm_mod_state;

void
do_unstack_all()
{
	target_context_t *tgt_ctxt;
#ifdef INM_AIX
	int ipl = 0;
#endif

	inm_mod_state |= INM_ALLOW_UNLOAD;

	INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));
	get_time_stamp(&(driver_ctx->dc_tel.dt_unstack_all_time));

retry:
	while(!inm_list_empty(&driver_ctx->tgt_list)){
		tgt_ctxt = inm_list_entry(driver_ctx->tgt_list.next,
			   			target_context_t, tc_list);
		info("unstack_all : ctx:%p tc_guid:%s", tgt_ctxt,
			   				tgt_ctxt->tc_guid);
		if(check_for_tc_state(tgt_ctxt, 1)){
			tgt_ctxt = NULL;
			goto retry;
		}

#ifdef INM_AIX
		INM_SPIN_LOCK(&driver_ctx->tgt_list_lock, ipl);
#endif
		volume_lock(tgt_ctxt);
		tgt_ctxt->tc_flags |= VCF_VOLUME_DELETING;
		tgt_ctxt->tc_filtering_disable_required = 1;
		get_time_stamp(&(tgt_ctxt->tc_tel.tt_user_stop_flt_time));
		telemetry_set_dbs(&tgt_ctxt->tc_tel.tt_blend, 
					 DBS_FILTERING_STOPPED_BY_USER);
		volume_unlock(tgt_ctxt);
#ifdef INM_AIX
		INM_SPIN_UNLOCK(&driver_ctx->tgt_list_lock, ipl);
#endif
		if (driver_ctx->dc_root_disk == tgt_ctxt)
			driver_ctx->dc_root_disk = NULL;
		INM_UP_WRITE(&(driver_ctx->tgt_list_sem));

		if(tgt_ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN)
			inm_scst_unregister(tgt_ctxt);

		tgt_ctx_force_soft_remove(tgt_ctxt);
		INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));
	}

	INM_UP_WRITE(&(driver_ctx->tgt_list_sem));
}

void
start_notify_completion(void)
{
	data_mode_cleanup_for_s2_exit();
}

void
involflt_completion(target_context_t *tgt_ctxt, write_metadata_t *wmdp, 
				inm_wdata_t *wdatap, int lock_held)
{
	INM_BUG_ON_TMP(tgt_ctxt);

	if (!lock_held)
		volume_lock(tgt_ctxt);

	tgt_ctxt->tc_bytes_tracked += wmdp->length;

	update_cx_session(tgt_ctxt, wmdp->length);

	if(!(tgt_ctxt->tc_flags & VCF_FILTERING_STOPPED)) {

		switch(tgt_ctxt->tc_cur_mode) {
		case FLT_MODE_DATA:
			save_data_in_data_mode(tgt_ctxt, wmdp, wdatap);
			break;
	
		default:
			if (save_data_in_metadata_mode(tgt_ctxt, wmdp, wdatap)) {
				if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
					info("Save meta data function failed:...\n");
				}
			}
			break;
		}

		if (!tgt_ctxt->tc_bp->volume_bitmap &&
			!(tgt_ctxt->tc_flags & VCF_OPEN_BITMAP_REQUESTED) &&
			can_open_bitmap_file(tgt_ctxt, FALSE) &&
			(!driver_ctx->sys_shutdown)) {
			request_service_thread_to_open_bitmap(tgt_ctxt);
		}
	}

	if (!lock_held)
		volume_unlock(tgt_ctxt);

	if(should_wakeup_s2(tgt_ctxt))
		INM_WAKEUP_INTERRUPTIBLE(&tgt_ctxt->tc_waitq);
}

int
do_start_filtering(inm_devhandle_t *idhp, inm_dev_extinfo_t *dev_infop)
{
	inm_s32_t r = 0;
	target_context_t *ctx = NULL;
	inm_block_device_t  *src_dev;

	switch(dev_infop->d_type) {
		case FILTER_DEV_HOST_VOLUME:
			r = validate_pname(dev_infop->d_pname);
			if (!r)
			r = do_volume_stacking(dev_infop);

			if (r){
				err("volume:%s -> %s stacking failed with %d",
					dev_infop->d_guid, dev_infop->d_pname, 
					r);
			}
		break;
		case FILTER_DEV_FABRIC_LUN:
#ifdef INM_LINUX
			src_dev = NULL;
			src_dev = open_by_dev_path(dev_infop->d_guid, 0);
			if (src_dev) {
				close_bdev(src_dev, FMODE_READ);
				r = INM_EINVAL;
				err("Device:%s incorrectly sent as source device for AT LUN",
					dev_infop->d_guid);
			}
#else
			INM_BUG_ON(1);
#endif
		break;

		default:
			r = INM_EINVAL;
			err("Invalid source:%s device type:%d",
				dev_infop->d_guid, dev_infop->d_type);
	}
	if (r)
		return r;

	ctx = get_tgt_ctxt_from_uuid(dev_infop->d_guid);
	if (ctx) {
		inm_s32_t flt_on = FALSE;

		volume_lock(ctx);

		get_time_stamp(&(ctx->tc_tel.tt_start_flt_time_by_user));

		if(is_target_filtering_disabled(ctx)) {
			ctx->tc_flags &= ~VCF_FILTERING_STOPPED;
			ctx->tc_flags |= VCF_IGNORE_BITMAP_CREATION;
			flt_on = TRUE;
		}

	/* Request the service thread to open the bitmap file, by which
	 * the filtering mode & write order state would change and helps
	 * in issuing tags for a disk (belonging to a volume group) with
	 * no I/Os.
	 */
	if (!ctx->tc_bp->volume_bitmap &&
		!(ctx->tc_flags & VCF_OPEN_BITMAP_REQUESTED) &&
		can_open_bitmap_file(ctx, FALSE) &&
		(!driver_ctx->sys_shutdown)){
		request_service_thread_to_open_bitmap(ctx);
	}

		volume_unlock(ctx);
		if (flt_on) {
			set_int_vol_attr(ctx, VolumeFilteringDisabled, 0);
			set_unsignedlonglong_vol_attr(ctx, VolumeRpoTimeStamp,
				ctx->tc_hist.ths_start_flt_ts*HUNDREDS_OF_NANOSEC_IN_SECOND);
		}

		if (!idhp->private_data) {
			idhp->private_data = (void *)ctx;
		} else {
			put_tgt_ctxt(ctx);
		}

		if (dev_infop->d_type == FILTER_DEV_HOST_VOLUME &&
			strcmp(dev_infop->d_mnt_pt, ctx->tc_mnt_pt)) {
			set_string_vol_attr(ctx, VolumeMountPoint, 
							dev_infop->d_mnt_pt);
		}
		set_unsignedlonglong_vol_attr(ctx, VolumeIsDeviceMultipath,
		 ((dev_infop->d_flags & INM_IS_DEVICE_MULTIPATH)? 1:0));
		set_unsignedlonglong_vol_attr(ctx, VolumeDiskFlags, 
							dev_infop->d_flags);

		telemetry_clear_dbs(&ctx->tc_tel.tt_blend, 
					DBS_FILTERING_STOPPED_BY_USER);
		telemetry_clear_dbs(&ctx->tc_tel.tt_blend, 
					DBS_FILTERING_STOPPED_BY_KERNEL);

		r = 0;
	} else {
		r = INM_EINVAL;
		err("start filtering:%s failing with EINVAL", 
							dev_infop->d_guid);
	}

	return r;
}

mirror_vol_entry_t *
build_mirror_volume(inm_s32_t vol_length, void *ptr, 
		struct inm_list_head *mirror_list_head, int keep_device_open, 
		int lun_type)
{
	mirror_vol_entry_t *vol_entry = NULL;
	char *vol_ptr = NULL;

	keep_device_open = 1;

	vol_ptr = (char*)INM_KMALLOC(INM_GUID_LEN_MAX, INM_KM_SLEEP, 
							INM_KERNEL_HEAP);
	if(!vol_ptr){
	err("MIRROR Setup Failed: failed to allocate");
	goto out;
	}

	if (!INM_ACCESS_OK(VERIFY_READ,
		(void __INM_USER *)ptr, vol_length)) {
		err("MIRROR Setup Failed: Access violation while accessing \
			element in volume list");
		goto out;
	}

	if (INM_COPYIN(vol_ptr, ptr, vol_length)) {
		err("MIRROR Setup Failed: INM_COPYIN failed while accessing \
			volumes");
		goto out;
	}
	vol_ptr[vol_length-1] = '\0';
	vol_entry = (mirror_vol_entry_t*)INM_KMALLOC(sizeof(mirror_vol_entry_t),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!vol_entry){
		err("MIRROR Setup Failed: failed to allocate vol_entry");
		goto out;
	}

	if(INM_PIN(vol_entry, sizeof(mirror_vol_entry_t))){
		INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t), INM_KERNEL_HEAP);
		vol_entry = NULL;
		goto out;
	}

	INM_MEM_ZERO(vol_entry, sizeof(mirror_vol_entry_t));
	strncpy_s(vol_entry->tc_mirror_guid, INM_GUID_LEN_MAX, vol_ptr, 
								vol_length);
	vol_entry->vol_flags = lun_type;

	/* Find out the mirror device */
	if(inm_get_mirror_dev(vol_entry)){
		INM_UNPIN(vol_entry, sizeof(mirror_vol_entry_t));
		INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t), INM_KERNEL_HEAP);
		vol_entry = NULL;
		goto out;
	}

	dbg("Mirror volume: Volume Path %s", vol_ptr);
	if (vol_entry && mirror_list_head) {
		vol_entry->vol_error = 0;
		vol_entry->vol_state = INM_VOL_ENTRY_ALIVE;
		vol_entry->vol_count = NO_SKIPS_AFTER_ERROR;
		INM_ATOMIC_SET(&vol_entry->vol_ref, 1);
		inm_list_add_tail(&vol_entry->next, mirror_list_head);
	}

out:
	if (vol_ptr) {
		INM_KFREE(vol_ptr, INM_GUID_LEN_MAX, INM_KERNEL_HEAP);
	}
	return vol_entry;
}

void
free_mirror_list(struct inm_list_head *list_head, int close_device)
{
	struct inm_list_head *ptr = NULL,*nextptr = NULL;
	mirror_vol_entry_t *vol_entry;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("free_mirror_list: entered");
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
			info("Traversing volume list");
	}

	close_device = 1;

	inm_list_for_each_safe(ptr, nextptr, list_head) {
		inm_list_del(ptr);
		vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
			info("vol:%s ",vol_entry->tc_mirror_guid);
	}

	inm_free_mirror_dev(vol_entry);
		vol_entry->vol_state = INM_VOL_ENTRY_FREED;
	INM_UNPIN(vol_entry, sizeof(mirror_vol_entry_t));
		INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t), 
						INM_KERNEL_HEAP);
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("\nfree_mirror_list: leaving");
	}

}

void
print_mirror_list(struct inm_list_head *list_head)
{
	struct inm_list_head *ptr = NULL,*nextptr = NULL;
	mirror_vol_entry_t *vol_entry;

	inm_list_for_each_safe(ptr, nextptr, list_head) {
		vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);
		info(":%s: mirror_dev:%p",vol_entry->tc_mirror_guid, 
						vol_entry->mirror_dev);
	}
}


inm_s32_t
populate_volume_lists(struct inm_list_head *src_mirror_list_head, 
				struct inm_list_head *dst_mirror_list_head,
				mirror_conf_info_t *mirror_infop)
{
	inm_s32_t r, num_src_vols, num_dst_vols, i, vol_length;
	void *user_buf = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entered");
	}

	r = 0;

	/* Get the number of source volumes   */
	num_src_vols = mirror_infop->nsources;
	vol_length = INM_GUID_LEN_MAX;

	/* Form a list of source volume guids */
	user_buf = mirror_infop->src_guid_list;
	for (i=1; i<=num_src_vols; i++) {
		if (!build_mirror_volume(vol_length, user_buf,
					src_mirror_list_head, 0, INM_PT_LUN)) {
			err("Error while building the source volume of mirror setup");
			r = SRC_LUN_INVALID;
			break;
		}
		user_buf += vol_length;
	}

	if (r) {
		/* Release volume entries for source volume */
		free_mirror_list(src_mirror_list_head, 0);
		return r;
	}

	/* Get the number of source volumes   */
	num_dst_vols = mirror_infop->ndestinations;

	/* Form a list of AT LUN guids */
	user_buf = mirror_infop->dst_guid_list;
	for (i=1; i<=num_dst_vols; i++) {
		if (!build_mirror_volume(vol_length, user_buf, 
					dst_mirror_list_head, 1, INM_AT_LUN)) {
			err("Error while building the destination volume of mirror setup");
			r = ATLUN_INVALID;
			break;
		}
		user_buf += vol_length;
	}

	if (r) {
		/* Release volume entries for source and destination volumes */
		free_mirror_list(src_mirror_list_head, 0);
		free_mirror_list(dst_mirror_list_head, 1);
		return r;
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving r:%d",r);
	}
	return r;

}

void
write_src_dst_attr(target_context_t *ctxt, mirror_conf_info_t *mirror_infop)
{
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	mirror_vol_entry_t *vol_entry;
	char *buf = NULL;
	int buf_len = 0;
	char *sptr;
	int size = mirror_infop->nsources*INM_GUID_LEN_MAX;

	buf = INM_KMALLOC(size, INM_KM_SLEEP, INM_KERNEL_HEAP);
	INM_MEM_ZERO(buf, size);

	sptr = buf;
	volume_lock(ctxt);
	inm_list_for_each_safe(ptr, nextptr, &ctxt->tc_src_list) {
		vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);
		if (sptr!=buf) {
			snprintf(sptr, size-buf_len, ",");
			sptr += 1;
			buf_len += 1;
		}
		snprintf(sptr, strlen(vol_entry->tc_mirror_guid)+1, "%s",
			vol_entry->tc_mirror_guid);
		sptr += strlen(vol_entry->tc_mirror_guid);
		buf_len += strlen(vol_entry->tc_mirror_guid);
	}
	volume_unlock(ctxt);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("Formed source list:%s size:%d", buf, (int)strlen(buf));
	}
	set_string_vol_attr(ctxt, VolumeMirrorSourceList, buf);

	if (buf) {
		INM_KFREE(buf, size, INM_KERNEL_HEAP);
		buf = NULL;
	}
	size = mirror_infop->ndestinations*INM_GUID_LEN_MAX;
	buf = INM_KMALLOC(size, INM_KM_SLEEP, INM_KERNEL_HEAP);
	INM_MEM_ZERO(buf, size);
	sptr = buf;
	volume_lock(ctxt);
	inm_list_for_each_safe(ptr, nextptr, &ctxt->tc_dst_list) {
		vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);
		if (sptr!=buf) {
			snprintf(sptr, size-buf_len, ",");
			sptr += 1;
			buf_len += 1;
		}
		snprintf(sptr, size-buf_len, "%s",
			vol_entry->tc_mirror_guid);
		sptr += strlen(vol_entry->tc_mirror_guid);
		buf_len += strlen(vol_entry->tc_mirror_guid);
	}
	volume_unlock(ctxt);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("Formed destination list:%s size:%d", buf, (int)strlen(buf));
	}
	set_string_vol_attr(ctxt, VolumeMirrorDestinationList, buf);
	if (buf) {
		INM_KFREE(buf, size, INM_KERNEL_HEAP);
	}
}

int
do_start_mirroring(inm_devhandle_t *idhp, mirror_conf_info_t *mirror_infop)
{
	inm_s32_t r;
	inm_s32_t mark_resync = 0;
	target_context_t *ctx;
	inm_dev_extinfo_t *dev_infop = NULL;
	struct inm_list_head src_mirror_list_head, dst_mirror_list_head;
	struct inm_list_head del_src_mirror_list_head, del_dst_mirror_list_head;
	struct inm_list_head deref_mirror_list;
	struct inm_list_head *ptr1, *nextptr1;
	struct inm_list_head *ptr2, *nextptr2;
	mirror_vol_entry_t *vol_entry1, *vol_entry2;
	mirror_vol_entry_t *vol_entry = NULL;
	host_dev_t *hdc_dev = NULL;
	host_dev_ctx_t *hdcp = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entered");
	}

	ctx = NULL;
	r = INM_EINVAL;
	INM_INIT_LIST_HEAD(&src_mirror_list_head);
	INM_INIT_LIST_HEAD(&dst_mirror_list_head);
	INM_INIT_LIST_HEAD(&del_src_mirror_list_head);
	INM_INIT_LIST_HEAD(&del_dst_mirror_list_head);
	INM_INIT_LIST_HEAD(&deref_mirror_list);
	mirror_infop->d_status = populate_volume_lists(&src_mirror_list_head,
						&dst_mirror_list_head,
						mirror_infop);
	if (mirror_infop->d_status) {
		r = EINVAL;
		goto out;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("source volumes:%u scsi_id:%s: list: ",
			mirror_infop->nsources, mirror_infop->src_scsi_id);
		print_mirror_list(&src_mirror_list_head);
		info("destination volumes:%u scsi_id:%s: list: ",
			mirror_infop->ndestinations, mirror_infop->dst_scsi_id);
		print_mirror_list(&dst_mirror_list_head);
	}

	if (!mirror_infop->nsources) {
		err("Number of source devices is zero");
		r = EINVAL;
		mirror_infop->d_status = SRC_LUN_INVALID;
		free_mirror_list(&src_mirror_list_head, 0);
		free_mirror_list(&dst_mirror_list_head, 1);
		goto out;
	}
	if (!mirror_infop->ndestinations) {
		err("Number of destination devices is zero");
		r = EINVAL;
		mirror_infop->d_status = ATLUN_INVALID;
		free_mirror_list(&src_mirror_list_head, 0);
		free_mirror_list(&dst_mirror_list_head, 1);
		goto out;
	}
	if (mirror_infop->src_scsi_id[0] == ' ' || 
				mirror_infop->src_scsi_id[0] == '\0') {
		err("Empty source scsi id:%s:",mirror_infop->src_scsi_id);
		r = EINVAL;
		mirror_infop->d_status = SRC_DEV_SCSI_ID_ERR;
		free_mirror_list(&src_mirror_list_head, 0);
		free_mirror_list(&dst_mirror_list_head, 1);
		goto out;
	}
	if (mirror_infop->dst_scsi_id[0] == ' ' || 
				mirror_infop->dst_scsi_id[0] == '\0') {
		err("Empty destination scsi id:%s:",mirror_infop->src_scsi_id);
		r = EINVAL;
		mirror_infop->d_status = DST_DEV_SCSI_ID_ERR;
		free_mirror_list(&src_mirror_list_head, 0);
		free_mirror_list(&dst_mirror_list_head, 1);
		goto out;
	}
	vol_entry = inm_list_entry(src_mirror_list_head.next, 
						mirror_vol_entry_t, next);
	INM_BUG_ON(!vol_entry);
	dev_infop = (inm_dev_extinfo_t *)INM_KMALLOC(sizeof(inm_dev_extinfo_t), 
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!dev_infop) {
		err("INM_KMALLOC failed to allocate memory for inm_dev_info_t");
		r = INM_ENOMEM;
		mirror_infop->d_status = DRV_MEM_ALLOC_ERR;
		free_mirror_list(&src_mirror_list_head, 0);
		free_mirror_list(&dst_mirror_list_head, 1);
		goto out;
	}
	INM_MEM_ZERO(dev_infop, sizeof(inm_dev_extinfo_t));

	dev_infop->d_type = mirror_infop->d_type;
	strncpy_s(dev_infop->d_guid, INM_GUID_LEN_MAX, vol_entry->tc_mirror_guid,
			strlen(vol_entry->tc_mirror_guid)); 
	strncpy_s(dev_infop->d_src_scsi_id, INM_GUID_LEN_MAX, 
			mirror_infop->src_scsi_id, INM_MAX_SCSI_ID_SIZE); 
	strncpy_s(dev_infop->d_dst_scsi_id, INM_GUID_LEN_MAX, 
			mirror_infop->dst_scsi_id, INM_MAX_SCSI_ID_SIZE); 
	dev_infop->d_guid[INM_GUID_LEN_MAX-1] = '\0';
	dev_infop->d_src_scsi_id[strlen(mirror_infop->src_scsi_id)] = '\0';
	dev_infop->d_dst_scsi_id[strlen(mirror_infop->dst_scsi_id)] = '\0';
	dev_infop->d_flags = mirror_infop->d_flags;
	dev_infop->d_nblks = mirror_infop->d_nblks;
	dev_infop->d_bsize = mirror_infop->d_bsize;
	dev_infop->src_list = &src_mirror_list_head;
	dev_infop->dst_list = &dst_mirror_list_head;
	dev_infop->d_startoff = mirror_infop->startoff;

	if (mirror_infop->d_type == FILTER_DEV_MIRROR_SETUP) {
		r = do_volume_stacking(dev_infop);
		if (r) {
			mirror_infop->d_status = MIRROR_STACKING_ERR;
			free_mirror_list(&src_mirror_list_head, 0);
			free_mirror_list(&dst_mirror_list_head, 1);
			goto out;
		}
	}

	ctx = get_tgt_ctxt_from_scsiid(dev_infop->d_src_scsi_id);
	if (ctx) {
		inm_s32_t flt_on = FALSE;

		INM_DOWN_READ(&(driver_ctx->tgt_list_sem));

		if (mirror_infop->d_flags & 
				MIRROR_SETUP_PENDING_RESYNC_CLEARED_FLAG) {
			reset_volume_out_of_sync(ctx);
		}
		volume_lock(ctx);
		if (mirror_infop->d_flags & 
				MIRROR_SETUP_PENDING_RESYNC_CLEARED_FLAG) {
			ctx->tc_flags &= ~VCF_MIRRORING_PAUSED;
		}
		if (r) {
			goto err_case;
		}
		if (is_target_filtering_disabled(ctx)) {
			ctx->tc_flags &= ~VCF_FILTERING_STOPPED;
			ctx->tc_flags |= VCF_IGNORE_BITMAP_CREATION;
			ctx->tc_flags |= VCF_DATA_FILES_DISABLED;
			ctx->tc_flags |= VCF_BITMAP_WRITE_DISABLED;
			ctx->tc_flags |= VCF_BITMAP_READ_DISABLED;
			flt_on = TRUE;
		}

		/* disable data files for mirror setup */
		ctx->tc_flags |= VCF_DATA_FILES_DISABLED;

		/* In case of update, source devices may have new path in source list */
		if (!inm_list_empty(&ctx->tc_src_list)) {
			/* Discard filtered paths from the list */
			inm_list_for_each_safe(ptr1, nextptr1, &src_mirror_list_head) {
				vol_entry1 = inm_list_entry(ptr1, 
						mirror_vol_entry_t, next);
				inm_list_for_each_safe(ptr2, nextptr2, 
							&ctx->tc_src_list) {
					vol_entry2 = inm_list_entry(ptr2, 
							mirror_vol_entry_t, 
							next);
					if (!strcmp(vol_entry1->tc_mirror_guid,
						vol_entry2->tc_mirror_guid)) {
						inm_list_del(ptr1);
						inm_list_add_tail(ptr1, 
						&del_src_mirror_list_head);
						break;
					}
				}
			}
			/* check if new path has been added for source device */
			if (!inm_list_empty(&src_mirror_list_head)) {
				hdcp = (host_dev_ctx_t*)ctx->tc_priv;
				inm_list_for_each_safe(ptr2, nextptr2, 
						&src_mirror_list_head) {
					vol_entry2 = inm_list_entry(ptr2, 
						mirror_vol_entry_t, next);
					info("Mirror setup for new path:%s for scsi id:%s",
						vol_entry2->tc_mirror_guid,
						mirror_infop->src_scsi_id);
					/* Process vol_entry for adding to the list */
					hdc_dev = (host_dev_t*)INM_KMALLOC(sizeof(host_dev_t),
							INM_KM_NOSLEEP,
							INM_KERNEL_HEAP);
					INM_MEM_ZERO(hdc_dev, 
							sizeof(host_dev_t));
					if (hdc_dev) {
#if (defined(INM_LINUX))
						req_queue_info_t *q_info;
						hdc_dev->hdc_dev = vol_entry2->mirror_dev->bd_inode->i_rdev;
						hdc_dev->hdc_disk_ptr = vol_entry2->mirror_dev->bd_disk;
						volume_unlock(ctx);
						q_info = alloc_and_init_qinfo(vol_entry2->mirror_dev, ctx);
						volume_lock(ctx);
						if (!q_info) {
							r = INM_EINVAL;
							mirror_infop->d_status = DRV_MEM_ALLOC_ERR;
							INM_KFREE(hdc_dev, sizeof(host_dev_t), INM_KERNEL_HEAP);
							err("Failed to allocate and initialize q_info during"
							    "mirror setup");
							break;
						}
						hdc_dev->hdc_req_q_ptr = q_info;
						INM_ATOMIC_INC(&q_info->vol_users);
						init_tc_kobj(q_info, vol_entry2->mirror_dev,
							         &hdc_dev->hdc_disk_kobj_ptr);
						inm_list_add_tail(&hdc_dev->hdc_dev_list,
							&hdcp->hdc_dev_list_head);
#endif
#if (defined(INM_SOLARIS) || defined(INM_AIX))
						hdc_dev->hdc_dev = *(vol_entry2->mirror_dev);
						inm_list_add_tail(&hdc_dev->hdc_dev_list,
							&hdcp->hdc_dev_list_head);
#endif
						inm_list_del(ptr2);
						inm_list_add_tail(ptr2,
							&ctx->tc_src_list);
					}
				}
				mark_resync = 1;
			}
		}
		else if (inm_list_empty(&ctx->tc_src_list)) {
			list_change_head(&ctx->tc_src_list, 
					&src_mirror_list_head);
		}

		mv_stale_entry_to_dead_list(ctx, &dst_mirror_list_head,
			&del_dst_mirror_list_head, &deref_mirror_list);
		if (!inm_list_empty(&dst_mirror_list_head)) {
			 inm_list_splice_at_tail(&dst_mirror_list_head, 
					 &ctx->tc_dst_list);
		}

		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
			info("destination scsi_id:%s: list: ",
				 mirror_infop->dst_scsi_id);
			print_mirror_list(&(ctx->tc_dst_list));
		}

		/* Get the first entry in the list and set it as tcp mirror_dev */
		vol_entry = inm_list_entry(ctx->tc_dst_list.next, 
						mirror_vol_entry_t, next);
		INM_BUG_ON(!vol_entry);
		ctx->tc_vol_entry = vol_entry;

		if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
#if (defined(INM_LINUX))
			info("Setting up mirror for source:%s mirror dev:%s(%d,%d)",
				ctx->tc_guid, vol_entry->tc_mirror_guid,
				INM_GET_MAJOR((ctx->tc_vol_entry->mirror_dev)->bd_dev),
				INM_GET_MINOR((ctx->tc_vol_entry->mirror_dev)->bd_dev));
#endif
#if (defined(INM_SOLARIS) || defined(INM_AIX))
			info("Setting up mirror for source:%s mirror dev:%s(%d,%d)",
				ctx->tc_guid, vol_entry->tc_mirror_guid,
				INM_GET_MAJOR(*(ctx->tc_vol_entry->mirror_dev)),
				INM_GET_MINOR(*(ctx->tc_vol_entry->mirror_dev)));
#endif
		}
err_case:
		volume_unlock(ctx);
		inm_deref_all_vol_entry_list(&deref_mirror_list, ctx);
		INM_UP_READ(&(driver_ctx->tgt_list_sem));
		if (!inm_list_empty(&del_src_mirror_list_head)) {
			free_mirror_list(&del_src_mirror_list_head, 0);
		}
		if (!inm_list_empty(&del_dst_mirror_list_head)) {
			free_mirror_list(&del_dst_mirror_list_head, 1);
		}
		if (r) {
			if (!inm_list_empty(&del_src_mirror_list_head)) {
				free_mirror_list(&src_mirror_list_head, 0);
			}
			if (!inm_list_empty(&dst_mirror_list_head)) {
				free_mirror_list(&dst_mirror_list_head, 1);
			}
			put_tgt_ctxt(ctx);
			goto out;
		}
		write_src_dst_attr(ctx, mirror_infop);
		if (flt_on) {
			set_int_vol_attr(ctx, VolumeFilteringDisabled, 0);
		}
		set_unsignedlonglong_vol_attr(ctx, VolumeIsDeviceMultipath, 
		 ((mirror_infop->d_flags & INM_IS_DEVICE_MULTIPATH)? 1:0));
		set_int_vol_attr(ctx, VolumeDeviceVendor, 
						mirror_infop->d_vendor);
		set_unsignedlonglong_vol_attr(ctx, VolumeDiskFlags, 
						mirror_infop->d_flags);
		set_unsignedlonglong_vol_attr(ctx, VolumeDevStartOff, 
						mirror_infop->startoff);
		if (mark_resync) {
			queue_worker_routine_for_set_volume_out_of_sync(ctx,
				ERROR_TO_REG_NEW_SOURCE_PATH_ADDED,
				INM_EINVAL);
		}

		if (!idhp->private_data) {
			idhp->private_data = (void *)ctx;
		} else {
			put_tgt_ctxt(ctx);
		}

	} else { //need to change agent stuff
		r = INM_EINVAL;
		mirror_infop->d_status = MIRROR_STACKING_ERR;
		/* Release volume entries for source and destination volumes */
		free_mirror_list(&src_mirror_list_head, 0);
		free_mirror_list(&dst_mirror_list_head, 1);
	}

out:
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving r:%d status:%u",r, mirror_infop->d_status);
	}

	if(dev_infop){
		INM_KFREE(dev_infop, sizeof(inm_dev_extinfo_t), INM_KERNEL_HEAP); 
	}
	return r;
}

extern void inm_exchange_strategy(host_dev_ctx_t *);

void
do_stop_filtering(target_context_t *tgt_ctxt)
{
	struct inm_list_head chg_nodes_hd ;
	struct inm_list_head *curp = NULL, *nxtp = NULL;
	volume_bitmap_t *vbmap = NULL;
	bitmap_info_t   *bitmap = tgt_ctxt->tc_bp;
	inm_s32_t seton = FALSE;
	inm_u64_t PrevEndSequenceNumber;
	inm_u64_t PrevEndTimeStamp;
	inm_u32_t PrevSequenceIDforSplitIO;
	host_dev_ctx_t *hdcp = tgt_ctxt->tc_priv;

	INM_INIT_LIST_HEAD(&chg_nodes_hd);

	volume_lock(tgt_ctxt);
	if(!is_target_filtering_disabled(tgt_ctxt)) {
		/* pending change nodes are marked as orphaned nodes as we do
		 * in clear diffs
		 */
		if (tgt_ctxt->tc_pending_confirm && 
				!(tgt_ctxt->tc_pending_confirm->flags & 
				CHANGE_NODE_ORPHANED)) {
			change_node_t *cnp = tgt_ctxt->tc_pending_confirm;
			cnp->flags |= CHANGE_NODE_ORPHANED;
			inm_list_del_init(&cnp->next);
			/* If change node on non write order data mode list, then
			 * remove it from that list
			 */
			if (!inm_list_empty(&cnp->nwo_dmode_next)) {
				inm_list_del_init(&cnp->nwo_dmode_next);
			}
			deref_chg_node(cnp);
		} 
		inm_list_for_each_safe(curp, nxtp, 
				&tgt_ctxt->tc_nwo_dmode_list) {
			inm_list_del_init(curp);
		}
		list_change_head(&chg_nodes_hd, &tgt_ctxt->tc_node_head);
		INM_INIT_LIST_HEAD(&tgt_ctxt->tc_node_head);

		if(tgt_ctxt->tc_filtering_disable_required)
			tgt_ctxt->tc_flags |= VCF_FILTERING_STOPPED;

		tgt_ctxt->tc_cur_node = NULL;
		vbmap = bitmap->volume_bitmap;
		stop_filtering_device(tgt_ctxt, TRUE, &vbmap);
		info(" filtering mode = %d, stop filtering flag = %d, write order state = %d",
		tgt_ctxt->tc_cur_mode, is_target_filtering_disabled(tgt_ctxt), 
		tgt_ctxt->tc_cur_wostate);
		seton = TRUE;
	}

	if(!tgt_ctxt->tc_filtering_disable_required){
		seton = is_target_filtering_disabled(tgt_ctxt)? 1 : 0;
		PrevEndTimeStamp = tgt_ctxt->tc_PrevEndTimeStamp;
		PrevEndSequenceNumber = tgt_ctxt->tc_PrevEndSequenceNumber;
		PrevSequenceIDforSplitIO = tgt_ctxt->tc_PrevSequenceIDforSplitIO;
	}else{
		seton = TRUE;
		PrevEndTimeStamp = 0;
		PrevEndSequenceNumber = 0;
		PrevSequenceIDforSplitIO = 0;
	}
	tgt_ctxt->tc_filtering_disable_required = 0;

	volume_unlock(tgt_ctxt);

	set_int_vol_attr(tgt_ctxt, VolumeFilteringDisabled, seton);
	set_unsignedlonglong_vol_attr(tgt_ctxt, VolumePrevEndTimeStamp, 
						PrevEndTimeStamp);
	set_unsignedlonglong_vol_attr(tgt_ctxt, VolumePrevEndSequenceNumber, 
						PrevEndSequenceNumber);
	set_unsignedlonglong_vol_attr(tgt_ctxt, VolumePrevSequenceIDforSplitIO, 
						PrevSequenceIDforSplitIO);

	set_int_vol_attr(tgt_ctxt, VolumeDrainBlocked, 0);

	cleanup_change_nodes(&chg_nodes_hd, ecFilteringStopped);

	volume_lock(tgt_ctxt);
	tgt_ctxt->tc_stats.st_mode_switch_time = INM_GET_CURR_TIME_IN_SEC;
	tgt_ctxt->tc_stats.st_wostate_switch_time = INM_GET_CURR_TIME_IN_SEC;
	tgt_ctxt->tc_pending_changes = 0;
	tgt_ctxt->tc_bytes_pending_changes = 0;
	tgt_ctxt->tc_pending_wostate_data_changes = 0;
	tgt_ctxt->tc_pending_wostate_md_changes = 0;
	tgt_ctxt->tc_pending_wostate_bm_changes = 0;
	tgt_ctxt->tc_pending_wostate_rbm_changes = 0;
	tgt_ctxt->tc_commited_changes = 0;
	tgt_ctxt->tc_bytes_commited_changes = 0;

	bitmap = tgt_ctxt->tc_bp;
	bitmap->num_bitmap_open_errors = 0;
	bitmap->num_bitmap_clear_errors = 0;
	bitmap->num_bitmap_read_errors = 0;
	bitmap->num_bitmap_write_errors = 0;
	bitmap->num_changes_queued_for_writing = 0;
	bitmap->num_byte_changes_queued_for_writing = 0;
	bitmap->num_changes_read_from_bitmap = 0;
	bitmap->num_changes_written_to_bitmap = 0;
	bitmap->num_of_times_bitmap_written = 0;
	bitmap->num_of_times_bitmap_read = 0;

	telemetry_clear_dbs(&tgt_ctxt->tc_tel.tt_blend, 
					DBS_DRIVER_RESYNC_REQUIRED);
	tgt_ctxt->tc_resync_required = 0;
	tgt_ctxt->tc_resync_indicated = 0;
	tgt_ctxt->tc_nr_out_of_sync = 0;
	tgt_ctxt->tc_out_of_sync_err_code = 0;
	tgt_ctxt->tc_out_of_sync_time_stamp = 0;
	tgt_ctxt->tc_out_of_sync_err_status = 0;
	tgt_ctxt->tc_nr_out_of_sync_indicated = 0;

	volume_unlock(tgt_ctxt);

	remove_disk_sess_from_dc(tgt_ctxt);

	/* resetting resync required flags if set any */
	set_int_vol_attr(tgt_ctxt, VolumeResyncRequired, 
					tgt_ctxt->tc_resync_required);
	set_int_vol_attr(tgt_ctxt, VolumeOutOfSyncErrorCode, 
					tgt_ctxt->tc_out_of_sync_err_code);
	set_int_vol_attr(tgt_ctxt, VolumeOutOfSyncCount, 
					tgt_ctxt->tc_nr_out_of_sync);
	set_longlong_vol_attr(tgt_ctxt, VolumeOutOfSyncTimestamp, 
					tgt_ctxt->tc_out_of_sync_time_stamp);

	/* Exchange the strategy functions for host target context */
	if (tgt_ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		inm_exchange_strategy(hdcp);
	}

	/* Wait for all I/Os to complete */
	while (INM_ATOMIC_READ(&tgt_ctxt->tc_nr_in_flight_ios)) {
		INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(tgt_ctxt->tc_wq_in_flight_ios,
		(INM_ATOMIC_READ(&tgt_ctxt->tc_nr_in_flight_ios) == 0), 
		3 * INM_HZ);
	}

	volume_lock(tgt_ctxt);
#ifdef INM_QUEUE_RQ_ENABLED
	if(!inm_list_empty(&tgt_ctxt->tc_non_drainable_node_head)) {
		tgt_ctxt->tc_flags &= ~VCF_IO_BARRIER_ON;
		inm_list_splice_at_tail(&tgt_ctxt->tc_non_drainable_node_head,
			&tgt_ctxt->tc_node_head);
		INM_INIT_LIST_HEAD(&tgt_ctxt->tc_non_drainable_node_head);
	}
#endif
	list_change_head(&chg_nodes_hd, &tgt_ctxt->tc_node_head);
	INM_INIT_LIST_HEAD(&tgt_ctxt->tc_node_head);
	volume_unlock(tgt_ctxt);
	cleanup_change_nodes(&chg_nodes_hd, ecFilteringStopped);

	if (vbmap) {
		close_bitmap_file(vbmap, TRUE);
		bitmap->volume_bitmap = NULL;
	}
}

void
free_volume_list(tag_volinfo_t *vinfo, inm_s32_t num_vols)
{
	inm_s32_t temp = 0;
	tag_volinfo_t *lptr = vinfo;

	if(!vinfo)
		return;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	while(temp < num_vols) {
		if(lptr->ctxt) {
			volume_lock(lptr->ctxt);
			lptr->ctxt->tc_flags &= ~VCF_VOLUME_TO_BE_FROZEN;
			volume_unlock(lptr->ctxt);
			put_tgt_ctxt(lptr->ctxt);
		}

#ifdef INM_AIX
	if(lptr->chg_node){
		inm_free_change_node(lptr->chg_node);
	}

	if(lptr->meta_page){
		inm_page_t *pgp = lptr->meta_page;
		INM_UNPIN(pgp->cur_pg, INM_PAGESZ);
		INM_FREE_PAGE(pgp->cur_pg, INM_KERNEL_HEAP);
		pgp->cur_pg = NULL;
		INM_UNPIN(pgp, sizeof(inm_page_t));
		INM_KFREE(pgp, sizeof(inm_page_t), INM_KERNEL_HEAP);
	}
#endif

		temp++;
		lptr++;
	}

	INM_KFREE(vinfo, num_vols * sizeof(tag_volinfo_t), INM_KERNEL_HEAP);

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

}

void
free_tag_list(tag_info_t *tag_list, inm_s32_t num_tags)
{

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	INM_KFREE(tag_list, num_tags * sizeof(tag_info_t), INM_KERNEL_HEAP);

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

}

void
add_tags(tag_volinfo_t *tag_volinfop, tag_info_t *tag_info, inm_s32_t num_tags,
		tag_guid_t *tag_guid, inm_s32_t index)
{
	target_context_t *ctxt = tag_volinfop->ctxt;

	if (ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
		inm_form_tag_cdb(ctxt, tag_info, num_tags);
		return;
	}
	volume_lock(ctxt);
	if(ctxt->tc_cur_wostate != ecWriteOrderStateData) {
		add_tag_in_non_stream_mode(tag_volinfop, tag_info, num_tags, tag_guid, 
				   index, TAG_COMMIT_NOT_PENDING, NULL);
	} else {
		if(!add_tag_in_stream_mode(tag_volinfop, tag_info, num_tags, tag_guid, 
								index))
			add_tag_in_non_stream_mode(tag_volinfop, tag_info, num_tags, 
				tag_guid, index, TAG_COMMIT_NOT_PENDING, NULL);
	}
	volume_unlock(ctxt);

	INM_WAKEUP_INTERRUPTIBLE(&ctxt->tc_waitq);
}                                    

inm_s32_t
issue_tags(inm_s32_t vols, tag_volinfo_t *vol_list, inm_s32_t tags,
		tag_info_t *tag_list, inm_s32_t flags, tag_guid_t *tag_guid)
{
	inm_s32_t num_vols = 0, index = 0, error = 0;
	tag_volinfo_t *temp = vol_list;


	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	/* Freeze all volumes */
	if (!(flags & TAG_FS_FROZEN_IN_USERSPACE)) {
		freeze_volumes(vols, vol_list);
	}

	while(num_vols < vols) {
		if(temp->ctxt && temp->ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP &&
				temp->ctxt->tc_cur_wostate != ecWriteOrderStateData) {
			dbg("One of the volume is not in Wrote Order State Data");
			error = INM_EAGAIN;
			goto unfreeze_all;
		}

		num_vols++;
		temp++;
	}

	temp = vol_list;
	num_vols = 0;

	/* Issue tags to all volumes with the supplied timestamp. */
	while(num_vols < vols) {
		if(temp->ctxt) {
			add_tags(temp, tag_list, tags, tag_guid, index);
		}
		index++;
		num_vols++;
		temp++;
	}

unfreeze_all:
	/* Unfreeze all volumes */
	if (!(flags & TAG_FS_FROZEN_IN_USERSPACE)) {
		unfreeze_volumes(vols, vol_list);
	}

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return error;
}

static_inline tag_volinfo_t *
build_volume_list(inm_s32_t num_vols, void __INM_USER **user_buf, 
							inm_s32_t *error)
{
	inm_u16_t vol_length = 0;
	char vol_ptr[TAG_VOLUME_MAX_LENGTH];
	inm_s32_t i = 0;
	target_context_t *ctxt = NULL;
	tag_volinfo_t *list = NULL, *list_temp = NULL;

	inm_s32_t vols = 0;

#ifdef INM_AIX
	change_node_t *chg_node = NULL;
	inm_page_t *pgp = NULL;
#endif

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	*error = 0;

	list = (tag_volinfo_t *)INM_KMALLOC((num_vols * sizeof(tag_volinfo_t)),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!list) {
		err("TAG Input Failed: INM_KMALLOC failed for volumes");
		return 0;
	}

	list_temp = list;

	INM_MEM_ZERO(list, (num_vols * sizeof(tag_volinfo_t)));

	while(i < num_vols) {
		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)*user_buf,
					  sizeof(unsigned short))){
			err("TAG Input Failed: Access violation while accessing %d \
					    element in volume list", i);
			*error = -EFAULT;
			break;
		}

		if(INM_COPYIN(&vol_length, *user_buf, sizeof(unsigned short))) {
			err("TAG Input Failed: INM_COPYIN failed while accessing  \
							    flags");
			*error = -EFAULT;
			break;
		}

		if(vol_length > TAG_VOLUME_MAX_LENGTH) {
			err("TAG Input Failed: volume length greater than limit");
			*error = -EFAULT;
			break;
		}

		*user_buf += sizeof(unsigned short);

		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)*user_buf, vol_length)){
			err("TAG Input Failed: Access violation while accessing %d \
						element in volume list", i);
			*error = -EFAULT;
			break;
		}

		if(INM_COPYIN(vol_ptr, *user_buf, vol_length)) {
			err("TAG Input Failed: INM_COPYIN failed while accessing \
						flags");
			*error = -EFAULT;
			break;
		}
		vol_ptr[vol_length] = '\0';

		dbg("TAG: Volume Path %s", vol_ptr);

		ctxt = get_tgt_ctxt_from_uuid_nowait(vol_ptr);
		if(ctxt) {
			if(!is_target_filtering_disabled(ctxt) && 
					!is_target_being_frozen(ctxt)) {
				list_temp->ctxt = ctxt;
				vols++;
				volume_lock(ctxt);
				list_temp->ctxt->tc_flags |= VCF_VOLUME_TO_BE_FROZEN;
				volume_unlock(ctxt);
			} else {
				put_tgt_ctxt(ctxt);
			}
		} else {
			dbg("TAG Input Failed: can't issue tag to %s", vol_ptr);
			list_temp->ctxt = NULL;
		}

#ifdef INM_AIX
	chg_node = inm_alloc_change_node(NULL, INM_KM_NOSLEEP);
	if(!chg_node){
		err("Failed to allocate change node");
		*error = INM_ENOMEM;
		break;
	}

	INM_INIT_SEM(&chg_node->mutex);
	chg_node->mutext_initialized = 1;

	pgp = get_page_from_page_pool(0, 0, NULL);
	if(!pgp){
		INM_DESTROY_SEM(&chg_node->mutex);
		inm_free_change_node(chg_node);
		err("Failed to allocate metadata page");
		*error = INM_ENOMEM;
		break;
	}

	list_temp->chg_node = chg_node;
	list_temp->meta_page = pgp;
#endif

		*user_buf += vol_length;
		i++;
		list_temp++;
	}

	if(*error || !vols) {
		free_volume_list(list, num_vols);
		return NULL;
	}

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return list;
}

static_inline void
init_tag_list(tag_info_t *tag_ptr, inm_s32_t num_tags)
{
	inm_s32_t temp = 0;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	while(temp < num_tags) {
		tag_ptr->tag_len = 0;
		tag_ptr++;
		temp++;
	}

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

}

static_inline tag_info_t *
build_tag_list(inm_s32_t num_tags, void __INM_USER **user_buf, inm_s32_t *error)
{
	inm_s32_t temp = 0;
	inm_u16_t tag_length = 0;
	inm_s32_t valid_tags = 0;
	tag_info_t *tag_ptr = NULL;
	tag_info_t *tag_list = NULL;
	*error = 0;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	tag_list = (tag_info_t *)INM_KMALLOC((num_tags * sizeof(tag_info_t)),
				INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!tag_list) {
		err("Failed to allocated memory for tags");
		*error = -ENOMEM;
		return NULL;
	}

	tag_ptr = tag_list;
	init_tag_list(tag_list, num_tags);

	while(temp < num_tags) {

		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)*user_buf,
					  sizeof(unsigned short))){
			err("TAG Input Failed: Access violation while accessing %d \
						element in tag list", temp);
			*error = -EFAULT;
			break;
		}

		if(INM_COPYIN(&tag_length, *user_buf, sizeof(unsigned short))) {
			err("TAG Input Failed: Access violation while accessing %d \
						element in tag list", temp);
			*error = -EFAULT;
			break;
		}

		if((tag_length > TAG_MAX_LENGTH) || (tag_length <= 0)) {
			err("TAG Input Failed: Exceeded max limit size for each tag");
			*error = -EFAULT;
			break;
		}

		*user_buf += sizeof(unsigned short);

		if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)*user_buf,
					  tag_length)){
			err("TAG Input Failed: Access violation while accessing %d \
						element in tag list", temp);
			*error = -EFAULT;
			break;
		}

		if(INM_COPYIN(tag_ptr->tag_name, *user_buf, tag_length)) {
			err("TAG Input Failed: Access violation while accessing %d \
						element in tag list", temp);
			*error = -EFAULT;
			break;
		}
		tag_ptr->tag_len = tag_length;

		*user_buf += tag_length;
		temp++;
		tag_ptr++;
		valid_tags++;
	}

	if(*error || !valid_tags) {
		INM_KFREE(tag_list, (num_tags * sizeof(tag_info_t)), 
							INM_KERNEL_HEAP);
		return NULL;
	}

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return tag_list;
}

tag_guid_t *
get_tag_from_guid(char *guid)
{
	struct inm_list_head *ptr;
	tag_guid_t *tag_guid = NULL;

	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	for(ptr = driver_ctx->tag_guid_list.next; 
			ptr != &(driver_ctx->tag_guid_list);
			ptr = ptr->next, tag_guid = NULL) {
	tag_guid = inm_list_entry(ptr, tag_guid_t, tag_list);
	if(!strcmp(tag_guid->guid, guid))
		break;
	}
	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	return tag_guid;
}

void
flt_cleanup_sync_tag(tag_guid_t *tag_guid)
{
	if(!tag_guid)
	return;

	if(tag_guid->guid) 
		INM_KFREE(tag_guid->guid, tag_guid->guid_len + 1, INM_KERNEL_HEAP);

	if(tag_guid->status)
		INM_KFREE(tag_guid->status, tag_guid->num_vols * sizeof(inm_s32_t), 
							INM_KERNEL_HEAP);

	INM_DESTROY_WAITQUEUE_HEAD(&tag_guid->wq);
	INM_KFREE(tag_guid, sizeof(tag_guid_t), INM_KERNEL_HEAP);
}

int
flt_process_tags(inm_s32_t num_vols, void __INM_USER **user_buf,
		 inm_s32_t flags, tag_guid_t *tag_guid)
{
	inm_u16_t num_tags = 0;
	tag_volinfo_t *vol_list = NULL;
	tag_info_t *tag_list = NULL;
	inm_s32_t error = 0;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	/* Build volume list of target context info. Need to acquire tag_sem here when
	 * the volume list is built.
	 */

	INM_DOWN(&driver_ctx->tag_sem);

	vol_list = build_volume_list(num_vols, user_buf, &error);
	if(error || !vol_list){
		err("TAG Input Failed: Failed while building volume list");
		goto release_sem;
	}

	/* Get total number of tags.
	 */
	if(INM_COPYIN(&num_tags, *user_buf, sizeof(unsigned short))) {
		err("TAG Input Failed: INM_COPYIN failed while accessing flags");
		error = -EFAULT;
		goto release_sem;
	}

	if(num_tags <= 0) {
		err("TAG Input Failed: Number of tags can't be zero or negative");
		goto release_sem;
	}

	*user_buf += sizeof(unsigned short);

	/* Now, build the tag list.
	 */
	tag_list = build_tag_list(num_tags, user_buf, &error);
	if(error || !tag_list) {
		err("TAG Input Failed: Failed while building tag list");
		goto release_sem;
	}

	if(tag_guid){
		if(!INM_ACCESS_OK(VERIFY_WRITE, (void __INM_USER *)*user_buf,
				num_vols * sizeof(inm_s32_t))){ 
			err("TAG Input Failed: Access violation in getting guid status");
			error = INM_EFAULT;
			free_tag_list(tag_list, num_tags);
			goto release_sem;
		}
	}

	error = issue_tags(num_vols, vol_list, num_tags, tag_list, flags, 
								tag_guid);

	free_tag_list(tag_list, num_tags);

release_sem:
	INM_UP(&driver_ctx->tag_sem);
	free_volume_list(vol_list, num_vols);
	
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return error;
}

inm_s32_t
is_flt_disabled(char *pname) 
{
	char *s = NULL;
	inm_s32_t status = 0;

	s = INM_KMEM_CACHE_ALLOC_PATH(names_cachep, INM_KM_SLEEP, INM_PATH_MAX, 
							      INM_KERNEL_HEAP);
	INM_BUG_ON(!s);
	strncpy_s(s, INM_PATH_MAX, pname, INM_PATH_MAX);
	strcat_s(&s[0], INM_PATH_MAX, "/VolumeFilteringDisabled");
	read_value_from_file(s, &status);

	dbg("volume filter disabled flag = %d\n", status);
	INM_KMEM_CACHE_FREE_PATH(names_cachep, s,INM_KERNEL_HEAP);
	s = NULL;

	return ((status != 0) ? TRUE : FALSE);
}


inm_s32_t init_boottime_stacking(void)
{
	return 0;
}

void
load_bal_rr(target_context_t *ctx, inm_u32_t io_sz)
{
	struct inm_list_head *ptr, *hd, *nextptr;
	mirror_vol_entry_t *vol_entry = NULL;
	mirror_vol_entry_t *init_vol_entry = ctx->tc_vol_entry;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		dbg("entered");
	}

	INM_BUG_ON(!init_vol_entry);
	if(!init_vol_entry){
	   goto out;
	}
	if(io_sz){
		UPDATE_ATIO_SEND(init_vol_entry, io_sz);
		ctx->tc_commited_changes++;
		ctx->tc_bytes_commited_changes += io_sz;
	}
	hd = &(init_vol_entry->next);
	inm_list_for_each_safe(ptr, nextptr, hd){
		if(ptr == &(ctx->tc_dst_list)){
			continue;
		}
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		if(vol_entry->vol_error){
			vol_entry->vol_io_skiped++;
			continue;
		}
			ctx->tc_vol_entry = vol_entry;
		break;
	}

out:
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		 dbg("exiting");
	}
	return;
}

/* Function to discard dead entries from tc_dst_list and add only new path
 * entries to tc_dst_list 
 */
static void
mv_stale_entry_to_dead_list(target_context_t *tcp,
	struct inm_list_head *new_dst_listp, 
	struct inm_list_head *delete_dst_list,
	struct inm_list_head *deref_list)
{
	struct inm_list_head *ptr, *hd, *nextptr;
	struct inm_list_head *ptr_new, *hd_new, *nextptr_new;
	mirror_vol_entry_t *vol_entry = NULL;
	mirror_vol_entry_t *vol_entry_new = NULL;
	inm_s32_t mv_entry = 1;

	hd = &(tcp->tc_dst_list);
	inm_list_for_each_safe(ptr, nextptr, hd) {
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		hd_new = new_dst_listp;
		/* scan through destination list from user space (reconfiguration)
		 * and isolate common (already existing in tc_dst_list) from it 
		 * to delete_dst_list
		 */
		inm_list_for_each_safe(ptr_new, nextptr_new, hd_new) {
			vol_entry_new = inm_container_of(ptr_new, 
						mirror_vol_entry_t, next);
			if (!strncmp(vol_entry->tc_mirror_guid, 
						vol_entry_new->tc_mirror_guid, 
						INM_GUID_LEN_MAX)) {
				inm_list_del(ptr_new);
				inm_list_add_tail(ptr_new, delete_dst_list);
				vol_entry->vol_error = 0;
				mv_entry = 0;
				break;
			}
		}
		/* Uncommon entries are dead entries and are moved to dead list */
		if (mv_entry) {
			inm_list_del(ptr);
			inm_list_add_tail(ptr, deref_list);
		}
		mv_entry = 1;
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("tcp destination list: ");
		print_mirror_list(&(tcp->tc_dst_list));
		info("delete destination list: ");
		print_mirror_list(delete_dst_list);
		info("input new destination list: ");
		print_mirror_list(new_dst_listp);
		info("deref list list: ");
		print_mirror_list(deref_list);
	}
}

static inm_s32_t
inm_deref_all_vol_entry_list(struct inm_list_head *deref_list, 
					target_context_t *tcp)
{
	struct inm_list_head *ptr, *hd, *nextptr;
	mirror_vol_entry_t *vol_entry = NULL;
	inm_s32_t error = 0;
	hd = deref_list;
	inm_list_for_each_safe(ptr, nextptr, hd) {
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		while(INM_ATOMIC_READ(&(vol_entry->vol_ref)) > 1){
			INM_DELAY(1 * INM_HZ);
		}
	}
	free_mirror_list(deref_list, 1);
	return error;
}

inm_s32_t
ptio_cancel_send(target_context_t *tcp, inm_u64_t write_off,
		inm_u32_t write_len)
{
	unsigned char cdbp[WRITE_CANCEL_CDB_LEN];
	inm_s32_t ret = 0;

	dbg("PTIO cancel issued at <off,len> <%llu, %u>",write_off, write_len);
	cdbp[0] = WRITE_CANCEL_CDB;
	cdbp[1] = 0x0;
	cdbp[2] = (write_off >> 56) & 0xFF;
	cdbp[3] = (write_off >> 48) & 0xFF;
	cdbp[4] = (write_off >> 40) & 0xFF;
	cdbp[5] = (write_off >> 32) & 0xFF;
	cdbp[6] = (write_off >> 24) & 0xFF;
	cdbp[7] = (write_off >> 16) & 0xFF;
	cdbp[8] = (write_off >> 8) & 0xFF;
	cdbp[9] = (write_off) & 0xFF;
	cdbp[10] = (write_len >> 24 ) & 0xFF;
	cdbp[11] = (write_len >> 16) & 0xFF;
	cdbp[12] = (write_len >> 8) & 0xFF;
	cdbp[13] = (write_len) & 0xFF;
	cdbp[14] = 0;
	cdbp[15] = 0;

	ret = inm_all_AT_cdb_send(tcp, cdbp, WRITE_CANCEL_CDB_LEN, 1, NULL, 0, 
							0);
	if(ret){
		err("USCSI ioctl failed for cmd %x retval %u",
						WRITE_CANCEL_CDB_LEN, ret);
		goto out;
	}
	INM_ATOMIC_INC(&(tcp->tc_stats.tc_write_cancel));
out:
	return ret;
}

inm_iodone_t
INM_MIRROR_IODONE(inm_pt_mirror_iodone, pt_bp, done, error)
{
	inm_mirror_bufinfo_t *mbufinfo = (inm_mirror_bufinfo_t *) inm_container_of(pt_bp, inm_mirror_bufinfo_t, imb_pt_buf);
	target_context_t *tcp = mbufinfo->imb_privp;

	INM_MORE_IODONE_EXPECTED(pt_bp);
	INM_IMB_ERROR_SET(mbufinfo->imb_pt_err, error);
	INM_IMB_DONE_SET(mbufinfo->imb_pt_done, done);
	if(is_target_mirror_paused(tcp)){
		goto ptio_done;
	}
	INM_INJECT_ERR(inject_ptio_err, error, pt_bp);

	if( INM_BUF_FAILED(pt_bp, error) ) {
		volume_lock(tcp);
		if( INM_BUF_RESID(pt_bp, done) == mbufinfo->imb_io_sz ){
			mbufinfo->imb_flag |= INM_PTIO_FULL_FAILED;
		}
		mbufinfo->imb_flag |= INM_PTIO_CANCEL_PENDING;
		volume_unlock(tcp);
	}

ptio_done:
	if(INM_ATOMIC_DEC_RET(&(mbufinfo->imb_done_cnt)) == INM_ALL_IOS_DONE){
		inm_mirror_done(mbufinfo);
	}

	return INM_RET_IODONE;
}

inm_iodone_t
INM_MIRROR_IODONE(inm_at_mirror_iodone, at_bp, done, error)
{
	inm_mirror_atbuf *atbuf_wrap = (inm_mirror_atbuf *) inm_container_of(at_bp, inm_mirror_atbuf, imb_atbuf_buf);
	mirror_vol_entry_t *vol_entry = atbuf_wrap->imb_atbuf_vol_entry;
	inm_mirror_bufinfo_t *mbufinfo = atbuf_wrap->imb_atbuf_imbinfo;
	target_context_t *tcp = mbufinfo->imb_privp;

	INM_MORE_IODONE_EXPECTED(at_bp);
	if(is_target_mirror_paused(tcp)){
		goto atio_done;
	}
	INM_INJECT_ERR(inject_atio_err, error, at_bp);
	INM_IMB_DONE_SET(atbuf_wrap->imb_atbuf_done, done);

	if( INM_BUF_FAILED(at_bp, error) ){
		add_item_to_work_queue(&driver_ctx->wqueue, 
						&(atbuf_wrap->imb_atbuf_wqe));
		goto out;
	}

atio_done:
	INM_DEREF_VOL_ENTRY(vol_entry, tcp);
	if(INM_ATOMIC_DEC_RET(&(mbufinfo->imb_done_cnt)) == 
							INM_ALL_IOS_DONE){
		inm_mirror_done(mbufinfo);
	}
out:
	return INM_RET_IODONE;
}

static void
inm_mirror_done(inm_mirror_bufinfo_t *mbufinfo)
{
	target_context_t *tcp = mbufinfo->imb_privp;	
	mirror_vol_entry_t *vol_entry = mbufinfo->imb_vol_entry;
	inm_mirror_atbuf *atbuf_wrap = NULL;
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	inm_u32_t failed_atbufs = 0;
#ifndef INM_LINUX
	host_dev_ctx_t *hdcp = tcp->tc_priv;
	inm_s32_t flag;
#endif

	INM_BUG_ON(INM_ATOMIC_READ(&(mbufinfo->imb_done_cnt)) != 0);

	/*
	 * No need to protect inm_flag as nobody else would be refering it
	 * as both the IO has completed.
	 */
	if(mbufinfo->imb_flag & INM_PTIO_CANCEL_PENDING){
		if(mbufinfo->imb_flag & INM_PTIO_FULL_FAILED){
			inm_list_for_each_safe(ptr, nextptr, 
						&mbufinfo->imb_atbuf_list) {
				atbuf_wrap = inm_list_entry(ptr, 
					inm_mirror_atbuf, imb_atbuf_this);
				if(atbuf_wrap->imb_atbuf_flag & 
							INM_ATBUF_FULL_FAILED){
					failed_atbufs++;
				}
			}
			if(failed_atbufs == mbufinfo->imb_atbuf_cnt){
				goto done;
			}
		}
		INM_BUG_ON(mbufinfo->imb_flag & INM_PTIO_CANCEL_SENT);
		add_item_to_work_queue(&driver_ctx->wqueue, 
						&(mbufinfo->ptio_can_wqe));
		goto out;
	}
done:
	INM_PT_IODONE(mbufinfo);
	INM_MIRROR_INFO_RETURN(hdcp, mbufinfo, flag);
	put_tgt_ctxt(tcp);
	INM_ATOMIC_DEC(&tcp->tc_nr_in_flight_ios);
	INM_DEREF_VOL_ENTRY(vol_entry, tcp);
out:
	return;
}

void
inm_atio_retry(wqentry_t *wqe)
{
	inm_mirror_atbuf *atbuf_wrap = (inm_mirror_atbuf *) (wqe->context);
	inm_mirror_bufinfo_t *mbufinfo = atbuf_wrap->imb_atbuf_imbinfo;
	mirror_vol_entry_t *first_vol_entry = atbuf_wrap->imb_atbuf_vol_entry;
	mirror_vol_entry_t *vol_entry = NULL;
	inm_buf_t *at_bp = &(atbuf_wrap->imb_atbuf_buf);
	target_context_t *tcp = mbufinfo->imb_privp;
	inm_s32_t err = 0;

	volume_lock(tcp);
	first_vol_entry->vol_error = 1;
	UPDATE_ATIO_FAILED(first_vol_entry, mbufinfo->imb_io_sz);
	INM_DEREF_VOL_ENTRY(first_vol_entry, tcp);
	if( INM_BUF_RESID(at_bp, atbuf_wrap->imb_atbuf_done) == 
						atbuf_wrap->imb_atbuf_iosz ){
		atbuf_wrap->imb_atbuf_flag |= INM_ATBUF_FULL_FAILED;
	} else {
		atbuf_wrap->imb_atbuf_flag |= INM_ATBUF_PARTIAL_FAILED;
	}
	if(mbufinfo->imb_flag & INM_PTIO_CANCEL_PENDING){
		/* 
		 * No need to resend the ATIO as PTIO cancel anyway will happen.
		 */
		goto atio_done;
	}

	err = 1;
	vol_entry = inm_get_healthy_vol_entry(tcp);
	if(!vol_entry){
		goto atio_done;
	}
	INM_REF_VOL_ENTRY(vol_entry);
	UPDATE_ATIO_SEND(vol_entry, atbuf_wrap->imb_atbuf_iosz);
	atbuf_wrap->imb_atbuf_flag &= ~(INM_ATBUF_FULL_FAILED | 
						INM_ATBUF_PARTIAL_FAILED);
	volume_unlock(tcp);
	atbuf_wrap->imb_atbuf_vol_entry = vol_entry;
	atbuf_wrap = inm_freg_atbuf(atbuf_wrap);
	at_bp = &(atbuf_wrap->imb_atbuf_buf);
	INM_DEREF_VOL_ENTRY(vol_entry, tcp);
	inm_issue_atio(at_bp, vol_entry);
out:
	return;

atio_done:
	volume_unlock(tcp);
	if(INM_ATOMIC_DEC_RET(&(mbufinfo->imb_done_cnt)) == 
							INM_ALL_IOS_DONE){
		inm_mirror_done(mbufinfo);
	}
	if(err){
		dbg("AT IO retry Buf: Offset = %lld, count = %u", 
			(long long int)INM_BUF_SECTOR(at_bp),  
			INM_BUF_COUNT(at_bp));
		queue_worker_routine_for_set_volume_out_of_sync(tcp, 
					ERROR_TO_REG_AT_PATHS_FAILURE, 0);
	}
	goto out;
}

void
issue_ptio_cancel_cdb(wqentry_t *wqe)
{
	inm_mirror_bufinfo_t *mbufinfo = (inm_mirror_bufinfo_t *)(wqe->context);
	target_context_t *tcp = mbufinfo->imb_privp;
	inm_u64_t cancel_io_offset = mbufinfo->imb_atbuf_absoff;

	INM_BUG_ON(INM_ATOMIC_READ(&(mbufinfo->imb_done_cnt)) != 0);
	inm_map_abs_off_ln(&(mbufinfo->imb_pt_buf), tcp, &cancel_io_offset);
	if(ptio_cancel_send(tcp, mbufinfo->imb_io_off, mbufinfo->imb_io_sz)){
		queue_worker_routine_for_set_volume_out_of_sync(tcp, 
					ERROR_TO_REG_PTIO_CANCEL_FAILED, 2);
	}
	/*
	* No need to protect inm_flag as nobody else would be refering it
	* as both the IO has completed. We would come here from inm_mirror_done() only.
	*/
	mbufinfo->imb_flag |= INM_PTIO_CANCEL_SENT;
	mbufinfo->imb_flag &= ~INM_PTIO_CANCEL_PENDING;

	inm_mirror_done(mbufinfo);
	return;
}

mirror_vol_entry_t *
get_cur_vol_entry(target_context_t *tcp, inm_u32_t io_sz)
{
		mirror_vol_entry_t *vol_entry = NULL;

		if(tcp->tc_dev_type != FILTER_DEV_MIRROR_SETUP){
				goto out;
		}
		if ((vol_entry = tcp->tc_vol_entry)) {
				INM_REF_VOL_ENTRY(vol_entry);
		}
		INM_BUG_ON(!vol_entry);
		load_bal_rr(tcp, io_sz);

out:
		return vol_entry;
}

static mirror_vol_entry_t *
inm_get_healthy_vol_entry(target_context_t *tcp)
{
	struct inm_list_head *ptr, *nextptr;
	mirror_vol_entry_t *vol_entry = NULL;

	inm_list_for_each_safe(ptr, nextptr, &(tcp->tc_dst_list)){
		vol_entry = inm_container_of(ptr, 
					mirror_vol_entry_t, next);
		if(vol_entry->vol_error){
			vol_entry = NULL;
			continue;
		}
		break;
	}
	return vol_entry;
}

int
inm_save_mirror_bufinfo(target_context_t *tcp, inm_mirror_bufinfo_t **imbinfopp,
		 inm_buf_t **org_bpp, mirror_vol_entry_t *vol_entry)
{
	inm_buf_t *bp = *org_bpp;
	inm_buf_t *prev_at_buf = NULL;
	inm_buf_t *first_atbuf = NULL;
	host_dev_ctx_t *hdcp = NULL;
	inm_buf_t *newbp_hdp = NULL, *newbp_tailp = NULL;
	inm_mirror_bufinfo_t *newbp = NULL;
	int ret = INM_ENOMEM;
	inm_u32_t idx;
	inm_u32_t count = 0;
	inm_u32_t max_xfer_size = INM_MAX_XFER_SZ(vol_entry, bp);
	inm_u32_t no_atbufs = (INM_BUF_COUNT(bp) + max_xfer_size - 1) / 
								max_xfer_size;
	inm_u64_t io_sz = 0;
	inm_list_head_t	tmp_atbuf_list;
	inm_mirror_atbuf *atbuf_wrap = NULL;

	hdcp = tcp->tc_priv;

	do {
#if (defined(IDEBUG) || defined(IDEBUG_BMAP))
		dbg("write entry pt : off = %llu, sz = %d", INM_BUF_SECTOR(bp),
			INM_BUF_COUNT(bp));
#endif
		newbp = NULL;
		INM_INIT_LIST_HEAD(&tmp_atbuf_list);
		newbp = inm_get_imb_cached(hdcp);
		if(newbp){
			goto out;
		}

		newbp = INM_KMEM_CACHE_ALLOC(driver_ctx->dc_host_info.mirror_bioinfo_cache, INM_KM_NOIO);
		if (!newbp){
			err("Failed to allocate inm_mirror_bufinfo_t object");
			goto error;
		}

		INM_MEM_ZERO(newbp, sizeof(inm_mirror_bufinfo_t));

		INM_ATOMIC_SET(&(newbp->ptio_can_wqe.refcnt), 1);

		INM_INIT_LIST_HEAD(&(newbp->imb_atbuf_list));

		newbp->ptio_can_wqe.context = newbp;
		newbp->ptio_can_wqe.work_func = issue_ptio_cancel_cdb;

out:
		newbp->imb_atbuf_cnt = 0;
		INM_ATOMIC_SET(&(newbp->imb_done_cnt), 2);
		newbp->imb_org_bp = bp;
		first_atbuf = NULL;

		inm_bufoff_to_fldisk(bp, tcp, &(newbp->imb_atbuf_absoff));
		
		inm_list_splice_init(&(newbp->imb_atbuf_list), &tmp_atbuf_list);
		do{
			if(!inm_list_empty(&tmp_atbuf_list)){
				atbuf_wrap = inm_list_entry(tmp_atbuf_list.next, 
					inm_mirror_atbuf, imb_atbuf_this);
				if (atbuf_wrap) {
					inm_list_del(&atbuf_wrap->imb_atbuf_this);
					INM_INIT_LIST_HEAD(&(atbuf_wrap->imb_atbuf_this));
					atbuf_wrap->imb_atbuf_flag = 0;
					goto populate_atbuf;
				}
			}
			if(!(atbuf_wrap = inm_alloc_atbuf_wrap(newbp))){
				err("failed to allocate atbug_wrap");
				goto free_newbp;
			}
			INM_BUG_ON(!(atbuf_wrap->imb_atbuf_imbinfo));
populate_atbuf:
			inm_list_add_tail(&(atbuf_wrap->imb_atbuf_this), 
						&(newbp->imb_atbuf_list));
			inm_prepare_atbuf(atbuf_wrap, bp, vol_entry, 
							newbp->imb_atbuf_cnt);
			if(!first_atbuf){
				first_atbuf = &(atbuf_wrap->imb_atbuf_buf);
			}
			newbp->imb_atbuf_cnt++;
			io_sz += INM_BUF_COUNT((&atbuf_wrap->imb_atbuf_buf));
		}while(no_atbufs > newbp->imb_atbuf_cnt);

		inm_free_atbuf_list(&(tmp_atbuf_list));
		get_tgt_ctxt(tcp); /* this ref is handled with bufinfo */
		idx = inm_comp_io_bkt_idx(INM_BUF_COUNT(bp));
		INM_ATOMIC_INC(&tcp->tc_stats.io_pat_writes[idx]);
		memcpy_s(&newbp->imb_pt_buf, sizeof(*bp), bp, sizeof(*bp));
		newbp->imb_io_sz = INM_BUF_COUNT((&atbuf_wrap->imb_atbuf_buf));
		newbp->imb_vol_entry = vol_entry;
		newbp->imb_io_off = INM_BUF_SECTOR(bp);
		INM_SET_ENDIO_FN((&newbp->imb_pt_buf), inm_pt_mirror_iodone);
		newbp->imb_flag = 0;
		newbp->imb_privp = tcp;

		INM_ATOMIC_INC(&tcp->tc_nr_bufs_pending);
		INM_ATOMIC_INC(&tcp->tc_nr_in_flight_ios);

		if (newbp_hdp) {
			INM_CHAIN_BUF((inm_buf_t *)newbp, newbp_tailp);
			INM_CHAIN_BUF(first_atbuf, prev_at_buf);
			INM_REF_VOL_ENTRY(vol_entry);
		} else { 
			newbp_hdp = (inm_buf_t *)newbp;
		}

		prev_at_buf = &(atbuf_wrap->imb_atbuf_buf);
		count += newbp->imb_atbuf_cnt;
		newbp_tailp = (inm_buf_t *)newbp;
		bp = INM_GET_FWD_BUF(bp);
	} while (bp);
	*org_bpp = newbp_hdp;
	*imbinfopp = (inm_mirror_bufinfo_t *)newbp_hdp;
	INM_UPDATE_VOL_ENTRY_STAT(tcp, vol_entry, count, io_sz);

	ret = 0;
	goto exit;

free_newbp:
	INM_BUG_ON(!inm_list_empty(&tmp_atbuf_list));
	INM_KMEM_CACHE_FREE(driver_ctx->dc_host_info.mirror_bioinfo_cache, 
									newbp);

error:
	while (newbp_hdp) {
		INM_ATOMIC_DEC(&tcp->tc_nr_bufs_pending);
		INM_ATOMIC_DEC(&tcp->tc_nr_in_flight_ios);
		newbp = (inm_mirror_bufinfo_t *)newbp_hdp;
		newbp_hdp = INM_GET_FWD_BUF((&newbp->imb_pt_buf));
		inm_free_atbuf_list(&(newbp->imb_atbuf_list));
		put_tgt_ctxt(tcp);
		INM_KMEM_CACHE_FREE(driver_ctx->dc_host_info.mirror_bioinfo_cache, 
									newbp);
	}

	queue_worker_routine_for_set_volume_out_of_sync(tcp, 
			ERROR_TO_REG_FAILED_TO_ALLOC_BIOINFO, INM_ENOMEM);
exit:
	inm_cleanup_mirror_bufinfo(hdcp);
	inm_free_atbuf_list(&(tmp_atbuf_list));
	return (ret);
} /* end of inm_save_mirror_bufinfo() */

static inm_mirror_atbuf *
inm_freg_atbuf(inm_mirror_atbuf *atbuf_wrap)
{
	mirror_vol_entry_t *vol_entry = atbuf_wrap->imb_atbuf_vol_entry;
	inm_mirror_bufinfo_t *mbufinfo = atbuf_wrap->imb_atbuf_imbinfo;
	target_context_t *tcp = (target_context_t *)mbufinfo->imb_privp;
	inm_buf_t *at_bp = &atbuf_wrap->imb_atbuf_buf;
	inm_u32_t max_xfer_size = INM_MAX_XFER_SZ(vol_entry, at_bp);
	inm_mirror_atbuf *new_atbuf_wrap = NULL;
	inm_list_head_t prev_head;
	inm_u32_t count = 0;
	inm_u32_t more = 0;
	inm_u32_t err = 0;
	inm_u64_t org_atbuf_blkno = mbufinfo->imb_atbuf_absoff;

	dbg("entered in inm_freg_atbuf");

	/* No need to add the start device offset in blkno as they are added
	 * already during save_mirror_bufinfo.
	 */

	mbufinfo->imb_atbuf_absoff = 0;
	if(max_xfer_size >= atbuf_wrap->imb_atbuf_iosz){
		inm_prepare_atbuf(atbuf_wrap, &atbuf_wrap->imb_atbuf_buf, 
				vol_entry, count);
		new_atbuf_wrap = atbuf_wrap;
	} else {
		INM_INIT_LIST_HEAD(&(prev_head));
		do {
			new_atbuf_wrap = inm_alloc_atbuf_wrap(mbufinfo);
			if(!new_atbuf_wrap){
				info("While AT IO retry memory allocation failed");
				err = INM_ENOMEM;
				break;
			}
			inm_list_add_tail(&(new_atbuf_wrap->imb_atbuf_this), &prev_head);
			more = inm_prepare_atbuf(new_atbuf_wrap, at_bp, vol_entry, count);
			dbg("breaking at_pb %p of size %u in %dth buf of size %u",
				at_bp,  INM_BUF_COUNT(at_bp), count, 
				INM_BUF_COUNT((&atbuf_wrap->imb_atbuf_buf)));
			count++;
		} while(more);
		if(err){
			goto out;
		}
		new_atbuf_wrap = inm_container_of(prev_head.next, 
					inm_mirror_atbuf, imb_atbuf_this);
		volume_lock(tcp);
		inm_list_splice(&prev_head, &(atbuf_wrap->imb_atbuf_this));
		inm_list_del(&(atbuf_wrap->imb_atbuf_this));
		volume_unlock(tcp);
		INM_UNPIN(atbuf_wrap, sizeof(inm_mirror_atbuf));
		INM_KFREE(atbuf_wrap, sizeof(inm_mirror_atbuf), 
							INM_KERNEL_HEAP);
		atbuf_wrap = NULL;
	}
out:
	mbufinfo->imb_atbuf_absoff = org_atbuf_blkno;
	while(err && !inm_list_empty(&prev_head)){
		new_atbuf_wrap = inm_list_entry(prev_head.next, 
					inm_mirror_atbuf, imb_atbuf_this);
		inm_list_del(&(new_atbuf_wrap->imb_atbuf_this));
		INM_UNPIN(new_atbuf_wrap, sizeof(mirror_vol_entry_t));
		INM_KFREE(new_atbuf_wrap, sizeof(mirror_vol_entry_t), 
							INM_KERNEL_HEAP);
		new_atbuf_wrap = NULL;
	}
	dbg("exiting from inm_freg_atbuf with err %d, new_atbuf %p",err, 
							new_atbuf_wrap);
	return new_atbuf_wrap;
}

static inm_mirror_atbuf *
inm_alloc_atbuf_wrap(inm_mirror_bufinfo_t *mbufinfo)
{
	inm_mirror_atbuf *atbuf_wrap = NULL;
	inm_s32_t err = 0;

	atbuf_wrap = (inm_mirror_atbuf *) INM_KMALLOC(sizeof(inm_mirror_atbuf), 
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!atbuf_wrap){
		err = INM_ENOMEM;
		goto out;
	}
	if(INM_PIN(atbuf_wrap, sizeof(inm_mirror_atbuf))){
		err = 2;
		goto out;
	}
	INM_MEM_ZERO(atbuf_wrap, sizeof(inm_mirror_atbuf));
	INM_INIT_LIST_HEAD(&(atbuf_wrap->imb_atbuf_this));
	INM_ATOMIC_SET((&atbuf_wrap->imb_atbuf_wqe.refcnt), 1);
	atbuf_wrap->imb_atbuf_wqe.context = atbuf_wrap;
	atbuf_wrap->imb_atbuf_imbinfo = mbufinfo;
	atbuf_wrap->imb_atbuf_wqe.work_func = inm_atio_retry;
out:
	if(err){
		if(atbuf_wrap){
			INM_KFREE(atbuf_wrap, sizeof(inm_mirror_atbuf),
							INM_KERNEL_HEAP);
		}
		atbuf_wrap = NULL;
	}
	return atbuf_wrap;
}

void
inm_free_atbuf_list(inm_list_head_t *atbuf_list)
{
	inm_mirror_atbuf *atbuf_wrap = NULL;

	while(!inm_list_empty(atbuf_list)){
		atbuf_wrap = NULL;
		atbuf_wrap = inm_list_entry(atbuf_list->next, inm_mirror_atbuf, 
							imb_atbuf_this);
		INM_BUG_ON(!atbuf_wrap);
		inm_list_del(&atbuf_wrap->imb_atbuf_this);
		INM_UNPIN(atbuf_wrap, sizeof(inm_mirror_atbuf));
		INM_KFREE(atbuf_wrap, sizeof(inm_mirror_atbuf), 
							INM_KERNEL_HEAP);
	}
}

static void
inm_map_abs_off_ln(inm_buf_t *bp, target_context_t *tcp, inm_u64_t *abs_off)
{

	*abs_off += INM_BUF_SECTOR(bp);
	*abs_off += (tcp->tc_dev_startoff >> 9);
}

/*
 * function to start processing of tags for a given volume.
 */
int
process_tag_volume(tag_info_t_v2 *tag_vol, tag_info_t *tag_list, 
				   int commit_pending)
{
	tag_volinfo_t *tag_volinfop = NULL;
	int ret = 0;
	inm_s32_t error = 0;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	INM_DOWN(&driver_ctx->tag_sem);

	tag_volinfop = build_volume_node_totag(tag_vol->vol_info, &error);
	if (error || !tag_volinfop) {
		dbg("TAG Input Failed: Failed while building volume context");
		ret = error;
		if (!(tag_vol->vol_info->status & STATUS_TAG_NOT_PROTECTED)) {
			tag_vol->vol_info->status |= STATUS_TAG_NOT_ACCEPTED;
		} 
		goto out;
	}

	ret = issue_tag_volume(tag_vol, tag_volinfop, tag_list,
						   commit_pending);
	if(ret) {
		dbg("the issue tag volume failed for the volume");
		if (!(tag_vol->vol_info->status & STATUS_TAG_NOT_PROTECTED) &&
			!(tag_vol->vol_info->status & STATUS_TAG_WO_METADATA)) {
			tag_vol->vol_info->status |= STATUS_TAG_NOT_ACCEPTED;
		}
	}

out:
	if(tag_volinfop) {
		if(tag_volinfop->ctxt) {
			put_tgt_ctxt(tag_volinfop->ctxt);
			tag_volinfop->ctxt = NULL;
		}
		INM_KFREE(tag_volinfop, sizeof(tag_volinfo_t), INM_KERNEL_HEAP);
		tag_volinfop = NULL;
	}

	INM_UP(&driver_ctx->tag_sem);

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}
	return ret;
}

/*
 * function to build tag list for set of tags.
 * this has to be moved in main function
 */
tag_info_t *
build_tag_vol_list(tag_info_t_v2 *tag_vol, int *error)
{
	tag_info_t *tag_list = NULL;
	int numtags = 0;
	unsigned short tmp_len;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	*error = 0;

	tag_list = (tag_info_t *)INM_KMALLOC((tag_vol->nr_tags * sizeof(tag_info_t)),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!tag_list) {
		err("Failed to allocated memory for tags");
		return NULL;
	}

	for(numtags = 0; numtags < tag_vol->nr_tags; numtags++) {
		tmp_len = tag_vol->tag_names[numtags].tag_len;
		/* don't proceed if tag_len coming from user is greater than 256 */
		if (tmp_len > INM_GUID_LEN_MAX) {
			*error = -1;
			goto out;
		}
		tag_list[numtags].tag_len = tmp_len;
		if(memcpy_s(tag_list[numtags].tag_name, INM_GUID_LEN_MAX,
				 tag_vol->tag_names[numtags].tag_name,
				 tmp_len)) {
			*error = -1;
			goto out;
		}
	}

out:

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return tag_list;
}

/*
 * function to issue tags for given volume
 */
inm_s32_t
issue_tag_volume(tag_info_t_v2 *tag_vol, tag_volinfo_t *tag_volinfop, 
				 tag_info_t *tag_list, int commit_pending)
{
	int ret = 0;
	TAG_COMMIT_STATUS *tag_status = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

	if(tag_volinfop->ctxt && tag_volinfop->ctxt->tc_dev_type != 
		FILTER_DEV_MIRROR_SETUP &&
		tag_volinfop->ctxt->tc_cur_wostate != ecWriteOrderStateData) {

		if (tag_volinfop->ctxt->tc_cur_wostate != 
						ecWriteOrderStateData)
			tag_vol->vol_info->status |= STATUS_TAG_WO_METADATA;
		
		INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
		if (driver_ctx->dc_tag_drain_notify_guid &&
			!INM_MEM_CMP(driver_ctx->dc_cp_guid,
					driver_ctx->dc_tag_drain_notify_guid,
					GUID_LEN)) {
			tag_status = tag_volinfop->ctxt->tc_tag_commit_status;
			info("The disk %s is in non write order state", 
						tag_volinfop->ctxt->tc_guid);
		}
		INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);

		if (tag_status)
			set_tag_drain_notify_status(tag_volinfop->ctxt, 
					TAG_STATUS_INSERTION_FAILED,
					DEVICE_STATUS_NON_WRITE_ORDER_STATE);

		dbg("the volume is not in Write Order State Data");
		ret = INM_EAGAIN;
		goto out;
	}

	add_volume_tags(tag_vol, tag_volinfop, tag_list, commit_pending);

out:

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return ret;
}

/*
 * function to add tag to given volume
 */
void
add_volume_tags(tag_info_t_v2 *tag_vol, tag_volinfo_t *tag_volinfop, 
				tag_info_t *tag_info_listp, int commit_pending)
{
	target_context_t *ctxt = tag_volinfop->ctxt;
	int index = 0;

	if (ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
		inm_form_tag_cdb(ctxt, tag_info_listp, tag_vol->nr_tags);
		tag_vol->vol_info->status |= STATUS_TAG_NOT_ACCEPTED;
		return;
	}

	volume_lock(ctxt);

	/*
	 * add tags only in metadata mode, to save the data pages.
	 */

	if(!add_tag_in_non_stream_mode(tag_volinfop, tag_info_listp, 
				tag_vol->nr_tags, NULL, index, commit_pending, 
				NULL)) {
		tag_vol->vol_info->status |= STATUS_TAG_ACCEPTED;
		if (commit_pending)
			driver_ctx->dc_cp |= INM_CP_TAG_COMMIT_PENDING;
	} else {
		if (tag_volinfop->ctxt->tc_cur_wostate != ecWriteOrderStateData)
			tag_vol->vol_info->status |= STATUS_TAG_WO_METADATA;
		else
			tag_vol->vol_info->status |= STATUS_TAG_NOT_ACCEPTED;
	} 

	volume_unlock(ctxt);

	INM_WAKEUP_INTERRUPTIBLE(&ctxt->tc_waitq);
}

/*
 * function to build the volume context for the given
 * volume to issue tags
 */
tag_volinfo_t *
build_volume_node_totag(volume_info_t *vol_info, inm_s32_t *error)
{
	target_context_t *ctxt = NULL;
	tag_volinfo_t *tmp_vol;

	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}

#ifdef INM_AIX
	change_node_t *chg_node = NULL;
	inm_page_t *pgp = NULL;
#endif

	*error = 0;

	tmp_vol = (tag_volinfo_t *)INM_KMALLOC(sizeof(tag_volinfo_t),
					INM_KM_NOSLEEP, INM_KERNEL_HEAP);
	if(!tmp_vol) {
		err("TAG Input Failed: INM_KMALLOC failed for volumes");
		return 0;
	}
	INM_MEM_ZERO(tmp_vol, sizeof(tag_volinfo_t));

	if ( !(INM_ATOMIC_READ(&driver_ctx->is_iobarrier_on)) ) {
		ctxt = get_tgt_ctxt_from_uuid_nowait(vol_info->vol_name);
	} else {
		ctxt = get_tgt_ctxt_from_uuid_nowait_locked(vol_info->vol_name);
	}
	if(ctxt) {
		if(!is_target_filtering_disabled(ctxt)) {
			tmp_vol->ctxt = ctxt;
		} else {
			put_tgt_ctxt(ctxt);
			tmp_vol->ctxt = NULL;
			*error = -1;
			vol_info->status |= STATUS_TAG_NOT_PROTECTED;
			goto out;
		}
	} else {
		dbg("TAG Input Failed: can't issue tag to %s", 
							vol_info->vol_name);
		*error = -1;
		vol_info->status |= STATUS_TAG_NOT_PROTECTED;
		goto out;
	}
#ifdef INM_AIX
		chg_node = inm_alloc_change_node(NULL, INM_KM_NOSLEEP);
		if(!chg_node){
			err("Failed to allocate change node");
			*error = INM_ENOMEM;
			goto out;
		}

		INM_INIT_SEM(&chg_node->mutex);
		chg_node->mutext_initialized = 1;

		pgp = get_page_from_page_pool(0, 0, NULL);
		if(!pgp){
			INM_DESTROY_SEM(&chg_node->mutex);
			inm_free_change_node(chg_node);
			err("Failed to allocate metadata page");
			*error = INM_ENOMEM;
			goto out;
		}

		tmp_vol->chg_node = chg_node;
		tmp_vol->meta_page = pgp;
#endif

out:
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

	return tmp_vol;
}

void set_tag_drain_notify_status(target_context_t *ctxt, int tag_status,
		 int dev_status)
{
	dbg("tag_status = %d, dev_status = %d", tag_status, dev_status);

	INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	if (ctxt->tc_tag_commit_status) {
		ctxt->tc_tag_commit_status->Status = dev_status;
		ctxt->tc_tag_commit_status->TagStatus = tag_status;

		if (tag_status == TAG_STATUS_COMMITTED)
			INM_ATOMIC_DEC(&driver_ctx->dc_nr_tag_commit_status_pending_disks);
		else if (tag_status != TAG_STATUS_INSERTED)
			INM_ATOMIC_INC(&driver_ctx->dc_tag_commit_status_failed);

		if (TAG_STATUS_DROPPED == tag_status) {
			info("The failback tag is dropped for disk %s", 
								ctxt->tc_guid);
		}

		wake_up_interruptible(&driver_ctx->dc_tag_commit_status_waitq);
	}
	INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
}

inm_s32_t modify_persistent_device_name(target_context_t *ctx, char *p_name)
{
	if (strcpy_s(ctx->tc_pname, GUID_SIZE_IN_CHARS, p_name)) {
		err("strcpy failed for pname");
		return INM_EFAULT;
	}
	return 0;
}
