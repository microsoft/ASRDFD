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
#include "data-mode.h"
#include "change-node.h"
#include "utils.h"
#include "filestream.h"
#include "iobuffer.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "bitmap_api.h"
#include "VBitmap.h"
#include "work_queue.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "driver-context.h"
#include "involflt_debug.h"
#include "db_routines.h"
#include "filter.h"
#include "data-file-mode.h"
#include "tunable_params.h"
#include "file-io.h"
#include "filter_host.h"
#include "telemetry-types.h"
#include "telemetry.h"

extern driver_context_t *driver_ctx;
extern inm_s32_t fabric_volume_init(target_context_t *, inm_dev_info_t *);
extern inm_s32_t fabric_volume_deinit(target_context_t *ctx);
extern inm_s32_t inm_validate_fabric_vol(target_context_t *, inm_dev_info_t *);
extern void do_stop_filtering(target_context_t *);
static inm_s32_t inm_deref_all_vol_entry_tcp(target_context_t *);


const inm_u64_t
inm_dbwait_notify_lat_bkts_in_usec[INM_LATENCY_DIST_BKT_CAPACITY] = {
						10,
						100,
						1000, // Milli second
						10000, // 10 Milli seconds
						100000,
						1000000, // 1 Second
						10000000, // 10 Seconds
						30000000, // 30 Seconds
						60000000, // 1 Minute
						0,
};

const inm_u64_t
inm_dbcommit_lat_bkts_in_usec[INM_LATENCY_DIST_BKT_CAPACITY] = {
						80000,
						150000,
						200000,
						250000, 
						325000,
						400000,
						500000,
						1000000,
						3000000,
						0,
};

const inm_u64_t
inm_dbret_lat_bkts_in_usec[INM_LATENCY_DIST_BKT_CAPACITY] = {
						10,
						100,
						1000, // Milli second
						10000, // 10 Milli seconds
						100000,
						1000000, // 1 Second
						10000000, // 10 Seconds
						30000000, // 30 Seconds
						60000000, // 1 Minute
						600000000, // 10 Minutes
						1200000000, // 20 Minutes
						0,
};
void init_latency_stats(inm_latency_stats_t *lat_stp, const inm_u64_t *bktsp);

#ifdef INM_LINUX
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
inm_super_block_t *freeze_bdev(inm_block_device_t *);
void thaw_bdev(inm_block_device_t *, inm_super_block_t *);
#endif
#endif

void volume_lock_irqsave(target_context_t *ctx)
{
	INM_SPIN_LOCK_IRQSAVE(&ctx->tc_lock, ctx->tc_lock_flag);
}

void volume_unlock_irqrestore(target_context_t *ctx)
{
	INM_SPIN_UNLOCK_IRQRESTORE(&ctx->tc_lock, ctx->tc_lock_flag);
}

void volume_lock_bh(target_context_t *ctx)
{
	INM_VOL_LOCK(&ctx->tc_lock, ctx->tc_lock_flag);
}

void volume_unlock_bh(target_context_t *ctx)
{
	INM_VOL_UNLOCK(&ctx->tc_lock, ctx->tc_lock_flag);
}

void
inm_tc_reserv_init(target_context_t *ctx, int vol_lock)
{
	inm_u32_t tc_res_pages = 0, try = 0;
	inm_s32_t ret = -1, len;
	unsigned long lock_flag = 0;
	inm_u32_t data_pool_size = 0;
	char new_data_pool_size[NUM_CHARS_IN_LONGLONG + 1];

	/* sysfs read must have read tc_reserve_pages */
	if(!strncmp(ctx->tc_guid, "DUMMY_LUN_ZERO", strlen("DUMMY_LUN_ZERO"))){
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, 
								lock_flag);
		driver_ctx->dc_flags |= DRV_DUMMY_LUN_CREATED;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								lock_flag);
		return;
	}

	if (vol_lock)
		volume_lock(ctx);
	
	tc_res_pages = ctx->tc_reserved_pages;
	ctx->tc_reserved_pages = 0;
	/* Add page reservations to this context */
	ret = inm_tc_resv_add(ctx, tc_res_pages);

	if (vol_lock)
		volume_unlock(ctx);

	if (ret) {
		/* There is no enough memory in dc's unreserve pages for
		 * target context
		 */
retry:
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
		data_pool_size = driver_ctx->tunable_params.data_pool_size;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
									lock_flag);
		if ((data_pool_size - driver_ctx->data_flt_ctx.pages_allocated) < tc_res_pages) {
			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, 
									lock_flag);
			len = sprintf(new_data_pool_size,"%u",
							tc_res_pages + data_pool_size);
			ret = wrap_common_attr_store(DataPoolSize, new_data_pool_size, 
										len);
		} else {
			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, 
									lock_flag);
		}

		if (ret >= 0) {
			wrap_reorg_datapool();

			if (vol_lock)
				volume_lock(ctx);
		
			ret = inm_tc_resv_add(ctx, tc_res_pages);
		
			if (vol_lock)
				volume_unlock(ctx);

			if (!ret) {
				recalc_data_file_mode_thres();
				return;
			} else {
				if (try < 1) {
					try++;
					goto retry;
				}
			}
		}
		info("Insufficient data page pool for %s reservations.Continuing! ret=%d",
			   ctx->tc_guid, ret);
	}

	recalc_data_file_mode_thres();
}

static_inline void 
inm_tc_reserv_deinit(target_context_t *ctx)
{
	inm_s32_t ret = -1;
  
	if ((ret = inm_tc_resv_del(ctx, ctx->tc_reserved_pages))) {
		/* 
		 * we could not release page reservations - not good
		 */
		info("Failed to release page reservations! ret:%d", ret);
		INM_BUG_ON(1);
	}
	recalc_data_file_mode_thres();
}

target_context_t *
target_context_ctr(void)
{
	target_context_t *ctx;

	ctx = (target_context_t *) INM_KMALLOC(sizeof (*ctx), INM_KM_SLEEP, 
							INM_PINNED_HEAP);
	if (ctx == NULL) {
		return NULL;
	}
	INM_MEM_ZERO(ctx, sizeof(*ctx));
	return ctx;
}

void 
target_context_dtr(target_context_t *ctx)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p ",ctx);
	}
	INM_KFREE(ctx, sizeof(target_context_t), INM_PINNED_HEAP);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

inm_s32_t 
tgt_ctx_common_init(target_context_t *ctx, inm_dev_extinfo_t *dev_info)
{
	inm_device_t dtype;
	inm_s32_t err = -1;
	char *dst_scsi_id = NULL;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p volume:%s",ctx, dev_info->d_guid);
	}

	ctx->tc_data_log_dir = INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP, 
							INM_KERNEL_HEAP);
	if(!ctx->tc_data_log_dir) {	
		err = -ENOMEM;
		goto out_err;
	}
	ctx->tc_bp = INM_KMALLOC(sizeof(struct bitmap_info), INM_KM_SLEEP, 
							INM_PINNED_HEAP);
	if (!ctx->tc_bp) {
		INM_KFREE(ctx->tc_data_log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
		err = -ENOMEM;
		goto out_err;
	}

	INM_MEM_ZERO(ctx->tc_bp, sizeof(struct bitmap_info));

	ctx->tc_bp->bitmap_file_name[0]='\0';
	fill_bitmap_filename_in_volume_context(ctx);
	err = validate_path_for_file_name(ctx->tc_bp->bitmap_file_name);
	if (err) {
		INM_KFREE(ctx->tc_data_log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
		INM_KFREE(ctx->tc_bp, sizeof(struct bitmap_info), 
							INM_PINNED_HEAP);
		err("Cannot get bitmap file name");
		goto out_err;
	}

	ctx->tc_mnt_pt = INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP, 
							INM_KERNEL_HEAP);
	if(!ctx->tc_mnt_pt) {
		INM_KFREE(ctx->tc_data_log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
		INM_KFREE(ctx->tc_bp, sizeof(struct bitmap_info), 
							INM_PINNED_HEAP);
		err = -ENOMEM;
		goto out_err;
	}

	ctx->tc_db_v2 = (UDIRTY_BLOCK_V2 *)INM_KMALLOC(sizeof(UDIRTY_BLOCK_V2), 
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!ctx->tc_db_v2) {
		INM_KFREE(ctx->tc_data_log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
		INM_KFREE(ctx->tc_bp, sizeof(struct bitmap_info), 
							INM_PINNED_HEAP);
		INM_KFREE(ctx->tc_mnt_pt, INM_PATH_MAX, INM_KERNEL_HEAP);
		err = -ENOMEM;
		goto out_err;
	}
	INM_MEM_ZERO(ctx->tc_db_v2, sizeof(UDIRTY_BLOCK_V2));

	/* By default, filtering is disabled, user space would send
	 * START_FILTERING ioctl, which would enable filtering.
	 */
	ctx->tc_stats.st_mode_switch_time = INM_GET_CURR_TIME_IN_SEC;
	ctx->tc_stats.st_wostate_switch_time = INM_GET_CURR_TIME_IN_SEC;
	INM_INIT_SEM(&ctx->tc_sem);   
	INM_INIT_SEM(&ctx->tc_resync_sem);   
	ctx->tc_cur_mode = FLT_MODE_UNINITIALIZED;
	ctx->tc_prev_mode = FLT_MODE_UNINITIALIZED;	
	ctx->tc_cur_wostate = ecWriteOrderStateUnInitialized;
	ctx->tc_prev_wostate = ecWriteOrderStateUnInitialized;
	ctx->tc_dev_state = DEVICE_STATE_ONLINE;
	INM_INIT_SPIN_LOCK(&(ctx->tc_lock));
	INM_INIT_SPIN_LOCK(&ctx->tc_tunables_lock);
	INM_INIT_LIST_HEAD(&(ctx->tc_node_head));
	INM_INIT_LIST_HEAD(&(ctx->tc_non_drainable_node_head));
	ctx->tc_db_notify_thres = DEFAULT_DB_NOTIFY_THRESHOLD;
	ctx->tc_data_to_disk_limit = 
				driver_ctx->tunable_params.data_to_disk_limit;

	INM_INIT_WAITQUEUE_HEAD(&ctx->tc_wq_in_flight_ios);
	INM_ATOMIC_SET(&(ctx->tc_nr_in_flight_ios), 0);

	INM_ATOMIC_SET(&(ctx->tc_nr_chain_bios_submitted), 0);
	INM_ATOMIC_SET(&(ctx->tc_nr_chain_bios_pending), 0);
	INM_ATOMIC_SET(&(ctx->tc_nr_completed_in_child_stack), 0);
	INM_ATOMIC_SET(&(ctx->tc_nr_completed_in_own_stack), 0);
	INM_ATOMIC_SET(&(ctx->tc_nr_bio_reentrant), 0);
	INM_ATOMIC_SET(&(ctx->tc_nr_chain_bio_reentrant), 0);
#if (defined REQ_OP_WRITE_ZEROES || defined OL7UEK5)
	INM_ATOMIC_SET(&(ctx->tc_nr_write_zero_bios), 0);
#endif
	INM_ATOMIC_SET(&(ctx->tc_async_bufs_pending), 0);
	INM_ATOMIC_SET(&(ctx->tc_async_bufs_processed), 0);
	INM_ATOMIC_SET(&(ctx->tc_async_bufs_write_pending), 0);
	INM_ATOMIC_SET(&(ctx->tc_async_bufs_write_processed), 0);

	ctx->tc_lock_fn = volume_lock_irqsave;
	ctx->tc_unlock_fn = volume_unlock_irqrestore;

	init_latency_stats(&ctx->tc_dbret_latstat, inm_dbret_lat_bkts_in_usec);
	init_latency_stats(&ctx->tc_dbwait_notify_latstat, 
					inm_dbwait_notify_lat_bkts_in_usec);
	init_latency_stats(&ctx->tc_dbcommit_latstat, 
					inm_dbcommit_lat_bkts_in_usec);
	/* added the 2nd arg as ctx->tc_priv which holds the name is not yet 
	 * initialized
	 */
	if ((err = sysfs_init_volume(ctx, dev_info->d_pname))) {
		ctx->tc_reserved_pages = 0;
		err("sysfs_init_volume failed err = %d\n", err);
		goto ret1;
	}
	if ((err = init_data_file_flt_ctxt(ctx))) {
			ctx->tc_reserved_pages = 0;
			err("init_data_file_flt_ctxt failed err = %d\n", err);
			goto ret2;
	}

	if ((err = create_datafile_dir_name(ctx,(inm_dev_info_t *)dev_info))) {
		ctx->tc_reserved_pages = 0;
		err("create_proc_for_target failed w/ error = %d\n", err);
		goto ret3;
	}

	/* if the device is just added, create the sysfs entry for FilterDevType */
	dtype = filter_dev_type_get(ctx->tc_pname);
	if (dtype != ctx->tc_dev_type) {
		if ((err = filter_dev_type_set(ctx, ctx->tc_dev_type))) {
			err("tgt_ctx_eommon_init: failed for %s to set filter_dev_type err = %d",
			ctx->tc_guid, err);
			goto ret3;
		}
		info("set filter_dev_type to %d", ctx->tc_dev_type);
	}

	/* Allocate tc'c reservations from dc's unreserved pages */
	if (dev_info->d_type != FILTER_DEV_MIRROR_SETUP) 
		inm_tc_reserv_init(ctx, 0);

	get_time_stamp(&(ctx->tc_tel.tt_create_time));

	err = 0;
	goto out;

ret3:
	free_data_file_flt_ctxt(ctx);
ret2:
	put_tgt_ctxt(ctx);
	goto out;
ret1:
	INM_DESTROY_WAITQUEUE_HEAD(&ctx->tc_waitq);
	INM_DESTROY_SPIN_LOCK(&ctx->tc_tunables_lock);
	INM_DESTROY_SPIN_LOCK(&(ctx->tc_lock));
	INM_DESTROY_SEM(&ctx->tc_sem);   
	INM_DESTROY_SEM(&ctx->tc_resync_sem);   
	INM_KFREE(ctx->tc_mnt_pt, INM_PATH_MAX, INM_KERNEL_HEAP);
	ctx->tc_mnt_pt = NULL;
	INM_KFREE(ctx->tc_db_v2, sizeof(UDIRTY_BLOCK_V2), INM_KERNEL_HEAP);
	ctx->tc_db_v2 = NULL;
	INM_KFREE(ctx->tc_bp, sizeof(struct bitmap_info), INM_PINNED_HEAP);
	ctx->tc_bp = NULL;
	INM_KFREE(ctx->tc_data_log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
	ctx->tc_data_log_dir = NULL;

out_err:
	remove_tc_from_dc(ctx);
	inm_free_host_dev_ctx(ctx->tc_priv);
	INM_DESTROY_SEM(&ctx->cdw_sem);
	target_context_dtr(ctx);
	INM_MODULE_PUT();

out:
	if(dst_scsi_id){
		INM_KFREE(dst_scsi_id, INM_MAX_SCSI_ID_SIZE, INM_KERNEL_HEAP);
		dst_scsi_id = NULL;
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return err;
}

/*
 * called when tgt_ctx_spec_init() failed or normal unstaking.
 * in either case calling free_data_file_flt_ctxt() here in this function is
 * a NOP because if tgt_ctx_spec_init() failed there is nothing this function
 * does since there won't be any messages queued. In the case of normal
 * stop we don't even get here as each message on the queue has a referece
 * on the target_context.
 */
void
tgt_ctx_common_deinit(target_context_t *ctx)
{
	unsigned long lock_flag = 0;

	ctx->tc_flags &= VCF_VOLUME_CREATING | VCF_VOLUME_DELETING | 
								VCF_IN_NWO;
	if (ctx->tc_filtering_disable_required)
		ctx->tc_flags |= VCF_FILTERING_STOPPED;
	ctx->tc_cur_mode = FLT_MODE_UNINITIALIZED;
	ctx->tc_cur_wostate = ecWriteOrderStateUnInitialized;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p",ctx);
	}
	if(!strncmp(ctx->tc_guid, "DUMMY_LUN_ZERO", strlen("DUMMY_LUN_ZERO"))){
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, 
								lock_flag);
		driver_ctx->dc_flags &= ~DRV_DUMMY_LUN_CREATED;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								lock_flag);
	}else {
		/* Release tc'c reservations to dc's unreserved pages */
		inm_tc_reserv_deinit(ctx);
	}

	if(ctx->tc_datafile_dir_name) {
		INM_KFREE(ctx->tc_datafile_dir_name, INM_GUID_LEN_MAX, 
							INM_KERNEL_HEAP);
		ctx->tc_datafile_dir_name = NULL;
	}

	if(ctx->tc_mnt_pt){
		INM_KFREE(ctx->tc_mnt_pt, INM_PATH_MAX, INM_KERNEL_HEAP);
		ctx->tc_mnt_pt = NULL;
	}

	if(ctx->tc_db_v2){
		INM_KFREE(ctx->tc_db_v2 , sizeof(UDIRTY_BLOCK_V2), 
							INM_KERNEL_HEAP);
		ctx->tc_db_v2 = NULL;
	}

	if(ctx->tc_bp){
	   INM_KFREE(ctx->tc_bp, sizeof(struct bitmap_info), INM_PINNED_HEAP);
	   ctx->tc_bp = NULL;
	}

	if(ctx->tc_data_log_dir){
		INM_KFREE(ctx->tc_data_log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
		ctx->tc_data_log_dir = NULL;
	}

	INM_DESTROY_WAITQUEUE_HEAD(&ctx->tc_wq_in_flight_ios);
	INM_DESTROY_WAITQUEUE_HEAD(&ctx->tc_waitq);
	INM_DESTROY_SPIN_LOCK(&ctx->tc_tunables_lock);
	INM_DESTROY_SPIN_LOCK(&(ctx->tc_lock));
	INM_DESTROY_SEM(&ctx->tc_sem);   
	INM_DESTROY_SEM(&ctx->tc_resync_sem);   
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

int
tgt_ctx_spec_init(target_context_t *ctx, inm_dev_extinfo_t *dev_info)
{
	inm_s32_t error = 1;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p volume:%s", ctx, dev_info->d_guid);
	}

	switch(ctx->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
	if (stack_host_dev(ctx, dev_info)) {
		error = 1;
		goto out;	
	}
		error = 0;
	break;
	
	case FILTER_DEV_FABRIC_LUN:
		if ((error = fabric_volume_init(ctx, 
						(inm_dev_info_t*)dev_info))) {
			goto out;
		}
		error = 0;
	break;

	default:
	dbg("do_volume_stacking: bad dev type for filtering");
		break;
	}

out:
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving error:%d", error);
	}
	return error;
}

void
tgt_ctx_spec_deinit(target_context_t *ctx)
{
	switch (ctx->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
		case FILTER_DEV_MIRROR_SETUP:
			if (ctx->tc_priv) {
				/* need completion to improve code to fit both the approaches */
				INM_REL_DEV_RESOURCES(ctx);
			}
			break;
	
		case FILTER_DEV_FABRIC_LUN:
			fabric_volume_deinit(ctx);
			break;
		
		default:
			break;
	}
}

/**
 * check_for_tc_state
 * @tgt_ctx - target context object
 * @write_lock - flag to check whether the caller has taken read/write lock
 *
 * The caller will wait if the target is undergone for creation or deletion.
 *
 * Returns 1 if it has to wait. Otherwise 0.
 */
int
check_for_tc_state(target_context_t *tgt_ctx, int write_lock)
{
	struct create_delete_wait *cdw_item;
	int ret = 0;

	cdw_item = INM_KMALLOC(sizeof(struct create_delete_wait), INM_KM_NOIO, 
							INM_KERNEL_HEAP);
	if(!cdw_item){
		INM_DELAY(3 * INM_HZ);
		return 1;
	}

	if(tgt_ctx->tc_flags & (VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)){
		INM_INIT_COMPLETION(&cdw_item->wait);
		INM_DOWN(&tgt_ctx->cdw_sem);
		inm_list_add_tail(&cdw_item->list, &tgt_ctx->cdw_list);
		INM_UP(&tgt_ctx->cdw_sem);

		if(write_lock)
			INM_UP_WRITE(&(driver_ctx->tgt_list_sem));
		else
			INM_UP_READ(&(driver_ctx->tgt_list_sem));

		INM_WAIT_FOR_COMPLETION(&cdw_item->wait);

		if(write_lock)
			INM_DOWN_WRITE(&(driver_ctx->tgt_list_sem));
		else
			INM_DOWN_READ(&(driver_ctx->tgt_list_sem));

		INM_DESTROY_COMPLETION(&cdw_item->wait);
		ret = 1;
	}

	INM_KFREE(cdw_item, sizeof(struct create_delete_wait), 
							INM_KERNEL_HEAP);

	return ret;
}

/**
 * wake_up_tc_state
 * @tgt_ctx - target context object
 *
 * This function will wake-up all the threads which are waiting
 * for the target context's creation or deletion.
 */
void
wake_up_tc_state(target_context_t *tgt_ctx)
{
	struct create_delete_wait *cdw_item;

	while(!inm_list_empty(&tgt_ctx->cdw_list)){
		cdw_item = inm_list_entry(tgt_ctx->cdw_list.next, 
					struct create_delete_wait, list);
		INM_DOWN(&tgt_ctx->cdw_sem);
		inm_list_del(&cdw_item->list);
		INM_UP(&tgt_ctx->cdw_sem);
		INM_COMPLETE(&cdw_item->wait);
	}
}

target_context_t *
get_tgt_ctxt_from_device_name_locked(char *uuid)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;

retry:
	for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		dbg("get_tgt_ctxt_from_scsiid_locked tgt:%s  devinfo:%s",
			tgt_ctxt->tc_guid, uuid);
		if (strcmp(tgt_ctxt->tc_guid, uuid) == 0) {
			break;
		}
	}

	if (tgt_ctxt && check_for_tc_state(tgt_ctxt, 1)) {
		tgt_ctxt = NULL;
		goto retry;
	}

	if (tgt_ctxt) {
		get_tgt_ctxt(tgt_ctxt);
	}
	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_from_uuid_locked(char *uuid)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;
	host_dev_ctx_t  *hdcp;
	dev_t           dev = 0;

	convert_path_to_dev(uuid, &dev);
retry:
	for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);

		if (tgt_ctxt->tc_dev_type == FILTER_DEV_HOST_VOLUME ||
			tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			hdcp = (host_dev_ctx_t *) (tgt_ctxt->tc_priv);
			if (hdcp) {
				struct inm_list_head *hptr = NULL;
				host_dev_t *hdc_dev = NULL;
				__inm_list_for_each(hptr, 
						&hdcp->hdc_dev_list_head) {
					hdc_dev = inm_list_entry(hptr, 
						host_dev_t, hdc_dev_list);
					if (hdc_dev->hdc_dev == dev) {
						dbg("uuid %s uuid_dev %u matching dev",uuid, dev);
						break;
					}
					hdc_dev = NULL;
				}
				if (hdc_dev) break;
			}
		} else if (strcmp(tgt_ctxt->tc_guid, uuid) == 0) {
			   break;
		}
	}

	if(tgt_ctxt && check_for_tc_state(tgt_ctxt, 1)){
	   	tgt_ctxt = NULL;
	   	goto retry;
	}

	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_from_scsiid(char *scsiid)
{
	target_context_t *tgt_ctxt = NULL;

	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	tgt_ctxt = get_tgt_ctxt_from_scsiid_locked(scsiid);
	if (tgt_ctxt) {
		get_tgt_ctxt(tgt_ctxt);
	}
	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_from_scsiid_locked(char *scsi_id)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;

retry:
	for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);

		if (tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			dbg("get_tgt_ctxt_from_scsiid_locked tgt:%s  devinfo:%s",
					tgt_ctxt->tc_pname, scsi_id);
			if (strcmp(tgt_ctxt->tc_pname, scsi_id) == 0) {
				break;
			}
		}
	}

	if (tgt_ctxt && check_for_tc_state(tgt_ctxt, 1)) {
	   	tgt_ctxt = NULL;
	   	goto retry;
	}

	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_persisted_name_nowait_locked(char *persisted_name)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;

	for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if (strcmp(tgt_ctxt->tc_pname, persisted_name) == 0) {
			break;
		}
	}

	if(tgt_ctxt){
		if(tgt_ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)){
			tgt_ctxt = NULL;
		} else {
			get_tgt_ctxt(tgt_ctxt);
		}
	}

	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_from_name_nowait_locked(char *id)
{
	target_context_t *tgt_ctxt = NULL;

	tgt_ctxt = get_tgt_ctxt_from_uuid_nowait_locked(id);
	if (!tgt_ctxt)
		/* If persistent name recieved */
		tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(id);

	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_from_name_nowait(char *id)
{
	target_context_t *tgt_ctxt = NULL;

	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	tgt_ctxt = get_tgt_ctxt_from_name_nowait_locked(id);
	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	return tgt_ctxt;
}

target_context_t *
get_tgt_ctxt_from_uuid(char *uuid)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;
	host_dev_ctx_t  *hdcp;
	inm_dev_t           dev = 0;

	convert_path_to_dev(uuid, &dev);
	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
retry:
	for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);

		if (tgt_ctxt->tc_dev_type == FILTER_DEV_HOST_VOLUME ||
			tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			hdcp = (host_dev_ctx_t *) (tgt_ctxt->tc_priv);
			if (hdcp) {
				struct inm_list_head *hptr = NULL;
				host_dev_t *hdc_dev = NULL;
				__inm_list_for_each(hptr, 
						&hdcp->hdc_dev_list_head) {
					hdc_dev = inm_list_entry(hptr, 
						host_dev_t, hdc_dev_list);
					if (hdc_dev->hdc_dev == dev) {
						dbg("uuid %s uuid_dev %u dev %u", 
						uuid, dev, hdc_dev->hdc_dev);
						break;
					}
					hdc_dev = NULL;
				}
				if (hdc_dev) break;
			}
		}
		else if (strcmp(tgt_ctxt->tc_guid, uuid) == 0) {
			break;
		}
	}

	if(tgt_ctxt && check_for_tc_state(tgt_ctxt, 0)){
		tgt_ctxt = NULL;
		goto retry;
	}

	if(tgt_ctxt)
		get_tgt_ctxt(tgt_ctxt);

	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	return tgt_ctxt;
}

target_context_t *get_tgt_ctxt_from_uuid_nowait(char *uuid)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;
	host_dev_ctx_t  *hdcp;
	dev_t           dev = 0;

	convert_path_to_dev(uuid, &dev);
	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if (tgt_ctxt->tc_dev_type == FILTER_DEV_HOST_VOLUME ||
			tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			hdcp = (host_dev_ctx_t *) (tgt_ctxt->tc_priv);
			if (hdcp) {
				struct inm_list_head *hptr = NULL;
				host_dev_t *hdc_dev = NULL;
				__inm_list_for_each(hptr, 
						&hdcp->hdc_dev_list_head) {
					hdc_dev = inm_list_entry(hptr, 
						host_dev_t, hdc_dev_list);
					if (hdc_dev->hdc_dev == dev) {
						break;
					}
					hdc_dev = NULL;
				}
				if (hdc_dev) break;
			}
		} else if (strcmp(tgt_ctxt->tc_guid, uuid) == 0) {
			break;
		}
	}

	if(tgt_ctxt && (tgt_ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)))
		tgt_ctxt = NULL;

	if(tgt_ctxt)
		get_tgt_ctxt(tgt_ctxt);

	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	return tgt_ctxt;
}

/*
 * caller of this function make sure to hold lock tgt_list_sem
 * before calling this function.
 */
target_context_t *get_tgt_ctxt_from_uuid_nowait_locked(char *uuid)
{
	struct inm_list_head *ptr;
	target_context_t *tgt_ctxt = NULL;
	host_dev_ctx_t  *hdcp;
	dev_t           dev = 0;

	convert_path_to_dev(uuid, &dev);
	for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
		ptr = ptr->next, tgt_ctxt = NULL) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if (tgt_ctxt->tc_dev_type == FILTER_DEV_HOST_VOLUME ||
			tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			hdcp = (host_dev_ctx_t *) (tgt_ctxt->tc_priv);
			if (hdcp) {
				struct inm_list_head *hptr = NULL;
				host_dev_t *hdc_dev = NULL;
				__inm_list_for_each(hptr, 
						&hdcp->hdc_dev_list_head) {
					hdc_dev = inm_list_entry(hptr, 
						host_dev_t, hdc_dev_list);
					if (hdc_dev->hdc_dev == dev) {
						break;
					}
					hdc_dev = NULL;
				}
				if (hdc_dev) break;
			}
		} else if (strcmp(tgt_ctxt->tc_guid, uuid) == 0) {
			break;
		}
	}

	if(tgt_ctxt && (tgt_ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)))
		tgt_ctxt = NULL;

	if(tgt_ctxt)
		get_tgt_ctxt(tgt_ctxt);

	return tgt_ctxt;
}

inm_s32_t
set_tgt_ctxt_filtering_mode(target_context_t *tgt_ctxt, flt_mode new_flt_mode,
						inm_s32_t service_initiated)
{
	register flt_mode curr_flt_mode = FLT_MODE_UNINITIALIZED;
	inm_u64_t last_time = 0, time_in_secs = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered cur mode:%d req mode:%d", tgt_ctxt->tc_cur_mode, 
									new_flt_mode);
	}

	/* validate the inputs and store the volume */
	if (!tgt_ctxt || new_flt_mode < 0 || service_initiated < 0)
		return -EINVAL;

	curr_flt_mode = tgt_ctxt->tc_cur_mode; /* save the present state 
						   * before modifying it */
	if (new_flt_mode == curr_flt_mode)
	return 0;

	last_time = tgt_ctxt->tc_stats.st_mode_switch_time;
	tgt_ctxt->tc_stats.st_mode_switch_time = INM_GET_CURR_TIME_IN_SEC;

	/* The time (last_time) of switching to one of the mode is
	 * greater than the time (current time) of switching to the other mode.
	 * So the number of seconds that the driver spent in previous mode gets
	 * negative. So in this scenario, set last_time to current time and the
	 * the number of seconds that the driver spent in previous mode will
	 * always be 0.
	 */
	if(last_time > tgt_ctxt->tc_stats.st_mode_switch_time)
		last_time = tgt_ctxt->tc_stats.st_mode_switch_time;


	time_in_secs = (tgt_ctxt->tc_stats.st_mode_switch_time - \
				 last_time);
	
	/* add the value to respective mode. */
	tgt_ctxt->tc_stats.num_secs_in_flt_mode[curr_flt_mode] += time_in_secs;

	switch (new_flt_mode) {
	case FLT_MODE_DATA:
		dbg("setting filtering mode as DATA-MODE ");
		curr_flt_mode = FLT_MODE_DATA;
		break;

	case FLT_MODE_METADATA:
		curr_flt_mode = FLT_MODE_METADATA;
		dbg("setting filtering mode as META-DATA-MODE \n");

		if (service_initiated) {
			tgt_ctxt->tc_stats.num_change_metadata_flt_mode_on_user_req++;
		}
		break;

	default:
		dbg("unknown filtering mode \n");
		return -EINVAL;
		break;
	}
	tgt_ctxt->tc_prev_mode = tgt_ctxt->tc_cur_mode;
	tgt_ctxt->tc_cur_mode = curr_flt_mode;
	tgt_ctxt->tc_stats.num_change_to_flt_mode[curr_flt_mode]++;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving cur mode:%d req mode:%d", tgt_ctxt->tc_cur_mode, 
									new_flt_mode);
	}

	return 0;
}

inm_s32_t   
set_tgt_ctxt_wostate(target_context_t *tgt_ctxt, etWriteOrderState new_wostate,
			 inm_s32_t service_initiated, etWOSChangeReason reason)
{
	etWriteOrderState curr_wostate = ecWriteOrderStateUnInitialized;
	inm_u64_t last_time = 0, time_in_secs = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered cur write order state:%d req write order state:%d", 
					tgt_ctxt->tc_cur_wostate, new_wostate);
	}

	if (!tgt_ctxt || new_wostate < 0 || service_initiated < 0)
		return INM_EINVAL;

	curr_wostate = tgt_ctxt->tc_cur_wostate;

	if (new_wostate == curr_wostate)
		return 0;

	last_time = tgt_ctxt->tc_stats.st_wostate_switch_time;
	tgt_ctxt->tc_stats.st_wostate_switch_time = INM_GET_CURR_TIME_IN_SEC;

	if(last_time > tgt_ctxt->tc_stats.st_wostate_switch_time)
		last_time = tgt_ctxt->tc_stats.st_wostate_switch_time;

	time_in_secs = (tgt_ctxt->tc_stats.st_wostate_switch_time - last_time);

	/* add the value to respective write order state. */
	tgt_ctxt->tc_stats.num_secs_in_wostate[curr_wostate] += time_in_secs;

	telemetry_nwo_stats_record(tgt_ctxt, curr_wostate, new_wostate, reason);

	switch (new_wostate) {
	case ecWriteOrderStateData:
		dbg("setting write order state as DATA ");
		curr_wostate = ecWriteOrderStateData;
		break;

	case ecWriteOrderStateMetadata:
		dbg("setting write order state as METADATA ");
		curr_wostate = ecWriteOrderStateMetadata;
		break;

	case ecWriteOrderStateBitmap:
		dbg("setting write order state as BITMAP ");
		curr_wostate = ecWriteOrderStateBitmap;
		break;

	case ecWriteOrderStateRawBitmap:
		dbg("setting write order state as RAW BITMAP");
		curr_wostate = ecWriteOrderStateRawBitmap;
		break;

	case ecWriteOrderStateUnInitialized:
		dbg("setting write order state as UNINITIALIZED");
		curr_wostate = ecWriteOrderStateUnInitialized;
		break;

	default:
		dbg("unknown write order state \n");
		return INM_EINVAL;
		break;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);
	if (new_wostate == ecWriteOrderStateData) {
		tgt_ctxt->tc_flags &= ~VCF_IN_NWO;
		driver_ctx->total_prot_volumes_in_nwo--;
	} else if (tgt_ctxt->tc_cur_wostate == ecWriteOrderStateData) {
		tgt_ctxt->tc_flags |= VCF_IN_NWO;
		driver_ctx->total_prot_volumes_in_nwo++;
		end_cx_session();
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);

	tgt_ctxt->tc_prev_wostate = tgt_ctxt->tc_cur_wostate;
	tgt_ctxt->tc_cur_wostate = curr_wostate;
	if (service_initiated)
		tgt_ctxt->tc_stats.num_change_to_wostate_user[curr_wostate]++;
	else
		tgt_ctxt->tc_stats.num_change_to_wostate[curr_wostate]++;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving cur write order state:%d req write order state:%d", 
					tgt_ctxt->tc_cur_wostate, new_wostate);
	}

	return 0;
}

void
set_malloc_fail_error(target_context_t *tgt_ctxt)
{
	unsigned long lock_flag = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (tgt_ctxt) {
		/* ACQUIRE NOMEMORY_LOG_EVENT lock */
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->log_lock, lock_flag);

		driver_ctx->stats.num_malloc_fails++;
		tgt_ctxt->tc_stats.num_malloc_fails++;


		/* RELEASE NOMEMORY_LOG_EVENT lock */
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->log_lock, lock_flag);
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

}

inm_s32_t
can_switch_to_data_filtering_mode(target_context_t *tgt_ctxt)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!(tgt_ctxt->tc_optimize_performance && 
				PERF_OPT_DATA_MODE_CAPTURE_WITH_BITMAP))
	{
		if (!tgt_ctxt->tc_bp || !tgt_ctxt->tc_bp->volume_bitmap ||
			(ecVBitmapStateReadCompleted !=
			tgt_ctxt->tc_bp->volume_bitmap->eVBitmapState))
			return FALSE;
	}

	/*
	 * Can switch to data mode: target context data page pool 
	 * threshold drops below the minimum volume data pages reservations 
	 */
	if (tgt_ctxt->tc_stats.num_pages_allocated > 
						tgt_ctxt->tc_reserved_pages) {
		dbg("Returning FALSE, as # of pages allocated (%#x) > tc_reserve_pages (%#x)\n",
			tgt_ctxt->tc_stats.num_pages_allocated,
			tgt_ctxt->tc_reserved_pages);
		return FALSE;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		dbg("Returning TRUE, as\nFree data pages = %#x\nData pages allocated = %#x\ntc_reserve_pages = %#x\n", 
			driver_ctx->data_flt_ctx.pages_free,
			driver_ctx->data_flt_ctx.pages_allocated,
			tgt_ctxt->tc_reserved_pages);
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return TRUE; /* to enable data mode filtering */
}

inm_s32_t
can_switch_to_data_wostate(target_context_t *tgt_ctxt)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if(!tgt_ctxt->tc_bp || !tgt_ctxt->tc_bp->volume_bitmap || 
			(ecVBitmapStateReadCompleted != 
			 tgt_ctxt->tc_bp->volume_bitmap->eVBitmapState))
		return FALSE;

	if(tgt_ctxt->tc_pending_md_changes)
		return FALSE;

	if(FLT_MODE_METADATA == tgt_ctxt->tc_cur_mode)
		return FALSE;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return TRUE; /* to enable write order state */
}

void
add_changes_to_pending_changes(target_context_t *ctx, 
			etWriteOrderState wostate, inm_u32_t num_changes)
{
	switch(wostate){
	case ecWriteOrderStateData:
		ctx->tc_pending_wostate_data_changes += num_changes;
		break;

	case ecWriteOrderStateMetadata:
		ctx->tc_pending_wostate_md_changes += num_changes;
		break;

	case ecWriteOrderStateBitmap:
		ctx->tc_pending_wostate_bm_changes += num_changes;
		break;

	case ecWriteOrderStateRawBitmap:
		ctx->tc_pending_wostate_rbm_changes += num_changes;
		break;

	default:
		err("Write Order State didn't match with the existing ones\n");
		break;
	}
}

void
subtract_changes_from_pending_changes(target_context_t *ctx, 
			etWriteOrderState wostate, inm_u32_t num_changes)
{
	switch(wostate){
	case ecWriteOrderStateData:
		ctx->tc_pending_wostate_data_changes -= num_changes;
		break;

	case ecWriteOrderStateMetadata:
		ctx->tc_pending_wostate_md_changes -= num_changes;
		break;

	case ecWriteOrderStateBitmap:
		ctx->tc_pending_wostate_bm_changes -= num_changes;
		break;

	case ecWriteOrderStateRawBitmap:
		ctx->tc_pending_wostate_rbm_changes -= num_changes;
		break;

	default:
		err("Write Order State didn't match with the existing ones\n");
		break;
	}
}

inm_s32_t
is_data_filtering_enabled_for_this_volume(target_context_t *vcptr)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!vcptr)
		return FALSE;

	if(!driver_ctx->service_supports_data_filtering)
		return FALSE;

	if(!driver_ctx->tunable_params.enable_data_filtering)
		return FALSE;

	if (vcptr->tc_flags & VCF_DATA_MODE_DISABLED)
		return FALSE;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
	return TRUE;
}

void
fs_freeze_volume(target_context_t *ctxt, struct inm_list_head *head)
{
	host_dev_ctx_t *hdcp;
	inm_s32_t count, success;
	struct inm_list_head *hptr = NULL;
	host_dev_t *hdc_dev = NULL;
	vol_info_t *vinfo = NULL;

	if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN)
		return;

	INM_INIT_LIST_HEAD(head);
	count = success = 0;
	hdcp = ctxt->tc_priv;
	__inm_list_for_each(hptr, &hdcp->hdc_dev_list_head) {
		hdc_dev = inm_list_entry(hptr, host_dev_t, hdc_dev_list);
		count++;
		vinfo = (vol_info_t*)INM_KMALLOC(sizeof(vol_info_t),
			                  INM_KM_SLEEP, INM_KERNEL_HEAP);
		if(!vinfo){
			err("Failed to allocate the vol_info_t object");
			break;
		}
		INM_MEM_ZERO(vinfo, sizeof(vol_info_t));
#ifdef INM_LINUX
		vinfo->bdev = inm_open_by_devnum(hdc_dev->hdc_dev, 
						FMODE_READ | FMODE_WRITE);
#endif
		if (IS_ERR(vinfo->bdev)) {
			info(" failed to open block device %s", ctxt->tc_guid);
			vinfo->bdev = NULL;
			INM_KFREE(vinfo, sizeof(vol_info_t), INM_KERNEL_HEAP);
			break;
		}
		inm_freeze_bdev(vinfo->bdev, vinfo->sb);
		success++;
		inm_list_add_tail(&vinfo->next, head);
	}

	if (count == success) {
		dbg("Freeze successful for device %s", ctxt->tc_guid);
	} else {
		while(!inm_list_empty(head)){
			vinfo = inm_list_entry(head->next, vol_info_t, next);
			inm_list_del(&vinfo->next);
			inm_thaw_bdev(vinfo->bdev, vinfo->sb);
			INM_KFREE(vinfo, sizeof(vol_info_t), INM_KERNEL_HEAP);
		}

		if (success) {
			err("Freeze Failed for one or more paths of device %s", 
							ctxt->tc_guid);
		} else {
			err("Freeze Failed for device %s", ctxt->tc_guid);
		}
	}
}

void
thaw_volume(target_context_t *ctxt, struct inm_list_head *head)
{
	vol_info_t *vinfo = NULL;

	if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN)
		return;

	while(!inm_list_empty(head)){
		vinfo = inm_list_entry(head->next, vol_info_t, next);
		inm_list_del(&vinfo->next);
		inm_thaw_bdev(vinfo->bdev, vinfo->sb);
		if (vinfo->sb) {
			dbg("Thaw successful for device %s for filesystem", 
							ctxt->tc_guid);
		} else {
			dbg("Thaw successful for device %s", ctxt->tc_guid);
		}
#ifdef INM_LINUX
		close_bdev(vinfo->bdev, FMODE_READ | FMODE_WRITE);
#endif
		INM_KFREE(vinfo, sizeof(vol_info_t), INM_KERNEL_HEAP);
	}
}

void target_context_release(target_context_t *ctxt)
{
	info("Target Context destroyed %d:%d device:%s",
			INM_GET_MAJOR(inm_dev_id_get(ctxt)),\
		 	INM_GET_MINOR(inm_dev_id_get(ctxt)), ctxt->tc_guid);

	tgt_ctx_spec_deinit(ctxt);
	tgt_ctx_common_deinit(ctxt);

	remove_tc_from_dc(ctxt);

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				      driver_ctx->dc_vm_cx_session_lock_flag);
	if (ctxt->tc_flags & VCF_IN_NWO)
		driver_ctx->total_prot_volumes_in_nwo--;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				      driver_ctx->dc_vm_cx_session_lock_flag);

	inm_free_host_dev_ctx(ctxt->tc_priv);

	INM_DESTROY_SEM(&ctxt->cdw_sem);
	
	if(ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
		free_tc_global_at_lun(&(ctxt->tc_dst_list));
		inm_deref_all_vol_entry_tcp(ctxt);
	}
	if (!inm_list_empty(&ctxt->tc_src_list)) {
		free_mirror_list(&ctxt->tc_src_list, 0);
	}
	if (!inm_list_empty(&ctxt->tc_dst_list)) {
		free_mirror_list(&ctxt->tc_dst_list, 1);
	}

	target_context_dtr(ctxt);
	INM_MODULE_PUT();
}

/*
 * This function is called when a target has been fully initialized and is
 * now ready to be cleaned up due to
 * disk removal (lvm reconfig) for host volumes.
 * lun cleanup for fabric case.
 * 
 * the caller expects that on return the target_context is removed. 
 */
void
tgt_ctx_force_soft_remove(target_context_t *ctx)
{
	if (ctx) {
		target_forced_cleanup(ctx);

		/* Unregister sysfs interface which would do the cleanup. */
		put_tgt_ctxt(ctx);
	}
}

/* Call this function whenever the driver needs to do forced cleanup of
 * target. Called during lvm removal or during uninstallation.
 */
void target_forced_cleanup(target_context_t *ctx)
{

	info("\tRemoved dev-type: %d, dev-id: %d dev:%s", ctx->tc_dev_type,
			inm_dev_id_get(ctx), ctx->tc_guid);
	info("\tStop filtering the device..:%s", ctx->tc_guid);

	do_stop_filtering(ctx);

	/* Perform Data File Mode cleanup */
	free_data_file_flt_ctxt(ctx);

#ifdef INM_AIX
	while(1) {
		host_dev_ctx_t *hdcp = ctx->tc_priv;
		volume_lock(ctx);
		if(!hdcp->hdc_buf_head){
			volume_unlock(ctx);
			break;
		}
		volume_unlock(ctx);

		INM_DELAY(3 * HZ);
	}
#endif
}

void
inm_do_clear_stats(target_context_t *tcp)
{
	bitmap_info_t *bp = NULL;
	tgt_hist_stats_t *thsp = NULL;
	inm_u8_t idx = 0;

	INM_BUG_ON(!tcp);
	bp = tcp->tc_bp;
	thsp = &tcp->tc_hist;
	INM_DOWN(&tcp->tc_sem);
	INM_MEM_ZERO(tcp->tc_stats.num_change_to_flt_mode,
		sizeof(tcp->tc_stats.num_change_to_flt_mode));
	INM_MEM_ZERO(tcp->tc_stats.num_secs_in_flt_mode,
		sizeof(tcp->tc_stats.num_secs_in_flt_mode));
	volume_lock(tcp);
	for (idx = 0; idx < MAX_NR_IO_BUCKETS; idx++) {
		INM_ATOMIC_SET(&tcp->tc_stats.io_pat_reads[idx], 0);
		INM_ATOMIC_SET(&tcp->tc_stats.io_pat_writes[idx], 0);
	}
	INM_ATOMIC_SET(&tcp->tc_stats.tc_write_cancel, 0);
	thsp->ths_nr_clrdiffs = 0;
	thsp->ths_clrdiff_ts = 0;
	thsp->ths_nr_osyncs = 0;
	thsp->ths_osync_ts = 0;
	thsp->ths_osync_err = 0;
	thsp->ths_clrstats_ts = INM_GET_CURR_TIME_IN_SEC;
	tcp->tc_stats.st_mode_switch_time = thsp->ths_clrstats_ts;
	tcp->tc_stats.st_wostate_switch_time = thsp->ths_clrstats_ts;
	volume_unlock(tcp);

	bp->num_bitmap_open_errors = 0;
	bp->num_bitmap_clear_errors = 0;
	bp->num_bitmap_read_errors = 0;
	bp->num_bitmap_write_errors = 0;
	bp->num_changes_read_from_bitmap = 0;
	bp->num_byte_changes_read_from_bitmap = 0;
	bp->num_changes_written_to_bitmap = 0;
	bp->num_byte_changes_written_to_bitmap = 0;
	INM_UP(&tcp->tc_sem);
}

/*
 * inm_validate_tc_devattr()
 * @tcp : target context ptr
 * notes : Validate the device/lun attributes
 * 			Callers should hold appropriate locks 
 */
int
inm_validate_tc_devattr(target_context_t *tcp, inm_dev_info_t *dip)
{
	inm_s32_t ret = -1;

	if (!tcp) {
		return -EINVAL;
	}

	switch (dip->d_type) {
	case FILTER_DEV_FABRIC_LUN:
		ret = inm_validate_fabric_vol(tcp, dip);
		break;

	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
		/* If the newly requested start filtering guid/pname mapping
		 * does not match preexisting, log an error
		 */
		if (strcmp(tcp->tc_guid, dip->d_guid) != 0 ||
			strcmp(tcp->tc_pname, dip->d_pname) !=0) 
			ret = -EINVAL;
		else
			ret = 0;

		break;

	case FILTER_DEV_FABRIC_VSNAP:
		ret = 0;
		break;

	default:
		info("Unknown device type inm_dev_info_t = %d\n", dip->d_type);
		break;
	}

	return ret;
}

void do_clear_diffs(target_context_t *tgt_ctxt)
{
	target_context_t *vcptr = NULL;
	struct inm_list_head chg_nodes_hd;
	struct inm_list_head *curp = NULL, *nxtp = NULL;
	volume_bitmap_t *vbmap = NULL;
	bitmap_info_t *bitmap = tgt_ctxt->tc_bp;

	INM_INIT_LIST_HEAD(&chg_nodes_hd);

	INM_DOWN(&tgt_ctxt->tc_sem);
	volume_lock(tgt_ctxt);

	set_tgt_ctxt_wostate(tgt_ctxt, ecWriteOrderStateUnInitialized, FALSE,
				            ecWOSChangeReasonUnInitialized);

	tgt_ctxt->tc_cur_mode = FLT_MODE_UNINITIALIZED;
	tgt_ctxt->tc_prev_mode = FLT_MODE_UNINITIALIZED;
	tgt_ctxt->tc_cur_wostate = ecWriteOrderStateUnInitialized;
	tgt_ctxt->tc_prev_wostate = ecWriteOrderStateUnInitialized;

	/* Data corruption issue caused due to releasing the data pages of 
	 * pending change node, before committing. this has occurred
	 * when tc_pending_confirm initialized to NULL. 
	 * So check all the code paths, when initializing
	 * tc_pending_confirm to NULL (which is mainly used in perform_commit() fn
	 *
	 * w/ this fix, orphan pages idea has replaced with orphan change nodes.
	 * orphan nodes are not considered for updating tgt ctxt's statistics.
	 **/
	 if (tgt_ctxt->tc_pending_confirm && 
			 !(tgt_ctxt->tc_pending_confirm->flags & 
				 CHANGE_NODE_ORPHANED)) {
		 change_node_t *cnp = tgt_ctxt->tc_pending_confirm;
		 cnp->flags |= CHANGE_NODE_ORPHANED;
		 inm_list_del_init(&cnp->next);
		 if (!inm_list_empty(&cnp->nwo_dmode_next)) {
			 inm_list_del_init(&cnp->nwo_dmode_next);
		 }
		 deref_chg_node(cnp);
	 } 
	/* Before writing to bitmap, remove data mode node from
	 * non write order list
	 */
	inm_list_for_each_safe(curp, nxtp, &tgt_ctxt->tc_nwo_dmode_list) {
		inm_list_del_init(curp);
	}
	list_change_head(&chg_nodes_hd, &tgt_ctxt->tc_node_head);
	INM_INIT_LIST_HEAD(&tgt_ctxt->tc_node_head);
	tgt_ctxt->tc_cur_node = NULL;

	tgt_ctxt->tc_pending_changes = 0;
	tgt_ctxt->tc_pending_md_changes = 0;
	tgt_ctxt->tc_bytes_pending_md_changes = 0;
	tgt_ctxt->tc_bytes_pending_changes = 0;
	tgt_ctxt->tc_pending_wostate_data_changes = 0;
	tgt_ctxt->tc_pending_wostate_md_changes = 0;
	tgt_ctxt->tc_pending_wostate_bm_changes = 0;
	tgt_ctxt->tc_pending_wostate_rbm_changes = 0;
	tgt_ctxt->tc_commited_changes = 0;
	tgt_ctxt->tc_bytes_commited_changes = 0;
	tgt_ctxt->tc_transaction_id = 0;
	telemetry_clear_dbs(&tgt_ctxt->tc_tel.tt_blend, 
						DBS_DRIVER_RESYNC_REQUIRED);
	tgt_ctxt->tc_resync_required = 0;

	/* bitmap related data */
	vcptr = tgt_ctxt;
	vbmap = bitmap->volume_bitmap;
	bitmap->volume_bitmap = NULL;
	bitmap->num_bitmap_open_errors = 0;
	tgt_ctxt->tc_hist.ths_clrdiff_ts = INM_GET_CURR_TIME_IN_SEC;
	tgt_ctxt->tc_hist.ths_nr_clrdiffs++;

	volume_unlock(tgt_ctxt);

	cleanup_change_nodes(&chg_nodes_hd, ecClearDiffs);

	volume_lock(tgt_ctxt);
	tgt_ctxt->tc_stats.st_mode_switch_time = INM_GET_CURR_TIME_IN_SEC;
	tgt_ctxt->tc_stats.st_wostate_switch_time = INM_GET_CURR_TIME_IN_SEC;
	volume_unlock(tgt_ctxt);
	
	if (vbmap)
		close_bitmap_file(vbmap, TRUE);

	set_unsignedlonglong_vol_attr(tgt_ctxt, VolumeRpoTimeStamp,
		tgt_ctxt->tc_hist.ths_clrdiff_ts*HUNDREDS_OF_NANOSEC_IN_SECOND);

	INM_UP(&tgt_ctxt->tc_sem);
}

inm_u32_t get_data_source(target_context_t *ctxt)
{

	switch(ctxt->tc_cur_mode) {
	case FLT_MODE_DATA:
		return INVOLFLT_DATA_SOURCE_DATA;
	case FLT_MODE_METADATA:
		return INVOLFLT_DATA_SOURCE_META_DATA;
	default:
		return INVOLFLT_DATA_SOURCE_META_DATA;
	}
}
 
/*
 *inm_deref_all_vol_entry_tcp() can only be called after stop filtering is issued
 */
static inm_s32_t
inm_deref_all_vol_entry_tcp(target_context_t *tgt_ctxt)
{
	  struct inm_list_head *ptr, *hd, *nextptr;
	  mirror_vol_entry_t *vol_entry = NULL;
	  inm_s32_t error = 0;

	  hd = &(tgt_ctxt->tc_dst_list);
	  inm_list_for_each_safe(ptr, nextptr, hd) {
		vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
		while(INM_ATOMIC_READ(&(vol_entry->vol_ref)) > 1){
			INM_DELAY(1 * INM_HZ);
		}
	  }
	  free_mirror_list(&(tgt_ctxt->tc_dst_list), 1);
	  free_mirror_list(&(tgt_ctxt->tc_src_list), 1);
	  return error;
}

void
init_latency_stats(inm_latency_stats_t *lat_stp, const inm_u64_t *bktsp)
{
	inm_s32_t i;

	if (!lat_stp || !bktsp) {
		err("initializing latency buckets failed\n");
		return;
	}

	INM_MEM_ZERO(lat_stp, sizeof(*lat_stp));

	for (i=0; ((i < INM_LATENCY_DIST_BKT_CAPACITY) &&
			(bktsp[i] > 0)); i++) {
		lat_stp->ls_bkts[i]=bktsp[i];
	}
	lat_stp->ls_nr_avail_bkts = i;
}

void
collect_latency_stats(inm_latency_stats_t *lat_stp, inm_u64_t time_in_usec)
{
	inm_u32_t idx = 0;
	inm_u64_t max_nr_bkts = lat_stp->ls_nr_avail_bkts-1;

	if (time_in_usec > lat_stp->ls_bkts[max_nr_bkts]) {
		idx = max_nr_bkts;
	} else {
		for (idx = 0; idx < max_nr_bkts; idx++) {
			if (time_in_usec <= lat_stp->ls_bkts[idx]) {
				break;
			}
		}
	}	
	
	lat_stp->ls_freq[idx]++;
	if (!lat_stp->ls_init_min_max) {
		lat_stp->ls_log_min = lat_stp->ls_log_max = time_in_usec;
		lat_stp->ls_init_min_max = 1;
	}
	if (lat_stp->ls_log_min > time_in_usec) {	
		lat_stp->ls_log_min = time_in_usec;
	}
	if (lat_stp->ls_log_max < time_in_usec) {	
		lat_stp->ls_log_max = time_in_usec;
	}

	idx = (lat_stp->ls_log_idx % INM_LATENCY_LOG_CAPACITY);
	lat_stp->ls_log_buf[idx] = time_in_usec;
	lat_stp->ls_log_idx++;
}

void
retrieve_volume_latency_stats(target_context_t *tcp, 
						VOLUME_LATENCY_STATS *vlsp)
{
	inm_u32_t	idx, o_idx;

	if (!tcp || !vlsp) {
		err("invalid buffers to copy latency data");
		return;
	}

	memcpy_s(vlsp->s2dbret_bkts, sizeof(tcp->tc_dbret_latstat.ls_bkts),
		tcp->tc_dbret_latstat.ls_bkts, 
		sizeof(tcp->tc_dbret_latstat.ls_bkts));
	memcpy_s(vlsp->s2dbret_freq, sizeof(tcp->tc_dbret_latstat.ls_freq),
		tcp->tc_dbret_latstat.ls_freq, 
		sizeof(tcp->tc_dbret_latstat.ls_freq));
	vlsp->s2dbret_nr_avail_bkts = tcp->tc_dbret_latstat.ls_nr_avail_bkts;
	vlsp->s2dbret_log_min = tcp->tc_dbret_latstat.ls_log_min;
	vlsp->s2dbret_log_max = tcp->tc_dbret_latstat.ls_log_max;
	
	
	memcpy_s(vlsp->s2dbwait_notify_bkts, 
			sizeof(tcp->tc_dbwait_notify_latstat.ls_bkts),
			tcp->tc_dbwait_notify_latstat.ls_bkts, 
			sizeof(tcp->tc_dbwait_notify_latstat.ls_bkts));
	memcpy_s(vlsp->s2dbwait_notify_freq, 
			sizeof(tcp->tc_dbwait_notify_latstat.ls_freq),
			tcp->tc_dbwait_notify_latstat.ls_freq, 
			sizeof(tcp->tc_dbwait_notify_latstat.ls_freq));
	vlsp->s2dbwait_notify_nr_avail_bkts = 
				tcp->tc_dbwait_notify_latstat.ls_nr_avail_bkts;
	vlsp->s2dbwait_notify_log_min = 
				tcp->tc_dbwait_notify_latstat.ls_log_min;
	vlsp->s2dbwait_notify_log_max = 
				tcp->tc_dbwait_notify_latstat.ls_log_max;
	
	memcpy_s(vlsp->s2dbcommit_bkts, 
			sizeof(tcp->tc_dbcommit_latstat.ls_bkts),
			tcp->tc_dbcommit_latstat.ls_bkts, 
			sizeof(tcp->tc_dbcommit_latstat.ls_bkts));
	memcpy_s(vlsp->s2dbcommit_freq, 
			sizeof(tcp->tc_dbcommit_latstat.ls_freq),
			tcp->tc_dbcommit_latstat.ls_freq, 
			sizeof(tcp->tc_dbcommit_latstat.ls_freq));
	vlsp->s2dbcommit_nr_avail_bkts = 
				tcp->tc_dbcommit_latstat.ls_nr_avail_bkts;
	vlsp->s2dbcommit_log_min = tcp->tc_dbcommit_latstat.ls_log_min;
	vlsp->s2dbcommit_log_max = tcp->tc_dbcommit_latstat.ls_log_max;

	for (o_idx = 0; o_idx < INM_LATENCY_LOG_CAPACITY; o_idx++) {
		idx = (tcp->tc_dbret_latstat.ls_log_idx + 
					INM_LATENCY_LOG_CAPACITY - 1) %
					INM_LATENCY_LOG_CAPACITY;
		vlsp->s2dbret_log_buf[o_idx] = 
					tcp->tc_dbret_latstat.ls_log_buf[idx];
		tcp->tc_dbret_latstat.ls_log_idx++;

		idx = (tcp->tc_dbwait_notify_latstat.ls_log_idx + 
					INM_LATENCY_LOG_CAPACITY - 1) %
					INM_LATENCY_LOG_CAPACITY;
		vlsp->s2dbwait_notify_log_buf[o_idx] = 
				tcp->tc_dbwait_notify_latstat.ls_log_buf[idx];
		tcp->tc_dbwait_notify_latstat.ls_log_idx++;

		idx = (tcp->tc_dbcommit_latstat.ls_log_idx + 
					INM_LATENCY_LOG_CAPACITY - 1) %
					INM_LATENCY_LOG_CAPACITY;
		vlsp->s2dbcommit_log_buf[o_idx] = 
				tcp->tc_dbcommit_latstat.ls_log_buf[idx];
		tcp->tc_dbcommit_latstat.ls_log_idx++;
		
	}
}

inm_u64_t
get_rpo_timestamp(target_context_t *ctxt, inm_u32_t flag,
				  change_node_t *pending_confirm)
{
	inm_irqflag_t lock_flag = 0;
	struct inm_list_head *ptr;
	change_node_t *oldest_chg_node;

	/* TSO commit or rpo timestamp req. through ioctl */
	if (inm_list_empty(&ctxt->tc_node_head)) {
		if (ctxt->tc_cur_wostate != ecWriteOrderStateBitmap &&
			(ctxt->tc_cur_wostate != 
			 		ecWriteOrderStateUnInitialized)) {
			/* Get the current driver time stamp */
			INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, 
								lock_flag);
			ctxt->tc_rpo_timestamp = driver_ctx->last_time_stamp;
			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, 
								lock_flag);
		} /* otherwise just return the older rpo timestamp */
		return ctxt->tc_rpo_timestamp;
	}
	ptr = ctxt->tc_node_head.next;
	oldest_chg_node = (change_node_t *)inm_list_entry(ptr, change_node_t, 
									next);

	/* TSO file commit OR ADDITIONAL STATS IOCTL codepath */
	if (ctxt->tc_tso_file == 1 ||
		flag == IOCTL_INMAGE_GET_ADDITIONAL_VOLUME_STATS) {
		/* See if RPO timestamp can be set to the start TS of oldest chgnode */
		if ((oldest_chg_node->wostate != ecWriteOrderStateBitmap) &&
			(oldest_chg_node != ctxt->tc_pending_confirm)) {
			ctxt->tc_rpo_timestamp =
			oldest_chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;
		}
		return  ctxt->tc_rpo_timestamp;
	}

	/* User data dirty block commit */
	INM_BUG_ON(!pending_confirm);
	if (pending_confirm->wostate ==  ecWriteOrderStateData) {
		ptr = ctxt->tc_node_head.next->next;
		if (ptr && ptr != &ctxt->tc_node_head) {
			/* set RPO to start timestamp of the second from oldest iff
			 * not in bitmap wostate otherwise set it to end timestamp of
			 * currently drained change node (pending_confirm)
			 */
			oldest_chg_node = (change_node_t *)inm_list_entry(ptr,
							 change_node_t, next);
			if (oldest_chg_node->wostate != 
						ecWriteOrderStateBitmap)
				ctxt->tc_rpo_timestamp =
				oldest_chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;
			else
				ctxt->tc_rpo_timestamp =
				pending_confirm->changes.end_ts.TimeInHundNanoSecondsFromJan1601;
		}
		else {
			/* Last change node got drained then RPO is zero */
			INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, 
								lock_flag);
			ctxt->tc_rpo_timestamp = driver_ctx->last_time_stamp;
			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, 
								lock_flag);
		}
	}
	else {
		/* pending confirm is not in wo state data i.e. perf changes
		 * kicked in and pending confirm always has manupulated
		 * timestamp
		 */
		 if (pending_confirm != oldest_chg_node &&
			 oldest_chg_node->wostate != ecWriteOrderStateBitmap) {
			 ctxt->tc_rpo_timestamp =
			 oldest_chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601;
		 }
	}
	return  ctxt->tc_rpo_timestamp;
}

void end_cx_session()
{
	vm_cx_session_t   *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	disk_cx_session_t *disk_cx_sess;
	inm_list_head_t   *ptr;

	if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED) ||
			(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED))
		return;

	vm_cx_sess->vcs_flags |= VCS_CX_SESSION_ENDED;
	get_time_stamp(&(vm_cx_sess->vcs_end_ts));

	for (ptr = driver_ctx->dc_disk_cx_sess_list.next;
			ptr != &(driver_ctx->dc_disk_cx_sess_list); 
			ptr = ptr->next) {
		disk_cx_sess = inm_list_entry(ptr, disk_cx_session_t, 
								dcs_list);

		if (!(disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED))
			continue;

		disk_cx_sess->dcs_flags |= DCS_CX_SESSION_ENDED;
		disk_cx_sess->dcs_end_ts = vm_cx_sess->vcs_end_ts;
	}
}

void update_disk_churn_buckets(disk_cx_session_t *disk_cx_sess)
{
	vm_cx_session_t *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	inm_u32_t disk_churn_in_MB = 
		(disk_cx_sess->dcs_tracked_bytes_per_second >>
					       MEGABYTE_BIT_SHIFT);
	inm_u32_t disk_bucket_idx = disk_churn_in_MB / 5;

	if (disk_bucket_idx >= DEFAULT_NR_CHURN_BUCKETS)
		disk_bucket_idx = DEFAULT_NR_CHURN_BUCKETS - 1;

	disk_cx_sess->dcs_churn_buckets[disk_bucket_idx]++;

	if (disk_cx_sess->dcs_tracked_bytes_per_second >=
			   vm_cx_sess->vcs_default_disk_peak_churn) {
		disk_cx_sess->dcs_excess_churn +=
			   (disk_cx_sess->dcs_tracked_bytes_per_second -
				vm_cx_sess->vcs_default_disk_peak_churn);

		get_time_stamp(&(disk_cx_sess->dcs_last_peak_churn_ts));
		if (!disk_cx_sess->dcs_first_peak_churn_ts)
			disk_cx_sess->dcs_first_peak_churn_ts =
					 disk_cx_sess->dcs_last_peak_churn_ts;

		if (disk_cx_sess->dcs_tracked_bytes_per_second >
					      disk_cx_sess->dcs_max_peak_churn)
			disk_cx_sess->dcs_max_peak_churn =
				 disk_cx_sess->dcs_tracked_bytes_per_second;
	}

	disk_cx_sess->dcs_tracked_bytes_per_second = 0;
	disk_cx_sess->dcs_base_secs_ts += HUNDREDS_OF_NANOSEC_IN_SECOND;
}

void update_vm_churn_buckets(vm_cx_session_t *vm_cx_sess)
{
	inm_u32_t vm_churn_in_MB = (vm_cx_sess->vcs_tracked_bytes_per_second >>
				                           MEGABYTE_BIT_SHIFT);
	inm_u32_t vm_bucket_idx = vm_churn_in_MB / 10;

	if (vm_bucket_idx >= DEFAULT_NR_CHURN_BUCKETS)
		vm_bucket_idx = DEFAULT_NR_CHURN_BUCKETS - 1;

	vm_cx_sess->vcs_churn_buckets[vm_bucket_idx]++;

	if (vm_cx_sess->vcs_tracked_bytes_per_second >=
				 vm_cx_sess->vcs_default_vm_peak_churn) {
		vm_cx_sess->vcs_excess_churn +=
				 (vm_cx_sess->vcs_tracked_bytes_per_second -
				  vm_cx_sess->vcs_default_vm_peak_churn);

		get_time_stamp(&(vm_cx_sess->vcs_last_peak_churn_ts));
		if (!vm_cx_sess->vcs_first_peak_churn_ts)
			vm_cx_sess->vcs_first_peak_churn_ts =
					vm_cx_sess->vcs_last_peak_churn_ts;

		if (vm_cx_sess->vcs_tracked_bytes_per_second >
					 vm_cx_sess->vcs_max_peak_churn)
			vm_cx_sess->vcs_max_peak_churn =
				vm_cx_sess->vcs_tracked_bytes_per_second;
	}

	vm_cx_sess->vcs_tracked_bytes_per_second = 0;
	vm_cx_sess->vcs_base_secs_ts += HUNDREDS_OF_NANOSEC_IN_SECOND;
}

void add_disk_sess_to_dc(target_context_t *ctxt)
{
	disk_cx_session_t *disk_cx_sess = &ctxt->tc_disk_cx_session;

	inm_list_add_tail(&disk_cx_sess->dcs_list,
					   &driver_ctx->dc_disk_cx_sess_list);
}

void remove_disk_sess_from_dc(target_context_t *ctxt)
{
	disk_cx_session_t *disk_cx_sess = &ctxt->tc_disk_cx_session;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				     driver_ctx->dc_vm_cx_session_lock_flag);
	inm_list_del(&disk_cx_sess->dcs_list);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				     driver_ctx->dc_vm_cx_session_lock_flag);
}

void start_disk_cx_session(target_context_t *ctxt, vm_cx_session_t *vm_cx_sess,
					   inm_u32_t nr_bytes)
{
	disk_cx_session_t *disk_cx_sess = &ctxt->tc_disk_cx_session;
	inm_u32_t         churn;

	churn = ((ctxt->tc_bytes_pending_changes <=
			  CX_SESSION_PENDING_BYTES_THRESHOLD) ?
			 (ctxt->tc_bytes_pending_changes + nr_bytes -
			  CX_SESSION_PENDING_BYTES_THRESHOLD) : nr_bytes);

	inm_list_del(&disk_cx_sess->dcs_list);
	INM_MEM_ZERO(disk_cx_sess, sizeof(disk_cx_session_t));
	inm_list_add_tail(&disk_cx_sess->dcs_list,
					   &driver_ctx->dc_disk_cx_sess_list);

	if (!vm_cx_sess->vcs_num_disk_cx_sess) {
		vm_cx_sess->vcs_tracked_bytes = 
			ctxt->tc_bytes_pending_changes + nr_bytes;
		vm_cx_sess->vcs_tracked_bytes_per_second += churn;

		disk_cx_sess->dcs_start_ts = vm_cx_sess->vcs_start_ts;
	} else {
		vm_cx_sess->vcs_tracked_bytes += nr_bytes;

		get_time_stamp(&(disk_cx_sess->dcs_start_ts));
		if (disk_cx_sess->dcs_start_ts - vm_cx_sess->vcs_base_secs_ts >=
				               HUNDREDS_OF_NANOSEC_IN_SECOND) {
			update_disk_churn_buckets(disk_cx_sess);
			update_vm_churn_buckets(vm_cx_sess);
		}

		vm_cx_sess->vcs_tracked_bytes_per_second += nr_bytes;
	}

	vm_cx_sess->vcs_num_disk_cx_sess++;
	disk_cx_sess->dcs_flags |= DCS_CX_SESSION_STARTED;
	disk_cx_sess->dcs_base_secs_ts = vm_cx_sess->vcs_base_secs_ts;
	disk_cx_sess->dcs_tracked_bytes = 
				ctxt->tc_bytes_pending_changes + nr_bytes;
	disk_cx_sess->dcs_tracked_bytes_per_second += churn;
	disk_cx_sess->dcs_nth_cx_session = vm_cx_sess->vcs_nth_cx_session;
}

void start_cx_session(target_context_t *ctxt, vm_cx_session_t *vm_cx_sess,
				                            inm_u32_t nr_bytes)
{
	INM_MEM_ZERO(vm_cx_sess, sizeof(vm_cx_session_t));

	vm_cx_sess->vcs_flags |= VCS_CX_SESSION_STARTED;
	get_time_stamp(&(vm_cx_sess->vcs_start_ts));
	vm_cx_sess->vcs_base_secs_ts = vm_cx_sess->vcs_start_ts;

	vm_cx_sess->vcs_nth_cx_session = ++driver_ctx->dc_nth_cx_session;

	if (driver_ctx->dc_disk_level_supported_churn) {
		vm_cx_sess->vcs_default_disk_peak_churn =
				driver_ctx->dc_disk_level_supported_churn;
		vm_cx_sess->vcs_default_vm_peak_churn =
				driver_ctx->dc_vm_level_supported_churn;
	} else {
		vm_cx_sess->vcs_default_disk_peak_churn = 
						DISK_LEVEL_SUPPORTED_CHURN;
		vm_cx_sess->vcs_default_vm_peak_churn = 
						VM_LEVEL_SUPPORTED_CHURN;
	}

	start_disk_cx_session(ctxt, vm_cx_sess, nr_bytes);
}

disk_cx_stats_info_t *find_disk_stat_info(target_context_t *ctxt)
{
	inm_list_head_t        *disk_cx_stats_ptr;
	disk_cx_stats_info_t   *disk_cx_stats_info;
	DEVICE_CXFAILURE_STATS *dev_cx_stats;

	for (disk_cx_stats_ptr = &driver_ctx->dc_disk_cx_stats_list;
				 disk_cx_stats_ptr != 
				 &driver_ctx->dc_disk_cx_stats_list;
				 disk_cx_stats_ptr = disk_cx_stats_ptr->next) {
		disk_cx_stats_info = inm_list_entry(disk_cx_stats_ptr,
				              disk_cx_stats_info_t, dcsi_list);
		dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
		if (!disk_cx_stats_info->dcsi_valid) {
			disk_cx_stats_info->dcsi_valid = 1;
			strcpy_s(dev_cx_stats->DeviceId.volume_guid, 
					GUID_SIZE_IN_CHARS, ctxt->tc_pname);
			return disk_cx_stats_info;
		}

		if (!strcmp(ctxt->tc_pname, 
				dev_cx_stats->DeviceId.volume_guid))
			return disk_cx_stats_info;
	}

	return NULL;
}

void close_disk_cx_session(target_context_t *ctxt, int reason_code)
{
	vm_cx_session_t        *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	disk_cx_session_t      *disk_cx_sess = &ctxt->tc_disk_cx_session;
	disk_cx_stats_info_t   *disk_cx_stats_info;
	DEVICE_CXFAILURE_STATS *disk_cx_stats;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				     driver_ctx->dc_vm_cx_session_lock_flag);
	if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED))
		goto out;

	if (disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED) {
		if (reason_code == CX_CLOSE_STOP_FILTERING_ISSUED ||
			   reason_code == CX_CLOSE_DISK_REMOVAL) {
			disk_cx_stats_info = 
					disk_cx_sess->dcs_disk_cx_stats_info;
			if (!disk_cx_stats_info) {
				 disk_cx_stats_info = find_disk_stat_info(ctxt);
				 if (!disk_cx_stats_info)
					 goto erase_disk_session;

				 driver_ctx->dc_num_disk_cx_stats++;
			}

			disk_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;

			if (reason_code & CX_CLOSE_STOP_FILTERING_ISSUED)
				disk_cx_stats->ullFlags |= 
					DISK_CXSTATUS_DISK_NOT_FILTERED;

			if (reason_code & CX_CLOSE_DISK_REMOVAL)
				disk_cx_stats->ullFlags |= 
					DISK_CXSTATUS_DISK_REMOVED;
		}

erase_disk_session:
		disk_cx_sess->dcs_flags = 0;

		vm_cx_sess->vcs_num_disk_cx_sess--;
		if (!vm_cx_sess->vcs_num_disk_cx_sess)
			INM_MEM_ZERO(vm_cx_sess, sizeof(vm_cx_session_t));
	}

out:
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);
}

void update_disk_cx_session(disk_cx_session_t *disk_cx_sess,
			vm_cx_session_t *vm_cx_sess, inm_u32_t nr_bytes)
{
	inm_u64_t cuur_ts;

	if (disk_cx_sess->dcs_base_secs_ts < vm_cx_sess->vcs_base_secs_ts) {
		update_disk_churn_buckets(disk_cx_sess);
		disk_cx_sess->dcs_base_secs_ts = vm_cx_sess->vcs_base_secs_ts;
	}

	get_time_stamp(&cuur_ts);
	if (cuur_ts - vm_cx_sess->vcs_base_secs_ts >= 
					HUNDREDS_OF_NANOSEC_IN_SECOND)
		update_disk_churn_buckets(disk_cx_sess);

	disk_cx_sess->dcs_tracked_bytes += nr_bytes;
	disk_cx_sess->dcs_tracked_bytes_per_second += nr_bytes;
}

void update_vm_cx_session(vm_cx_session_t *vm_cx_sess, inm_u32_t nr_bytes)
{
	inm_u64_t cuur_ts;

	get_time_stamp(&cuur_ts);
	if (cuur_ts - vm_cx_sess->vcs_base_secs_ts >= 
					HUNDREDS_OF_NANOSEC_IN_SECOND)
		update_vm_churn_buckets(vm_cx_sess);

	vm_cx_sess->vcs_tracked_bytes += nr_bytes;
	vm_cx_sess->vcs_tracked_bytes_per_second += nr_bytes;
}

void update_cx_session(target_context_t *ctxt, inm_u32_t nr_bytes)
{
	vm_cx_session_t   *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	disk_cx_session_t *disk_cx_sess = &ctxt->tc_disk_cx_session;
	inm_list_head_t   *ptr;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);
	if (driver_ctx->total_prot_volumes_in_nwo)
		goto out;

	if (!(disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED) &&
		 (vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED) &&
		 (ctxt->tc_bytes_pending_changes + nr_bytes) >
					  CX_SESSION_PENDING_BYTES_THRESHOLD) {
		for (ptr = driver_ctx->dc_disk_cx_sess_list.next;
				ptr != &driver_ctx->dc_disk_cx_sess_list; 
				ptr = ptr->next) {
			disk_cx_session_t *dcs;

			dcs = inm_list_entry(ptr, disk_cx_session_t, dcs_list);
			if (!(dcs->dcs_flags & DCS_CX_SESSION_STARTED))
				continue;

			dcs->dcs_flags = 0;

			vm_cx_sess->vcs_num_disk_cx_sess--;
			if (!vm_cx_sess->vcs_num_disk_cx_sess)
				INM_MEM_ZERO(vm_cx_sess, 
						sizeof(vm_cx_session_t));
		}
	}

	if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED)
		goto out;

	if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED)) {
		if ((ctxt->tc_bytes_pending_changes + nr_bytes) >
				  CX_SESSION_PENDING_BYTES_THRESHOLD)
			start_cx_session(ctxt, vm_cx_sess, nr_bytes);
	} else {
		if (!(disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED)) {
			if ((ctxt->tc_bytes_pending_changes + nr_bytes) >
					  CX_SESSION_PENDING_BYTES_THRESHOLD)
				start_disk_cx_session(ctxt, vm_cx_sess, 
								nr_bytes);
			else
				update_vm_cx_session(vm_cx_sess, nr_bytes);
		} else {
			update_disk_cx_session(disk_cx_sess, vm_cx_sess, 
								nr_bytes);
			update_vm_cx_session(vm_cx_sess, nr_bytes);
		}
	}

out:
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);
}

void update_cx_session_with_committed_bytes(target_context_t *ctxt, 
						inm_s32_t committed_bytes)
{
	vm_cx_session_t   *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	disk_cx_session_t *disk_cx_sess = &ctxt->tc_disk_cx_session;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				     driver_ctx->dc_vm_cx_session_lock_flag);
	if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED &&
			   !(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED)) {
		vm_cx_sess->vcs_drained_bytes += committed_bytes;

		if (disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED &&
			   !(disk_cx_sess->dcs_flags & DCS_CX_SESSION_ENDED))
			disk_cx_sess->dcs_drained_bytes += committed_bytes;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				     driver_ctx->dc_vm_cx_session_lock_flag);
}

void update_cx_product_issue(int flag)
{
	vm_cx_session_t *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	int             updated = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
	if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED) {
		if (!(vm_cx_sess->vcs_flags & flag)) {
			vm_cx_sess->vcs_flags |= (flag | VCS_CX_PRODUCT_ISSUE);
			updated = 1;
		}
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);

	if (!updated)
		return;

	switch (flag) {
		case VCS_CX_S2_EXIT:
		info("Drainer exited while CX sesion is in progress");
		break;

		case VCS_CX_SVAGENT_EXIT:
		info("svagent exited while CX sesion is in progress");
		break;

		case VCS_CX_TAG_FAILURE:
		info("Tag failed before CX session has ended");
		break;

		case VCS_CX_UNSUPPORTED_BIO:
		dbg("Unsupported BIO is detected");
		break;
	}
}

void update_cx_with_tag_failure()
{
	vm_cx_session_t *vm_cx_sess = &driver_ctx->dc_vm_cx_session;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
	if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED) {
		INM_BUG_ON(!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED));
		vm_cx_sess->vcs_num_consecutive_tag_failures++;

		if (vm_cx_sess->vcs_flags & VCS_CX_PRODUCT_ISSUE)
			goto out;

		if (vm_cx_sess->vcs_transaction_id)
			vm_cx_sess->vcs_transaction_id = 
					++driver_ctx->dc_transaction_id;

		if (vm_cx_sess->vcs_num_consecutive_tag_failures >=
				  driver_ctx->dc_num_consecutive_tags_failed)
			wake_up_interruptible(&driver_ctx->dc_vm_cx_session_waitq);
	}

out:
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
}

void update_cx_with_tag_success()
{
	vm_cx_session_t *vm_cx_sess = &driver_ctx->dc_vm_cx_session;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
	if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED) {
		vm_cx_sess->vcs_num_consecutive_tag_failures = 0;
		vm_cx_sess->vcs_transaction_id = 0;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
}

void update_cx_with_s2_latency(target_context_t *ctxt)
{
	vm_cx_session_t   *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	disk_cx_session_t *disk_cx_sess = &ctxt->tc_disk_cx_session;
	inm_u64_t         curr_ts;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				     driver_ctx->dc_vm_cx_session_lock_flag);
	if (disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED) {
		get_time_stamp(&curr_ts);
		if (ctxt->tc_s2_latency_base_ts &&
			   (curr_ts - ctxt->tc_s2_latency_base_ts) >
			   disk_cx_sess->dcs_max_s2_latency)
			disk_cx_sess->dcs_max_s2_latency = curr_ts -
					    ctxt->tc_s2_latency_base_ts;

		if (disk_cx_sess->dcs_max_s2_latency > 
					vm_cx_sess->vcs_max_s2_latency)
			vm_cx_sess->vcs_max_s2_latency = 
					disk_cx_sess->dcs_max_s2_latency;
	}

	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				driver_ctx->dc_vm_cx_session_lock_flag);
}

void update_cx_with_time_jump(inm_u64_t cur_time, inm_u64_t prev_time)
{
	vm_cx_session_t *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	int             time_jump_detected = 0;
	inm_u64_t       jump_in_ns;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
	if (cur_time > prev_time) {
		if (cur_time - prev_time >
			 (driver_ctx->dc_max_fwd_timejump_ms * 10000ULL)) {
			time_jump_detected = 1;
			vm_cx_sess->vcs_flags |= VCS_CX_TIME_JUMP_FWD;
			jump_in_ns = cur_time - prev_time;
		}
	} else {
		if (prev_time - cur_time >
			  (driver_ctx->dc_max_bwd_timejump_ms * 10000ULL)) {
			time_jump_detected = 1;
			vm_cx_sess->vcs_flags |= VCS_CX_TIME_JUMP_BWD;
			jump_in_ns = prev_time - cur_time;
		}
	}

	if (time_jump_detected) {
		vm_cx_sess->vcs_timejump_ts = prev_time;
		vm_cx_sess->vcs_max_jump_ms = (jump_in_ns / 10000ULL);

		if (vm_cx_sess->vcs_transaction_id)
			vm_cx_sess->vcs_transaction_id = 
					++driver_ctx->dc_transaction_id;

		wake_up_interruptible(&driver_ctx->dc_vm_cx_session_waitq);
	}

	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				  driver_ctx->dc_vm_cx_session_lock_flag);
}

void reset_s2_latency_time()
{
	target_context_t *ctxt;
	inm_list_head_t  *ptr;

	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
				           ptr = ptr->next, ctxt = NULL) {
		ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if (ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING))
			continue;

		volume_lock(ctxt);
		ctxt->tc_s2_latency_base_ts = 0;
		volume_unlock(ctxt);
	}
	INM_UP_READ(&driver_ctx->tgt_list_sem);
	
}

void volume_lock_all_close_cur_chg_node(void)
{
	target_context_t *ctxt;
	inm_list_head_t  *ptr;

	for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
				           ptr = ptr->next, ctxt = NULL) {
		ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		if (ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING))
			continue;

		INM_BUG_ON(!inm_list_empty(&ctxt->tc_non_drainable_node_head));
		volume_lock(ctxt);
		ctxt->tc_flags |= VCF_VOLUME_LOCKED;
		if ((ctxt->tc_optimize_performance &
			PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) &&
			!inm_list_empty(&ctxt->tc_node_head) &&
			ctxt->tc_cur_node) {
			do_perf_changes(ctxt, ctxt->tc_cur_node, 
								IN_IOCTL_PATH);
		}

		ctxt->tc_cur_node = NULL;
	}
}

void volume_unlock_all(void)
{
	target_context_t *ctxt;
	inm_list_head_t  *ptr;

	/* Accessing the target contexts in reverse order to main the lock
	 * hierarchy provided by volume_lock_all_close_cur_chg_node
	 */
	for (ptr = driver_ctx->tgt_list.prev; ptr != &(driver_ctx->tgt_list);
						ptr = ptr->prev, ctxt = NULL) {
		ctxt = inm_list_entry(ptr, target_context_t, tc_list);

		if (ctxt->tc_flags & VCF_VOLUME_LOCKED) {
			ctxt->tc_flags &= ~VCF_VOLUME_LOCKED;
			volume_unlock(ctxt);
		}
	}
}
