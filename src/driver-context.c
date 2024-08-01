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

#include "inm_types.h"
#define FLT_VERBOSITY
inm_u32_t inm_verbosity;

#include "involflt.h"
#include "involflt-common.h"
#include "data-mode.h"
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
#include "driver-context.h"
#include "file-io.h"
#include "utils.h"
#include "tunable_params.h"
#include "filter_host.h"
#include "filter.h"
#include "telemetry.h"

inm_s32_t data_mode = 1;

driver_context_t *driver_ctx = NULL;

inm_s32_t init_driver_context(void)
{
	inm_s32_t r = 0;
	

	driver_ctx = (driver_context_t *)INM_KMALLOC(sizeof(*driver_ctx), 
				INM_KM_SLEEP, INM_PINNED_HEAP);
	if(!driver_ctx) {    
		err("Failed to initialize driver context err = %d", ENOMEM);
		return -ENOMEM;
	}
	INM_MEM_ZERO(driver_ctx, sizeof(*driver_ctx));

#if (defined(INM_DEBUG))
	inm_verbosity |= (inm_u32_t)INM_DEBUG_ONLY;
#endif
#if (defined(IDEBUG))
	inm_verbosity |= INM_IDEBUG;
#endif
#if defined(IDEBUG_BMAP)
	inm_verbosity |= INM_IDEBUG_BMAP;
#endif
#if defined(IDEBUG_MIRROR)
	inm_verbosity |= INM_IDEBUG_MIRROR;
#endif
#if defined(IDEBUG_MIRROR_IO)
	inm_verbosity |= INM_IDEBUG_MIRROR_IO;
#endif
#if defined(IDEBUG_META)
	inm_verbosity |= INM_IDEBUG_META;
#endif
#if defined(DEBUG_REF)
	inm_verbosity |= INM_IDEBUG_REF;
#endif
#if defined(IDEBUG_BMAP_REF)
	inm_verbosity |= INM_IDEBUG_IO;
#endif

	/* Reserve 6.25% of system memory for data page pool */
	driver_ctx->default_data_pool_size_mb = get_data_page_pool_mb();
	if (!driver_ctx->default_data_pool_size_mb) {
		r = -ENOMEM;	
		err("Memory is not enough for driver initialization err = %d", 
								r);
		goto free_dc;
	}

	INM_INIT_SPIN_LOCK(&driver_ctx->tunables_lock);
	init_driver_tunable_params();

#ifndef INM_AIX
	driver_ctx->dc_host_info.bio_info_cache =
		INM_KMEM_CACHE_CREATE("global_bio_info_cache", INM_BIOSZ, 0, 0, 
				NULL, NULL, INM_MAX_NR_GLOBAL_BUF_INFO_POOL,
				INM_MIN_NR_GLOBAL_BUF_INFO_POOL, INM_PINNED);
	if(!driver_ctx->dc_host_info.bio_info_cache){
		INM_DESTROY_SPIN_LOCK(&driver_ctx->tunables_lock);
		r = INM_ENOMEM;	
		err("INM_KMEM_CACHE_CREATE failed to create bio cache err = %d", 
								r);
		goto free_dc;
	}
#endif
	driver_ctx->dc_host_info.mirror_bioinfo_cache =
		INM_KMEM_CACHE_CREATE("global_mirror_bioinfo_cache", 
				INM_MIRROR_BIOSZ, 0, 0, NULL, NULL, 
				INM_MAX_NR_GLOBAL_MIRROR_BUF_INFO_POOL,
				INM_MIN_NR_GLOBAL_MIRROR_BUF_INFO_POOL, 
				INM_PINNED);
	if(!driver_ctx->dc_host_info.mirror_bioinfo_cache){
		INM_DESTROY_SPIN_LOCK(&driver_ctx->tunables_lock);
#ifndef INM_AIX
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.bio_info_cache);
#endif
		r = INM_ENOMEM;
		err("INM_KMEM_CACHE_CREATE failed to create mirror bio cache "
				"err = %d", r);
		goto free_dc;
	}

#ifdef INM_AIX
	driver_ctx->dc_host_info.data_file_node_cache = 
		INM_KMEM_CACHE_CREATE("data_file_node_cache", 
				sizeof(data_file_node_t), 0, 0, NULL, NULL,
				INM_MAX_NR_DATA_FILE_NODE_POOL, 
				INM_MIN_NR_DATA_FILE_NODE_POOL, INM_PINNED);
	if(!driver_ctx->dc_host_info.data_file_node_cache){
		INM_DESTROY_SPIN_LOCK(&driver_ctx->tunables_lock);
		r = -ENOMEM;
		err("INM_KMEM_CACHE_CREATE failed to create data_file_node_cache "
					"err = %d", r);
		goto free_bio_cache;
	}
#endif

	INM_INIT_LIST_HEAD(&driver_ctx->tgt_list);
	INM_RW_SEM_INIT(&driver_ctx->tgt_list_sem);
	INIT_OSSPEC_DRV_CTX(driver_ctx);

	INM_INIT_LIST_HEAD(&driver_ctx->tag_guid_list);
	INM_RW_SEM_INIT(&driver_ctx->tag_guid_list_sem);

	driver_ctx->service_state = SERVICE_UNITIALIZED;
	INM_INIT_SPIN_LOCK(&driver_ctx->log_lock);
	 
	/* initialize the stats structure */
	INM_MEM_ZERO(&driver_ctx->stats, sizeof(dc_stats_t));

	/* change node memory pool */
	INM_INIT_LIST_HEAD(&driver_ctx->page_pool);
	INM_INIT_SPIN_LOCK(&driver_ctx->page_pool_lock);

	/* allocate bitmap work item pool */ 
	/* allocate work queue entry pool */ 
	r = alloc_cache_pools();
	if (r)
		goto deinit_locks;

	/* initialize head_for_volume_bitmaps */
	INM_INIT_LIST_HEAD(&driver_ctx->dc_bmap_info.head_for_volume_bitmaps);
	driver_ctx->dc_bmap_info.num_volume_bitmaps = 0;
	INM_ATOMIC_SET(&driver_ctx->involflt_refcnt,0);

	INM_INIT_SPIN_LOCK(&driver_ctx->clean_shutdown_lock);
		
	if (driver_ctx->tunable_params.data_pool_size) {
		r = init_data_flt_ctxt(&driver_ctx->data_flt_ctx);
	}
	else {
	   r = -ENOMEM;
	}
	if(r)
		goto free_cache_pools;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		/*   print_driver_context(driver_ctx); */
	}

	INM_ATOMIC_SET(&(driver_ctx->stats.pending_chg_nodes), 0);	
	INM_INIT_LIST_HEAD(&driver_ctx->dc_host_info.rq_list);
	INM_INIT_SPIN_LOCK(&driver_ctx->dc_host_info.rq_list_lock);

	INM_INIT_SPIN_LOCK(&driver_ctx->time_stamp_lock);
	driver_ctx->sys_shutdown = 0;

	INM_INIT_COMPLETION(&driver_ctx->shutdown_completion);
	INM_INIT_SEM(&driver_ctx->tag_sem);

	driver_ctx->sentinal_pid = 0;
	driver_ctx->sentinal_idhp = NULL;
	driver_ctx->svagent_pid = 0;
	driver_ctx->svagent_idhp = NULL;

#ifdef INM_QUEUE_RQ_ENABLED
	INM_INIT_SPIN_LOCK(&driver_ctx->dc_inmaops_lock);
#else
	INM_RW_SEM_INIT(&driver_ctx->dc_inmaops_sem);
#endif

	INM_INIT_LIST_HEAD(&driver_ctx->dc_inma_ops_list);

	INM_INIT_LIST_HEAD(&driver_ctx->recursive_writes_meta_list);
	INM_INIT_SPIN_LOCK(&driver_ctx->recursive_writes_meta_list_lock);

	/* initialize work queue context */
	r = init_work_queue(&driver_ctx->wqueue, NULL);
	if(r)
		goto free_cache_pools;

	/* Per IO stamp file */
	snprintf(driver_ctx->driver_time_stamp, INM_PATH_MAX ,
		"%s/%s/GlobalTimeStamp", PERSISTENT_DIR, COMMON_ATTR_NAME);
	
	/* Per IO stamp seqno file */
	snprintf(driver_ctx->driver_time_stamp_seqno, INM_PATH_MAX , 
		"%s/%s/SequenceNumber", PERSISTENT_DIR, COMMON_ATTR_NAME);

	 /* Consistency Point */
	INM_ATOMIC_SET(&driver_ctx->is_iobarrier_on, 0);
	INM_INIT_LIST_HEAD(&driver_ctx->freeze_vol_list);
	driver_ctx->dc_cp = INM_CP_NONE;
	INM_MEM_ZERO(driver_ctx->dc_cp_guid, 
				 sizeof(driver_ctx->dc_cp_guid));
	INM_INIT_SEM(&driver_ctx->dc_cp_mutex);

	driver_ctx->dc_lcw_aops = NULL;
	driver_ctx->dc_lcw_rhdl = NULL;
	driver_ctx->dc_lcw_rflag = 0;

	driver_ctx->dc_root_disk = NULL;

	INM_INIT_SPIN_LOCK(&driver_ctx->dc_tel.dt_dbs_slock);
	telemetry_set_dbs(&driver_ctx->dc_tel.dt_blend, 
					DBS_DRIVER_NOREBOOT_MODE);

	INM_INIT_SPIN_LOCK(&driver_ctx->dc_vm_cx_session_lock);
	INM_INIT_WAITQUEUE_HEAD(&driver_ctx->dc_vm_cx_session_waitq);
	INM_INIT_LIST_HEAD(&driver_ctx->dc_disk_cx_stats_list);
	INM_INIT_LIST_HEAD(&driver_ctx->dc_disk_cx_sess_list);
	driver_ctx->dc_num_consecutive_tags_failed =
				VCS_NUM_CONSECTIVE_TAG_FAILURES_ALLOWED;
	driver_ctx->dc_max_fwd_timejump_ms = FORWARD_TIMEJUMP_ALLOWED;
	driver_ctx->dc_max_bwd_timejump_ms = BACKWARD_TIMEJUMP_ALLOWED;

	INM_INIT_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_tag_commit_status_pending_disks, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_tag_commit_status_failed, 0);
	INM_INIT_WAITQUEUE_HEAD(&driver_ctx->dc_tag_commit_status_waitq);
	
	/* initialize timer queue context */
	r = init_work_queue(&driver_ctx->dc_tqueue, timer_worker);
	if(r)
		goto cleanup_wqueue;
	
	telemetry_check_time_jump();
	get_time_stamp(&(driver_ctx->dc_tel.dt_drv_load_time));

	driver_ctx->dc_verifier_on = 0;
	INM_INIT_SPIN_LOCK(&driver_ctx->dc_verifier_lock);
	driver_ctx->dc_verifier_area = NULL;

	return 0;

cleanup_wqueue:
	cleanup_work_queue(&driver_ctx->wqueue);

free_cache_pools:
	INM_DESTROY_SPIN_LOCK(&driver_ctx->clean_shutdown_lock);
	dealloc_cache_pools();

deinit_locks:
	INM_DESTROY_SPIN_LOCK(&driver_ctx->page_pool_lock);
	INM_DESTROY_SPIN_LOCK(&driver_ctx->log_lock);
	INM_RW_SEM_DESTROY(&driver_ctx->tgt_list_sem);
	INM_RW_SEM_DESTROY(&driver_ctx->tag_guid_list_sem);
#ifdef INM_AIX
	INM_DESTROY_SEM(&driver_ctx->dc_mxs_sem);

free_bio_cache:
#endif
#ifndef INM_AIX
	if(driver_ctx->dc_host_info.bio_info_cache){
	   INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.bio_info_cache);
	}
#endif
	if(driver_ctx->dc_host_info.mirror_bioinfo_cache){
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.mirror_bioinfo_cache);
	}
#ifdef INM_AIX
	INM_DESTROY_SPIN_LOCK(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn));
	INM_DESTROY_SPIN_LOCK(&(driver_ctx->dc_at_lun.dc_cdb_dev_list_lock));
	INM_DESTROY_SPIN_LOCK(&driver_ctx->tgt_list_lock);
	INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.data_file_node_cache);
#endif

free_dc:
	INM_KFREE(driver_ctx, sizeof(*driver_ctx), INM_PINNED_HEAP);
	driver_ctx = NULL;

	return r;
}

void free_driver_context(void)
{
	struct inm_list_head *lp = NULL, *np = NULL;
	unsigned long lock_flag;

	INM_BUG_ON(!inm_list_empty(&driver_ctx->dc_disk_cx_sess_list));

	while (!inm_list_empty(&driver_ctx->dc_disk_cx_stats_list)) {
		disk_cx_stats_info_t *disk_cx_stats_info;

		disk_cx_stats_info =
			inm_list_entry(driver_ctx->dc_disk_cx_stats_list.next,
				         disk_cx_stats_info_t, dcsi_list);
		inm_list_del(&disk_cx_stats_info->dcsi_list);
		INM_KFREE(disk_cx_stats_info, sizeof(disk_cx_stats_info_t),
						         INM_KERNEL_HEAP);
	}

	free_data_flt_ctxt(&driver_ctx->data_flt_ctx);

	cleanup_work_queue(&driver_ctx->dc_tqueue);
	cleanup_work_queue(&driver_ctx->wqueue);

	/* freeing inma_ops */
	lock_inmaops(TRUE, &lock_flag);
	
	inm_list_for_each_safe(lp, np, &driver_ctx->dc_inma_ops_list) {
		inma_ops_t *t_inma_opsp = NULL;

		inm_list_del(lp);
		t_inma_opsp = (inma_ops_t *) inm_list_entry(lp, inma_ops_t,
								ia_list);
		inm_free_inma_ops(t_inma_opsp);
	}
	unlock_inmaops(TRUE, &lock_flag);
	
	/* free the bitmap work item, work queue entry pools */
	dealloc_cache_pools();

	/* Destroy tag guid list if exists */
	INM_DOWN_WRITE(&driver_ctx->tag_guid_list_sem);
	while(!inm_list_empty(&driver_ctx->tag_guid_list)){
		tag_guid_t *tag_guid = inm_list_entry(driver_ctx->tag_guid_list.next,
							tag_guid_t, tag_list);
		inm_list_del(&tag_guid->tag_list);
		INM_WAKEUP_INTERRUPTIBLE(&tag_guid->wq);
		flt_cleanup_sync_tag(tag_guid);
	}
	INM_UP_WRITE(&driver_ctx->tag_guid_list_sem);

	INM_DESTROY_COMPLETION(&driver_ctx->shutdown_completion);
#ifdef INM_QUEUE_RQ_ENABLED
	INM_DESTROY_SPIN_LOCK(&driver_ctx->dc_inmaops_lock);
#else
	INM_RW_SEM_DESTROY(&driver_ctx->dc_inmaops_sem);
#endif
	INM_DESTROY_SEM(&driver_ctx->tag_sem);
	INM_DESTROY_SPIN_LOCK(&driver_ctx->time_stamp_lock);
	INM_DESTROY_SPIN_LOCK(&driver_ctx->dc_host_info.rq_list_lock);
	INM_DESTROY_SPIN_LOCK(&driver_ctx->page_pool_lock);
	INM_DESTROY_SPIN_LOCK(&driver_ctx->log_lock);
	INM_RW_SEM_DESTROY(&driver_ctx->tgt_list_sem);
#ifdef INM_AIX
	free_all_at_lun_entries();
	free_all_mxs_entries();
	INM_DESTROY_SPIN_LOCK(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn));
	INM_DESTROY_SPIN_LOCK(&(driver_ctx->dc_at_lun.dc_cdb_dev_list_lock));
	INM_DESTROY_SPIN_LOCK(&driver_ctx->tgt_list_lock);
	INM_DESTROY_SEM(&driver_ctx->dc_mxs_sem);
	INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.data_file_node_cache);
#endif
	INM_RW_SEM_DESTROY(&driver_ctx->tag_guid_list_sem);
	INM_DESTROY_SPIN_LOCK(&driver_ctx->recursive_writes_meta_list_lock);

	if(driver_ctx) {
		inm_flush_clean_shutdown(CLEAN_SHUTDOWN);
		INM_DESTROY_SPIN_LOCK(&driver_ctx->clean_shutdown_lock);

#ifndef INM_AIX
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.bio_info_cache);
#endif
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_host_info.mirror_bioinfo_cache);
		INM_KFREE(driver_ctx, sizeof(*driver_ctx), INM_PINNED_HEAP);    
		driver_ctx = NULL;
	}
	
}

void add_tc_to_dc(target_context_t *tc)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	tc->tc_hist.ths_start_flt_ts = INM_GET_CURR_TIME_IN_SEC;
	inm_list_add_tail(&tc->tc_list, &driver_ctx->tgt_list);
	driver_ctx->total_prot_volumes++;
	if(tc->tc_dev_type ==  FILTER_DEV_MIRROR_SETUP){
		driver_ctx->mirror_prot_volumes++;
	}else {
		driver_ctx->host_prot_volumes++;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

void remove_tc_from_dc(target_context_t *tc)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}
	INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	inm_list_del(&tc->tc_list);
	driver_ctx->total_prot_volumes--;
	if(tc->tc_dev_type ==  FILTER_DEV_MIRROR_SETUP){
		driver_ctx->mirror_prot_volumes--;
	}else {
		driver_ctx->host_prot_volumes--;
	}
	wake_up_tc_state(tc);
	INM_UP_WRITE(&driver_ctx->tgt_list_sem);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

/* allocate global pools */
inm_s32_t alloc_cache_pools()
{

	inm_s32_t err = 0;
	inm_s32_t threshold = 256, i = 0;
	inm_page_t *pg = NULL;
	
	
	while (i < threshold) {
		pg = (inm_page_t *) INM_KMALLOC(sizeof(inm_page_t),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
		if (!pg) {
			err = -ENOMEM;
			goto next;
		}

		INM_MEM_ZERO(pg, sizeof(inm_page_t));

		if(INM_PIN(pg, sizeof(inm_page_t))){
			err = -ENOMEM;
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			goto next;
		}

		pg->cur_pg = (unsigned long *)__INM_GET_FREE_PAGE(INM_KM_SLEEP, 
							INM_KERNEL_HEAP);
		if (!pg->cur_pg) {
			err = -ENOMEM;
			INM_UNPIN(pg, sizeof(inm_page_t));
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			goto next;
		}
		if(INM_PIN(pg->cur_pg, INM_PAGESZ)){
			err = -ENOMEM;
			INM_FREE_PAGE(pg->cur_pg, INM_KERNEL_HEAP);
			INM_UNPIN(pg, sizeof(inm_page_t));
			INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
			goto next;
		}
		inm_list_add_tail(&pg->entry, &driver_ctx->page_pool);
#ifdef INM_QUEUE_RQ_ENABLED
		pg->flags = METAPAGE_ALLOCED_FROM_POOL;
#endif
		i++;
	}
	driver_ctx->dc_res_cnode_pgs = threshold;

	driver_ctx->dc_bmap_info.bitmap_work_item_pool =
		INM_KMEM_CACHE_CREATE("BITMAP_WORK_ITEM_POOL",
			  sizeof(bitmap_work_item_t), 0, INM_SLAB_HWCACHE_ALIGN,
			  NULL, NULL, INM_MAX_NR_BITMAP_WORK_ITEM_POOL,
			  INM_MIN_NR_BITMAP_WORK_ITEM_POOL, INM_UNPINNED);
	if (IS_ERR(driver_ctx->dc_bmap_info.bitmap_work_item_pool)) {
		err = -ENOMEM;
		goto next;
	} else
		driver_ctx->flags |= DC_FLAGS_BITMAP_WORK_ITEM_POOL_INIT;

	driver_ctx->wq_entry_pool = INM_KMEM_CACHE_CREATE("WQ_ENTRY_POOL",
			 	sizeof(wqentry_t), 0, INM_SLAB_HWCACHE_ALIGN,
				NULL, NULL, INM_MAX_NR_WQ_ENTRY_POOL, 
				INM_MIN_NR_WQ_ENTRY_POOL, INM_PINNED);
	if (IS_ERR(driver_ctx->wq_entry_pool))
		err = -ENOMEM;
	else
		driver_ctx->flags |= DC_FLAGS_WORKQUEUE_ENTRIES_POOL_INIT;

next:
	if (err) 
		dealloc_cache_pools();
	
	return err;

}

inm_s32_t dealloc_cache_pools()
{

	inm_s32_t err = 0;
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	inm_page_t *pg = NULL;

	inm_list_for_each_safe(ptr, nextptr, &driver_ctx->page_pool) {
		pg = inm_list_entry(ptr, inm_page_t, entry);
		inm_list_del(&pg->entry);
		INM_UNPIN(pg->cur_pg, INM_PAGESZ);
		INM_FREE_PAGE(pg->cur_pg, INM_KERNEL_HEAP);
		INM_UNPIN(pg, sizeof(inm_page_t));
		INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
	}

	if (driver_ctx->flags & DC_FLAGS_BITMAP_WORK_ITEM_POOL_INIT) {
		INM_KMEM_CACHE_DESTROY(driver_ctx->dc_bmap_info.bitmap_work_item_pool);
	}

	if (driver_ctx->flags & DC_FLAGS_WORKQUEUE_ENTRIES_POOL_INIT) {
		INM_KMEM_CACHE_DESTROY(driver_ctx->wq_entry_pool);
	}
	driver_ctx->flags &= ~(DC_FLAGS_BITMAP_WORK_ITEM_POOL_INIT |
			   DC_FLAGS_WORKQUEUE_ENTRIES_POOL_INIT);
	return err;
}

void
service_shutdown_completion(void)
{
	driver_ctx->service_state = SERVICE_SHUTDOWN;
	info("service got shutdown");

	driver_ctx->flags |= DC_FLAGS_SERVICE_STATE_CHANGED;

	INM_ATOMIC_INC(&driver_ctx->service_thread.wakeup_event_raised);
	INM_WAKEUP_INTERRUPTIBLE(&driver_ctx->service_thread.wakeup_event);
	INM_COMPLETE(&driver_ctx->service_thread._new_event_completion);
}

void
inm_svagent_exit(void)
{
	info("Service exiting pid = %d", driver_ctx->svagent_pid);
	get_time_stamp(&(driver_ctx->dc_tel.dt_svagent_stop_time));
	telemetry_set_dbs(&driver_ctx->dc_tel.dt_blend, DBS_SERVICE_STOPPED);
	driver_ctx->svagent_pid = 0;
	driver_ctx->svagent_idhp = NULL;
	service_shutdown_completion();
	update_cx_product_issue(VCS_CX_SVAGENT_EXIT);
}

void
inm_s2_exit(void)
{

	target_context_t *tgt_ctxt = NULL;
	change_node_t *chg_node;
	struct inm_list_head *curp = NULL, *nxtp = NULL;

	dbg("Drainer exiting pid = %d", driver_ctx->sentinal_pid);
	get_time_stamp(&(driver_ctx->dc_tel.dt_s2_stop_time));
	telemetry_set_dbs(&driver_ctx->dc_tel.dt_blend, DBS_S2_STOPPED);
	start_notify_completion();

	update_cx_product_issue(VCS_CX_S2_EXIT);
	reset_s2_latency_time();

retry:
	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	inm_list_for_each_safe(curp, nxtp, &driver_ctx->tgt_list){ 
		tgt_ctxt = inm_list_entry(curp, target_context_t, tc_list);
		volume_lock(tgt_ctxt);
		chg_node = tgt_ctxt->tc_pending_confirm;
		if (chg_node) {
			chg_node->flags &= ~CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2;
			/* Reset closed state of a change node in non write order mode:
			 * drainer gets killed with currently mapped matadata change node
			 * and in the mean time, data mode change node is available before
			 * drainer comes up and again calls getdb, we would serve data mode 
			 * change node instead due perf changes
			 * Hence currently closed metadata change node needs to reset
			 * its start and end time stamps during its next getdb call
			 * otherwise we would see OOD issue
			 */
			if (tgt_ctxt->tc_optimize_performance &
				(PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) &&
				(chg_node->type == NODE_SRC_METADATA) &&
				(chg_node->flags & CHANGE_NODE_IN_NWO_CLOSED)) {
				chg_node->flags &= ~(CHANGE_NODE_IN_NWO_CLOSED);
				chg_node->transaction_id = 0;
				--tgt_ctxt->tc_transaction_id;
				if (tgt_ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DATA_DRAIN) {
					 info("drainer_exit: Reset metadata closed state chg_node:%p mode:%d"
						 "delta ts:%llu seq:%llu tc_cur_node:%p", chg_node,chg_node->type,
						 chg_node->changes.end_ts.TimeInHundNanoSecondsFromJan1601 -
						 chg_node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
						 chg_node->changes.end_ts.ullSequenceNumber -
						 chg_node->changes.start_ts.ullSequenceNumber,
						 tgt_ctxt->tc_cur_node);
				}
			}
		}
		tgt_ctxt->tc_pending_confirm = NULL;
		volume_unlock(tgt_ctxt);

		if (chg_node) {
			if (chg_node->flags & CHANGE_NODE_ORPHANED) {

				if (chg_node->type == NODE_SRC_TAGS) 
					telemetry_log_tag_history(chg_node,
							tgt_ctxt, ecTagStatusDropped, 
							ecOrphan, ecMsgTagDropped);

					commit_change_node(chg_node);
			} else {
				INM_DOWN(&chg_node->mutex);
				chg_node->mapped_thread = NULL;
#ifdef INM_AIX
				chg_node->mapped_address = 0;
#else
#ifdef INM_LINUX
				if(current->mm)
#endif
					unmap_change_node(chg_node);      
#endif
				INM_UP(&chg_node->mutex);
				deref_chg_node(chg_node);
			}
			INM_UP_READ(&driver_ctx->tgt_list_sem); 
			put_tgt_ctxt(tgt_ctxt);
			goto retry;
		}
	}
	INM_UP_READ(&driver_ctx->tgt_list_sem);
	/* de-initialize and free the associated resources
	 * related to mapped dblk*/
	driver_ctx->sentinal_pid = 0;
	driver_ctx->sentinal_idhp = NULL;
}

/* lock inmaops with read or write, read = 0, write = 1 */
void lock_inmaops(bool write, unsigned long* lock_flag)
{
#ifdef INM_QUEUE_RQ_ENABLED
    INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_inmaops_lock, *lock_flag);
#else
    if (write) {
        INM_DOWN_WRITE(&driver_ctx->dc_inmaops_sem);
    } else {
        INM_DOWN_READ(&driver_ctx->dc_inmaops_sem);
    } 
    
#endif	
  
}
/* unlock inmaops with read or write, read = 0, write = 1 */
void unlock_inmaops(bool write, unsigned long* lock_flag)
{
#ifdef INM_QUEUE_RQ_ENABLED
    INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_inmaops_lock, *lock_flag);
#else
    if (write) {
        INM_UP_WRITE(&driver_ctx->dc_inmaops_sem);
    } else {
        INM_UP_READ(&driver_ctx->dc_inmaops_sem);
    } 
#endif	
}
