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
 #include "driver-context.h"
 #include "utils.h"
 #include "tunable_params.h"
 #include "db_routines.h"
 #include "involflt_debug.h"
 #include "metadata-mode.h"
 #include "file-io.h"
 #include "filter_host.h"
 #include "filter.h"
 #include "errlog.h"
 #ifdef INM_LINUX
 #include "filter_lun.h"
 #endif
 #include "ioctl.h"
 #include "filestream_raw.h"
 #include "last_chance_writes.h"
 #include "telemetry.h"
 
 struct _inm_resync_notify_info;
 extern driver_context_t *driver_ctx;
 extern char *ErrorToRegErrorDescriptionsA[];
 extern const inm_s32_t sv_const_sz;
 extern const inm_s32_t sv_chg_sz;
 extern inm_s32_t flt_process_tags(inm_s32_t num_vols,
		  void __INM_USER **user_buf, inm_s32_t flags, tag_guid_t *);
 #ifdef INM_LINUX
 extern flt_timer_t cp_timer;
 void start_cp_timer(int timeout_ms, timeout_t callback);
 void inm_fvol_list_thaw_on_timeout(wqentry_t *not_used);
 inm_s32_t iobarrier_issue_tag_all_volume(tag_info_t *tag_list, int nr_tags, 
			 int commit_pending, tag_telemetry_common_t *);
 extern inm_s32_t driver_state;
 #endif
 static inm_u32_t inm_calc_len_required( struct inm_list_head *ptr);
 static inm_u32_t inm_wait_exception_ev(target_context_t *, 
						 inm_resync_notify_info_t *);
 static inm_s32_t inm_fill_resync_notify_info(target_context_t *tgt_ctxt,
				 struct _inm_resync_notify_info *resync_info);
 static void print_AT_stat_common(target_context_t *tcp, char *page, 
							 inm_s32_t *len);
 
 inm_s32_t stop_filtering_volume(char *uuid, inm_devhandle_t *idhp, 
								 int dbs_flag); 
 
 static inm_u32_t
 inm_wait_exception_ev(target_context_t *tgt_ctxt, 
				 inm_resync_notify_info_t *resync_info)
 {
	 inm_u32_t ret = 0;
	 host_dev_ctx_t *hdcp = NULL;
 
	 dbg("entered");
	 hdcp = tgt_ctxt->tc_priv;
	 INM_BUG_ON(!hdcp);
	 if (hdcp) {
		 if (tgt_ctxt->tc_resync_required) {
			 inm_fill_resync_notify_info(tgt_ctxt, resync_info);
			 goto out;
		 }
		 inm_wait_event_interruptible_timeout(hdcp->resync_notify,
					 tgt_ctxt->tc_resync_required,
					 resync_info->timeout_in_sec * INM_HZ);
	 } else {
		 ret = INM_EINVAL;
		 resync_info->rstatus = MIRROR_STACKING_ERR;
		 goto out;
	 }
 
	 if(tgt_ctxt->tc_resync_required){
		 inm_fill_resync_notify_info(tgt_ctxt, resync_info);
	 } else {
		 if (!(is_target_mirror_paused(tgt_ctxt))){
			 inm_heartbeat_cdb(tgt_ctxt);
		 }
		 ret = INM_ETIMEDOUT;
	 }
 
 out:
	 dbg("leaving");
	 return ret;
 }
 
 
 static inm_s32_t
 inm_fill_resync_notify_info(target_context_t *tgt_ctxt, 
				 inm_resync_notify_info_t *resync_info)
 {
	 inm_s32_t ret = 0;
	 unsigned long sync_err = 0;
 
	 if (!tgt_ctxt || !resync_info){
		 ret = INM_EINVAL;
		 INM_BUG_ON(1);
		 goto out;
	 }
 
	 volume_lock(tgt_ctxt);
	 tgt_ctxt->tc_flags |= VCF_MIRRORING_PAUSED;
	 volume_unlock(tgt_ctxt);
 
	 resync_info->rsin_flag |= INM_SET_RESYNC_REQ_FLAG;
	 resync_info->rsin_resync_err_code = tgt_ctxt->tc_out_of_sync_err_code;
	 resync_info->rsin_out_of_sync_count =  tgt_ctxt->tc_nr_out_of_sync;
	 resync_info->rsin_out_of_sync_time_stamp = tgt_ctxt->tc_out_of_sync_time_stamp;
	 resync_info->rsin_out_of_sync_err_status = tgt_ctxt->tc_out_of_sync_err_status;
	 tgt_ctxt->tc_nr_out_of_sync_indicated = tgt_ctxt->tc_nr_out_of_sync;
	 dbg("tcp TS %llu resy TS %llu tc_out_of_sync_err_code:%lu",
		 tgt_ctxt->tc_out_of_sync_time_stamp,
		 resync_info->rsin_out_of_sync_time_stamp, 
		 tgt_ctxt->tc_out_of_sync_err_code);
	 sync_err = tgt_ctxt->tc_out_of_sync_err_code;
	 if (sync_err > ERROR_TO_REG_MAX_ERROR) {
		 sync_err = ERROR_TO_REG_DESCRIPTION_IN_EVENT_LOG;
	 }
	 snprintf(resync_info->rsin_err_string_resync,
			 UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE,
			 ErrorToRegErrorDescriptionsA[sync_err],
			 tgt_ctxt->tc_out_of_sync_err_status);
	 resync_info->rsin_err_string_resync[UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE-1] = '\0';
 
 out:
	 return ret;
 }
 
 static inm_u32_t
 inm_calc_len_required( struct inm_list_head *ptr)
 {
	 inm_u32_t		len = 0;
	 target_context_t	*tgt_ctxt;
 
	 for (; ptr != &(driver_ctx->tgt_list); ptr = ptr->next,
				 tgt_ctxt = NULL) {
 
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 if(tgt_ctxt->tc_flags & (VCF_VOLUME_CREATING | 
							 VCF_VOLUME_DELETING)){
			 tgt_ctxt = NULL;
			 continue;
		 }
		 len += strlen(tgt_ctxt->tc_guid) + 1;
			 
	 }
	 return (len);
 }
 
 inm_s32_t process_start_notify_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
		 sizeof(PROCESS_START_NOTIFY_INPUT))) {
		 return -EFAULT;
	 }
 
	 /* Fail the ioctl, if start notify ioctl comes more than once */
	 if(driver_ctx->sentinal_idhp || driver_ctx->sentinal_pid) {
		 return -EINVAL;
	 }
 
	 driver_ctx->sentinal_pid = INM_CURPROC_PID;
	 driver_ctx->sentinal_idhp = idhp;
 
	 get_time_stamp(&(driver_ctx->dc_tel.dt_s2_start_time));
	 telemetry_clear_dbs(&driver_ctx->dc_tel.dt_blend, DBS_S2_STOPPED);
	 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t process_shutdown_notify_ioctl(inm_devhandle_t  *idhp, 
						 void __INM_USER *arg)
 {
	 unsigned long lock_flag = 0;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
		   sizeof(SHUTDOWN_NOTIFY_INPUT)))
		 return -EFAULT;
 
	 if(inm_flush_clean_shutdown(UNCLEAN_SHUTDOWN)){
		 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
		 driver_ctx->dc_flags |= SYS_UNCLEAN_SHUTDOWN;
		 driver_ctx->unclean_shutdown = 0;
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 }
	 driver_ctx->service_state = SERVICE_RUNNING;
	 driver_ctx->svagent_pid = INM_CURPROC_PID;
	 driver_ctx->svagent_idhp = idhp;
	 info("service has started = %d , process name = %s\n", INM_CURPROC_PID,
								  INM_CURPROC_COMM);
	 driver_ctx->flags |= DC_FLAGS_SERVICE_STATE_CHANGED;
	 driver_ctx->service_supports_data_filtering = TRUE;
	 INM_ATOMIC_INC(&driver_ctx->service_thread.wakeup_event_raised);
	 INM_WAKEUP_INTERRUPTIBLE(&driver_ctx->service_thread.wakeup_event);
	 INM_COMPLETE(&driver_ctx->service_thread._new_event_completion);
	 
	 get_time_stamp(&(driver_ctx->dc_tel.dt_svagent_start_time));
	 telemetry_clear_dbs(&driver_ctx->dc_tel.dt_blend, DBS_SERVICE_STOPPED);
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t process_volume_stacking_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 inm_dev_extinfo_t *dev_infop = NULL;
	 inm_s32_t err = 0;
	 inm_device_t dtype;
	 target_context_t *tgt_ctxt = NULL;
  
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("entered");
	 }
 
	 telemetry_clear_dbs(&driver_ctx->dc_tel.dt_blend, 
						 DBS_DRIVER_NOREBOOT_MODE);
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
						 sizeof(inm_dev_info_t))) {
		 err("Read access violation for inm_dev_info_t");
		 err = INM_EFAULT;
		 goto out;
	 }
 
	 dev_infop = (inm_dev_extinfo_t *)INM_KMALLOC(sizeof(inm_dev_extinfo_t), 
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!dev_infop) {
		 err("INM_KMALLOC failed to allocate memory for inm_dev_info_t");
		 err = INM_EFAULT;
		 goto out;
	 }
	 INM_MEM_ZERO(dev_infop, sizeof(inm_dev_info_t));
 
	 if(INM_COPYIN((inm_dev_info_t *)dev_infop, arg, 
						 sizeof(inm_dev_info_t))) {
		 err("INM_COPYIN failed");
		 err = INM_EFAULT;
		 goto out;
	 }
	 
	 dev_infop->d_guid[GUID_SIZE_IN_CHARS-1] = '\0';
	 dev_infop->d_pname[GUID_SIZE_IN_CHARS-1] = '\0';
	 dev_infop->d_mnt_pt[INM_PATH_MAX-1] = '\0';
 
	 switch (dev_infop->d_type) {
		 case FILTER_DEV_FABRIC_LUN:
		 case FILTER_DEV_HOST_VOLUME:
			 if (strncpy_s(dev_infop->d_src_scsi_id, 
				 INM_GUID_LEN_MAX, 
				 dev_infop->d_pname, INM_GUID_LEN_MAX)) {
				 err = INM_EFAULT;
				 goto out;
			 }
 
			 dev_infop->d_src_scsi_id[INM_MAX_SCSI_ID_SIZE-1] = '\0';
			 dev_infop->d_dst_scsi_id[INM_MAX_SCSI_ID_SIZE-1] = '\0';
			 dev_infop->src_list = NULL;
			 dev_infop->dst_list = NULL;
			 dev_infop->d_startoff = 0;
			 dev_infop->d_flags = HOST_VOLUME_STACKING_FLAG;
			 break;
		 case FILTER_DEV_MIRROR_SETUP:
			 dev_infop->d_flags = MIRROR_VOLUME_STACKING_FLAG;
			 break;
		 default:
			 err("invalid filter dev type:%d",dev_infop->d_type);
			 err = -EINVAL;
			 goto out;
	 }
	 
	 if (driver_state & DRV_LOADED_FULLY) {
		 if (is_flt_disabled(dev_infop->d_pname)) {
			 info("Filtering not enabled for %s", 
							 dev_infop->d_pname);
			 err = -EINVAL;
		 }
 
		 if (!err) {
			 dtype = filter_dev_type_get(dev_infop->d_pname);
			 if (dtype != FILTER_DEV_HOST_VOLUME &&
				 dtype != dev_infop->d_type) {
					 err("Invalid dev type %d for %s", dtype, 
								 dev_infop->d_pname);
				 err = -EINVAL;
			 }
		 }
	 }
 
	 /* 
	  * If the volume was partially stacked from initrd when it should not be, 
	  * let the volume be initialized fully before stop filtering on it
	  */
	 if (err) {
		 tgt_ctxt = get_tgt_ctxt_from_uuid(dev_infop->d_guid);
		 if (!tgt_ctxt)
			 goto out;
		 INM_BUG_ON(!(tgt_ctxt->tc_flags & VCF_VOLUME_STACKED_PARTIALLY));
	 }
 
	 err = do_volume_stacking(dev_infop);
 
	 if (tgt_ctxt) {
		 err("%s not protected", tgt_ctxt->tc_guid);
		 stop_filtering_volume(tgt_ctxt->tc_guid, idhp, 
					 DBS_FILTERING_STOPPED_BY_KERNEL);
		 put_tgt_ctxt(tgt_ctxt);
	 }
 
 out:    
	 if (err)
		 err("Stacking failed for %s (%s) - %d", dev_infop->d_guid, 
			 dev_infop->d_pname, err);
 
	 if (dev_infop)
		 INM_KFREE(dev_infop, sizeof(*dev_infop), INM_KERNEL_HEAP);
	 
	 idhp->private_data = NULL;
 
	 dbg("leaving");
 
	 return err;
 }
 
 inm_s32_t process_start_filtering_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 inm_dev_extinfo_t  *dev_infop = NULL;
	 inm_s32_t err = 0;
  
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("entered");
	 }
	
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
						 sizeof(inm_dev_info_t))) {
		 err("Read access violation for inm_dev_info_t");
		 return INM_EFAULT;
	 }
 
	 dev_infop = (inm_dev_extinfo_t *)INM_KMALLOC(sizeof(inm_dev_extinfo_t), 
				 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!dev_infop) {
		 err("INM_KMALLOC failed to allocate memory for inm_dev_info_t");
		 return INM_ENOMEM;
	 }
	 INM_MEM_ZERO(dev_infop, sizeof(inm_dev_extinfo_t));
 
	 if(INM_COPYIN((inm_dev_info_t *)dev_infop, arg, 
						 sizeof(inm_dev_info_t))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(dev_infop, sizeof(inm_dev_info_t), INM_KERNEL_HEAP);
		 return INM_EFAULT;
	 }
	 
	 dev_infop->d_guid[GUID_SIZE_IN_CHARS-1] = '\0';
	 dev_infop->d_pname[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 if (strncpy_s(dev_infop->d_src_scsi_id, INM_GUID_LEN_MAX,
				   dev_infop->d_pname, 
				   strlen(dev_infop->d_pname))) {
		 INM_KFREE(dev_infop, sizeof(inm_dev_info_t), INM_KERNEL_HEAP);
		 return INM_EFAULT;
	 }
 
	 dev_infop->d_src_scsi_id[INM_GUID_LEN_MAX-1] = '\0';
	 dev_infop->d_mnt_pt[INM_PATH_MAX-1] = '\0';
	 dev_infop->d_dst_scsi_id[0] = '\0';
	 dev_infop->src_list = NULL;
	 dev_infop->dst_list = NULL;
	 dev_infop->d_startoff = 0;
 
	 err = do_start_filtering(idhp, dev_infop);
 
	 INM_KFREE(dev_infop, sizeof(*dev_infop), INM_KERNEL_HEAP);
	 return err;
 }
 
 inm_s32_t
 process_start_mirroring_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
 {
	 mirror_conf_info_t  *mirror_infop = NULL;
	 inm_s32_t err = 0;
	 inm_irqflag_t lock_flag = 0;
  
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("entered");
	 }
	
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
					 sizeof(mirror_conf_info_t))) {
		 err("Read access violation for mirror_conf_info_t");
		 return INM_EFAULT;
	 }
 
	 mirror_infop = (mirror_conf_info_t *)INM_KMALLOC(sizeof(mirror_conf_info_t),
							 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!mirror_infop) {
		 err("INM_KMALLOC failed to allocate memory for mirror_conf_info_t");
		 return INM_ENOMEM;
	 }
	 INM_MEM_ZERO(mirror_infop, sizeof(mirror_conf_info_t));
 
	 if (INM_COPYIN(mirror_infop, arg, sizeof(mirror_conf_info_t))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(mirror_infop, sizeof(mirror_conf_info_t), 
							 INM_KERNEL_HEAP);
		 return INM_EFAULT;
	 }
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 if(driver_ctx->dc_flags & DRV_MIRROR_NOT_SUPPORT){
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
									lock_flag); 
		 err("Mirror is not supported as system didn't had any scsi device at driver loading time");
		 mirror_infop->d_status = MIRROR_NOT_SUPPORTED;
		 err = INM_ENOTSUP;
		 goto out;
	 }
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								 lock_flag); 
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("Mirror setup information:");
		 info("d_type:%d d_flags:%llu d_nblks:%llu d_bsize:%llu startoff:%llu",
			 mirror_infop->d_type, mirror_infop->d_flags, 
			 mirror_infop->d_nblks, mirror_infop->d_bsize, 
			 mirror_infop->startoff);
	 }
 
	 err = do_start_mirroring(idhp, mirror_infop);
 
 out:
	 if (INM_COPYOUT(arg, mirror_infop, sizeof(mirror_conf_info_t))) {
		 err("INM_COPYOUT failed");
		 err = INM_EFAULT;
	 }
	 INM_KFREE(mirror_infop, sizeof(*mirror_infop), INM_KERNEL_HEAP);
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("leaving err:%d",err);
	 }
	 return err;
 }
 
 inm_s32_t
 process_mirror_volume_stacking_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 mirror_conf_info_t  *mirror_infop = NULL;
	 inm_s32_t err = 0;
	 inm_dev_extinfo_t *dev_infop = NULL;
	 struct inm_list_head src_mirror_list_head, dst_mirror_list_head;
	 mirror_vol_entry_t *vol_entry = NULL;
	 inm_irqflag_t lock_flag = 0;
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("entered");
	 }
	
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
					 sizeof(mirror_conf_info_t))) {
		 err("Read access violation for mirror_conf_info_t");
		 return INM_EFAULT;
	 }
 
	 mirror_infop = (mirror_conf_info_t *)INM_KMALLOC(sizeof(mirror_conf_info_t),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!mirror_infop) {
		 err("INM_KMALLOC failed to allocate memory for mirror_conf_info_t");
		 return INM_ENOMEM;
	 }
	 INM_MEM_ZERO(mirror_infop, sizeof(mirror_conf_info_t));
 
	 if(INM_COPYIN(mirror_infop, arg, sizeof(mirror_conf_info_t))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(mirror_infop, sizeof(mirror_conf_info_t),
							 INM_KERNEL_HEAP);
		 return INM_EFAULT;
	 }
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 if(driver_ctx->dc_flags & DRV_MIRROR_NOT_SUPPORT){
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
									lock_flag); 
		 err("Mirror is not supported as system didn't had any scsi device at driver loading time");
		 mirror_infop->d_status = MIRROR_NOT_SUPPORTED;
		 err = INM_ENOTSUP;
		 goto out;
	 }
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag); 
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("Mirror setup information:");
		 info("d_type:%d d_flags:%llu d_nblks:%llu d_bsize:%llu",
			 mirror_infop->d_type, mirror_infop->d_flags, 
			 mirror_infop->d_nblks, mirror_infop->d_bsize);
	 }
	 INM_INIT_LIST_HEAD(&src_mirror_list_head);
	 INM_INIT_LIST_HEAD(&dst_mirror_list_head);
	 err = populate_volume_lists(&src_mirror_list_head,
					 &dst_mirror_list_head,
					 mirror_infop);
	 if (err) {
		 goto out;
	 }
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("source volume:%u scsi_id:%s: list: ",
			 mirror_infop->nsources, mirror_infop->src_scsi_id);
		 print_mirror_list(&src_mirror_list_head);
		 info("destination volume:%u scsi_id:%s: list: ",
			 mirror_infop->ndestinations, mirror_infop->dst_scsi_id);
		 print_mirror_list(&dst_mirror_list_head);
	 }
 
	 if (mirror_infop->src_scsi_id[0] == ' ' || 
				 mirror_infop->src_scsi_id[0] == '\0') {
		 err("Empty source scsi id:%s:",mirror_infop->src_scsi_id);
		 err = EINVAL;
		 mirror_infop->d_status = SRC_DEV_SCSI_ID_ERR;
		 free_mirror_list(&src_mirror_list_head, 0);
		 free_mirror_list(&dst_mirror_list_head, 1);
		 goto out;
	 }
	 if (mirror_infop->dst_scsi_id[0] == ' ' || 
				 mirror_infop->dst_scsi_id[0] == '\0') {
		 err("Empty destination scsi id:%s:",mirror_infop->src_scsi_id);
		 err = EINVAL;
		 mirror_infop->d_status = DST_DEV_SCSI_ID_ERR;
		 free_mirror_list(&src_mirror_list_head, 0);
		 free_mirror_list(&dst_mirror_list_head, 1);
		 goto out;
	 }
 
	 /* This is mirroring code and change to is_flt_disabled() should not affect */
	 if (is_flt_disabled(mirror_infop->src_scsi_id)) {
		 dbg("stop mirroring already issued on device with scsi id %s\n",
			 mirror_infop->src_scsi_id);
		 return -EINVAL;
	 }
	 vol_entry = inm_list_entry(src_mirror_list_head.next, 
						 mirror_vol_entry_t, next);
	 INM_BUG_ON(!vol_entry);
	 dev_infop = (inm_dev_extinfo_t *)INM_KMALLOC(sizeof(inm_dev_extinfo_t), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!dev_infop) {
		 err("INM_KMALLOC failed to allocate memory for inm_dev_info_t");
		 err = INM_ENOMEM;
		 mirror_infop->d_status = DRV_MEM_ALLOC_ERR;
		 free_mirror_list(&src_mirror_list_head, 0);
		 free_mirror_list(&dst_mirror_list_head, 1);
		 goto out;
	 }
	 INM_MEM_ZERO(dev_infop, sizeof(inm_dev_extinfo_t));
 
	 dev_infop->d_type = mirror_infop->d_type;
	 dev_infop->d_startoff = 0;
	 if (strncpy_s(dev_infop->d_guid, INM_GUID_LEN_MAX, 
						 vol_entry->tc_mirror_guid,
	 strlen(vol_entry->tc_mirror_guid)) ||
	 strncpy_s(dev_infop->d_src_scsi_id, INM_MAX_SCSI_ID_SIZE, 
		 mirror_infop->src_scsi_id,
		 INM_MAX_SCSI_ID_SIZE - 1) ||
	 strncpy_s(dev_infop->d_dst_scsi_id, INM_MAX_SCSI_ID_SIZE, 
		 mirror_infop->dst_scsi_id, INM_MAX_SCSI_ID_SIZE - 1)) {
 
		 free_mirror_list(&src_mirror_list_head, 0);
		 free_mirror_list(&dst_mirror_list_head, 1);
		 err = INM_EFAULT;
		 goto out;
	 }
 
	 dev_infop->d_guid[INM_GUID_LEN_MAX-1] = '\0';
	 dev_infop->d_src_scsi_id[strlen(mirror_infop->src_scsi_id)] = '\0';
	 dev_infop->d_dst_scsi_id[strlen(mirror_infop->dst_scsi_id)] = '\0';
	 dev_infop->d_flags = mirror_infop->d_flags;
	 dev_infop->d_flags |= MIRROR_VOLUME_STACKING_FLAG;
	 dev_infop->d_nblks = mirror_infop->d_nblks;
	 dev_infop->d_bsize = mirror_infop->d_bsize;
	 dev_infop->src_list = &src_mirror_list_head;
	 dev_infop->dst_list = &dst_mirror_list_head;
	 dev_infop->d_startoff = mirror_infop->startoff;
	 
	 if (mirror_infop->d_type == FILTER_DEV_MIRROR_SETUP) {
		 err = do_volume_stacking(dev_infop);
		 mirror_infop->d_status = MIRROR_STACKING_ERR;
	 }
 
	 
 out:
	 if (INM_COPYOUT(arg, mirror_infop, sizeof(mirror_conf_info_t))) {
		 err("INM_COPYOUT failed");
		 err = INM_EFAULT;
	 }
	 
	 if (mirror_infop) {
		 INM_KFREE(mirror_infop, sizeof(*mirror_infop), 
						 INM_KERNEL_HEAP);
	 }
	 if (dev_infop) {
		 INM_KFREE(dev_infop, sizeof(*dev_infop), INM_KERNEL_HEAP);
	 }
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		 info("leaving err:%d",err);
	 }
	 return err;
 }
 void
 process_stop_filtering_common(target_context_t *tgt_ctxt, 
					 inm_devhandle_t *idhp)
 {
	 dbg("entered");
	 get_tgt_ctxt(tgt_ctxt);
 
	 switch (tgt_ctxt->tc_dev_type) {
		 case FILTER_DEV_HOST_VOLUME:
		 case FILTER_DEV_FABRIC_LUN:
			 if (tgt_ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
				 inm_scst_unregister(tgt_ctxt);
			 }
			 break;
 
		 case FILTER_DEV_MIRROR_SETUP:
			 break;
		 default: err("Invalid dev type:%d",tgt_ctxt->tc_dev_type);
	 }
 
	 tgt_ctx_force_soft_remove(tgt_ctxt);
 
	 inm_unlink(tgt_ctxt->tc_bp->bitmap_file_name, 
				tgt_ctxt->tc_bp->bitmap_dir_name);
	 put_tgt_ctxt(tgt_ctxt);
 
	 if (idhp && idhp->private_data) {
		 /* One extra dereference as we did extra reference in
		  * start filtering
		  */
		 put_tgt_ctxt(tgt_ctxt);
	 }
 
	 dbg("leaving");
 }
 
 inm_s32_t
 stop_filtering_volume(char *uuid, inm_devhandle_t *idhp, int dbs_flag)
 {
	 target_context_t *tgt_ctxt = NULL;
	 dev_t dev = 0;
 #ifdef INM_AIX
	 int flag;
 #endif
 
	 convert_path_to_dev(uuid, &dev);
	 INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	 tgt_ctxt = get_tgt_ctxt_from_uuid_locked(uuid, &dev);
	 if(!tgt_ctxt) {
		 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
		 dbg("Failed to get target context from uuid");
		 return -ENODEV;
	 }
 
 #ifdef INM_AIX
	 INM_SPIN_LOCK(&driver_ctx->tgt_list_lock, flag);
 #endif
	 volume_lock(tgt_ctxt);
	 tgt_ctxt->tc_flags |= VCF_VOLUME_DELETING;
	 tgt_ctxt->tc_filtering_disable_required = 1;
	 get_time_stamp(&(tgt_ctxt->tc_tel.tt_user_stop_flt_time));
	 telemetry_set_dbs(&tgt_ctxt->tc_tel.tt_blend, dbs_flag);
	 close_disk_cx_session(tgt_ctxt, CX_CLOSE_STOP_FILTERING_ISSUED);
	 set_tag_drain_notify_status(tgt_ctxt, TAG_STATUS_DROPPED,
					 DEVICE_STATUS_FILTERING_STOPPED);
	 volume_unlock(tgt_ctxt);
 #ifdef INM_AIX
	 INM_SPIN_UNLOCK(&driver_ctx->tgt_list_lock, flag);
 #endif
	 if (driver_ctx->dc_root_disk == tgt_ctxt)
		 driver_ctx->dc_root_disk = NULL;
 
	 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
 
	 inm_erase_resync_info_from_persistent_store(tgt_ctxt->tc_pname);
	 process_stop_filtering_common(tgt_ctxt, idhp);
 
	 return 0;
 }
 
 inm_s32_t process_stop_filtering_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 inm_s32_t error = 0;
	 VOLUME_GUID *guid = NULL;
 
	 dbg("entered");
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
							 sizeof(VOLUME_GUID))) {
		 err("Read access violation for VOLUME_GUID");
		 return -EFAULT;
	 }
 
	 guid = (VOLUME_GUID *)INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!guid) {
		 err("INM_KMALLOC failed to allocate memory for VOLUME_GUID");
		 return -ENOMEM;
	 }
 
	 if(INM_COPYIN(guid, arg, sizeof(VOLUME_GUID))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 guid->volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 error = stop_filtering_volume((char *)&guid->volume_guid[0], idhp, 
					   DBS_FILTERING_STOPPED_BY_USER);
 
	 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
	 idhp->private_data = NULL;
 
	 dbg("leaving");
 
	 return error;
 }
 
 inm_s32_t remove_filter_device(char *uuid)
 {
	 target_context_t *tgt_ctxt = NULL;
 
 #if (defined(RHEL9) && !defined(OL9UEK7)) || LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
	 info("Removing filter device : %s", uuid);
	 INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	 tgt_ctxt = get_tgt_ctxt_from_device_name_locked(uuid);
	 if(!tgt_ctxt) {
		 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
		 err("Failed to get target context from device name : %s", uuid);
		 return -ENODEV;
	 }
 
	 volume_lock(tgt_ctxt);
	 tgt_ctxt->tc_flags |= VCF_VOLUME_DELETING;
	 tgt_ctxt->tc_filtering_disable_required = 0;
	 close_disk_cx_session(tgt_ctxt, CX_CLOSE_DISK_REMOVAL);
	 set_tag_drain_notify_status(tgt_ctxt, TAG_STATUS_DROPPED, 
						 DEVICE_STATUS_REMOVED);
	 volume_unlock(tgt_ctxt);
	 if (driver_ctx->dc_root_disk == tgt_ctxt)
		 driver_ctx->dc_root_disk = NULL;
 
	 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
 
	 if (tgt_ctxt->tc_bp->volume_bitmap) {
		 wait_for_all_writes_to_complete(tgt_ctxt->tc_bp->volume_bitmap);
		 flush_and_close_bitmap_file(tgt_ctxt);
	 }
 
	 tgt_ctx_force_soft_remove(tgt_ctxt);
	 put_tgt_ctxt(tgt_ctxt);
 
 #else
	 info("Remove filter device is no-op.");
 #endif
 
	 return 0;
 }
 
 inm_s32_t process_remove_filter_device_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 inm_s32_t error = 0;
	 VOLUME_GUID *guid = NULL;
 
	 dbg("entered");
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
							 sizeof(VOLUME_GUID))) {
		 err("Read access violation for VOLUME_GUID");
		 return -EFAULT;
	 }
 
	 guid = (VOLUME_GUID *)INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!guid) {
		 err("INM_KMALLOC failed to allocate memory for VOLUME_GUID");
		 return -ENOMEM;
	 }
 
	 if(INM_COPYIN(guid, arg, sizeof(VOLUME_GUID))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 guid->volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 error = remove_filter_device((char *)&guid->volume_guid[0]);
 
	 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
 
	 dbg("leaving");
 
	 return error;
 }
 
 inm_s32_t process_stop_mirroring_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *tgt_ctxt = NULL;
	 SCSI_ID *scsi_id = NULL;
	 inm_irqflag_t lock_flag = 0;
 
	 dbg("entered");
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 if(driver_ctx->dc_flags & DRV_MIRROR_NOT_SUPPORT){
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);
		 err("Mirror is not supported as system didn't had any scsi device at driver loading time");
		 return INM_ENOTSUP;
	 }
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								 lock_flag);
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
							 sizeof(SCSI_ID))) {
		 err("Read access violation for SCSI_ID");
		 return -EFAULT;
	 }
 
	 scsi_id = (SCSI_ID *)INM_KMALLOC(sizeof(SCSI_ID), INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!scsi_id) {
		 err("INM_KMALLOC failed to allocate memory for SCSI_ID");
		 return -ENOMEM;
	 }
 
	 if (INM_COPYIN(scsi_id, arg, sizeof(SCSI_ID))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(scsi_id, sizeof(SCSI_ID), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 scsi_id->scsi_id[INM_MAX_SCSI_ID_SIZE-1] = '\0';
 
	 INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	 tgt_ctxt = get_tgt_ctxt_from_scsiid_locked((char *)&scsi_id->scsi_id[0]);
	 if (!tgt_ctxt) {
		 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
		 dbg("Failed to get target context from scsi id:%s",scsi_id->scsi_id);
		 INM_KFREE(scsi_id, sizeof(SCSI_ID), INM_KERNEL_HEAP);
		 return 0;
	 }
	 volume_lock(tgt_ctxt);
	 tgt_ctxt->tc_flags |= VCF_VOLUME_DELETING;
	 tgt_ctxt->tc_filtering_disable_required = 1;
	 volume_unlock(tgt_ctxt);
 
	 if (driver_ctx->dc_root_disk == tgt_ctxt)
		 driver_ctx->dc_root_disk = NULL;
 
	 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
 
	 inm_erase_resync_info_from_persistent_store(tgt_ctxt->tc_pname);
	 process_stop_filtering_common(tgt_ctxt, idhp);
 
	 INM_KFREE(scsi_id, sizeof(SCSI_ID), INM_KERNEL_HEAP);
	 idhp->private_data = NULL;
 
	 dbg("leaving");
 
	 return 0;
 }
 
 inm_s32_t process_volume_unstacking_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *tgt_ctxt = NULL;
	 VOLUME_GUID *guid = NULL;
	 dev_t dev = 0;
 #ifdef INM_AIX
	 int flag;
 #endif
 
	 dbg("entered");
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
							 sizeof(VOLUME_GUID))) {
		 err("Read access violation for VOLUME_GUID");
		 return -EFAULT;
	 }
 
	 guid = (VOLUME_GUID *)INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!guid) {
		 err("INM_KMALLOC failed to allocate memory for VOLUME_GUID");
		 return -ENOMEM;
	 }
 
	 if(INM_COPYIN(guid, arg, sizeof(VOLUME_GUID))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 guid->volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 convert_path_to_dev((char *)&guid->volume_guid[0], &dev);
	 INM_DOWN_WRITE(&driver_ctx->tgt_list_sem);
	 tgt_ctxt = get_tgt_ctxt_from_uuid_locked(
		 (char *)&guid->volume_guid[0], &dev);
	 if(!tgt_ctxt) {
		 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
		 return -EINVAL;
	 }
 
 #ifdef INM_AIX
	 INM_SPIN_LOCK(&driver_ctx->tgt_list_lock, flag);
 #endif
	 volume_lock(tgt_ctxt);
	 tgt_ctxt->tc_flags |= VCF_VOLUME_DELETING;
	 tgt_ctxt->tc_filtering_disable_required = 1;
	 get_time_stamp(&(tgt_ctxt->tc_tel.tt_user_stop_flt_time));
	 telemetry_set_dbs(&tgt_ctxt->tc_tel.tt_blend, 
					   DBS_FILTERING_STOPPED_BY_USER);
 
	 close_disk_cx_session(tgt_ctxt, CX_CLOSE_STOP_FILTERING_ISSUED);
	 volume_unlock(tgt_ctxt);
 #ifdef INM_AIX
	 INM_SPIN_UNLOCK(&driver_ctx->tgt_list_lock, flag);
 #endif
 
	 if (driver_ctx->dc_root_disk == tgt_ctxt)
		 driver_ctx->dc_root_disk = NULL;
 
	 INM_UP_WRITE(&driver_ctx->tgt_list_sem);
 
	 inm_erase_resync_info_from_persistent_store(tgt_ctxt->tc_pname);
 
	 if (tgt_ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
		 inm_scst_unregister(tgt_ctxt);
	 }
 
	 get_tgt_ctxt(tgt_ctxt);
 
	 tgt_ctx_force_soft_remove(tgt_ctxt);
	 inm_unlink(tgt_ctxt->tc_bp->bitmap_file_name, 
				tgt_ctxt->tc_bp->bitmap_dir_name);
	 put_tgt_ctxt(tgt_ctxt);
 
	 if (idhp->private_data) 
		 put_tgt_ctxt(tgt_ctxt);
	 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
	 idhp->private_data = NULL;
  
	 dbg("leaving");
  
	 return 0;
 }
 
 inm_s32_t process_get_db_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
 {
	 target_context_t *ctxt = (target_context_t *)idhp->private_data;
	 UDIRTY_BLOCK_V2 *user_db = NULL; 
	 inm_s32_t status = 0;                 
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!ctxt) {
		 err("Get_Db_trans ioctl called as file private is NULL");
		 return -EINVAL;    
	 }
 
	 if(is_target_filtering_disabled(ctxt)) {
		 dbg("Get_Db_trans ioctl is failed as filtering is not enabled");
		 return INM_EBUSY;
	 }
 
	 if(ctxt->tc_flags & VCF_DRAIN_BLOCKED) {
		 return -EFAULT;
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
						 sizeof(UDIRTY_BLOCK_V2)))
		 return -EFAULT;
 
	 user_db = ctxt->tc_db_v2;
	 INM_BUG_ON(!user_db);
	 if(!user_db) {
		 err("Failed to allocate memory for Udirty Block");
		 return -ENOMEM;
	 }
 
	 if(INM_COPYIN(user_db, arg, sizeof(UDIRTY_BLOCK_V2))) {
		 err("Copy from user failed in get_db");
		 return -EFAULT;
	 }
 
	 get_tgt_ctxt(ctxt);
 
	 volume_lock(ctxt);
	 get_time_stamp(&ctxt->tc_tel.tt_getdb_time);
	 update_cx_with_s2_latency(ctxt);
 
	 if (ctxt->tc_tel.tt_ds_throttle_stop == 
					 TELEMETRY_THROTTLE_IN_PROGRESS) {
		 get_time_stamp(&ctxt->tc_tel.tt_ds_throttle_stop);
		 telemetry_clear_dbs(&ctxt->tc_tel.tt_blend, 
						 DBS_DIFF_SYNC_THROTTLE);
	 }
	 volume_unlock(ctxt);
 
	 status = fill_udirty_block(ctxt, user_db, idhp);
 
	 put_tgt_ctxt(ctxt);
 
	 if(INM_COPYOUT(arg, user_db, sizeof(UDIRTY_BLOCK_V2))) {
		 err("copy to user failed in get_db");
		 return -EFAULT;
	 }
 
 #ifdef INM_QUEUE_RQ_ENABLED
	 inm_alloc_pools();
 #else
	 balance_page_pool(INM_KM_SLEEP, 0);
 #endif
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return status;
 }
 
 inm_s32_t process_commit_db_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
 {
	 inm_s32_t err = 0;
	 target_context_t *ctxt = (target_context_t *)idhp->private_data;
	 COMMIT_TRANSACTION *commit_db;
 
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!ctxt) {
		 err("Commit DB failed as file private is NULL");
		 return -EINVAL;
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
						 sizeof(COMMIT_TRANSACTION)))
		 return -EFAULT;
 
	 commit_db = (COMMIT_TRANSACTION*)INM_KMALLOC(sizeof(COMMIT_TRANSACTION),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!commit_db) {
		 err("Failed to allocate memory for Commit DB");
		 return -ENOMEM;
	 }
 
	 if(INM_COPYIN(commit_db, arg, sizeof(COMMIT_TRANSACTION))) {
		 err("copy from user failed in commit db ioctl");
		 INM_KFREE(commit_db, sizeof(COMMIT_TRANSACTION), 
							 INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 get_tgt_ctxt(ctxt);
 
	 err = perform_commit(ctxt, commit_db, idhp);
 
	 put_tgt_ctxt(ctxt);
 
	 INM_KFREE(commit_db, sizeof(COMMIT_TRANSACTION), INM_KERNEL_HEAP);
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return err;
 }
 
 inm_s32_t process_get_time_ioctl(void __INM_USER *arg)
 {
	 inm_u64_t ts = 0;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_WRITE, (void __INM_USER *)arg, 
						 sizeof(long long))) {
		 err("write access verification failed");
		 return -EFAULT;
	 }
 
	 get_time_stamp(&ts);
 
	 if(INM_COPYOUT(arg, &ts, sizeof(long long))) {
		 err("copy to user failed");
		 return -EFAULT;
	 }
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t process_clear_diffs_ioctl(inm_devhandle_t *idhp, 
							 void __INM_USER *arg)
 {
	 char *uuid = NULL;
	 target_context_t *tgt_ctxt = NULL;
 
	 dbg("clear diffs issued");
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
							 sizeof(VOLUME_GUID)))
		 return -EFAULT; 
 
	 uuid = (char *)INM_KMALLOC(GUID_SIZE_IN_CHARS, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!uuid)
		 return -ENOMEM;
 
	 if(INM_COPYIN(uuid, arg, GUID_SIZE_IN_CHARS)) {
		 INM_KFREE(uuid, GUID_SIZE_IN_CHARS, INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 tgt_ctxt = get_tgt_ctxt_from_uuid_nowait(uuid);
	 if(!tgt_ctxt) {
		 /* It is possible that cleardiffs may come before
		  * completing the stacking, in this case return
		  * the status is considered as success.
		  */
		 INM_KFREE(uuid, GUID_SIZE_IN_CHARS, INM_KERNEL_HEAP);
		 return 0;
	 }
 
	 do_clear_diffs(tgt_ctxt);
 
	 put_tgt_ctxt(tgt_ctxt);
 
	 INM_KFREE(uuid, GUID_SIZE_IN_CHARS, INM_KERNEL_HEAP);
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t process_set_volume_flags_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *ctxt;
	 VOLUME_FLAGS_INPUT *flagip;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
		   sizeof(VOLUME_FLAGS_OUTPUT)))
		 return -EFAULT;
 
	 flagip = (VOLUME_FLAGS_INPUT *)INM_KMALLOC(sizeof(VOLUME_FLAGS_INPUT),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!flagip)
		 return -ENOMEM;
	 
	 if(INM_COPYIN(flagip, arg, sizeof(VOLUME_FLAGS_INPUT))) {
		 INM_KFREE(flagip, sizeof(VOLUME_FLAGS_INPUT), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)flagip->VolumeGUID);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(flagip, sizeof(VOLUME_FLAGS_INPUT), INM_KERNEL_HEAP);
		 return -EINVAL;
	 }
 
	 volume_lock(ctxt);
 
	 if(flagip->eOperation == ecBitOpSet) {
		 if(flagip->ulVolumeFlags & VCF_READ_ONLY)
			 ctxt->tc_flags |= VCF_READ_ONLY;
	 } else {
		 if(flagip->ulVolumeFlags & VCF_READ_ONLY) {
			 if(ctxt->tc_flags & VCF_READ_ONLY)
				 ctxt->tc_flags &= ~VCF_READ_ONLY;
			 else
				 ctxt->tc_flags |= VCF_READ_ONLY;
		 }
	 }
 
	 volume_unlock(ctxt);
 
	 put_tgt_ctxt(ctxt);
 
	 INM_KFREE(flagip, sizeof(VOLUME_FLAGS_INPUT), INM_KERNEL_HEAP);
  
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t process_get_volume_flags_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *ctxt;
	 VOLUME_FLAGS_INPUT *flagip;
	 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_WRITE, (void __INM_USER *)arg,
		   sizeof(VOLUME_FLAGS_OUTPUT)))
		 return -EFAULT;
 
	 flagip = (VOLUME_FLAGS_INPUT *)INM_KMALLOC(sizeof(VOLUME_FLAGS_INPUT),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!flagip)
		 return -ENOMEM;
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)flagip->VolumeGUID);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(flagip, sizeof(VOLUME_FLAGS_INPUT), INM_KERNEL_HEAP);
		 return -EINVAL;
	 }
 
	 volume_lock(ctxt);
 
	 flagip->ulVolumeFlags = ctxt->tc_flags;
 
	 volume_unlock(ctxt);
 
	 if(INM_COPYOUT(arg, flagip, sizeof(VOLUME_FLAGS_INPUT))) {
		 INM_KFREE(flagip, sizeof(VOLUME_FLAGS_INPUT), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 put_tgt_ctxt(ctxt);
 
	 INM_KFREE(flagip, sizeof(VOLUME_FLAGS_INPUT), INM_KERNEL_HEAP);
	 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 
 inm_s32_t 
 wait_for_db(target_context_t *ctxt, inm_s32_t timeout)
 {
	 inm_s64_t timeout_err = 0;
	 inm_s32_t need_to_wait = 1;
 
	 volume_lock(ctxt);
	 
	 if(!should_wait_for_db(ctxt))
		 need_to_wait = 0;
	 else 
		 GET_TIME_STAMP_IN_USEC(ctxt->tc_dbwait_event_ts_in_usec);
	 
	 volume_unlock(ctxt);
	 
	 if(need_to_wait) {
		 inm_wait_event_interruptible_timeout(ctxt->tc_waitq, 
			  should_wakeup_s2(ctxt), (timeout * INM_HZ));
 
		 volume_lock(ctxt);
		 if (!ctxt->tc_pending_changes) {
			 timeout_err = (inm_s32_t)INM_ETIMEDOUT;
			 ctxt->tc_dbwait_event_ts_in_usec = 0;
		 }
		 volume_unlock(ctxt);
	 }
 
	 return (inm_s32_t)timeout_err;
 }
 
 inm_s32_t process_wait_for_db_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *ctxt;
	 WAIT_FOR_DB_NOTIFY *notify;
	 inm_s32_t timeout_err = 0;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
		   sizeof(WAIT_FOR_DB_NOTIFY)))
		 return -EFAULT;
 
	 notify = (WAIT_FOR_DB_NOTIFY *)INM_KMALLOC(sizeof(WAIT_FOR_DB_NOTIFY),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!notify)
		 return -ENOMEM;
 
	 if(INM_COPYIN(notify, arg, sizeof(WAIT_FOR_DB_NOTIFY))) {
		 INM_KFREE(notify, sizeof(WAIT_FOR_DB_NOTIFY), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 notify->VolumeGUID[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 dbg("wait db on volume = %s", &notify->VolumeGUID[0]);
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&notify->VolumeGUID[0]);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(notify, sizeof(WAIT_FOR_DB_NOTIFY), INM_KERNEL_HEAP);
		 INM_DELAY(60*INM_HZ);
		 return -EINVAL;
	 }
 
	 timeout_err = wait_for_db(ctxt, notify->Seconds);
 
	 get_time_stamp(&(ctxt->tc_s2_latency_base_ts));    
	 INM_KFREE(notify, sizeof(WAIT_FOR_DB_NOTIFY), INM_KERNEL_HEAP);
	 put_tgt_ctxt(ctxt);
 
	 return timeout_err;
 }
 
 inm_s32_t process_wait_for_db_v2_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *ctxt = NULL;
	 WAIT_FOR_DB_NOTIFY *notify = NULL;
	 inm_s32_t error = 0;
 
	 if (!INM_ACCESS_OK(VERIFY_READ, arg, sizeof(WAIT_FOR_DB_NOTIFY))) {
		 error = -EFAULT;
		 goto err;
	 }
	 
	 notify = INM_KMALLOC(sizeof(WAIT_FOR_DB_NOTIFY), INM_KM_SLEEP, 
						  INM_KERNEL_HEAP);
	 if (!notify) {
		 error = -ENOMEM;
		 goto err;
	 }
		 
	 if (INM_COPYIN(notify, arg, sizeof(WAIT_FOR_DB_NOTIFY))) {
		 error = -EFAULT;
		 goto err;
	 }
 
	 notify->VolumeGUID[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 ctxt = (target_context_t *)idhp->private_data;
	 if(!ctxt) {
		 err("Wait_DB_V2 ioctl called without file private");
		 error = -EINVAL;    
		 goto err;
	 }
	 
	 get_tgt_ctxt(ctxt);
 
	 if(is_target_filtering_disabled(ctxt)) {
		 err("Wait_DB_V2 ioctl filtering disabled");
		 error = INM_EBUSY;
		 goto err;
	 }
		 
	 if (strcmp(ctxt->tc_guid, notify->VolumeGUID)) {
		 err("Wait_DB_V2 ioctl called without file private");
		 error = -EINVAL;    
		 goto err;
	 }
 
	 dbg("wait db on volume = %s", ctxt->tc_guid);
 
	 error = wait_for_db(ctxt, notify->Seconds);
 
	 get_time_stamp(&(ctxt->tc_s2_latency_base_ts));
 out:
	 if (ctxt)
		 put_tgt_ctxt(ctxt);
 
	 if (notify)
		 INM_KFREE(notify, sizeof(WAIT_FOR_DB_NOTIFY), INM_KERNEL_HEAP);
 
	 return error;
 
 err:
	 INM_DELAY(60*INM_HZ);
	 goto out;
 }
 
 static
 inm_s32_t shutdown_volume(target_context_t *vcptr, inm_s32_t freeze_root)
 {
	 struct inm_list_head head;
 
	 dbg("Shutting down %s", vcptr->tc_guid);
 
	 set_unsignedlonglong_vol_attr(vcptr, VolumePrevEndTimeStamp, 
					 vcptr->tc_PrevEndTimeStamp);
	 set_unsignedlonglong_vol_attr(vcptr, VolumePrevEndSequenceNumber, 
					 vcptr->tc_PrevEndSequenceNumber);
	 set_unsignedlonglong_vol_attr(vcptr, VolumePrevSequenceIDforSplitIO, 
					 vcptr->tc_PrevSequenceIDforSplitIO);
	 set_unsignedlonglong_vol_attr(vcptr, VolumeRpoTimeStamp, 
					 vcptr->tc_rpo_timestamp);
 
	 fs_freeze_volume(vcptr, &head);
	 thaw_volume(vcptr, &head);
	 wait_for_all_writes_to_complete(vcptr->tc_bp->volume_bitmap);
 
	 if (freeze_root) {
		 /*
		  * freeze_root flag is only set when shutting down root volume/disk
		  * in the end. Flush all the cached data which may be caused by all
		  * the bitmap writes for other volumnes and private file writes by 
		  * freezing the root
		  */ 
		 freeze_root_dev();
		 /*
		  * Write all pending dirty blocks to bitmap and wait for bitmap 
		  * updation to complete
		  */
		 inmage_flt_save_all_changes(vcptr, TRUE, INM_NO_OP);
		 /*
		  * Flush all telemetry logs generated by tags dropped while
		  * converting pending writes to bitmap int the step above
		  */
		 telemetry_shutdown();
		 /*
		  * The bitmap and telemetry writes may have caused additional writes.
		  * Freeze the root again to flush any of those pending changes.
		  */
		 freeze_root_dev();
		 /*
		  * Write all pending dirty blocks to bitmap and wait for bitmap 
		  * updation to complete
		  */
		 inmage_flt_save_all_changes(vcptr, TRUE, INM_NO_OP);
		 /*
		  * The bitmap writes may have caused additional 
		  * writes to metadata. Freeze the root again to flush any of 
		  * those pending changes.
		  */
		 freeze_root_dev();
	 }
 
	 volume_lock(vcptr);
	 vcptr->tc_flags |= VCF_VOLUME_FROZEN_SYS_SHUTDOWN;
	 volume_unlock(vcptr);
	 /* Write all pending dirty blocks to bitmap and close it */
	 inmage_flt_save_all_changes(vcptr, TRUE, INM_NO_OP);
	 lcw_move_bitmap_to_raw_mode(vcptr);
 
	 return 0;
 }
 
 inm_s32_t process_sys_shutdown_notify_ioctl(inm_devhandle_t *idhp, 
							 void __INM_USER *arg)
 {
	 struct inm_list_head *ptr = NULL, *nextptr = NULL;
	 target_context_t *vcptr = NULL;
	 unsigned long lock_flag = 0;
	 inm_s32_t error = 0;
	 target_context_t *root = NULL;
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		 info("entered\n");
	 }
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
			sizeof(SYS_SHUTDOWN_NOTIFY_INPUT)))
		 return -EFAULT;
 
	 err("system_shutdown is informed to inm driver");
 #ifdef INM_QUEUE_RQ_ENABLED
	 move_chg_nodes_to_drainable_queue();
 #endif
 
	 driver_ctx->sys_shutdown = DC_FLAGS_SYSTEM_SHUTDOWN;
	 INM_ATOMIC_INC(&driver_ctx->service_thread.wakeup_event_raised);
	 INM_WAKEUP_INTERRUPTIBLE(&driver_ctx->service_thread.wakeup_event);
	 INM_COMPLETE(&driver_ctx->service_thread._new_event_completion);
	 INM_WAIT_FOR_COMPLETION_INTERRUPTIBLE(&driver_ctx->shutdown_completion);
 
 retry:
	 INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	 inm_list_for_each_safe(ptr, nextptr, &driver_ctx->tgt_list) {
		 vcptr = inm_list_entry(ptr, target_context_t, tc_list);
		 if(vcptr->tc_flags & (VCF_VOLUME_CREATING | 
				 VCF_VOLUME_DELETING | 
				 VCF_VOLUME_FROZEN_SYS_SHUTDOWN)){
			 vcptr = NULL;
			 continue;
		 }
 
		 /* keep the root device for the end */
		 if (isrootdev(vcptr)) {
			 root = vcptr;
			 vcptr = NULL;
			 continue;
		 }
 
		 INM_BUG_ON_TMP(vcptr);
 
		 if (vcptr->tc_bp->volume_bitmap) {
			 get_tgt_ctxt(vcptr);
			 INM_UP_READ(&driver_ctx->tgt_list_sem);
			 shutdown_volume(vcptr, FALSE);
			 put_tgt_ctxt(vcptr);
			 goto retry;
		 }
	 }
	 INM_UP_READ(&driver_ctx->tgt_list_sem);
 
	 inm_flush_ts_and_seqno_to_file(TRUE);
	 inm_close_ts_and_seqno_file();
   
	 /*
	 * If root device is not found, mark it for resync
	 */ 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 driver_ctx->dc_flags |= SYS_CLEAN_SHUTDOWN;
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								 lock_flag);
	 if (!inm_flush_clean_shutdown(CLEAN_SHUTDOWN))
		 error=-EIO;
 
 #ifdef INM_AIX
	 inm_flush_log_file();
 #endif
 
	 if (root)
		 shutdown_volume(root, TRUE);
 
	 inm_register_reboot_notifier(TRUE);
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		 info("leaving");
	 }
	 return error;
 }
 
 inm_s32_t process_sys_pre_shutdown_notify_ioctl(inm_devhandle_t *idhp, 
							 void __INM_USER *arg)
 {
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		 info("entered\n");
	 }
 
	 err("System PreShutdown");
 
	 /*
	  * Since we cant hold dc_cp_mutex as timeout function
	  * itself can require it, we keep force timing out any 
	  * active CP until we reach a no active CP state
	  */
	 do {
		 dbg("Killing CP timers");
		 INM_DOWN(&driver_ctx->dc_cp_mutex);
		 if (driver_ctx->dc_cp != INM_CP_NONE &&
			 driver_ctx->dc_cp != INM_CP_SHUTDOWN ) {
			 force_timeout(&cp_timer);
			 INM_UP(&driver_ctx->dc_cp_mutex);
			 inm_ksleep(INM_HZ);
		 } else {
			 break;
		 }
	 } while(1);
 
	 /* Prevent further CP */
	 driver_ctx->dc_cp = INM_CP_SHUTDOWN;
	 INM_UP(&driver_ctx->dc_cp_mutex);
 
	 if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		 info("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t 
 process_lcw_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
 {
	 inm_s32_t error = 0;
	 lcw_op_t *op = NULL;
 
	 if (!INM_ACCESS_OK(VERIFY_READ, arg, sizeof(lcw_op_t))) {
		 error = -EFAULT;
		 goto out;
	 }
 
	 op = (lcw_op_t *)INM_KMALLOC(sizeof(lcw_op_t), INM_KM_SLEEP, 
							  INM_KERNEL_HEAP);
	 if(!op){
		 err("op allocation failed");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(op, arg, sizeof(lcw_op_t))) {
		 err("copyin failed");
		 error = -EFAULT;
		 goto out;
	 }
 
	 op->lo_name.volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 if (op->lo_op == LCW_OP_MAP_FILE)
		 error = lcw_map_file_blocks(op->lo_name.volume_guid);
	 else
		 error = lcw_perform_bitmap_op(op->lo_name.volume_guid, 
								 op->lo_op);
 
 out:
	 if (op)
		 INM_KFREE(op, sizeof(lcw_op_t), INM_KERNEL_HEAP);
 
	 return error;
 }
 
 /* Format:
  *     <Flags(uint)>,<NumVolumes<ushort>),
  *     <Vol1Len(ushort)>,<Vol1Name(char array)>,
  *     <Vol2Len(ushort)>,<Vol2Name(char array)>, ........
  *     <VolnLen(ushort)>, <VolnName(char array)>,
  *     <NumTags(ushort)>, 
  *     <Tag1Len(ushort)>, <Tag1Name(char array)>,
  *     <TagnLen(ushort)>, <TagnName(char array)>
  */
 inm_s32_t process_tag_ioctl(inm_devhandle_t *idhp, void __INM_USER *user_buf, 
							 inm_s32_t sync_tag)
 {
	 inm_s32_t flags = 0;	
	 inm_u16_t num_vols = 0, i;
	 inm_s32_t error = 0;
	 tag_guid_t *tag_guid = NULL;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("entered");
	 }
 
	 if(sync_tag){
		 tag_guid = (tag_guid_t *)INM_KMALLOC(sizeof(tag_guid_t), INM_KM_SLEEP, 
								 INM_KERNEL_HEAP);
		 if(!tag_guid){
			 err("TAG Input Failed: Allocation of tag_guid_t object");
			 error = INM_ENOMEM;
			 goto just_exit;
		 }
 
		 INM_MEM_ZERO(tag_guid, sizeof(tag_guid_t));
		 INM_INIT_WAITQUEUE_HEAD(&tag_guid->wq);
 
		 if(!INM_ACCESS_OK(VERIFY_READ , (void __INM_USER *)user_buf,
			 sizeof(unsigned short))){
			 err("TAG Input Failed: Access violation in getting guid length");
			 error = INM_EFAULT;
			 goto just_exit;
		 }
 
		 if(INM_COPYIN(&tag_guid->guid_len, user_buf, sizeof(unsigned short))){
			 err("TAG Input Failed: INM_COPYIN failed while accessing guid length");
			 error = INM_EFAULT;
			 goto just_exit;
		 }
 
		 user_buf += sizeof(unsigned short);
 
		 if(!INM_ACCESS_OK(VERIFY_READ , (void __INM_USER *)user_buf, 
								 tag_guid->guid_len)){
			 err("TAG Input Failed: Access violation in getting guid");
			 error = INM_EFAULT;
			 goto just_exit;
		 }
 
		 tag_guid->guid = (char *)INM_KMALLOC(tag_guid->guid_len + 1, 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
		 if(!tag_guid->guid){
			 err("TAG Input Failed: Allocation of memory for guid");
			 error = INM_ENOMEM;
			 goto just_exit;
		 }
 
		 if(INM_COPYIN(tag_guid->guid, user_buf, tag_guid->guid_len)){
			 err("TAG Input Failed: INM_COPYIN failed while accessing guid");
			 error = INM_EFAULT;
			 goto just_exit;
		 }
 
		 user_buf += tag_guid->guid_len;
 
		 tag_guid->guid[tag_guid->guid_len] = '\0';
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ , (void __INM_USER *)user_buf,
		   (sizeof(inm_u32_t) + sizeof(unsigned short)))) {
		 err("TAG Input Failed: Access violation in getting Flags and \
				 Total Number of volumes");
		 error = -EFAULT;
		 goto just_exit;
	 }
 
	 if(INM_COPYIN(&flags, user_buf, sizeof(inm_u32_t))) {
		 err("TAG Input Failed: INM_COPYIN failed while accessing flags");
		 error = -EFAULT;
		 goto just_exit;
	 }
 
	 /* Get total number of volumes in the input stream. */
	 user_buf += sizeof(inm_u32_t);
 
	 if(INM_COPYIN(&num_vols, user_buf, sizeof(unsigned short))) {
		 err("TAG Input Failed: INM_COPYIN failed while accessing flags");
		 error = -EFAULT;
		 goto just_exit;
	 }
 
	 if(num_vols <= 0) {
		 err("TAG Input Failed: Number of volumes can't be zero or negative");
		 error = -EINVAL;
		 goto just_exit;
	 }
 
	 dbg("TAG: No of volumes: %d", num_vols);
 
	 user_buf += sizeof(unsigned short);
 
	 if(sync_tag){
		 tag_guid->num_vols = num_vols;
 
		 tag_guid->status = INM_KMALLOC(num_vols * sizeof(inm_s32_t), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
		 if(!tag_guid->status){
			 err("TAG Input Failed: Allocation of memory for status of tag");
			 error = INM_ENOMEM;
			 goto just_exit;
		 }
 
		 error = flt_process_tags(num_vols, &user_buf, flags, tag_guid);
		 if(error)
			 goto just_exit;
 
		 if(INM_COPYOUT(user_buf, tag_guid->status, 
						 num_vols * sizeof(inm_s32_t))) {
			 err("copy to user failed for tag status");
				 error = INM_EFAULT;
			 goto just_exit;
		 }
 
		 for(i = 0; i < num_vols; i++){
			 if(tag_guid->status[i] == STATUS_PENDING){
				 INM_DOWN_WRITE(&(driver_ctx->tag_guid_list_sem));
				 inm_list_add_tail(&tag_guid->tag_list, 
							 &driver_ctx->tag_guid_list);
				 INM_UP_WRITE(&(driver_ctx->tag_guid_list_sem));
				 return error;
			 }
		 }
 
		 goto just_exit;
	 }else
		 error = flt_process_tags(num_vols, &user_buf, flags, NULL);
 
	 return error;
 
 just_exit:
	 if(sync_tag)
	 flt_cleanup_sync_tag(tag_guid);
 
	 return error;
 }
 
 inm_s32_t
 process_get_tag_status_ioctl(inm_devhandle_t *idhp, void __INM_USER *user_buf)
 {
	 inm_u16_t guid_len;
	 char *guid = NULL;
	 inm_s32_t status = 0, error, need_to_wait = 1, i;
	 tag_guid_t *tag_guid;
	 unsigned short seconds;
 
	 if(!INM_ACCESS_OK(VERIFY_READ , (void __INM_USER *)user_buf,
		 sizeof(unsigned short))){
		 err("TAG STATUS Input Failed: Access violation in getting guid length");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 if(INM_COPYIN(&guid_len, user_buf, sizeof(unsigned short))){
		 err("TAG STATUS Input Failed: INM_COPYIN failed while accessing guid length");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 user_buf += sizeof(unsigned short);
 
	 if(!INM_ACCESS_OK(VERIFY_READ , (void __INM_USER *)user_buf, 
								 guid_len)){
		 err("TAG STATUS Input Failed: Access violation in getting guid");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 guid = (char *)INM_KMALLOC(guid_len + 1, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!guid){
		 err("TAG STATUS Input Failed: Allocation of memory for guid");
		 error = INM_ENOMEM;
		 goto out_err;
	 }
 
	 if(INM_COPYIN(guid, user_buf, guid_len)){
		 err("TAG STATUS Input Failed: INM_COPYIN failed while accessing guid");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 guid[guid_len] = '\0';
	 user_buf += guid_len;
 
	 if(!INM_ACCESS_OK(VERIFY_READ , (void __INM_USER *)user_buf,
		 sizeof(unsigned short))){
		 err("TAG STATUS Input Failed: Access violation in getting seconds");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 if(INM_COPYIN(&seconds, user_buf, sizeof(unsigned short))){
		 err("TAG STATUS Input Failed: INM_COPYIN failed while accessing seconds");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 info("Timeout = %u\n", seconds);
 
	 user_buf += sizeof(unsigned short);
 
 retry:
	 INM_DOWN_READ(&(driver_ctx->tag_guid_list_sem));
	 tag_guid = get_tag_from_guid(guid);
	 if(!tag_guid){
		 INM_UP_READ(&(driver_ctx->tag_guid_list_sem));
		 error = INM_EINVAL;
		 err("There is no matching synchronous tag");
		 goto out_err;
	 }
 
	 for(i = 0; i < tag_guid->num_vols; i++){
		 if(tag_guid->status[i] == STATUS_PENDING){
			 if(need_to_wait){
				 INM_UP_READ(&(driver_ctx->tag_guid_list_sem));
				 goto wait;
			 }
 
			 status = STATUS_PENDING;
			 break;
		 }
	 }
	 INM_UP_READ(&(driver_ctx->tag_guid_list_sem));
 
	 if(!INM_ACCESS_OK(VERIFY_WRITE, (void __INM_USER *)user_buf,
		 tag_guid->num_vols * sizeof(inm_s32_t))){
		 err("TAG STATUS Input Failed: Access violation in getting guid status");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 if(INM_COPYOUT(user_buf, tag_guid->status, 
				 tag_guid->num_vols * sizeof(inm_s32_t))) {
		 err("TAG STATUS Output Failed: copy to user failed for tag status");
		 error = INM_EFAULT;
		 goto out_err;
	 }
 
	 if(status != STATUS_PENDING){
		 INM_DOWN_WRITE(&(driver_ctx->tag_guid_list_sem));
		 inm_list_del(&tag_guid->tag_list);
		 INM_UP_WRITE(&(driver_ctx->tag_guid_list_sem));
		 flt_cleanup_sync_tag(tag_guid);
	 }
 
	 error = 0;
	 goto out_err;
 
 wait:
	 if(seconds)
		 inm_wait_event_interruptible_timeout(tag_guid->wq, 0, 
							 (seconds * INM_HZ));
	 else
		 inm_wait_event_interruptible(tag_guid->wq, 0);
 
	 need_to_wait = 0;
	 goto retry;
 
 out_err:
	 if(guid)
		 INM_KFREE(guid, guid_len + 1, INM_KERNEL_HEAP);
 
	 return error;
 }
 
 inm_s32_t process_wake_all_threads_ioctl(inm_devhandle_t *idhp, 
					 void __INM_USER *user_buf)
 {
	 struct inm_list_head *ptr;
	 target_context_t *tgt_ctxt = NULL;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
 
	 for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
							 ptr = ptr->next) {
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 INM_WAKEUP_INTERRUPTIBLE(&tgt_ctxt->tc_waitq);
	 }
 
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t process_get_db_threshold(inm_devhandle_t *idhp, 
						 void __INM_USER *user_buf)
 {
	 get_db_thres_t *thr;
	 target_context_t *ctxt;
	 
	 if(!INM_ACCESS_OK(VERIFY_READ | VERIFY_WRITE, 
			 (void __INM_USER *)user_buf,
			 sizeof(get_db_thres_t))) {
		 err("Access violation for get_db_thres_t buffer");
		 return -EFAULT;
	 }
 
	 thr = (get_db_thres_t *)INM_KMALLOC(sizeof(get_db_thres_t),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!thr)
		 return -ENOMEM;
 
	 if(INM_COPYIN(thr, user_buf, sizeof(get_db_thres_t))) {
		 INM_KFREE(thr, sizeof(get_db_thres_t), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 thr->VolumeGUID[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&thr->VolumeGUID[0]);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(thr, sizeof(get_db_thres_t), INM_KERNEL_HEAP);
		 return -EINVAL;
	 }
 
	 thr->threshold = ctxt->tc_db_notify_thres;	 
 
	 if(INM_COPYOUT(user_buf, thr, sizeof(get_db_thres_t))) {
		 err("copy to user failed in get_db");
		 put_tgt_ctxt(ctxt);
		 INM_KFREE(thr, sizeof(get_db_thres_t), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 put_tgt_ctxt(ctxt);
 
	 INM_KFREE(thr, sizeof(get_db_thres_t), INM_KERNEL_HEAP);
 
	 return 0;	
 }
 
 inm_s32_t process_resync_start_ioctl(inm_devhandle_t *idhp, 
					 void __INM_USER *user_buf)
 {
	 RESYNC_START_V2 *resync_start;
	 TIME_STAMP_TAG_V2 ts;
	 target_context_t *ctxt = NULL;
 
	 if(!INM_ACCESS_OK(VERIFY_READ | VERIFY_WRITE, 
			 (void __INM_USER *)user_buf,
			 sizeof(RESYNC_START_V2))) {
		 err("Access violation for RESYNC_START buffer");
		 return -EFAULT;
	 }
 
	 resync_start = (RESYNC_START_V2 *)INM_KMALLOC(sizeof(RESYNC_START_V2),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!resync_start)
		 return -ENOMEM;
 
	 if(INM_COPYIN(resync_start, user_buf, sizeof(RESYNC_START_V2))) {
		 INM_KFREE(resync_start, sizeof(RESYNC_START_V2), 
							 INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 resync_start->VolumeGUID[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&resync_start->VolumeGUID[0]);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(resync_start, sizeof(RESYNC_START_V2), 
							 INM_KERNEL_HEAP);
		 return -EINVAL;
	 }
 
	 volume_lock(ctxt);    
	 
	 if (ctxt->tc_cur_node && ctxt->tc_optimize_performance &
		 PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO) {
		 INM_BUG_ON(!inm_list_empty(&ctxt->tc_cur_node->nwo_dmode_next));
		 if (ctxt->tc_cur_node->type == NODE_SRC_DATA &&
			 ctxt->tc_cur_node->wostate != ecWriteOrderStateData) {
			 close_change_node(ctxt->tc_cur_node, IN_IOCTL_PATH);
			 inm_list_add_tail(&ctxt->tc_cur_node->nwo_dmode_next,   
							   &ctxt->tc_nwo_dmode_list);
			 if (ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DATA_DRAIN) {
				 info("Appending chg:%p to ctxt:%p next:%p prev:%p mode:%d",
					  ctxt->tc_cur_node,ctxt,
					  ctxt->tc_cur_node->nwo_dmode_next.next,
					  ctxt->tc_cur_node->nwo_dmode_next.prev,
					  ctxt->tc_cur_node->type);
			 }
		 }
	 }
	 /* set cur_node to NULL. */
	 ctxt->tc_cur_node = NULL;
 
	 /* get timestamp. */
	 get_time_stamp_tag(&ts);
 
	 resync_start->TimeInHundNanoSecondsFromJan1601 = ts.TimeInHundNanoSecondsFromJan1601;
	 resync_start->ullSequenceNumber = ts.ullSequenceNumber;
	 
	 ctxt->tc_tel.tt_resync_start = ts.TimeInHundNanoSecondsFromJan1601;
 
	 volume_unlock(ctxt);
 
	 if(INM_COPYOUT(user_buf, resync_start, sizeof(RESYNC_START_V2))) {
		 err("copy to user failed in resync_start");
		 put_tgt_ctxt(ctxt);
		 INM_KFREE(resync_start, sizeof(RESYNC_START_V2), 
							 INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
	 
	 put_tgt_ctxt(ctxt);
 
	 INM_KFREE(resync_start, sizeof(RESYNC_START_V2), INM_KERNEL_HEAP);
 
	 return 0;	
 }
 
 inm_s32_t process_resync_end_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *user_buf)
 {
	 RESYNC_END_V2 *resync_end;
	 TIME_STAMP_TAG_V2 ts;
	 target_context_t *ctxt = NULL;
 
	 if(!INM_ACCESS_OK(VERIFY_READ | VERIFY_WRITE, 
			 (void __INM_USER *)user_buf,
			 sizeof(RESYNC_END))) {
		 err("Access violation for RESYNC_END buffer");
		 return -EFAULT;
	 }
 
	 resync_end = (RESYNC_END_V2 *)INM_KMALLOC(sizeof(RESYNC_END_V2),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!resync_end)
		 return -ENOMEM;
 
	 if(INM_COPYIN(resync_end, user_buf, sizeof(RESYNC_END_V2))) {
		 INM_KFREE(resync_end, sizeof(RESYNC_END_V2), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 resync_end->VolumeGUID[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&resync_end->VolumeGUID[0]);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(resync_end, sizeof(RESYNC_END_V2), INM_KERNEL_HEAP);
		 return -EINVAL;
	 }
 
	 volume_lock(ctxt);
 
	 if (ctxt->tc_cur_node && (ctxt->tc_optimize_performance &
		 PERF_OPT_DRAIN_PREF_DATA_MODE_CHANGES_IN_NWO)) {
		 INM_BUG_ON(!inm_list_empty(&ctxt->tc_cur_node->nwo_dmode_next));
		 if (ctxt->tc_cur_node->type == NODE_SRC_DATA &&
			 ctxt->tc_cur_node->wostate != ecWriteOrderStateData) {
			 close_change_node(ctxt->tc_cur_node, IN_IOCTL_PATH);
			 inm_list_add_tail(&ctxt->tc_cur_node->nwo_dmode_next,   
						   &ctxt->tc_nwo_dmode_list);
			 if (ctxt->tc_optimize_performance & PERF_OPT_DEBUG_DATA_DRAIN) {
				 info("Appending chg:%p to ctxt:%p next:%p prev:%p mode:%d",
					  ctxt->tc_cur_node,ctxt,
					  ctxt->tc_cur_node->nwo_dmode_next.next,
					  ctxt->tc_cur_node->nwo_dmode_next.prev,
					  ctxt->tc_cur_node->type);
			 }
		 }
	 }
	 /* set cur_node to NULL. */
	 ctxt->tc_cur_node = NULL;
 
	 /* get timestamp. */
	 get_time_stamp_tag(&ts);
 
	 resync_end->TimeInHundNanoSecondsFromJan1601 = ts.TimeInHundNanoSecondsFromJan1601;
	 resync_end->ullSequenceNumber = ts.ullSequenceNumber;
	 ctxt->tc_tel.tt_resync_end = ts.TimeInHundNanoSecondsFromJan1601;
 
	 volume_unlock(ctxt);
 
	 if(INM_COPYOUT(user_buf, resync_end, sizeof(RESYNC_END_V2))) {
		 err("copy to user failed in resync_end");
		 put_tgt_ctxt(ctxt);
		 INM_KFREE(resync_end, sizeof(RESYNC_END_V2), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 put_tgt_ctxt(ctxt);
 
	 INM_KFREE(resync_end, sizeof(RESYNC_END_V2), INM_KERNEL_HEAP);
 
	 return 0;
 }
 
 inm_s32_t process_get_driver_version_ioctl(inm_devhandle_t *idhp, 
						 void __INM_USER *user_buf)
 {
	 DRIVER_VERSION *version;
 
	 if(!INM_ACCESS_OK(VERIFY_READ | VERIFY_WRITE, 
			 (void __INM_USER *)user_buf,
			 sizeof(DRIVER_VERSION))) {
		 err("Access violation for DRIVER_VERSION buffer");
		 return -EFAULT;
	 }
 
	 version = (DRIVER_VERSION *)INM_KMALLOC(sizeof(DRIVER_VERSION),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!version)
		 return -ENOMEM;
 
	 if(INM_COPYIN(version, user_buf, sizeof(DRIVER_VERSION))) {
		 INM_KFREE(version, sizeof(DRIVER_VERSION), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 version->ulDrMajorVersion = DRIVER_MAJOR_VERSION;
	 version->ulDrMinorVersion = DRIVER_MINOR_VERSION;
	 version->ulDrMinorVersion2 = DRIVER_MINOR_VERSION2;
	 version->ulDrMinorVersion3 = DRIVER_MINOR_VERSION3;
 
	 version->ulPrMajorVersion = INMAGE_PRODUCT_VERSION_MAJOR;
	 version->ulPrMinorVersion = INMAGE_PRODUCT_VERSION_MINOR;
	 version->ulPrMinorVersion2 = INMAGE_PRODUCT_VERSION_PRIVATE;
	 version->ulPrBuildNumber = INMAGE_PRODUCT_VERSION_BUILDNUM;
 
	 if(INM_COPYOUT(user_buf, version, sizeof(DRIVER_VERSION))) {
		 err("copy to user failed in get_driver_version");
		 INM_KFREE(version, sizeof(DRIVER_VERSION), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 INM_KFREE(version, sizeof(DRIVER_VERSION), INM_KERNEL_HEAP);
 
	 return 0;
 }
 
 inm_s32_t process_shell_log_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
 {
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered");
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
		   sizeof(SHUTDOWN_NOTIFY_INPUT)))
		 return -EFAULT;
 
	 dbg("%s\n", (char *)arg); 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("leaving");
	 }
 
	 return 0;
 }
 
 inm_s32_t 
 process_get_global_stats_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 inm_u32_t           len = 0;
	 inm_u64_t           mb_allocated, mb_free;
	 inm_u64_t           mb_unres, mb_total_res;
	 inm_s32_t           ret = 0;
	 char                guid[sizeof(driver_ctx->dc_cp_guid) + 1];
	 char                *page;
	 char                *strp;
	 vm_cx_session_t     *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	 int                 idx;
 
	 /* notes: use some sort of structure that includes the buf len 
	  *      : its ok not to take any lock during accessing the field 
	  * 	  of driver context since here we are the reader only so at most
	  *        we could get little inaccurate info but we it wont' cause any kernel
	  *        panic. In future if we see really weird behaviour we'll take the proper locks.
	  */
 
	 mb_allocated = driver_ctx->data_flt_ctx.pages_allocated >>
					(MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
	 mb_free = driver_ctx->data_flt_ctx.pages_free >>
			   (MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
	 mb_unres = driver_ctx->dc_cur_unres_pages >> 
				(MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
	 mb_total_res = driver_ctx->dc_cur_res_pages >>
					(MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
 
	 page = INM_KMALLOC(INM_PAGESZ, INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!page){
		 ret = -ENOMEM;
		 goto out;
	 }    
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "\n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "Common Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len), "------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "No. Pending Change Nodes    : %d\n", 
		 INM_ATOMIC_READ(&driver_ctx->stats.pending_chg_nodes));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Service state               : %u (pid = %u)\n",
		 (driver_ctx->service_state), driver_ctx->svagent_pid);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "[Note: 0.uninit, 1.not started, 2.running 3. shutdown]\n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "sentinal state              : %s (pid = %u)\n\n",
		 (driver_ctx->sentinal_pid)? "RUNNING" : "STOPPED",
		 driver_ctx->sentinal_pid);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "No of protected volumes    : %d\n", 
		 driver_ctx->total_prot_volumes);
	 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "DRIVER BUILD TIME           : %s (%s)\n", BLD_DATE, BLD_TIME);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Reserved change-node pages  : %u Pages\n",
		 (driver_ctx->dc_res_cnode_pgs));
 
 #ifdef INM_QUEUE_RQ_ENABLED
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Reserved BIOInfo/failed     : %d/%d\n",
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced),
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_allocs_failed));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Reserved changeNodes/failed : %d/%d\n",
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced),
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_chgnode_allocs_failed));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Reserved meta pages/failed  : %d/%d\n",
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced),
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_metapage_allocs_failed));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Allocated BIOInfo/Change nodes/Meta pages from Pool       : %d/%d/%d\n",
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced_from_pool),
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_chgnodes_alloced_from_pool),
		 INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced_from_pool));
 #endif
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "\nData Mode Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len), "---------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Data Pool Size Allocated/Required    : %llu MB(%u pages)/%u MB\n",
		 mb_allocated, driver_ctx->data_flt_ctx.pages_allocated,
		 driver_ctx->tunable_params.data_pool_size);
 
	 if (mb_free){ 	
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Data Pool Size Free         : %llu MB(%u pages) \n", 
			 mb_free, driver_ctx->data_flt_ctx.pages_free);
	 } else {
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Data Pool Size Free         : %ld bytes(%d pages) \n", 
			 (driver_ctx->data_flt_ctx.pages_free * INM_PAGESZ),
			 driver_ctx->data_flt_ctx.pages_free);
	 }
 
		len += snprintf(page+len, (INM_PAGESZ - len),
		 "Total Reserved Pages        : %llu MB(%u pages) \n", 
		 mb_total_res, driver_ctx->dc_cur_res_pages);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Unreserved Pages            : %llu MB(%u pages) \n", 
		 mb_unres, driver_ctx->dc_cur_unres_pages);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "\nData File Mode Info:\n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "----------------------\n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Data File Mode Directory    : %s \n",
		 (driver_ctx->tunable_params.data_file_log_dir));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Data File Mode - Disk Limit : %lld MB\n",
		 driver_ctx->tunable_params.data_to_disk_limit/MEGABYTES);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Data File Mode Enabled      : %s \n",
		 (driver_ctx->tunable_params.enable_data_file_mode ?
			  "Yes" : "No"));	
	 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Free Pages Threshold        : %d \n\n", 
		 driver_ctx->tunable_params.free_pages_thres_for_filewrite);
 
 #ifdef INM_AIX
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Bitmap Work Item Pool Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"---------------------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of available objects    : %u\n",
				driver_ctx->dc_bmap_info.bitmap_work_item_pool->pi_reserved);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of used objects         : %u\n",
				driver_ctx->dc_bmap_info.bitmap_work_item_pool->pi_allocd);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Max / Min limit             : %u/%u\n\n",
				driver_ctx->dc_bmap_info.bitmap_work_item_pool->pi_max_nr,
				driver_ctx->dc_bmap_info.bitmap_work_item_pool->pi_min_nr);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Work Queue Entry Pool Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"---------------------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of available objects    : %u\n",
				driver_ctx->wq_entry_pool->pi_reserved);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of used objects         : %u\n",
				driver_ctx->wq_entry_pool->pi_allocd);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Max / Min limit             : %u/%u\n\n",
				driver_ctx->wq_entry_pool->pi_max_nr,
				driver_ctx->wq_entry_pool->pi_min_nr);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"I/O Buffer Pool Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"---------------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of available objects    : %u\n",
				driver_ctx->dc_bmap_info.iob_obj_pool->pi_reserved);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of used objects         : %u\n",
				driver_ctx->dc_bmap_info.iob_obj_pool->pi_allocd);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Max / Min limit             : %u/%u\n\n",
				driver_ctx->dc_bmap_info.iob_obj_pool->pi_max_nr,
				driver_ctx->dc_bmap_info.iob_obj_pool->pi_min_nr);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"I/O Buffer Data Pool Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"--------------------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of available objects    : %u\n",
				driver_ctx->dc_bmap_info.iob_data_pool->pi_reserved);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of used objects         : %u\n",
				driver_ctx->dc_bmap_info.iob_data_pool->pi_allocd);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Max / Min limit             : %u/%u\n\n",
				driver_ctx->dc_bmap_info.iob_data_pool->pi_max_nr,
				driver_ctx->dc_bmap_info.iob_data_pool->pi_min_nr);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Data File Node Pool Info:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"-------------------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of available objects    : %u\n",
				driver_ctx->dc_host_info.data_file_node_cache->pi_reserved);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of used objects         : %u\n",
				driver_ctx->dc_host_info.data_file_node_cache->pi_allocd);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Max / Min limit             : %u/%u\n\n",
				driver_ctx->dc_host_info.data_file_node_cache->pi_max_nr,
				driver_ctx->dc_host_info.data_file_node_cache->pi_min_nr);
 #endif
 #ifdef INM_LINUX
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Total memory usage		: %lu KB \n\n",
		 (unsigned long) (atomic_read(&inm_flt_memprint)/1024));
 #endif
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				   driver_ctx->dc_vm_cx_session_lock_flag);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"CX Session Details:\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"-------------------\n");
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. Of disks in Non Wrote Order   : %u\n",
				   driver_ctx->total_prot_volumes_in_nwo);
 
	 if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED)) {
		 strp = "Session Not Started";
		 len += snprintf(page+len, (INM_PAGESZ - len),
				"State                             : %s\n", strp);
 
		 goto unlcok_session_lock;
	 }
 
	 if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED)
		 strp = "Session Ended";
	 else
		 strp = "Session Started";
 
	 len += snprintf(page+len, (INM_PAGESZ - len), 
				"State                             : %s", strp);
 
	 if (vm_cx_sess->vcs_flags & VCS_CX_S2_EXIT)
		 len += snprintf(page+len, (INM_PAGESZ - len), ", Drainer Exited");
	 if (vm_cx_sess->vcs_flags & VCS_CX_SVAGENT_EXIT)
		 len += snprintf(page+len, (INM_PAGESZ - len), ", Service exited");
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"\nSession Number                  : %u\n",
				vm_cx_sess->vcs_nth_cx_session);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Transaction ID                  : %llu\n",
				vm_cx_sess->vcs_transaction_id);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"No. of Disks in session         : %llu\n",
				vm_cx_sess->vcs_num_disk_cx_sess);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"CX Start / End Time             : %llu/%llu\n",
				vm_cx_sess->vcs_start_ts, vm_cx_sess->vcs_end_ts);
 #ifdef INM_DEBUG
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Base Time for 1 sec interval    : %llu\n",
				vm_cx_sess->vcs_base_secs_ts);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Tracked bytes in 1 sec          : %llu\n",
				vm_cx_sess->vcs_tracked_bytes_per_second);
 #endif
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Tracked / Drained bytes         : %llu / %llu\n",
				vm_cx_sess->vcs_tracked_bytes, 
				vm_cx_sess->vcs_drained_bytes);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Churn Buckets                   : ");
	 for (idx = 0; idx < DEFAULT_NR_CHURN_BUCKETS; idx++) {
			len += snprintf(page+len, (INM_PAGESZ - len), "%llu ",
					  vm_cx_sess->vcs_churn_buckets[idx]);
	 }
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"\nDefault Disk / VM Peak Churn    : %llu / %llu\n",
				vm_cx_sess->vcs_default_disk_peak_churn,
				vm_cx_sess->vcs_default_vm_peak_churn);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Max Peak / Excess Churn           : %llu / %llu\n",
				vm_cx_sess->vcs_max_peak_churn, 
				vm_cx_sess->vcs_excess_churn);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"First / Last Peak Churn TS        : %llu / %llu\n",
				vm_cx_sess->vcs_first_peak_churn_ts,
				vm_cx_sess->vcs_last_peak_churn_ts);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Consecutive Tag Failures          : %llu\n",
				vm_cx_sess->vcs_num_consecutive_tag_failures);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Time Jump at TS                   : %llu\n",
				vm_cx_sess->vcs_timejump_ts);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Time Jump in msec                 : %llu\n",
				vm_cx_sess->vcs_max_jump_ms);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"FWD / BWD Time Jump TS            : %llu / %llu\n",
				driver_ctx->dc_max_fwd_timejump_ms,
				driver_ctx->dc_max_bwd_timejump_ms);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"Drainer latency                   : %llu\n",
				vm_cx_sess->vcs_max_s2_latency);
 unlcok_session_lock:
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				   driver_ctx->dc_vm_cx_session_lock_flag);
 
	 memcpy_s(guid, sizeof(guid), driver_ctx->dc_cp_guid, 
				 sizeof(driver_ctx->dc_cp_guid));
	 guid[sizeof(guid) - 1] = '\0';
	 len += snprintf(page+len, (INM_PAGESZ - len),
				"CP: %d (%s)\n", driver_ctx->dc_cp, guid);
 
	 if (INM_COPYOUT(arg, page, INM_PAGESZ)){
		 err("copyout failed");
		 ret = -EFAULT;
		 goto out;
	 }
 
 out:
	 if (page){
		 INM_KFREE(page, INM_PAGESZ, INM_KERNEL_HEAP);
	 }
 
	 return (ret);
 }
 
 inm_s32_t 
 process_get_monitoring_stats_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 inm_s32_t ret = 0;
	 MONITORING_STATS *vol_lw_statsp = NULL;
	 target_context_t *ctxt = NULL;
 
	 if (!INM_ACCESS_OK(VERIFY_READ | VERIFY_WRITE, (void __user*)arg,
						sizeof(MONITORING_STATS))) {
		 err( "Read Access Violation for GET_MONITORING_STATS\n");
		 ret = -EFAULT;
		 return ret;
	 }
 
	 vol_lw_statsp = (MONITORING_STATS*) INM_KMALLOC(sizeof(MONITORING_STATS), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!vol_lw_statsp) {
		 ret = -ENOMEM;
		 err("INM_KMALLOC failed\n");
		 return ret;
	 }
 
	 INM_MEM_ZERO(vol_lw_statsp, sizeof(MONITORING_STATS));
 
	 if (INM_COPYIN(vol_lw_statsp, arg, sizeof(MONITORING_STATS))) {
		 err("INM_COPYIN failed");
		 ret = -EFAULT;
		 goto ERR_EXIT;
	 }
 
	 vol_lw_statsp->VolumeGuid.volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&vol_lw_statsp->VolumeGuid.volume_guid[0]);
	 if (!ctxt) {
		 err("Failed to get target context for uuid %s", 
				 vol_lw_statsp->VolumeGuid.volume_guid);
		 ret = -EINVAL;
		 goto ERR_EXIT;
	 }
 
	 switch(vol_lw_statsp->ReqStat) {
		 case GET_TAG_STATS:
			 vol_lw_statsp->TagStats.TagsDropped = 
			 INM_ATOMIC_READ(&ctxt->tc_stats.num_tags_dropped);
			 break;
		 case GET_CHURN_STATS:
			 vol_lw_statsp->ChurnStats.NumCommitedChangesInBytes = 
					 ctxt->tc_bytes_commited_changes;
			 break;
		 default:
			 err("ReqStat %d not supported", vol_lw_statsp->ReqStat);
			 ret = -EINVAL;
			 put_tgt_ctxt(ctxt);
			 goto ERR_EXIT;
	 }
 
	 put_tgt_ctxt(ctxt);
 
	 if (INM_COPYOUT((void*)arg, vol_lw_statsp, sizeof(MONITORING_STATS))) {
		 err("INM_COPYOUT failed");
		 ret = -EFAULT;
	 }
 
 ERR_EXIT:
	 INM_KFREE(vol_lw_statsp, sizeof(MONITORING_STATS), INM_KERNEL_HEAP);
 
	 return ret;
 }
 
 inm_s32_t 
 process_get_volume_stats_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 inm_s32_t       ret = 0;
	 inm_s32_t       len = 0;
	 inm_s32_t       idx = 0;
	 char            *page = NULL;
	 char            *strp, *strp_2;
	 VOLUME_STATS	*vol_stat = NULL;
	 target_context_t    *ctxt = NULL;
	 bitmap_info_t   *bitmap = NULL;
		 disk_cx_session_t *disk_cx_sess;
 
	 vol_stat = (VOLUME_STATS *) INM_KMALLOC(sizeof(VOLUME_STATS), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!vol_stat){
		 dbg("vol_stat allocation volume_stats failed\n");
		 ret = INM_ENOMEM;
		 goto out;
	 }
	 if (INM_COPYIN(vol_stat, arg, sizeof(VOLUME_STATS))){
		 err("copyin failed");
		 ret = -EFAULT;
		 goto out;
	 }
	 vol_stat->guid.volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	 ctxt = get_tgt_ctxt_from_name_nowait_locked(vol_stat->guid.volume_guid);
	 if (!ctxt){
		 INM_UP_READ(&driver_ctx->tgt_list_sem);
		 dbg("%s device is not stacked",vol_stat->guid.volume_guid);
		 goto out;
	 }
	 INM_UP_READ(&driver_ctx->tgt_list_sem);
 
	 bitmap = ctxt->tc_bp;
	 page = INM_KMALLOC(INM_PAGESZ, INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!page){
		 dbg("page allocation volume_stats failed");
		 ret = -ENOMEM;
		 goto out;
	 }
	 INM_MEM_ZERO(page, sizeof(*page));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "\nPersistent Name                     : ");
	 len += snprintf(page+len, (INM_PAGESZ - len), "%s", ctxt->tc_pname);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "\nVolume State                        : ");
 
	 if (ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
		 if (is_target_mirror_paused(ctxt)){
			 strp = "Mirroring Paused";
		 }else {
			 strp = "Mirroring Enabled";
		 }
	 }else {
		 if (is_target_filtering_disabled(ctxt)) {
			 strp = "Filtering Disabled ";
		 } else {
			 strp = "Filtering Enabled ";
		 }
	 }
	 len += snprintf(page+len, (INM_PAGESZ - len), strp);
 
	 if (is_target_read_only(ctxt)) {
		 strp = ", Read-Only ";
	 } else {
		 strp = ", Read-Write ";
	 }
	 len += snprintf(page+len, (INM_PAGESZ - len), strp);
 
	 if (ctxt->tc_resync_required) {
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 ", Resync Required ");
	 }
	 len += snprintf(page+len, (INM_PAGESZ - len), "\n");
 
	 if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP){
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Filtering Mode/Write Order State    : ");
 
		 if (ctxt->tc_cur_mode == FLT_MODE_DATA) {
			 strp = "Data";
		 } else if (ctxt->tc_cur_mode == FLT_MODE_METADATA) {
			 strp = "MetaData";
		 } else { 
			 strp = "Uninitialized/";
		 } 
 
		 if (ctxt->tc_cur_wostate == ecWriteOrderStateData)
			 strp_2 = "Data\n";
		 else if (ctxt->tc_cur_wostate == ecWriteOrderStateMetadata)
			 strp_2 = "MetaData\n";
		 else if (ctxt->tc_cur_wostate == ecWriteOrderStateBitmap)
			 strp_2 = "Bitmap\n";
		 else if (ctxt->tc_cur_wostate == ecWriteOrderStateRawBitmap)
			 strp_2 = "Raw Bitmap\n";
		 else
			 strp_2 = "Uninitialized\n";
 
		 len += snprintf(page+len, (INM_PAGESZ - len), "%s/%s", 
								 strp, strp_2);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			  "Time spent in Curr mode/state (sec) : %llu/%llu\n",
			 (INM_GET_CURR_TIME_IN_SEC - 
				 ctxt->tc_stats.st_mode_switch_time),
			 (INM_GET_CURR_TIME_IN_SEC -
				 ctxt->tc_stats.st_wostate_switch_time));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
				 "Writes (bytes)                      : %lld\n", 
				 ctxt->tc_bytes_tracked); 
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
				 "Pending Changes/bytes               : %lld/%lld\n", 
				 ctxt->tc_pending_changes,
				 ctxt->tc_bytes_pending_changes); 
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			   "Pending Changes/bytes in metadata   : %lld/%lld\n", 
			 ctxt->tc_pending_md_changes, 
			 ctxt->tc_bytes_pending_md_changes);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Commited Changes/bytes              : %lld/%lld\n", 
			 ctxt->tc_commited_changes, 
			 ctxt->tc_bytes_commited_changes); 
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Chain Bio Submitted/Pening          : %d/%d\n", 
			 INM_ATOMIC_READ(&ctxt->tc_nr_chain_bios_submitted),
			 INM_ATOMIC_READ(&ctxt->tc_nr_chain_bios_pending));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Chain Bio in child/Own stack        : %d/%d\n", 
			 INM_ATOMIC_READ(&ctxt->tc_nr_completed_in_child_stack),
			 INM_ATOMIC_READ(&ctxt->tc_nr_completed_in_own_stack));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Re-entrant bio count/extra size/orig size           : %d/%lld/%lld\n", 
			 INM_ATOMIC_READ(&ctxt->tc_nr_bio_reentrant),
			 ctxt->tc_bio_reentrant_size,
			 ctxt->tc_bio_reentrant_orig_size);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Re-entrant chain bio count/extra size           : %d/%lld\n", 
			 INM_ATOMIC_READ(&ctxt->tc_nr_chain_bio_reentrant),
			 ctxt->tc_chain_bio_reentrant_size);
 
 #if (defined REQ_OP_WRITE_ZEROES || defined OL7UEK5)
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Number of WRITE_ZERO BIOs Received  : %d\n",
			 INM_ATOMIC_READ(&ctxt->tc_nr_write_zero_bios));
 #endif
 
		 if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
			 len += snprintf(page+len, (INM_PAGESZ - len),
				 "Total Write IOs received            : %llu (%llu bytes)\n", 
				 ctxt->tc_stats.tc_write_io_rcvd_bytes, 
				 ctxt->tc_stats.tc_write_io_rcvd); 
 
			 len += snprintf(page+len, (INM_PAGESZ - len),
				 "Total Write IO Cancels received     : %d (%llu bytes)\n", 
				 INM_ATOMIC_READ(&(ctxt->tc_stats.tc_write_cancel)),
				 ctxt->tc_stats.tc_write_cancel_rcvd_bytes);
		 }
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Data Files Created/Pending          : %d/%d\n",
			 INM_ATOMIC_READ(&ctxt->tc_stats.num_dfm_files),
			 INM_ATOMIC_READ(&ctxt->tc_stats.num_dfm_files_pending));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Data File Disk Space (Alloc/Used)   : %lld/%lld\n",
			 ctxt->tc_data_to_disk_limit, 
			 ctxt->tc_stats.dfm_bytes_to_disk);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Bitmap Changes Queued/bytes         : %llu/%llu\n",
			 bitmap->num_changes_queued_for_writing,
			 bitmap->num_byte_changes_queued_for_writing);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Bitmap Changes Read/bytes           : %llu/%llu (%llu times)\n",
			 bitmap->num_changes_read_from_bitmap,
			 bitmap->num_byte_changes_read_from_bitmap,
			 bitmap->num_of_times_bitmap_read);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Bitmap Changes Written/bytes        : %llu/%llu (%llu times)\n",
			 bitmap->num_changes_written_to_bitmap,
			 bitmap->num_byte_changes_written_to_bitmap,
			 bitmap->num_of_times_bitmap_written);
 
 #ifdef INM_AIX
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Async bufs submitted/processed      : %u, %u/%u, %u\n",
			 INM_ATOMIC_READ(&ctxt->tc_async_bufs_pending), 
			 INM_ATOMIC_READ(&ctxt->tc_async_bufs_write_pending),
			 INM_ATOMIC_READ(&ctxt->tc_async_bufs_processed), 
			 INM_ATOMIC_READ(&ctxt->tc_async_bufs_write_processed));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of requests queued to thread    : %lu\n",
			 ctxt->tc_nr_requests_queued);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of calles to ddwrite            : %lu\n",
			 ctxt->tc_nr_ddwrites_called);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Request has both read & write bufs  : %d\n",
			 INM_ATOMIC_READ(&ctxt->tc_mixedbufs));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "First Read / Write                  : %u / %u\n",
			 INM_ATOMIC_READ(&ctxt->tc_read_buf_first), 
			 INM_ATOMIC_READ(&ctxt->tc_write_buf_first));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of bufs submitted/processed     : %u/%u\n",
			 INM_ATOMIC_READ(&ctxt->tc_nr_bufs_pending), 
			 INM_ATOMIC_READ(&ctxt->tc_nr_bufs_processed));
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of bufs queued/processed        : %lu/%lu\n",
			 ctxt->tc_nr_bufs_queued_to_thread, 
			 ctxt->tc_nr_bufs_processed_by_thread);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of queued bufs submitted        : %lu\n",
			 ctxt->tc_nr_processed_queued_bufs);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "More done set/more bufs submitted   : %d/%d\n",
			 ctxt->tc_more_done_set, 
			 ctxt->tc_nr_bufs_submitted_gr_than_one);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Meta split I/Os excetption          : %lu\n",
			 ctxt->tc_nr_spilt_io_data_mode);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of xm_mapin failures            : %lu\n",
			 ctxt->tc_nr_xm_mapin_failures);
 #endif
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Pending Changes in each state       : "
			 "Data = %lld | Meta = %lld | Bitmap = %lld\n",
			 ctxt->tc_pending_wostate_data_changes,
			 ctxt->tc_pending_wostate_md_changes,
			 ctxt->tc_pending_wostate_bm_changes);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Pages Allocated                     : %d\n",
			 ctxt->tc_stats.num_pages_allocated);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of Pages Reserved               : %u\n",
			 ctxt->tc_reserved_pages);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "No. of change-node pages            : %lld\n",
			 ctxt->tc_cnode_pgs);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Threshold for DF in pages           : %u \n", 
			 (driver_ctx->tunable_params.volume_percent_thres_for_filewrite*
			 ctxt->tc_reserved_pages)/100);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Pages in DF Queue                   : %d\n",
			 ctxt->tc_stats.num_pgs_in_dfm_queue);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Changes Lost                        : %s\n",
			 (ctxt->tc_resync_required) ? "Yes" : "No");
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "DB Notify Threshold                 : %d\n",
			 ctxt->tc_db_notify_thres);
	 } else {
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Writes/bytes sent to PS             : %lld/%lld\n",
			 ctxt->tc_commited_changes,
			 ctxt->tc_bytes_commited_changes);
	 }
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Tags Dropped                        : %d\n",
		 INM_ATOMIC_READ(&ctxt->tc_stats.num_tags_dropped));
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Metadata transition due to delay Data Pool allocation : %d\n",
		 INM_ATOMIC_READ(&ctxt->tc_stats.metadata_trans_due_to_delay_alloc));
 
	 if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP){
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Total Mode Transistions             : "
			 "Data = %ld | Meta = %ld\n",
			 ctxt->tc_stats.num_change_to_flt_mode[FLT_MODE_DATA],
			 ctxt->tc_stats.num_change_to_flt_mode[FLT_MODE_METADATA]);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			  "Total Time spent in each Mode(sec)  : "
				 "Data = %ld | Meta = %ld\n",
			 ctxt->tc_stats.num_secs_in_flt_mode[FLT_MODE_DATA],
			 ctxt->tc_stats.num_secs_in_flt_mode[FLT_MODE_METADATA]);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Total State Transistions            : "
			 "Data = %ld | Meta = %ld | Bitmap = %ld\n",
			 ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateData] +
			 ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateData],
			 ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateMetadata] +
			 ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateMetadata],
			 ctxt->tc_stats.num_change_to_wostate[ecWriteOrderStateBitmap] +
			 ctxt->tc_stats.num_change_to_wostate_user[ecWriteOrderStateBitmap]);
 
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Total Time spent in each State(sec) : "
				 "Data = %ld | Meta = %ld | Bitmap = %ld\n",
			 ctxt->tc_stats.num_secs_in_wostate[ecWriteOrderStateData],
			 ctxt->tc_stats.num_secs_in_wostate[ecWriteOrderStateMetadata],
			 ctxt->tc_stats.num_secs_in_wostate[ecWriteOrderStateBitmap]);
	 } else{
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "Times PT Write I/O Cancelled        : %d\n",
			 INM_ATOMIC_READ(&ctxt->tc_stats.tc_write_cancel));
	 }
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "IO Pattern\n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "OP 512 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k 1M 2M 4M 8M 8M+\n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "W ");
 
	 for (idx = 0; idx < MAX_NR_IO_BUCKETS; idx++) {
		  len += snprintf(page+len, (INM_PAGESZ - len), "%d ", 
			 INM_ATOMIC_READ(&ctxt->tc_stats.io_pat_writes[idx]));
	 }
	 len += snprintf(page+len, (INM_PAGESZ - len), "\n");
	 len += snprintf(page+len, (INM_PAGESZ - len), "\n");
	 print_AT_stat_common(ctxt, page, &len);
	 len += snprintf(page+len, (INM_PAGESZ - len), "\n");
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
					   driver_ctx->dc_vm_cx_session_lock_flag);
	 disk_cx_sess = &ctxt->tc_disk_cx_session;
	 if (!(disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED)) {
		 len += snprintf(page+len, (INM_PAGESZ - len),
			 "CX State                            : Session Not Started\n");
 
		 goto unlock_session_lock;
	 }
 
	 if (disk_cx_sess->dcs_flags & DCS_CX_SESSION_ENDED)
		 strp = "Session Ended";
	 else
		 strp = "Session Started";
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "CX State                             : %s\n", strp);
	 len += snprintf(page+len, (INM_PAGESZ - len),
				 "Session Number                      : %llu\n",
				 disk_cx_sess->dcs_nth_cx_session);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "CX Start / End Time                 : %llu/%llu\n",
		 disk_cx_sess->dcs_start_ts, disk_cx_sess->dcs_end_ts);
 #ifdef INM_DEBUG
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Base Time for 1 sec interval        : %llu\n",
		 disk_cx_sess->dcs_base_secs_ts);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Tracked bytes in 1 sec              : %llu\n",
		 disk_cx_sess->dcs_tracked_bytes_per_second);
 #endif
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Tracked / Drained bytes             : %llu / %llu\n",
		 disk_cx_sess->dcs_tracked_bytes,
				 disk_cx_sess->dcs_drained_bytes);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Churn Buckets                       : ");
	 for (idx = 0; idx < DEFAULT_NR_CHURN_BUCKETS; idx++) {
			 len += snprintf(page+len, (INM_PAGESZ - len), "%llu ",
				 disk_cx_sess->dcs_churn_buckets[idx]);
		 }
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "\nMax Peak / Excess Churn             : %llu / %llu\n",
		 disk_cx_sess->dcs_max_peak_churn,
				 disk_cx_sess->dcs_excess_churn);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "First / Last Peak Churn TS          : %llu / %llu\n",
		 disk_cx_sess->dcs_first_peak_churn_ts,
				 disk_cx_sess->dcs_last_peak_churn_ts);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "First / Last NW failure TS          : %llu / %llu\n",
				 disk_cx_sess->dcs_first_nw_failure_ts,
		 disk_cx_sess->dcs_last_nw_failure_ts);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "No. of NW failires                  : %llu\n",
		 disk_cx_sess->dcs_nr_nw_failures);
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "S2 latency                          : %llu\n",
				 disk_cx_sess->dcs_max_s2_latency);
 unlock_session_lock:
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				   driver_ctx->dc_vm_cx_session_lock_flag);
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "History \n");
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Start filtering issued at (sec)     : %llu\n",
		 ctxt->tc_hist.ths_start_flt_ts);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Clear stats issued at (sec)         : %llu\n",
		 ctxt->tc_hist.ths_clrstats_ts);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Clear diffs issued                  : %u\n",
		 ctxt->tc_hist.ths_nr_clrdiffs);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Last Clear diffs issued at (sec)    : %llu\n",
		 ctxt->tc_hist.ths_clrdiff_ts);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Times Resync marked                 : %u\n",
		 ctxt->tc_hist.ths_nr_osyncs);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Last Resync marked at(sec)          : %llu\n",
		 ctxt->tc_hist.ths_osync_ts);
 
	 len += snprintf(page+len, (INM_PAGESZ - len),
		 "Last Resync Error                   : %u\n",
		 ctxt->tc_hist.ths_osync_err);
 
	 len += snprintf(page+len, (INM_PAGESZ - len), "\n");
 
 
	 if (INM_COPYOUT(vol_stat->bufp, page,
		 MIN(vol_stat->buf_len, INM_PAGESZ))) {
		 err("copyout failed");
		 ret = INM_EFAULT;
		 goto out;
	 }
 
 out:
	 if(ctxt)
		 put_tgt_ctxt(ctxt);
	 if (page){
		 INM_KFREE(page, INM_PAGESZ, INM_KERNEL_HEAP);
	 }
	 if (vol_stat){
		 INM_KFREE(vol_stat, sizeof(VOLUME_STATS), INM_KERNEL_HEAP);
	 }
 
	 return ret;
 }
 
 inm_s32_t 
 process_get_volume_stats_v2_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 TELEMETRY_VOL_STATS *telemetry_vol_stats = NULL;
	 int ret = 0;
	 target_context_t *tgt_ctxt = NULL;
	 VOLUME_STATS_DATA *drv_statsp = NULL;
	 VOLUME_STATS_V2 *vol_statsp = NULL;
 
	 telemetry_vol_stats = (TELEMETRY_VOL_STATS *) INM_KMALLOC(
					 sizeof(TELEMETRY_VOL_STATS),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!telemetry_vol_stats) {
		 err("Failed to allocated telemetry_vol_stats\n");
		 ret = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(telemetry_vol_stats, arg, 
					 sizeof(TELEMETRY_VOL_STATS))) {
		 err("Failed to copy into telemetry_vol_stats");
		 ret = -EFAULT;
		 goto out;
	 }
 
	 drv_statsp = &(telemetry_vol_stats->drv_stats);
	 vol_statsp = &(telemetry_vol_stats->vol_stats);
 
	 vol_statsp->VolumeGUID[GUID_SIZE_IN_CHARS-1] = '\0';
 
	 tgt_ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&vol_statsp->VolumeGUID[0]);
	 if (!tgt_ctxt) {
		 err("Failed to get target context for uuid %s",
			 vol_statsp->VolumeGUID);
		 ret = -ENODEV;
		 goto out;
	 }
 
	 drv_statsp->usMajorVersion = VOLUME_STATS_DATA_MAJOR_VERSION;
	 drv_statsp->usMinorVersion = VOLUME_STATS_DATA_MINOR_VERSION;
	 /* Fills up only one volume stats per call */
	 drv_statsp->ulVolumesReturned = 1;
	 drv_statsp->ulNonPagedMemoryLimitInMB = 0;
	 drv_statsp->LockedDataBlockCounter = 0;
 
	 drv_statsp->ulTotalVolumes = driver_ctx->total_prot_volumes;
	 drv_statsp->ulNumProtectedDisk = driver_ctx->total_prot_volumes;
	 drv_statsp->eServiceState = driver_ctx->service_state;
	 if (driver_ctx->dc_tel.dt_blend & DBS_DRIVER_NOREBOOT_MODE)
		 drv_statsp->eDiskFilterMode = NoRebootMode;
	 else
		 drv_statsp->eDiskFilterMode = RebootMode;
	 drv_statsp->LastShutdownMarker = driver_ctx->clean_shutdown;
 
	 drv_statsp->PersistentRegistryCreated = 
			 driver_ctx->dc_tel.dt_persistent_dir_created;
	 drv_statsp->ulDriverFlags = driver_ctx->dc_flags;
 
	 drv_statsp->ulCommonBootCounter = 0;
	 drv_statsp->ullDataPoolSizeAllocated = 
				 (driver_ctx->data_flt_ctx.pages_allocated * PAGE_SIZE);
	 drv_statsp->ullPersistedTimeStampAfterBoot = 
					driver_ctx->dc_tel.dt_timestamp_in_persistent_store;
	 drv_statsp->ullPersistedSequenceNumberAfterBoot =
					driver_ctx->dc_tel.dt_seqno_in_persistent_store;
	 vol_statsp->ullDataPoolSize = 
		  (driver_ctx->tunable_params.data_pool_size << MEGABYTE_BIT_SHIFT);
	 vol_statsp->liDriverLoadTime.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_drv_load_time);
	 vol_statsp->llTimeJumpDetectedTS = 
				 TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				 driver_ctx->dc_tel.dt_time_jump_exp);
	 vol_statsp->llTimeJumpedTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				 driver_ctx->dc_tel.dt_time_jump_cur);
	 vol_statsp->liLastS2StartTime.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_s2_start_time);
	 vol_statsp->liLastS2StopTime.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_s2_stop_time);
	 vol_statsp->liLastAgentStartTime.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_svagent_start_time);
	 vol_statsp->liLastAgentStopTime.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_svagent_stop_time);
	 vol_statsp->liLastTagReq.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_last_tag_request_time);
	 vol_statsp->liStopFilteringAllTimeStamp.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					driver_ctx->dc_tel.dt_unstack_all_time);
 
	 vol_statsp->ullTotalTrackedBytes = tgt_ctxt->tc_bytes_commited_changes;
	 vol_statsp->ulVolumeFlags = tgt_ctxt->tc_flags;
	 vol_statsp->ulVolumeSize.QuadPart = inm_dev_size_get(tgt_ctxt);
 
	 vol_statsp->liVolumeContextCreationTS.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					tgt_ctxt->tc_tel.tt_create_time);
 
	 vol_statsp->liStartFilteringTimeStamp.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_SEC(
					tgt_ctxt->tc_hist.ths_start_flt_ts);
	 vol_statsp->liStartFilteringTimeStampByUser.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					tgt_ctxt->tc_tel.tt_start_flt_time_by_user);
 
	 vol_statsp->liStopFilteringTimeStamp.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					tgt_ctxt->tc_tel.tt_stop_flt_time);
	 vol_statsp->liStopFilteringTimestampByUser.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					tgt_ctxt->tc_tel.tt_user_stop_flt_time);
 
	 vol_statsp->liClearDiffsTimeStamp.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_SEC(
					tgt_ctxt->tc_hist.ths_clrdiff_ts);
	 vol_statsp->liCommitDBTimeStamp.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					tgt_ctxt->tc_tel.tt_commitdb_time);
	 vol_statsp->liGetDBTimeStamp.QuadPart = 
					TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					tgt_ctxt->tc_tel.tt_getdb_time);
 
	 if (INM_COPYOUT(arg, telemetry_vol_stats,
					 sizeof(TELEMETRY_VOL_STATS))) {
		 err("Failed to copyout from telemetry_vol_stats\n");
		 ret = INM_EFAULT;
		 goto out;
	 }
 
 out:    
	 if (tgt_ctxt) {
		 put_tgt_ctxt(tgt_ctxt);
	 }
	 if (telemetry_vol_stats) {
		 INM_KFREE(telemetry_vol_stats, 
				 sizeof(TELEMETRY_VOL_STATS),
				 INM_KERNEL_HEAP);
	 }
 
	 return ret;
 }
 
 inm_s32_t
 process_get_protected_volume_list_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 GET_VOLUME_LIST		*vol_list = NULL; 
	 inm_s32_t		ret = 0;
	 inm_u32_t		len = 0;
	 inm_schar		*lbufp = NULL;
	 target_context_t	*tgt_ctxt = NULL;
	 struct inm_list_head	*ptr = NULL, *nextptr = NULL;
	 inm_u32_t		usr_buf_len = 0;
	 inm_u32_t		unit_guid_len = 0;
	 inm_u32_t		lbuf_len = INM_GUID_LEN_MAX + 2;
 
	 vol_list = (GET_VOLUME_LIST *) INM_KMALLOC(sizeof(GET_VOLUME_LIST),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!vol_list){
		 err("vol_list allocation volume_list ioctl failed\n");
		 ret = INM_ENOMEM;
		 goto out;
	 }
	 if (INM_COPYIN(vol_list, (GET_VOLUME_LIST *) arg, 
						 sizeof(GET_VOLUME_LIST))) {
		 err("copyin failed\n");
		 ret = INM_EFAULT;
		 goto out;
	 }
	 if(vol_list->buf_len == 0){
		 err("allocate some space in user space");
		 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
		 len = inm_calc_len_required(driver_ctx->tgt_list.next); 
		 INM_UP_READ(&(driver_ctx->tgt_list_sem));
		 ret = INM_EAGAIN;
		 goto out;
	 }
	 lbufp = (char *)INM_KMALLOC(lbuf_len, INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!lbufp){
		 err("buffer allocation volume_list ioctl failed\n");
		 ret = INM_ENOMEM;
		 goto out;
	 }
	 usr_buf_len = vol_list->buf_len;
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 inm_list_for_each_safe(ptr, nextptr, &driver_ctx->tgt_list) {
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 if(tgt_ctxt->tc_flags & (VCF_VOLUME_CREATING | 
							 VCF_VOLUME_DELETING)){
			 tgt_ctxt = NULL;
			 continue;
		 }
		 unit_guid_len = snprintf(lbufp, lbuf_len, "%s\n", 
							 tgt_ctxt->tc_guid);
		 if (vol_list->buf_len < (len + unit_guid_len)) {
			 err("insufficient mem allocated by user");
			 ret = INM_EAGAIN;
			 len += inm_calc_len_required(ptr);	
			 break;
		 }
		 if (INM_COPYOUT(vol_list->bufp + len, lbufp,
			 unit_guid_len)) {
				 err("copyout failed\n");
				 ret = INM_EFAULT;
			 break;
		 }
		 len += unit_guid_len;
	 }
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
	 if ( (len+1) > vol_list->buf_len){
		 ret = INM_EAGAIN;
	 }
	 if (INM_COPYOUT(vol_list->bufp + len, "\0",
		 sizeof("\0"))) {
			 err("copyout failed\n");
			 ret = INM_EFAULT;
	 }
 
 out:
	 if (ret == INM_EAGAIN){
		 vol_list->buf_len = len + EXTRA_PROTECTED_VOLUME;
 
		 vol_list->bufp = NULL;
		 if (INM_COPYOUT((GET_VOLUME_LIST *) arg, vol_list,
					 sizeof (GET_VOLUME_LIST))) {
			 err("copyout failed\n");
			 ret = INM_EFAULT;
		 }
	 }
	 if(lbufp){
		 INM_KFREE(lbufp, lbuf_len, INM_KERNEL_HEAP);
	 }
	 if(vol_list){
		 INM_KFREE(vol_list, sizeof(GET_VOLUME_LIST), INM_KERNEL_HEAP);
	 }
	 return (ret);
 }
 
 inm_s32_t
 process_get_set_attr_ioctl(inm_devhandle_t *handle, void __INM_USER *arg)
 {
	 inm_attribute_t		*attr = NULL;
	 inm_s32_t		ret = 0;
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
		 sizeof(inm_attribute_t))){
		 err("Access ok failed");
		 return -EFAULT;
	 }
 
	 attr = (inm_attribute_t *) INM_KMALLOC(sizeof(inm_attribute_t),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!attr){
		 err("attr allocation get_set ioctl failed\n");
		 ret = INM_ENOMEM;
		 goto out;
	 }
	 INM_MEM_ZERO(attr, sizeof(*attr));
 
	 if (INM_COPYIN(attr, arg, sizeof(inm_attribute_t))) {
		 err("copyin failed\n");
		 ret = INM_EFAULT;
		 goto out;
	 }
	 INM_BUG_ON((attr->why != SET_ATTR) && (attr->why != GET_ATTR));
	 if(!strcmp(attr->guid.volume_guid, "common")){
			 ret = common_get_set_attribute_entry(attr);
	 } else {
		 ret = volume_get_set_attribute_entry(attr);
	 }
 
 out:
	 if (attr){
		 INM_KFREE(attr, sizeof(inm_attribute_t), INM_KERNEL_HEAP);
		 attr = NULL;
	 }
	 return ret;
 }
 
 inm_u32_t
 process_boottime_stacking_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("entered");
	 }
	 dbg("boottime stacking during ioctl");
	 init_boottime_stacking();
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 info("leaving");
	 }
	 return 0;
 }
 
 inm_u32_t
 process_mirror_exception_notify_ioctl(inm_devhandle_t *handle, void * arg)
 {
	 char *src_scsi_id = NULL;
	 target_context_t *tgt_ctxt = NULL;
	 inm_resync_notify_info_t *resync_info = NULL;
	 host_dev_ctx_t *hdcp = NULL;
	 inm_irqflag_t lock_flag = 0;
	 inm_u32_t ret = 0;
 
	 dbg("entered");
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 if(driver_ctx->dc_flags & DRV_MIRROR_NOT_SUPPORT){
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
									lock_flag);
		 err("Mirror is not supported as system didn't had any scsi device at driver loading time");
		 return INM_ENOTSUP;
	 }
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								 lock_flag);
 
	 resync_info = (inm_resync_notify_info_t *) INM_KMALLOC(sizeof(*resync_info),
							 INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!resync_info){
		 err("resync_info allocation get_set ioctl failed\n");
		 ret = INM_ENOMEM;
		 goto out;
	 }
	 INM_MEM_ZERO(resync_info, sizeof(*resync_info));
 
	 if (INM_COPYIN(resync_info, (inm_resync_notify_info_t *) arg, 
						 sizeof(*resync_info))) {
		 err("copyin failed\n");
		 ret = INM_EFAULT;
		 goto out;
	 }
	 src_scsi_id = resync_info->rsin_src_scsi_id;
	 if (!strcmp(src_scsi_id, "")){
		 err("NULL scsi id sent to resync nofication ioctl"); 
		 ret = INM_EINVAL;
		 resync_info->rstatus = SRC_DEV_SCSI_ID_ERR;
		 goto out;
	 }
	 INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(src_scsi_id);
	 INM_UP_READ(&driver_ctx->tgt_list_sem);
	 if (!tgt_ctxt) {
		 dbg("Volume is not filtering");
		 resync_info->rstatus = MIRROR_NOT_SETUP;
		 ret = INM_EINVAL;
		 goto out;
	 }
	 hdcp = (host_dev_ctx_t *)(tgt_ctxt->tc_priv);
 
	 if (resync_info->rsin_flag & INM_RESET_RESYNC_REQ_FLAG) {
		 reset_volume_out_of_sync(tgt_ctxt);
		 resync_info->rsin_flag &= ~INM_RESET_RESYNC_REQ_FLAG;
	 }
	 if ((ret = inm_wait_exception_ev(tgt_ctxt, resync_info))){
		 goto out; 
	 }
	 if (INM_COPYOUT((inm_resync_notify_info_t *) arg, resync_info, 
						 sizeof(*resync_info))) {
		 err("copyout failed\n");
		 ret = INM_EFAULT;
	 }
 
 out:
	 dbg("exiting");
	 if(resync_info){
		 INM_KFREE(resync_info, sizeof(*resync_info), INM_KERNEL_HEAP);
	 }
	 if (tgt_ctxt){
		 put_tgt_ctxt(tgt_ctxt);
	 }
	 return ret;
 }
 
 inm_s32_t
 process_get_dmesg(inm_devhandle_t *handle, void * arg)
 {
	 inm_s32_t ret = 0;
 
 #ifdef INM_AIX
	 inm_flush_log_file();
 #endif
 
	 return ret;
 }
 
 inm_s32_t process_mirror_test_heartbeat(inm_devhandle_t *idhp, 
						 void __INM_USER *arg)
 {
	 target_context_t *tgt_ctxt = NULL;
	 SCSI_ID *scsi_id = NULL;
	 inm_irqflag_t lock_flag = 0;
	 inm_s32_t ret = 0;
 
	 dbg("entered");
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	 if(driver_ctx->dc_flags & DRV_MIRROR_NOT_SUPPORT){
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
								 lock_flag);
		 err("Mirror is not supported as system didn't had any scsi device at driver loading time");
		 return INM_ENOTSUP;
	 }
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock,
								 lock_flag);
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg, 
							 sizeof(SCSI_ID))) {
		 err("Read access violation for SCSI_ID");
		 return -EFAULT;
	 }
 
	 scsi_id = (SCSI_ID *)INM_KMALLOC(sizeof(SCSI_ID), INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!scsi_id) {
		 err("INM_KMALLOC failed to allocate memory for SCSI_ID");
		 return -ENOMEM;
	 }
 
	 if (INM_COPYIN(scsi_id, arg, sizeof(SCSI_ID))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(scsi_id, sizeof(SCSI_ID), INM_KERNEL_HEAP);
		 return -EFAULT;
	 }
 
	 scsi_id->scsi_id[INM_MAX_SCSI_ID_SIZE-1] = '\0';
 
	 INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked((char *)&scsi_id->scsi_id[0]);
	 if (!tgt_ctxt) {
		 INM_UP_READ(&driver_ctx->tgt_list_sem);
		 dbg("Failed to get target context from scsi id:%s",
							 scsi_id->scsi_id);
		 INM_KFREE(scsi_id, sizeof(SCSI_ID), INM_KERNEL_HEAP);
		 return 0;
	 }
	 INM_UP_READ(&driver_ctx->tgt_list_sem);
 
	 ret = inm_heartbeat_cdb(tgt_ctxt);
 
	 INM_KFREE(scsi_id, sizeof(SCSI_ID), INM_KERNEL_HEAP);
	 idhp->private_data = NULL;
	 put_tgt_ctxt(tgt_ctxt);
 
	 dbg("leaving");
 
	 return ret;
 }
 
 static void
 print_AT_stat_common(target_context_t *tcp, char *page, inm_s32_t *len)
 {
	 mirror_vol_entry_t *vol_entry = NULL;
	 struct inm_list_head *ptr, *hd, *nextptr;
 
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("entered with tcp %p, page %p, len %p len %d",tcp, page, len, *len);
	 }
	 if(tcp->tc_dev_type == FILTER_DEV_MIRROR_SETUP){
		 (*len) += snprintf((page+(*len)), (INM_PAGESZ - (*len)),
				 "AT name, #IO issued, #successful IOs, #No of Byte written, Status of path, no of ref \n");
		 volume_lock(tcp);
		 hd = &(tcp->tc_dst_list);
		 inm_list_for_each_safe(ptr, nextptr, hd){
			 vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
			 (*len) += snprintf((page+(*len)), (INM_PAGESZ - (*len)), 
				 "%s, %llu, %llu, %llu, %s %d\n", 
				 vol_entry->tc_mirror_guid,
				  vol_entry->vol_io_issued, 
				  vol_entry->vol_io_succeeded, 
				  vol_entry->vol_byte_written, 
				  vol_entry->vol_error?"offline":"online", 
				  INM_ATOMIC_READ(&(vol_entry->vol_ref)));
		 }
		 volume_unlock(tcp);
	 }
	 if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		 dbg("exiting");
	 }
 }
 
 inm_s32_t
 process_get_additional_volume_stats(inm_devhandle_t *handle, void *arg)
 {
	 inm_s32_t ret = -1;
	 VOLUME_STATS_ADDITIONAL_INFO *vsa_infop = NULL;
	 target_context_t *ctxt = NULL;
	 inm_irqflag_t lock_flag = 0;
 
	 if ( !INM_ACCESS_OK(VERIFY_READ, (void __user*)arg, 
				 sizeof(VOLUME_STATS_ADDITIONAL_INFO))) {
		 err( " Read Access Violation for GET_ADDITIONAL_VOLUME_STATS\n");
		 ret = -EFAULT;
		 return (ret);
	 }
 
	 vsa_infop = (VOLUME_STATS_ADDITIONAL_INFO *) INM_KMALLOC(sizeof(VOLUME_STATS_ADDITIONAL_INFO), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!vsa_infop) {
		 ret = -ENOMEM;
		 err("INM_KMALLOC() failed additional stats structure\n");
		 return (ret);
	 }
 
	 INM_MEM_ZERO(vsa_infop, sizeof(VOLUME_STATS_ADDITIONAL_INFO));
 
	 if ( INM_COPYIN( vsa_infop, arg, 
				 sizeof( VOLUME_STATS_ADDITIONAL_INFO ))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(vsa_infop, sizeof( VOLUME_STATS_ADDITIONAL_INFO ), 
							 INM_KERNEL_HEAP);
		 ret = -EFAULT;
		 return (ret);
	 }
 
	 vsa_infop->VolumeGuid.volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&vsa_infop->VolumeGuid.volume_guid[0]);
	 if (!ctxt) {
			 dbg("Failed to get target context from uuid");
		 INM_KFREE(vsa_infop, sizeof( VOLUME_STATS_ADDITIONAL_INFO ), 
							 INM_KERNEL_HEAP);
		 ret = -EINVAL;
		 return (ret);
	 }
	 /* collect the in-core pending changes and set appropriate rpo timestamp */
	 volume_lock(ctxt);
	 vsa_infop->ullTotalChangesPending = ctxt->tc_bytes_pending_changes;
	 vsa_infop->ullOldestChangeTimeStamp = get_rpo_timestamp(ctxt,
			 IOCTL_INMAGE_GET_ADDITIONAL_VOLUME_STATS, NULL);
	 volume_unlock(ctxt);
 
	 /* Get the current driver time stamp */
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, lock_flag);
	 vsa_infop->ullDriverCurrentTimeStamp = driver_ctx->last_time_stamp;
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, lock_flag);
	 /* can't negative RPOs */
	 if (vsa_infop->ullDriverCurrentTimeStamp < 
					 vsa_infop->ullOldestChangeTimeStamp) {
		 vsa_infop->ullDriverCurrentTimeStamp = 
					 vsa_infop->ullOldestChangeTimeStamp;
	 }
 
	 /* Add outstanding bitmap changes to the total pending changes */
	 if (ctxt->tc_bp && ctxt->tc_bp->volume_bitmap && 
				 ctxt->tc_bp->volume_bitmap->bitmap_api) {
		 bitmap_api_t *bapi = ctxt->tc_bp->volume_bitmap->bitmap_api;
 
		 INM_DOWN(&bapi->sem);
		 vsa_infop->ullTotalChangesPending +=
			 bitmap_api_get_dat_bytes_in_bitmap(bapi, NULL);	
		 INM_UP(&bapi->sem);
	 }
	 put_tgt_ctxt(ctxt);
	 ret = 0;
 
	 if ( INM_COPYOUT( (void*) arg, vsa_infop, 
				 sizeof(VOLUME_STATS_ADDITIONAL_INFO))) {
		 err("INM_COPYOUT failed");
		 INM_KFREE(vsa_infop, sizeof( VOLUME_STATS_ADDITIONAL_INFO ), 
							 INM_KERNEL_HEAP);
		 ret =  -EFAULT;
		 return (ret);
	 }
	 INM_KFREE(vsa_infop, sizeof( VOLUME_STATS_ADDITIONAL_INFO ), 
							 INM_KERNEL_HEAP);
 
	 return (ret);
 }
 
 inm_s32_t
 process_get_volume_latency_stats(inm_devhandle_t *handle, void *arg)
 {
	 inm_s32_t ret = -1;
	 VOLUME_LATENCY_STATS *vol_latstatsp = NULL;
	 target_context_t *ctxt = NULL;
 
	 if ( !INM_ACCESS_OK(VERIFY_READ, (void __user*)arg, 
					 sizeof(VOLUME_LATENCY_STATS))) {
		 err( " Read Access Violation for GET_ADDITIONAL_VOLUME_STATS\n");
		 ret = -EFAULT;
		 return (ret);
	 }
 
	 vol_latstatsp = (VOLUME_LATENCY_STATS *) INM_KMALLOC(sizeof(*vol_latstatsp), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!vol_latstatsp) {
		 ret = -ENOMEM;
		 err("INM_KMALLOC() failed additional stats structure\n");
		 return (ret);
	 }
 
	 INM_MEM_ZERO(vol_latstatsp, sizeof(VOLUME_LATENCY_STATS));
 
	 if ( INM_COPYIN(vol_latstatsp, arg, sizeof(VOLUME_LATENCY_STATS))) {
		 err("INM_COPYIN failed");
		 INM_KFREE(vol_latstatsp, sizeof(VOLUME_LATENCY_STATS),
							 INM_KERNEL_HEAP);
		 ret = -EFAULT;
		 return (ret);
	 }
 
	 vol_latstatsp->VolumeGuid.volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
 
 
	 ctxt = get_tgt_ctxt_from_uuid_nowait((char *)&vol_latstatsp->VolumeGuid.volume_guid[0]);
	 if(!ctxt) {
		 dbg("Failed to get target context from uuid");
		 INM_KFREE(vol_latstatsp, sizeof( VOLUME_LATENCY_STATS ), 
							 INM_KERNEL_HEAP);
		 ret = -EINVAL;
		 return (ret);
	 }
	 volume_lock(ctxt);
	 retrieve_volume_latency_stats(ctxt, vol_latstatsp);
	 volume_unlock(ctxt);
	 put_tgt_ctxt(ctxt);
	 ret = 0;
 
	 if ( INM_COPYOUT( (void*) arg, vol_latstatsp, 
					 sizeof(VOLUME_LATENCY_STATS))) {
		 err("INM_COPYOUT failed");
		 INM_KFREE(vol_latstatsp, sizeof( VOLUME_LATENCY_STATS ), 
							 INM_KERNEL_HEAP);
		 ret =  -EFAULT;
		 return (ret);
	 }
	 INM_KFREE(vol_latstatsp, sizeof( VOLUME_LATENCY_STATS ), 
							 INM_KERNEL_HEAP);
 
	 return (ret);
 }
 
 inm_s32_t
 process_bitmap_stats_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 VOLUME_BMAP_STATS *vbstatsp;
	 VOLUME_GUID *vguidp = NULL;
	 bmap_bit_stats_t *bbsp = NULL;
	 inm_s32_t ret = INM_EFAULT;
	 volume_bitmap_t *vbmap = NULL;
	 target_context_t *tcp = NULL;
 
	 vbstatsp = (VOLUME_BMAP_STATS *) INM_KMALLOC(sizeof(*vbstatsp), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!vbstatsp) {
		 err("INM_KMALLOC() failed\n");
		 return -ENOMEM;
	 }
 
	 INM_MEM_ZERO(vbstatsp, sizeof(*vguidp));
 
	 if (INM_COPYIN(vbstatsp, arg, sizeof(*vbstatsp))) {
		 err("copyin failed\n");
		 INM_KFREE(vbstatsp, sizeof(*vbstatsp), INM_KERNEL_HEAP);
		 ret = INM_EFAULT;
		 return (ret);
	 }
	 tcp = get_tgt_ctxt_from_uuid_nowait(vbstatsp->VolumeGuid.volume_guid);
	 if(!tcp) {
		 err("no target context for %s\n", 
					 vbstatsp->VolumeGuid.volume_guid);
		 INM_KFREE(vbstatsp, sizeof(*vbstatsp), INM_KERNEL_HEAP);
		 ret = INM_EFAULT;
		 return ret;
	 }
 
	 bbsp = (bmap_bit_stats_t *) INM_KMALLOC(sizeof(*bbsp), INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!bbsp) {
		 err("INM_KMALLOC() failed\n");
		 put_tgt_ctxt(tcp);
		 INM_KFREE(vbstatsp, sizeof(*vbstatsp), INM_KERNEL_HEAP);
		 return -ENOMEM;
 
	 }
	 if (tcp->tc_bp) {
		 vbmap = tcp->tc_bp->volume_bitmap;
		 if (vbmap && vbmap->bitmap_api) {
			 vbstatsp->bmap_data_sz =
				 bitmap_api_get_dat_bytes_in_bitmap(vbmap->bitmap_api, bbsp);
			 vbstatsp->nr_dbs = (inm_u32_t)bbsp->bbs_nr_dbs;
			 vbstatsp->bmap_gran = bbsp->bbs_bmap_gran;
		 }
	 }	
 
	 info("Volume Name : %s \n", vbstatsp->VolumeGuid.volume_guid);
	 info("bitmap gran : %lld \n", bbsp->bbs_bmap_gran);
	 info("bitmap dblks: %d\n", bbsp->bbs_nr_dbs);
 
	 INM_KFREE(bbsp, sizeof(*bbsp), INM_KERNEL_HEAP);
	 put_tgt_ctxt(tcp);
	 ret = 0;
 
	 if ( INM_COPYOUT( (void*) arg, vbstatsp, sizeof(VOLUME_BMAP_STATS))) {
		 err("INM_COPYOUT failed");
		 INM_KFREE(vbstatsp, sizeof( VOLUME_BMAP_STATS ), 
							 INM_KERNEL_HEAP);
		 ret =  -EFAULT;
		 return (ret);
	 }
	 INM_KFREE(vbstatsp, sizeof(*vbstatsp), INM_KERNEL_HEAP);
 
	 return (ret);
 }
 
 inm_s32_t
 process_set_involflt_verbosity(inm_devhandle_t *handle, void *arg)
 {
	 inm_u32_t ioc_verbose = 0;
	 inm_s32_t ret = 0;
 
	 if (INM_COPYIN(&ioc_verbose, arg, sizeof(inm_u32_t))) {
		 err("copyin failed\n");
		 ret = INM_EFAULT;
		 return (ret);
	 }
	 if (ioc_verbose < 1) {
		 inm_verbosity = 0;
		 goto out;
	 }
	 inm_verbosity |= INM_DEBUG_ONLY;
	 if (ioc_verbose < 2) {
		 goto out;
	 }
	 inm_verbosity |= INM_IDEBUG;
	 if (ioc_verbose < 3) {
		 goto out;
	 }
	 inm_verbosity |= INM_IDEBUG_META;
	 if (ioc_verbose < 4) {
		 goto out;
	 }
	 inm_verbosity |= INM_IDEBUG_MIRROR;
	 if (ioc_verbose < 5) {
		 goto out;
	 }
	 inm_verbosity |= INM_IDEBUG_MIRROR_IO;
	 if (ioc_verbose < 6) {
		 goto out;
	 }
	 inm_verbosity |= INM_IDEBUG_REF;
	 if (ioc_verbose < 7) {
		 goto out;
	 }
	 inm_verbosity |= INM_IDEBUG_IO;
 
 out:
	 return ret;
 }
 
 inm_s32_t
 process_tag_volume_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg)
 {
	 tag_info_t_v2 *tag_vol = NULL;
	 int ret = 0;
	 int numvol = 0;
	 int no_of_vol_tags_done = 0;
	 inm_s32_t error = 0;
	 tag_info_t *tag_list = NULL;
	 int commit_pending = TAG_COMMIT_PENDING;
	 inm_u32_t vacp_app_tag_commit_timeout = 0;
	 unsigned long lock_flag = 0;
	 int set_tag_guid = 0;
 
	 dbg("entered process_tag_volume_ioctl");
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
							sizeof(tag_info_t_v2))) {
		 err("Read access violation for tag_info_t_v2");
		 ret = -EFAULT;
		 goto out;
	 }
 
	 tag_vol = (tag_info_t_v2 *)INM_KMALLOC(sizeof(tag_info_t_v2),
					   INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if(!tag_vol) {
		 err("INM_KMALLOC failed to allocate memory for tag_info_t_v2");
		 ret = -ENOMEM;
		 goto out;
	 }
 
	 if(INM_COPYIN(tag_vol, arg, sizeof(tag_info_t_v2))) {
		 err("INM_COPYIN failed");
		 ret = -EFAULT;
		 goto out_err;
	 }
  
	 if(tag_vol->nr_tags <= 0) {
		 err("Tag Input Failed: number of tags can't be zero or negative");
		 ret = -EINVAL;
		 goto out_err;
	 }
 
	 if(tag_vol->nr_vols <= 0 &&
	 !(tag_vol->flags & TAG_ALL_PROTECTED_VOLUME_IOBARRIER)) {
		 err("Tag Input Failed: Number of volumes can't be zero or negative");
		 ret = -EINVAL;
		 goto out_err;
	 }
 
	 arg = tag_vol->tag_names;
	 tag_vol->tag_names = NULL;
 
	 tag_vol->tag_names = (tag_names_t *)INM_KMALLOC(tag_vol->nr_tags *
				 sizeof(tag_names_t), INM_KM_SLEEP, 
				 INM_KERNEL_HEAP);
	 if(!tag_vol->tag_names) {
		 err("INM_KMALLOC failed to allocate memory for tag_names_t");
		 ret = -EFAULT;
		 goto out_err;
	 }
 
	 if(!INM_ACCESS_OK(VERIFY_READ, (void __INM_USER *)arg,
				  tag_vol->nr_tags * sizeof(tag_names_t))) {
		 err("Read access violation for tag_names_t");
		 ret = -EFAULT;
		 goto out_err_vol;
	 }
 
 
	 if(INM_COPYIN(tag_vol->tag_names, arg, 
				 tag_vol->nr_tags * sizeof(tag_names_t))) {
		 err("INM_COPYIN failed");
		 ret = -EFAULT;
		 goto out_err_vol;
	 }
 
	 /* now build the tag list which will be use for set of given volumes */
	 tag_list = build_tag_vol_list(tag_vol, &error);
	 if(error | !tag_list) {
		 err("build tag volume list failed for the volume");
		 ret = error;
		 goto out_err_vol;
	 }
 
 
	 arg = tag_vol->vol_info;
	 tag_vol->vol_info = NULL;
	 
	 INM_DOWN(&driver_ctx->dc_cp_mutex);
 
	 if (driver_ctx->dc_cp != INM_CP_NONE) {  /* Active CP */
		 if (INM_MEM_CMP(driver_ctx->dc_cp_guid, tag_vol->tag_guid,
					 sizeof(driver_ctx->dc_cp_guid))) {
			 err("GUID mismatch");
			 ret = -EINVAL;
			 goto out_unlock;
		 }
 
		 if (driver_ctx->dc_cp & INM_CP_TAG_COMMIT_PENDING) {
			 err("Already Tagged");
			 ret = -EINVAL;
			 goto out_unlock;
		 }
	 }
 
	 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	 if (driver_ctx->dc_tag_drain_notify_guid &&
		 driver_ctx->dc_cp_guid[0] == NULL &&
		 !INM_MEM_CMP(tag_vol->tag_guid,
					  driver_ctx->dc_tag_drain_notify_guid,
					  GUID_LEN)) {
		 set_tag_guid = 1;
		 memcpy_s(&driver_ctx->dc_cp_guid, 
				 sizeof(driver_ctx->dc_cp_guid),
				 tag_vol->tag_guid, sizeof(tag_vol->tag_guid));
	 }
	 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
 
	 if ((tag_vol->flags & TAG_ALL_PROTECTED_VOLUME_IOBARRIER) ==
					   TAG_ALL_PROTECTED_VOLUME_IOBARRIER) {
 #ifdef INM_LINUX
		 if (driver_ctx->dc_cp == INM_CP_CRASH_ACTIVE) {
			 dbg("issuing tag");
			 ret = iobarrier_issue_tag_all_volume(tag_list, 
					 tag_vol->nr_tags, commit_pending, 
					 NULL);
			 if(ret) {
				 dbg("Failed to tag all the volume\n");
			 } else
				 update_cx_with_tag_success();
		 } else {
			 err("Barrier not created");
			 dbg("cp state = %d", driver_ctx->dc_cp);
			 ret = -EINVAL;
		 }
 #else
		 err("Crash consistency not supported on non-Linux platforms");
		 ret = -EINVAL;;
 #endif
		 goto out_unlock;
	 }
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	 vacp_app_tag_commit_timeout = driver_ctx->tunable_params.vacp_app_tag_commit_timeout;
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
 
	 /*
	 * If we need to start the timer, check for timeout sanity
	 */
	 if (driver_ctx->dc_cp == INM_CP_NONE) {
		 if (tag_vol->timeout <= 0 ||
			 tag_vol->timeout > vacp_app_tag_commit_timeout) { 
			 err("Tag Input Failed: Invalid timeout");
			 ret = -EINVAL;
			 goto out_unlock;
		 }
	 }
 
	 /* alloc a buffer and reuse it to store the volume info for a set of volumes */
	 tag_vol->vol_info = (volume_info_t *)INM_KMALLOC(
					  sizeof(volume_info_t),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
 
	 if(!tag_vol->vol_info) {
		 err("INM_KMALLOC failed to allocate memory for volume_info_t");
		 ret = -EFAULT;
		 goto out_unlock;
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
		 ret = process_tag_volume(tag_vol, tag_list, commit_pending);
		 if(ret) {
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
 
	 if (no_of_vol_tags_done) {
		 if(no_of_vol_tags_done ==  tag_vol->nr_vols) {
			 dbg("Tagged all volumes");
			 ret = INM_TAG_SUCCESS;
		 } else {
			 dbg("Volumes partially tagged");
			 ret = INM_TAG_PARTIAL;
		 }
 #ifdef INM_LINUX
		 /* 
		  * If no kernel fs freeze, start timer to
		  * revoke tags on timeout
		  */
		 if (driver_ctx->dc_cp == INM_CP_TAG_COMMIT_PENDING) {
			 set_tag_guid = 0;
			 memcpy_s(&driver_ctx->dc_cp_guid, 
					 sizeof(driver_ctx->dc_cp_guid),
					 tag_vol->tag_guid, 
					 sizeof(tag_vol->tag_guid));
			 start_cp_timer(tag_vol->timeout, 
						 inm_fvol_list_thaw_on_timeout);
		 }
 #endif
	 } else {
		 INM_BUG_ON(ret >= 0);
	 }
 
	 dbg("no_of_vol_tags_done [%d], no of volumes [%d]", 
					 no_of_vol_tags_done,tag_vol->nr_vols);
 
 out_unlock:
	 INM_UP(&driver_ctx->dc_cp_mutex);
 
 out:
	 if (set_tag_guid)
		  INM_MEM_ZERO(driver_ctx->dc_cp_guid, 
					  sizeof(driver_ctx->dc_cp_guid));
 
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
 
 inm_s32_t 
 process_get_blk_mq_status_ioctl(inm_devhandle_t *handle, void *arg)
 {
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	 inm_s32_t ret = 0;
	 inm_block_device_t *bdev = NULL;
	 struct request_queue *q = NULL;
	 BLK_MQ_STATUS *blk_mq_status = NULL;
 #if defined(INM_HANDLE_FOR_BDEV_ENABLED)
	 struct bdev_handle *bdev_handle = NULL;
 #elif defined(INM_FILP_FOR_BDEV_ENABLED)
	 struct file *filp = NULL;
 #endif
 
	 if (!INM_ACCESS_OK(VERIFY_READ | VERIFY_WRITE, (void __user*)arg,
						sizeof(BLK_MQ_STATUS))) {
		 err( "Access Violation for GET_BLK_MQ_STATUS");
		 ret = -EFAULT;
		 return ret;
	 }
 
	 blk_mq_status = (BLK_MQ_STATUS*) INM_KMALLOC(sizeof(BLK_MQ_STATUS), 
						 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!blk_mq_status) {
		 ret = -ENOMEM;
		 err("INM_KMALLOC failed to allocate blk_mq_status");
		 return ret;
	 }
 
	 INM_MEM_ZERO(blk_mq_status, sizeof(BLK_MQ_STATUS));
 
	 if (INM_COPYIN(blk_mq_status, arg, sizeof(BLK_MQ_STATUS))) {
		 err("INM_COPYIN failed");
		 ret = -EFAULT;
		 goto ERR_EXIT;
	 }
 
	 blk_mq_status->VolumeGuid.volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
	 blk_mq_status->blk_mq_enabled = 0;
 
	 dbg("Device path: %s", blk_mq_status->VolumeGuid.volume_guid);
 #if defined(INM_HANDLE_FOR_BDEV_ENABLED)
	 bdev_handle = inm_bdevhandle_open_by_dev_path(blk_mq_status->VolumeGuid.volume_guid,
			 FMODE_READ);
	 if (bdev_handle) {
		 bdev = bdev_handle->bdev;
	 }
	 else {
 #elif defined(INM_FILP_FOR_BDEV_ENABLED)
	 filp = inm_file_open_by_dev_path(blk_mq_status->VolumeGuid.volume_guid,
			 FMODE_READ);
	 if (filp) {
		 bdev = file_bdev(filp);
	 }
	 else {
 
 #else
	 bdev = open_by_dev_path(blk_mq_status->VolumeGuid.volume_guid, 0);
	 if (!bdev) {
 #endif
		 dbg("Failed to convert dev path (%s) to bdev", 
			 blk_mq_status->VolumeGuid.volume_guid);
		 ret = -ENODEV;
		 goto ERR_EXIT;
	 }
 
	 q = bdev_get_queue(bdev);
	 if (q->mq_ops != NULL) {
		 blk_mq_status->blk_mq_enabled = 1;
	 }
 
	 if (INM_COPYOUT(arg, blk_mq_status, sizeof(BLK_MQ_STATUS))) {
		 err("copyout failed");
		 ret = INM_EFAULT;
	 }
 
 ERR_EXIT:
 #if defined(INM_HANDLE_FOR_BDEV_ENABLED)
	 if (bdev_handle != NULL)
		 close_bdev_handle(bdev_handle);
 #elif defined(INM_FILP_FOR_BDEV_ENABLED)
	 if (filp != NULL)
		 close_file(filp);
 #else
	 if (bdev != NULL)
		 close_bdev(bdev, FMODE_READ);
 #endif
	 if (blk_mq_status != NULL)
		 INM_KFREE(blk_mq_status, sizeof(BLK_MQ_STATUS), 
							 INM_KERNEL_HEAP);
 
	 return ret;
 #else
	 return INM_ENOTSUP;
 #endif
 }
 
 inm_s32_t
 process_replication_state_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 inm_s32_t error = 0;
	 replication_state_t *rep = NULL;
	 target_context_t *ctxt = NULL;
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg, 
						sizeof(replication_state_t))) {
		 err( "Access Violation for replication_state_t");
		 error = -EFAULT;
		 goto out;
	 }
 
	 rep = (replication_state_t *)INM_KMALLOC(sizeof(replication_state_t), 
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!rep) {
		 error = -ENOMEM;
		 err("INM_KMALLOC failed to allocate replication_state_t");
		 goto out;
	 }
 
	 if (INM_COPYIN(rep, arg, sizeof(replication_state_t))) {
		 err("copyin failed for replication_state_t");
		 error = -EFAULT;
		 goto out;
	 }
 
	 if (!(rep->ulFlags & REPLICATION_STATES_SUPPORTED)) {
		 err("Unsupported flag %llu", rep->ulFlags);
		 error = -EINVAL;
		 goto out;
	 }
	 
	 ctxt = get_tgt_ctxt_from_uuid(rep->DeviceId.volume_guid);
	 if (!ctxt) {
		 err("Cannot find %s to set DS throttle", 
						 rep->DeviceId.volume_guid);
		 error = -EFAULT;
		 goto out;
	 }
 
	 volume_lock(ctxt);
	 if (!ctxt->tc_tel.tt_ds_throttle_start ||
			 (ctxt->tc_tel.tt_ds_throttle_stop != 
				  TELEMETRY_THROTTLE_IN_PROGRESS)) {
		 telemetry_set_dbs(&ctxt->tc_tel.tt_blend, 
						 DBS_DIFF_SYNC_THROTTLE);
		 get_time_stamp(&ctxt->tc_tel.tt_ds_throttle_start);
		 ctxt->tc_tel.tt_ds_throttle_stop = 
						 TELEMETRY_THROTTLE_IN_PROGRESS;
	 }
	 volume_unlock(ctxt);
 
	 put_tgt_ctxt(ctxt);
 
 out:
	 if (rep)
		 INM_KFREE(rep, sizeof(replication_state_t), INM_KERNEL_HEAP);
 
	 return error;
 }
 
 inm_s32_t
 process_name_mapping_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 inm_s32_t error = 0;
	 vol_name_map_t *vnmap= NULL;
	 target_context_t *ctxt = NULL;
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg, 
						sizeof(vol_name_map_t))) {
		 err( "Access Violation for vol_name_map_t");
		 error = -EFAULT;
		 goto out;
	 }
 
	 vnmap = (vol_name_map_t *)INM_KMALLOC(sizeof(vol_name_map_t), 
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!vnmap) {
		 error = -ENOMEM;
		 err("INM_KMALLOC failed to allocate vol_name_map_t");
		 goto out;
	 }
 
	 if (INM_COPYIN(vnmap, arg, sizeof(vol_name_map_t))) {
		 err("copyin failed for vol_name_map_t");
		 error = -EFAULT;
		 goto out;
	 }
 
	 if (!(vnmap->vnm_flags & INM_VOL_NAME_MAP_GUID) &&
		 !(vnmap->vnm_flags & INM_VOL_NAME_MAP_PNAME)) {
		 err("Request flag not set");
		 error = -EINVAL;
		 goto out;
	 }
 
	 vnmap->vnm_request[sizeof(vnmap->vnm_request) - 1] = '\0';
 
	 if (vnmap->vnm_flags & INM_VOL_NAME_MAP_GUID)
		 ctxt = get_tgt_ctxt_from_uuid_nowait(vnmap->vnm_request);
	 else
		 ctxt = get_tgt_ctxt_from_name_nowait(vnmap->vnm_request);
 
	 if (!ctxt) {
		 err("Cannot find %s for name mapping", vnmap->vnm_request);
		 error = -ENODEV;
		 goto out;
	 }
 
	 if (vnmap->vnm_flags & INM_VOL_NAME_MAP_GUID)
		 strcpy_s(vnmap->vnm_response, sizeof(vnmap->vnm_response),
				  ctxt->tc_pname);
	 else 
		 strcpy_s(vnmap->vnm_response, sizeof(vnmap->vnm_response),
				  ctxt->tc_guid); 
			  
	 put_tgt_ctxt(ctxt);
 
	 if (INM_COPYOUT(arg, vnmap, sizeof(vol_name_map_t))) {
		 err("copyout failed");
		 error = INM_EFAULT;
	 }
 
 out:
	 if (vnmap)
		 INM_KFREE(vnmap, sizeof(vol_name_map_t), INM_KERNEL_HEAP);
 
	 return error;
 }
 
 inm_s32_t process_commitdb_fail_trans_ioctl(inm_devhandle_t *idhp, void *arg)
 {
	 COMMIT_DB_FAILURE_STATS *cdf_stats = NULL;
	 target_context_t        *ctxt = (target_context_t *)idhp->private_data;
	 vm_cx_session_t         *vm_cx_sess;
	 disk_cx_session_t       *disk_cx_sess;
	 inm_s32_t               error = 0;
 
	 if (!ctxt) {
		 err("commitdb_fail_trans ioctl is called with file private as NULL");
		 error = INM_EINVAL;
		 goto out;
	 }
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg,
						sizeof(COMMIT_DB_FAILURE_STATS))) {
		 err( "Access Violation for COMMIT_DB_FAILURE_STATS");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 cdf_stats = INM_KMALLOC(sizeof(COMMIT_DB_FAILURE_STATS), INM_KM_SLEEP,
								INM_KERNEL_HEAP);
	 if (!cdf_stats) {
		 err("failed to allocate COMMIT_DB_FAILURE_STATS");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(cdf_stats, arg, sizeof(COMMIT_DB_FAILURE_STATS))) {
		 err("copyin failed for COMMIT_DB_FAILURE_STATS");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if(is_target_filtering_disabled(ctxt)) {
		 dbg("commitdb_fail_trans ioctl failed as filtering is not enabled for"
			 " %s", cdf_stats->DeviceID.volume_guid);
		 error = INM_EBUSY;
		 goto out;
	 }
 
	 get_tgt_ctxt(ctxt);
 
	 vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	 disk_cx_sess = &ctxt->tc_disk_cx_session;
 
	 volume_lock(ctxt);
	 ctxt->tc_s2_latency_base_ts = 0;
	 volume_unlock(ctxt);
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
	 if (vm_cx_sess->vcs_flags & VCS_CX_SESSION_STARTED &&
			 !(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED)&&
			 disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED) {
		 change_node_t *chg_node = ctxt->tc_pending_confirm;
 
		 if (chg_node && (chg_node->transaction_id == 
					 cdf_stats->ulTransactionID)) {
			 if (cdf_stats->ullFlags & COMMITDB_NETWORK_FAILURE) {
				 disk_cx_sess->dcs_nr_nw_failures++;
				 disk_cx_sess->dcs_last_nw_failure_error_code =
						  cdf_stats->ullErrorCode;
				 get_time_stamp(&(disk_cx_sess->dcs_last_nw_failure_ts));
				 if (!disk_cx_sess->dcs_first_nw_failure_ts)
					 disk_cx_sess->dcs_first_nw_failure_ts =
						 disk_cx_sess->dcs_last_nw_failure_ts;
			 }
		 }
	 }
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				   driver_ctx->dc_vm_cx_session_lock_flag);
 
	 put_tgt_ctxt(ctxt);
 
 out:
	 if (cdf_stats)
		 INM_KFREE(cdf_stats, sizeof(COMMIT_DB_FAILURE_STATS), 
							 INM_KERNEL_HEAP);
 
	 return error;
 }
 
 inm_s32_t validate_output_disk_buffer(void *device_list_arg,
					 inm_u32_t num_protected_disks,
					 inm_u32_t num_output_disks,
					 inm_u32_t *num_output_disks_occupied,
					 inm_list_head_t *disk_cx_stats_list)
 {
	 inm_s32_t              error = 0;
	 disk_cx_stats_info_t   *disk_cx_stats_info = NULL;
	 DEVICE_CXFAILURE_STATS *dev_cx_stats;
	 VOLUME_GUID            *guid = NULL;
	 target_context_t       *tgt_ctxt = NULL;
	 inm_list_head_t        *ptr;
	 inm_list_head_t        *disk_cx_stats_ptr;
	 int                    idx;
	 int                    found;
	 int                    num_out_disks = 0;
 
	 for (idx = 1; idx <= num_output_disks; idx++) {
		 disk_cx_stats_info = INM_KMALLOC(sizeof(disk_cx_stats_info_t),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
		 if (!disk_cx_stats_info) {
			 err("Failed to allocate disk_cx_stats_info_t");
			 error = INM_ENOMEM;
			 goto out;
		 }
 
		 INM_MEM_ZERO(disk_cx_stats_info, sizeof(disk_cx_stats_info_t));
		 inm_list_add_tail(&disk_cx_stats_info->dcsi_list, 
							 disk_cx_stats_list);
	 }
 
	 guid = INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!guid) {
		 err("Failed to allocate VOLUME_GUID");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 while (num_protected_disks) {
		 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)device_list_arg,
							  sizeof(VOLUME_GUID))) {
			 err( "Access Violation for VOLUME_GUID");
			 error = INM_EFAULT;
			 goto out;
		 }
 
		 if (INM_COPYIN(guid, device_list_arg, sizeof(VOLUME_GUID))) {
			 err("copyin failed for VOLUME_GUID");
			 error = INM_EFAULT;
			 goto out;
		 }
 
		 disk_cx_stats_info = inm_list_entry(disk_cx_stats_list->prev,
					 disk_cx_stats_info_t, dcsi_list);
		 inm_list_del(&disk_cx_stats_info->dcsi_list);
 
		 disk_cx_stats_info->dcsi_valid = 1;
		 dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
 
		 memcpy_s(&dev_cx_stats->DeviceId, sizeof(VOLUME_GUID), guid,
								 sizeof(VOLUME_GUID));
		 dev_cx_stats->ullFlags |= DISK_CXSTATUS_DISK_NOT_FILTERED;
		 inm_list_add(&disk_cx_stats_info->dcsi_list, 
							 disk_cx_stats_list);
		 num_out_disks++;
 
		 device_list_arg += sizeof(VOLUME_GUID);
		 num_protected_disks--;
	 }
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 for(ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
					 ptr = ptr->next, tgt_ctxt = NULL) {
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 if (tgt_ctxt->tc_flags & (VCF_VOLUME_CREATING | 
							 VCF_VOLUME_DELETING))
			 continue;
 
		 found = 0;
		 for (disk_cx_stats_ptr = disk_cx_stats_list->next;
				  disk_cx_stats_ptr != disk_cx_stats_list;
				  disk_cx_stats_ptr = disk_cx_stats_ptr->next) {
			 disk_cx_stats_info = inm_list_entry(disk_cx_stats_ptr,
					   disk_cx_stats_info_t, dcsi_list);
			 dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
 
			 if (!disk_cx_stats_info->dcsi_valid)
				 break;
 
			 if (!strcmp(tgt_ctxt->tc_pname,
					dev_cx_stats->DeviceId.volume_guid)) {
				 dev_cx_stats->ullFlags &= 
					 ~DISK_CXSTATUS_DISK_NOT_FILTERED;
				 found = 1;
				 break;
			 }
		 }
 
		 if (found)
			 continue;
 
		 if (num_out_disks == num_output_disks) {
			 INM_UP_READ(&(driver_ctx->tgt_list_sem));
			 error = INM_EAGAIN;
			 goto out;
		 }
 
		 disk_cx_stats_info = inm_list_entry(disk_cx_stats_list->prev,
					 disk_cx_stats_info_t, dcsi_list);
		 inm_list_del(&disk_cx_stats_info->dcsi_list);
 
		 disk_cx_stats_info->dcsi_valid = 1;
		 dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
 
		 strcpy_s(dev_cx_stats->DeviceId.volume_guid, GUID_SIZE_IN_CHARS,
								   tgt_ctxt->tc_pname);
		 inm_list_add(&disk_cx_stats_info->dcsi_list, disk_cx_stats_list);
		 num_out_disks++;
	 }
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 *num_output_disks_occupied = num_out_disks;
 
 out:
	 if (guid)
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
 
	 return error;
 }
 
 inm_s32_t process_get_cxstatus_notify_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 GET_CXFAILURE_NOTIFY   *get_cx_notify = NULL;
	 VM_CXFAILURE_STATS     *vm_cx_stats = NULL;
	 void                   *device_list_arg;
	 void                   *disk_cx_stats_arg;
	 inm_list_head_t        disk_cx_stats_list;
	 inm_list_head_t        *ptr;
	 inm_list_head_t        *disk_cx_stats_ptr;
	 inm_s32_t              error = 0;
	 vm_cx_session_t        *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	 disk_cx_session_t      *disk_cx_sess;
	 inm_u32_t              num_output_disks;
	 inm_u32_t              num_output_disks_occupied = 0;
	 disk_cx_stats_info_t   *disk_cx_stats_info = NULL;
	 DEVICE_CXFAILURE_STATS *dev_cx_stats;
	 inm_u64_t              flags;
	 target_context_t       *tgt_ctxt;
	 int                    found;
	 int                    ret;
 
	 INM_INIT_LIST_HEAD(&disk_cx_stats_list);
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg,
					   sizeof(GET_CXFAILURE_NOTIFY))) {
		 err( "Access Violation for GET_CXFAILURE_NOTIFY");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 get_cx_notify = INM_KMALLOC((sizeof(GET_CXFAILURE_NOTIFY) -
					  sizeof(VOLUME_GUID)),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!get_cx_notify) {
		 err("failed to allocate GET_CXFAILURE_NOTIFY");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(get_cx_notify, arg, (sizeof(GET_CXFAILURE_NOTIFY) - 
						 sizeof(VOLUME_GUID)))) {
		 err("copyin failed for GET_CXFAILURE_NOTIFY");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (!get_cx_notify->ulNumberOfProtectedDisks) {
		 err("GET_CXFAILURE_NOTIFY: Number of protected disks can't be zero");
		 error = INM_EINVAL;
	 }
 
	 if (!get_cx_notify->ulNumberOfOutputDisks) {
		 err("GET_CXFAILURE_NOTIFY: Number of output disks can't be zero");
		 error = INM_EINVAL;
	 }
 
	 if (get_cx_notify->ulNumberOfOutputDisks <
				 get_cx_notify->ulNumberOfProtectedDisks) {
		 err("GET_CXFAILURE_NOTIFY: Number of output disks can't be less than"
					 "  number of protected disks");
		 error = INM_EINVAL;
	 }
 
	 vm_cx_stats = INM_KMALLOC((sizeof(VM_CXFAILURE_STATS) -
					 sizeof(DEVICE_CXFAILURE_STATS)),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!vm_cx_stats) {
		 err("failed to allocate VM_CXFAILURE_STATS");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 INM_MEM_ZERO(vm_cx_stats, sizeof(VM_CXFAILURE_STATS) -
					 sizeof(DEVICE_CXFAILURE_STATS));
 
	 device_list_arg = arg + sizeof(GET_CXFAILURE_NOTIFY) - 
					 sizeof(VOLUME_GUID);
	 num_output_disks = get_cx_notify->ulNumberOfOutputDisks;
	 error = validate_output_disk_buffer(device_list_arg,
				 get_cx_notify->ulNumberOfProtectedDisks,
				 get_cx_notify->ulNumberOfOutputDisks,
				 &num_output_disks_occupied,
				 &disk_cx_stats_list);
	 if (error)
		 goto out;
 
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
	 inm_list_replace_init(&disk_cx_stats_list,
				 &driver_ctx->dc_disk_cx_stats_list);
	 driver_ctx->dc_num_disk_cx_stats = num_output_disks_occupied;
	 driver_ctx->dc_num_consecutive_tags_failed =
			  get_cx_notify->ullMinConsecutiveTagFailures;
	 driver_ctx->dc_disk_level_supported_churn =
			  get_cx_notify->ullMaxDiskChurnSupportedMBps << MEGABYTE_BIT_SHIFT;
	 driver_ctx->dc_vm_level_supported_churn =
			  get_cx_notify->ullMaxVMChurnSupportedMBps << MEGABYTE_BIT_SHIFT;
 
	 driver_ctx->dc_max_fwd_timejump_ms =
			  get_cx_notify->ullMaximumTimeJumpFwdAcceptableInMs;
	 driver_ctx->dc_max_bwd_timejump_ms =
			  get_cx_notify->ullMaximumTimeJumpBwdAcceptableInMs;
 
	 if (get_cx_notify->ullFlags & CXSTATUS_COMMIT_PREV_SESSION &&
			 get_cx_notify->ulTransactionID &&
			 get_cx_notify->ulTransactionID == 
				 vm_cx_sess->vcs_transaction_id) {
		 vm_cx_sess->vcs_transaction_id = 0;
 
		 if (!(vm_cx_sess->vcs_flags & VCS_CX_PRODUCT_ISSUE) &&
			   (get_cx_notify->ullMinConsecutiveTagFailures <=
				 vm_cx_sess->vcs_num_consecutive_tag_failures))
			 vm_cx_sess->vcs_num_consecutive_tag_failures = 0;
 
		 vm_cx_sess->vcs_timejump_ts = 0;
		 vm_cx_sess->vcs_flags &= ~(VCS_CX_TIME_JUMP_FWD | 
							 VCS_CX_TIME_JUMP_BWD);
	 }
 
	 while(1) {
		 if (driver_ctx->dc_wokeup_monitor_thread) {
			 driver_ctx->dc_wokeup_monitor_thread = 0;
			 break;
		 }
 
		 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
 
		 ret = inm_wait_event_interruptible_timeout(
				 driver_ctx->dc_vm_cx_session_waitq,
				 should_wakeup_monitor_thread(vm_cx_sess, 
					 get_cx_notify),
				 60 * INM_HZ);
 
		 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				   driver_ctx->dc_vm_cx_session_lock_flag);
		 if (ret || should_wakeup_monitor_thread(vm_cx_sess, 
							 get_cx_notify)) {
			 driver_ctx->dc_wokeup_monitor_thread = 0;
			 break;
		 }
	 }
 
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
 
	 arg += sizeof(GET_CXFAILURE_NOTIFY) +
		  ((get_cx_notify->ulNumberOfProtectedDisks - 1) * 
		   sizeof(VOLUME_GUID));
	 disk_cx_stats_arg = arg + sizeof(VM_CXFAILURE_STATS) -
				  sizeof(DEVICE_CXFAILURE_STATS);
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
	 inm_list_replace_init(&driver_ctx->dc_disk_cx_stats_list,
							 &disk_cx_stats_list);
	 num_output_disks_occupied = driver_ctx->dc_num_disk_cx_stats;
	 if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED) ||
		  (vm_cx_sess->vcs_flags & VCS_CX_PRODUCT_ISSUE) ||
		  (get_cx_notify->ullMinConsecutiveTagFailures >
		   vm_cx_sess->vcs_num_consecutive_tag_failures))
		 goto update_timejump;
 
	 for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
						ptr = ptr->next, tgt_ctxt = NULL) {
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 if (tgt_ctxt->tc_flags & (VCF_VOLUME_CREATING | 
							 VCF_VOLUME_DELETING))
			 continue;
 
		 disk_cx_sess = &tgt_ctxt->tc_disk_cx_session;
		 found = 0;
		 for (disk_cx_stats_ptr = disk_cx_stats_list.next;
				  disk_cx_stats_ptr != &disk_cx_stats_list;
				  disk_cx_stats_ptr = disk_cx_stats_ptr->next) {
			 disk_cx_stats_info = inm_list_entry(disk_cx_stats_ptr,
					  disk_cx_stats_info_t, dcsi_list);
			 if (!disk_cx_stats_info->dcsi_valid)
				 continue;
 
			 dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
			 if (!strncmp(tgt_ctxt->tc_pname,
					 dev_cx_stats->DeviceId.volume_guid, 
					 GUID_SIZE_IN_CHARS)) {
				 found = 1;
				 dev_cx_stats->ullFlags &= 
					 ~DISK_CXSTATUS_DISK_NOT_FILTERED;
				 break;
			 }
		 }
 
		 if (found)
			 goto update_disk_cx_session;
 
		 if (num_output_disks_occupied == num_output_disks) {
			 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
			 INM_UP_READ(&(driver_ctx->tgt_list_sem));
			 error = INM_EAGAIN;
			 goto out;
		 }
 
		 disk_cx_stats_info = inm_list_entry(disk_cx_stats_list.prev,
					 disk_cx_stats_info_t, dcsi_list);
		 inm_list_del(&disk_cx_stats_info->dcsi_list);
 
		 disk_cx_stats_info->dcsi_valid = 1;
		 dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
		 strcpy_s(dev_cx_stats->DeviceId.volume_guid, GUID_SIZE_IN_CHARS,
								   tgt_ctxt->tc_pname);
		 inm_list_add(&disk_cx_stats_info->dcsi_list, 
						 &disk_cx_stats_list);
		 num_output_disks_occupied++;
 
 update_disk_cx_session:
		 disk_cx_sess->dcs_disk_cx_stats_info = disk_cx_stats_info;
		 flags = 0;
 
		 if (!(disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED) ||
			   !(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED))
			 continue;
 
		 if (disk_cx_sess->dcs_nr_nw_failures)
			 flags |= DISK_CXSTATUS_NWFAILURE_FLAG;
		 else if (disk_cx_sess->dcs_max_peak_churn)
			 flags |= DISK_CXSTATUS_PEAKCHURN_FLAG;
		 else if (disk_cx_sess->dcs_tracked_bytes >
					   disk_cx_sess->dcs_drained_bytes) {
			 flags |= DISK_CXSTATUS_CHURNTHROUGHPUT_FLAG;
			 dev_cx_stats->ullDiffChurnThroughputInBytes =
					  (disk_cx_sess->dcs_tracked_bytes -
					   disk_cx_sess->dcs_drained_bytes);
		 }
 
		 dev_cx_stats->ullFlags |= flags;
 
		 dev_cx_stats->firstNwFailureTS = 
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_first_nw_failure_ts);
		 dev_cx_stats->lastNwFailureTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_last_nw_failure_ts);
		 dev_cx_stats->ullTotalNWErrors = 
					 disk_cx_sess->dcs_nr_nw_failures;
		 dev_cx_stats->ullLastNWErrorCode =
				  disk_cx_sess->dcs_last_nw_failure_error_code;
 
		 dev_cx_stats->firstPeakChurnTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_first_peak_churn_ts);
		 dev_cx_stats->lastPeakChurnTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_last_peak_churn_ts);
		 dev_cx_stats->ullTotalExcessChurnInBytes =
				  disk_cx_sess->dcs_excess_churn;
		 memcpy_s(dev_cx_stats->ChurnBucketsMBps,
				  sizeof(dev_cx_stats->ChurnBucketsMBps),
				  disk_cx_sess->dcs_churn_buckets,
				  sizeof(disk_cx_sess->dcs_churn_buckets));
		 dev_cx_stats->ullMaximumPeakChurnInBytes =
				  disk_cx_sess->dcs_max_peak_churn;
 
		 dev_cx_stats->ullMaxS2LatencyInMS = 
				 (disk_cx_sess->dcs_max_s2_latency / 10000ULL);
 
		 dev_cx_stats->CxStartTS = disk_cx_sess->dcs_start_ts;
		 dev_cx_stats->CxEndTS = vm_cx_sess->vcs_end_ts;
	 }
 
	 /* Update VM CX session */
	 flags = 0;
 
	 if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED))
		 goto update_timejump;
 
	 if (vm_cx_sess->vcs_max_peak_churn)
		 flags |= VM_CXSTATUS_PEAKCHURN_FLAG;
	 else if (vm_cx_sess->vcs_tracked_bytes - 
					 vm_cx_sess->vcs_drained_bytes) {
		 flags |= VM_CXSTATUS_CHURNTHROUGHPUT_FLAG;
		 vm_cx_stats->ullDiffChurnThroughputInBytes =
			  (vm_cx_sess->vcs_tracked_bytes - 
					   vm_cx_sess->vcs_drained_bytes);
	 }
 
	 vm_cx_stats->ullFlags |= flags;
 
	 vm_cx_stats->firstPeakChurnTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					 vm_cx_sess->vcs_first_peak_churn_ts);
	 vm_cx_stats->lastPeakChurnTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					 vm_cx_sess->vcs_last_peak_churn_ts);
	 vm_cx_stats->ullTotalExcessChurnInBytes = vm_cx_sess->vcs_excess_churn;
	 memcpy_s(vm_cx_stats->ChurnBucketsMBps,
			sizeof(vm_cx_stats->ChurnBucketsMBps), 
			vm_cx_sess->vcs_churn_buckets,
			sizeof(vm_cx_sess->vcs_churn_buckets));
	 vm_cx_stats->ullMaximumPeakChurnInBytes = 
					 vm_cx_sess->vcs_max_peak_churn;
 
	 vm_cx_stats->ullMaxS2LatencyInMS = 
			 (vm_cx_sess->vcs_max_s2_latency / 10000ULL);
 
	 vm_cx_stats->CxStartTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
							vm_cx_sess->vcs_start_ts);
	 vm_cx_stats->CxEndTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
							vm_cx_sess->vcs_end_ts);
 
	 if (!vm_cx_sess->vcs_transaction_id)
		 vm_cx_sess->vcs_transaction_id = 
					 ++driver_ctx->dc_transaction_id;
 
	 vm_cx_stats->ulTransactionID = vm_cx_sess->vcs_transaction_id;
	 vm_cx_stats->ullNumOfConsecutiveTagFailures =
				vm_cx_sess->vcs_num_consecutive_tag_failures;
	 vm_cx_stats->ullNumDisks = num_output_disks_occupied;
 
 update_timejump:
	 if (!vm_cx_sess->vcs_transaction_id)
		 vm_cx_sess->vcs_transaction_id = 
					 ++driver_ctx->dc_transaction_id;
 
	 vm_cx_stats->ulTransactionID = vm_cx_sess->vcs_transaction_id;
	 vm_cx_stats->TimeJumpTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
						  vm_cx_sess->vcs_timejump_ts);
	 vm_cx_stats->ullTimeJumpInMS = vm_cx_sess->vcs_max_jump_ms;
 
	 if (vm_cx_sess->vcs_flags & VCS_CX_TIME_JUMP_FWD)
		 vm_cx_stats->ullFlags |= VM_CXSTATUS_TIMEJUMP_FWD_FLAG;
 
	 if (vm_cx_sess->vcs_flags & VCS_CX_TIME_JUMP_BWD)
		 vm_cx_stats->ullFlags |= VM_CXSTATUS_TIMEJUMP_BCKWD_FLAG;
 
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 while (!inm_list_empty(&disk_cx_stats_list)) {
		 disk_cx_stats_info = inm_list_entry(disk_cx_stats_list.next,
						disk_cx_stats_info_t, dcsi_list);
		 inm_list_del(&disk_cx_stats_info->dcsi_list);
 
		 if (!INM_ACCESS_OK(VERIFY_WRITE, (void __user*)disk_cx_stats_arg,
					   sizeof(DEVICE_CXFAILURE_STATS))) {
			 err("Access Violation for DEVICE_CXFAILURE_STATS");
			 INM_KFREE(disk_cx_stats_info, 
					 sizeof(disk_cx_stats_info_t),
					 INM_KERNEL_HEAP);
			 error = INM_EFAULT;
			 goto out;
		 }
 
		 if (INM_COPYOUT(disk_cx_stats_arg,
					 &disk_cx_stats_info->dcsi_dev_cx_stats,
					 sizeof(DEVICE_CXFAILURE_STATS))) {
			 err("copyout failed for DEVICE_CXFAILURE_STATS");
			 INM_KFREE(disk_cx_stats_info, 
					 sizeof(disk_cx_stats_info_t),
					 INM_KERNEL_HEAP);
			 error = INM_EFAULT;
			 goto out;
		 }
 
		 INM_KFREE(disk_cx_stats_info, sizeof(disk_cx_stats_info_t),
									  INM_KERNEL_HEAP);
		 disk_cx_stats_arg += sizeof(DEVICE_CXFAILURE_STATS);
	 }
 
	 if (!INM_ACCESS_OK(VERIFY_WRITE, (void __user*)arg,
						  sizeof(VM_CXFAILURE_STATS))) {
		 err( "Access Violation for VM_CXFAILURE_STATS");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (INM_COPYOUT(arg, vm_cx_stats, (sizeof(VM_CXFAILURE_STATS) -
					   sizeof(DEVICE_CXFAILURE_STATS)))) {
		 err("copyout failed for VM_CXFAILURE_STATS");
		 error = INM_EFAULT;
		 goto out;
	 }
 
 out:
	 while (!inm_list_empty(&disk_cx_stats_list)) {
		 disk_cx_stats_info = inm_list_entry(disk_cx_stats_list.next,
					   disk_cx_stats_info_t, dcsi_list);
		 inm_list_del(&disk_cx_stats_info->dcsi_list);
		 INM_KFREE(disk_cx_stats_info, sizeof(disk_cx_stats_info_t),
									  INM_KERNEL_HEAP);
	 }
 
	 if (get_cx_notify)
		 INM_KFREE(get_cx_notify, (sizeof(GET_CXFAILURE_NOTIFY) -
				   sizeof(VOLUME_GUID)), INM_KERNEL_HEAP);
 
	 if (vm_cx_stats)
		 INM_KFREE(vm_cx_stats, (sizeof(VM_CXFAILURE_STATS) -
			   sizeof(DEVICE_CXFAILURE_STATS)), INM_KERNEL_HEAP);
 
	 return error;
 }
 
 inm_s32_t process_wakeup_get_cxstatus_notify_ioctl(inm_devhandle_t *handle,
								 void *arg)
 {
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
 
	 wake_up_interruptible(&driver_ctx->dc_vm_cx_session_waitq);
	 driver_ctx->dc_wokeup_monitor_thread = 1;
 
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
 
	 return 0;
 }
 
 inm_s32_t process_tag_drain_notify_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 TAG_COMMIT_NOTIFY_INPUT  *tag_drain_notify_input = NULL;
	 TAG_COMMIT_NOTIFY_OUTPUT *tag_drain_notify_output = NULL;
	 VOLUME_GUID             *guid = NULL;
	 TAG_COMMIT_STATUS       *tag_commit_status;
	 int                     out_size = 0;
	 int                     idx;
	 void                    *device_list_arg;
	 vm_cx_session_t         *vm_cx_sess = &driver_ctx->dc_vm_cx_session;
	 inm_list_head_t         *ptr;
	 target_context_t        *tgt_ctxt;
	 disk_cx_session_t       *disk_cx_sess;
	 inm_list_head_t         *disk_cx_stats_ptr;
	 disk_cx_stats_info_t    *disk_cx_stats_info;
	 DEVICE_CXFAILURE_STATS  *dev_cx_stats;
	 VM_CXFAILURE_STATS      *vm_cx_stats;
	 inm_u64_t               flags;
	 inm_s32_t               error = 0;
	 int                     found;
	 static int              tag_drain_notify_thread_in_progress = 0;
 
	 info("Tag drain notify thread arrived");
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg,
					   sizeof(TAG_COMMIT_NOTIFY_INPUT))) {
		 err( "Access Violation for TAG_DRAIN_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 tag_drain_notify_input = INM_KMALLOC((sizeof(TAG_COMMIT_NOTIFY_INPUT) -
					  sizeof(VOLUME_GUID)),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!tag_drain_notify_input) {
		 err("failed to allocate TAG_COMMIT_NOTIFY_INPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(tag_drain_notify_input, arg,
					 (sizeof(TAG_COMMIT_NOTIFY_INPUT) - 
					  sizeof(VOLUME_GUID)))) {
		 err("copyin failed for TAG_COMMIT_NOTIFY_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (!tag_drain_notify_input->ulNumDisks) {
		 err("TAG_COMMIT_NOTIFY_INPUT: Number of protected disks from user can't be zero");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 driver_ctx->dc_tag_commit_notify_flag = tag_drain_notify_input->ulFlags;
	 out_size = sizeof(TAG_COMMIT_NOTIFY_OUTPUT) - sizeof(TAG_COMMIT_STATUS) +
				tag_drain_notify_input->ulNumDisks * sizeof(TAG_COMMIT_STATUS);
	 tag_drain_notify_output = INM_KMALLOC(out_size, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!tag_drain_notify_output) {
		 err("failed to allocate TAG_COMMIT_NOTIFY_OUTPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 INM_MEM_ZERO(tag_drain_notify_output, out_size);
	 memcpy_s(tag_drain_notify_output->TagGUID, GUID_LEN,
				 tag_drain_notify_input->TagGUID, GUID_LEN);
	 tag_drain_notify_output->ulNumDisks = tag_drain_notify_input->ulNumDisks;
 
	 device_list_arg = arg + sizeof(TAG_COMMIT_NOTIFY_INPUT) - sizeof(VOLUME_GUID);
	 guid = INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!guid) {
		 err("Failed to allocate VOLUME_GUID");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 tag_commit_status = tag_drain_notify_output->TagStatus;
	 for (idx = 0; idx < tag_drain_notify_input->ulNumDisks; idx++) {
		 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)device_list_arg,
							  sizeof(VOLUME_GUID))) {
			 err( "Access Violation for VOLUME_GUID");
			 error = INM_EFAULT;
			 goto out;
		 }
 
		 if (INM_COPYIN(guid, device_list_arg, sizeof(VOLUME_GUID))) {
			 err("copyin failed for VOLUME_GUID");
			 error = INM_EFAULT;
			 goto out;
		 }
 
		 memcpy_s(&tag_commit_status[idx].DeviceId, sizeof(VOLUME_GUID), 
				 guid, sizeof(VOLUME_GUID));
		 info("input pname = %s", 
				 tag_commit_status[idx].DeviceId.volume_guid);
		 tag_commit_status[idx].Status = DEVICE_STATUS_UNKNOWN;
		 tag_commit_status[idx].TagStatus = TAG_STATUS_UNINITALIZED;
 
		 device_list_arg += sizeof(VOLUME_GUID);
	 }
 
	 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	 if (tag_drain_notify_thread_in_progress) {
		 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
		 info("One thread is already in progress, so quitting");
		 error = INM_EBUSY;
		 goto out;
	 }
 
	 tag_drain_notify_thread_in_progress = 1;
	 driver_ctx->dc_tag_drain_notify_guid = tag_drain_notify_output->TagGUID;
	 info("input tag guid = %.36s", driver_ctx->dc_tag_drain_notify_guid);
	 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 info("Number of disks = %llu and protected number of disks = %d",
			tag_drain_notify_input->ulNumDisks, 
			driver_ctx->total_prot_volumes);
	 if (tag_drain_notify_input->ulNumDisks > 
					 driver_ctx->total_prot_volumes) {
		 INM_UP_READ(&(driver_ctx->tgt_list_sem));
		 err("TAG_COMMIT_NOTIFY_INPUT: Number of protected disks from user (%llu) can't"
			 " be greater than the actual number protected disks (%d) at driver",
			 tag_drain_notify_input->ulNumDisks, 
			 driver_ctx->total_prot_volumes);
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (driver_ctx->dc_tag_commit_notify_flag & 
					 TAG_COMMIT_NOTIFY_BLOCK_DRAIN_FLAG) {
		 int ret = 0;
		 for (idx = 0; idx < 
				 tag_drain_notify_input->ulNumDisks; idx++) {
			 char *uuid = &tag_commit_status[idx].DeviceId.volume_guid[0];
 
			 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
			 if (!tgt_ctxt) {
				 err("The disk %s is not protected", uuid);
				 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
				 tag_commit_status[idx].Status = DEVICE_STATUS_NOT_FOUND;
				 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
				 error = -ENODEV;
				 ret = 1;
				 break;
			 }
			 volume_lock(tgt_ctxt);
			 if (tgt_ctxt->tc_flags & VCF_DRAIN_BLOCKED) {
				 err("Draining is already blocked for uuid : %s\n", uuid);
				 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
				 tag_commit_status[idx].Status = DEVICE_STATUS_DRAIN_ALREADY_BLOCKED;
				 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
				 error = INM_EEXIST;
				 ret = 1;
			 }
			 volume_unlock(tgt_ctxt);
			 put_tgt_ctxt(tgt_ctxt);
 
			 if (ret) {
				 break;
			 }
		 }
		 if (ret) {
			 INM_UP_READ(&(driver_ctx->tgt_list_sem));
			 goto update_tag_drain_notify_output;
		 }
	 }
	 found = 1;
	 for (idx = 0; idx < tag_drain_notify_input->ulNumDisks; idx++) {
		 char *uuid = &tag_commit_status[idx].DeviceId.volume_guid[0];
 
		 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
		 if (!tgt_ctxt) {
			 info("The disk %s is not protected", uuid);
			 found = 0;
 
			 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
			 tag_commit_status[idx].Status = DEVICE_STATUS_NOT_FOUND;
			 tag_commit_status[idx].TagStatus = TAG_STATUS_UNKNOWN;
			 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
			 continue;
		 }
 
		 INM_ATOMIC_INC(&driver_ctx->dc_nr_tag_commit_status_pending_disks);
 
		 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
		 tag_commit_status[idx].Status = DEVICE_STATUS_SUCCESS;
		 tag_commit_status[idx].TagStatus = TAG_STATUS_UNINITALIZED;
		 tgt_ctxt->tc_tag_commit_status = &tag_commit_status[idx];
		 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
 
		 put_tgt_ctxt(tgt_ctxt);
	 }
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	 while(found) {
		 int ret = 0;
 
		 if (driver_ctx->dc_wokeup_tag_drain_notify_thread) {
			 driver_ctx->dc_wokeup_tag_drain_notify_thread = 0;
			 error = INM_EINTR;
			 break;
		 }
 
		 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
		 ret = inm_wait_event_interruptible_timeout(
			 driver_ctx->dc_tag_commit_status_waitq,
			 !INM_ATOMIC_READ(&driver_ctx->dc_nr_tag_commit_status_pending_disks) ||
			 INM_ATOMIC_READ(&driver_ctx->dc_tag_commit_status_failed), 60 * INM_HZ);
 
		 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
		 if (ret || !INM_ATOMIC_READ(&driver_ctx->dc_nr_tag_commit_status_pending_disks) ||
				 INM_ATOMIC_READ(&driver_ctx->dc_tag_commit_status_failed)) {
			 info("The tag drain notify waiitng over");
			 break;
		 }
	 }
 
	 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
 
	 if (driver_ctx->dc_tag_commit_notify_flag &
					 TAG_COMMIT_NOTIFY_BLOCK_DRAIN_FLAG) {
		 int ret = 0;
		 for (idx = 0; idx < tag_drain_notify_input->ulNumDisks; idx++) {
			 char *uuid = &tag_commit_status[idx].DeviceId.volume_guid[0];
 
			 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
			 if (!tgt_ctxt) {
				 err("The disk %s is not protected", uuid);
				 error = -ENODEV;
				 ret = 1;
				 break;
			 }
			 volume_lock(tgt_ctxt);
			 if (!(tgt_ctxt->tc_flags & VCF_DRAIN_BLOCKED)) {
				 err("Drain block failed for uuid : %s\n", uuid);
				 error = INM_EFAULT;
				 ret = 1;
			 }
			 volume_unlock(tgt_ctxt);
			 put_tgt_ctxt(tgt_ctxt);
 
			 if(ret) {
				 break;
			 }
		 }
 
		 if (ret) {
 
 unblock_drain:
			 info("Unblocking drain for all disks\n");
			 for (idx = 0; idx < tag_drain_notify_input->ulNumDisks; idx++) {
				 char *uuid = &tag_commit_status[idx].DeviceId.volume_guid[0];
 
				 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
				 if (!tgt_ctxt) {
					 err("The disk %s is not protected", uuid);
					 error = -ENODEV;
					 continue;
				 }
				 info("Unblocking drain for disk : %s\n", uuid);
				 set_int_vol_attr(tgt_ctxt, VolumeDrainBlocked, 0);
				 put_tgt_ctxt(tgt_ctxt);
			 }
		 } else {
			 for (idx = 0; idx < tag_drain_notify_input->ulNumDisks; idx++) {
				 char *uuid = &tag_commit_status[idx].DeviceId.volume_guid[0];
 
				 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
				 if (!tgt_ctxt) {
					 err("The disk %s is not protected", uuid);
					 error = -ENODEV;
					 goto unblock_drain;
				 }
				 info("Persist drain block for disk: %s\n", uuid);
				 if(set_int_vol_attr(tgt_ctxt, VolumeDrainBlocked, 1)) {
					 err("Persist drain block failed for disk :%s\n", uuid);
					 tag_commit_status[idx].Status = DEVICE_STATUS_DRAIN_BLOCK_FAILED;
					 put_tgt_ctxt(tgt_ctxt);
					 error = INM_EFAULT;
					 goto unblock_drain;
				 }
				 put_tgt_ctxt(tgt_ctxt);
			 }
		 }
	 }
	 INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_vm_cx_session_lock,
						   driver_ctx->dc_vm_cx_session_lock_flag);
	 if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED) ||
		  (vm_cx_sess->vcs_flags & VCS_CX_PRODUCT_ISSUE))
		 goto update_tag_drain_notify_output;
 
	 for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
						ptr = ptr->next, tgt_ctxt = NULL) {
		 int found = 0;
 
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 if (tgt_ctxt->tc_flags & (VCF_VOLUME_CREATING | 
							 VCF_VOLUME_DELETING))
			 continue;
 
		 disk_cx_sess = &tgt_ctxt->tc_disk_cx_session;
		 if (!(disk_cx_sess->dcs_flags & DCS_CX_SESSION_STARTED) ||
			   !(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED))
			 continue;
 
		 for (disk_cx_stats_ptr = driver_ctx->dc_disk_cx_stats_list.next;
						  disk_cx_stats_ptr != &driver_ctx->dc_disk_cx_stats_list;
						  disk_cx_stats_ptr = disk_cx_stats_ptr->next) {
			 disk_cx_stats_info = inm_list_entry(disk_cx_stats_ptr,
						  disk_cx_stats_info_t, dcsi_list);
			 if (!disk_cx_stats_info->dcsi_valid)
				 continue;
 
			 dev_cx_stats = &disk_cx_stats_info->dcsi_dev_cx_stats;
			 if (!strncmp(tgt_ctxt->tc_pname,
				   dev_cx_stats->DeviceId.volume_guid, 
				   GUID_SIZE_IN_CHARS)) {
				 found = 1;
				 break;
			 }
		 }
 
		 if (!found)
			 continue;
 
		 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
		 if (!tgt_ctxt->tc_tag_commit_status) {
			 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
			 continue;
		 }
 
		 dev_cx_stats = &tgt_ctxt->tc_tag_commit_status->DeviceCxStats;
		 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
 
		 flags = 0;
		 if (disk_cx_sess->dcs_nr_nw_failures)
			 flags |= DISK_CXSTATUS_NWFAILURE_FLAG;
		 else if (disk_cx_sess->dcs_max_peak_churn)
			 flags |= DISK_CXSTATUS_PEAKCHURN_FLAG;
		 else if (disk_cx_sess->dcs_tracked_bytes >
					   disk_cx_sess->dcs_drained_bytes) {
			 flags |= DISK_CXSTATUS_CHURNTHROUGHPUT_FLAG;
			 dev_cx_stats->ullDiffChurnThroughputInBytes =
					  (disk_cx_sess->dcs_tracked_bytes -
					   disk_cx_sess->dcs_drained_bytes);
		 }
 
		 dev_cx_stats->ullFlags |= flags;
 
		 dev_cx_stats->firstNwFailureTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_first_nw_failure_ts);
		 dev_cx_stats->lastNwFailureTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_last_nw_failure_ts);
		 dev_cx_stats->ullTotalNWErrors = disk_cx_sess->dcs_nr_nw_failures;
		 dev_cx_stats->ullLastNWErrorCode =
				  disk_cx_sess->dcs_last_nw_failure_error_code;
 
		 dev_cx_stats->firstPeakChurnTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_first_peak_churn_ts);
		 dev_cx_stats->lastPeakChurnTS =
			  TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
				  disk_cx_sess->dcs_last_peak_churn_ts);
		 dev_cx_stats->ullTotalExcessChurnInBytes =
				  disk_cx_sess->dcs_excess_churn;
		 memcpy_s(dev_cx_stats->ChurnBucketsMBps,
				  sizeof(dev_cx_stats->ChurnBucketsMBps),
				  disk_cx_sess->dcs_churn_buckets,
				  sizeof(disk_cx_sess->dcs_churn_buckets));
		 dev_cx_stats->ullMaximumPeakChurnInBytes =
				  disk_cx_sess->dcs_max_peak_churn;
 
		 dev_cx_stats->ullMaxS2LatencyInMS = 
				 (disk_cx_sess->dcs_max_s2_latency / 10000ULL);
 
		 dev_cx_stats->CxStartTS = disk_cx_sess->dcs_start_ts;
		 dev_cx_stats->CxEndTS = vm_cx_sess->vcs_end_ts;
	 }
 
	 /* Update VM CX session */
	 flags = 0;
 
	 if (!(vm_cx_sess->vcs_flags & VCS_CX_SESSION_ENDED))
		 goto update_tag_drain_notify_output;
 
	 vm_cx_stats = &tag_drain_notify_output->vmCxStatus;
	 if (vm_cx_sess->vcs_max_peak_churn)
		 flags |= VM_CXSTATUS_PEAKCHURN_FLAG;
	 else if (vm_cx_sess->vcs_tracked_bytes - vm_cx_sess->vcs_drained_bytes) {
		 flags |= VM_CXSTATUS_CHURNTHROUGHPUT_FLAG;
		 vm_cx_stats->ullDiffChurnThroughputInBytes =
			  (vm_cx_sess->vcs_tracked_bytes - vm_cx_sess->vcs_drained_bytes);
	 }
 
	 vm_cx_stats->ullFlags |= flags;
 
	 vm_cx_stats->firstPeakChurnTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					 vm_cx_sess->vcs_first_peak_churn_ts);
	 vm_cx_stats->lastPeakChurnTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
					 vm_cx_sess->vcs_last_peak_churn_ts);
	 vm_cx_stats->ullTotalExcessChurnInBytes = vm_cx_sess->vcs_excess_churn;
	 memcpy_s(vm_cx_stats->ChurnBucketsMBps,
			sizeof(vm_cx_stats->ChurnBucketsMBps), 
			vm_cx_sess->vcs_churn_buckets,
			sizeof(vm_cx_sess->vcs_churn_buckets));
	 vm_cx_stats->ullMaximumPeakChurnInBytes = vm_cx_sess->vcs_max_peak_churn;
 
	 vm_cx_stats->ullMaxS2LatencyInMS = 
			 (vm_cx_sess->vcs_max_s2_latency / 10000ULL);
 
	 vm_cx_stats->CxStartTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
							vm_cx_sess->vcs_start_ts);
	 vm_cx_stats->CxEndTS = TELEMETRY_FMT1601_TIMESTAMP_FROM_100NSEC(
							vm_cx_sess->vcs_end_ts);
 
	 vm_cx_stats->ullNumOfConsecutiveTagFailures = 0;
	 vm_cx_stats->ullNumDisks = 0;
 
 update_tag_drain_notify_output:
	 INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_vm_cx_session_lock,
				 driver_ctx->dc_vm_cx_session_lock_flag);
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 if (!INM_ACCESS_OK(VERIFY_WRITE, (void __user*)device_list_arg, 
								 out_size)) {
		 err( "Access Violation for TAG_COMMIT_NOTIFY_OUTPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (INM_COPYOUT(device_list_arg, tag_drain_notify_output, out_size)) {
		 err("copyout failed for TAG_COMMIT_NOTIFY_OUTPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
 out:
	 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	 driver_ctx->dc_tag_drain_notify_guid = NULL;
	 tag_drain_notify_thread_in_progress = 0;
	 driver_ctx->dc_tag_commit_notify_flag = 0;
	 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 for (ptr = driver_ctx->tgt_list.next; ptr != &(driver_ctx->tgt_list);
					 ptr = ptr->next, tgt_ctxt = NULL) {
		 tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);
		 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
		 tgt_ctxt->tc_tag_commit_status = NULL;
		 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
	 }
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 INM_ATOMIC_SET(&driver_ctx->dc_nr_tag_commit_status_pending_disks, 0);
	 INM_ATOMIC_SET(&driver_ctx->dc_tag_commit_status_failed, 0);
 
	 if (guid)
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
 
	 if (tag_drain_notify_output)
		 INM_KFREE(tag_drain_notify_output, out_size, INM_KERNEL_HEAP);
 
	 if (tag_drain_notify_input)
		 INM_KFREE(tag_drain_notify_input, 
				 (sizeof(TAG_COMMIT_NOTIFY_INPUT) -
				 sizeof(VOLUME_GUID)), INM_KERNEL_HEAP);
 
	 info("Tag drain notify thread is quitting with error = %d", error);
	 return error;
 }
 
 inm_s32_t process_wakeup_tag_drain_notify_ioctl(inm_devhandle_t *handle, 
								 void *arg)
 {
	 info("Waking up the tag drain notify thread");
	 INM_SPIN_LOCK(&driver_ctx->dc_tag_commit_status);
	 wake_up_interruptible(&driver_ctx->dc_tag_commit_status_waitq);
	 driver_ctx->dc_wokeup_tag_drain_notify_thread = 1;
	 INM_SPIN_UNLOCK(&driver_ctx->dc_tag_commit_status);
 
	 return 0;
 }
 
 inm_s32_t process_modify_persistent_device_name(inm_devhandle_t *handle, 
								 void *arg)
 {
	 MODIFY_PERSISTENT_DEVICE_NAME_INPUT  *modify_pname_input = NULL;
	 target_context_t *tgt_ctxt = NULL;
	 inm_s32_t error = 0;
	 char *old_path = NULL, *new_path = NULL;
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg,
			 sizeof(MODIFY_PERSISTENT_DEVICE_NAME_INPUT))) {
		 err( "Access Violation for MODIFY_PERSISTENT_DEVICE_NAME");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 modify_pname_input = INM_KMALLOC(sizeof(MODIFY_PERSISTENT_DEVICE_NAME_INPUT),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!modify_pname_input) {
		 err("failed to allocate MODIFY_PERSISTENT_DEVICE_NAME_INPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(modify_pname_input, arg,
			 sizeof(MODIFY_PERSISTENT_DEVICE_NAME_INPUT))) {
		 err("copyin failed for MODIFY_PERSISTENT_DEVICE_NAME_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 info("Modifying persistent device name source disk : %s, old pname : %s, new pname : %s\n",
		 modify_pname_input->DevName.volume_guid,
		 modify_pname_input->OldPName.volume_guid,
		 modify_pname_input->NewPName.volume_guid);
 
	 tgt_ctxt = get_tgt_ctxt_from_uuid_nowait(
				 modify_pname_input->DevName.volume_guid);
	 if (!tgt_ctxt) {
		 err("The disk %s is not protected", 
				 modify_pname_input->DevName.volume_guid);
		 error = -ENODEV;
		 goto out;
	 }
 
	 if (strncmp(tgt_ctxt->tc_pname, 
			 modify_pname_input->OldPName.volume_guid,
			 GUID_SIZE_IN_CHARS)) {
		 err("Device : %s, Expected pname : %s, Received pname :%s\n",
			 modify_pname_input->DevName.volume_guid,
			 tgt_ctxt->tc_pname,
			 modify_pname_input->OldPName.volume_guid);
		 error = -EINVAL;
		 goto out;
	 }
 
	 old_path = (char *)INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!old_path){
		 err("Allocation of memory failed for old_path.\n");
		 error = INM_ENOMEM;
		 goto out;
	 }
	 new_path = (char *)INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if(!new_path){
		 err("Allocation of memory failed for new_path.\n");
		 error = INM_ENOMEM;
		 goto out;
	 }
	 snprintf(old_path, INM_PATH_MAX, "%s", tgt_ctxt->tc_pname);
	 snprintf(new_path, INM_PATH_MAX, "%s", 
				 modify_pname_input->NewPName.volume_guid);
	 if (inm_is_upgrade_pname(old_path, new_path)) {
		 error = INM_EFAULT;
		 goto out;
	 }
	 snprintf(old_path, INM_PATH_MAX, "%s/%s%s%s", tgt_ctxt->tc_pname,
		 LOG_FILE_NAME_PREFIX, tgt_ctxt->tc_pname, LOG_FILE_NAME_SUFFIX);
	 snprintf(new_path, INM_PATH_MAX, "%s/%s%s%s", tgt_ctxt->tc_pname,
		 LOG_FILE_NAME_PREFIX, modify_pname_input->NewPName.volume_guid, 
		 LOG_FILE_NAME_SUFFIX);
	 if (inm_is_upgrade_pname(old_path, new_path)) {
		 error = INM_EFAULT;
		 goto out;
	 }
	 error = modify_persistent_device_name(tgt_ctxt, 
				 modify_pname_input->NewPName.volume_guid);
 
 out:
	 if(tgt_ctxt) {
		 put_tgt_ctxt(tgt_ctxt);
	 }
	 if (new_path) {
		 INM_KFREE(new_path, INM_PATH_MAX, INM_KERNEL_HEAP);
	 }
	 if (old_path) {
		 INM_KFREE(old_path, INM_PATH_MAX, INM_KERNEL_HEAP);
	 }
	 if (modify_pname_input) {
		 INM_KFREE(modify_pname_input, 
			 sizeof(MODIFY_PERSISTENT_DEVICE_NAME_INPUT),
			 INM_KERNEL_HEAP);
	 }
 
	 dbg("modify persistent device name is exiting with error = %d", error);
	 return error;
 }
 
 inm_s32_t process_get_drain_state_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 GET_DISK_STATE_INPUT  *drain_state_input = NULL;
	 GET_DISK_STATE_OUTPUT *drain_state_output = NULL;
	 VOLUME_GUID             *guid = NULL;
	 int                     out_size = 0;
	 int                     idx;
	 void                    *device_list_arg;
	 target_context_t        *tgt_ctxt;
	 char                    *uuid;
	 inm_s32_t               error = 0;
 
	 dbg("Get Drain state thread arrived");
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg,
					   sizeof(GET_DISK_STATE_INPUT))) {
		 err("Access Violation for GET_DISK_STATE_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 drain_state_input = INM_KMALLOC((sizeof(GET_DISK_STATE_INPUT) -
					  sizeof(VOLUME_GUID)),
					  INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!drain_state_input) {
		 err("failed to allocate GET_DISK_STATE_INPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(drain_state_input, arg,
		 (sizeof(GET_DISK_STATE_INPUT) - sizeof(VOLUME_GUID)))) {
		 err("copyin failed for GET_DISK_STATE_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (!drain_state_input->ulNumDisks) {
		 err("GET_DISK_STATE_INPUT: Number of protected disks from user can't be zero");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 out_size = sizeof(GET_DISK_STATE_OUTPUT) - sizeof(DISK_STATE) +
				drain_state_input->ulNumDisks * sizeof(DISK_STATE);
	 drain_state_output = INM_KMALLOC(out_size, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!drain_state_output) {
		 err("failed to allocate GET_DISK_STATE_OUTPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 INM_MEM_ZERO(drain_state_output, out_size);
	 drain_state_output->ulNumDisks = drain_state_input->ulNumDisks;
 
	 device_list_arg = arg + sizeof(GET_DISK_STATE_INPUT) - 
							 sizeof(VOLUME_GUID);
	 guid = INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!guid) {
		 err("Failed to allocate VOLUME_GUID");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 for (idx = 0; idx < drain_state_input->ulNumDisks; idx++) {
		 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)device_list_arg,
							  sizeof(VOLUME_GUID))) {
			 err( "Access Violation for VOLUME_GUID");
			 error = INM_EFAULT;
			 break;
		 }
 
		 if (INM_COPYIN(guid, device_list_arg, sizeof(VOLUME_GUID))) {
			 err("copyin failed for VOLUME_GUID");
			 error = INM_EFAULT;
			 break;
		 }
 
		 memcpy_s(&drain_state_output->diskState[idx].DeviceId, 
			 sizeof(VOLUME_GUID), guid, sizeof(VOLUME_GUID));
 
		 uuid = drain_state_output->diskState[idx].DeviceId.volume_guid;
		 info("input pname : %s", uuid);
		 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
		 if (!tgt_ctxt) {
			 err("The disk %s is not protected", uuid);
			 error = -ENODEV;
			 break;
		 }
		 if (tgt_ctxt->tc_flags & VCF_DRAIN_BLOCKED) {
			 info("Draining blocked for uuid : %s.\n", uuid);
			 drain_state_output->diskState[idx].ulFlags |= 
						 DISK_STATE_DRAIN_BLOCKED;
		 }
		 else {
			 info("Draining is not blocked for uuid : %s\n", uuid);
			 drain_state_output->diskState[idx].ulFlags |= 
						 DISK_STATE_FILTERED;
		 }
		 put_tgt_ctxt(tgt_ctxt);
 
		 device_list_arg += sizeof(VOLUME_GUID);
	 }
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
	 
	 if (!INM_ACCESS_OK(VERIFY_WRITE, (void __user*)device_list_arg, 
								 out_size)) {
		 err("Access Violation for GET_DISK_STATE_OUTPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (INM_COPYOUT(device_list_arg, drain_state_output, out_size)) {
		 err("copyout failed for GET_DISK_STATE_OUTPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
 out:
 
	 if (guid)
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
 
	 if (drain_state_output)
		 INM_KFREE(drain_state_output, out_size, INM_KERNEL_HEAP);
 
	 if (drain_state_input)
		 INM_KFREE(drain_state_input, (sizeof(GET_DISK_STATE_INPUT) -
					 sizeof(VOLUME_GUID)), INM_KERNEL_HEAP);
 
	 dbg("Get Drain state thread is quitting with error = %d", error);
	 return error;
 }
 
 inm_s32_t process_set_drain_state_ioctl(inm_devhandle_t *handle, void *arg)
 {
	 SET_DRAIN_STATE_INPUT   *drain_state_input = NULL;
	 SET_DRAIN_STATE_OUTPUT  *drain_state_output = NULL;
	 VOLUME_GUID             *guid = NULL;
	 int                     idx;
	 int                     out_size = 0;
	 void                    *device_list_arg;
	 target_context_t        *tgt_ctxt;
	 char                    *uuid;
	 inm_s32_t               error = 0;
	 int                     ret;
 
	 dbg("Set Drain state thread arrived");
 
	 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)arg,
					 sizeof(SET_DRAIN_STATE_INPUT))) {
		 err( "Access Violation for SET_DRAIN_STATE_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 drain_state_input = INM_KMALLOC((sizeof(SET_DRAIN_STATE_INPUT) -
					 sizeof(VOLUME_GUID)),
					 INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!drain_state_input) {
		 err("failed to allocate SET_DRAIN_STATE_INPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 if (INM_COPYIN(drain_state_input, arg,
					 (sizeof(SET_DRAIN_STATE_INPUT) - 
					  sizeof(VOLUME_GUID)))) {
		 err("copyin failed for SET_DRAIN_STATE_INPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (!drain_state_input->ulNumDisks) {
		 err("SET_DRAIN_STATE_INPUT: Number of protected disks from user can't be zero");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 out_size = sizeof(SET_DRAIN_STATE_OUTPUT) - sizeof(DISK_STATE) +
				drain_state_input->ulNumDisks * sizeof(DISK_STATE);
	 drain_state_output = INM_KMALLOC(out_size, INM_KM_SLEEP, 
							 INM_KERNEL_HEAP);
	 if (!drain_state_output) {
		 err("failed to allocate SET_DRAIN_STATE_OUTPUT");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 INM_MEM_ZERO(drain_state_output, out_size);
	 drain_state_output->ulNumDisks = drain_state_input->ulNumDisks;
	 for (idx = 0; idx < drain_state_input->ulNumDisks; idx++) {
		 drain_state_output->diskStatus[idx].Status = 
						 SET_DRAIN_STATUS_UNKNOWN;
	 }
 
	 device_list_arg = arg + sizeof(SET_DRAIN_STATE_INPUT) - 
							 sizeof(VOLUME_GUID);
	 guid = INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, INM_KERNEL_HEAP);
	 if (!guid) {
		 err("Failed to allocate VOLUME_GUID");
		 error = INM_ENOMEM;
		 goto out;
	 }
 
	 INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	 for (idx = 0; idx < drain_state_input->ulNumDisks; idx++) {
		 if (!INM_ACCESS_OK(VERIFY_READ, (void __user*)device_list_arg,
					 sizeof(VOLUME_GUID))) {
			 err( "Access Violation for VOLUME_GUID");
			 error = INM_EFAULT;
			 break;
		 }
 
		 if (INM_COPYIN(guid, device_list_arg, sizeof(VOLUME_GUID))) {
			 err("copyin failed for VOLUME_GUID");
			 error = INM_EFAULT;
			 break;
		 }
 
		 memcpy_s(&drain_state_output->diskStatus[idx].DeviceId, 
					 sizeof(VOLUME_GUID),
					 guid, sizeof(VOLUME_GUID));
		 uuid = guid->volume_guid;
		 info("input pname : %s", uuid);
		 tgt_ctxt = get_tgt_ctxt_persisted_name_nowait_locked(uuid);
		 if (!tgt_ctxt) {
			 err("The disk %s is not protected", uuid);
			 error = -ENODEV;
			 drain_state_output->diskStatus[idx].Status = 
					 SET_DRAIN_STATUS_DEVICE_NOT_FOUND;
			 break;
		 }
		 info("Unblocking drain for disk : %s\n", uuid);
		 ret = set_int_vol_attr(tgt_ctxt, VolumeDrainBlocked, 0);
		 if (ret) {
			 err ("Unblocking drain failed for %s\n", uuid);
			 error = INM_EFAULT;
			 drain_state_output->diskStatus[idx].Status = 
					 SET_DRAIN_STATUS_PERSISTENCE_FAILED;
			 drain_state_output->diskStatus[idx].ulInternalError = 
									 ret;
		 }
		 else {
			 drain_state_output->diskStatus[idx].Status = 
						 SET_DRAIN_STATUS_SUCCESS;
		 }
		 put_tgt_ctxt(tgt_ctxt);
 
		 device_list_arg += sizeof(VOLUME_GUID);
	 }
	 INM_UP_READ(&(driver_ctx->tgt_list_sem));
 
	 if (!INM_ACCESS_OK(VERIFY_WRITE, (void __user*)device_list_arg, 
								 out_size)) {
		 err("Access Violation for GET_DISK_STATE_OUTPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
	 if (INM_COPYOUT(device_list_arg, drain_state_output, out_size)) {
		 err("copyout failed for GET_DISK_STATE_OUTPUT");
		 error = INM_EFAULT;
		 goto out;
	 }
 
 out:
 
	 if (guid)
		 INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
 
	 if (drain_state_input)
		 INM_KFREE(drain_state_input, (sizeof(GET_DISK_STATE_INPUT) -
					 sizeof(VOLUME_GUID)), INM_KERNEL_HEAP);
 
	 dbg("Set Drain state thread is quitting with error = %d", error);
	 return error;
 }
 