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

#ifndef _INM_IOCTL_H
#define _INM_IOCTL_H

#include "inm_utypes.h"
#include "involflt.h"
#include "osdep.h"
#include "driver-context.h"

/* IOCTL function declarations */
inm_s32_t process_volume_stacking_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_mirror_volume_stacking_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_start_notify_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_shutdown_notify_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_start_filtering_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_stop_filtering_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_remove_filter_device_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_start_mirroring_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_stop_mirroring_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_volume_unstacking_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_get_db_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_commit_db_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_get_time_ioctl(void __INM_USER *);
inm_s32_t process_clear_diffs_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_set_volume_flags_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_get_volume_flags_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_wait_for_db_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_wait_for_db_v2_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_sys_shutdown_notify_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_sys_pre_shutdown_notify_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_tag_ioctl(inm_devhandle_t *, void __INM_USER *, inm_s32_t);
inm_s32_t process_get_tag_status_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_wake_all_threads_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_get_db_threshold(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_resync_start_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_resync_end_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_get_driver_version_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_shell_log_ioctl(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_at_lun_create(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_at_lun_last_write_vi(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_at_lun_last_host_io_timestamp(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_at_lun_query(inm_devhandle_t *, void __INM_USER*);
inm_s32_t process_at_lun_delete(inm_devhandle_t *, void __INM_USER *);
inm_s32_t process_get_global_stats_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_volume_stats_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_volume_stats_v2_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_monitoring_stats_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_protected_volume_list_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_set_attr_ioctl(inm_devhandle_t *handle, void * arg);
inm_u32_t process_boottime_stacking_ioctl(inm_devhandle_t *handle, void * arg);
inm_u32_t process_mirror_exception_notify_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_dmesg(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_additional_volume_stats(inm_devhandle_t *handle, void * arg);
inm_s32_t process_get_volume_latency_stats(inm_devhandle_t *handle, void * arg);
inm_s32_t process_bitmap_stats_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_set_involflt_verbosity(inm_devhandle_t *handle, void *arg);
inm_s32_t process_mirror_test_heartbeat(inm_devhandle_t *handle, void *arg);
inm_s32_t process_tag_volume_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_get_blk_mq_status_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_replication_state_ioctl(inm_devhandle_t *handle, void * arg);
inm_s32_t process_name_mapping_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_lcw_ioctl(inm_devhandle_t *idhp, void __INM_USER *arg);
inm_s32_t process_commitdb_fail_trans_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_get_cxstatus_notify_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_wakeup_get_cxstatus_notify_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_tag_drain_notify_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_wakeup_tag_drain_notify_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_modify_persistent_device_name(inm_devhandle_t *handle, void *arg);
inm_s32_t process_get_drain_state_ioctl(inm_devhandle_t *handle, void *arg);
inm_s32_t process_set_drain_state_ioctl(inm_devhandle_t *handle, void *arg);
#endif /* _INM_FILTER_H */
