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

/*
 * File       : db_routines.h
 */

inm_s32_t set_volume_out_of_sync(target_context_t *vcptr,
			   inm_u64_t out_of_sync_error_code,
			   inm_s32_t status_to_log);

void set_volume_out_of_sync_worker_routine(wqentry_t *wqe);

inm_s32_t queue_worker_routine_for_set_volume_out_of_sync(target_context_t *vcptr,
						    int64_t out_of_sync_error_code, inm_s32_t status);

inm_s32_t stop_filtering_device(target_context_t *vcptr, inm_s32_t lock_acquired, volume_bitmap_t **vbmap_ptr);
void add_resync_required_flag(UDIRTY_BLOCK_V2 *udb, target_context_t *vcptr);
void reset_volume_out_of_sync(target_context_t *vcptr);
