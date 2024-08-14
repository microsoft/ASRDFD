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

#ifndef _TEL_H
#define _TEL_H

#include "target-context.h"
#include "change-node.h"
#include "telemetry-types.h"

/*
 * Prototypes - telemetry types ops
 */
void telemetry_set_dbs(inm_u64_t *, inm_u64_t);
void telemetry_clear_dbs(inm_u64_t *, inm_u64_t);
inm_u64_t telemetry_get_dbs(target_context_t *, inm_s32_t, 
                            etTagStateTriggerReason);

void telemetry_tag_stats_record(struct _target_context *, tgt_stats_t *);
inm_u64_t telemetry_get_wostate(struct _target_context *tgt_ctxt);
inm_u64_t telemetry_md_capture_reason(struct _target_context *);

void telemetry_tag_common_put(tag_telemetry_common_t *);
void telemetry_tag_common_get(tag_telemetry_common_t *);
tag_telemetry_common_t *telemetry_tag_common_alloc(inm_s32_t);

void telemetry_tag_history_free(tag_history_t *);
tag_history_t *telemetry_tag_history_alloc(struct _target_context *,
						   tag_telemetry_common_t *);
void telemetry_tag_history_record(struct _target_context *, tag_history_t *);

void telemetry_nwo_stats_record(target_context_t *, etWriteOrderState,
                                etWriteOrderState, etWOSChangeReason);
void telemetry_check_time_jump(void);

/*
 * Prototypes - telemetry ops
 */
inm_s32_t telemetry_init(void);
void telemetry_shutdown(void);

inm_s32_t telemetry_log_tag_history(change_node_t *, target_context_t *, 
                                 etTagStatus, etTagStateTriggerReason, 
                                 etMessageType);
inm_s32_t telemetry_log_tag_failure(target_context_t *,tag_telemetry_common_t *,
                                    inm_s32_t , etMessageType);
inm_s32_t telemetry_log_ioctl_failure(tag_telemetry_common_t *, inm_s32_t, 
                                      etMessageType);
void telemetry_log_drop_error(inm_s32_t);
#endif            
