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

#ifndef LINVOLFLT_METADATA_MODE_H
#define LINVOLFLT_METADATA_MODE_H
typedef struct _write_metadata_tag
{
	inm_u64_t offset;
	inm_u32_t length;

}write_metadata_t;

inm_u32_t split_change_into_chg_node(target_context_t *vcptr, write_metadata_t *wmd,
		inm_s32_t data_source, struct inm_list_head *split_chg_list_hd, inm_wdata_t *wdatap);
inm_s32_t add_metadata(target_context_t *vcptr, struct _change_node *chg_node, write_metadata_t *wmd,
				inm_s32_t data_source, inm_wdata_t *wdatap);
inm_s32_t save_data_in_metadata_mode(target_context_t *, write_metadata_t *, inm_wdata_t *);

inm_s32_t add_tag_in_non_stream_mode(tag_volinfo_t *, tag_info_t *,
                                     int, tag_guid_t *, inm_s32_t, 
                                     int commit_pending, tag_history_t *);
#endif
