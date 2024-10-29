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
#include "work_queue.h"
#include "utils.h"
#include "filestream.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "VBitmap.h"
#include "change-node.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "data-mode.h"
#include "driver-context.h"
#include "file-io.h"
#include "osdep.h"
#include "db_routines.h"
#include "errlog.h"
#include "filestream_raw.h"
#include "bitmap_api.h"
#include "filter_host.h"

extern driver_context_t *driver_ctx;

void
lcw_move_bitmap_to_raw_mode(target_context_t *tgt_ctxt)
{
	inm_s32_t           error = 0;
	inm_u64_t           resync_error = 0;
	volume_bitmap_t     *vbmap = NULL;
	bitmap_api_t        *bapi = NULL;

	err("Switching bitmap file to rawio mode for %s", tgt_ctxt->tc_guid);

	inmage_flt_save_all_changes(tgt_ctxt, TRUE, INM_NO_OP);

	volume_lock(tgt_ctxt);
	if(tgt_ctxt->tc_bp->volume_bitmap) {
		get_volume_bitmap(tgt_ctxt->tc_bp->volume_bitmap);
		vbmap = tgt_ctxt->tc_bp->volume_bitmap;
	}
	volume_unlock(tgt_ctxt);
		
	if (!vbmap) {
		resync_error = ERROR_TO_REG_LEARN_PHYSICAL_IO_FAILURE;
		error = LINVOLFLT_ERR_DELETE_BITMAP_FILE_NO_NAME;
		goto out;
	}

	INM_DOWN(&vbmap->sem);

	if (vbmap->eVBitmapState != ecVBitmapStateClosed) {
		bapi = tgt_ctxt->tc_bp->volume_bitmap->bitmap_api;
		error = bitmap_api_switch_to_rawio_mode(bapi, &resync_error);
	} else {
		resync_error = ERROR_TO_REG_LEARN_PHYSICAL_IO_FAILURE;
		error = LINVOLFLT_ERR_BITMAP_FILE_CANT_OPEN;
	}
	
	INM_UP(&vbmap->sem);
	put_volume_bitmap(vbmap);

out:
	if (resync_error || error) {
		set_volume_out_of_sync(tgt_ctxt, resync_error, error);
		flush_and_close_bitmap_file(tgt_ctxt);
	}
}

static void
lcw_flush_volume_changes(target_context_t *tgt_ctxt)
{
	volume_bitmap_t     *vbmap = NULL;

	err("Flushing bitmap file in rawio mode for %s", tgt_ctxt->tc_guid);
	volume_lock(tgt_ctxt);
	if(tgt_ctxt->tc_bp->volume_bitmap) {
		vbmap = tgt_ctxt->tc_bp->volume_bitmap;
		get_volume_bitmap(vbmap);
	}
	volume_unlock(tgt_ctxt);
		
	if (!vbmap) 
		goto out;

	INM_BUG_ON(vbmap->eVBitmapState == ecVBitmapStateClosed); 
	
	inmage_flt_save_all_changes(tgt_ctxt, TRUE, INM_NO_OP);

	if (tgt_ctxt->tc_resync_required)
		bitmap_api_set_volume_out_of_sync(vbmap->bitmap_api,
					tgt_ctxt->tc_out_of_sync_err_code,
					tgt_ctxt->tc_out_of_sync_err_status);

	volume_lock(tgt_ctxt);
	tgt_ctxt->tc_flags |= VCF_VOLUME_STACKED_PARTIALLY;
	volume_unlock(tgt_ctxt);

	flush_and_close_bitmap_file(tgt_ctxt);
	
	volume_lock(tgt_ctxt);
	tgt_ctxt->tc_flags &= ~VCF_VOLUME_STACKED_PARTIALLY;
	volume_unlock(tgt_ctxt);

	put_volume_bitmap(vbmap);

out:
	return;
}

void
lcw_flush_changes(void)
{
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	target_context_t    *tgt_ctxt = NULL;
	target_context_t    *root = NULL;

	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	inm_list_for_each_safe(ptr, nextptr, &driver_ctx->tgt_list) {
		tgt_ctxt = inm_list_entry(ptr, target_context_t, tc_list);

		if (tgt_ctxt->tc_flags & 
				(VCF_VOLUME_CREATING | VCF_VOLUME_DELETING))
			continue;

		/* keep the root device for the end */
		if (isrootdev(tgt_ctxt)) {
			root = tgt_ctxt;
			continue;
		}

		if (tgt_ctxt->tc_bp->volume_bitmap) 
			lcw_flush_volume_changes(tgt_ctxt);
	}

	if (root && root->tc_bp->volume_bitmap)
		lcw_flush_volume_changes(root);
	else
		INM_BUG_ON(1); /* This should never happen */

	INM_UP_READ(&driver_ctx->tgt_list_sem);
}

static inm_s32_t
lcw_map_bitmap_file_blocks(target_context_t *tgt_ctxt)
{
	inm_s32_t           error = 0;
	volume_bitmap_t     *vbmap = NULL;
	fstream_raw_hdl_t   *hdl = NULL;

	err("Mapping bitmap file for %s", tgt_ctxt->tc_guid);

	volume_lock(tgt_ctxt);
	if(tgt_ctxt->tc_bp->volume_bitmap) {
		get_volume_bitmap(tgt_ctxt->tc_bp->volume_bitmap);
		vbmap = tgt_ctxt->tc_bp->volume_bitmap;
	}
	volume_unlock(tgt_ctxt);
		
	if (!vbmap) {
		error = INM_ENOENT;
		goto out;
	}

	INM_DOWN(&vbmap->sem);

	error = bitmap_api_map_file_blocks(vbmap->bitmap_api, &hdl);
	if (!error)
		fstream_raw_close(hdl);

	INM_UP(&vbmap->sem);
	put_volume_bitmap(vbmap);

out:
	return error;
}

inm_s32_t
lcw_perform_bitmap_op(char *guid, enum LCW_OP op)
{
	inm_s32_t           error = 0;
	target_context_t    *tgt_ctxt = NULL;


	tgt_ctxt = get_tgt_ctxt_from_uuid(guid);
	if (!tgt_ctxt) {
		error = -ENOENT;
		err("Guid not found - %s", guid);
		goto out;
	}

	err("Running op %d for disk %s", op, guid);

	switch (op) {
	case LCW_OP_BMAP_MAP_FILE: 
		error = lcw_map_bitmap_file_blocks(tgt_ctxt);
		break;

	case LCW_OP_BMAP_SWITCH_RAWIO:
		lcw_move_bitmap_to_raw_mode(tgt_ctxt);
		break;

	case LCW_OP_BMAP_CLOSE:
		lcw_flush_volume_changes(tgt_ctxt);
		write_to_file("/proc/sys/vm/drop_caches", "1", strlen("1"), 
									NULL);
		break;

	case LCW_OP_BMAP_OPEN:
		request_service_thread_to_open_bitmap(tgt_ctxt);
		break;

	default:
		err("Invalid opcode - %d", op);
		error = -EINVAL;
		break;
	}

	put_tgt_ctxt(tgt_ctxt);

out:
	return error;
}

inm_s32_t
lcw_map_file_blocks(char *name)
{
	fstream_raw_hdl_t   *hdl = NULL;
	inm_s32_t error = 0;

	error = fstream_raw_open(name, 0, 0, &hdl);
	if (error)
		fstream_raw_close(hdl);

	return error;
}

