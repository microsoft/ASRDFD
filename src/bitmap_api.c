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

/*********************************************************************
 * File       : bitmap_api.c
 *
 * Description: This file contains bitmap mode implementation of the
 *              filter driver.
 *
 * Functions defined in this file are
 *      bitmap_api_ctr
 *      bitmap_api_dtr
 *      initialize_bitmap_api
 *      terminate_bitmap_api
 *      bitmap_api_load_bitmap_header_from_filestream
 *      bitmap_api_is_bitmap_closed
 *      bitmap_api_close
 *      bitmap_api_set_writesize_not_to_exceed_volumesize
 *      bitmap_api_setbits
 *      bitmap_api_clearbits
 *      bitmap_api_get_first_runs
 *      bitmap_api_get_next_runs
 *      bitmap_api_clear_all_bits
 *      move_rawio_changes_to_bitmap
 *      bitmap_api_init_bitmap_file
 *      bitmap_api_commit_bitmap_internal
 *      bitmap_api_fast_zero_bitmap
 *      bitmap_api_commit_header
 *      bitmap_api_calculate_hdr_integrity_checksums
 *      bitmap_api_read_and_verify_bitmap_header
 *      bitmap_api_verify_header
 *      bitmap_api_save_write_metadata_to_bitmap
 *      bitmap_api_change_bitmap_mode_to_raw_io
 *      bitmap_api_commit_bitmap
 *      is_volume_in_sync
 *
 ************************************************************************/

#include "involflt-common.h"
#include "involflt.h"
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
#include "errlog.h"
#include "metadata-mode.h"
#include "md5.h"

extern driver_context_t *driver_ctx;

bitmap_api_t *bitmap_api_ctr()
{
	bitmap_api_t *bapi = NULL;

	bapi = (bitmap_api_t *)INM_KMALLOC(sizeof(bitmap_api_t), INM_KM_SLEEP,
						INM_KERNEL_HEAP);
	if (!bapi)
		return NULL;

	INM_MEM_ZERO(bapi,sizeof(*bapi));
	bapi->bitmap_file_state = BITMAP_FILE_STATE_UNINITIALIZED;
	INM_INIT_SEM(&bapi->sem);
	bapi->volume_insync = FALSE;
	bapi->err_causing_outofsync = 0;

	return bapi;
}


void bitmap_api_dtr(bitmap_api_t *bmap)
{
	if (bmap)
		INM_KFREE(bmap, sizeof(bitmap_api_t), INM_KERNEL_HEAP);
	bmap = NULL;
}


inm_s32_t initialize_bitmap_api()
{
	/* initialize async, iobuffer lookaside lists */
	return iobuffer_initialize_memory_lookaside_list();
}

inm_s32_t terminate_bitmap_api()
{
	/* terminate async, iobuffer lookaside lists */
	iobuffer_terminate_memory_lookaside_list();
	return 0;
}

inm_s32_t bitmap_api_open(bitmap_api_t *bapi, target_context_t *vcptr,
			inm_u32_t granularity, inm_u32_t offset,
			inm_u64_t volume_size, char *volume_name,
			inm_u32_t segment_cache_limit,
			inm_s32_t *detailed_status)
{
	inm_s32_t ret = 0;
	inm_s32_t status = 0;
	inm_u32_t max_bitmap_buffer_required = 0;
	fstream_segment_mapper_t *fssm = NULL;
	inm_u64_t _gran_vol_size = volume_size;
	inm_s32_t _dstatus = 0;
	char *bitmap_filename = vcptr->tc_bp->bitmap_file_name;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!bapi || !detailed_status || !bitmap_filename || !granularity ||
					!volume_size)
		return 1;

	*detailed_status = 0;

	INM_DOWN(&bapi->sem);
	bapi->bitmap_granularity = granularity;
	bapi->bitmap_offset = offset;
	bapi->volume_size = volume_size;

	if (volume_name) {
		if (strncpy_s(bapi->volume_name, INM_NAME_MAX + 1, volume_name,
							INM_NAME_MAX)) {
			ret = INM_EFAULT;
			goto cleanup_and_return_failure;
		}
	}

	INM_DO_DIV(_gran_vol_size, granularity);
	bapi->nr_bits_in_bitmap = (inm_u32_t)(_gran_vol_size + 1);
	bapi->bitmap_size_in_bytes = ((bapi->nr_bits_in_bitmap + 7) / 8);

	if ((bapi->bitmap_size_in_bytes % BITMAP_FILE_SEGMENT_SIZE) != 0)
		bapi->bitmap_size_in_bytes += BITMAP_FILE_SEGMENT_SIZE -
		(bapi->bitmap_size_in_bytes % BITMAP_FILE_SEGMENT_SIZE);

	bapi->bitmap_size_in_bytes += LOG_HEADER_OFFSET;
	max_bitmap_buffer_required =
		min((segment_cache_limit * BITMAP_FILE_SEGMENT_SIZE),
			bapi->bitmap_size_in_bytes);

	bapi->segment_cache_limit = segment_cache_limit;
	if (strncpy_s(bapi->bitmap_filename, INM_NAME_MAX + 1, bitmap_filename,
							INM_NAME_MAX)) {
		ret = INM_EFAULT;
		goto cleanup_and_return_failure;
	}

	if ((driver_ctx->dc_bmap_info.current_bitmap_buffer_memory +
			       			max_bitmap_buffer_required) >
		driver_ctx->dc_bmap_info.max_bitmap_buffer_memory) {
		*detailed_status = LINVOLFLT_ERR_BITMAP_FILE_EXCEEDED_MEMORY_LIMIT;
		ret = -ENOMEM;
		goto cleanup_and_return_failure;
	}

	if (INM_MEM_CMP("/dev/", bitmap_filename, strlen("/dev/")) == 0) {
		//bitmap is a raw volume
	} else {
		bapi->bitmap_offset = 0;
	}

	bapi->fssm = fssm = fstream_segment_mapper_ctr();
	if (!fssm) {
		info("error in fssm_ctr \n");
		goto cleanup_and_return_failure;
	}

	fssm->bapi = bapi;

	ret = fstream_segment_mapper_attach(fssm, bapi,
				bapi->bitmap_offset + LOG_HEADER_OFFSET,
				(bapi->nr_bits_in_bitmap/8)+1,
				segment_cache_limit);
	if (ret) {
		info("fssm attach error = %d", ret);
		goto cleanup_and_return_failure;
	}

	bapi->sb = segmented_bitmap_ctr(fssm, bapi->nr_bits_in_bitmap);
	if (bapi->sb == NULL) {
		*detailed_status = LINVOLFLT_ERR_NO_MEMORY;
		status = -ENOMEM;
		info("sb ctr error = %d",ret);
		goto cleanup_and_return_failure;
	}

	driver_ctx->dc_bmap_info.current_bitmap_buffer_memory +=
						max_bitmap_buffer_required;
	ret = bitmap_api_open_bitmap_stream(bapi, vcptr, &_dstatus);
	*detailed_status = _dstatus;

	if (ret && (bapi->bitmap_filename[0] == '/')) {
		if (is_rootfs_ro()) {
			info("root is read only file system : "
			     "can't open/create bitmap files, "
			     "so moving to raw bitmap mode.\n");
			     goto exit_fn;
		}
		else {
			info("root file system is full or missing directory "
				"hierarchy : so can't open/create bitmap "
				"files.\n");
			goto cleanup_and_return_failure;
		}
	}

exit_fn:
	INM_UP(&bapi->sem);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return 0;

cleanup_and_return_failure:

	if (bapi->sb != NULL) {
		segmented_bitmap_put(bapi->sb);
		bapi->sb = NULL;
	}

	if (bapi->fssm != NULL) {
		fstream_segment_mapper_put(bapi->fssm);
		bapi->fssm = NULL;
	}

	if (bapi->fs != NULL) {
		fstream_close(bapi->fs);
		fstream_put(bapi->fs);
		bapi->fs = NULL;
	}

	if (bapi->io_bitmap_header != NULL) {
		iobuffer_put(bapi->io_bitmap_header);
		bapi->io_bitmap_header = NULL;
	}

	bapi->bitmap_file_state = BITMAP_FILE_STATE_UNINITIALIZED;
	INM_UP(&bapi->sem);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving - cleaning the memory on error");
	}

	return ret;
}


void bitmap_api_upgrade_header(bitmap_api_t *bapi)
{
	inm_s32_t error = 0;
	inm_s32_t upgrade_error = 0;

	while (!error && 
		bapi->bitmap_header.un.header.version != BITMAP_FILE_VERSION) {
		switch (bapi->bitmap_header.un.header.version) {
		case BITMAP_FILE_VERSION1:
			bapi->bitmap_header.un.header.resync_required = 0; 
			bapi->bitmap_header.un.header.resync_errcode = 0; 
			bapi->bitmap_header.un.header.resync_errstatus = 0; 
			bapi->bitmap_header.un.header.version =
			       				BITMAP_FILE_VERSION2;
			bapi->bitmap_header.un.header.header_size =
							BITMAP_HDR2_SIZE;
			break;

		default:
			/* This should never happen as header is verified
			 * before upgrade
			 */
			err("Invalid version - %x", 
			        bapi->bitmap_header.un.header.version);
			INM_BUG_ON(1); 
			error = -EINVAL;
		}
	}

	if (!error) {
		bitmap_api_calculate_hdr_integrity_checksums(&bapi->bitmap_header);
		if (bitmap_api_verify_header(bapi, &bapi->bitmap_header)) {
			error = bitmap_api_commit_header(bapi, FALSE,
							&upgrade_error);
			if (error) {
				err("Cannot persist bitmap header - %x",
								upgrade_error);
			} else {
				info("Successfully upgraded bitmap to version "
					"0x%x", 
			         bapi->bitmap_header.un.header.version);
			}
		} else {
			err("Bitmap upgrade header verification failed");
		}
	}
}

inm_s32_t bitmap_api_load_bitmap_header_from_filestream(bitmap_api_t *bapi,
			 inm_s32_t *detailed_status, inm_s32_t was_created)
{
	inm_s32_t ret = 0;
	iobuffer_t *iob;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}


	*detailed_status = 0;
	bapi->volume_insync = FALSE;
	bapi->err_causing_outofsync = 0;

	bapi->io_bitmap_header = iob =  iobuffer_ctr(bapi, LOG_HEADER_SIZE, 0);
	if (!iob) {
		info("iob is null");
		return -ENOMEM;
	}
	
	if (!was_created)
	{
		ret = iobuffer_sync_read(iob);

		if (ret) {
			*detailed_status = bapi->err_causing_outofsync =
			    LINVOLFLT_ERR_BITMAP_FILE_CANT_READ;
			goto cleanup_and_return_failure;
		}

		if (memcpy_s(&bapi->bitmap_header, sizeof(bapi->bitmap_header), 
			iob->buffer, sizeof(bapi->bitmap_header))) {
			ret = INM_EFAULT;
			goto cleanup_and_return_failure;
		}

		if (!bitmap_api_verify_header(bapi, &bapi->bitmap_header))
		{
			*detailed_status = bapi->err_causing_outofsync =
			    LINVOLFLT_ERR_BITMAP_FILE_LOG_FIXED;
			info("Verify header failed, bitmap file is corrupted");
			bapi->corrupt_bitmap = TRUE;
		}

		if (bapi->bitmap_header.un.header.recovery_state ==
		BITMAP_LOG_RECOVERY_STATE_CLEAN_SHUTDOWN) {
			if ((bapi->bitmap_header.un.header.version >=
							BITMAP_FILE_VERSION2) 
			&& (bapi->bitmap_header.un.header.resync_required)) {
			*detailed_status = bapi->err_causing_outofsync = 
				bapi->bitmap_header.un.header.resync_errcode;
			        bapi->bitmap_header.un.header.resync_required = 0;
			        bapi->bitmap_header.un.header.resync_errcode = 0;
			        bapi->bitmap_header.un.header.resync_errstatus = 0;
			} else {
				dbg("previous shutdown was normal");
				bapi->volume_insync = TRUE;
			}
		} else {
			*detailed_status = bapi->err_causing_outofsync =
			    LINVOLFLT_ERR_LOST_SYNC_SYSTEM_CRASHED;
			info("indicates unexpected previous shutdown");
		}

		bapi->bitmap_header.un.header.boot_cycles++;

		if (bapi->bitmap_header.un.header.version !=
							BITMAP_FILE_VERSION)
			bitmap_api_upgrade_header(bapi);

		return 0;
		
	} else {
		bapi->new_bitmap = 1;
		*detailed_status = bapi->err_causing_outofsync =
			LINVOLFLT_ERR_BITMAP_FILE_CREATED;
	}


	ret = bitmap_api_init_bitmap_file(bapi, detailed_status);

	if(ret) {
		*detailed_status = bapi->err_causing_outofsync =
			LINVOLFLT_ERR_BITMAP_FILE_CANT_INIT;
		goto cleanup_and_return_failure;
	}

	if (bapi->empyt_bitmap) {
		err("repaired empty bitmap file");
	}
	else {
		if (bapi->corrupt_bitmap) {
			err("repaired corrupt bitmap file");
		}
		else {
			err("created new bitmap file");
		}
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return 0;

cleanup_and_return_failure:

	if (bapi->io_bitmap_header != NULL) {
		err("error in loading bitmap header");
		iobuffer_dtr(bapi->io_bitmap_header);
		bapi->io_bitmap_header = NULL;
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}


inm_s32_t bitmap_api_is_volume_insync(bitmap_api_t *bapi,
		inm_u8_t *volume_insync, inm_s32_t *out_of_sync_err_code)
{
	inm_s32_t ret = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (volume_insync == NULL)
		return EINVAL;

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:
	case BITMAP_FILE_STATE_RAWIO:
		*volume_insync = bapi->volume_insync;
		if (out_of_sync_err_code != NULL)
			*out_of_sync_err_code = bapi->err_causing_outofsync;

		break;
	default:
		ret = EINVAL;
		break;
	}

	INM_UP(&bapi->sem);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving - volume in sync = %d", *volume_insync);
	}

	return ret;
}


inm_s32_t bitmap_api_is_bitmap_closed(bitmap_api_t *bapi)
{
	inm_s32_t closed = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:
	case BITMAP_FILE_STATE_RAWIO:
		closed = 0;
		break;
	default:
		closed = 1;
		break;
	}

	INM_UP(&bapi->sem);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving = %d", closed);
	}

	return closed;
}


inm_s32_t bitmap_api_close(bitmap_api_t *bapi, inm_s32_t *close_status)
{
	inm_s32_t ret = 0;
	int clean_shutdown = 1;
	

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:
	case BITMAP_FILE_STATE_RAWIO:
		dbg("close issued on %s in %d state\n",
			bapi->bitmap_filename, bapi->bitmap_file_state);
		ret = bitmap_api_commit_bitmap_internal(bapi, clean_shutdown,
								close_status);    
		break;
	default:
		ret = EINVAL;
	break;
	}

	if (bapi->sb != NULL) {
		segmented_bitmap_put(bapi->sb);
		bapi->sb = NULL;
	}

	if (bapi->fssm != NULL) {
		fstream_segment_mapper_put(bapi->fssm);
		bapi->fssm = NULL;
	}

	if (bapi->fs != NULL) {
		fstream_close(bapi->fs);
		fstream_put(bapi->fs);
		bapi->fs = NULL;
	}

	if (bapi->io_bitmap_header != NULL) {
		iobuffer_put(bapi->io_bitmap_header);
		bapi->io_bitmap_header = NULL;
	}

	driver_ctx->dc_bmap_info.current_bitmap_buffer_memory -=
		min(bapi->segment_cache_limit * BITMAP_FILE_SEGMENT_SIZE,
				bapi->bitmap_size_in_bytes);
	bapi->bitmap_file_state = BITMAP_FILE_STATE_CLOSED;

	INM_UP(&bapi->sem);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value %d", ret);
	}

	return ret;
}

void bitmap_api_getscaled_offsetandsize_from_diskchange(bitmap_api_t *bapi,
	disk_chg_t *dc, inm_u64_t *scaled_offset, inm_u64_t *scaled_size)
{
	inm_u64_t _gran_scaled_offset = (inm_u64_t) dc->offset;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DO_DIV(_gran_scaled_offset, bapi->bitmap_granularity);

	/* round down offset */
	*scaled_offset= _gran_scaled_offset * bapi->bitmap_granularity;

	/* 1st, calculate how much size grew from rounding down */
	*scaled_size = dc->offset - *scaled_offset;

	/* 2nd, add in the actual size plus rounding factor */
	*scaled_size += ((inm_u64_t)dc->length) +
					(bapi->bitmap_granularity - 1);

	 /* 3rd, now scale it to the granularity */
	INM_DO_DIV(*scaled_size, bapi->bitmap_granularity);

	INM_DO_DIV(*scaled_offset, bapi->bitmap_granularity);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving scaled offset = %llu , scaled size = %llu",
				*scaled_offset, *scaled_size);
	}

}

void bitmap_api_getscaled_offsetandsize_from_writemetadata(bitmap_api_t *bapi,
		write_metadata_t *wmd, inm_u64_t *scaled_offset,
		inm_u64_t *scaled_size)
{
	inm_u64_t _gran_scaled_offset = (inm_u64_t) wmd->offset;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DO_DIV(_gran_scaled_offset, bapi->bitmap_granularity);

	/* round down offset */
	*scaled_offset= _gran_scaled_offset * bapi->bitmap_granularity;

	/* 1st, calculate how much size grew from rounding down */
	*scaled_size = ((inm_u64_t)wmd->offset) - *scaled_offset;

	/* 2nd, add in the actual size plus rounding factor */
	*scaled_size += wmd->length + (bapi->bitmap_granularity - 1);

	/* 3rd, now scale it to the granularity */
	INM_DO_DIV(*scaled_size, bapi->bitmap_granularity);

	INM_DO_DIV(*scaled_offset, bapi->bitmap_granularity);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

}

inm_s32_t bitmap_api_set_writesize_not_to_exceed_volumesize(bitmap_api_t *bapi,
						      disk_chg_t *dc)
{
	inm_s32_t ret = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if ((dc->length + dc->offset) > bapi->volume_size) {
		if (dc->offset < bapi->volume_size) {
			dc->length = (inm_u32_t)(bapi->volume_size -
								dc->offset);
			ret = 0;
		} else {
			ret = EOF_BMAP;
		}
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}


inm_s32_t bitmap_api_setbits(bitmap_api_t *bapi, bitruns_t *bruns, 
			                 volume_bitmap_t *vbmap)
{
	inm_s32_t ret = 0;
	inm_u32_t current_run = 0;
	inm_u64_t scaled_offset = 0, scaled_size = 0;
	logheader_t *lh = NULL; /* log header */
	bitmap_header_t *bh = NULL;
	inm_u32_t index = 0, rem = 0;
	struct inm_list_head *ptr;
	inm_page_t *pgp;
	inm_ull64_t rem_runs, nbr_runs;
	int skip_logged = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	bruns->nbr_runs_processed = 0;

	bh = &bapi->bitmap_header;
	lh = &bh->un.header;

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:

	rem_runs = bruns->nbr_runs;
	__inm_list_for_each(ptr, &bruns->meta_page_list){
		pgp = inm_list_entry(ptr, inm_page_t, entry);
		bruns->runs = (disk_chg_t *)pgp->cur_pg;
		nbr_runs = pgp->nr_chgs;

		for(current_run = 0; current_run < nbr_runs; current_run++) {
			INM_DOWN(&vbmap->sem);
			if (!vbmap->bitmap_skip_writes) {
			        INM_UP(&vbmap->sem);
				bitmap_api_getscaled_offsetandsize_from_diskchange(bapi,
				    		&bruns->runs[current_run],
						&scaled_offset, &scaled_size);
				if ((bruns->runs[current_run].offset < bapi->volume_size) &&
						(bruns->runs[current_run].offset >= 0) &&
						((bruns->runs[current_run].offset +
						bruns->runs[current_run].length) <=
								bapi->volume_size)) {
			    
					bruns->final_status = segmented_bitmap_set_bitrun(bapi->sb,
					    		(inm_u32_t)scaled_size,
						    	scaled_offset);
					ret = bruns->final_status;
					if (ret)
						goto out_err;
					bruns->nbr_runs_processed++;
				}
			} else {
				INM_UP(&vbmap->sem);
				if (!skip_logged) {
					err("Skipping bitmap writes");
					skip_logged = 1;
				}

				/* treat it as successful write so downstream 
				 * processing is not affected 
				 */
				bruns->final_status = 0;
				bruns->nbr_runs_processed++;
			}
		}

		rem_runs -= nbr_runs;
		if(!rem_runs)
			break;
	}

out_err:
	break;

	case BITMAP_FILE_STATE_RAWIO:

	dbg("writing last chance changes \n");
	rem_runs = bruns->nbr_runs;
	__inm_list_for_each(ptr, &bruns->meta_page_list){
		pgp = inm_list_entry(ptr, inm_page_t, entry);
		bruns->runs = (disk_chg_t *)pgp->cur_pg;
		nbr_runs = pgp->nr_chgs;

		for(current_run = 0; current_run < nbr_runs; current_run++) {
			if (lh->last_chance_changes ==
				(MAX_WRITE_GROUPS_IN_BITMAP_HEADER *
						MAX_CHANGES_IN_WRITE_GROUP)){
				lh->changes_lost += bruns->nbr_runs - current_run;
				break;
			}

			bitmap_api_getscaled_offsetandsize_from_diskchange(bapi,
				       &bruns->runs[current_run],
				       &scaled_offset, &scaled_size);

			while (scaled_size > 0 && lh->last_chance_changes <
				(MAX_WRITE_GROUPS_IN_BITMAP_HEADER * MAX_CHANGES_IN_WRITE_GROUP)) {
				index = lh->last_chance_changes/MAX_CHANGES_IN_WRITE_GROUP;
				rem = lh->last_chance_changes % MAX_CHANGES_IN_WRITE_GROUP;

				bh->change_groups[index].un.length_offset_pair[rem] =
					(min(scaled_size, (inm_u64_t)0xffff) << 48) |
					(scaled_offset & 0xffffffffffffULL);

				 dbg("len off pair = %llu, off = %llu, len = %llu", 
					 bh->change_groups[index].un.length_offset_pair[rem], 
					 scaled_offset, scaled_size);

				 scaled_offset += min(scaled_size, (inm_u64_t)0xffff);
				 scaled_size -= min(scaled_size, (inm_u64_t)0xffff);
				 lh->last_chance_changes++;
			}

			bruns->nbr_runs_processed++;
			dbg("bruns = %d\n", bruns->nbr_runs_processed);
		}

		info("# of last chance changes = %d", lh->last_chance_changes);
		rem_runs -= nbr_runs;
		if(!rem_runs)
			break;
	}

	bruns->final_status = 0;
	break;

	default:
	ret = -EBUSY;
	bruns->final_status = ret;
	break;
	}

	INM_UP(&bapi->sem);

	if (bruns->completion_callback)
		bruns->completion_callback(bruns);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}


inm_s32_t bitmap_api_clearbits(bitmap_api_t *bapi, bitruns_t *bruns)
{
	inm_s32_t ret = 0;
	inm_u32_t current_run;
	inm_u64_t scaled_offset, scaled_size;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	bruns->nbr_runs_processed = 0;
	
	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:
	for(current_run = 0; current_run < bruns->nbr_runs; current_run++)
	{
		bitmap_api_getscaled_offsetandsize_from_diskchange(bapi,
			&bruns->runs[current_run], &scaled_offset, &scaled_size);

		if ((bruns->runs[current_run].offset < bapi->volume_size) &&
		(bruns->runs[current_run].offset >= 0) &&
		((bruns->runs[current_run].offset + 
		  bruns->runs[current_run].length) <= bapi->volume_size)) {
			bruns->final_status =
				segmented_bitmap_clear_bitrun(bapi->sb,
						  (inm_u32_t)scaled_size,
						  scaled_offset);

			ret = bruns->final_status;
			if (ret)
				break;
			bruns->nbr_runs_processed++;                    
		}
	}

	if (bruns->nbr_runs_processed != 0)
		segmented_bitmap_sync_flush_all(bapi->sb);
	break;
			    
	default:
	ret = -EBUSY;
	break;
	}

	INM_UP(&bapi->sem);
	
	bruns->final_status = ret;
	
	if (bruns->completion_callback)
		bruns->completion_callback(bruns);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}

inm_s32_t bitmap_api_get_first_runs(bitmap_api_t *bapi, bitruns_t *bruns)
{
	inm_s32_t ret = 0;
	inm_u32_t current_run = 0;

	bruns->nbr_runs = 0;
	bruns->nbr_runs_processed = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state)
	{
	case BITMAP_FILE_STATE_OPENED:
	ret = segmented_bitmap_get_first_bitrun(bapi->sb,
			(inm_u32_t *)&bruns->runs[current_run].length,
			&bruns->runs[current_run].offset);

	bruns->runs[current_run].length *= bapi->bitmap_granularity;
	bruns->runs[current_run].offset *= bapi->bitmap_granularity;

	if (ret == 0)
		ret = bitmap_api_set_writesize_not_to_exceed_volumesize(bapi,
					&bruns->runs[current_run]);

	if (ret == 0) {
		current_run++;
		bruns->nbr_runs_processed++;
		bruns->nbr_runs++;

		while(ret == 0 && current_run < MAX_KDIRTY_CHANGES) {
			ret = segmented_bitmap_get_next_bitrun(bapi->sb,
				(inm_u32_t *)&bruns->runs[current_run].length,
				&bruns->runs[current_run].offset);

			bruns->runs[current_run].length *= bapi->bitmap_granularity;

			bruns->runs[current_run].offset *= bapi->bitmap_granularity;
			        
			if (ret == 0)
				ret = bitmap_api_set_writesize_not_to_exceed_volumesize(bapi,
							  &bruns->runs[current_run]);                    

			if (ret == 0) {
				if ((current_run > 0) && 
				((bruns->runs[current_run - 1].offset +
				  bruns->runs[current_run -1].length) ==
				 (bruns->runs[current_run].offset)) &&
				bruns->runs[current_run-1].length < 0x1000000 &&
				(bruns->runs[current_run-1].length < 0x1000000)) {
				/*
				 * don't merge if already large size,
				 *  prevents int32 overflow
				 */
				bruns->runs[current_run-1].length +=
				bruns->runs[current_run].length;
				} else {
					bruns->nbr_runs_processed++;
					bruns->nbr_runs++;
					current_run++;
				}
			}

		}
	}

	if (ret == 0 && current_run == MAX_KDIRTY_CHANGES) {
		ret = EAGAIN;
	} else if (ret == EOF_BMAP) {
		ret = 0;
	}                
	break;
			    
	default:
	ret = EBUSY;
	break;
	}

	INM_UP(&bapi->sem);

	bruns->final_status = ret;
	
	if (bruns->completion_callback)
		bruns->completion_callback(bruns);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}


inm_s32_t bitmap_api_get_next_runs(bitmap_api_t *bapi, bitruns_t *bruns)
{
	inm_s32_t ret = 0;
	inm_u32_t current_run = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	bruns->nbr_runs = 0;
	bruns->nbr_runs_processed = 0;

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state)
	{
	case BITMAP_FILE_STATE_OPENED:
			
	while(ret == 0 && current_run < MAX_KDIRTY_CHANGES)
	{
		ret = segmented_bitmap_get_next_bitrun(bapi->sb,
			(inm_u32_t *)&bruns->runs[current_run].length,
			&bruns->runs[current_run].offset);
		bruns->runs[current_run].length *= bapi->bitmap_granularity;
		bruns->runs[current_run].offset *= bapi->bitmap_granularity;
			    
		if (ret == 0)
			ret = bitmap_api_set_writesize_not_to_exceed_volumesize(bapi,
					&bruns->runs[current_run]);                    
			    
		if (ret == 0) {
			if ((current_run > 0) && 
				((bruns->runs[current_run - 1].offset + bruns->runs[current_run -1].length) ==
				 (bruns->runs[current_run].offset)) && bruns->runs[current_run-1].length < 0x1000000 &&
				(bruns->runs[current_run-1].length < 0x1000000)) {
				/* don't merge if already large size, prevents int32 overflow */
				bruns->runs[current_run-1].length +=
						bruns->runs[current_run].length;
			}
			else {
				bruns->nbr_runs_processed++;
				bruns->nbr_runs++;
				current_run++;
			}
		}
			        
		if (ret == 0 && current_run == MAX_KDIRTY_CHANGES) {
			ret = EAGAIN;
		}
		else if (ret == EOF_BMAP) {
			ret = 0;
			break;
		}
	}
			    
	break;
			    
	default:
	ret = EBUSY;
	break;
	}

	INM_UP(&bapi->sem);

	bruns->final_status = ret;
	
	if (bruns->completion_callback)
		bruns->completion_callback(bruns);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;
}

inm_s32_t bitmap_api_clear_all_bits(bitmap_api_t *bapi)
{

	inm_s32_t ret = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DOWN(&bapi->sem);

	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:
		fstream_enable_buffered_io(bapi->fs);
		ret = segmented_bitmap_clear_all_bits(bapi->sb);
		segmented_bitmap_sync_flush_all(bapi->sb);
		fstream_disable_buffered_io(bapi->fs);
		fstream_sync(bapi->fs);
		break;
			    
	default:
		ret = EBUSY;
		break;
	}

	INM_UP(&bapi->sem);


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", ret);
	}

	return ret;        
}

inm_s32_t move_rawio_changes_to_bitmap(bitmap_api_t *bapi,
					inm_s32_t *inmage_open_status)
{

	inm_u64_t i = 0, scaled_size = 0, write_size = 0;
	inm_u64_t   size_offset_pair = 0,
	scaled_offset = 0,
	write_offset = 0,
	rounded_volume_size = 0;
			               
	inm_s32_t status = 0;
	inm_u32_t max_nr_lcw = 0;
	inm_s32_t nr_changes_discarded = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	
	/*
	 * bitmap has to be in opened state
	 * this operation can't be performed in committed, raw io/closed state
	 */
	
	if (bapi->bitmap_file_state != BITMAP_FILE_STATE_OPENED)
		return -EINVAL;
		
	rounded_volume_size = ((inm_u64_t) bapi->volume_size +
			   bapi->bitmap_granularity - 1);
	INM_DO_DIV(rounded_volume_size, bapi->bitmap_granularity);
	rounded_volume_size *= bapi->bitmap_granularity;
	
	/* now sweep through and save any last chance changes into bitmap */


	max_nr_lcw = min(bapi->bitmap_header.un.header.last_chance_changes,
			         (inm_u32_t)(MAX_WRITE_GROUPS_IN_BITMAP_HEADER * MAX_CHANGES_IN_WRITE_GROUP));
	info("%s: Last chance changes - %u", bapi->volume_name, max_nr_lcw);
	for (i = 0; i < max_nr_lcw; i++) {
		size_offset_pair = bapi->bitmap_header.change_groups[i /
		MAX_CHANGES_IN_WRITE_GROUP ].un.length_offset_pair[i%MAX_CHANGES_IN_WRITE_GROUP];
		
		scaled_size = (unsigned long) (size_offset_pair >> 48);
		scaled_offset = size_offset_pair & 0xFFFFFFFFFFFFULL;
		dbg("read len off pair = %llu off = %llu len = %llu", 
				size_offset_pair, scaled_offset, scaled_size);
		write_offset = scaled_offset * bapi->bitmap_granularity;
		write_size = scaled_size * bapi->bitmap_granularity;
	
		if (write_offset < bapi->volume_size) {
			
			if ((write_offset + write_size) > rounded_volume_size) {
				INM_BUG_ON(1);
				/*
				 * as the granularity used to save changes in raw io mode is same as
				 * bitmap granularity. this should not happen
				 */
				dbg("correcting write offset, write size");
				scaled_size = (unsigned long)
					((inm_u64_t) bapi->volume_size - write_offset);

				scaled_size = scaled_size + bapi->bitmap_granularity - 1;
				INM_DO_DIV(scaled_size, bapi->bitmap_granularity);
				    
				dbg("corrected write size ");
			}
			
			/* In case of header blocks verification signature, size == 0 */
			if (scaled_size) { 
				status = segmented_bitmap_set_bitrun(bapi->sb,
						 (inm_u32_t) scaled_size,
						 scaled_offset);
				if (status) {
					*inmage_open_status = bapi->err_causing_outofsync = 
						LINVOLFLT_ERR_BITMAP_FILE_CANT_APPLY_SHUTDOWN_CHANGES;
					bapi->volume_insync = FALSE;
					info("error writing raw io changes to bitmap");
					return status;
				}
			}
		} else {
			nr_changes_discarded++;
		}
	}

	if (nr_changes_discarded) {
		info("Number of changes discarded for volume %s = %d",
			bapi->volume_name, nr_changes_discarded);
	}
	
	if (bapi->bitmap_header.un.header.changes_lost) {
		*inmage_open_status = bapi->err_causing_outofsync =
		LINVOLFLT_ERR_TOO_MANY_LAST_CHANCE;
		bapi->volume_insync = FALSE;
		info("lost changes");
	}
	
	bapi->bitmap_header.un.header.last_chance_changes = 0;
	bapi->bitmap_header.un.header.changes_lost = 0;

	/* unless we shutdown clean, assume dirty */
	bapi->bitmap_header.un.header.recovery_state =
		BITMAP_LOG_RECOVERY_STATE_DIRTY_SHUTDOWN; 
	
	/*
	 * We have to update the header even if there are no raw io changes.
	 * We have to do this to save the header with new state indicating the bitmap is dirty.
	 */
	bapi->bitmap_header.un.header.last_chance_changes = 0;
	status = bitmap_api_commit_header(bapi, FALSE, inmage_open_status);
		
	if (status) {
		info("error in updating bitmap header ");
		*inmage_open_status = bapi->err_causing_outofsync =
				LINVOLFLT_ERR_BITMAP_FILE_CANT_UPDATE_HEADER;
		bapi->volume_insync = FALSE;
	}
		

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}

inm_s32_t bitmap_api_init_bitmap_file(bitmap_api_t *bapi,
		inm_s32_t *inmage_status)
{
	inm_s32_t status = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	status = bitmap_api_fast_zero_bitmap(bapi);
	if (status != 0)
		return status;
	
#define bmap_hdr    bapi->bitmap_header.un.header

	bmap_hdr.endian = BITMAP_FILE_ENDIAN_FLAG;
	bmap_hdr.header_size = sizeof(logheader_t);
	bmap_hdr.version = BITMAP_FILE_VERSION;
	bmap_hdr.data_offset = LOG_HEADER_OFFSET;
	bmap_hdr.bitmap_offset = bapi->bitmap_offset;
	bmap_hdr.bitmap_size = bapi->nr_bits_in_bitmap;
	bmap_hdr.bitmap_granularity = bapi->bitmap_granularity;
	bmap_hdr.volume_size = bapi->volume_size;
	bmap_hdr.recovery_state = BITMAP_LOG_RECOVERY_STATE_DIRTY_SHUTDOWN;
	bmap_hdr.last_chance_changes = 0;
	bmap_hdr.boot_cycles = 0;
	bmap_hdr.changes_lost = 0;
	bmap_hdr.resync_required = 0;
	bmap_hdr.resync_errcode = 0;
	bmap_hdr.resync_errstatus = 0;

	status = bitmap_api_commit_header(bapi, FALSE, inmage_status);
	

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
#undef bmap_hdr
}

inm_s32_t bitmap_api_commit_bitmap_internal(bitmap_api_t *bapi, 
		int clean_shutdown, inm_s32_t *inmage_status)
{

	inm_s32_t status = 0;
	

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	switch (bapi->bitmap_file_state) {
	
	case BITMAP_FILE_STATE_OPENED:
		bapi->bitmap_header.un.header.recovery_state = clean_shutdown ?
			BITMAP_LOG_RECOVERY_STATE_CLEAN_SHUTDOWN : 
			BITMAP_LOG_RECOVERY_STATE_DIRTY_SHUTDOWN;
		segmented_bitmap_sync_flush_all(bapi->sb);
		status = bitmap_api_commit_header(bapi, FALSE, inmage_status);
		if (status) {
			info("unable to write header");
			status = LINVOLFLT_ERR_FINAL_HEADER_FS_WRITE_FAILED;
		}
		break;
	
	case BITMAP_FILE_STATE_RAWIO:
		if (!bapi->io_bitmap_header) {
			status = -EINVAL;
			break;
		}
		/* Flush all the changes with a dirty header. This way, we can 
		 * guarantee all the lcw have been written to the disk before
		 * marking the header clean on the disk.
		 */
		bapi->bitmap_header.un.header.recovery_state =
			    BITMAP_LOG_RECOVERY_STATE_DIRTY_SHUTDOWN;
		status = bitmap_api_commit_header(bapi, TRUE, inmage_status);
		if (!status && clean_shutdown) {
			bapi->bitmap_header.un.header.recovery_state =
			    BITMAP_LOG_RECOVERY_STATE_CLEAN_SHUTDOWN;
			status = bitmap_api_commit_header(bapi, FALSE,
				       				inmage_status);
			if (status) {
				info("unable to write header with raw io");
				status = LINVOLFLT_ERR_FINAL_HEADER_FS_WRITE_FAILED;
			}
		}
		break;
		
	default:
		status = 1;
		break;
	}
	

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}

inm_s32_t bitmap_api_fast_zero_bitmap(bitmap_api_t *bapi)
{
	inm_s32_t status = 0;
	inm_u64_t i = 0;
	iobuffer_t *iob = NULL;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	iob = iobuffer_ctr(bapi, BITMAP_FILE_SEGMENT_SIZE, 0);
	if (!iob) {
		info("memory allocation failed for iobuffer %p\n", iob);
		return -ENOMEM;
	}

	iobuffer_set_fstream(iob, bapi->fs);
	fstream_enable_buffered_io(bapi->fs);
	
	for(i = bapi->bitmap_offset + LOG_HEADER_OFFSET;
		i < (bapi->bitmap_offset + bapi->bitmap_size_in_bytes);
		i += BITMAP_FILE_SEGMENT_SIZE) {

		iobuffer_set_foffset(iob, i);
		iobuffer_setdirty(iob);
		status = iobuffer_sync_flush(iob);
	
		if (status != 0) {
			break;
		}
	}
	
	fstream_disable_buffered_io(bapi->fs);
	fstream_sync(bapi->fs);

	iobuffer_put(iob);
		iob = NULL;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}


inm_s32_t bitmap_api_verify_header_blocks(bitmap_api_t *bapi, bitmap_header_t *hdr)
{
	int i = 0;
	inm_u64_t sig = 0;
	char *vname = NULL;
	char *csig = (char *)&sig;
	int matches = TRUE;

	/* The last three bytes of volume name are always unique */
	vname = bapi->volume_name + 
			(strlen(bapi->volume_name) -
			 BITMAP_LCW_SIGNATURE_PREFIX_SZ);

	/* Volume Name as prefix */
	for (i = 0; i < BITMAP_LCW_SIGNATURE_PREFIX_SZ; i++)
		csig[i] = vname[i];

	sig |= BITMAP_LCW_SIGNATURE_SUFFIX;

	info("Signature: %llx", sig);
	
	for (i = 0; i < MAX_WRITE_GROUPS_IN_BITMAP_HEADER; i++) {
		if (hdr->change_groups[i].un.length_offset_pair[0] != sig) {
			err("Signature Mismatch. CG[%d] %llx != %llx", i, 
			    hdr->change_groups[i].un.length_offset_pair[0],
			    sig);
			matches = FALSE;
			break;
		}
	}

	return matches;
}

void bitmap_api_clear_signed_header_blocks(bitmap_api_t *bapi)
{
	int i = 0;

	for (i = 0; i < MAX_WRITE_GROUPS_IN_BITMAP_HEADER; i++)
		bapi->bitmap_header.change_groups[i].un.length_offset_pair[0] = 0; 
}

void bitmap_api_sign_header_blocks(bitmap_api_t *bapi)
{
	int i = 0;
	inm_u64_t sig = 0;
	char *vname = NULL;
	char *csig = (char *)&sig;

	/* The last three bytes of volume name are always unique */
	vname = bapi->volume_name + 
			(strlen(bapi->volume_name) -
			 BITMAP_LCW_SIGNATURE_PREFIX_SZ);

	/* Volume Name as prefix */
	for (i = 0; i < BITMAP_LCW_SIGNATURE_PREFIX_SZ; i++)
		csig[i] = vname[i];

	sig |= BITMAP_LCW_SIGNATURE_SUFFIX;

	info("Signature: %llx", sig);

	for (i = 0; i < MAX_WRITE_GROUPS_IN_BITMAP_HEADER; i++)
		bapi->bitmap_header.change_groups[i].un.length_offset_pair[0] = sig; 
}


inm_s32_t bitmap_api_commit_header(bitmap_api_t *bapi,
			     inm_s32_t verify_existing_hdr_for_raw_io,
			     inm_s32_t *inmage_status)
{
	inm_s32_t status = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}


	switch(bapi->bitmap_file_state) {
	
	case BITMAP_FILE_STATE_OPENED:
		bitmap_api_calculate_hdr_integrity_checksums(&bapi->bitmap_header);
		if (memcpy_s(bapi->io_bitmap_header->buffer,
				sizeof(bitmap_header_t),
				&bapi->bitmap_header,
				sizeof(bitmap_header_t))) {
			status = 1;
			break;
		}

		iobuffer_setdirty(bapi->io_bitmap_header);
		status = iobuffer_sync_flush(bapi->io_bitmap_header);
		if (status != 0)
			*inmage_status = 
			    LINVOLFLT_ERR_FINAL_HEADER_FS_WRITE_FAILED;

		break;

	case BITMAP_FILE_STATE_RAWIO:
		if (verify_existing_hdr_for_raw_io)
			status = bitmap_api_read_and_verify_bitmap_header(bapi,
							      inmage_status);
		else
			status = 0;

		if (status == 0) {
			bitmap_api_calculate_hdr_integrity_checksums(&bapi->bitmap_header);
			if (memcpy_s(bapi->io_bitmap_header->buffer,
					sizeof(bitmap_header_t),
					&bapi->bitmap_header,
					sizeof(bitmap_header_t))) {
				status = 1;
				break;
			}

			iobuffer_setdirty(bapi->io_bitmap_header);
			status = iobuffer_sync_flush(bapi->io_bitmap_header);
			if (status != 0)
				*inmage_status = LINVOLFLT_ERR_FINAL_HEADER_DIRECT_WRITE_FAILED;
		}

		break;

	default:
		status = 1;
		break;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}

void bitmap_api_calculate_hdr_integrity_checksums(bitmap_header_t *bhdr)
{
	MD5Context ctx;
	
	/* calculate the checksum */
	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char *)(&bhdr->un.header.endian),
		  HEADER_CHECKSUM_DATA_SIZE);
	MD5Final(bhdr->un.header.validation_checksum, &ctx);

	return;
}

inm_s32_t bitmap_api_read_and_verify_bitmap_header(bitmap_api_t *bapi,
					     inm_s32_t *inmage_status)
{
	
	inm_s32_t status = 0;
	bitmap_header_t *hdriob = (bitmap_header_t *)bapi->io_bitmap_header->buffer;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	status = iobuffer_sync_read(bapi->io_bitmap_header);
	if (status == 0) {
		if (bitmap_api_verify_header(bapi, hdriob) &&
			bitmap_api_verify_header_blocks(bapi, hdriob))
			return 0;
		else
			*inmage_status = LINVOLFLT_ERR_FINAL_HEADER_VALIDATE_FAILED;
	} else {
		if (inmage_status)
			*inmage_status = LINVOLFLT_ERR_FINAL_HEADER_READ_FAILED;
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}

inm_s32_t bitmap_api_verify_header(bitmap_api_t *bapi,
		bitmap_header_t *bheader)
{
	unsigned char actual_checksum[HEADER_CHECKSUM_SIZE] = {0};
	MD5Context ctx;
	inm_s32_t _rc = 0;
	

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	/* recalculate the checksum */
	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char *)(&(bheader->un.header.endian)),
		  HEADER_CHECKSUM_DATA_SIZE);
	MD5Final(actual_checksum, &ctx);
#define bhdr     bheader->un.header

	_rc = ((bhdr.endian == BITMAP_FILE_ENDIAN_FLAG) &&
	   /* Hdr size should match version */
	   ((bhdr.version == BITMAP_FILE_VERSION1 && 
		 bhdr.header_size == BITMAP_HDR1_SIZE) ||
		(bhdr.version == BITMAP_FILE_VERSION2 &&
		 bhdr.header_size == BITMAP_HDR2_SIZE))&&
	   (bhdr.data_offset == LOG_HEADER_OFFSET) &&
	   (bhdr.bitmap_offset == bapi->bitmap_offset) &&
	   (bhdr.bitmap_size == bapi->nr_bits_in_bitmap) &&
	   (bhdr.bitmap_granularity == bapi->bitmap_granularity) &&
	   (bhdr.volume_size == bapi->volume_size) &&
	   (INM_MEM_CMP(bhdr.validation_checksum, actual_checksum,
		   HEADER_CHECKSUM_SIZE) == 0));


	if (!_rc) {
		info("Invalid Header for volume %s", bapi->volume_name);
		info("validition of bmap hdr");
		info("endian  = %d", (bhdr.endian == BITMAP_FILE_ENDIAN_FLAG));
		info("hdr sz  = %d", bhdr.header_size); 
		info("version = 0x%x", (bhdr.version));
		info("data offset = %d", (bhdr.data_offset == LOG_HEADER_OFFSET));
		info("bmap offset = %d", (bhdr.bitmap_offset == bapi->bitmap_offset));
		info("nr bmap bits= %d", (bhdr.bitmap_size == bapi->nr_bits_in_bitmap));
		info("granularity = %d", (bhdr.bitmap_granularity == bapi->bitmap_granularity));
		info("vol size    = %d", (bhdr.volume_size == bapi->volume_size));
		info("checksum    = %d",
			 (INM_MEM_CMP(bhdr.validation_checksum, actual_checksum,
			         HEADER_CHECKSUM_SIZE) == 0));

	}

#undef bhdr
	return _rc;

}

inm_s32_t bitmap_api_commit_bitmap(bitmap_api_t *bapi, int clean_shutdown,
			                        inm_s32_t *inmage_close_status) 
{
	inm_s32_t status = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_DOWN(&bapi->sem);
	status = bitmap_api_commit_bitmap_internal(bapi, clean_shutdown,
			                                   inmage_close_status);
	INM_UP(&bapi->sem);
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
	return status;
}

inm_s32_t is_volume_in_sync(bitmap_api_t *bapi, inm_s32_t *vol_in_sync,
			  inm_s32_t *out_of_sync_err_code)
{
	inm_s32_t status = 0;


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (!bapi || !vol_in_sync || !out_of_sync_err_code)
		return -EINVAL;

	INM_DOWN(&bapi->sem);
	switch(bapi->bitmap_file_state) {
	case BITMAP_FILE_STATE_OPENED:
	case BITMAP_FILE_STATE_RAWIO:
		*vol_in_sync = bapi->volume_insync;
		*out_of_sync_err_code = bapi->err_causing_outofsync;
		dbg("volume in sync = %d , out of sync code = %x\n",
			bapi->volume_insync, bapi->err_causing_outofsync);
		break;

	default:
		status = -EINVAL;
		break;
	}
	INM_UP(&bapi->sem);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %d", status);
	}

	return status;
}

inm_u64_t
bitmap_api_get_dat_bytes_in_bitmap(bitmap_api_t *bapi, bmap_bit_stats_t *bbsp) 
{
	inm_u64_t data_bytes = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}
	if (bbsp) {
		INM_MEM_ZERO(bbsp, sizeof(*bbsp));
		bbsp->bbs_bmap_gran = bapi->bitmap_granularity;
		bbsp->bbs_max_nr_bits_in_chg = 
				(1024 * 1024)/bapi->bitmap_granularity;
	}

	if (bapi && bapi->volume_size < (1024*KILOBYTES)) {
		return 0;
	}
	if (bapi->sb) {
		data_bytes = segmented_bitmap_get_number_of_bits_set(bapi->sb,
									bbsp);
		data_bytes *= bapi->bitmap_granularity;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with ret value = %llu", data_bytes);
	}

	return data_bytes;
}

int
bitmap_api_open_bitmap_stream(bitmap_api_t *bapi, target_context_t *vcptr,
				inm_s32_t *detailed_status)
{
	inm_s32_t file_created = 0;
	inm_s32_t ret = -1;
	inm_s32_t prev_state = BITMAP_FILE_STATE_UNINITIALIZED;

	bapi->fs = fstream_ctr(vcptr);
	if (!bapi->fs) {
		*detailed_status = LINVOLFLT_ERR_NO_MEMORY;
		ret = -ENOMEM;
		goto last;
	}

	prev_state = bapi->bitmap_file_state;
	ret = fstream_open_or_create(bapi->fs, bapi->bitmap_filename,
				&file_created, bapi->bitmap_size_in_bytes);
	if (ret) {
		*detailed_status = LINVOLFLT_ERR_BITMAP_FILE_CANT_OPEN;
		info("Error in opening bitmap file = %d\n", ret);
		goto last;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("bitmap file %s opened \n", bapi->bitmap_filename);
	}
	if (!bapi->io_bitmap_header) {
		/* hdr already loaded from physical blocks of volume */
		bapi->bitmap_file_state = BITMAP_FILE_STATE_OPENED;
		ret = bitmap_api_load_bitmap_header_from_filestream(bapi,
							    detailed_status,
							    file_created);

		if (ret) {
			info("error in load bhdr = %d", ret);
			if (bapi->io_bitmap_header != NULL) {
			    iobuffer_put(bapi->io_bitmap_header);
			    bapi->io_bitmap_header = NULL;
			}
			goto last;
		}
	} else if (file_created) {
		ret = bitmap_api_fast_zero_bitmap(bapi);
		if (ret)
			goto last;

		/* recorded changes might have been lost here, set out of sync here */
		*detailed_status = bapi->err_causing_outofsync =
		LINVOLFLT_ERR_BITMAP_FILE_CREATED;

		bapi->bitmap_file_state = BITMAP_FILE_STATE_OPENED;
		ret = bitmap_api_commit_header(bapi, FALSE, detailed_status);
		if (ret) {
			goto last;
		}
	} else {
		bapi->bitmap_file_state = BITMAP_FILE_STATE_OPENED;
	}

	ret = move_rawio_changes_to_bitmap(bapi, detailed_status);
	if (ret)
		goto last;

	ret = 0;
	return ret;

last:
	bapi->bitmap_file_state = prev_state;
	if (bapi->fs != NULL) {
		fstream_close(bapi->fs);
		fstream_put(bapi->fs);
		bapi->fs = NULL;
	}

	return ret;
}

inm_s32_t is_bmaphdr_loaded(volume_bitmap_t *vbmap)
{
	if (vbmap && vbmap->bitmap_api &&
				vbmap->bitmap_api->io_bitmap_header) {
	return TRUE;
	}

	return FALSE;
}

inm_s32_t
bitmap_api_map_file_blocks(bitmap_api_t *bapi, fstream_raw_hdl_t **hdl)
{
	return fstream_raw_open(bapi->bitmap_filename, 0, 
			                sizeof(bitmap_header_t), hdl);
}
	
inm_s32_t
bitmap_api_switch_to_rawio_mode(bitmap_api_t *bapi, inm_u64_t *resync_error)
{
	inm_s32_t error = 0;
	int clean_shutdown = 1;
	fstream_raw_hdl_t *hdl = NULL;

	INM_DOWN(&bapi->sem);

	if (bapi->bitmap_file_state != BITMAP_FILE_STATE_OPENED) {
		*resync_error = ERROR_TO_REG_PRESHUTDOWN_BITMAP_FLUSH_FAILURE;
		error = LINVOLFLT_ERR_BITMAP_FILE_CANT_OPEN;
		goto out;
	}

	/* Add signatures to header blocks to verify the raw blocks */
	bitmap_api_sign_header_blocks(bapi);

	error = bitmap_api_commit_bitmap_internal(bapi, !clean_shutdown,
								&error);
	
	bitmap_api_clear_signed_header_blocks(bapi);

	if (error) {
		*resync_error = ERROR_TO_REG_PRESHUTDOWN_BITMAP_FLUSH_FAILURE;
		goto out;
	}

	error = bitmap_api_map_file_blocks(bapi, &hdl);
	if (error) {
		*resync_error = ERROR_TO_REG_LEARN_PHYSICAL_IO_FAILURE;
		goto out;
	}

	bapi->bitmap_file_state = BITMAP_FILE_STATE_RAWIO;
	fstream_switch_to_raw_mode(bapi->fs, hdl);
out:
	INM_UP(&bapi->sem);
	return error;
}

void
bitmap_api_set_volume_out_of_sync(bitmap_api_t *bapi, inm_u64_t error_status, 
			                      inm_u32_t error_code)
{
	bapi->bitmap_header.un.header.resync_required = 1; 
	bapi->bitmap_header.un.header.resync_errcode = error_code; 
	bapi->bitmap_header.un.header.resync_errstatus = error_status; 
}
