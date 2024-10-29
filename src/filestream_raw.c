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

extern driver_context_t *driver_ctx;
extern inm_u32_t lcwModeOn;

static void
fstream_raw_print_map(char *file, fstream_raw_hdl_t *hdl)
{
	int i = 0;
	int j = 0;
	inm_u32_t nblks = 0;
	inm_u64_t doffset = 0;
	inm_u64_t foffset = 0;
	inm_u32_t len = 0;
	void *disk = 0;
	char diskname[INM_BDEVNAME_SIZE];

	if (!hdl) {
		dump_stack();
		return;
	}

	nblks = hdl->frh_nblks;

	info("HDL0: %s", file);
	info("HDL1: fsize = %llu, offset = %llu, len = %u, alen = %u",
		hdl->frh_fsize, hdl->frh_offset, hdl->frh_len, hdl->frh_alen);
	info("HDL2: nbsize = %u, bshift = %u, blks = %u, npgs = %u",
		hdl->frh_bsize, hdl->frh_bshift, hdl->frh_nblks, 
		hdl->frh_npages);
	info("HDL3: Blkmap");
	for (i = 0; i < hdl->frh_npages; i++) {
		info("page[%d] = %p", i, hdl->frh_blocks[i]);
		info("%16s %16s %16s %16s", 
			"foffset","disk", "sector", "length");

		for (j = 0; j < FSRAW_BLK_PER_PAGE && nblks; nblks--, j++) {
			if (doffset != 0) { /* previous valid block */
				/* If the block is contiguous with previous block */
				if (((hdl->frh_blocks[i][j]).fb_disk == disk &&
					(doffset + len) == 
					(hdl->frh_blocks[i][j]).fb_offset)) {
					len += hdl->frh_bsize;
				} else {
					inm_blkdev_name(disk, diskname);
					info("%16llu %16s %16llu %16u", 
					    foffset, diskname, 
					    doffset >> INM_SECTOR_SHIFT, len);
					foffset += len;
					doffset = 0;
				}
			}

			if (doffset == 0) {
				disk = (hdl->frh_blocks[i][j]).fb_disk;
				doffset = (hdl->frh_blocks[i][j]).fb_offset;
				len = hdl->frh_bsize;
			}

			if (nblks == 1) {
				inm_blkdev_name(disk, diskname);
				info("%16llu %16s %16llu %16u", 
					foffset, diskname, 
					doffset >> INM_SECTOR_SHIFT, len);
			}
		}
	}
}

static void
fstream_raw_revert_recursive_detection(void *filp)
{
	int rflag = 0;

	rflag = driver_ctx->dc_lcw_rflag;
	lcwModeOn = 0;
	
	driver_ctx->dc_lcw_rflag = 0;
	driver_ctx->dc_lcw_aops = NULL;
	driver_ctx->dc_lcw_rhdl = NULL;
	
	inm_restore_org_addr_space_ops(INM_HDL_TO_INODE(filp));

	if (rflag) 
		inm_restore_org_addr_space_ops(INM_HDL_TO_INODE(filp));
}

/* 
 * Recursive writes logic is optimized to share same duplicate aops
 * across multiple files which cannot be used to distinguish raw mapping
 * writes from writes to other files. As a workaround, we prepare the 
 * file twice for recursive writes which gives the inode a distinct 
 * aops/mapping and allows us to distinguish from writes to other files.
 */
static inm_s32_t
fstream_raw_prepare_for_recusive_detection(void *filp, fstream_raw_hdl_t *hdl)
{
	inm_s32_t error = 0;
	inma_ops_t *aops = NULL;
	int rflag = 0;
   
	/* 
	 * If file is not already prepped for recursive writes, do it the first
	 * time to get the mapping/aops shared with other files
	 */
	aops = inm_get_inmaops_from_aops(INM_INODE_AOPS(INM_HDL_TO_INODE(filp)), 
						INM_DUP_ADDR_SPACE_OPS);
	if (!aops) { 
		error = inm_prepare_tohandle_recursive_writes(INM_HDL_TO_INODE(filp));
		if (error) {
			err("Recursive IO (1) handling failed");
			goto out;
		}
		rflag = 1;
	}

	/*
	 * Override the shared mapping/aops with a new one distinct from others.
	 */
	error = inm_prepare_tohandle_recursive_writes(INM_HDL_TO_INODE(filp));
	if (error) {
		err("Recursive IO (2) handling failed");
		if (rflag) 
			inm_restore_org_addr_space_ops(INM_HDL_TO_INODE(filp));
		
		goto out;
	}

	driver_ctx->dc_lcw_aops = inm_get_inmaops_from_aops(
					INM_INODE_AOPS(INM_HDL_TO_INODE(filp)), 
					INM_DUP_ADDR_SPACE_OPS);
	driver_ctx->dc_lcw_rhdl = hdl;
	lcwModeOn = 1;
	driver_ctx->dc_lcw_rflag = rflag;
   
out:
	return error; 
}

static void
fstream_raw_map_file_blocks(fstream_raw_hdl_t *hdl, inm_bio_dev_t *disk, 
			inm_u64_t foffset, inm_u64_t doffset, inm_u32_t len)
{
	fr_block_t *map = NULL;
	inm_u32_t page = 0;
	inm_u32_t block = 0;
	inm_irqflag_t flag = 0;

	dbg("disk = %p, f_offset = %llu, d_offset = %llu, len = %u", 
		disk, foffset, doffset, len);

	while (len) {
		page = FSRAW_BLK_PAGE(hdl, foffset);
		block = FSRAW_BLK_IDX(hdl, foffset);
	  
		INM_BUG_ON(!(hdl->frh_blocks[page]));

		INM_SPIN_LOCK_IRQSAVE(&(hdl->frh_slock), flag); 
		
		map = &(hdl->frh_blocks[page][block]);
		if (map->fb_disk) {
			err("Mapping already mapped block");
			hdl->frh_nblks = 0;
			INM_SPIN_UNLOCK_IRQRESTORE(&(hdl->frh_slock), flag);
			break;
		}
		
		if (hdl->frh_nblks == (hdl->frh_alen >> hdl->frh_bshift)) {
			err("Mapping more blocks then expected hdl->frh_nblks=%u, "
				"hdl->frh_alen=%u, hdl->frh_bshift=%u",
				hdl->frh_nblks, hdl->frh_alen, hdl->frh_bshift);
			hdl->frh_nblks = 0;
			INM_SPIN_UNLOCK_IRQRESTORE(&(hdl->frh_slock), flag);
			break;
		}

		map->fb_disk = disk;
		map->fb_offset = doffset;
		hdl->frh_nblks++;
		
		INM_SPIN_UNLOCK_IRQRESTORE(&(hdl->frh_slock), flag); 

		foffset += hdl->frh_bsize;
		doffset += hdl->frh_bsize; 
		len -= min(len, hdl->frh_bsize);
	}
}

void
fstream_raw_map_bio(inm_buf_t *bio)
{
	inm_u64_t foffset = 0;
	inm_u32_t len = 0;
	fstream_raw_hdl_t *hdl = driver_ctx->dc_lcw_rhdl;
	inm_bio_dev_t *bdev;

	dbg("Hdl = %p", hdl);
   
	if (hdl->frh_bsize < PAGE_SIZE) {
		/* Write should be fs block aligned and < PAGE_SIZE */ 
		if (!IS_ALIGNED(INM_BUF_OFFSET(bio), hdl->frh_bsize) ||
			!IS_ALIGNED(INM_BUF_COUNT(bio),  hdl->frh_bsize) ||
			INM_BUF_COUNT(bio) > PAGE_SIZE) {
			err("LCW Learn: bsize = %u, io size = %u, page offset = %lu", 
				hdl->frh_bsize, INM_BUF_COUNT(bio), 
				(long unsigned int)INM_BUF_OFFSET(bio));
			hdl->frh_nblks = 0;
			return;
		}
		
		foffset = hdl->frh_nblks * hdl->frh_bsize;
		/* 
		 * Since FS writes are of size == PAGE_SIZE, multiple bio may be 
		 * generated if fs bsize < PAGE_SIZE and some of the blocks may have 
		 * been mapped. Align the file offset to PAGE_SIZE on the lower side
		 */
		if (foffset)
			foffset = ALIGN((foffset - (PAGE_SIZE - 1)), PAGE_SIZE);
	   
		dbg("foffset(1) = %llu", foffset);

		/* 
		 * The vector page maps PAGE_SIZE and vector offset == offset from
		 * PAGE_SIZE aligned file offset.
		 */
		foffset += INM_BUF_OFFSET(bio);
		dbg("foffset(2) = %llu", foffset);

		len = INM_BUF_COUNT(bio);
		dbg("len = %d", len);
	} else {
		/* Write should be upto fs bsize and should start at vec pg offset 0 */
		if ((INM_BUF_COUNT(bio) > hdl->frh_bsize) ||
							INM_BUF_OFFSET(bio)) { 
			err("LCW Learn: bsize = %u, io size = %u, page offset = %lu", 
				hdl->frh_bsize, INM_BUF_COUNT(bio), 
				(long unsigned int)INM_BUF_OFFSET(bio));
			hdl->frh_nblks = 0;
			return;
		}

		foffset = hdl->frh_nblks * hdl->frh_bsize;
		len = hdl->frh_bsize;
	}

	bdev = INM_BUF_BDEV(bio);
	if (!bdev)
		return;

	if (inm_blkdev_get(bdev))
		return;
   
	fstream_raw_map_file_blocks(hdl, bdev, foffset,  
				INM_BUF_SECTOR(bio) << INM_SECTOR_SHIFT, len);
}

static void
fstream_raw_hdl_free(fstream_raw_hdl_t *hdl)
{
	int i = 0;

	if (!hdl) {
		dump_stack();
		return;
	}

	for (i = 0; i < hdl->frh_npages; i++) {
		dbg("Free Page %p", hdl->frh_blocks[i]);
		inm_free_page((unsigned long)hdl->frh_blocks[i]);
	}
		
	i = sizeof(fstream_raw_hdl_t) + (sizeof(fr_block_t *) * 
							hdl->frh_npages);
	dbg("Free HDL: %d", i);

	INM_KFREE(hdl, i, INM_KERNEL_HEAP);
}

static inm_s32_t
fstream_raw_hdl_alloc(void *filp, inm_u64_t offset, inm_u32_t len, 
					  fstream_raw_hdl_t **rhdl)
{
	int error = 0;
	fstream_raw_hdl_t *hdl = NULL;
	int nblks = 0;
	int npages = 0;
	loff_t fsize = 0;
	fr_block_t *page = NULL;

	if (!flt_get_file_size(filp, &fsize)) {
		error = -ENOENT;
		goto out;
	}

	if (offset)
		return -EINVAL;

	if (!len) {                            /* If no len , map entire file   */
		if ((fsize - offset) > UINT_MAX) { /* len == uint                   */
			error = -EINVAL;
			goto out;
		}

		len = (inm_u32_t)(fsize - offset);
	}

	if ((offset + len) > fsize) {
		error = -EINVAL;
		goto out;
	}

	nblks = ALIGN(len, (INM_HDL_TO_INODE(filp))->i_sb->s_blocksize);
	nblks = nblks >> (INM_HDL_TO_INODE(filp))->i_sb->s_blocksize_bits;;
	
	npages = ((nblks - 1) >> FSRAW_BLK_PER_PAGE_SHIFT) + 1;
	dbg("Expected nblks = %u, npages = %u", nblks, npages);

	hdl = INM_KMALLOC(sizeof(fstream_raw_hdl_t) + 
			(sizeof(fr_block_t *) * npages), INM_KM_SLEEP, 
			INM_KERNEL_HEAP);
	if (!hdl) {
		error = -ENOMEM;
		goto out;
	}

	INM_MEM_ZERO(hdl, 
		sizeof(fstream_raw_hdl_t) + (sizeof(fr_block_t *) * npages));

	INM_INIT_SPIN_LOCK(&hdl->frh_slock);
	hdl->frh_fsize = fsize;
	hdl->frh_offset = offset;
	hdl->frh_len = len;
	hdl->frh_alen = ALIGN(len, 
				(INM_HDL_TO_INODE(filp))->i_sb->s_blocksize);
	hdl->frh_bsize = (INM_HDL_TO_INODE(filp))->i_sb->s_blocksize;
	hdl->frh_bshift = (INM_HDL_TO_INODE(filp))->i_sb->s_blocksize_bits;
	hdl->frh_nblks = 0;

	err("fstream_raw_hdl_alloc frh_alen=%u", hdl->frh_alen);
	
	/* access the block map as 2D array */
	hdl->frh_blocks = (fr_block_t **)((char *)hdl + 
						sizeof(fstream_raw_hdl_t));
	for (hdl->frh_npages = 0; hdl->frh_npages < npages; 
						hdl->frh_npages++) {
		page = (fr_block_t *)__inm_get_free_page(INM_KM_SLEEP);
		if (!page)
			break;

		dbg("Page[%u] = %p", hdl->frh_npages, page);
		INM_MEM_ZERO(page, PAGE_SIZE);
		hdl->frh_blocks[hdl->frh_npages] = page;
	}
	
	if (hdl->frh_npages != npages) {
		error = -ENOMEM;
		fstream_raw_hdl_free(hdl);
		hdl = NULL;
	} else {
		*rhdl = hdl;
	}

out:
	return error;
}

/*
 * This API is not multithread safe and calls should be serialized
 */
inm_s32_t
fstream_raw_open(char *file, inm_u64_t offset, inm_u32_t len, 
					    fstream_raw_hdl_t **raw_hdl)
{
	int error = 0;
	void *filp = NULL;
	char *buf = NULL;
	inm_u32_t iosize = 0;
	inm_u32_t iodone = 0;
	fstream_raw_hdl_t *hdl = NULL;
	
	dbg("Mapping %s -> %llu:%d", file, offset, len);

	if (!flt_open_file(file, INM_RDWR | INM_SYNC, &filp)) {
		err("Cannot open %s", file);
		filp = NULL;
		error = -ENOENT;
		goto out;
	}

	error = fstream_raw_hdl_alloc(filp, offset, len, &hdl);
	if (error) {
		err("Cannot alloc raw handle - %d", error);
		goto out;
	}
	len = hdl->frh_len;

	buf = (char *)__inm_get_free_page(INM_KM_SLEEP);
	if (!buf) {
		error = -ENOMEM;
		goto out;
	}

	error = fstream_raw_prepare_for_recusive_detection(filp, hdl);
	if (error) {
		err("Recursive IO handling failed");
		goto out;
	}

	while (len) {
		iosize = min(len, (inm_u32_t)PAGE_SIZE);

		if (!flt_read_file(filp, buf, offset, iosize, &iodone) ||
			iodone != iosize) {
			err("Read Failed: %llu:%u:%u", offset, iosize, iodone);
			error = -EIO;
			break;
		}

		if (!flt_write_file(filp, buf, offset, iosize, &iodone) || 
			iodone != iosize) {
			err("Write Failed: %llu:%u:%u", 
						offset, iosize, iodone);
			error = -EIO;
			break;
		}

		/* 
		 * For fs bsize >= PAGE_SIZE except last partial block io, 
		 * move to next fs block 
		 */
		if (hdl->frh_bsize >= PAGE_SIZE && iosize == PAGE_SIZE)
			iosize = hdl->frh_bsize;

		offset += iosize;
		len -= iosize;
	}
   
	fstream_raw_revert_recursive_detection(filp);

	/* If all blocks could not be mapped */
	if (hdl->frh_nblks != (hdl->frh_alen >> hdl->frh_bshift)) {
		err("Mapped: Actual = %d Expected = %d", hdl->frh_nblks, 
			(hdl->frh_alen >> hdl->frh_bshift));
		error = -EBADF;
	}

out:
	if (!error) {
		*raw_hdl = hdl;
		fstream_raw_print_map(file, hdl);
	} else {
		if (hdl)
			fstream_raw_close(hdl);
		err("Cannot map %s", file);
	}

	if (buf)
		inm_free_page((unsigned long)buf);

	if (filp)
		flt_close_file(filp);

	return error;
}

inm_s32_t
fstream_raw_get_fsize(fstream_raw_hdl_t *hdl)
{
	return hdl->frh_fsize;
}

inm_s32_t 
fstream_raw_close(fstream_raw_hdl_t *hdl)
{
	fstream_raw_hdl_free(hdl);
	return 0;
}

inm_s32_t
fstream_raw_perform_block_io(inm_bio_dev_t *disk, char *buf, inm_u64_t offset, 
						inm_u32_t len, inm_u32_t write)
{
	static void *filp = NULL;
	static inm_bio_dev_t *prev_disk = NULL;
	static char diskname[INM_BDEVNAME_SIZE];
	inm_u32_t iodone = 0;

	if (disk != prev_disk && filp) {
		flt_close_file(filp);
		filp = NULL;
		prev_disk = NULL;
	}

	if (!filp) {
		snprintf(diskname, INM_PATH_MAX, "%s", INM_BDEVNAME_PREFIX);
		inm_blkdev_name(disk, diskname + strlen(INM_BDEVNAME_PREFIX));

		if (!flt_open_file(diskname, O_RDWR | O_SYNC, &filp)) {
			err("Cannot open file %s", diskname);
			filp = NULL;
			return -EIO;
		}

		prev_disk = disk;
	}

	info("%s: %s [%llu:%u] %p", write ? "WRITE" : "READ",
		 diskname, offset, len, buf);
	if (write) 
		flt_write_file(filp, buf, offset, len, &iodone);
	else
		flt_read_file(filp, buf, offset, len, &iodone);

	return (iodone == len) ? 0 : -EIO;
}

inm_s32_t
fstream_raw_io(fstream_raw_hdl_t *hdl, char *buf, inm_u32_t len, 
			   inm_u64_t offset, int write)
{
	inm_s32_t error = 0;
	int iosize = 0;
	inm_u64_t doffset = 0;
	int page = 0;
	int block = 0;
	inm_bio_dev_t *disk = NULL;

	if (offset < hdl->frh_offset ||
		(offset + len) > (hdl->frh_offset + hdl->frh_len))
		return -EINVAL;

	while (len) {
		page = FSRAW_BLK_PAGE(hdl, offset);
		block = FSRAW_BLK_IDX(hdl, offset);

		disk = (hdl->frh_blocks[page][block]).fb_disk;
		doffset = (hdl->frh_blocks[page][block]).fb_offset;
		iosize = min(len, hdl->frh_bsize);

		dbg("FSRAW %s: disk = %p, off = %llu, len = %u, page = %d, block = %u," 
			"doffset = %llu, iosize = %u", write ? "WRITE" : "READ", disk,
			 offset, len, page, block, doffset, iosize);

		error = fstream_raw_perform_block_io(disk, buf, doffset, 
								iosize, write);
		if (error)
			break;

		buf += iosize;
		offset += iosize;
		len -= iosize;
	}

	if (error)
		err("Raw IO failed with error - %d", error);

	return error ? 1 : 0;
}

inm_s32_t
fstream_raw_read(fstream_raw_hdl_t *hdl, char *buf, inm_u32_t len, 
				 inm_u64_t offset)
{
	return fstream_raw_io(hdl, buf, len, offset, 0);
}

inm_s32_t
fstream_raw_write(fstream_raw_hdl_t *hdl, char *buf, inm_u32_t len, 
				 inm_u64_t offset)
{
	return fstream_raw_io(hdl, buf, len, offset, 1);
}

