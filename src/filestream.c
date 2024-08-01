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

#include <linux/dcache.h>
#include <linux/mount.h>

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
#include "file-io.h"
#include "involflt_debug.h"
#include "db_routines.h"
#include "data-file-mode.h"
#include "tunable_params.h"
#include "errlog.h"
#include "filestream_raw.h"

extern driver_context_t *driver_ctx;

fstream_t *fstream_ctr(void *ctx)
{

	fstream_t *fs = NULL;


	fs = (fstream_t *)INM_KMALLOC(sizeof(*fs), INM_KM_SLEEP,
		       				INM_KERNEL_HEAP);

	if(!fs)
		return NULL;

	INM_MEM_ZERO(fs, sizeof(*fs));

	fs->context = ctx;
	INM_ATOMIC_SET(&fs->refcnt, 1);

	return fs;
}

void fstream_dtr(fstream_t *fs)
{
	if(!fs)
		return;

	kfree(fs);
	fs = NULL;
	return;
}

fstream_t *fstream_get(fstream_t *fs)
{
	INM_ATOMIC_INC(&fs->refcnt);
	return fs;
}

void fstream_put(fstream_t *fs)
{
	if (INM_ATOMIC_DEC_AND_TEST(&fs->refcnt))
		fstream_dtr(fs);
}

inm_s32_t fstream_open(fstream_t *fs, char *path, inm_s32_t flags,
							inm_s32_t mode)
{
	struct file *fp = NULL;
	inm_s32_t _rc = 0;
	mm_segment_t _mfs;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	_mfs = get_fs();
	set_fs(KERNEL_DS);
	INM_BUG_ON(!path);
	if (path[0] == '/') {
		//open the file with full path
		fp = filp_open(path, flags, mode);
	}

	if (!fp) {
		_rc = -1;
		goto out;
	}

	if (IS_ERR(fp)) {
		_rc = PTR_ERR(fp);
		set_fs(_mfs);
		return _rc;
	}

	if (!S_ISREG((INM_HDL_TO_INODE(fp))->i_mode)) {
		_rc = -EACCES;
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	if (!fp->f_op->write || !fp->f_op->read) {
		_rc = -EIO;
		goto out;
	}
#endif    
	 
	inm_prepare_tohandle_recursive_writes(INM_HDL_TO_INODE(fp));
	fs->filp = fp;
	fs->inode = INM_HDL_TO_INODE(fp);
	_rc = 0;
	goto success;

out:
	if (fp)
	filp_close(fp, current->files);

success:
	set_fs(_mfs);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return _rc;
}

inm_s32_t fstream_close(fstream_t *fs)
{
	struct file *fp = (struct file *)fs->filp;
	struct inode *_tinode = (struct inode *)fs->inode;
	inm_s32_t _rc = 0;
	mm_segment_t _mfs;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (fs->fs_raw_hdl)
		return fstream_raw_close(fs->fs_raw_hdl);

	if (!fp)
		return (1);
	
	fs->filp = NULL;
	fs->inode = NULL;

	_mfs = get_fs();
	set_fs(KERNEL_DS);
	inm_restore_org_addr_space_ops(_tinode);
	filp_close(fp, NULL);
	set_fs(_mfs);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return _rc;
}

inm_s32_t fstream_get_fsize(fstream_t *fs)
{
	struct file *fp = (struct file *)fs->filp;

	if (fs->fs_raw_hdl)
		return fstream_raw_get_fsize(fs->fs_raw_hdl);

	if (!fp)
		return -EINVAL;

	return (INM_HDL_TO_INODE(fp))->i_size;
}

inm_s32_t fstream_open_or_create(fstream_t *fs, char *path,
				inm_s32_t *file_created, inm_u32_t bmap_sz)
{
	inm_s32_t ret = 0, c_ret = 0;
	inm_s32_t oflags = (O_RDWR | O_EXCL | O_LARGEFILE | O_NOATIME);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	ret = fstream_open(fs, path, oflags, 0644);

	if (ret) {    // may be file does not exist, create it
		oflags |= O_CREAT;
		c_ret = fstream_open(fs, path, oflags, 0644);
		if (c_ret) {
			if (c_ret == -EEXIST)
				return ret;
			else
				return c_ret;
		} else {
			ret = c_ret;
		}

		*file_created = 1;
	} else {
		if (fstream_get_fsize(fs) < bmap_sz) {
			//bmap file corrupted
			*file_created = 2;
		}
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}

	return ret;

}

void
fstream_enable_buffered_io(fstream_t *fs)
{
	fs->fs_flags |= FS_FLAGS_BUFIO;
}

void
fstream_disable_buffered_io(fstream_t *fs)
{
	fs->fs_flags &= ~FS_FLAGS_BUFIO;
}


void
fstream_sync_range(fstream_t *fs, inm_u64_t offset, inm_u32_t size)
{
	struct file *fp = (struct file *)fs->filp;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	sync_page_range(fp->f_dentry->d_inode, fp->f_mapping, offset, size);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	filemap_write_and_wait_range(fp->f_mapping, offset, offset + size - 1);
#else
	vfs_fsync_range(fp, offset, offset + size - 1, 0);
#endif
}

void
fstream_sync(fstream_t *fs)
{
	inm_s32_t size = fstream_get_fsize(fs);

	if (size <= 0) {
		err("Invalid bitmap size (%d)", size);
		INM_BUG_ON(size < 0);
	} else {
		fstream_sync_range(fs, 0, (inm_u32_t)size);
	}
}

inm_s32_t fstream_write(fstream_t *fs, char *buffer, inm_u32_t size,
							inm_u64_t offset)
{
	struct file *fp = (struct file *)fs->filp;
	ssize_t nr = 0;
	mm_segment_t _mfs;
	loff_t pos = (loff_t) offset;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (fs->fs_raw_hdl)
		return fstream_raw_write(fs->fs_raw_hdl, buffer, size, offset);

	if (!fp)
		return 1;

	_mfs = get_fs();
	set_fs(KERNEL_DS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	nr = kernel_write(fp, buffer, (ssize_t)size, &pos);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	nr = vfs_write(fp, buffer, (ssize_t)size, &pos);
#else
	nr = fp->f_op->write(fp, buffer, (ssize_t)size, &pos);
#endif
#endif

	if (nr > 0 && !(fs->fs_flags & FS_FLAGS_BUFIO))
		fstream_sync_range(fs, offset, nr);

	set_fs(_mfs);

	if (nr != (ssize_t)size) {
		info("Write requested for %d bytes wrote %d bytes \n",
			       				size, (int)nr);
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with status = %d , num of bytes written"
			       "into bmap = %d", (nr == size), (int)nr);
	}

	return nr == size ? 0 : nr;
}

inm_s32_t fstream_read(fstream_t *fs, char *buffer, inm_u32_t size,
							inm_u64_t offset)
{
	struct file *fp = (struct file *)fs->filp;
	ssize_t nr = 0;
	mm_segment_t _mfs;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	if (fs->fs_raw_hdl)
		return fstream_raw_read(fs->fs_raw_hdl, buffer, size, offset);

	if (!fp)
		return 1;

	_mfs = get_fs();
	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	nr = kernel_read(fp, buffer, (ssize_t)size, &offset);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	nr = vfs_read(fp, buffer, (ssize_t)size, &offset);
#else
	nr = fp->f_op->read(fp, buffer, (ssize_t)size, &offset);
#endif
#endif
	if (nr < 0) {
		err("Unable to read the data %0xx\n", size);
		set_fs(_mfs);
		return 1;
	}
	set_fs(_mfs);
	if (nr != (ssize_t)size) {
		info("Read requested for %u bytes read %d bytes \n",
							size, (int)nr);
	}


	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving with status %d, nr bytes read from bmap = %d",
			(nr == size), (int)nr);
	}

	return nr == size ? 0 : 1;
}

inm_s32_t
fstream_map_file_blocks(fstream_t *fs, inm_u64_t offset, inm_u32_t len, 
			            fstream_raw_hdl_t **hdl)
{
	return fstream_raw_open(fs->filp, offset, len, hdl);
}

void
fstream_switch_to_raw_mode(fstream_t *fs, fstream_raw_hdl_t *raw_hdl)
{
	dbg("Switching filestream to rawe mode");
	fstream_close(fs);
	fs->fs_raw_hdl = raw_hdl;
}
