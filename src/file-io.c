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
#include <linux/syscalls.h>
#include <linux/mount.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) || defined(SLES15SP6)
#include <linux/filelock.h>
#endif

extern driver_context_t *driver_ctx;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,13)
#define RHEL_OLD
#endif

inm_s32_t flt_open_file (const char *fname, inm_u32_t mode, void **hdl)
{
	struct file *fp = NULL;
	mm_segment_t fs;
	inm_s32_t err = 1; 
  
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered fname:%s", fname);
	}

	INM_BUG_ON (fname == NULL);

	*hdl = NULL;

	fs = get_fs ();
	set_fs (KERNEL_DS);

	fp = filp_open (fname, mode, 0644);
	if (IS_ERR (fp)) {
		dbg ("Not able to open %s", fname);
		err = 0;
		goto filp_open_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	if ((!fp->f_op->write) || !(fp->f_op->read)) {
		dbg ("No write found for the fild id %p", fp);
		err = 0;
		filp_close (fp, NULL);
		goto filp_open_failed;
	}
#endif

	*hdl = (void *) fp;
	set_fs (fs);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return 1;

filp_open_failed:
	set_fs (fs);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return err;
}

inm_s32_t
flt_read_file (void *hdl, void *buffer, inm_u64_t offset, inm_u32_t length,
		 	inm_u32_t *bytes_read)
{
	struct file *fp;
	ssize_t read;
	mm_segment_t fs;

	INM_BUG_ON ((hdl == NULL) || (buffer == NULL));

	fp = (struct file *) hdl;

	if (bytes_read != NULL)
		*bytes_read = 0;

	fs = get_fs ();
	set_fs (KERNEL_DS);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	read = kernel_read(fp, (char *) buffer, length, (loff_t *) & offset);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	read = vfs_read(fp, (char *) buffer, length, (loff_t *) & offset);
#else
	read = fp->f_op->read (fp, (char *) buffer, length, (loff_t *) & offset);
#endif
#endif

	set_fs (fs);

	if (bytes_read != NULL)
		*bytes_read = 0;

	if (read <= 0) {
		return 0;
	}

	if (bytes_read != NULL)
		*bytes_read = read;

	return 1;
}

inm_s32_t flt_write_file (void *hdl, void *buffer, inm_u64_t offset, 
			inm_u32_t length, inm_u32_t *bytes_written)
{
	struct file *fp;
	ssize_t NrWritten;
	mm_segment_t fs;

	INM_BUG_ON ((hdl == NULL) || (buffer == NULL));

	fp = (struct file *) hdl;

	fs = get_fs ();
	set_fs (KERNEL_DS);

	fp->f_pos = offset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
	NrWritten =
	kernel_write(fp, (char *) buffer, length, (loff_t *) & offset);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	NrWritten =
	vfs_write(fp, (char *) buffer, length, (loff_t *) & offset);
#else
	NrWritten =
	fp->f_op->write (fp, (char *) buffer, length, (loff_t *) & offset);
#endif
#endif
	fp->f_pos = offset;

	set_fs (fs);

	if (bytes_written != NULL)
		*bytes_written = 0;

	if (NrWritten <= 0) {
		dbg("write failed with error 0x%x", (int32_t) NrWritten);
		return 0;
	}

	if (bytes_written != NULL)
		*bytes_written = NrWritten;

	return 1;
}

inm_s32_t flt_seek_file (void *hdl, inm_s64_t offset, inm_s64_t * newoffset, 
		   inm_u32_t seekpos)
{
	struct file *fp;
	loff_t FinalOffset;
	mm_segment_t fs;

	INM_BUG_ON (hdl == NULL); 

	fp = (struct file *) hdl;

	fs = get_fs ();
	set_fs (KERNEL_DS);

	if (fp->f_op && fp->f_op->llseek) {
		FinalOffset = fp->f_op->llseek (fp, (loff_t) offset, seekpos);
	} else {
		FinalOffset = default_llseek (fp, (loff_t) offset, seekpos);
	}

	set_fs (fs);

	if (FinalOffset < 0) {
		dbg ("llSsek to offset[%lld] from [%d] in file-id[%p] failed.",
			offset, seekpos, fp);
		return 0;
	}

	*newoffset = (int64_t) FinalOffset;
	return 1;
}

inm_s32_t flt_get_file_size (void *hdl, loff_t *fs_size)
{
	struct file *fp;
	loff_t size;
	struct address_space *mapping;
	struct inode *inode;

	INM_BUG_ON ((hdl == NULL) || (fs_size == NULL));

	fp = (struct file *) hdl;

	mapping = fp->f_mapping;
	inode = mapping->host;
	size = i_size_read (inode);

	*fs_size = (inm_u64_t)size;

	return 1;
}

void flt_close_file (void *hdl)
{
	INM_BUG_ON (hdl == NULL);
	filp_close ((struct file *) hdl, NULL);
}

inm_s32_t read_full_file(char *filename, char *buffer, inm_u32_t length,
				inm_u32_t *bytes_read)
{
	inm_u32_t read = 0;
	void *hdl = NULL;
	loff_t size = 0;
	inm_s32_t ret = 1;

	INM_MEM_ZERO(buffer, length);

	if (!flt_open_file (filename, O_RDONLY, &hdl)) {
		dbg("involflt: Opening file %s failed.", filename);
		return 0;
	}

	if(!flt_get_file_size(hdl, &size)) {
		dbg("flt_get_file_size failed");
		ret = 0;
		goto close_return;
	}

	if(length < size) {
		dbg("Insufficient buffer specified in read_full_file");
		ret = 0;
		goto close_return;
	}

	do {
		if (!flt_read_file(hdl, buffer, 0, length,
						(inm_s32_t *) &read)) {
			dbg("flt_read_file failed for %s", filename);
			ret = 0;
			goto close_return;	
		}

		*bytes_read += read;
	} while (0);

close_return:
	flt_close_file(hdl);

	return ret;
}

int32_t
__write_to_file(char *filename, void *buffer, inm_s32_t length, 
			  inm_u32_t * bytes_written, int oflag)
{
	void *hdl = NULL;
	int32_t success = 1;

	if (1 != flt_open_file(filename, O_RDWR | O_CREAT | O_SYNC | oflag,
					&hdl)) {
		dbg("involflt: Opening file %s failed.", filename);
		return 0;
	}
	do {
		if (!flt_write_file(hdl, buffer, 0, length,
					(inm_s32_t *) bytes_written)) {
			dbg("involflt: file write failed");
			success = 0;
			break;
		}
	} while (0);

	flt_close_file (hdl);

	return success;
}

int32_t
write_full_file(char *filename, void *buffer, inm_s32_t length, 
			inm_u32_t * bytes_written)
{
	return __write_to_file(filename, buffer, length, bytes_written,
					O_TRUNC);
}

int32_t
write_to_file(char *filename, void *buffer, inm_s32_t len, inm_u32_t *written)
{
	return __write_to_file(filename, buffer, len, written, 0);
}

int
file_exists(char *name)
{
	void *hdl = NULL;

	if (flt_open_file(name, O_RDONLY, &hdl)) {
		flt_close_file(hdl);
		return 1;
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15)
static struct dentry *
inm_cached_lookup(struct dentry *base, struct qstr *qstr,
				struct nameidata *nameidata)
{
	struct dentry *dir = d_lookup(base, qstr);

	if (!dir)
	dir = d_lookup(base, qstr);

	if (dir && dir->d_op && dir->d_op->d_revalidate) {
		if (!dir->d_op->d_revalidate(dir, nameidata) &&
						!d_invalidate(dir)) {
			dput(dir);
			dir = NULL;
		}
	}
	return dir;
}
static struct dentry *
inm__lookup_hash(struct qstr *qstr, struct dentry *base_dir,
				struct nameidata *nameidata)
{
	struct dentry *dir;
	struct inode *vfs_inode;
	inm_s32_t error;

	vfs_inode = base_dir->d_inode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	error = inode_permission(vfs_inode, MAY_EXEC);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	error = vfs_permission(nameidata, MAY_EXEC);
#else
	error = permission(vfs_inode, MAY_EXEC, nameidata);
#endif
#endif
	dir= ERR_PTR(error);
	if (error)
		goto out;

	if (base_dir->d_op && base_dir->d_op->d_hash) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
		error = base_dir->d_op->d_hash(base_dir, qstr);
#else
		error = base_dir->d_op->d_hash(base_dir, base_dir->d_inode,
							qstr);
#endif
		dir = ERR_PTR(error);
		if (error < 0)
			goto out;
	}

	dir = inm_cached_lookup(base_dir, qstr, nameidata);
	if (!dir) {
		struct dentry *new_dir = d_alloc(base_dir, qstr);
		dir = ERR_PTR(-ENOMEM);
		if (!new_dir)
			goto out;
		dir = vfs_inode->i_op->lookup(vfs_inode, new_dir, nameidata);
		if (!dir)
			dir = new_dir;
		else
			dput(new_dir);
	}
out:
	return dir;
}

static struct dentry *inm_lookup_hash(struct nameidata *nameidata)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	return inm__lookup_hash(&nameidata->last, nameidata->path.dentry,
						nameidata);
#else
	return inm__lookup_hash(&nameidata->last, nameidata->dentry,
						nameidata);
#endif
}
#endif

struct dentry *
inm_lookup_create(struct nameidata *nameidata, inm_s32_t is_dentry)
{
	struct dentry *dir = ERR_PTR(-EEXIST);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15)
#ifdef CONFIG_DEBUG_LOCK_ALLOC
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_lock_nested(&nameidata->path.dentry->d_inode->i_mutex,
							I_MUTEX_PARENT);
#else
	mutex_lock_nested(&nameidata->dentry->d_inode->i_mutex,
							I_MUTEX_PARENT);
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_lock(&nameidata->path.dentry->d_inode->i_mutex);
#else
	mutex_lock(&nameidata->dentry->d_inode->i_mutex);
#endif
#endif

	if (nameidata->last_type != LAST_NORM)
		goto fail;
	nameidata->flags &= ~LOOKUP_PARENT;
	nameidata->flags |= LOOKUP_CREATE;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
	nameidata->intent.open.flags = O_EXCL;
#endif

	dir = inm_lookup_hash(nameidata);
#else
	INM_DOWN(&nameidata->dentry->d_inode->i_sem);
	if (nameidata->last_type != LAST_NORM)
		goto fail;

	nameidata->flags &= ~LOOKUP_PARENT;
#ifdef CONFIG_KGDB
	dir = lookup_hash(nameidata);
#else
	dir = lookup_hash(&nameidata->last, nameidata->dentry);
#endif
#endif
	if (IS_ERR(dir))
		goto fail;
  
	if (!is_dentry && nameidata->last.name[nameidata->last.len] &&
							!dir->d_inode)
		goto enoent;

	return dir;

enoent:
	dput(dir);
	dir = ERR_PTR(-ENOENT);
fail:
	return dir;
}

#endif


long
inm_mkdir(char *dir_name, inm_s32_t mode)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15)
	inm_s32_t err = 0;
	char *tmp;
	
	tmp = dir_name;
	do {
		struct dentry *dir;
		inm_lookup_t nameidata;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)
		err = inm_path_lookup_parent(tmp, &nameidata);
		if (err) {
			err("Error in path_lookup\n");
			break;
		}
		dir = inm_lookup_create(&nameidata, 1);
#else
		dir = kern_path_create(AT_FDCWD, tmp, &nameidata.path,
							LOOKUP_DIRECTORY);
#endif
		err = PTR_ERR(dir);
		if (!IS_ERR(dir)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
			if (!IS_POSIXACL(nameidata.path.dentry->d_inode))
#else
			if (!IS_POSIXACL(nameidata.dentry->d_inode))
#endif
				mode &= ~current->fs->umask;
			dbg("Coming in inm_mkdir befor vfs_mkdir\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) || defined(RHEL9_6) || defined(SLES15SP6)
			err = vfs_mkdir(mnt_idmap(nameidata.path.mnt),
						nameidata.path.dentry->d_inode,
						dir, mode);
#else
			err = vfs_mkdir(mnt_user_ns(nameidata.path.mnt),
						nameidata.path.dentry->d_inode,
						dir, mode);
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
			err = vfs_mkdir(nameidata.path.dentry->d_inode,
						dir, mode);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
			err = vfs_mkdir(nameidata.path.dentry->d_inode,
						dir, nameidata.path.mnt, mode);
#else
#if (defined suse && DISTRO_VER==10 && PATCH_LEVEL>=2) || \
			LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
			err = vfs_mkdir(nameidata.dentry->d_inode, dir,
						nameidata.mnt, mode);
#else
			err = vfs_mkdir(nameidata.dentry->d_inode, dir, mode);
#endif
#endif
#endif
#endif
			dbg("Coming in inm_mkdir after vfs_mkdir\n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
			dput(dir);
#else
			done_path_create(&nameidata.path, dir);
#endif
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
		if(IS_ERR(dir)) {
			break;
		}
#endif	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		mutex_unlock(&nameidata.path.dentry->d_inode->i_mutex);
#else
		mutex_unlock(&nameidata.dentry->d_inode->i_mutex);
#endif
		inm_path_release(&nameidata);
#endif
	} while(0);

	return err;
#else

	inm_s32_t err = 0;
	struct dentry *dir;
	struct nameidata nameidata;

	err = inm_path_lookup_parent(dir_name, &nameidata);
	if (err)
		return err;

	dir = inm_lookup_create(&nameidata, 1);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		err = vfs_mkdir(nameidata.dentry->d_inode, dir, mode);
		dput(dir);
	}
	INM_UP(&nameidata.dentry->d_inode->i_sem);
	path_release(&nameidata);
	return err;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)

long 
__inm_unlink(const char * pathname, char *parent_path)
{
	inm_s32_t		error = 0;
	char		    *name = (char *)pathname;
	struct inode    *parent_inode = NULL;
	struct file     *parent_hdl = NULL;
	struct path		path;
	struct dentry	*dentry = NULL;
	struct inode    *deleg = NULL;
	int             retry = 0;
   
	dbg("Unlink called on %s, parent = %s", pathname, parent_path);

	parent_hdl = filp_open(parent_path, O_DIRECTORY, 0);
	if (IS_ERR(parent_hdl))
		error = PTR_ERR(parent_hdl);

	if (!error) {
		parent_inode = INM_HDL_TO_INODE(parent_hdl);

		do {
			deleg = NULL;
			retry = 0;

			error = kern_path(name, 0, &path);
			if (!error) {
				dentry = path.dentry;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
				inode_lock_nested(parent_inode,
							I_MUTEX_PARENT);
#else
				mutex_lock_nested(&parent_inode->i_mutex,
							I_MUTEX_PARENT);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0) || defined(RHEL9_6) || defined(SLES15SP6)
				error = vfs_unlink(mnt_idmap(path.mnt),
							parent_inode,
							dentry, &deleg);
#else
				error = vfs_unlink(mnt_user_ns(path.mnt),
							parent_inode,
							dentry, &deleg);
#endif
#else
				error = vfs_unlink(parent_inode, dentry,
							&deleg);
#endif
				if (error && !deleg)
					err("vfs_unlink failed with error %d",
								error);
		
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
				inode_unlock(parent_inode);
#else
				mutex_unlock(&parent_inode->i_mutex);
#endif

				path_put(&path);
			} else {
				dbg("Path lookup failed: %d", error);
			}

			if (deleg) {
				error = break_deleg_wait(&deleg);
				if (error)
					err("Cannot break delegation %p,"
						" error %d", deleg, error);
				else
					retry = 1;
			}
		} while(retry);
		/* cant use deleg as deleg=NULL in break_deleg_wait()*/

		filp_close(parent_hdl, NULL);
	} else {
		dbg("Parent path %s open failed: %d", parent_path, error);
	}

	return error;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)

long 
__inm_unlink(const char * pathname, char *unused)
{
	inm_s32_t		error = 0;
	char		    *name = (char *)pathname;
	struct path		parent_path, path;
	struct dentry	*dentry = NULL;
	struct inode    *deleg = NULL;
	int             retry = 0;
	
	dbg("Unlink called on %s", pathname);

	error = kern_path(name, LOOKUP_DIRECTORY | LOOKUP_PARENT,
					&parent_path);
	if (!error) {
		do {
			deleg = NULL;
			retry = 0;

			error = kern_path(name, 0, &path);
			if (!error) {
				dentry = path.dentry;

				mutex_lock_nested(&parent_path.dentry->d_inode->i_mutex, 
						  	I_MUTEX_PARENT);

				error = vfs_unlink(parent_path.dentry->d_inode,
							dentry, &deleg);
				if (error && !deleg)
					err("vfs_unlink failed with error %d\n",
									error);
		
				mutex_unlock(&parent_path.dentry->d_inode->i_mutex);

				path_put(&path);
			} else {
				dbg("Path lookup failed: %d", error);
			}


			if (deleg) {
				error = break_deleg_wait(&deleg);
				if (error)
					err("Cannot break delegation %p,"
						"error %d", deleg, error);
				else
					retry = 1;
			}
		} while(retry);
		/* cant use deleg as deleg=NULL in break_deleg_wait()*/

		path_put(&parent_path);
	} else {
		dbg("Parent path lookup failed: %d", error);
	}

	return error;
}

#else

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
long 
__inm_unlink(const char * pathname, char *unused)
{
	inm_s32_t		error = 0;
	char		*name = (char *)pathname;
	struct path		parent_path, path;
	struct dentry	*dentry;

	error = kern_path(name, LOOKUP_DIRECTORY | LOOKUP_PARENT,
		      			&parent_path);
	if (error) {
		dbg("Parent path lookup failed");
		goto out;
	}

	error = kern_path(name, 0, &path);
	if (error) {
		dbg("Path lookup failed");
		goto out_1;
	}

	dentry = path.dentry;

	mutex_lock_nested(&parent_path.dentry->d_inode->i_mutex, 
			      I_MUTEX_PARENT);

	error = vfs_unlink(parent_path.dentry->d_inode, dentry);
	if (error)
		err("vfs_unlink failed with error = %di\n", error);

	mutex_unlock(&parent_path.dentry->d_inode->i_mutex);
	
	path_put(&path);

out_1:
	path_put(&parent_path);

out:
	return error;
}
#else
long
__inm_unlink(const char *path, char *unused)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15)
	inm_s32_t err = 0;
	char *pathname;
	struct dentry *dir;
	struct nameidata nameidata;
	struct inode *vfs_inode = NULL;

	pathname = (char *) path;
	err = inm_path_lookup_parent(pathname, &nameidata);
	if (err)
		goto exit;
	err = -EISDIR;
	if (nameidata.last_type != LAST_NORM)
		goto exit1;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_lock_nested(&nameidata.path.dentry->d_inode->i_mutex,
							I_MUTEX_PARENT);
#else
	mutex_lock_nested(&nameidata.dentry->d_inode->i_mutex,
							I_MUTEX_PARENT);
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_lock(&nameidata.path.dentry->d_inode->i_mutex);
#else
	mutex_lock(&nameidata.dentry->d_inode->i_mutex);
#endif
#endif
	dir = inm_lookup_hash(&nameidata);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		if (nameidata.last.name[nameidata.last.len])
			goto slashes;
		vfs_inode = dir->d_inode;
		if (vfs_inode)
			INM_ATOMIC_INC(&vfs_inode->i_count);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
		err = vfs_unlink(nameidata.path.dentry->d_inode, dir);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		err = vfs_unlink(nameidata.path.dentry->d_inode, dir,
							nameidata.path.mnt);
#else
#if (defined suse && DISTRO_VER==10 && PATCH_LEVEL>=2) || \
			LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
		err = vfs_unlink(nameidata.dentry->d_inode, dir,
							nameidata.mnt);
#else
		err = vfs_unlink(nameidata.dentry->d_inode, dir);
#endif
#endif
#endif

		exit2:
		dput(dir);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_unlock(&nameidata.path.dentry->d_inode->i_mutex);
#else
	mutex_unlock(&nameidata.dentry->d_inode->i_mutex);
#endif
	if (vfs_inode)
		iput(vfs_inode);
exit1:
	inm_path_release(&nameidata);
exit:
	return err;

slashes:
	err = !dir->d_inode ? -ENOENT :
	S_ISDIR(dir->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
#else
	inm_s32_t err = 0;
	char * pathname;
	struct dentry *dir;
	struct nameidata nameidata;
	struct inode *vfs_inode = NULL;

	pathname = (char *) path;
	err = inm_path_lookup_parent(pathname, &nameidata);
	if (err)
		goto exit;
	err = -EISDIR;
	if (nameidata.last_type != LAST_NORM)
		goto exit1;
	INM_DOWN(&nameidata.dentry->d_inode->i_sem);
#ifdef CONFIG_KGDB
	dir = lookup_hash(&nameidata);
#else
	dir = lookup_hash(&nameidata.last, nameidata.dentry);
#endif
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		if (nameidata.last.name[nameidata.last.len])
			goto slashes;
		vfs_inode = dir->d_inode;
		if (vfs_inode)
			INM_ATOMIC_INC(&vfs_inode->i_count);
		err = vfs_unlink(nameidata.dentry->d_inode, dir);
exit2:
		dput(dir);
	}
	INM_UP(&nameidata.dentry->d_inode->i_sem);
	if (vfs_inode)
		iput(vfs_inode);
exit1:
	path_release(&nameidata);
exit:
	return err;

slashes:
	err = !dir->d_inode ? -ENOENT :
	S_ISDIR(dir->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
	goto exit2;
#endif
}
#endif
#endif

long 
inm_unlink(const char *pathname, char *parent)
{
	if (file_exists((char *)pathname)) 
		return __inm_unlink(pathname, parent);
	
	return 0;
}

inm_s32_t
inm_unlink_symlink(const char * pathname, char *parent_path)
{
	struct file *filp = NULL;
	int unlink = 0;

	filp = filp_open(pathname, O_RDONLY | O_NOFOLLOW, 0777);
	if (IS_ERR(filp)) {
		/* O_NOFOLLOW gives ELOOP for slink */
		if (PTR_ERR(filp) == -ELOOP) {
			dbg("%s is a symlink", pathname);
			unlink = 1;
		} else {
			dbg("Cannot open %s", pathname);
		}
	} else {
		dbg("%s is not a symlink", pathname);
		filp_close(filp, NULL);
	}

	if (unlink) {
		dbg("Deleting existing symlink %s", pathname);
		inm_unlink(pathname, parent_path);
	}

	return 0;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
long
inm_rmdir(const char *name)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15)
	inm_s32_t err = 0;
	char * pathname;
	struct dentry *dir;
	struct nameidata nameidata;

	pathname = (char *) name;
	err = inm_path_lookup_parent(pathname, &nameidata);
	if (err)
		goto exit;

	switch(nameidata.last_type) {
	case LAST_DOTDOT:
		err = -ENOTEMPTY;
		goto exit1;
	case LAST_DOT:
		err = -EINVAL;
		goto exit1;
	case LAST_ROOT:
		err = -EBUSY;
		goto exit1;
	}
#ifdef CONFIG_DEBUG_LOCK_ALLOC
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_lock_nested(&nameidata.path.dentry->d_inode->i_mutex,
							I_MUTEX_PARENT);
#else
	mutex_lock_nested(&nameidata.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_lock(&nameidata.path.dentry->d_inode->i_mutex);
#else
	mutex_lock(&nameidata.dentry->d_inode->i_mutex);
#endif
#endif
	dir = inm_lookup_hash(&nameidata);
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
		err = vfs_rmdir(nameidata.path.dentry->d_inode, dir);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
		err = vfs_rmdir(nameidata.path.dentry->d_inode, dir,
							nameidata.path.mnt);
#else
#if (defined suse && DISTRO_VER==10 && PATCH_LEVEL>=2) || \
				LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
		err = vfs_rmdir(nameidata.dentry->d_inode, dir, nameidata.mnt);
#else
		err = vfs_rmdir(nameidata.dentry->d_inode, dir);
#endif
#endif
#endif
		dput(dir);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mutex_unlock(&nameidata.path.dentry->d_inode->i_mutex);
#else
	mutex_unlock(&nameidata.dentry->d_inode->i_mutex);
#endif
exit1:
	inm_path_release(&nameidata);
exit:
	return err;
#else
	inm_s32_t err = 0;
	char * pathname;
	struct dentry *dir;
	struct nameidata nameidata;

	pathname = (char *)name;
	err = inm_path_lookup_parent(pathname, &nameidata);
	if (err)
		goto exit;

	switch(nameidata.last_type) {
	case LAST_DOTDOT:
		err = -ENOTEMPTY;
		goto exit1;
	case LAST_DOT:
		err = -EINVAL;
		goto exit1;
	case LAST_ROOT:
		err = -EBUSY;
		goto exit1;
	}
	INM_DOWN(&nameidata.dentry->d_inode->i_sem);
#ifdef CONFIG_KGDB 
	dir = lookup_hash(&nameidata);
#else
	dir = lookup_hash(&nameidata.last, nameidata.dentry);
#endif
	err = PTR_ERR(dir);
	if (!IS_ERR(dir)) {
		err = vfs_rmdir(nameidata.dentry->d_inode, dir);
		dput(dir);
	}
	INM_UP(&nameidata.dentry->d_inode->i_sem);
exit1:
	path_release(&nameidata);
exit:
	return err;
#endif
}
#endif

void remove_slashes(char *vol_name, char *target)
{
	char * ptr;
	strcpy_s(target, strlen(vol_name) + 1, vol_name);

	ptr = target;
	while (*ptr) {
		if (*ptr == '/')
			*ptr = '_';
		ptr++;
	}
}

#ifdef INM_RECUSIVE_ADSPC 

inma_ops_t
*inm_alloc_inma_ops(void)
{
	inma_ops_t *inma_opsp = NULL;

	inma_opsp = (inma_ops_t *) INM_KMALLOC(sizeof(inma_ops_t), 
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (inma_opsp) 
		inma_opsp->ia_mapping = NULL;

	return inma_opsp;
}

void
inm_free_inma_ops(inma_ops_t *inma_opsp)
{
	if (inma_opsp)
		kfree(inma_opsp);
}

inma_ops_t *
inm_get_inmaops_from_aops(const inm_address_space_operations_t *mapping,
					inm_u32_t unused)
{
	struct inm_list_head *lp = NULL, *np = NULL;
	inma_ops_t *t_inma_opsp = NULL;

	INM_BUG_ON(!mapping);

	inm_list_for_each_safe(lp, np, &driver_ctx->dc_inma_ops_list) {
		t_inma_opsp = inm_list_entry(lp, inma_ops_t, ia_list);

		if (mapping == t_inma_opsp->ia_mapping) 
			break;
		
		t_inma_opsp = NULL;
	}

	return t_inma_opsp;
}

int
inm_prepare_tohandle_recursive_writes(struct inode *inodep)
{
	const inm_address_space_operations_t *mapping= NULL;
	inma_ops_t *t_inma_opsp = NULL;
	inm_s32_t ret = -1;
	unsigned long lock_flag = 0;

	if (!inodep || !inodep->i_mapping) {
		ret = -EINVAL;
		goto exit;
	}

	dbg("%p -> %p", inodep, inodep->i_mapping);
	mapping = (inm_address_space_operations_t *)inodep->i_mapping;
	INM_BUG_ON(!mapping);

	/* new node is required */
	lock_inmaops(TRUE, &lock_flag);

	t_inma_opsp = inm_get_inmaops_from_aops(mapping,
						INM_ORG_ADDR_SPACE_OPS);
	if (t_inma_opsp) {
		/* Multiple open files should not have same mapping */
		INM_BUG_ON(t_inma_opsp);
		ret = -EEXIST;
		goto exit_locked;
	}

	t_inma_opsp = inm_alloc_inma_ops();
	if (!t_inma_opsp) {
		ret = -ENOMEM;
		goto exit_locked;
	}
			
	t_inma_opsp->ia_mapping = mapping;
	dbg("Add recursive object: Lookup = %p, Mapping = %p", t_inma_opsp, 
	mapping);
	inm_list_add_tail(&t_inma_opsp->ia_list,
					&driver_ctx->dc_inma_ops_list);
	ret = 0;

exit_locked:
	unlock_inmaops(TRUE, &lock_flag);

exit:
	return ret;
}

void
inm_restore_org_addr_space_ops(struct inode *inodep)
{
	inma_ops_t *t_inma_opsp = NULL;
	unsigned long lock_flag;

	lock_inmaops(TRUE, &lock_flag);
	t_inma_opsp = inm_get_inmaops_from_aops(inodep->i_mapping, 
			                            INM_ORG_ADDR_SPACE_OPS);
	inm_list_del(&t_inma_opsp->ia_list);
	unlock_inmaops(TRUE, &lock_flag);

	dbg("Delete recursive object: Lookup = %p, mapping = %p", 
	t_inma_opsp, t_inma_opsp->ia_mapping);   

	inm_free_inma_ops(t_inma_opsp);
}

#else

/* allocates memory and returns inm_ops_t pointer */
inma_ops_t
*inm_alloc_inma_ops(void)
{
	inma_ops_t *inma_opsp = NULL;
	inm_address_space_operations_t *a_opsp = NULL;

	a_opsp = (inm_address_space_operations_t *)
		  INM_KMALLOC(sizeof(inm_address_space_operations_t),
				  	INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!a_opsp) {
		goto exit;
	}

	inma_opsp = (inma_ops_t *) INM_KMALLOC(sizeof(inma_ops_t),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!inma_opsp) {
		kfree(a_opsp);
		goto exit;
	}
	inma_opsp->ia_org_aopsp = NULL;
	inma_opsp->ia_dup_aopsp = a_opsp;

exit:

	return inma_opsp;
}

/* frees memory associated with inma_opsp ptr */
void
inm_free_inma_ops(inma_ops_t *inma_opsp)
{
	if (inma_opsp) {
		if (inma_opsp->ia_dup_aopsp) {
			kfree(inma_opsp->ia_dup_aopsp);
		}
		kfree(inma_opsp);
	}
}

/* walks through the inm_aops_list, if the a_opsp matches with
 * ia_org/dup_addr_space_opsp based on lookup_flag then it returns
 * the inma_aops_t ptr, otherwise returns NULL. 
 * the callers should acquire dc_inmaops_sem, before calling this fn */
inma_ops_t
*inm_get_inmaops_from_aops(const inm_address_space_operations_t *a_opsp,
			   inm_u32_t lookup_flag)
{
	struct inm_list_head *lp = NULL, *np = NULL;
	inma_ops_t *t_inma_opsp = NULL;

	INM_BUG_ON(!a_opsp);
	INM_BUG_ON(lookup_flag >= INM_MAX_ADDR_OPS);

	inm_list_for_each_safe(lp, np, &driver_ctx->dc_inma_ops_list) {
		t_inma_opsp = (inma_ops_t *) inm_list_entry(lp, inma_ops_t,
								ia_list);

		if (lookup_flag == INM_DUP_ADDR_SPACE_OPS) {
			if (a_opsp == t_inma_opsp->ia_dup_aopsp) {
				break;
			}
		} else if (a_opsp == t_inma_opsp->ia_org_aopsp) {
			break;
		}
		t_inma_opsp = NULL;
	}

	return t_inma_opsp;
}	


/* this function replaces a_ops with duplicated a_ops ptr in two steps, 
 * if one duplicated a_ops ptr is found in the dc_inma_ops_list, otherwise 
 * it allocates new inma_ops structure, then adds to the dc_inma_ops_list,
 * 
 * once appropriate duplicate a_ops exist in the global list, it replaces the
 * file's a_ops ptr with duplicate a_ops ptr
 */

int
inm_prepare_tohandle_recursive_writes(struct inode *inodep)
{
	const inm_address_space_operations_t *a_opsp = NULL;
	inma_ops_t *t_inma_opsp = NULL;
	inm_s32_t ret = -1;
	unsigned long lock_flag;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}

	if (!inodep || !inodep->i_mapping) {
		ret = -EINVAL;
		goto exit;
	}

	a_opsp = (inm_address_space_operations_t *)inodep->i_mapping->a_ops;
	INM_BUG_ON(!a_opsp);

	lock_inmaops(FALSE, &lock_flag);
	t_inma_opsp = inm_get_inmaops_from_aops(a_opsp,
						INM_ORG_ADDR_SPACE_OPS);
	unlock_inmaops(FALSE, &lock_flag);

	if (t_inma_opsp) {
		goto xchange;
	}

	/* new node is required */
	lock_inmaops(TRUE, &lock_flag);
	t_inma_opsp = inm_get_inmaops_from_aops(a_opsp,
						INM_ORG_ADDR_SPACE_OPS);
	if (t_inma_opsp) {
		/* some body else added the new node */
		unlock_inmaops(TRUE, &lock_flag);
		goto xchange;
	}
	t_inma_opsp = inm_alloc_inma_ops();
	if (!t_inma_opsp) {
		unlock_inmaops(TRUE, &lock_flag);
		ret = -ENOMEM;
		goto exit;
	}
			
	t_inma_opsp->ia_org_aopsp = a_opsp;
	memcpy_s(t_inma_opsp->ia_dup_aopsp, sizeof(*a_opsp), a_opsp,
							sizeof(*a_opsp));
	inm_list_add_tail(&t_inma_opsp->ia_list,
					&driver_ctx->dc_inma_ops_list);
	unlock_inmaops(TRUE, &lock_flag);

xchange:

	(void)xchg(&inodep->i_mapping->a_ops, t_inma_opsp->ia_dup_aopsp);
	dbg("DAOPS = %p, OAOPS = %p", t_inma_opsp->ia_dup_aopsp,
			                  t_inma_opsp->ia_org_aopsp);
	ret = 0;

exit:

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}
	return ret;
}

/* this function replaces the original address apace operations ptr, that was
 * replaced by inm_prepare_tohandle_recursive_writes() fn */
void
inm_restore_org_addr_space_ops(struct inode *inodep)
{
	inma_ops_t *t_inma_opsp = NULL;
	unsigned long lock_flag;

	lock_inmaops(FALSE, &lock_flag);
	t_inma_opsp = inm_get_inmaops_from_aops(
			    (inm_address_space_operations_t *)inodep->i_mapping->a_ops,
						INM_DUP_ADDR_SPACE_OPS);
	unlock_inmaops(FALSE, &lock_flag);
	if (t_inma_opsp) {
		(void)xchg(&inodep->i_mapping->a_ops,
			   t_inma_opsp->ia_org_aopsp);
	}
}

#endif

/* wrapper around flt_open_file, this is required only for data files */
inm_s32_t flt_open_data_file (const char *fnamep, inm_u32_t mode, void **hdlpp)
{
	void *t_hdlp = NULL;
	mm_segment_t fs;
	struct inode *inodep = NULL;
	inm_s32_t ret = 1; 
  
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}	

	ret = flt_open_file(fnamep, mode, &t_hdlp);
	if (ret == 0) {
		goto exit;
	}

	fs = get_fs ();
	set_fs (KERNEL_DS);
	inodep = INM_HDL_TO_INODE((struct file *) t_hdlp);
	inm_prepare_tohandle_recursive_writes(inodep);
	*hdlpp = t_hdlp;
	set_fs (fs);

exit:

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}	

	return ret;
}

