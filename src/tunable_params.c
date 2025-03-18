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
#include "metadata-mode.h"
#include "statechange.h"
#include "file-io.h"
#include "tunable_params.h"
#include "osdep.h"
#include "filter.h"
#include "filter_host.h"
#include "db_routines.h"
#include "verifier.h"

extern driver_context_t *driver_ctx;
extern char *ErrorToRegErrorDescriptionsA[];

#ifdef INM_SOLARIS
extern pgcnt_t physinstalled;
#endif

void init_driver_tunable_params(void)
{

	load_driver_params();

	driver_ctx->dc_tel.dt_timestamp_in_persistent_store = 
					driver_ctx->last_time_stamp;
	driver_ctx->dc_tel.dt_seqno_in_persistent_store = 
					driver_ctx->last_time_stamp_seqno;

	driver_ctx->tunable_params.max_data_pages_per_target = 
					DEFAULT_MAX_DATA_PAGES_PER_TARGET;
	driver_ctx->tunable_params.max_data_size_per_non_data_mode_drty_blk = 
			DEFAULT_MAX_DATA_SIZE_PER_NON_DATA_MODE_DIRTY_BLOCK;
	driver_ctx->tunable_params.free_pages_thres_for_filewrite = 
	(((driver_ctx->tunable_params.data_pool_size << 
		(MEGABYTE_BIT_SHIFT-INM_PAGESHIFT)) * 
	  (driver_ctx->tunable_params.free_percent_thres_for_filewrite)) / 100);

	if(!driver_ctx->clean_shutdown)
		driver_ctx->unclean_shutdown = 1;
}
/* Global data page pool memory allocation = 6.25% of system memory
 * Examples --
 * For <= 1 GB System Memory		-  64 MB
 * For    2 GB System Memory		- 128 MB
 * For    4 GB System Memory		- 256 MB
 * For    8 GB System Memory		- 512 MB
 * For   16 GB System Memory		- 1024 MB
 * For   32 GB System Memory		- 2048 MB
 */
inm_u32_t get_data_page_pool_mb(void)
{
	inm_u32_t total_ram_mb = 0, data_pool_mb = 0;
	inm_meminfo_t info;

	INM_SI_MEMINFO(&info);
	total_ram_mb = info.totalram >> (MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
	if (total_ram_mb < DEFAULT_DATA_POOL_SIZE_MB)
		return 0;

	/* 6.25 % of system memory is equal to 1/16th system memory */
	data_pool_mb = total_ram_mb >> 4;
#ifdef APPLIANCE_DRV
	if (total_ram_mb > INM_INCR_DPS_LIMIT_ON_APP) {
		data_pool_mb = total_ram_mb >> INM_DEFAULT_DPS_APPLIANCE_DRV;
	}
	dbg("total ram size is %u and DPS is %u",total_ram_mb, data_pool_mb);
#endif
	if (data_pool_mb < DEFAULT_DATA_POOL_SIZE_MB)
		data_pool_mb = DEFAULT_DATA_POOL_SIZE_MB;

	return data_pool_mb;
}

/* 
 * ============================COMMON ATTRIBUTES===========================================================
 */

inm_s32_t write_common_attr(const char *file_name, void *buf, inm_s32_t len)
{
	char *path = NULL;
	inm_u32_t wrote = 0, ret = 0;

	if(!get_path_memory(&path)) {
		err("Failed to allocate memory for path");
		goto out;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s/%s",PERSISTENT_DIR,
						COMMON_ATTR_NAME, file_name);

	dbg("Writing to file %s", path);

	if(!write_full_file(path, (void *)buf, len, &wrote)) {
		err("write to persistent store failed %s", path);
		goto free_path_buf;
	}
	
	ret = 1;

free_path_buf:
	free_path_memory(&path);

out:
	return ret;	
}

inm_s32_t read_common_attr(char *fname, void **buf, inm_s32_t len, 
						inm_s32_t *bytes_read)
{
	inm_s32_t ret = 0;
	char *path = NULL;

	if(!get_path_memory(&path)) {
		err("Failed to allocate memory for path");
		goto out;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s/%s",PERSISTENT_DIR,
						COMMON_ATTR_NAME, fname);

	dbg("Reading from file %s", path);

	*buf = (void *)INM_KMALLOC(len, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!*buf) {
		err("Failed to allocate memory for buffer");
		goto free_path_buf;
	}


	INM_MEM_ZERO(*buf, len);

	if(!read_full_file(path, *buf, len, (inm_u32_t *)bytes_read))
		goto free_buf;		

	ret = 1;
	goto free_path_buf;

free_buf:
	if(*buf)	
	INM_KFREE(*buf, len, INM_KERNEL_HEAP);
	*buf = NULL;

free_path_buf:
	free_path_memory(&path);

out:
	return ret;
}

static ssize_t common_attr_show(struct attribute *attr, char *page)
{
	struct common_attribute *common_attr;
	ssize_t ret = 0;

	common_attr = inm_container_of(attr, struct common_attribute, attr);

	if (common_attr->show)
		ret = common_attr->show(page);

	return ret;
}

static ssize_t common_attr_store(struct attribute *attr, const char *page,
				 size_t len)
{
	struct common_attribute *common_attr;
	ssize_t ret = len;

	common_attr = inm_container_of(attr, struct common_attribute, attr);

	if (common_attr->store)
		ret = common_attr->store(common_attr->file_name, page, len);

	if(ret < 0)
		return ret;
	else {
		return len;
	}
}

ssize_t
pool_size_show(char *buf)
{

	inm_u64_t mb = driver_ctx->tunable_params.data_pool_size;
	return snprintf(buf, INM_PAGESZ, "%lldMB\n", (unsigned long long)mb);
}

ssize_t
pool_size_store(const char *file_name, const char *buf, size_t len)
{
	inm_u32_t num_pages = 0, diff_pages = 0;
	inm_u32_t mem = 0;
	inm_u32_t orig_data_pool_size = 0;
	inm_u32_t max_data_pool_limit = 0;
	inm_meminfo_t meminfo;
	unsigned long lock_flag;
	inm_s32_t ret = 0;

	if (len > 6) {
		err("Invalid Data Pool Size Supplied: Very large value");	
		return -EINVAL;
	}

	if (!is_digit(buf, len)) {
		err("Data Pool Size supplied contains non-digit chars");
		return -EINVAL;
	}

	mem = inm_atoi(buf);
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	orig_data_pool_size = driver_ctx->tunable_params.data_pool_size;
	driver_ctx->tunable_params.data_pool_size = mem;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	if (mem < DEFAULT_DATA_POOL_SIZE_MB) {
		err("Invalid Data Pool Size! It cannot be less than %d MB.",
			DEFAULT_DATA_POOL_SIZE_MB);
		 ret = INM_EINVAL;
		 goto restore_old;
	}

	INM_SI_MEMINFO(&meminfo);
	max_data_pool_limit =
	((meminfo.totalram * driver_ctx->tunable_params.max_data_pool_percent)/100);
	num_pages = mem << (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
	info("DataPagePool modification -  num_pages:%u current alloc'd pages:%u",
		  num_pages, driver_ctx->data_flt_ctx.pages_allocated);

	if (num_pages > max_data_pool_limit) {
		max_data_pool_limit >>= (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
		info(
		"DataPoolSize:%uMB cannot be greater than %u%%(%uMB) of system memory:%luMB",
			 mem, driver_ctx->tunable_params.max_data_pool_percent,
			 max_data_pool_limit,
			 meminfo.totalram >> (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT));
		 ret = INM_EINVAL;
		 goto restore_old;
	}

	if(driver_ctx->data_flt_ctx.pages_allocated > num_pages) {
		diff_pages = driver_ctx->data_flt_ctx.pages_allocated - num_pages;
		INM_BUG_ON(diff_pages > driver_ctx->data_flt_ctx.pages_allocated);
		if (diff_pages > (driver_ctx->dc_cur_unres_pages)) {
			err("DataPoolSize can't be reduced below %uMB due to reservations",
				driver_ctx->dc_cur_res_pages >>

				(MEGABYTE_BIT_SHIFT-INM_PAGESHIFT));
			ret = INM_EINVAL;
			goto restore_old;
		}
		info("deleting %d pages", diff_pages);
		delete_data_pages(diff_pages);
		recalc_data_file_mode_thres();
	}
	
	if (!write_common_attr(file_name, (void *)buf, len))  {
		ret = INM_EINVAL;
		goto restore_old;
	}

out:
	return len;
restore_old:
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.data_pool_size = orig_data_pool_size;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	goto out;
}

ssize_t
inm_time_reorg_data_pool_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.time_reorg_data_pool_sec;

	return snprintf(buf, INM_PAGESZ, "%u\n", pc);
}


ssize_t
inm_time_reorg_data_pool_store(const char *file_name, const char *buf, 
								size_t len)
{
	int time_sec = 0;
	inm_irqflag_t lock_flag;

	if (!is_digit(buf, len)) {
		err("Percent Change Data Pool Size supplied contains non-digit chars");
		return INM_EINVAL;
	}

	time_sec = inm_atoi(buf);

	if(time_sec < 0){
		err("Time for Reorg Data Pool Size supplied is not a positive number");
		return INM_EINVAL;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.time_reorg_data_pool_sec = time_sec;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("TimeReorgDataPoolSec update failed to write file:%s.",
			file_name);
		return INM_EINVAL;
	}
	return len;
}

ssize_t
inm_time_reorg_data_pool_factor_store(const char *file_name, const char *buf, 
								size_t len)
{
	int factor = 0;
	inm_irqflag_t lock_flag;

	if (!is_digit(buf, len)) {
		err("Time reorg Data Pool Factor has to be interger");
		return INM_EINVAL;
	}

	factor = inm_atoi(buf);

	if(factor <= 0){
		err("Time Reorg Data Pool Factor has to be interger supplied is not a positive number");
		return INM_EINVAL;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.time_reorg_data_pool_factor = factor;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("TimeReorgDataPoolFactor update failed to write file:%s.",
			file_name);
		return INM_EINVAL;
	}
	return len;
}

ssize_t
inm_time_reorg_data_pool_factor_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.time_reorg_data_pool_factor;

	return snprintf(buf, INM_PAGESZ, "%u\n", pc);
}


ssize_t inm_recio_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.enable_recio);
}

ssize_t inm_recio_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for TrackRecursiveWrites");
		return -EINVAL;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) 
		return -EINVAL;
	else
		driver_ctx->tunable_params.enable_recio = val;

	if (driver_ctx->tunable_params.enable_recio) {
		info("Recursive IO tracking Enabled");
	} else {
		info("Recursive IO tracking Disabled");
	}

	return len;
}

ssize_t inm_recio_read(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		driver_ctx->tunable_params.enable_recio = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.enable_recio = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	if (driver_ctx->tunable_params.enable_recio) {
		info("Recursive IO tracking Enabled");
	}

	return 0;
}

ssize_t inm_stable_pages_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.stable_pages);
}

ssize_t inm_stable_pages_store(const char *file_name, const char *buf, 
								size_t len)
{

#ifndef INM_LINUX 
	return -EINVAL;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	return -EINVAL;
#else
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for TrackRecursiveWrites");
		return -EINVAL;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) 
		return -EINVAL;
	else
		driver_ctx->tunable_params.stable_pages = val;

	if (driver_ctx->tunable_params.stable_pages) {
		info("Stable Pages Enabled");
		set_stable_pages_for_all_devs();
	} else {
		info("Stable Pages Disabled");
		reset_stable_pages_for_all_devs();
	}

	return len;
#endif
}

ssize_t inm_stable_pages_read(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		driver_ctx->tunable_params.stable_pages = inm_atoi(buf);

		if (driver_ctx->tunable_params.stable_pages) {
			info("Stable Pages Enabled");
			set_stable_pages_for_all_devs();
		} else {
			info("Stable Pages Disabled");
			reset_stable_pages_for_all_devs();
		}

		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.stable_pages = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	return 0;
}

ssize_t inm_chained_io_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.enable_chained_io);
}

ssize_t inm_chained_io_store(const char *file_name, const char *buf, 
								size_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid EnableChainedIO value: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for EnableChainedIO");
		return -EINVAL;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) 
		return -EINVAL;

	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	info("Chained IO: %d", val);
	driver_ctx->tunable_params.enable_chained_io = val;
	INM_UP_READ(&driver_ctx->tgt_list_sem);

	return len;
}

ssize_t inm_chained_io_read(char *fname)
{
	inm_s32_t bytes_read = 0, val = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, val, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		val = inm_atoi(buf);

		INM_DOWN_READ(&driver_ctx->tgt_list_sem);
		driver_ctx->tunable_params.enable_chained_io = val;
		INM_UP_READ(&driver_ctx->tgt_list_sem);

		goto free_buf;
	}

set_default:
#ifdef INM_CHAIN_BIO_ENABLED
	driver_ctx->tunable_params.enable_chained_io = 1;
#else
	driver_ctx->tunable_params.enable_chained_io = 0;
#endif

free_buf:
	if(buf)
		INM_KFREE(buf, val, INM_KERNEL_HEAP);

	return 0;
}

ssize_t
inm_vacp_iobarrier_timeout_read(char *fname)
{
	inm_s32_t bytes_read = 0;
	inm_s32_t buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.vacp_iobarrier_timeout = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.vacp_iobarrier_timeout = 
							VACP_IOBARRIER_TIMEOUT;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_vacp_iobarrier_timeout_store(const char *file_name, const char *buf, 
								size_t len)
{
	int timeout = 0;
	inm_irqflag_t lock_flag;

	if (!is_digit(buf, len)) {
		err("VacpIObarrierTimeout has to be interger");
		return INM_EINVAL;
	}

	timeout = inm_atoi(buf);

	if (timeout <= 0) {
		err("VacpIObarrierTimeout must be greater than 0");
		return INM_EINVAL;
	}

	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("VacpIObarrierTimeout update failed to write file:%s.",
						file_name);
		return INM_EINVAL;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.vacp_iobarrier_timeout = timeout;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

	return len;
}

ssize_t
inm_vacp_iobarrier_timeout_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.vacp_iobarrier_timeout;

	return snprintf(buf, INM_PAGESZ, "%u\n", pc);
}

ssize_t
inm_fs_freeze_timeout_read(char *fname)
{
	inm_s32_t bytes_read = 0;
	inm_s32_t buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.fs_freeze_timeout = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.fs_freeze_timeout = FS_FREEZE_TIMEOUT;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_fs_freeze_timeout_store(const char *file_name, const char *buf, size_t len)
{
	int timeout = 0;
	inm_irqflag_t lock_flag;

	if (!is_digit(buf, len)) {
		err("FsFreezeTimeout has to be interger");
		return INM_EINVAL;
	}

	timeout = inm_atoi(buf);

	if (timeout <= 0) {
		err("FsFreezeTimeout must be greater than 0");
		return INM_EINVAL;
	}

	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("FsFreezeTimeout update failed to write file:%s.",
			file_name);
		return INM_EINVAL;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.fs_freeze_timeout = timeout;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

	return len;
}

ssize_t
inm_fs_freeze_timeout_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.fs_freeze_timeout;

	return snprintf(buf, INM_PAGESZ, "%u\n", pc);
}

ssize_t
inm_vacp_app_tag_commit_timeout_read(char *fname)
{
	inm_s32_t bytes_read = 0;
	inm_s32_t buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.vacp_app_tag_commit_timeout = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.vacp_app_tag_commit_timeout = 
						VACP_APP_TAG_COMMIT_TIMEOUT;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_vacp_app_tag_commit_timeout_store(const char *file_name, const char *buf, 
								size_t len)
{
	int timeout = 0;
	inm_irqflag_t lock_flag;

	if (!is_digit(buf, len)) {
		err("VacpAppTagCommitTimeout has to be interger");
		return INM_EINVAL;
	}

	timeout = inm_atoi(buf);

	if (timeout <= 0) {
		err("VacpAppTagCommitTimeout must be greater than 0");
		return INM_EINVAL;
	}

	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("VacpAppTagCommitTimeout update failed to write file:%s.",
			file_name);
		return INM_EINVAL;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.vacp_app_tag_commit_timeout = timeout;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

	return len;
}

ssize_t
inm_vacp_app_tag_commit_timeout_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.vacp_app_tag_commit_timeout;

	return snprintf(buf, INM_PAGESZ, "%u\n", pc);
}

ssize_t
inm_percent_change_data_pool_size_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.percent_change_data_pool_size;

	return snprintf(buf, INM_PAGESZ, "%u%%\n", pc);
}


ssize_t
inm_percent_change_data_pool_size_store(const char *file_name, const char *buf, 
								size_t len)
{
	int percentage = 0;
	inm_meminfo_t meminfo;
	inm_u32_t nr_pages;
	inm_irqflag_t lock_flag;

	if (len > 2) {
		err("Invalid Percent Change Data Pool Size Supplied: Very large value");
		return INM_EINVAL;
	}

	if (!is_digit(buf, len)) {
		err("Percent Change Data Pool Size supplied contains non-digit chars");
		return INM_EINVAL;
	}

	percentage = inm_atoi(buf);

	if(percentage <= 0){
		err("Percent Change Data Pool Size supplied is not a positive number");
		return INM_EINVAL;
	}
	INM_SI_MEMINFO(&meminfo);
	nr_pages = ((meminfo.totalram * percentage) / 100);
	info("PercentChangeDataPoolSize modification -  DataPoolSize:%u current alloc'd pages:%u",
				nr_pages, driver_ctx->data_flt_ctx.pages_allocated);

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	driver_ctx->tunable_params.percent_change_data_pool_size = percentage;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("PercentChangeDataPoolSize update failed to write file:%s.", file_name);
		return INM_EINVAL;
	}
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);
	driver_ctx->data_flt_ctx.dp_nrpgs_slab = nr_pages;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock, 
								lock_flag);
	return len;
}


ssize_t
inm_maxdatapool_sz_show(char *buf)
{
	unsigned int pc = driver_ctx->tunable_params.max_data_pool_percent;

	return snprintf(buf, INM_PAGESZ, "%u%%\n", pc);
}

ssize_t
inm_maxdatapool_sz_store(const char *file_name, const char *buf, size_t len)
{
	int percentage = 0;
	unsigned int max_data_pool_limit = 0;
	inm_meminfo_t meminfo;

	if (len > 2) {
		err("Invalid Max Data Pool Size Supplied: Very large value");
		return -EINVAL;
	}

	if (!is_digit(buf, len)) {
		err("Max Data Pool Size supplied contains non-digit chars");
		return -EINVAL;
	}

	percentage = inm_atoi(buf);

	INM_SI_MEMINFO(&meminfo);
	max_data_pool_limit = ((meminfo.totalram * percentage) / 100);
	info("MaxDataPagePoolSize modification -  MaxDataPoolSize:%u current alloc'd pages:%u",
		max_data_pool_limit, driver_ctx->data_flt_ctx.pages_allocated);

	if(max_data_pool_limit < driver_ctx->data_flt_ctx.pages_allocated) {
		info("MaxDataPoolSize:%u pages cannot be less than the current alloc'd pages:%u",
				max_data_pool_limit, 
				driver_ctx->data_flt_ctx.pages_allocated);
		return -EINVAL;
	}

	driver_ctx->tunable_params.max_data_pool_percent = percentage;

	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("MaxDataPoolSize update failed to write file:%s.",
			file_name);
		return -EINVAL;
	}
	return len;
}

ssize_t
inm_vol_respool_sz_show(char *buf)
{
	inm_u64_t mb = driver_ctx->tunable_params.volume_data_pool_size;

	return snprintf(buf, INM_PAGESZ, "%lldMB\n", (long long)mb);
}

ssize_t
inm_vol_respool_sz_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t num_pages = 0;
	inm_u64_t mem = 0;
	unsigned long lock_flag;

	/* Not supported */
	return -EINVAL;

	if (len > 6) {
		err("Invalid Data Pool Size Supplied: Very large value");	
		return -EINVAL;
	}

	if (!is_digit(buf, len)) {
		err("Data Pool Size supplied contains non-digit chars");
		return -EINVAL;
	}

	mem = inm_atoi64(buf);
	num_pages = mem << (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
	if(num_pages > driver_ctx->data_flt_ctx.pages_allocated){
		err("Per Volume Reserve Data Pool can not be bigger then Global Data Pool size");
		return INM_EINVAL;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, 
						lock_flag);

	driver_ctx->dc_vol_data_pool_size = num_pages;
	driver_ctx->tunable_params.volume_data_pool_size = 
		num_pages >> (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);

	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
					       lock_flag);

	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("VolumeResDataPoolSize update failed to write file:%s.",
			file_name);
		return -EINVAL;
	}
	return len;
}

ssize_t log_dir_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%s\n", 
				driver_ctx->tunable_params.data_file_log_dir);
}

ssize_t log_dir_store(const char *file_name, const char *buf, size_t len)
{
	unsigned long lock_flag = 0;

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
		if (strncpy_s(driver_ctx->tunable_params.data_file_log_dir, 
					INM_PATH_MAX, buf, len)) {
			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, 
							lock_flag);
			return -INM_EFAULT;
		}
		driver_ctx->tunable_params.data_file_log_dir[len] = '\0';
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, 
							lock_flag);
	}

	return len;
}

ssize_t free_thres_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d%%\n",
			driver_ctx->tunable_params.free_percent_thres_for_filewrite);
}

ssize_t free_thres_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(len > 3) {
		err("Invalid Free threshold percent supplied");
		return -EINVAL;
	}

	if(!is_digit(buf, len)) {
		err("Invalid Free threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);
	if((thres < 0) || (thres > 100)) {
		err("Percent free page threshold can't be less than zero or greater than 100");
	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.free_percent_thres_for_filewrite = thres;
		recalc_data_file_mode_thres();
	}

	return len;
}

ssize_t volume_thres_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d%%\n",
	driver_ctx->tunable_params.volume_percent_thres_for_filewrite);
}

ssize_t volume_thres_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(len > 3) {
		err("Invalid volume threshold percent supplied");
		return -EINVAL;
	}

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);
	if((thres < 0) || (thres > 100)) {
		err("Percent free page threshold can't be less than zero or greater than 100");
		return -EINVAL;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.volume_percent_thres_for_filewrite = thres;
	}    

	return len;
}

ssize_t dbhwm_sns_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
	driver_ctx->tunable_params.db_high_water_marks[SERVICE_NOTSTARTED]);
}

ssize_t dbhwm_sns_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.db_high_water_marks[SERVICE_NOTSTARTED] = thres;
	}

	return len;
}

ssize_t dblwm_sr_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
	driver_ctx->tunable_params.db_low_water_mark_while_service_running);
}

ssize_t dblwm_sr_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.db_low_water_mark_while_service_running = thres;
	}

	return len;
}

ssize_t dbhwm_sr_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
	driver_ctx->tunable_params.db_high_water_marks[SERVICE_RUNNING]);
}

ssize_t dbhwm_sr_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.db_high_water_marks[SERVICE_RUNNING] = thres;
	}

	return len;
}

ssize_t dbhwm_ss_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.db_high_water_marks[SERVICE_SHUTDOWN]);
}

ssize_t dbhwm_ss_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.db_high_water_marks[SERVICE_SHUTDOWN] = thres;
	}

	return len;
}

ssize_t dbp_hwm_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
	driver_ctx->tunable_params.db_topurge_when_high_water_mark_is_reached);
}

ssize_t dbp_hwm_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.db_topurge_when_high_water_mark_is_reached = thres;
	}

	return len;
}

ssize_t max_bmapmem_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n",
			driver_ctx->dc_bmap_info.max_bitmap_buffer_memory);
}

ssize_t max_bmapmem_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->dc_bmap_info.max_bitmap_buffer_memory = thres;
	}

	return len;
}

ssize_t bmap_512ksz_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n",
			driver_ctx->dc_bmap_info.bitmap_512K_granularity_size);
}

ssize_t bmap_512ksz_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t thres = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	thres = inm_atoi(buf);

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->dc_bmap_info.bitmap_512K_granularity_size = thres;
	}

	return len;
}

ssize_t vdf_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.enable_data_filtering);
}

ssize_t vdf_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeDataFiltering");
		return -EINVAL;
			
	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.enable_data_filtering = val;
	}

	return len;
}

ssize_t vdf_newvol_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
	driver_ctx->tunable_params.enable_data_filtering_for_new_volumes);
}

ssize_t vdf_newvol_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeDataFiltering");
		return -EINVAL;

	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.enable_data_filtering_for_new_volumes = val;
	}

	return len;
}

ssize_t vol_dfm_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.enable_data_file_mode);
}

ssize_t vol_dfm_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeDataFiltering");
		return -EINVAL;

	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.enable_data_file_mode = val;
	}

	return len;
}

#ifdef IDEBUG_MIRROR_IO
extern inm_s32_t inject_atio_err;
extern inm_s32_t inject_ptio_err;
extern inm_s32_t inject_vendorcdb_err;
extern inm_s32_t clear_vol_entry_err;
#endif

ssize_t newvol_dfm_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
	driver_ctx->tunable_params.enable_data_file_mode_for_new_volumes);
}

ssize_t newvol_dfm_store(const char *file_name, const char *buf, size_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi(buf);
#if (defined(IDEBUG_MIRROR_IO))
	if(val == 1){
		inject_atio_err = 1;
	}
	if(val == 2){
		inject_ptio_err = 1;
		dbg("enabled ptio error injection");
	}
	if(val == 3){
		inject_vendorcdb_err = 1;
	}
	if(val == 4){
		clear_vol_entry_err = 1;
	}
#endif
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeDataFiltering");
		return -EINVAL;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.enable_data_file_mode_for_new_volumes = val;
	}

	return len;
}

ssize_t dfm_disk_limit_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%lld MB\n", 
			(long long)(driver_ctx->tunable_params.data_to_disk_limit/MEGABYTES));
}

ssize_t dfm_disk_limit_store(const char *file_name, const char *buf, size_t len)
{
	inm_s64_t lmt = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		lmt = inm_atoi(buf);
		driver_ctx->tunable_params.data_to_disk_limit = (lmt * MEGABYTES);
	}

	return len;
}

ssize_t vol_dbnotify_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", 
			driver_ctx->tunable_params.db_notify);
}

ssize_t vol_dbnotify_store(const char *file_name, const char *buf, size_t len)
{
	info("Reset Global DB Notify limit to %u", 
			driver_ctx->tunable_params.db_notify);
	driver_ctx->tunable_params.db_notify = 
			driver_ctx->tunable_params.max_data_sz_dm_cn;
	return 0;
}

ssize_t inm_seqno_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%llu\n", 
			(unsigned long long)driver_ctx->last_time_stamp_seqno);
}

ssize_t
inm_seqno_store(const char *file_name, const char *buf, size_t len)
{
	inm_u64_t val = 0;
	unsigned long lock_flag = 0;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi64(buf);
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, lock_flag);
	if (val <= driver_ctx->last_time_stamp_seqno) {
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, lock_flag);
		info("new seqno val %llu is lessthan the current seqno %llu\n",
			 val, driver_ctx->last_time_stamp_seqno);
		return -EINVAL;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, lock_flag);

	sprintf((char *)buf, "%llu", ((inm_u64_t) val));

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, lock_flag);
		driver_ctx->last_time_stamp_seqno = val;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, 
							lock_flag);
	}

	return len;
}

ssize_t
inm_max_data_sz_dm_cn_show(char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%u MB", 
	((inm_u32_t)driver_ctx->tunable_params.max_data_sz_dm_cn)/(MEGABYTES));
}

ssize_t
inm_max_data_sz_dm_cn_store(const char *file_name, const char *buf, size_t len)
{
	inm_u64_t val = 0;
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	target_context_t *vcptr = NULL;

	if(!is_digit(buf, len)) {
		err("Invalid volume threshold percent supplied: has non-digit chars");
		return -EINVAL;
	}

	val = inm_atoi64(buf);
	val *= (MEGABYTES);
	val = max(val, (inm_u64_t)MIN_DATA_SZ_PER_CHANGE_NODE);
	val = min(val, (inm_u64_t)MAX_DATA_SZ_PER_CHANGE_NODE);
	sprintf((char *)buf, "%llu", ((inm_u64_t) val)/(MEGABYTES));

	if (driver_ctx->dc_verifier_on) {
		err("Cannot change data mode change node size with verifier on");
		return -EPERM;
	}

	if(!write_common_attr(file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		driver_ctx->tunable_params.max_data_sz_dm_cn = val;
		driver_ctx->tunable_params.db_notify = 
			driver_ctx->tunable_params.max_data_sz_dm_cn;

		INM_DOWN_READ(&driver_ctx->tgt_list_sem);
		inm_list_for_each_safe(ptr, nextptr, &driver_ctx->tgt_list) {
			vcptr = inm_list_entry(ptr, target_context_t, tc_list);
			if (vcptr->tc_flags & VCF_VOLUME_DELETING)
				continue;

			info("Update DB Notify Threshold from %u to %u", 
				 vcptr->tc_db_notify_thres, 
				 driver_ctx->tunable_params.max_data_sz_dm_cn);
			vcptr->tc_db_notify_thres = 
				driver_ctx->tunable_params.max_data_sz_dm_cn;
		}
		INM_UP_READ(&driver_ctx->tgt_list_sem);
	}

	return len;
}

ssize_t read_pool_size(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	inm_s32_t mem = 0;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read)) {
			err("Not a digit:");
			goto set_default;
		}
		
		mem =  inm_atoi(buf);
		if(mem < DEFAULT_DATA_POOL_SIZE_MB)
			mem = DEFAULT_DATA_POOL_SIZE_MB;

		driver_ctx->tunable_params.data_pool_size = mem;
		info("data pool size set to %dMB", 
				driver_ctx->tunable_params.data_pool_size);
		
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.data_pool_size = 
					driver_ctx->default_data_pool_size_mb;

free_buf:
	if(buf)
	INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t inm_read_vol_respool_sz(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	inm_s32_t mem = 0;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read)) {
			err("Not a digit:");
			goto set_default;
		}
		mem =  inm_atoi(buf);
		if (mem >= 0 && mem <= 
				driver_ctx->default_data_pool_size_mb ) {
			driver_ctx->tunable_params.volume_data_pool_size = mem;
			driver_ctx->dc_vol_data_pool_size = mem <<
			(MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
			goto free_buf;
		}
	}

set_default:
	driver_ctx->tunable_params.volume_data_pool_size =
	DEFAULT_VOLUME_DATA_POOL_SIZE_MB;
	driver_ctx->dc_vol_data_pool_size =
	DEFAULT_VOLUME_DATA_POOL_SIZE_MB << (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);

free_buf:
	if(buf)
	INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}


ssize_t
inm_read_maxdatapool_sz(char *fname)
{
	int bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	unsigned int percentage = 0;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(bytes_read > 2) {
			err("Invalid percentage value. Setting MaxDataPoolSize "
				"based on %d%%", 
				DEFAULT_MAX_DATA_POOL_PERCENTAGE);
			goto set_default;
		}

		if(!is_digit(buf, bytes_read)) {
			err("Not a digit:");
			goto set_default;
		}

		percentage =  inm_atoi(buf);
		driver_ctx->tunable_params.max_data_pool_percent = percentage;
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.max_data_pool_percent =
	DEFAULT_MAX_DATA_POOL_PERCENTAGE;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	return 0;
}


ssize_t read_log_dir(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = INM_PATH_MAX;
	void *buf = NULL;
	unsigned long lock_flag = 0;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(((char *)buf)[bytes_read-1] == '\n')
			bytes_read--;

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
		if (memcpy_s(driver_ctx->tunable_params.data_file_log_dir, 
					INM_PATH_MAX, buf, bytes_read)) {
			INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, 
									lock_flag);
			dbg("memcpy_s failed to copy the datafile log dire path");
			goto set_default;
		}
		driver_ctx->tunable_params.data_file_log_dir[bytes_read] = '\0';
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
		goto free_buf;
	}

set_default:
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	strcpy_s(driver_ctx->tunable_params.data_file_log_dir, INM_PATH_MAX, 
						DEFAULT_VOLUME_DATALOG_DIR );
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_free_thres(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		inm_s32_t sz = 0;
		if(!is_digit(buf, bytes_read))
			goto set_default;

		sz = inm_atoi(buf);
			
		if(sz < 0 || sz > 100)
			goto set_default;

		driver_ctx->tunable_params.free_percent_thres_for_filewrite = sz;
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.free_percent_thres_for_filewrite = 
					DEFAULT_FREE_THRESHOLD_FOR_FILEWRITE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	return 0;
}

ssize_t read_volume_thres(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		inm_s32_t sz = 0;
		if(!is_digit(buf, bytes_read))
			goto set_default;

		sz = inm_atoi(buf);

		if(sz < 0 || sz > 100)
			goto set_default;

		driver_ctx->tunable_params.volume_percent_thres_for_filewrite = sz;
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.volume_percent_thres_for_filewrite =
				DEFAULT_VOLUME_THRESHOLD_FOR_FILEWRITE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	return 0;
}

ssize_t read_dbhwm_sns(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.db_high_water_marks[SERVICE_NOTSTARTED] = 
		inm_atoi(buf);	
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.db_high_water_marks[SERVICE_NOTSTARTED] = 
				DEFAULT_DB_HIGH_WATERMARK_SERVICE_NOT_STARTED;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_dbhwm_sr(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.db_high_water_marks[SERVICE_RUNNING] =
		inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.db_high_water_marks[SERVICE_RUNNING] = 
				DEFAULT_DB_HIGH_WATERMARK_SERVICE_RUNNING;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;

}
ssize_t read_dblwm_sr(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.db_low_water_mark_while_service_running =
		inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.db_low_water_mark_while_service_running = 
				DEFAULT_DB_LOW_WATERMARK_SERVICE_RUNNING;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_dbhwm_ss(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.db_high_water_marks[SERVICE_SHUTDOWN] = 
		inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.db_high_water_marks[SERVICE_SHUTDOWN]= 
				DEFAULT_DB_HIGH_WATERMARK_SERVICE_SHUTDOWN;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_dbp_hwm(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.db_topurge_when_high_water_mark_is_reached =
		inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.db_topurge_when_high_water_mark_is_reached = 
				DEFAULT_DB_TO_PURGE_HIGH_WATERMARK_REACHED;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_max_bmapmem(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->dc_bmap_info.max_bitmap_buffer_memory = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->dc_bmap_info.max_bitmap_buffer_memory = \
		DEFAULT_MAXIMUM_BITMAP_BUFFER_MEMORY;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;


}

ssize_t read_bmap_512ksz(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->dc_bmap_info.bitmap_512K_granularity_size = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->dc_bmap_info.bitmap_512K_granularity_size = \
		DEFAULT_BITMAP_512K_GRANULARITY_SIZE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_vdf(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.enable_data_filtering = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.enable_data_filtering = 1;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_vdf_newvol(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.enable_data_filtering_for_new_volumes = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.enable_data_filtering_for_new_volumes= 1;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_vol_dfm(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.enable_data_file_mode = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.enable_data_file_mode= 0;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_newvol_dfm(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->tunable_params.enable_data_file_mode_for_new_volumes = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.enable_data_file_mode_for_new_volumes= 0;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_dfm_disk_limit(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	inm_s64_t lmt = 0;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		lmt = inm_atoi(buf);
		driver_ctx->tunable_params.data_to_disk_limit = (lmt * MEGABYTES);
	goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.data_to_disk_limit = 
			(DEFAULT_VOLUME_DATA_TO_DISK_LIMIT_IN_MB * MEGABYTES);
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t read_dbnotify(char *fname)
{
	if (driver_ctx->tunable_params.max_data_sz_dm_cn)
		driver_ctx->tunable_params.db_notify = 
			driver_ctx->tunable_params.max_data_sz_dm_cn;
	else
		driver_ctx->tunable_params.db_notify = 
						DEFAULT_DB_NOTIFY_THRESHOLD;
	return 0;
}

ssize_t inm_read_seqno(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		/* On first I/0 after reading the data from file, it should flush */
		driver_ctx->last_time_stamp_seqno = 
					inm_atoi64(buf) + RELOAD_TIME_SEQNO_JUMP_COUNT;
		goto free_buf;
	}

set_default:
	driver_ctx->last_time_stamp_seqno = DEFAULT_SEQNO;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	dbg("starting seq no  = %llu\n", driver_ctx->last_time_stamp_seqno);
	return 0;
}
/* read timstamp from disk */
ssize_t inm_read_ts(void)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;
	char *fname = "GlobalTimeStamp";

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		driver_ctx->last_time_stamp = 
				inm_atoi64(buf) + 2 * HUNDREDS_OF_NANOSEC_IN_SECOND;
		dbg("persitent value for ts = %llu\n", driver_ctx->last_time_stamp);
		goto free_buf;
	}

set_default:
	driver_ctx->last_time_stamp = DEFAULT_TIME_STAMP_VALUE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_read_max_data_sz_dm_cn(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		
		driver_ctx->tunable_params.max_data_sz_dm_cn = 
						inm_atoi64(buf) * (MEGABYTES);
		goto free_buf;
	}

set_default:
	driver_ctx->tunable_params.max_data_sz_dm_cn = 
					DEFAULT_MAX_DATA_SZ_PER_CHANGE_NODE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	driver_ctx->tunable_params.db_notify = 
		driver_ctx->tunable_params.max_data_sz_dm_cn;

	return 0;
}

ssize_t
inm_show_verifier(char *buf)
{    
	return snprintf(buf, INM_PAGESZ, "%u\n", driver_ctx->dc_verifier_on);
}


ssize_t
inm_store_verifier(const char *file_name, const char *buf, size_t len)
{
	inm_u32_t verifier_on = 0;
	inm_u32_t error = 0;
 
	if (!is_digit(buf, len)) {
		err("The supplied value of clean shutdown contains non-digit chars");
		return -EINVAL;
	}
 
	verifier_on = inm_atoi(buf);

	if (verifier_on == driver_ctx->dc_verifier_on)
		goto out;

	if (verifier_on) 
		error = inm_verify_alloc_area(driver_ctx->tunable_params.max_data_sz_dm_cn, 
					                  1);
	else
		inm_verify_free_area();

	if (!error) {
		info("Verification Mode: %d", verifier_on);
		driver_ctx->dc_verifier_on = verifier_on;
	}
	
	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("Verifier update failed to write file:%s.",
			file_name);
		err("Verifier = %d until next boot", verifier_on);
	}

out:
	return len;
}

ssize_t
inm_read_verifier(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	inm_u32_t verifier_on = 0;
	void *buf = NULL;
	inm_s32_t error = 0;

	driver_ctx->dc_verifier_on = 0;

	if(read_common_attr(fname, &buf, buf_len, &bytes_read) &&
		is_digit(buf, bytes_read)) {
 
		verifier_on = inm_atoi(buf);
		if (verifier_on) {
			info("Verification Mode On");
			error = inm_verify_alloc_area(driver_ctx->tunable_params.max_data_sz_dm_cn, 
					                  1);
		}

		if (error) 
			err("Cannot turn on verification mode");
		else
			driver_ctx->dc_verifier_on = verifier_on;
	}
 
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

	return 0;
}
ssize_t
inm_clean_shutdown_show(char *buf)
{    
	return snprintf(buf, INM_PAGESZ, "%u\n", driver_ctx->clean_shutdown);
}


ssize_t
inm_clean_shutdown_store(const char *file_name, const char *buf, size_t len)
{
	inm_u32_t clean_shutdown;
 
	if (!is_digit(buf, len)) {
		err("The supplied value of clean shutdown contains non-digit chars");
		return -EINVAL;
	}
 
	clean_shutdown = inm_atoi(buf);
	driver_ctx->clean_shutdown = clean_shutdown;
 
	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("CleanShutdown update failed to write file:%s.",
						file_name);
		return -EINVAL;
	}
	return len;
}

ssize_t
inm_read_clean_shutdown(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->clean_shutdown = inm_atoi(buf);
		if (driver_ctx->clean_shutdown) {
			info("Clean system shutdown");
		} else {
			info("Unclean system shutdown");
		}

		goto free_buf;
	}
 
set_default:
	driver_ctx->clean_shutdown = CLEAN_SHUTDOWN;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_max_md_coalesce_show(char *buf)
{    
	return snprintf(buf, INM_PAGESZ, "%u (bytes)\n",
		driver_ctx->tunable_params.max_sz_md_coalesce);
}

ssize_t
inm_max_md_coalesce_store(const char *file_name, const char *buf, size_t len)
{
	inm_u32_t max_sz_md_coalesce;
 
	if (!is_digit(buf, len)) {
		err("The supplied value of max coalesce bytes contains non-digit chars");
		return -EINVAL;
	}
 
	max_sz_md_coalesce = inm_atoi(buf);
	driver_ctx->tunable_params.max_sz_md_coalesce = max_sz_md_coalesce;
 
	if (!write_common_attr(file_name, (void *)buf, len)) {
		err("MaxCoalescedMetaDataChangeSize update failed to write file:%s.",
			file_name);
		return -EINVAL;
	}
	return len;
}

ssize_t
inm_max_md_coalesce_read(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.max_sz_md_coalesce = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.max_sz_md_coalesce =
			DEFAULT_MAX_COALESCED_METADATA_CHANGE_SIZE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_time_reorg_data_pool_read(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.time_reorg_data_pool_sec = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.time_reorg_data_pool_sec =
	DEFAULT_REORG_THRSHLD_TIME_SEC;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_time_reorg_data_pool_factor_read(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.time_reorg_data_pool_factor = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.time_reorg_data_pool_factor =
	DEFAULT_REORG_THRSHLD_TIME_FACTOR;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

ssize_t
inm_percent_change_data_pool_size_read(char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_common_attr(fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		driver_ctx->tunable_params.percent_change_data_pool_size = inm_atoi(buf);
		goto free_buf;
	}
 
set_default:
	driver_ctx->tunable_params.percent_change_data_pool_size =
					DEFAULT_PERCENT_CHANGE_DATA_POOL_SIZE;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	return 0;
}

COMMON_ATTR(common_attr_DataPoolSize, "DataPoolSize", INM_S_IRWXUGO, &pool_size_show, &pool_size_store, &read_pool_size);
COMMON_ATTR(common_attr_DefaultLogDirectory, "DefaultLogDirectory", INM_S_IRWXUGO,&log_dir_show, &log_dir_store, &read_log_dir);
COMMON_ATTR(common_attr_FreeThresholdForFileWrite, "FreeThresholdForFileWrite", INM_S_IRWXUGO, &free_thres_show, &free_thres_store, &read_free_thres);
COMMON_ATTR(common_attr_VolumeThresholdForFileWrite, "VolumeThresholdForFileWrite", INM_S_IRWXUGO, &volume_thres_show, &volume_thres_store, &read_volume_thres);
COMMON_ATTR(common_attr_DirtyBlockHighWaterMarkServiceNotStarted, "DirtyBlockHighWaterMarkServiceNotStarted", INM_S_IRWXUGO, &dbhwm_sns_show, &dbhwm_sns_store, &read_dbhwm_sns);
COMMON_ATTR(common_attr_DirtyBlockLowWaterMarkServiceRunning, "DirtyBlockLowWaterMarkServiceRunning", INM_S_IRWXUGO, &dblwm_sr_show, &dblwm_sr_store, &read_dblwm_sr);
COMMON_ATTR(common_attr_DirtyBlockHighWaterMarkServiceRunning, "DirtyBlockHighWaterMarkServiceRunning", INM_S_IRWXUGO, &dbhwm_sr_show, &dbhwm_sr_store, &read_dbhwm_sr);
COMMON_ATTR(common_attr_DirtyBlockHighWaterMarkServiceShutdown, "DirtyBlockHighWaterMarkServiceShutdown", INM_S_IRWXUGO, &dbhwm_ss_show, &dbhwm_ss_store, &read_dbhwm_ss);
COMMON_ATTR(common_attr_DirtyBlocksToPurgeWhenHighWaterMarkIsReached, "DirtyBlocksToPurgeWhenHighWaterMarkIsReached", INM_S_IRWXUGO, &dbp_hwm_show, &dbp_hwm_store, &read_dbp_hwm);
COMMON_ATTR(common_attr_MaximumBitmapBufferMemory, "MaximumBitmapBufferMemory", INM_S_IRWXUGO, &max_bmapmem_show, &max_bmapmem_store, &read_max_bmapmem);
COMMON_ATTR(common_attr_Bitmap512KGranularitySize, "Bitmap512KGranularitySize", INM_S_IRWXUGO, &bmap_512ksz_show, &bmap_512ksz_store, &read_bmap_512ksz);
COMMON_ATTR(common_attr_VolumeDataFiltering, "VolumeDataFiltering", INM_S_IRWXUGO, &vdf_show, &vdf_store, &read_vdf);
COMMON_ATTR(common_attr_VolumeDataFilteringForNewVolumes, "VolumeDataFilteringForNewVolumes", INM_S_IRWXUGO, &vdf_newvol_show, &vdf_newvol_store, &read_vdf_newvol);
COMMON_ATTR(common_attr_VolumeDataFiles, "VolumeDataFiles", INM_S_IRWXUGO, &vol_dfm_show, &vol_dfm_store, &read_vol_dfm);
COMMON_ATTR(common_attr_VolumeDataFilesForNewVolumes, "VolumeDataFilesForNewVolumes", INM_S_IRWXUGO, &newvol_dfm_show, &newvol_dfm_store, &read_newvol_dfm);
COMMON_ATTR(common_attr_VolumeDataToDiskLimitInMB, "VolumeDataToDiskLimitInMB", INM_S_IRWXUGO, &dfm_disk_limit_show, &dfm_disk_limit_store, &read_dfm_disk_limit);
COMMON_ATTR(common_attr_VolumeDataNotifyLimit, "VolumeDataNotifyLimit", INM_S_IRWXUGO, &vol_dbnotify_show, &vol_dbnotify_store, &read_dbnotify);
COMMON_ATTR(common_attr_SequenceNumber, "SequenceNumber", INM_S_IRWXUGO, &inm_seqno_show, inm_seqno_store, &inm_read_seqno);
COMMON_ATTR(common_attr_MaxDataSizeForDataModeDirtyBlock, "MaxDataSizeForDataModeDirtyBlock", INM_S_IRWXUGO, &inm_max_data_sz_dm_cn_show, &inm_max_data_sz_dm_cn_store, &inm_read_max_data_sz_dm_cn);
COMMON_ATTR(common_attr_VolumeResDataPoolSize, "VolumeResDataPoolSize", INM_S_IRWXUGO, &inm_vol_respool_sz_show, &inm_vol_respool_sz_store, &inm_read_vol_respool_sz);
COMMON_ATTR(common_attr_MaxDataPoolSize, "MaxDataPoolSize", INM_S_IRWXUGO, &inm_maxdatapool_sz_show, &inm_maxdatapool_sz_store, &inm_read_maxdatapool_sz);
COMMON_ATTR(common_attr_CleanShutdown, "CleanShutdown", INM_S_IRWXUGO, &inm_clean_shutdown_show, &inm_clean_shutdown_store, &inm_read_clean_shutdown);
COMMON_ATTR(common_attr_MaxCoalescedMetaDataChangeSize, "MaxCoalescedMetaDataChangeSize", INM_S_IRWXUGO, &inm_max_md_coalesce_show, &inm_max_md_coalesce_store, &inm_max_md_coalesce_read);
COMMON_ATTR(common_attr_PercentChangeDataPoolSize, "PercentChangeDataPoolSize", INM_S_IRWXUGO, &inm_percent_change_data_pool_size_show, &inm_percent_change_data_pool_size_store, &inm_percent_change_data_pool_size_read);
COMMON_ATTR(common_attr_TimeReorgDataPoolSec, "TimeReorgDataPoolSec", INM_S_IRWXUGO, &inm_time_reorg_data_pool_show, &inm_time_reorg_data_pool_store, &inm_time_reorg_data_pool_read);
COMMON_ATTR(common_attr_TimeReorgDataPoolFactor, "TimeReorgDataPoolFactor", INM_S_IRWXUGO, &inm_time_reorg_data_pool_factor_show, &inm_time_reorg_data_pool_factor_store, &inm_time_reorg_data_pool_factor_read);
COMMON_ATTR(common_attr_VacpIObarrierTimeout, "VacpIObarrierTimeout", INM_S_IRWXUGO, &inm_vacp_iobarrier_timeout_show, &inm_vacp_iobarrier_timeout_store, &inm_vacp_iobarrier_timeout_read);
COMMON_ATTR(common_attr_FsFreezeTimeout, "FsFreezeTimeout", INM_S_IRWXUGO, &inm_fs_freeze_timeout_show, &inm_fs_freeze_timeout_store, &inm_fs_freeze_timeout_read);
COMMON_ATTR(common_attr_VacpAppTagCommitTimeout, "VacpAppTagCommitTimeout", INM_S_IRWXUGO, &inm_vacp_app_tag_commit_timeout_show, &inm_vacp_app_tag_commit_timeout_store, &inm_vacp_app_tag_commit_timeout_read);
COMMON_ATTR(common_attr_TrackRecursiveWrites, "TrackRecursiveWrites", INM_S_IRWXUGO, &inm_recio_show, &inm_recio_store, &inm_recio_read);
COMMON_ATTR(common_attr_StablePages, "StablePages", INM_S_IRWXUGO, &inm_stable_pages_show, &inm_stable_pages_store, &inm_stable_pages_read);
COMMON_ATTR(common_attr_Verifier, "Verifier", INM_S_IRWXUGO, &inm_show_verifier, &inm_store_verifier, &inm_read_verifier);
COMMON_ATTR(common_attr_ChainedIO, "ChainedIO", INM_S_IRWXUGO, &inm_chained_io_show, &inm_chained_io_store, &inm_chained_io_read);


static struct attribute *sysfs_common_attrs[] = {
	&common_attr_DataPoolSize.attr,
	&common_attr_DefaultLogDirectory.attr,
	&common_attr_FreeThresholdForFileWrite.attr,
	&common_attr_VolumeThresholdForFileWrite.attr,
	&common_attr_DirtyBlockHighWaterMarkServiceNotStarted.attr,
	&common_attr_DirtyBlockLowWaterMarkServiceRunning.attr,
	&common_attr_DirtyBlockHighWaterMarkServiceRunning.attr,
	&common_attr_DirtyBlockHighWaterMarkServiceShutdown.attr,
	&common_attr_DirtyBlocksToPurgeWhenHighWaterMarkIsReached.attr,
	&common_attr_MaximumBitmapBufferMemory.attr,
	&common_attr_Bitmap512KGranularitySize.attr,
	&common_attr_VolumeDataFiltering.attr,
	&common_attr_VolumeDataFilteringForNewVolumes.attr,
	&common_attr_VolumeDataFiles.attr,
	&common_attr_VolumeDataFilesForNewVolumes.attr,
	&common_attr_VolumeDataToDiskLimitInMB.attr,
	&common_attr_VolumeDataNotifyLimit.attr,
	&common_attr_SequenceNumber.attr,
	&common_attr_MaxDataSizeForDataModeDirtyBlock.attr,
	&common_attr_VolumeResDataPoolSize.attr,
	&common_attr_MaxDataPoolSize.attr,
	&common_attr_CleanShutdown.attr,
	&common_attr_MaxCoalescedMetaDataChangeSize.attr,
	&common_attr_PercentChangeDataPoolSize.attr,
	&common_attr_TimeReorgDataPoolSec.attr,
	&common_attr_TimeReorgDataPoolFactor.attr,
	&common_attr_VacpIObarrierTimeout.attr,
	&common_attr_FsFreezeTimeout.attr,
	&common_attr_VacpAppTagCommitTimeout.attr,
	&common_attr_TrackRecursiveWrites.attr,
	&common_attr_StablePages.attr,
	&common_attr_Verifier.attr,
	&common_attr_ChainedIO.attr,
	NULL,
};

void load_driver_params(void)
{
	inm_s32_t num_attribs, temp;

	num_attribs = (sizeof(sysfs_common_attrs)/sizeof(struct atttribute *));
	num_attribs--;

	temp = 0;

	while(temp < num_attribs) {
	struct common_attribute *common_attr;
	struct attribute *attr = sysfs_common_attrs[temp];

	common_attr = inm_container_of(attr, struct common_attribute, attr);

	if (common_attr->read)
		common_attr->read(common_attr->file_name);
	temp++;
	}
	inm_read_ts();
}

inm_s32_t sysfs_involflt_init(void)
{
	char *path = NULL;

	if(!get_path_memory(&path)) {
		err("Failed to get memory while creating persistent directory");
		return 1;
	}

	/* Create /etc/vxagent */
	strcpy_s(path, INM_PATH_MAX, "/etc/vxagent");
	inm_mkdir(path, 0755);

	/* Create persistent dir, /etc/vxagent/involflt */	
	strcpy_s(path, INM_PATH_MAX, PERSISTENT_DIR);
	inm_mkdir(path, 0755);

	/* Create /etc/vxagent/involflt/common */
	snprintf(path, INM_PATH_MAX, "%s/%s", PERSISTENT_DIR, COMMON_ATTR_NAME);
	inm_mkdir(path, 0755);

	free_path_memory(&path);

	driver_ctx->dc_tel.dt_persistent_dir_created = 1;

	return 0;
}

inm_s32_t
common_get_set_attribute_entry(struct _inm_attribute *attr)
{
	inm_s32_t ret = 0;
	char	*lbufp = NULL;
	inm_u32_t lbuflen = 0;

	lbuflen = INM_MAX(attr->buflen, INM_PAGESZ);
	lbufp = (char *) INM_KMALLOC(lbuflen, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!lbufp){
		err("buffer allocation get_set ioctl failed\n");
		ret = INM_ENOMEM;
		goto out;
	}
	INM_MEM_ZERO(lbufp, lbuflen);

	if (INM_COPYIN(lbufp, attr->bufp, attr->buflen)) {
		err("copyin failed\n");
		ret = INM_EFAULT;
		goto out;
	}
	
	if(attr->why == SET_ATTR){
		ret = common_attr_store(sysfs_common_attrs[attr->type], lbufp, attr->buflen);
		if (ret < 0){
			err("attributre store failed");
			ret = -ret;
			goto out;
		}
	} else {
		ret = common_attr_show(sysfs_common_attrs[attr->type], lbufp);
		if (ret == 0){
			dbg("its unlikely but get attribute read 0 bytes only");
		} else if (ret > 0){
			if (INM_COPYOUT(attr->bufp, lbufp, ret+1)) {
				err("copyout failed\n");
				ret = INM_EFAULT;
				goto out;
			}
		} else {
			err("get attribute failed");
			ret = -ret;
			goto out;
		}
	}
	ret = 0;
out:
	if (lbufp) {
		INM_KFREE(lbufp, lbuflen, INM_KERNEL_HEAP); 
	}       
	return ret;
}


/*
 * ==============================================VOLUME ATTRIBUTES==============================================
 */

inm_s32_t read_vol_attr(target_context_t *ctxt, char *fname, void **buf, 
					    inm_s32_t len, inm_s32_t *bytes_read)
{
	inm_s32_t ret = 0;
	char *path = NULL;

	if(!get_path_memory(&path)) {
	err("Failed to allocated memory path");
	return ret;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s/%s", PERSISTENT_DIR, 
			 ctxt->tc_pname, fname);

	dbg("Reading from file %s", path);

	*buf = (void *)INM_KMALLOC(len, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!*buf)
		goto free_buf;

	dbg("Allocated buffer of len %d", len);
	INM_MEM_ZERO(*buf, len);

	if(!read_full_file(path, *buf, len, (inm_u32_t *)bytes_read)) {
		ret = 0;
		goto free_buf;
	}

	ret = 1;
	goto free_path_buf;

free_buf:
	if(*buf)
		INM_KFREE(*buf, len, INM_KERNEL_HEAP);
	*buf = NULL;

free_path_buf:
	if(path)
		free_path_memory(&path);
	
	path = NULL;

	return ret;
}

inm_s32_t vol_flt_disabled_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", (is_target_filtering_disabled(ctxt)? 1 : 0));
}

inm_s32_t vol_flt_disabled_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume filtering disabled = %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeFilteringDisabled");
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		volume_lock(ctxt);
		info("Setting filtering disabled flag : %d, process id = %d, process name = %s",
			val, INM_CURPROC_PID, INM_CURPROC_COMM);
		if(val)
			ctxt->tc_flags |= VCF_FILTERING_STOPPED;
		else
			ctxt->tc_flags &= ~VCF_FILTERING_STOPPED;
		volume_unlock(ctxt);
	}

	return len;
}

inm_s32_t vol_bmapread_disabled_show(target_context_t *temp, char *buf)
{
	return 1;
}

inm_s32_t vol_bmapread_disabled_store(target_context_t *temp, char *file_name, const char *buf, inm_s32_t len)
{
	return 0;
}

inm_s32_t vol_bmapwrite_disabled_show(target_context_t *temp, char *buf)
{
	return 1;
}

inm_s32_t vol_bmapwrite_disabled_store(target_context_t *temp, char *file_name, const char *buf, inm_s32_t len)
{
	return 1;
}

inm_s32_t vol_data_flt_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", ((ctxt->tc_flags & VCF_DATA_MODE_DISABLED)? 0 : 1));
}

inm_s32_t vol_data_flt_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume data filtering %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeDataFiltering");
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		volume_lock(ctxt);

		if(val) {
			ctxt->tc_flags &= ~VCF_DATA_MODE_DISABLED;
		} else {
			if(ctxt->tc_cur_mode == FLT_MODE_DATA)
				set_tgt_ctxt_filtering_mode(ctxt, FLT_MODE_METADATA, FALSE);

			if(ctxt->tc_cur_wostate == ecWriteOrderStateData) 
				set_tgt_ctxt_wostate(ctxt, ecWriteOrderStateMetadata, FALSE,
							ecWOSChangeReasonExplicitNonWO);

			ctxt->tc_flags |= VCF_DATA_MODE_DISABLED;
		}
		volume_unlock(ctxt);
	}

	return len;
}

inm_s32_t vol_data_files_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d\n", ((ctxt->tc_flags & VCF_DATA_FILES_DISABLED)? 0 : 1));
}

inm_s32_t vol_data_files_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume data files %s has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeDataFiles");
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		if(val)
			ctxt->tc_flags &= ~VCF_DATA_FILES_DISABLED;
		else
			ctxt->tc_flags |= VCF_DATA_FILES_DISABLED;
	}

	return len;
}

inm_s32_t vol_data_to_disk_limit_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%lld MB", (long long)(ctxt->tc_data_to_disk_limit/MEGABYTES)); 
}

inm_s32_t vol_data_to_disk_limit_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	inm_s64_t lmt = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume data to disk limit %s : has non-digit chars", buf);
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		lmt = inm_atoi(buf);
		ctxt->tc_data_to_disk_limit = (lmt * MEGABYTES);
	}

	return len;
}

inm_s32_t vol_data_notify_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d", (ctxt->tc_db_notify_thres)); 
}

inm_s32_t vol_data_notify_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	info("%s: Reset DB Notify limit to %u", ctxt->tc_guid, 
			driver_ctx->tunable_params.db_notify);
	ctxt->tc_db_notify_thres = driver_ctx->tunable_params.db_notify;
	return 0;
}

inm_s32_t vol_log_dir_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%s", ctxt->tc_data_log_dir);
}

inm_s32_t vol_log_dir_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	unsigned long lock_flag = 0;

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		INM_SPIN_LOCK_IRQSAVE(&ctxt->tc_tunables_lock, lock_flag);
		if (strncpy_s(ctxt->tc_data_log_dir, len + 1, buf, len)) {
			INM_SPIN_UNLOCK_IRQRESTORE(&ctxt->tc_tunables_lock, lock_flag);
			return -INM_EFAULT;
		}

		ctxt->tc_data_log_dir[len] = '\0';
		ctxt->tc_flags &= ~VCF_DATAFILE_DIR_CREATED;
		INM_SPIN_UNLOCK_IRQRESTORE(&ctxt->tc_tunables_lock, lock_flag);
	}

	return len;
}

inm_s32_t vol_bmap_gran_show(target_context_t *ctxt, char *buf)
{
	return 1;
}

inm_s32_t vol_bmap_gran_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	return 1;
}

inm_s32_t vol_resync_req_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d", ctxt->tc_resync_required);
}

inm_s32_t vol_resync_req_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	inm_s32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume resync required %s: has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeResyncRequired");
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_resync_required = val;
	}

	return len;
}

inm_s32_t vol_osync_errcode_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%ld", ctxt->tc_out_of_sync_err_code);
}

inm_s32_t vol_osync_errcode_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	if(!is_digit(buf, len)) {
		err("Invalid value for volume out of sync err code: %s (expecting decimal value)", buf);
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_out_of_sync_err_code = inm_atoi(buf);
	}

	return len;
}

inm_s32_t vol_osync_status_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%ld", ctxt->tc_out_of_sync_err_status);
}

inm_s32_t vol_osync_status_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	if(!is_digit(buf, len)) {
		err("Invalid value for volume out of sync err status %s\n", buf);
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_out_of_sync_err_status = inm_atoi(buf);
	}

	return len;
}

inm_s32_t vol_osync_count_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%ld", ctxt->tc_nr_out_of_sync);
}

inm_s32_t vol_osync_count_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	if(!is_digit(buf, len)) {
		err("Invalid value for out of sync count %s: has non-digit chars", buf);
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_nr_out_of_sync = inm_atoi(buf);
	}

	return len;
}

inm_s32_t vol_osync_ts_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%lld", (long long)ctxt->tc_out_of_sync_time_stamp);
}

inm_s32_t vol_osync_ts_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	if(!is_digit(buf, len)) {
		err("Invalid time stamp value %s: has non-digit chars", buf);
		return -EINVAL;
	}

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_out_of_sync_time_stamp = inm_atoi64(buf);
	}

	return len;
}
inm_s32_t vol_osync_desc_show(target_context_t *ctxt, char *buf)
{
	if (ctxt->tc_out_of_sync_err_code < 5) {
		return snprintf(buf, INM_PAGESZ, "%s\n",
					    ErrorToRegErrorDescriptionsA[ctxt->tc_out_of_sync_err_code]);
	} else {
		return snprintf(buf, INM_PAGESZ,
					    "See system log (/var/log/messages for error description\n");
	}
}

inm_s32_t vol_osync_desc_store(target_context_t *ctxt, char *file_name, const char *buf, inm_s32_t len)
{
	return 0;
}

inm_s32_t
inm_vol_reserv_show(target_context_t *ctxt, char *buf)
{
	inm_u32_t mb = 0;

	mb = ctxt->tc_reserved_pages >> (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);
	return snprintf(buf, INM_PAGESZ, "%u MB\n", mb);
}

inm_s32_t
inm_vol_reserv_store(target_context_t *ctxt, char *file_name,
				 const char *buf, inm_s32_t len)
{
	inm_u32_t thres = 0, num_pages = 0, diff_pages;
	inm_u32_t add_pages = 0;
	inm_u32_t num_pages_available = 0;

	/* Not supported */
	return -EINVAL;

	if (ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
		err("Tunable is invalid for mirror setup");
		return -EINVAL;
	}
	if (!is_digit(buf, len)) {
		err("Invalid value VolumeResDataPoolSize:%s has non-digit chars", buf);
		return -EINVAL;
	}
	thres = inm_atoi(buf);
	num_pages = thres << (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);

	if (!num_pages) {
		err("Invalid value VolumeResDataPoolSize:%s cannot be zero", buf);
		return -EINVAL;
	}

	volume_lock(ctxt);
	if (num_pages > ctxt->tc_reserved_pages) {
		add_pages = 1;
		diff_pages = num_pages - ctxt->tc_reserved_pages;
	}
	else {
		add_pages = 0;
		diff_pages = ctxt->tc_reserved_pages - num_pages;
	}
	volume_unlock(ctxt);

	if (!diff_pages) {
		return len;
	}
	if (add_pages) {
		if (inm_tc_resv_add(ctxt, diff_pages)) {
			num_pages_available = driver_ctx->dc_cur_unres_pages;
			err("VolumeResDataPoolSize is not within limits. Available:%uMB",
				(num_pages_available >> (MEGABYTE_BIT_SHIFT-INM_PAGESHIFT)));
			return -EINVAL;
		}
	}
	else {
		if (inm_tc_resv_del(ctxt, diff_pages)) {
			num_pages_available = driver_ctx->dc_cur_unres_pages;
			err("VolumeResDataPoolSize is not within limits. Available:%uMB",
				(num_pages_available >> (MEGABYTE_BIT_SHIFT-INM_PAGESHIFT)));
			return -EINVAL;
		}
	}
	recalc_data_file_mode_thres();

	if (!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		err("VolumeResDataPoolSize update failed to write file:%s.",
									file_name);
		return -EINVAL;
	}
	return len;
}

void read_vol_flt_disabled(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		inm_s32_t disabled;
		if(!is_digit(buf, bytes_read))
			goto set_default;
		disabled = inm_atoi(buf);
			
		if(disabled != 0 && disabled != 1)
			goto set_default;

		if(disabled != 0) {
			ctxt->tc_flags |= VCF_FILTERING_STOPPED;
		} else {		
			ctxt->tc_flags &= ~VCF_FILTERING_STOPPED;
		}

		goto free_buf;
	}

set_default:
	if (ctxt->tc_flags & VCF_VOLUME_STACKED_PARTIALLY)
		ctxt->tc_flags &= ~VCF_FILTERING_STOPPED;
	else
		ctxt->tc_flags |= VCF_FILTERING_STOPPED;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_bmapread_disabled(target_context_t *ctxt, char * fname)
{
	return;
}

void read_bmapwrite_disabled(target_context_t *ctxt, char * fname)
{
	return;
}

void read_data_flt_enabled(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	char tempbuf[2];

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		inm_s32_t enabled;
		if(!is_digit(buf, bytes_read))
			goto set_default;
		enabled = inm_atoi(buf);

		if(enabled != 0 && enabled != 1)
			goto set_default;

		if(enabled)
			ctxt->tc_flags &= ~VCF_DATA_MODE_DISABLED;
		else
			ctxt->tc_flags |= VCF_DATA_MODE_DISABLED;

		goto free_buf;
	}

set_default:
	if(driver_ctx->tunable_params.enable_data_filtering_for_new_volumes)
		tempbuf[0] = '1';
	else
		tempbuf[0] = '0';

	tempbuf[1] = '\0';

	vol_data_flt_store(ctxt,fname, tempbuf, strlen(tempbuf));

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_data_files_enabled(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	char tempbuf[2];

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		inm_s32_t enabled;
		if(!is_digit(buf, bytes_read))
			goto set_default;
		enabled = inm_atoi(buf);

		if(enabled != 0 && enabled != 1)
			goto set_default;

		if(enabled)
			ctxt->tc_flags &= ~VCF_DATA_FILES_DISABLED;
		else
			ctxt->tc_flags |= VCF_DATA_FILES_DISABLED;

		goto free_buf;
	}

set_default:
	if(driver_ctx->tunable_params.enable_data_file_mode_for_new_volumes)
		tempbuf[0] = '1';
	else
		tempbuf[0] = '0';

	tempbuf[1] = '\0';

	vol_data_files_store(ctxt,fname, tempbuf, strlen(tempbuf));

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_data_to_disk_limit(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	inm_s64_t lmt = 0;
	char tempbuf[NUM_CHARS_IN_INTEGER + 1];

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
		lmt = inm_atoi(buf);
		ctxt->tc_data_to_disk_limit = (lmt * MEGABYTES);
		goto free_buf;
	}

set_default:
	snprintf(tempbuf, NUM_CHARS_IN_INTEGER, "%d", (int)(driver_ctx->tunable_params.data_to_disk_limit/MEGABYTES));
	vol_data_to_disk_limit_store(ctxt, fname, tempbuf, strlen(tempbuf));

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_data_notify_limit(target_context_t *ctxt, char * fname)
{
	ctxt->tc_db_notify_thres = driver_ctx->tunable_params.db_notify;
}

void read_data_log_dir(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = INM_PATH_MAX;
	void *buf = NULL;
	unsigned long lock_flag, lock_flag1 = 0;
	char *path_buf = NULL;

	if(!read_vol_attr(ctxt,fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(((char *)buf)[bytes_read-1] == '\n')
			bytes_read--;

		INM_SPIN_LOCK_IRQSAVE(&ctxt->tc_tunables_lock, lock_flag1);
		if (memcpy_s(ctxt->tc_data_log_dir, INM_PATH_MAX, buf, bytes_read)) {
			INM_SPIN_UNLOCK_IRQRESTORE(&ctxt->tc_tunables_lock, lock_flag1);
			dbg("memcpy_s failed to copy the datafile log dire path");
			goto set_default;
		}

		ctxt->tc_data_log_dir[bytes_read] = '\0';
		INM_SPIN_UNLOCK_IRQRESTORE(&ctxt->tc_tunables_lock, lock_flag1);
		goto free_buf;
	}

set_default:
	
	get_path_memory(&path_buf);

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	if(path_buf)
		strcpy_s(path_buf, INM_PATH_MAX, driver_ctx->tunable_params.data_file_log_dir);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);

	if(path_buf) {
		vol_log_dir_store(ctxt, fname, path_buf, strlen(path_buf));
		free_path_memory(&path_buf);
	}

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_bmap_gran(target_context_t *ctxt, char * fname)
{
	return;
}

void read_resync_req(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		ctxt->tc_resync_required = inm_atoi(buf);	
		goto free_buf;
	}

set_default:
	ctxt->tc_resync_required = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_osync_errcode(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		ctxt->tc_out_of_sync_err_code = inm_atoi(buf);
		ctxt->tc_hist.ths_osync_err = ctxt->tc_out_of_sync_err_code;
		goto free_buf;
	}

set_default:
	ctxt->tc_out_of_sync_err_code = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_osync_status(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		ctxt->tc_out_of_sync_err_status = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	ctxt->tc_out_of_sync_err_status = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_osync_count(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		ctxt->tc_nr_out_of_sync = inm_atoi(buf);
		ctxt->tc_hist.ths_nr_osyncs = ctxt->tc_nr_out_of_sync;
		goto free_buf;
	}

set_default:
	ctxt->tc_nr_out_of_sync = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

}

void read_osync_ts(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		ctxt->tc_out_of_sync_time_stamp= inm_atoi64(buf);
		ctxt->tc_hist.ths_osync_ts = ctxt->tc_out_of_sync_time_stamp;
		goto free_buf;
	}

set_default:
	ctxt->tc_out_of_sync_time_stamp = 0;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

}

void read_osync_desc(target_context_t *ctxt, char *fname)
{
	return;
}

void
inm_read_reserv_dpsize(target_context_t *ctxt, char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	inm_u32_t thres = 0;
	void *buf = NULL;

	if (ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
		return;
	}
	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read)) {
			goto set_default;
		}

		thres = inm_atoi(buf);
		if ((thres >= 0) && 
			(thres <= driver_ctx->tunable_params.data_pool_size)) {
			ctxt->tc_reserved_pages = thres << 
				(MEGABYTE_BIT_SHIFT-INM_PAGESHIFT);
		}
		else  {
			goto set_default;	
		}
		goto free_buf;
	}

set_default:
		ctxt->tc_reserved_pages = driver_ctx->dc_vol_data_pool_size;

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t filter_dev_type_show(target_context_t *ctxt, char *buf)
{
	switch(ctxt->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
		return snprintf(buf, INM_PAGESZ, "Host-Volume");
		break;

	case FILTER_DEV_FABRIC_LUN:
		return snprintf(buf, INM_PAGESZ, "Fabric-Lun");
		break;

	case FILTER_DEV_MIRROR_SETUP:
		return snprintf(buf, INM_PAGESZ, "Host-Mirror-Setup");
		break;

	default:
		break;
	}
	return 0;
}

void read_filter_dev_type(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
	} else {
		ctxt->tc_dev_type = 9999; /* invalid type */
		if(is_digit(buf, bytes_read))
			ctxt->tc_dev_type = (inm_device_t) inm_atoi(buf);
	}
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

void read_filter_dev_nblks(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
	} else {
		inm_u64_t val;

		if(!is_digit(buf, bytes_read))
			goto set_default;

		val = inm_atoi64(buf);
		switch(ctxt->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
		case FILTER_DEV_MIRROR_SETUP:
			((host_dev_ctx_t *)ctxt->tc_priv)->hdc_nblocks = val;
			break;

		case FILTER_DEV_FABRIC_LUN:
			((target_volume_ctx_t *) (ctxt->tc_priv))->nblocks = val;
			break;

		default:
			break;
		}

		goto free_buf;
	}
set_default:
	switch(ctxt->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
		((host_dev_ctx_t *)ctxt->tc_priv)->hdc_nblocks = 0;
		break;
	default:
		break;
	}

free_buf:
	if(buf)
	INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t
filter_dev_nblks_show(target_context_t *ctxt, char *buf)
{
	switch(ctxt->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
		return snprintf(buf, INM_PAGESZ, "%lld",
			      (long long)((ctxt->tc_priv != NULL) ?
			           ((host_dev_ctx_t *)ctxt->tc_priv)->hdc_nblocks : -1));
		break;

	case FILTER_DEV_FABRIC_LUN:
		return sprintf(buf, "%lld",
			   (long long)((ctxt->tc_priv != NULL) ?
				((target_volume_ctx_t*)ctxt->tc_priv)->nblocks : -1));
		break;

	default:
		break;
	}
	return 0;
}

inm_s32_t filter_dev_nblks_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	inm_u64_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume number of blocks = %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi64(buf);
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		switch(ctxt->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
		case FILTER_DEV_MIRROR_SETUP:
			((host_dev_ctx_t *)ctxt->tc_priv)->hdc_nblocks = val;
			break;
		default:
			break;
		}
	}

	return len;
}

void read_filter_dev_bsize(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
	} else {
		inm_u32_t val;

		if(!is_digit(buf, bytes_read))
			goto set_default;

		val = inm_atoi(buf);
		switch(ctxt->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
		case FILTER_DEV_MIRROR_SETUP:
			((host_dev_ctx_t *)ctxt->tc_priv)->hdc_bsize = val;
			break;

		case FILTER_DEV_FABRIC_LUN:
			((target_volume_ctx_t *) (ctxt->tc_priv))->bsize = val;
			break;

		default:
			break;
		}

		goto free_buf;
	}

set_default:
	switch(ctxt->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
		((host_dev_ctx_t *)ctxt->tc_priv)->hdc_bsize = 0;
		break;

	default:
		break;
	}

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t filter_dev_bsize_show(target_context_t *ctxt, char *buf)
{
	switch(ctxt->tc_dev_type) {
	case FILTER_DEV_HOST_VOLUME:
	case FILTER_DEV_MIRROR_SETUP:
		return snprintf(buf, INM_PAGESZ, "%d",
				((ctxt->tc_priv != NULL) ?
			        ((host_dev_ctx_t *)ctxt->tc_priv)->hdc_bsize : -1));
		break;

	case FILTER_DEV_FABRIC_LUN:
		return sprintf(buf, "%d",
				((ctxt->tc_priv != NULL) ?
				((target_volume_ctx_t*)ctxt->tc_priv)->bsize : -1));
		break;

	default:
		break;
	}
	return 0;
}

inm_s32_t
inm_vol_pt_path_show(target_context_t *ctxt, char *buf)
{
	inm_u32_t len = 0;
	target_volume_ctx_t *tvcptr = NULL;

	if (ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		dbg("Volume tunable only for fabric setup");
		return 0;
	}
	if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
		tvcptr = (target_volume_ctx_t*) (ctxt->tc_priv);
		if (tvcptr) {
			len =  snprintf(buf, INM_PAGESZ, "%s\n", tvcptr->pt_guid);
				err("In inm_vol_pt_path_show GUID %s", tvcptr->pt_guid);
		}
	}
	else {
		len =  snprintf(buf, INM_PAGESZ, "Operation is not supported on %s\n",
					    ctxt->tc_guid);
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving inm_vol_pt_path_show :%s", buf);
	}
	return len;
}

inm_s32_t
inm_vol_pt_path_store(target_context_t *ctxt, char *file_name,
				 const char *buf, inm_s32_t len)
{
	target_volume_ctx_t *tvcptr = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("Entering inm_vol_pt_path_store :%s", buf);
	}
	if (ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		dbg("Volume tunable only for fabric setup");
		return 0;
	}
	if (len > INM_GUID_LEN_MAX) {
		err("%s PT path is too long or bad", buf);
		return -EINVAL;
	}
	if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
		tvcptr = (target_volume_ctx_t*) (ctxt->tc_priv);
		if (tvcptr) {
			INM_MEM_ZERO(tvcptr->pt_guid, INM_GUID_LEN_MAX);
			if (strncpy_s(tvcptr->pt_guid, INM_GUID_LEN_MAX, buf, len))
				return -INM_EFAULT;

			tvcptr->pt_guid[len] = '\0';
			err("In  inm_vol_pt_path_store GUID :%s:", tvcptr->pt_guid);
		}
		if (!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
			err("VolumePTPath update failed to write file:%s.",
				file_name);
			return -EINVAL;
		}
	}
	else {
		err("Operation is not supported on %s\n", ctxt->tc_guid);
	}
	return len;
}

void
inm_read_pt_path(target_context_t *ctxt, char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (INM_GUID_LEN_MAX);
	void *buf = NULL;
	inm_u32_t len = 0;
	target_volume_ctx_t *tvcptr = NULL;

	if (ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		dbg("Volume tunable only for fabric setup");
		return;
	}
	if (!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		len = strlen(buf);
		if (len > INM_GUID_LEN_MAX) {
			err("%s PT path is too long or bad", (char *)buf);
			goto free_buf;
		}
		if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
			tvcptr = (target_volume_ctx_t*) (ctxt->tc_priv);
			if (tvcptr) {
				memcpy_s(tvcptr->pt_guid, INM_GUID_LEN_MAX, buf, len);
			}
		}
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("Leaving inm_read_pt_path :%s", (char *)buf);
	}
set_default:

free_buf:
	if (buf) {
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	}
}


inm_s32_t
inm_vol_at_direct_rd_show(target_context_t *ctxt, char *buf)
{
	inm_u32_t len = 0;
	target_volume_ctx_t *tvcptr = NULL;

	if (ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		err("Volume tunable only for fabric setup");
		return 0;
	}
	if (ctxt->tc_dev_type == FILTER_DEV_FABRIC_LUN) {
		tvcptr = (target_volume_ctx_t*) (ctxt->tc_priv);
		if (tvcptr) {
			len =  snprintf(buf, INM_PAGESZ, "%d\n",
				 tvcptr->flags & TARGET_VOLUME_DIRECT_IO);
		}
	}
	else {
		len =  snprintf(buf, INM_PAGESZ, "Operation is not supported on %s\n",
					    ctxt->tc_guid);
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving inm_vol_at_direct_rd_show :%s", buf);
	}
	return len;
}

inm_s32_t
inm_vol_at_direct_rd_store(target_context_t *ctxt, char *file_name,
				 const char *buf, inm_s32_t len)
{
	inm_s32_t val = 0;
	target_volume_ctx_t *tvcptr = NULL;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entering inm_vol_at_direct_rd_store :%s", buf);
	}

	if (ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		dbg("Volume tunable only for fabric setup");
		return 0;
	}

	if(!is_digit(buf, len)) {
		err("Invalid value for volume data filtering %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if ((val != 0) && (val != 1)) {
		err("Cant have anything other than 0 and 1 for VolumeATDirectRead");
		return -EINVAL;
	}

	if (!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		volume_lock(ctxt);
		tvcptr = (target_volume_ctx_t*) (ctxt->tc_priv);
		if (tvcptr) {
			if (val) {
				tvcptr->flags |= TARGET_VOLUME_DIRECT_IO;
			} else {
				tvcptr->flags &= ~TARGET_VOLUME_DIRECT_IO;
			}
		}
		volume_unlock(ctxt);
	}

	return len;
}

void
inm_read_at_direct_rd(target_context_t *ctxt, char *fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	target_volume_ctx_t *tvcptr = (target_volume_ctx_t*) (ctxt->tc_priv);

	if (ctxt->tc_dev_type != FILTER_DEV_FABRIC_LUN) {
		dbg("Volume tunable only for fabric setup");
		return;
	}

	if (!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		inm_s32_t enabled;
		if (!is_digit(buf, bytes_read))
			goto set_default;

		enabled = inm_atoi(buf);
		if (tvcptr) {
			if(enabled != 0 && enabled != 1)
				goto set_default;
			if (enabled)
				tvcptr->flags |= TARGET_VOLUME_DIRECT_IO;
			else
				tvcptr->flags &= ~TARGET_VOLUME_DIRECT_IO;
		}
		goto free_buf;
	}

set_default:
	if (tvcptr) {
		tvcptr->flags |= TARGET_VOLUME_DIRECT_IO;
	}

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);

}

inm_s32_t filter_dev_bsize_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	inm_u32_t val = 0;

	if(!is_digit(buf, len)) {
		err("Invalid value for volume block size = %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		switch(ctxt->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
		case FILTER_DEV_MIRROR_SETUP:
			((host_dev_ctx_t *)ctxt->tc_priv)->hdc_bsize = val;
			break;

		default:
			break;
		}
	}

	return len;
}

inm_s32_t
vol_mount_point_show(target_context_t *ctxt, char *buf)
{
	if (ctxt->tc_dev_type != FILTER_DEV_HOST_VOLUME)
		return 0;

	return snprintf(buf, INM_PAGESZ, "%s", ctxt->tc_mnt_pt);
}

inm_s32_t
vol_mount_point_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	if (ctxt->tc_dev_type != FILTER_DEV_HOST_VOLUME)
		return len;

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		switch(ctxt->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
			volume_lock(ctxt);
			if (strncpy_s(ctxt->tc_mnt_pt, len + 1, buf, len)) {
				volume_unlock(ctxt);
				return -INM_EFAULT;
			}
			ctxt->tc_mnt_pt[len] = '\0';
			volume_unlock(ctxt);
			break;

		default:
			break;
		}
	}

	return len;
}

void
read_vol_mount_point(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = INM_PATH_MAX;
	void *buf = NULL;

	if (ctxt->tc_dev_type != FILTER_DEV_HOST_VOLUME)
		goto set_default;

	if(!read_vol_attr(ctxt,fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if(((char *)buf)[bytes_read-1] == '\n')
			bytes_read--;

		volume_lock(ctxt);
		if (memcpy_s(ctxt->tc_mnt_pt, INM_PATH_MAX, buf, bytes_read)) {
			volume_unlock(ctxt);
			goto set_default;
		}

		ctxt->tc_mnt_pt[bytes_read] = '\0';
		volume_unlock(ctxt);
		goto free_buf;
	}

set_default:
	ctxt->tc_mnt_pt[0] = '\0';

free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t
vol_prev_end_timestamp_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%llu", (unsigned long long)ctxt->tc_PrevEndTimeStamp);
}

inm_s32_t
vol_prev_end_timestamp_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	 inm_u64_t val;

	 if(!is_digit(buf, len)) {
		 err("Invalid value for volume previous end timestamps = %s : has non-digit chars", buf);
		 return -EINVAL;
	 }

	val = inm_atoi64(buf);

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_PrevEndTimeStamp = val;
	}
 
	return len;
}

void
read_vol_prev_end_timestamp(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;

		ctxt->tc_PrevEndTimeStamp = inm_atoi64(buf);
		goto free_buf;
	}

set_default:
	ctxt->tc_PrevEndTimeStamp = 0;
free_buf:
	if(driver_ctx->unclean_shutdown){
		err("The system is not cleanly shutdowned");
		set_volume_out_of_sync(ctxt, ERROR_TO_REG_UNCLEAN_SYS_SHUTDOWN, 0);
		ctxt->tc_PrevEndTimeStamp = -1ULL;
	}

	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t
vol_prev_end_sequence_number_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%llu", (unsigned long long)ctxt->tc_PrevEndSequenceNumber);
}
 
inm_s32_t
vol_prev_end_sequence_number_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	 inm_u64_t val;
 
	 if(!is_digit(buf, len)) {
		 err("Invalid value for volume previous end sequence number = %s : has non-digit chars", buf);
		 return -EINVAL;
	 }
 
	val = inm_atoi64(buf);
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_PrevEndSequenceNumber = val;
	}
	
	return len;     
}

void
read_vol_prev_end_sequence_number(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;
 
	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		ctxt->tc_PrevEndSequenceNumber = inm_atoi64(buf);
		goto free_buf;
	}
 
set_default:
	ctxt->tc_PrevEndSequenceNumber = 0;
free_buf:
	if(driver_ctx->unclean_shutdown)
		ctxt->tc_PrevEndSequenceNumber = -1ULL;

	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t
vol_prev_sequence_id_for_split_io_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%u", ctxt->tc_PrevSequenceIDforSplitIO);
}
 
inm_s32_t
vol_prev_sequence_id_for_split_io_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	 inm_u32_t val;
 
	 if(!is_digit(buf, len)) {
		 err("Invalid value for volume previous continuation id = %s : has non-digit chars", buf);
		 return -EINVAL;
	 }
 
	val = inm_atoi(buf);
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		volume_lock(ctxt);
		ctxt->tc_PrevSequenceIDforSplitIO = val;
		volume_unlock(ctxt);
	}
   
	return len;
}

void
read_vol_prev_sequence_id_for_split_io(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		ctxt->tc_PrevSequenceIDforSplitIO = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	ctxt->tc_PrevSequenceIDforSplitIO = 0;
free_buf:
	if(driver_ctx->unclean_shutdown)
		ctxt->tc_PrevSequenceIDforSplitIO = -1;

	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}

inm_s32_t
vol_mirror_source_list_show(target_context_t *ctxt, char *buf)
{
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	mirror_vol_entry_t *vol_entry;
	inm_s32_t buf_len = 0;
	char *sptr = buf;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entring");
	}

	if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
		return 0;

	INM_MEM_ZERO(buf,INM_PAGESZ);


	volume_lock(ctxt);
	inm_list_for_each_safe(ptr, nextptr, &ctxt->tc_src_list) {
		vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);
		if (buf_len+strlen(vol_entry->tc_mirror_guid+1) > INM_PAGESZ) {
			break;
		}
		snprintf(sptr, INM_PAGESZ-buf_len, "%s\n",
			vol_entry->tc_mirror_guid);
		sptr += strlen(vol_entry->tc_mirror_guid)+1;
		buf_len += strlen(vol_entry->tc_mirror_guid)+1;
	}
	volume_unlock(ctxt);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving buf_len:%d",buf_len);
	}
	return buf_len;
}
 
inm_s32_t
vol_mirror_source_list_store(target_context_t *ctxt, char * file_name,
					         const char *buf, inm_s32_t len)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entered buf:%s",buf);
	}
	if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
		return len;

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving buf:%s len:%d",buf,len);
	}
	return len;
}
inm_s32_t
prepare_volume_list(char *buf, struct inm_list_head *list_head,
					int keep_device_open) 
{
	char *str, *str1, *str2;
	int len = 0;
	int err = 0;
	mirror_vol_entry_t *vol_entry;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entered buf:%s",buf);
	}
	str = buf;
	while (1) {
		if ((str1 = strchr(str,'/'))) {
			if ((str2 = strchr(str,','))) {
				*str2 = '\0';
			}
			len = strlen(str1);
			vol_entry = INM_KMALLOC(sizeof(mirror_vol_entry_t),
					                INM_KM_SLEEP, INM_KERNEL_HEAP);
			INM_MEM_ZERO(vol_entry, sizeof(mirror_vol_entry_t));
			if (strncpy_s(vol_entry->tc_mirror_guid, INM_GUID_LEN_MAX,
					                                         str1, len)) {
				INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t),
					                             INM_KERNEL_HEAP);
				err = 1;
				break;
			}
			vol_entry->tc_mirror_guid[len] = '\0';
#ifdef INM_LINUX
#if defined(INM_HANDLE_FOR_BDEV_ENABLED)
			vol_entry->mirror_handle = inm_bdevhandle_open_by_dev_path(
				vol_entry->tc_mirror_guid, FMODE_WRITE);
			if (!vol_entry->mirror_handle) {
#elif defined(INM_FILP_FOR_BDEV_ENABLED)
			vol_entry->mirror_filp = inm_file_open_by_dev_path(
				vol_entry->tc_mirror_guid, FMODE_WRITE);
			if (!vol_entry->mirror_filp) {
#else
			vol_entry->mirror_dev = open_by_dev_path(vol_entry->tc_mirror_guid, 1);
			if (!vol_entry->mirror_dev || vol_entry->mirror_dev->bd_disk)  {
#endif				
				err("Failed to open the volume:%s during boot time stacking",
					vol_entry->tc_mirror_guid);
				INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t), INM_KERNEL_HEAP);
				err = 1;
				break;
			}
			else {
#if defined(INM_HANDLE_FOR_BDEV_ENABLED)
				vol_entry->mirror_dev = vol_entry->mirror_handle->bdev;
				if (!keep_device_open) {
					close_bdev_handle(vol_entry->mirror_handle);
#elif defined(INM_FILP_FOR_BDEV_ENABLED)
				vol_entry->mirror_dev = file_bdev(vol_entry->mirror_filp);
				if (!keep_device_open) {
					close_file(vol_entry->mirror_filp);
#else				
				if (!keep_device_open) {
					close_bdev(vol_entry->mirror_dev, FMODE_WRITE);
#endif					
				}
			}
#else
#ifdef INM_SOLARIS
			vol_entry->mirror_dev = (inm_block_device_t *)    
			INM_KMALLOC(sizeof(inm_block_device_t), INM_KM_SLEEP, INM_KERNEL_HEAP);
			*vol_entry->mirror_dev = 0;
			*vol_entry->mirror_dev = inm_get_dev_t_from_path(vol_entry->tc_mirror_guid);
			if (!*vol_entry->mirror_dev)  {
				err("Failed to open the volume:%s during boot time stacking for"
					"mirror setup", vol_entry->tc_mirror_guid);
				INM_KFREE(vol_entry, sizeof(mirror_vol_entry_t), INM_KERNEL_HEAP);
				err = 1;
				break;
			}
#endif
#endif
			dbg("prepare_volume_list(): Mirror Volume Path %s", vol_entry->tc_mirror_guid);
			
			inm_list_add_tail(&vol_entry->next, list_head);
			
			
			if (str2) {
				*str2 = ',';
				str = str2+1;
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}
	if (err) {
		free_mirror_list(list_head, keep_device_open);
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving buf:%s err:%d",buf,err);
	}
	return err;
}

void
read_vol_mirror_source_list(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len;
	void *buf = NULL;
	struct inm_list_head src_mirror_list_head;
	int err = 0;

	if (1) {
		return;
	}
	if (!inm_list_empty(&ctxt->tc_src_list)) {
		return;
	}
	INM_INIT_LIST_HEAD(&src_mirror_list_head);
 
	buf_len = INM_MAX_VOLUMES_IN_LIST*INM_GUID_LEN_MAX;
	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		err = 1;
		goto error_case;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entered %s", (char*)buf);
	}

	err = prepare_volume_list(buf, &src_mirror_list_head, 0);
	if (err) {
		free_mirror_list(&src_mirror_list_head, 0);
	}
	else {
		inm_list_splice_at_tail(&src_mirror_list_head, &ctxt->tc_src_list);
	}
error_case:
	if (err) {
		err("Failed to read source volumes of mirror setup");
	}
	if (buf) {
		INM_KFREE(buf, INM_MAX_VOLUMES_IN_LIST*INM_GUID_LEN_MAX, INM_KERNEL_HEAP);
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving err:%d", err);
	}
}

inm_s32_t
vol_mirror_destination_list_show(target_context_t *ctxt, char *buf)
{
	struct inm_list_head *ptr = NULL, *nextptr = NULL;
	mirror_vol_entry_t *vol_entry;
	inm_s32_t buf_len = 0;
	char *sptr = buf;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entring");
	}

	if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
		return 0;

	INM_MEM_ZERO(buf, INM_PAGESZ);

	volume_lock(ctxt);
	inm_list_for_each_safe(ptr, nextptr, &ctxt->tc_dst_list) {
		vol_entry = inm_list_entry(ptr, mirror_vol_entry_t, next);
		if (buf_len+strlen(vol_entry->tc_mirror_guid+1) > INM_PAGESZ) {
			break;
		}
		snprintf(sptr, INM_PAGESZ-buf_len, "%s\n",
				vol_entry->tc_mirror_guid);
		sptr += strlen(vol_entry->tc_mirror_guid)+1;
		buf_len += strlen(vol_entry->tc_mirror_guid)+1;
	}
	volume_unlock(ctxt);
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving buf_len:%d",buf_len);
	}
	return buf_len;
}
 
inm_s32_t
vol_mirror_destination_list_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("entered buf:%s",buf);
	}
	if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
		return len;

	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
		info("leaving buf:%s len:%d",buf,len);
	}
	return len;
}

void
read_vol_mirror_destination_list(target_context_t *ctxt, char * fname)
{
}

inm_s32_t
vol_mirror_destination_scsi_show(target_context_t *ctxt, char *uuid)
{
	inm_s32_t len = 0;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered volume:%s",ctxt->tc_pname);
	}

	 uuid = filter_guid_name_string_get(ctxt->tc_pname, 
			                    "VolumeMirrorDestinationScsiID", 
			                    INM_MAX_SCSI_ID_SIZE);
	 if (!uuid){
		 len = 0;
	 } else {
		uuid[INM_MAX_SCSI_ID_SIZE-1] = '\0';
		len = strlen(uuid);
	 }
	 return len;
}

inm_s32_t
vol_PTpath_list_show(target_context_t *ctxt, char *bufp)
{
	inm_s32_t len = 0;
	struct inm_list_head *ptr, *nextptr;
	mirror_vol_entry_t *vol_entry = NULL;
	#if (defined(IDEBUG) || defined(IDEBUG_BMAP))
		info("entered volume:%s",ctxt->tc_pname);
	#endif

	 if(ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP){
		 goto out;
	 }
	 volume_lock(ctxt);
	 inm_list_for_each_safe(ptr, nextptr, &ctxt->tc_src_list) {
		 vol_entry = inm_container_of(ptr, mirror_vol_entry_t, next);
	 len += snprintf((bufp+(len)), (INM_PAGESZ - len), vol_entry->tc_mirror_guid);
		 len += snprintf((bufp+(len)), (INM_PAGESZ - len), "\n");
	 }
	 volume_unlock(ctxt);

out:
	 return len;
}

inm_s32_t
vol_mirror_destination_scsi_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered volume:%s",ctxt->tc_pname);
	}

	if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
		return len;

	if(strlen(buf) == 0){
		return len;
	}
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	}
	return len;
}

inm_u64_t
filter_full_disk_flags_get(target_context_t *ctxt)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;
	inm_u64_t flags = 0;

	if(!read_vol_attr(ctxt, "VolumeDiskFlags", &buf, buf_len, &bytes_read)) {
		goto out;
	} else {
		if(!is_digit(buf, bytes_read)){
			goto out;
		}
		flags = inm_atoi(buf);
	}		

out:
	return flags;
}

inm_s32_t
vol_disk_flags_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{

	 if(!is_digit(buf, len)) {
		 err("Invalid value for volume disk flag %s : has non-digit chars", buf);
		 return INM_EINVAL;
	 }
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return INM_EINVAL;
	}
	return 0;
}

inm_s32_t
vol_dev_multipath_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{

	if(!is_digit(buf, len)) {
		err("Invalid value for volume disk flag %s : has non-digit chars", buf);
		return INM_EINVAL;
	}
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return INM_EINVAL;
	}
	return 0;
}

inm_s32_t
vol_dev_vendor_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{

	if(!is_digit(buf, len)) {
		err("Invalid value for volume disk flag %s : has non-digit chars", buf);
		return INM_EINVAL;
	}
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return INM_EINVAL;
	}
	return 0;
}

inm_s32_t
vol_dev_startoff_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{

	if(!is_digit(buf, len)) {
		err("Invalid value for volume disk flag %s : has non-digit chars", buf);
		return INM_EINVAL;
	}
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return INM_EINVAL;
	}
	return 0;
}

void vol_dev_startoff_read(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		inm_u64_t startoff;
		if(!is_digit(buf, bytes_read))
			goto free_buf;
		startoff = inm_atoi(buf);
			
		ctxt->tc_dev_startoff = startoff;
	}

	goto free_buf;

set_default:
	ctxt->tc_dev_startoff = 0;
free_buf:
	if(buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
}
inm_s32_t
mirror_dst_id_get(target_context_t *ctxt, char *uuid)
{
	inm_s32_t err = 0;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered volume:%s",ctxt->tc_pname);
	}

	 if (!vol_mirror_destination_scsi_show(ctxt, uuid)){
		err = 1;
	 }
	 return err;
}

inm_s32_t
mirror_dst_id_set(target_context_t *ctxt, char *uuid)
{

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered volume:%s",ctxt->tc_pname);
	}
	if(strlen(uuid) == 0){
		return 0;
	}
	if(!vol_mirror_destination_scsi_store(ctxt, 
			                      "VolumeMirrorDestinationScsiID", 
			                      (const char *)uuid, 
			                      INM_MAX_SCSI_ID_SIZE)){
		return 1;
	}
	return 0;
}

inm_s32_t
vol_max_xfersz_show(target_context_t *ctxt, char *buf)
{
	host_dev_ctx_t *hdcp = ctxt->tc_priv;
	host_dev_t *hdc_dev = NULL;
	inm_u32_t mxs = 0;

	if (ctxt->tc_dev_type & FILTER_DEV_HOST_VOLUME){
		volume_lock(ctxt);
		hdc_dev = inm_list_entry((hdcp->hdc_dev_list_head.next), host_dev_t, hdc_dev_list);
		mxs = INM_GET_HDEV_MXS(hdc_dev);
		volume_unlock(ctxt);
		return snprintf(buf, INM_PAGESZ, "%u", INM_GET_HDEV_MXS(hdc_dev));
   }
   return 0;
}
 
inm_s32_t
vol_max_xfersz_store(target_context_t *ctxt, char * file_name, const char *buf,
				   inm_s32_t len)
{
	 inm_u32_t val;
	 host_dev_ctx_t *hdcp = ctxt->tc_priv;
	 host_dev_t *hdc_dev = NULL;
 
	 if (!(ctxt->tc_dev_type & FILTER_DEV_HOST_VOLUME)){
		 return 0;
	 }
	 if(!is_digit(buf, len)) {
		 err("Invalid value for volume perf opt= %s : has non-digit chars", buf);
		 return -EINVAL;
	 }
 
	val = inm_atoi(buf);
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return INM_EINVAL;
	} else {
		volume_lock(ctxt);
		hdc_dev = inm_list_entry((hdcp->hdc_dev_list_head.next), host_dev_t, hdc_dev_list);
		INM_SET_HDEV_MXS(hdc_dev, val);
		volume_unlock(ctxt);
	}
   
	return len;
}

void
vol_max_xfersz_read(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
	host_dev_ctx_t *hdcp = ctxt->tc_priv;
	host_dev_t *hdc_dev = NULL;
 
	if (!(ctxt->tc_dev_type & FILTER_DEV_HOST_VOLUME)){
		return;
	}
	hdc_dev = inm_list_entry((hdcp->hdc_dev_list_head.next), host_dev_t, hdc_dev_list);
	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		INM_SET_HDEV_MXS(hdc_dev, (inm_atoi(buf)));
		goto free_buf;
	}

set_default:
	INM_SET_HDEV_MXS(hdc_dev, INM_DEFAULT_VOLUME_MXS);
free_buf:
	if (buf) {
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	}
}

inm_s32_t
vol_perf_opt_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%u", ctxt->tc_optimize_performance);
}
 
inm_s32_t
vol_perf_opt_store(target_context_t *ctxt, char * file_name, const char *buf,
				   inm_s32_t len)
{
	 inm_u32_t val;
 
	 if(!is_digit(buf, len)) {
		 err("Invalid value for volume perf opt= %s : has non-digit chars", buf);
		 return -EINVAL;
	 }
 
	val = inm_atoi(buf);
 
	if(!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		volume_lock(ctxt);
		ctxt->tc_optimize_performance = val | DEFAULT_PERFORMANCE_OPTMIZATION;
		volume_unlock(ctxt);
	}
   
	return len;
}

void
vol_perf_opt_read(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_INTEGER + 1);
	void *buf = NULL;
 
	if(!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		goto set_default;
	} else {
		if(!is_digit(buf, bytes_read))
			goto set_default;
 
		ctxt->tc_optimize_performance = inm_atoi(buf);
		goto free_buf;
	}

set_default:
	ctxt->tc_optimize_performance = DEFAULT_PERFORMANCE_OPTMIZATION;
free_buf:
	if (buf) {
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	}
}

inm_u64_t
vol_rpo_ts_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%llu", ctxt->tc_rpo_timestamp);
}

void
vol_rpo_ts_read(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1);
	void *buf = NULL;

	if (!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if (!is_digit(buf, bytes_read)) {
			goto set_default;
		}
			ctxt->tc_rpo_timestamp = inm_atoi64(buf);
			dbg("Rpo value set to %llu",ctxt->tc_rpo_timestamp);
			goto free_buf;
	}

set_default:
	ctxt->tc_rpo_timestamp = 0;
	dbg("Rpo value set to default %llu",ctxt->tc_rpo_timestamp);

free_buf:
	if (buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	dbg("RPO timestamp from persistent store = %llu\n",
					ctxt->tc_rpo_timestamp);

}

inm_s32_t
vol_rpo_ts_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	inm_u64_t val;

	if (!is_digit(buf, len)) {
		err("Invalid value for RPO timestamp = %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi64(buf);

	ctxt->tc_rpo_timestamp = val;

	if (!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		return -EINVAL;
	} else {
		ctxt->tc_rpo_timestamp = val;
	}
 
	return len;
}

inm_u64_t
vol_drain_blocked_show(target_context_t *ctxt, char *buf)
{
	return snprintf(buf, INM_PAGESZ, "%d", (ctxt->tc_flags & VCF_DRAIN_BLOCKED) ? 1 : 0);
}

inm_s32_t
vol_drain_blocked_store(target_context_t *ctxt, char * file_name, const char *buf, inm_s32_t len)
{
	inm_s32_t val;

	if (!is_digit(buf, len)) {
		err("Invalid value for volume drain blocked = %s : has non-digit chars", buf);
		return -EINVAL;
	}

	val = inm_atoi(buf);
	if (val != 0 && val != 1) {
		 err("Invalid value for volume drain block : %d", val);
		 return -EINVAL;
		
	}

	if (!write_vol_attr(ctxt, file_name, (void *)buf, len)) {
		err("Failed to persist drain block to disk");
		return -EINVAL;
	} else {
		info("Drain block flag : %d\n", val);
		volume_lock(ctxt);
		if (val) {
			ctxt->tc_flags |= VCF_DRAIN_BLOCKED;
		}
		else {
			ctxt->tc_flags &= ~VCF_DRAIN_BLOCKED;
		}
		volume_unlock(ctxt);
	}
 
	return 0;
}

void
vol_drain_blocked_read(target_context_t *ctxt, char * fname)
{
	inm_s32_t bytes_read = 0, buf_len = (NUM_CHARS_IN_LONGLONG + 1), val;
	void *buf = NULL;

	if (!read_vol_attr(ctxt, fname, &buf, buf_len, &bytes_read)) {
		dbg("read failed for %s", fname);
		goto set_default;
	} else {
		if (!is_digit(buf, bytes_read)) {
			goto set_default;
		}
		val = inm_atoi(buf);
		if (val == 0) {
			volume_lock(ctxt);
			ctxt->tc_flags &= ~VCF_DRAIN_BLOCKED;
			volume_unlock(ctxt);
			goto free_buf;
		}
		else if (val == 1) {
			volume_lock(ctxt);
			ctxt->tc_flags |= VCF_DRAIN_BLOCKED;
			volume_unlock(ctxt);
			goto free_buf;
		}
		else {
			dbg("Invalid value of val : %d\n", val);
			goto set_default;
		}
	}

set_default:
	volume_lock(ctxt);
	ctxt->tc_flags &= ~VCF_DRAIN_BLOCKED;
	volume_unlock(ctxt);
	dbg("Drain block set to default 0");

free_buf:
	if (buf)
		INM_KFREE(buf, buf_len, INM_KERNEL_HEAP);
	dbg("Drain block from persistent store = %d\n",
		(ctxt->tc_flags & VCF_DRAIN_BLOCKED) ? 1 : 0);

}

VOLUME_ATTR(vol_attr_VolumeFilteringDisabled, "VolumeFilteringDisabled", INM_S_IRWXUGO, &vol_flt_disabled_show, &vol_flt_disabled_store, &read_vol_flt_disabled);
VOLUME_ATTR(vol_attr_VolumeBitmapReadDisabled, "VolumeBitmapReadDisabled", INM_S_IRWXUGO, &vol_bmapread_disabled_show, &vol_bmapread_disabled_store, &read_bmapread_disabled);
VOLUME_ATTR(vol_attr_VolumeBitmapWriteDisabled, "VolumeBitmapWriteDisabled", INM_S_IRWXUGO, &vol_bmapwrite_disabled_show, &vol_bmapwrite_disabled_store, &read_bmapwrite_disabled);
VOLUME_ATTR(vol_attr_VolumeDataFiltering, "VolumeDataFiltering", INM_S_IRWXUGO, &vol_data_flt_show, &vol_data_flt_store, &read_data_flt_enabled);
VOLUME_ATTR(vol_attr_VolumeDataFiles, "VolumeDataFiles", INM_S_IRWXUGO, &vol_data_files_show, &vol_data_files_store, &read_data_files_enabled);
VOLUME_ATTR(vol_attr_VolumeDataToDiskLimitInMB, "VolumeDataToDiskLimitInMB", INM_S_IRWXUGO, &vol_data_to_disk_limit_show, &vol_data_to_disk_limit_store, &read_data_to_disk_limit);
VOLUME_ATTR(vol_attr_VolumeDataNotifyLimitInKB, "VolumeDataNotifyLimitInKB", INM_S_IRWXUGO, &vol_data_notify_show, &vol_data_notify_store, &read_data_notify_limit);
VOLUME_ATTR(vol_attr_VolumeDataLogDirectory, "VolumeDataLogDirectory", INM_S_IRWXUGO, &vol_log_dir_show, &vol_log_dir_store, &read_data_log_dir);
VOLUME_ATTR(vol_attr_VolumeBitmapGranularity, "VolumeBitmapGranularity", INM_S_IRWXUGO, &vol_bmap_gran_show, &vol_bmap_gran_store, &read_bmap_gran);
VOLUME_ATTR(vol_attr_VolumeResyncRequired, "VolumeResyncRequired", INM_S_IRWXUGO, &vol_resync_req_show, &vol_resync_req_store, &read_resync_req);
VOLUME_ATTR(vol_attr_VolumeOutOfSyncErrorCode, "VolumeOutOfSyncErrorCode", INM_S_IRWXUGO, &vol_osync_errcode_show, &vol_osync_errcode_store, &read_osync_errcode);
VOLUME_ATTR(vol_attr_VolumeOutOfSyncErrorStatus, "VolumeOutOfSyncErrorStatus", INM_S_IRWXUGO, &vol_osync_status_show, &vol_osync_status_store, &read_osync_status);
VOLUME_ATTR(vol_attr_VolumeOutOfSyncCount, "VolumeOutOfSyncCount", INM_S_IRWXUGO, &vol_osync_count_show, &vol_osync_count_store, &read_osync_count);
VOLUME_ATTR(vol_attr_VolumeOutOfSyncTimeStamp, "VolumeOutOfSyncTimeStamp", INM_S_IRWXUGO, &vol_osync_ts_show, &vol_osync_ts_store, &read_osync_ts);
VOLUME_ATTR(vol_attr_VolumeOutOfSyncErrorDescription, "VolumeOutOfSyncErrorDescription", INM_S_IRWXUGO, &vol_osync_desc_show, &vol_osync_desc_store, &read_osync_desc);
VOLUME_ATTR(vol_attr_VolumeFilterDevType, "VolumeFilterDevType", INM_S_IRUGO, &filter_dev_type_show, NULL, &read_filter_dev_type);
VOLUME_ATTR(vol_attr_VolumeNblks, "VolumeNblks", INM_S_IRWXUGO, &filter_dev_nblks_show, &filter_dev_nblks_store, &read_filter_dev_nblks);
VOLUME_ATTR(vol_attr_VolumeBsize, "VolumeBsize", INM_S_IRWXUGO, &filter_dev_bsize_show, &filter_dev_bsize_store, &read_filter_dev_bsize);
VOLUME_ATTR(vol_attr_VolumeResDataPoolSize, "VolumeResDataPoolSize", INM_S_IRWXUGO, &inm_vol_reserv_show, &inm_vol_reserv_store, &inm_read_reserv_dpsize);
VOLUME_ATTR(vol_attr_VolumeMountPoint, "VolumeMountPoint", INM_S_IRWXUGO, &vol_mount_point_show, &vol_mount_point_store, &read_vol_mount_point);
VOLUME_ATTR(vol_attr_VolumePrevEndTimeStamp, "VolumePrevEndTimeStamp", INM_S_IRWXUGO, &vol_prev_end_timestamp_show, &vol_prev_end_timestamp_store, &read_vol_prev_end_timestamp);
VOLUME_ATTR(vol_attr_VolumePrevEndSequenceNumber, "VolumePrevEndSequenceNumber", INM_S_IRWXUGO, &vol_prev_end_sequence_number_show, &vol_prev_end_sequence_number_store, &read_vol_prev_end_sequence_number);
VOLUME_ATTR(vol_attr_VolumePrevSequenceIDforSplitIO, "VolumePrevSequenceIDforSplitIO", INM_S_IRWXUGO, &vol_prev_sequence_id_for_split_io_show, &vol_prev_sequence_id_for_split_io_store, &read_vol_prev_sequence_id_for_split_io);
VOLUME_ATTR(vol_attr_VolumePTPath, "VolumePTPath", INM_S_IRWXUGO, &inm_vol_pt_path_show, &inm_vol_pt_path_store, &inm_read_pt_path);
VOLUME_ATTR(vol_attr_VolumeATDirectRead, "ATDirectRead", INM_S_IRWXUGO, &inm_vol_at_direct_rd_show, &inm_vol_at_direct_rd_store, &inm_read_at_direct_rd);
VOLUME_ATTR(vol_attr_VolumeMirrorSourceList, "VolumeMirrorSourceList", INM_S_IRWXUGO, &vol_mirror_source_list_show, &vol_mirror_source_list_store, &read_vol_mirror_source_list);
VOLUME_ATTR(vol_attr_VolumeMirrorDestinationList, "VolumeMirrorDestinationList", INM_S_IRWXUGO, &vol_mirror_destination_list_show, &vol_mirror_destination_list_store, &read_vol_mirror_destination_list);
VOLUME_ATTR(vol_attr_VolumeMirrorDestinationScsiID, "VolumeMirrorDestinationScsiID", INM_S_IRWXUGO, &vol_mirror_destination_scsi_show, &vol_mirror_destination_scsi_store, NULL);
VOLUME_ATTR(vol_attr_VolumeDiskFlags, "VolumeDiskFlags", INM_S_IRWXUGO, NULL, &vol_disk_flags_store, NULL);
VOLUME_ATTR(vol_attr_VolumeIsDeviceMultipath, "VolumeIsDeviceMultipath", INM_S_IRWXUGO, NULL, &vol_dev_multipath_store, NULL);
VOLUME_ATTR(vol_attr_VolumeDeviceVendor, "VolumeDeviceVendor", INM_S_IRWXUGO, NULL, &vol_dev_vendor_store, NULL);
VOLUME_ATTR(vol_attr_VolumeDevStartOff, "VolumeDevStartOff", INM_S_IRWXUGO, NULL, &vol_dev_startoff_store, &vol_dev_startoff_read);
VOLUME_ATTR(vol_attr_VolumePTpathList, "VolumePTpathList", INM_S_IRWXUGO, &vol_PTpath_list_show, NULL, NULL);
VOLUME_ATTR(vol_attr_VolumePerfOptimization, "VolumePerfOptimization", INM_S_IRWXUGO, &vol_perf_opt_show, &vol_perf_opt_store, &vol_perf_opt_read);
VOLUME_ATTR(vol_attr_VolumeMaxXferSz, "VolumeMaxXferSz", INM_S_IRWXUGO, &vol_max_xfersz_show, &vol_max_xfersz_store, &vol_max_xfersz_read);
VOLUME_ATTR(vol_attr_VolumeRpoTimeStamp, "VolumeRpoTimeStamp", INM_S_IRWXUGO, &vol_rpo_ts_show, &vol_rpo_ts_store, &vol_rpo_ts_read);
VOLUME_ATTR(vol_attr_VolumeDrainBlocked, "VolumeDrainBlocked", INM_S_IRWXUGO, &vol_drain_blocked_show, &vol_drain_blocked_store, &vol_drain_blocked_read);

static struct attribute *sysfs_volume_attrs[] = {
	&vol_attr_VolumeFilteringDisabled.attr,
	&vol_attr_VolumeBitmapReadDisabled.attr,
	&vol_attr_VolumeBitmapWriteDisabled.attr,
	&vol_attr_VolumeDataFiltering.attr,
	&vol_attr_VolumeDataFiles.attr,
	&vol_attr_VolumeDataToDiskLimitInMB.attr,
	&vol_attr_VolumeDataNotifyLimitInKB.attr,
	&vol_attr_VolumeDataLogDirectory.attr,
	&vol_attr_VolumeBitmapGranularity.attr,
	&vol_attr_VolumeResyncRequired.attr,
	&vol_attr_VolumeOutOfSyncErrorCode.attr,
	&vol_attr_VolumeOutOfSyncErrorStatus.attr,
	&vol_attr_VolumeOutOfSyncCount.attr,
	&vol_attr_VolumeOutOfSyncTimeStamp.attr,
	&vol_attr_VolumeOutOfSyncErrorDescription.attr,
	&vol_attr_VolumeFilterDevType.attr,
	&vol_attr_VolumeNblks.attr,
	&vol_attr_VolumeBsize.attr,
	&vol_attr_VolumeResDataPoolSize.attr,
	&vol_attr_VolumeMountPoint.attr,
	&vol_attr_VolumePrevEndTimeStamp.attr,
	&vol_attr_VolumePrevEndSequenceNumber.attr,
	&vol_attr_VolumePrevSequenceIDforSplitIO.attr,
	&vol_attr_VolumePTPath.attr,
	&vol_attr_VolumeATDirectRead.attr,
	&vol_attr_VolumeMirrorSourceList.attr,
	&vol_attr_VolumeMirrorDestinationList.attr,
	&vol_attr_VolumeMirrorDestinationScsiID.attr,
	&vol_attr_VolumeDiskFlags.attr,
	&vol_attr_VolumeIsDeviceMultipath.attr,
	&vol_attr_VolumeDeviceVendor.attr,
	&vol_attr_VolumeDevStartOff.attr,
	&vol_attr_VolumePTpathList.attr,
	&vol_attr_VolumePerfOptimization.attr,
	&vol_attr_VolumeMaxXferSz.attr,
	&vol_attr_VolumeRpoTimeStamp.attr,
	&vol_attr_VolumeDrainBlocked.attr,
	NULL,
};

int set_int_vol_attr(target_context_t *ctxt, enum volume_params_idx index, inm_s32_t val)
{
	char buf[(NUM_CHARS_IN_INTEGER + 1)];
	inm_s32_t copied;
	struct volume_attribute *volume_attr;
	struct attribute *attr = sysfs_volume_attrs[index];

	INM_MEM_ZERO(buf, NUM_CHARS_IN_INTEGER + 1);
	copied = snprintf(buf, NUM_CHARS_IN_INTEGER + 1, "%u", val);


	volume_attr = inm_container_of(attr, struct volume_attribute, attr);
	if(volume_attr->store)
		return volume_attr->store(ctxt, volume_attr->file_name, buf, copied);
	return INM_EFAULT;
}

void set_string_vol_attr(target_context_t *ctxt, enum volume_params_idx index, char *string)
{
	struct volume_attribute *volume_attr;
	struct attribute *attr = sysfs_volume_attrs[index];

	volume_attr = inm_container_of(attr, struct volume_attribute, attr);
	if(volume_attr->store)
		volume_attr->store(ctxt, volume_attr->file_name, string, strlen(string));
}

void set_longlong_vol_attr(target_context_t *ctxt, enum volume_params_idx index, inm_s64_t val)
{
	char buf[(NUM_CHARS_IN_LONGLONG + 1)];
	inm_s32_t copied;
	struct volume_attribute *volume_attr;
	struct attribute *attr = sysfs_volume_attrs[index];

	INM_MEM_ZERO(buf, NUM_CHARS_IN_LONGLONG + 1);
	copied = snprintf(buf, NUM_CHARS_IN_LONGLONG + 1, "%lld", (long long)val);

	volume_attr = inm_container_of(attr, struct volume_attribute, attr);
	if(volume_attr->store)
		volume_attr->store(ctxt, volume_attr->file_name, buf, copied);
}

void set_unsignedlonglong_vol_attr(target_context_t *ctxt, enum volume_params_idx index, inm_u64_t val)
{
	char buf[(NUM_CHARS_IN_LONGLONG + 1)];
	inm_s32_t copied;
	struct volume_attribute *volume_attr;
	struct attribute *attr = sysfs_volume_attrs[index];

	INM_MEM_ZERO(buf, NUM_CHARS_IN_LONGLONG + 1);
	copied = snprintf(buf, NUM_CHARS_IN_LONGLONG + 1, "%llu", (unsigned long long)val);

	volume_attr = inm_container_of(attr, struct volume_attribute, attr);
	if(volume_attr->store)
		volume_attr->store(ctxt, volume_attr->file_name, buf, copied);
}

static inm_s32_t vol_attr_show(void *vol_infop, struct attribute *attr,
				 char *page)
{
	target_context_t *temp;
	struct volume_attribute *volume_attr;
	inm_s32_t	ret = 0;	

	temp = (target_context_t *)vol_infop;
	volume_attr = inm_container_of(attr, struct volume_attribute, attr);

	if (volume_attr->show)
		ret = volume_attr->show(temp, page);

	return ret;
}

static inm_s32_t vol_attr_store(void *vol_infop, struct attribute *attr,
					          const char *page, inm_s32_t len)
{
	target_context_t *temp;
	struct volume_attribute *volume_attr;
	inm_s32_t ret = 0;

	temp = (target_context_t *)vol_infop;
	volume_attr = inm_container_of(attr, struct volume_attribute, attr);

	if (volume_attr->store)
		ret = volume_attr->store(temp, volume_attr->file_name, page,len);

	if(ret < 0)
		return ret;
	else {
		return len;
	}
}

static void volume_release(void *argp)
{
	target_context_t *ctxt = (target_context_t *) argp;

	target_context_release(ctxt);
}

void load_volume_params(target_context_t *ctxt)
{
	inm_s32_t num_attribs, temp;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p volume:%s",ctxt, ctxt->tc_guid);
	}
	num_attribs = (sizeof(sysfs_volume_attrs)/sizeof(struct atttribute *));
	num_attribs--;

	temp = 0;

	while(temp < num_attribs) {
		struct volume_attribute *volume_attr;
		struct attribute *attr = sysfs_volume_attrs[temp];

		volume_attr = inm_container_of(attr, struct volume_attribute, attr);

		if (volume_attr->read)
			volume_attr->read(ctxt, volume_attr->file_name);
		temp++;
	}
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving ctx:%p volume:%s",ctxt, ctxt->tc_guid);
	}
}

/* Modify persistent store based on persistent name */
int
inm_write_guid_attr(char *pname, enum volume_params_idx index, inm_s32_t val)
{
	char *path = NULL;
	inm_u32_t wrote = 0, ret = 0;
	char buf[(NUM_CHARS_IN_INTEGER + 1)];
	inm_s32_t copied;
	struct volume_attribute *volume_attr;
	struct attribute *attr = sysfs_volume_attrs[index];
	volume_attr = inm_container_of(attr, struct volume_attribute, attr);

	INM_MEM_ZERO(buf, NUM_CHARS_IN_INTEGER + 1);
	copied = snprintf(buf, (NUM_CHARS_IN_INTEGER) + 1, "%d", val);

	if(!get_path_memory(&path)) {
		err("write_guid_attr: Failed to allocated memory path");
		return 1;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s/%s", PERSISTENT_DIR, pname, 
			 volume_attr->file_name);
	dbg("Writing to file %s", path);

	if(!write_full_file(path, (void *)buf, copied, &wrote)) {
		err("write_guid_attr: write to persistent store failed %s", path);
		ret = 1;
	} else {
		ret = 0;
	}

	free_path_memory(&path);

	return ret;
}

inm_s32_t
volume_get_set_attribute_entry(struct _inm_attribute *inm_attr)
{
	inm_s32_t		ret = 0;
	char			*lbufp = NULL;
	inm_u32_t		lbuflen = 0;
	target_context_t	*ctxt = NULL;


	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
	ctxt = get_tgt_ctxt_from_name_nowait_locked(inm_attr->guid.volume_guid);
	if (!ctxt){
		INM_UP_READ(&driver_ctx->tgt_list_sem);
		dbg("%s is not stacked",inm_attr->guid.volume_guid);
		goto out;
	}

	INM_UP_READ(&driver_ctx->tgt_list_sem);
	lbuflen = INM_MAX(inm_attr->buflen, INM_PAGESZ);
	lbufp = (char *) INM_KMALLOC(lbuflen, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!lbufp){
		err("buffer allocation get_set ioctl failed\n");
		ret = INM_ENOMEM;
		goto out;
	}
	INM_MEM_ZERO(lbufp, lbuflen);

	if(inm_attr->why == SET_ATTR){
		if (INM_COPYIN(lbufp, inm_attr->bufp, inm_attr->buflen)) {
			err("copyin failed\n");
			ret = INM_EFAULT;
			goto out;
		}
		ret = vol_attr_store((void *)ctxt, sysfs_volume_attrs[inm_attr->type], lbufp, inm_attr->buflen);
		if (ret < 0){
			err("attributre store failed");
			ret = -ret;
			goto out;
		}
	} else {
		ret = vol_attr_show((void *)ctxt, sysfs_volume_attrs[inm_attr->type], lbufp);
		if (ret == 0){
			dbg("its unlikely but get attribute read 0 bytes only");
		} else if (ret > 0){
			if (INM_COPYOUT(inm_attr->bufp, lbufp, ret+1)) {
				err("copyout failed\n");
				ret = INM_EFAULT;
				goto out;
			}
		} else {
			err("get attribute failed");
			ret = -ret;
			goto out;
		}
	}
	ret = 0;
out:
	if(ctxt)
		put_tgt_ctxt(ctxt);

	if (lbufp) {
		   INM_KFREE(lbufp, lbuflen, INM_KERNEL_HEAP); 
	}       
	return ret;
}

inm_s32_t sysfs_init_volume(target_context_t *ctxt, char *pname)
{
	char *path = NULL;
	inm_s32_t err = -1;
#ifdef INM_AIX
	host_dev_ctx_t *hdcp = NULL;
	host_dev_t *hdc_dev = NULL;
	inm_s32_t mxs_vol = 0;
#endif

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p volume:%s",ctxt, pname);
	}
	ctxt->release = volume_release;
	get_tgt_ctxt(ctxt);

	if (!get_path_memory(&path)) {
		put_tgt_ctxt(ctxt);
		err = -ENOMEM;
		err("Failed to get memory while creating persistent directory");
		return err;
	}
	
	snprintf(path, INM_PATH_MAX, "%s/%s" , PERSISTENT_DIR, pname);
	/*
	 * Upgrades for change in persistent names are done by creating symlinks to
	 * existing persistent dir names. In case of a fresh protection, remove old
	 * symlinks if any before creating persistent directory
	 */
	inm_unlink_symlink(path, PERSISTENT_DIR);
	inm_mkdir(path, 0755);

	free_path_memory(&path);
#ifdef INM_AIX
	hdcp = ctxt->tc_priv;
	hdc_dev = inm_list_entry((hdcp->hdc_dev_list_head.next), host_dev_t, hdc_dev_list);
	if (mxs_vol = INM_GET_HDEV_MXS(hdc_dev)) {
		set_int_vol_attr(ctxt, VolumeMaxXferSz, mxs_vol);
	}
#endif

	load_volume_params(ctxt);

	err = 0;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving ctx:%p volume:%s ret:%d",ctxt, ctxt->tc_pname, err);
	}
	return err;
}

/* Wrapper to common_attr_store()
 */
ssize_t wrap_common_attr_store(inm_u32_t type, const char *page,
				size_t len)
{
	struct attribute *attr;
	attr  = sysfs_common_attrs[type];
	return common_attr_store(attr, page, len);
}

inm_s32_t
inm_is_upgrade_pname(char *actual, char *upgrade)
{
	int retval = 0;
	void *af = NULL;
	void *uf = NULL;
	char *path = NULL;

	if (!get_path_memory(&path)) {
		retval = -ENOMEM;
		path = NULL;
		goto out;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s" , PERSISTENT_DIR, actual);
	af = filp_open(path, O_RDONLY, 0777);
	if (IS_ERR(af)) {
		retval = PTR_ERR(af);
		err("Cannot open %s", path);
		goto out;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s" , PERSISTENT_DIR, upgrade);
	uf = filp_open(path, O_RDONLY, 0777);
	if (IS_ERR(uf)) {
		retval = -EINVAL;
		err("Cannot open %s", path);
		filp_close(af, NULL);
		goto out;
	}

	dbg("af = %p, uf = %p", INM_HDL_TO_INODE(af), INM_HDL_TO_INODE(uf));

	if (INM_HDL_TO_INODE(af) != INM_HDL_TO_INODE(uf)) 
		retval = -EINVAL;

	filp_close(af, NULL);
	filp_close(uf, NULL);

out:
	if (path)
		free_path_memory(&path);

	return retval;
}

