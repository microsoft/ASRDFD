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
#include "involflt_debug.h"
#include "tunable_params.h"
#include "filter_host.h"
#include "file-io.h"
#ifdef INM_LINUX
#include "filter_lun.h"
#endif
#include "filestream_raw.h"

extern driver_context_t *driver_ctx;
extern inm_s32_t driver_state;
inm_s32_t write_vol_attr(target_context_t * , const char *, void *, int);
static inm_u32_t is_big_endian(void);
#ifdef INM_DEBUG
static void print_tag_struct(tag_info_t *, inm_s32_t);
#endif

void 
get_time_stamp(inm_u64_t *time_in_100nsec)
{
#ifdef INM_AIX
	struct timestruc_t now;
#else
	inm_timespec now;
#endif
	
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("entered");
	}
	
	*time_in_100nsec = 0;

	INM_GET_CURRENT_TIME(now);

	(*time_in_100nsec) += (now.tv_sec*HUNDREDS_OF_NANOSEC_IN_SECOND);
	(*time_in_100nsec) += (now.tv_nsec/100);

	INM_BUG_ON(!*time_in_100nsec);
	
	if(IS_DBG_ENABLED(inm_verbosity, INM_IDEBUG)){
		info("leaving");
	}

}

void get_time_stamp_tag(TIME_STAMP_TAG_V2 *time_stamp)
{
#ifdef INM_AIX
	struct timestruc_t now;
#else
	inm_timespec now;
#endif
	inm_u64_t time_in_100nsec = 0;
	unsigned long lock_flag = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered");
	}

	INM_GET_CURRENT_TIME(now);
	time_in_100nsec += (now.tv_sec*HUNDREDS_OF_NANOSEC_IN_SECOND);
	time_in_100nsec += (now.tv_nsec/100);

	INM_BUG_ON(!time_in_100nsec);

	time_stamp->TimeInHundNanoSecondsFromJan1601 = time_in_100nsec;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, lock_flag);
	if(driver_ctx->last_time_stamp_seqno >= 
					INMAGE_MAX_TS_SEQUENCE_NUMBER) {
		 driver_ctx->last_time_stamp++;
		 driver_ctx->last_time_stamp_seqno = 0;
	} else {
		 driver_ctx->last_time_stamp_seqno++;
	}
	time_stamp->ullSequenceNumber = driver_ctx->last_time_stamp_seqno;

	if(time_stamp->TimeInHundNanoSecondsFromJan1601 <= 
						driver_ctx->last_time_stamp) {
		time_stamp->TimeInHundNanoSecondsFromJan1601 = 
				driver_ctx->last_time_stamp;
	} else {
		driver_ctx->last_time_stamp = 
				time_stamp->TimeInHundNanoSecondsFromJan1601;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, lock_flag);
	
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving");
	}
}

inm_s32_t 
validate_path_for_file_name(char *filename)
{
	char *local_fname = NULL;
	char *cptr = NULL;
	char *next = NULL;
	char *tmp_str = NULL;
	inm_u32_t sz = 0;
	inm_s32_t err = 0;
#if defined(__SunOS_5_9) || defined(__SunOS_5_8)
	inm_u32_t len = 0;
	char char_tmp;
#endif

	if (!filename || !strlen(filename))
		return -EINVAL;

	local_fname = (char *) INM_KMALLOC(MAX_LOG_PATHNAME, INM_KM_SLEEP,
			 			INM_KERNEL_HEAP);
	if (!local_fname) {
		return -ENOMEM;
	}

	tmp_str = (char *) INM_KMALLOC(MAX_LOG_PATHNAME, INM_KM_SLEEP, 
						INM_KERNEL_HEAP);
	if (!tmp_str) {
		INM_KFREE(local_fname, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
		return -ENOMEM;
	}
	local_fname[0] = '\0';
	if (strcpy_s(tmp_str, MAX_LOG_PATHNAME, "/")) {
		INM_KFREE(local_fname, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
		INM_KFREE(tmp_str, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
		return INM_EFAULT;
	}
	
	if (*filename == '/') {
		/* ensure that path doesn't have dev path */
		if (strncmp(filename, "/dev/", strlen("/dev/")) == 0)
			return 0;
		if (strlen(filename) > MAX_LOG_PATHNAME)
			return -EINVAL;
		cptr = filename;
	} else {
		sz = strlen(DEFAULT_LOG_DIRECTORY_VALUE);
		if (filename[sz-1] != '/') {
			sz++;
		}
		sz += strlen(filename);
		if (sz > MAX_LOG_PATHNAME) {
			INM_KFREE(local_fname, MAX_LOG_PATHNAME, 
							INM_KERNEL_HEAP);
			INM_KFREE(tmp_str, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
			return -EINVAL;
		}

		if (strcpy_s(local_fname, MAX_LOG_PATHNAME, 
					  DEFAULT_LOG_DIRECTORY_VALUE)) {
			INM_KFREE(local_fname, MAX_LOG_PATHNAME, 
							INM_KERNEL_HEAP);
			INM_KFREE(tmp_str, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
			return INM_EFAULT;
		}

		if (strcat_s(local_fname, MAX_LOG_PATHNAME, "/") || strcat_s(local_fname, MAX_LOG_PATHNAME, filename)) {
			INM_KFREE(local_fname, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
			INM_KFREE(tmp_str, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
			return INM_EFAULT;
		}

		cptr = local_fname;
	}

	while(cptr) {
		if (*cptr == '/') {
			cptr++;
			continue;
		}
		next = strchr(cptr, '/');
		if (!next)
			break;

#ifdef INM_LINUX
		strncat_s(tmp_str, MAX_LOG_PATHNAME, cptr, (next - cptr));
#endif
#ifdef INM_SOLARIS
#if defined(__SunOS_5_11) || defined(__SunOS_5_10)
		strncat_s(tmp_str, MAX_LOG_PATHNAME, cptr, (next - cptr));
#endif
#if defined(__SunOS_5_9) || defined(__SunOS_5_8)
		len = (next - cptr);
		char_tmp = cptr[len];
		cptr[len] = '\0';
		strcat_s(tmp_str, MAX_LOG_PATHNAME, cptr);
		cptr[len] = char_tmp;
#endif
#endif
#ifdef INM_AIX
		strncat_s(tmp_str, MAX_LOG_PATHNAME, cptr, (next - cptr));
#endif
		err = inm_mkdir(tmp_str, 0755);
		if (!(err == 0 || err == INM_EEXIST || err == INM_EROFS))
			INM_BUG_ON(1);

		strcat_s(tmp_str, MAX_LOG_PATHNAME, "/");
		cptr = next+1;
	}

	if (local_fname) {
		INM_KFREE(local_fname, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
		local_fname = NULL;
	}

	if (tmp_str) {
		INM_KFREE(tmp_str, MAX_LOG_PATHNAME, INM_KERNEL_HEAP);
		tmp_str = NULL;
	}
	return 0;
}

inm_s32_t 
validate_pname(char *pname)
{
	int error = 0;
	int i = 0;

	while (*pname && i < INM_GUID_LEN_MAX) {
		if (*pname == '/') {
			error = -EINVAL;
			break;
		}

		pname++;
		i++;
	}

	/* Make sure its null terminated */
	return *pname ? -EINVAL : 0;
}

inm_s32_t get_volume_size(int64_t *vol_size, inm_s32_t *inmage_status) {
	
	inm_s32_t status = 0;
	if (!vol_size || !inmage_status)
		return -EINVAL;

	*vol_size = (4096 * 4096);
	*inmage_status = 0;

	return status;
}

inm_s32_t
inm_find_msb(inm_u64_t x)
{
	inm_s32_t r = 64;

	if (!x)
		return 0;

	if (!(x & 0xffffffff00000000ULL)) {
		x <<= 32;
		r -= 32;
	}

	if (!(x & 0xffff000000000000ULL)) {
		x <<= 16;
		r -= 16;
	}

	if (!(x & 0xff00000000000000ULL)) {
		x <<= 8;
		r -= 8;
	}

	if (!(x & 0xf000000000000000ULL)) {
		x <<= 4;
		r -= 4;
	}

	if (!(x & 0xc000000000000000ULL)) {
		x <<= 2;
		r -= 2;
	}

	if (!(x & 0x8000000000000000ULL)) {
		x <<= 1;
		r -= 1;
	}

	return r;
}

/*
 * computing granularity, <512GB, 256K is the granularity
 * <1tb - 512k, <2tb - 1mb, <4tb - 2mb, and so on
 **/

inm_s32_t default_granularity_from_volume_size(inm_u64_t volume_size)
{

	inm_u64_t _scale = 0;
	inm_s32_t _rc = 0;

	_scale = volume_size-1;
	_scale >>= 30;

	/* <= 512G - 4k granularity, otherwise 16K */
	if (driver_ctx->dc_bmap_info.bitmap_512K_granularity_size &&
		  _scale > 
		  driver_ctx->dc_bmap_info.bitmap_512K_granularity_size) {
		_rc = SIXTEEN_K_SIZE;
	} else {
		_rc = FOUR_K_SIZE;
	}

	return _rc;
}

inm_ull64_t inm_atoull64(const char *name)
{
	inm_ull64_t val = 0;

	for (;; name++) {
		switch (*name) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = 10*val+(*name-'0');
			break;
		default:
			return val;
		}
	}
}

inm_u64_t inm_atoi64(const char *name)
{
	inm_u64_t val = 0;

	for (;; name++) {
		switch (*name) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = 10*val+(*name-'0');
			break;
		default:
			return val;
		}
	}
}

inm_u32_t inm_atoi(const char *name)
{
	inm_u32_t val = 0;

	for (;; name++) {
		switch (*name) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			val = 10*val+(*name-'0');
			break;
		default:
			return val;
		}
	}
}

inm_s32_t is_digit(const char *buf, inm_s32_t len)
{
	inm_s32_t i = 0;

	if (buf[len-1] == '\n')
		len--;

	while(i < len) {
		if(!isdigit(buf[i])) {
			return 0;
		}
		i++; 	
	}

	return 1;		
}

inm_s32_t get_path_memory(char **path)
{
	*path = (char *)INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP, 
							INM_KERNEL_HEAP);
	if(!*path)
		return 0;

	(*path)[0] = '\0';
	return 1;
}

void free_path_memory(char **path)
{
	if(*path == NULL)
		return;

	INM_KFREE(*path, INM_PATH_MAX, INM_KERNEL_HEAP);
	*path = NULL;
}

inm_s32_t 
filter_guid_name_val_get(char *pname, char *fname)
{
	char *s = NULL;
	inm_s32_t value = 0;

	s = INM_KMEM_CACHE_ALLOC_PATH(names_cachep, INM_KM_SLEEP, INM_PATH_MAX, 
							INM_KERNEL_HEAP);
	INM_BUG_ON(!s);
	strncpy_s(s, INM_PATH_MAX, pname, INM_PATH_MAX);
	strcat_s(&s[0], INM_PATH_MAX, "/");
	strcat_s(&s[0], INM_PATH_MAX, fname);
	read_value_from_file(s, &value);
 
	dbg("value from read for name %s val %d\n", s, value);
	INM_KMEM_CACHE_FREE_PATH(names_cachep, s, INM_KERNEL_HEAP);
	s = NULL;

	return ((inm_s32_t) value);
}

char *
filter_guid_name_string_get(char *guid, char *name, inm_s32_t len)
{
	char *s = NULL;
	char *buf = NULL;

	s = INM_KMEM_CACHE_ALLOC_PATH(names_cachep, INM_KM_SLEEP, INM_PATH_MAX, 
							INM_KERNEL_HEAP);
	INM_BUG_ON(!s);
	strncpy_s(s, INM_PATH_MAX, guid, INM_PATH_MAX);
	strcat_s(&s[0], INM_PATH_MAX, "/");
	strcat_s(&s[0], INM_PATH_MAX, name);
	read_string_from_file(s, buf, len);
 
	dbg("value from read for name %s val %s\n", name, buf);
	INM_KMEM_CACHE_FREE_PATH(names_cachep, s, INM_KERNEL_HEAP);
	s = NULL;

	return buf;
}

int
filter_ctx_name_val_set(target_context_t *ctxt, char *name, inm_s32_t value)
{
	inm_s32_t len = (NUM_CHARS_IN_INTEGER + 1);
	char buf[(NUM_CHARS_IN_INTEGER + 1)];
	inm_s32_t copied;

	INM_MEM_ZERO(buf, NUM_CHARS_IN_INTEGER + 1);
	copied = snprintf(buf, NUM_CHARS_IN_INTEGER + 1, "%d", value);

	if(!write_vol_attr(ctxt, name, (void *)buf, len)) {
		return -EINVAL;
	}
	return 0;
}


inm_device_t 
filter_dev_type_get(char *pname)
{
	inm_s32_t status = 0;
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered volume:%s",pname);
	}

	status = filter_guid_name_val_get(pname, "FilterDevType");
	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving volume:%s status:%d",pname, status);
	}
	return (inm_device_t) status;
}

int
filter_dev_type_set(target_context_t *ctxt, inm_device_t val)
{
	return filter_ctx_name_val_set(ctxt, "FilterDevType", val);
}

int
read_value_from_file(char *fname, inm_s32_t *val)
{
	inm_s32_t ret = 0;
	char *path = NULL, *buf = NULL;
	inm_u32_t len = 32, bytes_read = 0;

	if(!get_path_memory(&path)) {
		err("Failed to allocated memory path");
		return -EINVAL;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s", PERSISTENT_DIR, fname);

	dbg("Reading from file %s", path);

	buf = (void *)INM_KMALLOC(len, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!buf)
		goto free_path_buf;

	dbg("Allocated buffer of len %d", len);
	INM_MEM_ZERO(buf, len);

	if(!read_full_file(path, buf, len, &bytes_read)) {
		ret = 0;
		goto free_buf;
	}

	*val = inm_atoi(buf);

	ret = 1;

free_buf:
	if(buf)
		INM_KFREE(buf, len, INM_KERNEL_HEAP);
	buf = NULL;

free_path_buf:
	if(path)
		free_path_memory(&path);
	path = NULL;

	return ret;
}


char *
read_string_from_file(char *fname, char *buf, inm_s32_t len)
{
	char *path = NULL;
	int bytes_read = 0;
	buf = NULL;

	if (!get_path_memory(&path)) {
		 err("Failed to allocated memory path");
		 return NULL;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s", PERSISTENT_DIR, fname);

	dbg("Reading string from file %s", path);

	buf = (void *)INM_KMALLOC(len, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!buf)
	goto free_path_buf;

	dbg("Allocated buffer of len %d", len);
	INM_MEM_ZERO(buf, len);

	if (read_full_file(path, buf, len, &bytes_read)) {
		  goto free_buf;
	}

free_buf:
	if (buf) {
		 INM_KFREE(buf, len, INM_KERNEL_HEAP);
	}
	buf = NULL;

free_path_buf:
	if (path)
		free_path_memory(&path);
	path = NULL;

	return buf;
}

/* This fn gets the ts delta, and seqno deltas, and their overflow
 * info */
void
inm_get_ts_and_seqno_deltas(change_node_t *cnp, inm_tsdelta_t *tdp)
{
	inm_u64_t tdelta = 0, sdelta = 0; 
	
	tdp->td_oflow = FALSE;
	/* do not compute deltas for new change nodes */
	if (cnp->changes.change_idx) {
		  	TIME_STAMP_TAG_V2 ts;

		  	get_time_stamp_tag(&ts);
			  sdelta = ts.ullSequenceNumber - 
				  cnp->changes.start_ts.ullSequenceNumber;
			  tdelta = ts.TimeInHundNanoSecondsFromJan1601 -
			  cnp->changes.start_ts.TimeInHundNanoSecondsFromJan1601;

		/* check for overflow */
		if (tdelta >= 0xFFFFFFFE || sdelta >= 0xFFFFFFFE) {
			tdp->td_oflow = TRUE;
			sdelta = 0;
			tdelta = 0;
		} 
	} 
	tdp->td_time = (inm_u32_t) tdelta;
	tdp->td_seqno = (inm_u32_t) sdelta;
	if (cnp->vcptr->tc_cur_wostate != ecWriteOrderStateData) {
		  tdp->td_oflow = FALSE;
		  tdp->td_seqno = 0;
		  tdp->td_time = 0;
	}
}

/* persistent  store for timestamp and seq # */
/* called on every PERSISTENT_SEQNO_THRESHOLD diff */
void
inm_flush_ts_and_seqno(wqentry_t *wqep)
{
	inm_flush_ts_and_seqno_to_file(FALSE);
}

/* This fn flushes timestamp and seqno to disk 
 * called on every 1 sec */
void
inm_flush_ts_and_seqno_to_file(inm_u32_t force)
{
	inm_s32_t len = NUM_CHARS_IN_LONGLONG + 1, nr_bytes = 0;
	unsigned long lock_flag;
	static inm_u64_t prev_seqno = 0, prev_ts = 0;
	inm_u64_t cur_seqno = 0, cur_ts = 0;
	
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, lock_flag);
	if (!(driver_state & DRV_LOADED_FULLY)) {
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
				  				lock_flag);
		dbg("Driver is not initialized fully and so quitting without updating global timestamps");
		return;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, lock_flag);
	/*
	 * Reject any requests from worker thread once
	 * system shutdown in progress. System shutdown
	 * ioctl then uses force=1 to force write ts/seqno
	 */
	if (driver_ctx->sys_shutdown && !force)
		return;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->time_stamp_lock, lock_flag);
	cur_seqno = driver_ctx->last_time_stamp_seqno;
	cur_ts = driver_ctx->last_time_stamp;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->time_stamp_lock, lock_flag);
	
	/* Open handles for seqno */
	if (!driver_ctx->driver_time_stamp_handle) {
		flt_open_data_file(driver_ctx->driver_time_stamp,
				(INM_RDWR | INM_CREAT | INM_TRUNC | INM_SYNC),
				&driver_ctx->driver_time_stamp_handle);
	}
	/* Open handles for seqno */
	if (!driver_ctx->driver_time_stamp_seqno_handle) {
		flt_open_data_file(driver_ctx->driver_time_stamp_seqno,
				(INM_RDWR | INM_CREAT | INM_TRUNC | INM_SYNC),
				&driver_ctx->driver_time_stamp_seqno_handle);
	}

	if (prev_seqno == cur_seqno ||
			!driver_ctx->driver_time_stamp_seqno_handle) {
		return;
	}

	/* flush seq no. */
	INM_MEM_ZERO(driver_ctx->driver_time_stamp_buf, len);
	nr_bytes = snprintf(driver_ctx->driver_time_stamp_buf, len, "%llu",
			              (unsigned long long)cur_seqno);
	flt_write_file(driver_ctx->driver_time_stamp_seqno_handle,
			driver_ctx->driver_time_stamp_buf, 0, nr_bytes, NULL);
	prev_seqno = cur_seqno;

	if (prev_ts == cur_ts ||
			!driver_ctx->driver_time_stamp_handle) {
		return;
	}

	/* flush time stamp */
	INM_MEM_ZERO(driver_ctx->driver_time_stamp_buf, len);
	nr_bytes = snprintf(driver_ctx->driver_time_stamp_buf, len, "%llu",
			              (unsigned long long)cur_ts);
	flt_write_file(driver_ctx->driver_time_stamp_handle,
		driver_ctx->driver_time_stamp_buf, 0, nr_bytes, NULL);
}

void
inm_close_ts_and_seqno_file(void)
{
	/* Release handles on timestamp & seqno files */
	if (driver_ctx->driver_time_stamp_seqno_handle) {
#ifndef INM_AIX
		inm_restore_org_addr_space_ops(INM_HDL_TO_INODE(driver_ctx->driver_time_stamp_seqno_handle));
#endif
	
		INM_CLOSE_FILE(driver_ctx->driver_time_stamp_seqno_handle,
			             (INM_RDWR | INM_CREAT | INM_TRUNC | INM_SYNC));
		driver_ctx->driver_time_stamp_seqno_handle = NULL;
	}

	if (driver_ctx->driver_time_stamp_handle) {
#ifndef INM_AIX
		inm_restore_org_addr_space_ops(INM_HDL_TO_INODE(driver_ctx->driver_time_stamp_handle));
#endif
	
		INM_CLOSE_FILE(driver_ctx->driver_time_stamp_handle,
			             (INM_RDWR | INM_CREAT | INM_TRUNC | INM_SYNC));
		driver_ctx->driver_time_stamp_handle = NULL;
	}
}

inm_s32_t
inm_flush_clean_shutdown(inm_u32_t clean_shutdown)
{
	char *pathp = NULL, *bufp = NULL;
	inm_s32_t len = NUM_CHARS_IN_INTEGER + 1, nr_bytes = 0, err = 0;

	if (!get_path_memory(&pathp)) {
		err("Failed to allocate memory");
		goto exit;
	}

	bufp = (char *) INM_KMALLOC(len , INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!bufp) {
		err("Failed to allocate memory");
		goto exit;
	}
 
	INM_MEM_ZERO(bufp, len);
	snprintf(pathp, INM_PATH_MAX, "%s/%s/CleanShutdown", 
					PERSISTENT_DIR,COMMON_ATTR_NAME);
	nr_bytes=snprintf(bufp, len, "%u", clean_shutdown);
	driver_ctx->clean_shutdown = clean_shutdown;
	err = write_full_file(pathp, (void *)bufp, nr_bytes, NULL);

exit:
	if (bufp)
		INM_KFREE(bufp, len, INM_KERNEL_HEAP);

	if (pathp)
		free_path_memory(&pathp);

	return err;
}

/* fn computes index into io bucket array,
 * since io size 1k/4k is more frequent
 * care taken through this fn */
inm_u32_t 
inm_comp_io_bkt_idx(inm_u32_t io_sz)
{
	inm_s32_t nr_bit = 0;

	io_sz >>= 10; // converted into sectors
	if (io_sz <= 2) {
		//if io size <= 2k
		nr_bit=io_sz;
	} else if (io_sz == 4) {
		//if io size is 4k
		nr_bit = 3;
	} else {
		nr_bit = inm_find_msb((inm_u64_t) io_sz);
		if (io_sz & ~(1 << nr_bit)) {
			nr_bit++;
		}
		if (nr_bit > MAX_NR_IO_BUCKETS) {
			nr_bit = MAX_NR_IO_BUCKETS;
		}
	}

	return nr_bit;
}

inm_s32_t
write_vol_attr(target_context_t * ctxt, const char *file_name, void *buf, 
								inm_s32_t len)
{
	char *path = NULL;
	inm_s32_t wrote = 0, ret = 0;

	if (ctxt->tc_flags & VCF_VOLUME_STACKED_PARTIALLY)
		return -EROFS;

	if(!get_path_memory(&path)) {
		err("Failed to allocated memory path");
		return -EINVAL;
	}

	snprintf(path, INM_PATH_MAX, "%s/%s/%s", PERSISTENT_DIR, 
					ctxt->tc_pname, file_name);

	dbg("Writing to file %s", path);

	if(!write_full_file(path, (void *)buf, len, &wrote)) {
		if (!is_rootfs_ro()) 
			err("write to persistent store failed %s", path);
		ret = -EINVAL;
	} else {
		ret = 1;
	}

	free_path_memory(&path);

	return ret;
}

void
inm_free_host_dev_ctx(struct host_dev_context *hdcp)
{
	struct inm_list_head *ptr = NULL,*nextptr = NULL;
	host_dev_t *hdc_dev = NULL;

	if (hdcp) {
		inm_list_for_each_safe(ptr, nextptr, 
				 		&hdcp->hdc_dev_list_head) {
			inm_list_del(ptr);
			hdc_dev = inm_list_entry(ptr, host_dev_t, 
					  			hdc_dev_list);
			INM_KFREE(hdc_dev, sizeof(host_dev_t), 
					  		INM_KERNEL_HEAP);
		}
#ifdef INM_AIX
		INM_DESTROY_SPIN_LOCK(&hdcp->hdc_lock);
#endif
		INM_DESTROY_WAITQUEUE_HEAD(&hdcp->resync_notify);
		INM_KFREE(hdcp, sizeof(host_dev_ctx_t), INM_PINNED_HEAP);
		hdcp = NULL;
	}
}

inm_u32_t
is_AT_blocked()
{
	inm_u32_t ret = 0;

	if (strncmp(INM_CURPROC_COMM, "inm_dmit", strlen("inm_dmit")) &&
		strncmp(INM_CURPROC_COMM, "vx.sh", strlen("vx.sh")) &&
		strncmp(INM_CURPROC_COMM, "scsi_id", strlen("scsi_id")) &&
		strncmp(INM_CURPROC_COMM, "inm_scsi_id", strlen("inm_scsi_id")) &&
		strncmp(INM_CURPROC_COMM, "appservice", strlen("appservice")) &&
		strncmp(INM_CURPROC_COMM, "s2", strlen("s2")) &&
		(!(driver_ctx->flags & DC_FLAGS_INVOLFLT_LOAD) ||
		(strcmp(INM_CURPROC_COMM, "modprobe") && strcmp(INM_CURPROC_COMM, "insmod")))) {
		  
		ret =1;
	}
	return ret;
}

tag_info_t *
cnvt_tag_info2stream(tag_info_t * tag_info, inm_s32_t num_tags, inm_u32_t flag)
{
	tag_info_t *stag_info = NULL;
	unsigned short ltag_len = 0;
	unsigned long uuid_len = 0;
	unsigned char *taglenp = NULL;
	inm_u16_t i = 0;
	inm_u64_t processed_len;

	stag_info = (tag_info_t *)INM_KMALLOC(sizeof(tag_info_t) * num_tags,
		       			INM_KM_SLEEP | flag, INM_KERNEL_HEAP);
	if (!stag_info) {
		dbg("Failed to allocate tag info structure");
		goto out;
	}
	if (memcpy_s(stag_info, sizeof(tag_info_t) * num_tags, tag_info, 
					sizeof(tag_info_t) * num_tags)) {
		INM_KFREE(stag_info, sizeof(tag_info_t) * num_tags, INM_KERNEL_HEAP);
		stag_info = NULL;
		goto out;
	}
	if (!is_big_endian()) {
		goto out;
	}
	for (i = 0; i < num_tags; i++) {
		ltag_len = stag_info[i].tag_len;
		taglenp = (unsigned char *)&(stag_info[i].tag_len);
		taglenp[1] = ((ltag_len >> 8) & 0xFF);
		taglenp[0] = (ltag_len & 0xFF);

		processed_len = 0;
		while (processed_len < (inm_u64_t)(tag_info[i].tag_len)) {
			if(*(((unsigned char *)(tag_info[i].tag_name)) + processed_len + 2)) {
				taglenp = (unsigned char *)(stag_info[i].tag_name) + processed_len; 
				processed_len += *((unsigned long*)((tag_info[i].tag_name) + processed_len + 4));
			} else {
				taglenp = (unsigned char *)(stag_info[i].tag_name) + processed_len;
				processed_len += (*((unsigned char *)((tag_info[i].tag_name) + processed_len + 3)));
			}

			ltag_len = (unsigned short)(*((unsigned short*)taglenp));
			taglenp[1] = ((ltag_len >> 8) & 0xFF);
			taglenp[0] = ((ltag_len) & 0xFF);

			if(*(taglenp+2)){
				taglenp = ((unsigned char *)taglenp) + 4;
				uuid_len = (unsigned long)(*((unsigned long*)taglenp));
			
				taglenp[3] = ((uuid_len >> 24) & 0xFF);
				taglenp[2] = ((uuid_len >> 16) & 0xFF);
				taglenp[1] = ((uuid_len >> 8) & 0xFF);
				taglenp[0] = (uuid_len & 0xFF);
			}
		}
	}

out:

#ifdef INM_DEBUG
	dbg("Printing old tag struct");
	print_tag_struct(tag_info, num_tags);
	dbg("Printing new tag struct");
	print_tag_struct(stag_info, num_tags);
#endif

	return stag_info;
}

tag_info_t *
cnvt_stream2tag_info(tag_info_t *stag_info, inm_s32_t num_tags)
{
	tag_info_t *tag_info = NULL;
	unsigned short ltag_len = 0;
	unsigned char *taglenp = NULL;
	unsigned long uuid_len = 0;
	unsigned long *ltag_lenp = NULL;
	unsigned short *lstag_lenp = NULL;
	inm_u16_t i = 0;
	inm_u64_t processed_len;

	tag_info = (tag_info_t *)INM_KMALLOC(sizeof(tag_info_t) * num_tags, 
					INM_KM_NOSLEEP, INM_KERNEL_HEAP);
	if (!tag_info){
		 goto out;
	}
	if (memcpy_s(tag_info, sizeof(tag_info_t) * num_tags, stag_info, 
					sizeof(tag_info_t) * num_tags)) {
		INM_KFREE(tag_info, sizeof(tag_info_t) * num_tags, INM_KERNEL_HEAP);
		stag_info = NULL;
		goto out;
	}
	if(!is_big_endian()){
		goto out;
	}
	for (i = 0; i < num_tags; i++){
		taglenp = (unsigned char *)&(tag_info[i].tag_len);
		ltag_len = 0;
		ltag_len |= (((unsigned short)taglenp[1]) >> 8);
		ltag_len |= ((unsigned short)taglenp[0]);
		tag_info[i].tag_len = ltag_len;

		processed_len = 0;
		while (processed_len < tag_info[i].tag_len){
			if(*(((unsigned char *)(tag_info[i].tag_name)) + processed_len + 2)){
				taglenp = (unsigned char *)(tag_info[i].tag_name) + processed_len;
				processed_len += *((unsigned long*)((tag_info[i].tag_name) + 4));
			} else {
				taglenp = (unsigned char *)(tag_info[i].tag_name) + processed_len;
				processed_len += (unsigned long)(*((unsigned char *)((tag_info[i].tag_name) + 3)));
			}

			ltag_len = 0;
			ltag_len |= (((unsigned short)taglenp[0]) >> 8);
			ltag_len |= ((unsigned short)taglenp[1]);
			lstag_lenp = (unsigned short *) taglenp;
			*lstag_lenp = ltag_len;

			if(*(taglenp+2)){
				taglenp = ((unsigned char *)taglenp) + 4;
				uuid_len = 0;
			
				uuid_len |= (((unsigned long)taglenp[0]) >> 24);
				uuid_len |= (((unsigned long)taglenp[1]) >> 16);
				uuid_len |= (((unsigned long)taglenp[2]) >> 8);
				uuid_len |= (((unsigned long)taglenp[3]));
				ltag_lenp = (unsigned long *) taglenp;
				*ltag_lenp = uuid_len;
			}
		}
	}

out:

#ifdef INM_DEBUG
	dbg("Printing old tag struct");
	print_tag_struct(stag_info, num_tags);
	dbg("Printing new tag struct");
	print_tag_struct(tag_info, num_tags);
#endif

	return tag_info;
}

#ifdef INM_DEBUG
static void print_tag_struct(tag_info_t *tag_info, inm_s32_t num_tags)
{
	inm_u32_t i = 0;

	if(!tag_info){
		goto out;
	}
	for (i = 0 ; i < num_tags; i++){
		dbg("Tag %u's tag len is %u", i, tag_info[i].tag_len);
	}

out:
	return;
}
#endif

inm_s32_t
inm_form_tag_cdb(target_context_t *tcp, tag_info_t *tag_info, inm_s32_t num_tags)
{
	inm_s32_t error = 0;
	unsigned char cmd[16];
	inm_u32_t buflen = 0;
	inm_u32_t flag = INM_KM_SLEEP;
	tag_info_t *stag_info = NULL;

	if (!tcp){
		 error = 1;
		 goto out;
	}

	IS_DMA_FLAG(tcp, flag);
	stag_info = cnvt_tag_info2stream(tag_info, num_tags, flag);
	buflen = num_tags * sizeof(tag_info_t);

	cmd[0] = VACP_CDB;
	cmd[1] = (buflen >> 24) & 0xFF;
	cmd[2] = (buflen >> 16) & 0xFF;
	cmd[3] = (buflen >> 8) & 0xFF;
	cmd[4] = (buflen) & 0xFF;
	cmd[5] = 0x0;
	cmd[6] = 0x0;
	cmd[7] = 0x0;
	cmd[8] = 0x0;
	cmd[9] = 0x0;
	cmd[10] = 0x0;
	cmd[11] = 0x0;
	cmd[12] = 0x0;
	cmd[13] = 0x0;
	cmd[14] = 0x0;
	cmd[15] = 0x0;
	error = inm_all_AT_cdb_send(tcp, cmd, VACP_CDB_LEN, 1, 
				(unsigned char *)stag_info, buflen, 0);
	if (error){
		INM_ATOMIC_INC(&(tcp->tc_stats.num_tags_dropped));
	}

out:
	dbg("exiting form_tag_cdb with %d", error);

	if (stag_info){
		INM_KFREE(stag_info, sizeof(tag_info_t) * num_tags, 
							INM_KERNEL_HEAP);
	}
	return 0;
}

inm_s32_t
inm_heartbeat_cdb(target_context_t *tcp)
{
	inm_s32_t error = 0;
	unsigned char cmd[16];

	if (!tcp){
		error = 1;
		goto out;
	}
	cmd[0] = HEARTBEAT_CDB;
	cmd[1] = 0x0;
	cmd[2] = 0x0;
	cmd[3] = 0x0;
	cmd[4] = 0x0;
	cmd[5] = 0x0;
	cmd[6] = 0x0;
	cmd[7] = 0x0;
	cmd[8] = 0x0;
	cmd[9] = 0x0;
	cmd[10] = 0x0;
	cmd[11] = 0x0;
	cmd[12] = 0x0;
	cmd[13] = 0x0;
	cmd[14] = 0x0;
	cmd[15] = 0x0;

	error = try_reactive_offline_AT_path(tcp, cmd, HEARTBEAT_CDB_LEN, 1, 
							NULL, 0, 0);
	if(!error){
		goto out;
	}
	error = inm_all_AT_cdb_send(tcp, cmd, HEARTBEAT_CDB_LEN, 1, NULL, 0, 0);

out:
	dbg("exiting heart_beat_cdb with %d", error);
	return error;
}

static inm_u32_t
is_big_endian(void)
{
	unsigned short i = 1;
	char *c = (char *)&i;
	unsigned short j = (unsigned short)(*c);
	inm_u32_t ret = j?0:1;

	return ret;
}

inm_s32_t
inm_erase_resync_info_from_persistent_store(char *pname)
{
	inm_s32_t err = 0;
	char *parent = NULL, *fname = NULL;

	if(!get_path_memory(&fname)) {
		err("malloc failed");
		err = INM_ENOMEM;
		return err;
	}

	if(!get_path_memory(&parent)) {
		free_path_memory(&fname);
		err("malloc failed");
		err = INM_ENOMEM;
		return err;
	}

	snprintf(parent, INM_PATH_MAX, "%s/%s", PERSISTENT_DIR, pname);

	snprintf(fname, INM_PATH_MAX, "%s/VolumeResyncRequired", parent);
	inm_unlink(fname, parent);
	snprintf(fname, INM_PATH_MAX, "%s/VolumeOutOfSyncCount", parent);
	inm_unlink(fname, parent);
	snprintf(fname, INM_PATH_MAX, "%s/VolumeOutOfSyncErrorCode", parent);
	inm_unlink(fname, parent);
	snprintf(fname, INM_PATH_MAX, "%s/VolumeOutOfSyncErrorStatus", parent);
	inm_unlink(fname, parent);
	snprintf(fname, INM_PATH_MAX, "%s/VolumeOutOfSyncTimeStamp", parent);
	inm_unlink(fname, parent);

	free_path_memory(&fname);
	free_path_memory(&parent);

	return err;
}

void 
inm_get_tag_marker_guid(char *tag_buf, inm_u32_t tag_buf_len, 
			               char *guid, inm_u32_t guid_len)
						
{
	STREAM_REC_HDR_4B *hdr = NULL;

	hdr = (STREAM_REC_HDR_4B *)tag_buf;

	if (hdr->ucFlags & STREAM_REC_FLAGS_LENGTH_BIT) {
		tag_buf += sizeof(STREAM_REC_HDR_8B);
		tag_buf_len -= sizeof(STREAM_REC_HDR_8B);
	} else {
		tag_buf += sizeof(STREAM_REC_HDR_4B);
		tag_buf_len -= sizeof(STREAM_REC_HDR_8B);
	}

	memcpy_s(guid, guid_len, tag_buf, tag_buf_len);
}

#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 5)

/* Make sure compiler does printf style format checking */
int sprintf_s(char *buf, size_t bufsz, const char *fmt, ...) \
	__attribute__ ((format(printf, 3, 4)));

int
sprintf_s(char *buf, size_t bufsz, const char *fmt, ...)
{
	int retval = -1;
	va_list args;

	if( buf && bufsz > 0 && fmt ) {
		va_start(args, fmt);

		retval = vsnprintf(buf, bufsz, fmt, args);
		/* If buffer not adequate, return error */
		if( retval >= bufsz )
			retval = -1;

		va_end(args);
	}

	if( retval == -1 ) {
		if( buf && bufsz )
			*buf = '\0';
	}

	return retval;
}

#endif
