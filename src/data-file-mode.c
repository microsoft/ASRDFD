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
 * File       : data-file-mode.c
 *
 * Description: Data File Mode support.
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
#include "utils.h"
#include "tunable_params.h"
#include "svdparse.h"
#include "file-io.h"
#include "osdep.h"

extern driver_context_t *driver_ctx;
extern void finalize_data_stream(change_node_t *);

static_inline void set_next_file_thread(data_file_flt_t *flt_ctxt)
{
	INM_BUG_ON(flt_ctxt->next_thr == NULL);

	if(flt_ctxt->next_thr->next.next == &(flt_ctxt->dfm_thr_hd)) {
		flt_ctxt->next_thr =
			DFM_THREAD_ENTRY(flt_ctxt->dfm_thr_hd.next);
	} else {
		flt_ctxt->next_thr = 
			DFM_THREAD_ENTRY(flt_ctxt->next_thr->next.next);
	}
}

data_file_node_t *
inm_alloc_data_file_node(inm_u32_t flags)
{
	data_file_node_t *file_node = NULL;

#ifndef INM_AIX
	file_node = INM_KMALLOC(sizeof(data_file_node_t), flags,
							INM_KERNEL_HEAP);
#else
	file_node = INM_KMEM_CACHE_ALLOC(
			driver_ctx->dc_host_info.data_file_node_cache, flags);
#endif

	return file_node;
}

void inm_free_data_file_node(data_file_node_t *file_node)
{
#ifndef INM_AIX
	INM_KFREE(file_node, sizeof(data_file_node_t), INM_KERNEL_HEAP);
#else
	INM_KMEM_CACHE_FREE(driver_ctx->dc_host_info.data_file_node_cache,
								file_node);
#endif
}

inm_s32_t queue_chg_node_to_file_thread(target_context_t *tgt_ctxt,
				  change_node_t *node)
{
	data_file_flt_t    *flt_ctxt = &tgt_ctxt->tc_dfm;
	data_file_thread_t *thr = flt_ctxt->next_thr;
	data_file_node_t   *file_node = NULL;
	unsigned long lock_flag = 0;

	file_node = inm_alloc_data_file_node(INM_KM_NOSLEEP);
	if(!file_node)
	return 0;

	INM_ATOMIC_INC(&thr->pending);
	tgt_ctxt->tc_stats.num_pgs_in_dfm_queue += node->changes.num_data_pgs;

	ref_chg_node(node);
	file_node->chg_node = node;
	
	INM_SPIN_LOCK_IRQSAVE(&thr->wq_list_lock, lock_flag);
	inm_list_add_tail(&file_node->next, &thr->wq_hd);
	INM_SPIN_UNLOCK_IRQRESTORE(&thr->wq_list_lock, lock_flag);

	set_next_file_thread(flt_ctxt);
#ifdef INM_AIX
	INM_COMPLETE(&thr->compl);
#else
	INM_UP(&thr->mutex);
#endif

	return 1;
}

inm_s32_t
inm_unlink_datafile(target_context_t *tgt_ctxt, char *data_file_name)
{
	inm_s32_t error = 0;
	char *parent = NULL;

	if (!get_path_memory(&parent)) {
		err("Cannot alloc parent mem: %s", data_file_name);
		error = -ENOMEM;
	} else {
		sprintf_s(parent, INM_PATH_MAX, "%s/%s", 
				  tgt_ctxt->tc_data_log_dir,
				  tgt_ctxt->tc_datafile_dir_name);
		dbg("Parent: %s", parent);

		error = inm_unlink(data_file_name, parent);

		free_path_memory(&parent);
	}

	return error;
}

static_inline char *generate_data_file_name(change_node_t *node, 
					    target_context_t *tgt_ctxt)
{
	char *filename = NULL;
	char *log_dir = NULL, *fmt_strp = NULL;
	unsigned long lock_flag = 0;

	filename = (char*)INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP,
							INM_KERNEL_HEAP);
	if(!filename)
	return NULL;

	log_dir = (char *)INM_KMALLOC(INM_PATH_MAX, INM_KM_SLEEP,
							INM_KERNEL_HEAP);
	if (!log_dir) {
		INM_KFREE(filename, INM_PATH_MAX, INM_KERNEL_HEAP);
		return NULL;
	}

	INM_SPIN_LOCK_IRQSAVE(&tgt_ctxt->tc_tunables_lock, lock_flag);
	if (strcpy_s(log_dir, INM_PATH_MAX, tgt_ctxt->tc_data_log_dir)) {
		INM_SPIN_UNLOCK_IRQRESTORE(&tgt_ctxt->tc_tunables_lock, 
								lock_flag);
		INM_KFREE(filename, INM_PATH_MAX, INM_KERNEL_HEAP);
		INM_KFREE(log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
		return NULL;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&tgt_ctxt->tc_tunables_lock, lock_flag);

	if(0 == (tgt_ctxt->tc_flags & VCF_DATAFILE_DIR_CREATED)) {
		inm_mkdir(log_dir, 0700);
		snprintf(filename, 2048, "%s/%s", log_dir,
						tgt_ctxt->tc_datafile_dir_name);
		inm_mkdir(filename, 0700);
		volume_lock(tgt_ctxt);
		tgt_ctxt->tc_flags |= VCF_DATAFILE_DIR_CREATED;
		volume_unlock(tgt_ctxt);
	}
	if (node->flags & (KDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE |
				KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE)) {
		if (ecWriteOrderStateData == node->wostate)
			fmt_strp = "%s/%s/pre_completed_diff_S%llu_%llu_E%llu_%llu_WC%llu.dat";
		else
			fmt_strp = "%s/%s/pre_completed_diff_S%llu_%llu_E%llu_%llu_MC%llu.dat";
	} else {
		if (ecWriteOrderStateData == node->wostate)
			fmt_strp = "%s/%s/pre_completed_diff_S%llu_%llu_E%llu_%llu_WE%llu.dat";
		else
			fmt_strp = "%s/%s/pre_completed_diff_S%llu_%llu_E%llu_%llu_ME%llu.dat";
	}	

	snprintf(filename, 2048, fmt_strp,
		 log_dir, tgt_ctxt->tc_datafile_dir_name,
		 node->changes.start_ts.TimeInHundNanoSecondsFromJan1601,
		 node->changes.start_ts.ullSequenceNumber,
		 node->changes.end_ts.TimeInHundNanoSecondsFromJan1601,
		 node->changes.end_ts.ullSequenceNumber,
  	     (inm_u64_t)node->seq_id_for_split_io);

	INM_KFREE(log_dir, INM_PATH_MAX, INM_KERNEL_HEAP);
	return filename;	
}

#ifdef INM_AIX
#include "filter_host.h"

static_inline inm_s32_t write_changes_to_file(void *hdl, char *fname,
				change_node_t *node, inm_u64_t *file_offset)
{
	data_page_t *data_pg = PG_ENTRY(node->data_pg_head.next);
	inm_s32_t length = get_strm_len(node);
	char *buffer = NULL;
	inm_s32_t success = 0;
	inm_u32_t bytes_written = 0;
	offset_t file_len;
	inm_rec_write_meta_t *rec_write_meta;
	int flag;

	*file_offset = 0;

	buffer = INM_KMALLOC_ALIGN(INM_PAGESZ, INM_KM_SLEEP, INM_PAGESHIFT,
							INM_KERNEL_HEAP);
	if(!buffer)
		return success;

	INM_BUG_ON(inm_list_empty(&node->data_pg_head));

	rec_write_meta = INM_KMALLOC(sizeof(inm_rec_write_meta_t),
						INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!rec_write_meta){
		INM_KFREE(buffer, INM_PAGESZ, INM_KERNEL_HEAP);
		return success;
	}

	if(INM_PIN(rec_write_meta, sizeof(inm_rec_write_meta_t))){
		INM_KFREE(buffer, INM_PAGESZ, INM_KERNEL_HEAP);
		INM_KFREE(rec_write_meta, sizeof(inm_rec_write_meta_t),
							INM_KERNEL_HEAP);
		return success;
	}

	INM_MEM_ZERO(rec_write_meta, sizeof(inm_rec_write_meta_t));

	rec_write_meta->buf = buffer;
	rec_write_meta->len = INM_PAGESZ;
	rec_write_meta->pid = getpid();

	INM_SPIN_LOCK(&driver_ctx->recursive_writes_meta_list_lock, flag);
	inm_list_add_tail(&rec_write_meta->list,
				&driver_ctx->recursive_writes_meta_list);
	INM_SPIN_UNLOCK(&driver_ctx->recursive_writes_meta_list_lock, flag);

	file_len = length;

	while(length > 0) {
		inm_s32_t len;
		char *src;

		INM_MEM_ZERO(buffer, INM_PAGESZ);

		len = MIN(INM_PAGESZ, length);
		INM_PAGE_MAP(src, data_pg->page, KM_USER0);
		if (memcpy_s(buffer, len, src, len)) {
			INM_PAGE_UNMAP(src, data_pg->page, KM_USER0);
			break;
		}
		INM_PAGE_UNMAP(src, data_pg->page, KM_USER0);

		rec_write_meta->initialised = 1;

		if(!flt_write_file(hdl, buffer, *file_offset,
					INM_PAGESZ, &bytes_written)){
			break;
		}

		data_pg = PG_ENTRY(data_pg->next.next);
		length -= len;
		*file_offset += len;
	}

	INM_SPIN_LOCK(&driver_ctx->recursive_writes_meta_list_lock, flag);
	inm_list_del(&rec_write_meta->list);
	INM_SPIN_UNLOCK(&driver_ctx->recursive_writes_meta_list_lock, flag);

	if(length == 0){
		struct file *file = hdl;

		VNOP_FTRUNC(file->f_vnode, file->f_flag, file_len, NULL, file->f_cred);
		success = 1;
	}

	INM_UNPIN(rec_write_meta, sizeof(inm_rec_write_meta_t));
	INM_KFREE(rec_write_meta, sizeof(inm_rec_write_meta_t),
							INM_KERNEL_HEAP);

	INM_KFREE(buffer, INM_PAGESZ, INM_KERNEL_HEAP);

	return success;
}

#else
static_inline inm_s32_t write_changes_to_file(void *hdl, char *fname, 
				change_node_t *node, inm_u64_t *file_offset)
{
	data_page_t *data_pg = PG_ENTRY(node->data_pg_head.next);
	inm_s32_t length = get_strm_len(node);
	char *buffer = NULL;
	inm_s32_t success = 0;
	inm_u32_t bytes_written = 0;

	*file_offset = 0;

	buffer = INM_KMALLOC(INM_PAGESZ, INM_KM_SLEEP, INM_KERNEL_HEAP);
	if(!buffer)
		return success;

	INM_BUG_ON(inm_list_empty(&node->data_pg_head));

	while(length > 0) {
		inm_s32_t len;
		char *src;

		len = MIN(INM_PAGESZ, length);
		INM_PAGE_MAP(src, data_pg->page, KM_USER0);
		if (memcpy_s(buffer, len, src, len)) {
			INM_PAGE_UNMAP(src, data_pg->page, KM_USER0);
			break;
		}
		INM_PAGE_UNMAP(src, data_pg->page, KM_USER0);

		if(!flt_write_file(hdl, buffer, *file_offset,
				   len, &bytes_written))
			break;

		data_pg = PG_ENTRY(data_pg->next.next);
		length -= len;
		*file_offset += len;
	}

	if(length == 0)
		success = 1;

	INM_KFREE(buffer, INM_PAGESZ, INM_KERNEL_HEAP);

	return success;
}
#endif

static_inline void write_file_node(data_file_node_t *file_node, 
				   target_context_t *tgt_ctxt)
{
	change_node_t *node = file_node->chg_node;
	char *fname = NULL;
	void *hdl = NULL;
	inm_u64_t file_sz = 0;
	inm_s32_t err = 0;

	INM_DOWN(&node->mutex);

	do {
		volume_lock(tgt_ctxt);

		if((0 == (node->flags & CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE)) ||
		   (node->flags & CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2)) {
			volume_unlock(tgt_ctxt);
			break;
		}

		if(tgt_ctxt->tc_stats.dfm_bytes_to_disk >= 
				tgt_ctxt->tc_data_to_disk_limit) {
			volume_unlock(tgt_ctxt);
			break;	
		}

		if(0 == (node->flags & CHANGE_NODE_DATA_STREAM_FINALIZED))
			finalize_data_stream(node);

		volume_unlock(tgt_ctxt);
		
		fname = generate_data_file_name(file_node->chg_node, tgt_ctxt);
		if(!fname) {
			break;
		}
		
#ifdef INM_AIX
		if(!flt_open_data_file(fname, (INM_RDWR | INM_CREAT | INM_DIRECT),
									&hdl)) {
#else
		if(!flt_open_data_file(fname, (INM_RDWR | INM_CREAT), &hdl)) {
#endif
			err = 1; 
			break;
		}

		if(!write_changes_to_file(hdl, fname, node, &file_sz))
			err = 1;			
		
#ifndef INM_AIX
		inm_restore_org_addr_space_ops(INM_HDL_TO_INODE(hdl));
#endif
		
		INM_CLOSE_FILE(hdl, (INM_RDWR | INM_CREAT));
		hdl = NULL;

		if (!err) {
			volume_lock(tgt_ctxt);
			if (node->flags & CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2) {
				volume_unlock(tgt_ctxt);
				inm_unlink_datafile(tgt_ctxt, fname);
				break;
			}
			tgt_ctxt->tc_stats.num_pages_allocated -=
				node->changes.num_data_pgs;
			inm_rel_data_pages(tgt_ctxt, &node->data_pg_head,
						       node->changes.num_data_pgs);
			INM_INIT_LIST_HEAD(&node->data_pg_head);
			node->changes.num_data_pgs = 0;
			node->type = NODE_SRC_DATAFILE;
			tgt_ctxt->tc_stats.dfm_bytes_to_disk += file_sz;
			node->data_file_name = fname;
			node->data_file_size = file_sz;
			INM_ATOMIC_INC(&tgt_ctxt->tc_stats.num_dfm_files);
			INM_ATOMIC_INC(&tgt_ctxt->tc_stats.num_dfm_files_pending);
			volume_unlock(tgt_ctxt);
		} else {
			inm_unlink_datafile(tgt_ctxt, fname);
		}
	} while(0);			

	volume_lock(tgt_ctxt);
	node->flags &= ~CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE;
	tgt_ctxt->tc_stats.num_pgs_in_dfm_queue -= node->changes.num_data_pgs;
	volume_unlock(tgt_ctxt);
	
	if (err && fname)
		INM_KFREE(fname, INM_PATH_MAX, INM_KERNEL_HEAP);	
	INM_UP(&node->mutex);
	deref_chg_node(node);
	file_node->chg_node = NULL;
}

static_inline void process_file_writer_op(data_file_thread_t * thr)
{
	data_file_node_t *file_node = NULL;
	unsigned long lock_flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&thr->wq_list_lock, lock_flag);
	INM_BUG_ON(inm_list_empty(&thr->wq_hd));
	file_node = inm_list_entry(thr->wq_hd.next, data_file_node_t, next);
	inm_list_del(thr->wq_hd.next);
	INM_SPIN_UNLOCK_IRQRESTORE(&thr->wq_list_lock, lock_flag);
	write_file_node(file_node, thr->ctxt);
	if (file_node){
		inm_free_data_file_node(file_node);
	}
}

#ifdef INM_AIX
void
data_file_writer_thread_func(int flag, void *args, int arg_len)
{
	data_file_thread_t *thr = *(data_file_thread_t **)args;
#else
int
data_file_writer_thread_func(void *args)
{
	data_file_thread_t *thr = (data_file_thread_t *)args;
#endif
	dbg("thr = %p", thr);

	INM_DAEMONIZE("fw%d", inm_dev_id_get((target_context_t*)thr->ctxt),
								thr->id);

	INM_SET_USER_NICE(20);

	INM_ATOMIC_INC(&thr->pending);

	dbg("Data File Writer Thread %d started", thr->id);

	INM_COMPLETE(&thr->ctxt->exit);
	for(;;) {
#ifdef INM_AIX
	INM_WAIT_FOR_COMPLETION(&thr->compl);
#else
	INM_DOWN(&thr->mutex);
#endif

	if(!INM_ATOMIC_READ(&thr->pending))
		break;
		
	process_file_writer_op(thr);

	if(INM_ATOMIC_DEC_AND_TEST(&thr->pending))
		break;
	}

	dbg("Data File Writer Thread with id %d exiting", thr->id);

	/* signal the process waiting for completion. */
	INM_COMPLETE(&thr->exit);
	return 0;
}

inm_s32_t is_data_files_enabled(target_context_t *tgt_ctxt)
{
	if(!driver_ctx->service_supports_data_filtering)
		return 0;

	if(!driver_ctx->tunable_params.enable_data_file_mode)
		return 0;

	if(tgt_ctxt->tc_flags & VCF_DATA_FILES_DISABLED)
		return 0;

	return 1;
}

inm_s32_t init_data_file_flt_ctxt(target_context_t *tgt_ctxt)
{
	data_file_thread_t *thr;
	inm_s32_t thr_created = 0, thr_to_create = 0;
	data_file_flt_t *flt_ctxt = &tgt_ctxt->tc_dfm;

#ifdef INM_AIX
	char pname[30];
#endif

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("entered ctx:%p volume:%s",tgt_ctxt, tgt_ctxt->tc_guid);
	}

	INM_INIT_LIST_HEAD(&flt_ctxt->dfm_thr_hd);
	INM_INIT_SEM(&flt_ctxt->list_mutex);
	flt_ctxt->num_dfm_threads = 0;
	flt_ctxt->next_thr = NULL;
	INM_ATOMIC_SET(&flt_ctxt->terminating, 0);

	if (tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP ||
		!is_data_files_enabled(tgt_ctxt)) {
		return 0;
	}

	thr_to_create = DEFAULT_NUMBER_OF_FILEWRITERS_PER_VOLUME;

	INM_DOWN(&flt_ctxt->list_mutex);

	/* Create threads */
	while(thr_created != thr_to_create) {
		thr = (data_file_thread_t *)INM_KMALLOC(sizeof(data_file_thread_t),
			   INM_KM_NOSLEEP, INM_PINNED_HEAP);
		if(!thr) {
			err("Failed to allocate memory for data_file_thread_t");
			break;
		}

		thr->id =  thr_created;		
		dbg("DFM id %d", thr->id);
		INM_ATOMIC_SET(&thr->pending, 0);
		inm_list_add(&thr->next, &flt_ctxt->dfm_thr_hd);
		INM_INIT_COMPLETION(&thr->exit);	
		INM_INIT_COMPLETION(&tgt_ctxt->exit);
#ifdef INM_AIX
		INM_INIT_COMPLETION(&thr->compl);
#else
		INM_INIT_SEM_LOCKED(&thr->mutex);
#endif
		INM_INIT_SPIN_LOCK(&thr->wq_list_lock);
		INM_INIT_LIST_HEAD(&thr->wq_hd);
		get_tgt_ctxt(tgt_ctxt);
		thr->ctxt = (void *)tgt_ctxt;
 
#ifdef INM_SOLARIS
	if(INM_KERNEL_THREAD(data_file_writer_thread_func, thr, 0, 0) == NULL) {
#endif
#ifdef INM_LINUX
	if(INM_KERNEL_THREAD(thr->thread_task, data_file_writer_thread_func, thr, 0,
				"fw%d", inm_dev_id_get(tgt_ctxt)) < 0) {
#endif
#ifdef INM_AIX
	sprintf(pname, "fw%d", inm_dev_id_get(tgt_ctxt));
	info("process name = %s", pname);
	if(INM_KERNEL_THREAD(data_file_writer_thread_func, &thr, sizeof(thr),
								pname) < 0) {
#endif
			inm_list_del(&thr->next);
				put_tgt_ctxt(tgt_ctxt);
				INM_KFREE(thr, sizeof(data_file_thread_t),
							INM_PINNED_HEAP);
			err("Failed to create data file writer thread");
			break;
		}

		INM_WAIT_FOR_COMPLETION(&tgt_ctxt->exit);
		thr_created++;
	}

	INM_UP(&flt_ctxt->list_mutex);

	if (thr_created > 0) {
		flt_ctxt->next_thr = 
		DFM_THREAD_ENTRY(flt_ctxt->dfm_thr_hd.next);
		flt_ctxt->num_dfm_threads = thr_created;
		return 0;
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_BMAP))){
		info("leaving ctx:%p volume:%s",tgt_ctxt, tgt_ctxt->tc_guid);
	}
	return 1;
}

void flush_work_items(target_context_t *tgt_ctxt, data_file_thread_t *thr)
{
	unsigned long lock_flag;
	struct inm_list_head *ptr, *hd, *nextptr;
	data_file_node_t *file_node = NULL;

	INM_SPIN_LOCK_IRQSAVE(&thr->wq_list_lock, lock_flag);
	hd = &thr->wq_hd;

	inm_list_for_each_safe(ptr, nextptr, hd) {
	change_node_t *node = NULL;
	file_node = inm_list_entry(ptr, data_file_node_t, next);
	node = file_node->chg_node;
	inm_list_del(ptr);
	INM_ATOMIC_DEC(&thr->pending);
	INM_SPIN_LOCK_IRQSAVE(&tgt_ctxt->tc_lock, tgt_ctxt->tc_lock_flag);
	node->flags &= ~CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE;
	tgt_ctxt->tc_stats.num_pgs_in_dfm_queue -= node->changes.num_data_pgs;
	INM_SPIN_UNLOCK_IRQRESTORE(&tgt_ctxt->tc_lock, tgt_ctxt->tc_lock_flag);
	deref_chg_node(node);
	inm_free_data_file_node(file_node);
	}
	
	INM_SPIN_UNLOCK_IRQRESTORE(&thr->wq_list_lock, lock_flag);
}

void free_data_file_flt_ctxt(target_context_t *tgt_ctxt)
{
	struct inm_list_head *ptr, *hd, *nextptr;
	data_file_thread_t *thr;
	data_file_flt_t *flt_ctxt = &tgt_ctxt->tc_dfm;

	if (tgt_ctxt->tc_dev_type == FILTER_DEV_MIRROR_SETUP ||
		!is_data_files_enabled(tgt_ctxt)) {
	return;
	}

	INM_DOWN(&flt_ctxt->list_mutex);

	hd = &(tgt_ctxt->tc_dfm.dfm_thr_hd);

	inm_list_for_each_safe(ptr, nextptr, hd) {
		thr = inm_list_entry(ptr, data_file_thread_t, next);
		flush_work_items(tgt_ctxt, thr);
		if(INM_ATOMIC_DEC_AND_TEST(&thr->pending))
#ifdef INM_AIX
			INM_COMPLETE(&thr->compl);
#else
			INM_UP(&thr->mutex);
#endif

		INM_WAIT_FOR_COMPLETION(&thr->exit);
		INM_KTHREAD_STOP(thr->thread_task);

		inm_list_del(&thr->next);
		put_tgt_ctxt((target_context_t *)thr->ctxt);
		INM_DESTROY_COMPLETION(&thr->exit);
		INM_KFREE(thr, sizeof(data_file_thread_t), INM_PINNED_HEAP);
	}

	INM_DESTROY_COMPLETION(&tgt_ctxt->exit);
	INM_UP(&flt_ctxt->list_mutex);
}

inm_s32_t should_write_to_datafile(target_context_t *tgt_ctxt)
{
	inm_s32_t num_pages_used;
	unsigned long lock_flag = 0;
	inm_u32_t is_vol_thres_hit = 0;
	inm_u32_t is_drv_thres_hit = 0;
	inm_u32_t drv_thres_pages = 0;
	inm_u32_t vol_pg_thres_df = 0;
	inm_u32_t data_pool_size = 0;
	inm_u32_t total_unres_pages = 0;

	if (tgt_ctxt->tc_flags & VCF_VOLUME_STACKED_PARTIALLY)
		return 0;

	/* caculate the volume threshold based on volumes min data pool size */
	vol_pg_thres_df = 
		(((driver_ctx->tunable_params.volume_percent_thres_for_filewrite)*
		(tgt_ctxt->tc_reserved_pages))/100);

	if((driver_ctx->service_state != SERVICE_RUNNING) || 
		!is_data_files_enabled(tgt_ctxt)) {
		return 0;
	}

	num_pages_used = (tgt_ctxt->tc_stats.num_pages_allocated -
				tgt_ctxt->tc_stats.num_pgs_in_dfm_queue);	

	if (num_pages_used > vol_pg_thres_df) {
if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		dbg("Crossed volume data pages threshold for file write");
}
		is_vol_thres_hit = 1;
	}

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->tunables_lock, lock_flag);
	drv_thres_pages = driver_ctx->tunable_params.free_pages_thres_for_filewrite;
	data_pool_size = driver_ctx->tunable_params.data_pool_size;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->tunables_lock, lock_flag);
	data_pool_size <<= (MEGABYTE_BIT_SHIFT - INM_PAGESHIFT);

	/* Insure that driver threshold and target context thresholds
	 * are hit to start writing into data file
	 * Fairness solution after considering various scenarios
	 * DataPoolSize 64 MB i) 1 volume ii) 4 volumes
	 * DataPoolSize 256MB i) 1 volume ii) 4 or more voluames
	 * DataPoolSize X GB i) 1 volume ii) 4 or more voluames
	 */
	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->data_flt_ctx.data_pages_lock, lock_flag);
	total_unres_pages = driver_ctx->data_flt_ctx.pages_allocated -
						driver_ctx->dc_cur_unres_pages;
	total_unres_pages = data_pool_size - total_unres_pages;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->data_flt_ctx.data_pages_lock,
							lock_flag);
	if (total_unres_pages <= drv_thres_pages) {
if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		dbg("Reached driver cxt free data pages threshold for file write");
}
		is_drv_thres_hit = 1;
	}

	/* It is fairly okay to start writing to a data file on crossing 
	 * the volume threshold
	 */
	if (is_vol_thres_hit && is_drv_thres_hit) {
		 return 1;
	}

	return 0;
}

inm_s32_t create_datafile_dir_name(target_context_t *ctxt,
					inm_dev_info_t *dev_info)
{
	char *temp = NULL;
	char *ptr, *path;
	inm_s32_t len,i;

	path = ptr = dev_info->d_guid;
	temp = (char *)INM_KMALLOC(INM_GUID_LEN_MAX, INM_KM_SLEEP,
							INM_KERNEL_HEAP);
	if(!temp) {
		err("proc entry creation for volume %s failed: No Memory",
									path);
		return 1;
	}

	if(strncmp("/dev/", path, 5) == 0)
		ptr += 5;

	if (strcpy_s(temp, INM_GUID_LEN_MAX, ptr)) {
		INM_KFREE(temp, INM_GUID_LEN_MAX, INM_KERNEL_HEAP);;
		return 1;
	}

	len = strlen(temp);
	i = 0;

	while(i < len) {
		if(temp[i] == '/')
			temp[i] = '-';
		i++;
	}

	ctxt->tc_datafile_dir_name = temp;
	return 0;
}
