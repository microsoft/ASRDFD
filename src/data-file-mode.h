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
 * File       : data-file-mode.h
 *
 * Description: Data File Mode support
 */

#ifndef LINVOLFLT_DATAFILE_MODE_H
#define LINVOLFLT_DATAFILE_MODE_H

#include "involflt-common.h"
#include "involflt.h"

#define DEFAULT_NUMBER_OF_FILEWRITERS_PER_VOLUME 1

struct _target_context;
struct _change_node;

typedef struct _data_file_thread {
	inm_s32_t id;
	inm_atomic_t pending;
	struct inm_list_head next;
	inm_completion_t exit; 
#ifdef INM_AIX
	inm_completion_t compl;
#else
	inm_sem_t mutex;
#endif
	struct _target_context *ctxt;
	inm_spinlock_t wq_list_lock;
	struct inm_list_head wq_hd;
#ifdef INM_LINUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	struct task_struct *thread_task;
#endif
#endif
} data_file_thread_t;

typedef struct _data_file_context {
	inm_s32_t num_dfm_threads;
	inm_atomic_t terminating;
	inm_sem_t list_mutex;
	struct inm_list_head dfm_thr_hd;
	data_file_thread_t *next_thr;
} data_file_flt_t;

typedef struct _data_file_node {
	struct inm_list_head next;
	void *chg_node;
} data_file_node_t;

#define DFM_THREAD_ENTRY(ptr) (inm_list_entry(ptr, data_file_thread_t, next)) 

inm_s32_t init_data_file_flt_ctxt(struct _target_context *);
void free_data_file_flt_ctxt(struct _target_context *);
inm_s32_t inm_unlink_datafile(struct _target_context *, char *);
inm_s32_t should_write_to_datafile(struct _target_context *);
inm_s32_t queue_chg_node_to_file_thread(struct _target_context *, 
				  struct _change_node *);
inm_s32_t create_datafile_dir_name(struct _target_context *, 
		                         struct inm_dev_info *);

#endif
