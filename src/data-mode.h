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
 * File       : data-mode.h
 *
 * Description:  Header file used by data mode implementation
 */

#ifndef LINVOLFLT_DATA_MODE_H
#define LINVOLFLT_DATA_MODE_H

struct _target_context;
struct _write_metadata_tag;
struct _change_node;
struct _data_page;

#define MIN_DATA_SZ_PER_CHANGE_NODE          (1*1024*1024) 	/* 1MB */
#define DEFAULT_MAX_DATA_SZ_PER_CHANGE_NODE  (4*1024*1024)	/* 4MB */
#define MAX_DATA_SZ_PER_CHANGE_NODE          (64*1024*1024)	/* 64MB */
#define SECTOR_SIZE_MASK	0xFFFFFE00

/* struct for writedata information*/
struct inm_writedata {
	void    	*wd_iovp;
	inm_u32_t	wd_iovcnt;
	inm_u32_t 	wd_cplen;
	inm_u32_t	wd_flag;
	inm_u32_t	wd_resrved;
	void		*wd_privp;
	void		(*wd_copy_wd_to_datapgs)(struct _target_context *,
		                                 struct inm_writedata *,
					 	 struct inm_list_head *);
	struct _change_node *wd_chg_node;
	inm_page_t	*wd_meta_page;
};

typedef struct inm_writedata inm_wdata_t;

#define INM_WD_WRITE_OFFLOAD 0x1

/* This structure holds data mode filtering context. This structure will be
 * initialized during data mode initialization and the pointer is stored in
 * the driver context.
 */
typedef struct _data_flt
{
	/* Lock to synchronize data_pages list. */
	inm_spinlock_t data_pages_lock;

	/* List of free data pages */
	struct inm_list_head data_pages_head;

	/* Cumulative pages allocated for data mode filtering. */
	inm_u32_t pages_allocated;

	/* Current number of free pages available */
	inm_u32_t pages_free;
	inm_u32_t dp_nrpgs_slab;
	inm_u32_t dp_least_free_pgs;
	inm_s32_t dp_pages_alloc_free;
} data_flt_t;

inm_s32_t init_data_flt_ctxt(data_flt_t *);
void free_data_flt_ctxt(data_flt_t *);
void save_data_in_data_mode(struct _target_context *,
			    struct _write_metadata_tag *, inm_wdata_t *);
inm_s32_t get_data_pages(struct _target_context *tgt_ctxt,
		           struct inm_list_head *head, inm_s32_t num_pages);
inm_s32_t inm_rel_data_pages(struct _target_context*,struct inm_list_head *,
		               inm_u32_t);
void data_mode_cleanup_for_s2_exit(void);
inm_s32_t add_data_pages(inm_u32_t);
void recalc_data_file_mode_thres(void);
inm_s32_t add_tag_in_stream_mode(tag_volinfo_t *, tag_info_t *,
		                         int, tag_guid_t *, inm_s32_t);
inm_s32_t inm_tc_resv_add(struct _target_context *, inm_u32_t);
inm_s32_t inm_tc_resv_del(struct _target_context *, inm_u32_t);
data_page_t *get_cur_data_pg(struct _change_node *, inm_s32_t *);
void update_cur_dat_pg(struct _change_node *, data_page_t *, inm_s32_t);
#endif
