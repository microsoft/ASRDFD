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

#ifndef _INM_FILTER_H
#define _INM_FILTER_H

#include "involflt.h"
#include "involflt-common.h"

#define INM_MIRROR_MODEL_SETUP            0x00000001
#define INM_MIRROR_IO_TO_ATLUN            0x00000002
#define INM_MIRROR_IO_TO_SOURCE           0x00000004
#define INM_MIRROR_IO_TO_ATLUN_DONE       0x00000008
#define INM_MIRROR_IO_TO_SOURCE_DONE      0x00000010
#define INM_MIRROR_IO_PAGELOCKDONE        0x00000020
#define INM_MIRROR_IO_ATLUN_ERR           0x00000040
#define INM_MIRROR_IO_SOURCE_ERR          0x00000080
#define INM_MIRROR_IO_ATLUN_DIFF_PATH     0x00000100
#define INM_MIRROR_IO_ATLUN_PATHS_FAILURE 0x00000200
#define INM_MIRROR_IO_PTLUN_PATHS_FAILURE 0x00000400
#define INM_PTIO_CANCEL_PENDING		  0x00000800
#define INM_PTIO_CANCEL_SENT		  0x00001000
#define INM_PTIO_FULL_FAILED		  0x00002000
#define INM_ATIO_FULL_FAILED		  0x00004000

#define INM_ATBUF_FULL_FAILED		  0x00000001
#define INM_ATBUF_PARTIAL_FAILED	  0x00000002
#define INM_ATBUF_DONT_LINK_PREV          0x00000004

#define UPDATE_ATIO_SEND(vol_entryp, io_sz)			\
do{								\
	if(io_sz){						\
		vol_entryp->vol_byte_written += io_sz;		\
		vol_entryp->vol_io_issued++;			\
		vol_entryp->vol_io_succeeded++;			\
	}							\
}while(0)

#define UPDATE_ATIO_FAILED(vol_entryp, io_sz)               	\
do{                                                         	\
	vol_entryp->vol_byte_written -= io_sz;  		\
	vol_entryp->vol_io_succeeded--;         		\
}while(0)

typedef struct inm_dev_extinfo {
	inm_device_t d_type;
	char d_guid[INM_GUID_LEN_MAX];
	char d_mnt_pt[INM_PATH_MAX];
	inm_u64_t d_nblks;
	inm_u32_t d_bsize;
	inm_u64_t d_flags;
	char d_pname[INM_GUID_LEN_MAX];
	char d_src_scsi_id[INM_GUID_LEN_MAX];
	char d_dst_scsi_id[INM_GUID_LEN_MAX];
	struct inm_list_head *src_list;
	struct inm_list_head *dst_list;
	inm_u64_t d_startoff;
} inm_dev_extinfo_t;

void do_unstack_all(void);
inm_s32_t isrootdev(struct _target_context *vcptr);
inm_s32_t do_volume_stacking(inm_dev_extinfo_t *);
inm_s32_t do_start_filtering(inm_devhandle_t *, inm_dev_extinfo_t *);
inm_s32_t do_start_mirroring(inm_devhandle_t *, mirror_conf_info_t *);
inm_s32_t init_boottime_stacking(void);
inm_s32_t inm_dentry_callback(char *fname);
void flt_cleanup_sync_tag(tag_guid_t *);
tag_guid_t * get_tag_from_guid(char *);
inm_s32_t
populate_volume_lists(struct inm_list_head *src_mirror_list_head, 
		              struct inm_list_head *dst_mirror_list_head,
		              mirror_conf_info_t *mirror_infop);
void free_mirror_list(struct inm_list_head *list_head, int close_device);
void print_mirror_list(struct inm_list_head *list_head);
inm_s32_t is_flt_disabled(char *volname);
void add_tags(tag_volinfo_t *tag_volinfop, tag_info_t *tag_info, inm_s32_t num_tags, tag_guid_t *tag_guid, inm_s32_t index);
int flt_process_tags(inm_s32_t num_vols, void __INM_USER **user_buf,
		 inm_s32_t flags, tag_guid_t *tag_guid);
void load_bal_rr(struct _target_context *ctx, inm_u32_t io_sz);
inm_s32_t ptio_cancel_send(struct _target_context *tcp, inm_u64_t write_off, inm_u32_t write_len);
struct _mirror_vol_entry * get_cur_vol_entry(struct _target_context *tcp, inm_u32_t io_sz);
void inm_atio_retry(wqentry_t *wqe);
void issue_ptio_cancel_cdb(wqentry_t *wqe);
inm_iodone_t INM_MIRROR_IODONE(inm_pt_mirror_iodone, pt_bp, done, error);
inm_iodone_t INM_MIRROR_IODONE(inm_at_mirror_iodone, at_bp, done, error);
inm_u32_t inm_devpath_to_maxxfer(char *device_name);
void inm_free_atbuf_list(inm_list_head_t *);

int process_tag_volume(tag_info_t_v2 *tag_vol, tag_info_t *tag_list, 
		               int commit_pending);
tag_volinfo_t *build_volume_node_totag(volume_info_t *vol_info, inm_s32_t *error);
void add_volume_tags(tag_info_t_v2 *tag_vol, tag_volinfo_t *tag_volinfop,
		             tag_info_t *tag_info, int commit_pending);
inm_s32_t issue_tag_volume(tag_info_t_v2 *tag_vol, tag_volinfo_t *vol_tag,
		                   tag_info_t *tag_list, int commit_pending);
tag_info_t *build_tag_vol_list(tag_info_t_v2 *tag_vol, inm_s32_t *error);
void set_tag_drain_notify_status(struct _target_context *ctxt, int tag_status, int dev_status);
inm_s32_t modify_persistent_device_name(struct _target_context *ctx, char *p_name);

#ifdef IDEBUG_MIRROR_IO
#ifdef INM_LINUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#define INM_INJECT_ERR(cond, error, bp)		\
do{						\
	if(cond){				\
		dbg("injecting mirroring err");	\
		bp->bi_error = cond;		\
	}					\
}while(0)
#else
#define INM_INJECT_ERR(cond, error, bp)		\
do{						\
	if(cond){				\
		dbg("injecting mirroring err");	\
		error = cond;			\
	}					\
}while(0)
#endif
#else
#define INM_INJECT_ERR(cond, error, bp) 	\
do{						\
	if(cond){				\
		dbg("injecting mirroring err");	\
		bp->b_error = EIO;		\
	}					\
	cond = 0;				\
}while(0)
#endif

#define INJECT_VENDOR_CDB_ERR(cond, ret) 	\
do{						\
	if(cond){				\
		ret = 1;			\
	}					\
	cond = 0;				\
}while(0)

#else
#define INM_INJECT_ERR(cond, error, bp)
#define INJECT_VENDOR_CDB_ERR(inject_vendorcdb_err, ret)
#endif

struct inm_mirror_bufinfo {
	inm_buf_t           imb_pt_buf;
	inm_list_head_t imb_atbuf_list;
	inm_list_head_t imb_list;
	inm_buf_t        *imb_org_bp;
	void            *imb_privp;
	inm_u64_t       imb_io_off;
	inm_u64_t       imb_volsz;
	inm_u32_t       imb_io_sz;
	inm_atomic_t    imb_done_cnt;
	wqentry_t       ptio_can_wqe;
	struct _mirror_vol_entry *imb_vol_entry;
	inm_u32_t       imb_flag;
	inm_u32_t       imb_atbuf_cnt;
	inm_u64_t       imb_atbuf_absoff;
	inm_s32_t	imb_pt_err;
	inm_u32_t	imb_pt_done;
};
typedef struct inm_mirror_bufinfo inm_mirror_bufinfo_t;

struct _mirror_atbuf {
	inm_list_head_t imb_atbuf_this;
	inm_u32_t imb_atbuf_flag;
	wqentry_t imb_atbuf_wqe;
	inm_buf_t   imb_atbuf_buf;
	inm_mirror_bufinfo_t *imb_atbuf_imbinfo;
	struct _mirror_vol_entry *imb_atbuf_vol_entry;
	inm_u32_t imb_atbuf_iosz;
	inm_u32_t imb_atbuf_done;
};
typedef struct _mirror_atbuf inm_mirror_atbuf;
inm_s32_t inm_save_mirror_bufinfo(struct _target_context *, inm_mirror_bufinfo_t **, inm_buf_t **, struct _mirror_vol_entry *);
#ifdef INM_AIX
#define INM_ALLOC_MIRROR_BUFINFO(mrr_info) mrr_info = (inm_mirror_bufinfo_t *)INM_KMALLOC(sizeof(inm_mirror_bufinfo_t), INM_KM_SLEEP, INM_KERNEL_HEAP);
#else
#define INM_ALLOC_MIRROR_BUFINFO(mrr_info) mrr_info = INM_KMEM_CACHE_ALLOC(driver_ctx->dc_host_info.mirror_bioinfo_cache, INM_KM_NOIO);
#endif
#define INM_MIRROR_BIOSZ        sizeof(inm_mirror_bufinfo_t)
#endif /* _INM_FILTER_H */
