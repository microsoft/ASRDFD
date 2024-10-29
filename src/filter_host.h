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

#ifndef _INM_FILTER_HOST_H
#define _INM_FILTER_HOST_H

#include "involflt.h"
#include "involflt-common.h"

typedef struct host_dev
{
	struct inm_list_head  hdc_dev_list;
	inm_dev_t             hdc_dev;
	struct gendisk       *hdc_disk_ptr;
	req_queue_info_t     *hdc_req_q_ptr;
	struct kobject       *hdc_disk_kobj_ptr;
	const struct block_device_operations *hdc_fops;
} host_dev_t;

typedef struct host_dev_context
{
	struct inm_list_head  hdc_dev_list_head;
	sector_t              hdc_start_sect;
	sector_t              hdc_end_sect;
	sector_t              hdc_actual_end_sect;
	inm_mempool_t        *hdc_bio_info_pool;
	inm_u64_t             hdc_volume_size; /* to validate the write offset */
	inm_u32_t             hdc_bsize;
	inm_u64_t             hdc_nblocks;
	inm_wait_queue_head_t resync_notify;
} host_dev_ctx_t;

typedef host_dev_ctx_t *host_dev_ctxp;

#define INM_BIOSZ		sizeof(dm_bio_info_t)
#define INM_IOINFO_MPOOL_SZ	(INM_PAGESIZE/sizeof(dm_bio_info_t))
/* filtering definitions */
#ifdef INM_QUEUE_RQ_ENABLED
#ifndef queue_rq_fn
typedef blk_status_t (queue_rq_fn)(struct blk_mq_hw_ctx *,
		const struct blk_mq_queue_data *);
#endif
blk_status_t inm_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd);
dm_bio_info_t *inm_alloc_bioinfo(void);
change_node_t *inm_alloc_chgnode(void);
void inm_alloc_pools(void);
int create_alloc_thread(void);
void destroy_alloc_thread(void);
void inm_free_bio_info(dm_bio_info_t *);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
blk_qc_t flt_make_request_fn(struct request_queue *, struct bio *bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
void flt_make_request_fn(struct request_queue *, struct bio *);
#else
inm_s32_t flt_make_request_fn(struct request_queue *, struct bio *);
#endif
#endif
void flt_disk_obj_rel(struct kobject *);
void flt_part_obj_rel(struct kobject *);
void flt_queue_obj_rel(struct kobject *);
void get_qinfo(req_queue_info_t *);
void put_qinfo(req_queue_info_t *);

void copy_bio_data_to_data_pages(target_context_t *tgt_ctxt, 
	     inm_wdata_t *wdatap, struct inm_list_head *change_node_list);
void reset_stable_pages_for_all_devs(void);
void set_stable_pages_for_all_devs(void);
req_queue_info_t* alloc_and_init_qinfo(inm_block_device_t *bdev, target_context_t *tgt_ctxt);
void init_tc_kobj(req_queue_info_t *q_info, inm_block_device_t *bdev,
						struct kobject **hdc_disk_kobj_ptr);
void inm_bufoff_to_fldisk(inm_buf_t *bp, target_context_t *tcp, inm_u64_t *abs_off);
inm_mirror_bufinfo_t * inm_get_imb_cached(host_dev_ctx_t *);
void inm_cleanup_mirror_bufinfo(host_dev_ctx_t *hdcp);
inm_s32_t inm_prepare_atbuf(inm_mirror_atbuf *, inm_buf_t *, mirror_vol_entry_t *, inm_u32_t);
/* disk resize notification */
void unregister_disk_change_notification(target_context_t *ctx, host_dev_t *hdc_dev);
void register_disk_change_notification(target_context_t *ctx, host_dev_t *hdc_dev);
#define INM_ALL_IOS_DONE 0
#define INM_MIRROR_INFO_RETURN(hdcp, mbufinfo, flag)                    \
{                                                                       \
	inm_free_atbuf_list(&(mbufinfo->imb_atbuf_list));                                  \
	INM_KMEM_CACHE_FREE(driver_ctx->dc_host_info.mirror_bioinfo_cache, mbufinfo);           \
}
void inm_issue_atio(inm_buf_t *at_bp, mirror_vol_entry_t *vol_entry);
#define INM_MAX_XFER_SZ(vol_entry, bp) INM_BUF_COUNT(bp)
#define INM_UPDATE_VOL_ENTRY_STAT(tcp, vol_entry, count, io_sz)

#ifdef INM_DEBUG
#define INM_IS_TEST_MIRROR(bio) (bio->bi_private == driver_ctx)
#define INM_SET_TEST_MIRROR(bio) (bio->bi_private = driver_ctx)
#else
#define INM_IS_TEST_MIRROR(bio) 0
#define INM_SET_TEST_MIRROR(bio)
#endif

#define INIT_OSSPEC_DRV_CTX(driver_ctx)                                 \
do{                                                                     \
	INM_INIT_LIST_HEAD(&(driver_ctx->dc_at_lun.dc_at_lun_list));    \
	INM_INIT_SPIN_LOCK(&(driver_ctx->dc_at_lun.dc_at_lun_list_spn));\
}while(0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0) || defined SET_INM_QUEUE_FLAG_STABLE_WRITE
#define	SET_STABLE_PAGES(q)	blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, q)
#define CLEAR_STABLE_PAGES(q)	blk_queue_flag_clear(QUEUE_FLAG_STABLE_WRITES, q)
#define TEST_STABLE_PAGES(q)	blk_queue_stable_writes(q)
#else
#define	SET_STABLE_PAGES(q)	(INM_BDI_CAPABILITIES(q) |= BDI_CAP_STABLE_WRITES)
#define CLEAR_STABLE_PAGES(q)	(INM_BDI_CAPABILITIES(q) &= ~BDI_CAP_STABLE_WRITES)
#define TEST_STABLE_PAGES(q)	(INM_BDI_CAPABILITIES(q) & BDI_CAP_STABLE_WRITES)
#endif
#endif

#ifndef INMAGE_PRODUCT_VERSION_MAJOR
#define INMAGE_PRODUCT_VERSION_MAJOR	1
#endif

#ifndef INMAGE_PRODUCT_VERSION_MINOR
#define INMAGE_PRODUCT_VERSION_MINOR	0
#endif

#ifndef INMAGE_PRODUCT_VERSION_BUILDNUM
#define INMAGE_PRODUCT_VERSION_BUILDNUM 0
#endif

#ifndef INMAGE_PRODUCT_VERSION_PRIVATE
#define INMAGE_PRODUCT_VERSION_PRIVATE 1
#endif

#endif /* _INM_FILTER_HOST_H*/
