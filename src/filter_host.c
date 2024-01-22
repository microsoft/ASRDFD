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
#include "data-mode.h"
#include "driver-context.h"
#include "file-io.h"
#include "metadata-mode.h"
#include "statechange.h"
#include "tunable_params.h"
#include "db_routines.h"
#include "filter.h"
#include "filter_lun.h"
#include "ioctl.h"
#include "filter_host.h"
#include "osdep.h"
#include "telemetry.h"
#include "errlog.h"
#include "filestream_raw.h"
#include "verifier.h"
#include "telemetry-exception.h"

/* driver state */
inm_s32_t inm_mod_state;
inm_u32_t lcwModeOn;

#ifdef IDEBUG_MIRROR_IO
inm_s32_t inject_atio_err = 0;
inm_s32_t inject_ptio_err = 0;
inm_s32_t inject_vendorcdb_err = 0;
inm_s32_t clear_vol_entry_err = 0;
#endif

static inm_s32_t block_sd_open(void);
static void restore_sd_open(void);

struct completion_chk_req {
	target_context_t *ctx;
	inm_completion_t comp;
};
typedef struct completion_chk_req completion_chk_req_t;

extern driver_context_t *driver_ctx;
static void flt_orig_endio(struct bio *bio, inm_s32_t error);
extern void
involflt_completion(target_context_t *tgt_ctxt, write_metadata_t *wmd, 
						void *bio, int lock_held);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
extern inm_s32_t remap_pfn_range(struct vm_area_struct *, unsigned long,
				unsigned long , unsigned long , pgprot_t );

#define REMAP_PAGE remap_pfn_range
#define PAGE_2_PFN_OR_PHYS(x) (page_to_pfn(x))
#else
extern inm_s32_t remap_page_range(struct vm_area_struct *, unsigned long ,
				 unsigned long , unsigned long , pgprot_t );
#define REMAP_PAGE remap_page_range
#define PAGE_2_PFN_OR_PHYS(x) (page_to_phys(x))
#endif

typedef void (flt_part_release)(struct kobject *);
typedef void (flt_disk_release)(struct kobject *);

static flt_part_release *flt_part_release_fn = NULL;
static flt_disk_release *flt_disk_release_fn = NULL;
static struct kobj_type *disk_ktype_ptr = NULL;
static struct kobj_type *part_ktype_ptr = NULL;

void update_cur_dat_pg(change_node_t *, data_page_t *, int);
data_page_t *get_cur_data_pg(change_node_t *node, inm_s32_t *offset);
static void flt_end_io_chain(struct bio *bio, inm_s32_t error);

inm_s32_t driver_state = DRV_LOADED_FULLY;

req_queue_info_t *get_qinfo_from_kobj(struct kobject *kobj)
{
	req_queue_info_t *req_q;
	struct kobj_type *dev_ktype = NULL;

	dev_ktype = kobj->ktype;

	if(!dev_ktype)
		return NULL;

	if(dev_ktype->release == flt_queue_obj_rel)
		req_q = container_of(dev_ktype, req_queue_info_t, 
				  			mod_kobj_type);
	else
		req_q = NULL;

	return req_q;
}

void
reset_stable_pages_for_all_devs(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
	struct inm_list_head *entry = NULL;
	req_queue_info_t *qinfo = NULL;
	struct request_queue *q = NULL;
	inm_irqflag_t flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_host_info.rq_list_lock, flag);

	__inm_list_for_each(entry, &driver_ctx->dc_host_info.rq_list) {
		qinfo = inm_list_entry(entry, req_queue_info_t, next);
		q = qinfo->q;
		if (qinfo->rqi_flags & INM_STABLE_PAGES_FLAG_SET) {
				info("Setting stable pages off for %p", q);
				CLEAR_STABLE_PAGES(q);
				qinfo->rqi_flags &= ~INM_STABLE_PAGES_FLAG_SET;
		}
	}

	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
			 						flag);
#else
	return;
#endif
}

void
set_stable_pages_for_all_devs(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
	struct inm_list_head *entry = NULL;
	req_queue_info_t *qinfo = NULL;
	struct request_queue *q = NULL;
	inm_irqflag_t flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_host_info.rq_list_lock, flag);

	__inm_list_for_each(entry, &driver_ctx->dc_host_info.rq_list) {
		qinfo = inm_list_entry(entry, req_queue_info_t, next);
		q = qinfo->q;
		if (!TEST_STABLE_PAGES(q)) {
			qinfo->rqi_flags |= INM_STABLE_PAGES_FLAG_SET;
			info("Setting stable pages on for %p", q);
			SET_STABLE_PAGES(q);
		}
	}

	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
			 						flag);
#else
	return;
#endif
}

void add_qinfo_to_dc(req_queue_info_t *q_info)
{
	inm_list_add_tail(&q_info->next, &driver_ctx->dc_host_info.rq_list);
}

void remove_qinfo_from_dc(req_queue_info_t *q_info)
{
	inm_list_del(&q_info->next);
}

void get_qinfo(req_queue_info_t *q_info)
{
	INM_ATOMIC_INC(&q_info->ref_cnt);
}

void
inm_exchange_strategy(host_dev_ctx_t *hdcp)
{
	unsigned long lock_flag = 0;
	struct inm_list_head *ptr = NULL;
	host_dev_t *hdc_dev = NULL;
	req_queue_info_t *q_info;

	__inm_list_for_each(ptr, &hdcp->hdc_dev_list_head) {
		hdc_dev = inm_list_entry(ptr, host_dev_t, hdc_dev_list);
		q_info = hdc_dev->hdc_req_q_ptr;
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_host_info.rq_list_lock, 
									lock_flag);
		if(INM_ATOMIC_DEC_AND_TEST(&q_info->vol_users)){
			remove_qinfo_from_dc(q_info);

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
			(void)xchg(&q_info->q->mq_ops, q_info->orig_mq_ops);
#else
			(void)xchg(&q_info->q->make_request_fn, 
				  		q_info->orig_make_req_fn);
#endif
#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
			(void)xchg(&q_info->q->disk->queue_kobj.ktype, q_info->orig_kobj_type);
#else
			(void)xchg(&q_info->q->kobj.ktype, q_info->orig_kobj_type);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
			if (q_info->rqi_flags & INM_STABLE_PAGES_FLAG_SET) {
				CLEAR_STABLE_PAGES(q_info->q);
				q_info->rqi_flags &= 
						~INM_STABLE_PAGES_FLAG_SET;
			}
#endif
		}
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);
	}
}

void put_qinfo(req_queue_info_t *q_info)
{
	if(INM_ATOMIC_DEC_AND_TEST(&q_info->ref_cnt)) {
		info("Destroying q_info");
		kfree(q_info);
	}
}

void restore_disk_rel_ptrs(void)
{
	if(flt_disk_release_fn && disk_ktype_ptr)
		disk_ktype_ptr->release = flt_disk_release_fn;
	if(flt_part_release_fn && part_ktype_ptr)
		part_ktype_ptr->release = flt_part_release_fn;
}

void init_tc_kobj(req_queue_info_t *q_info, inm_block_device_t *bdev,
					struct kobject **hdc_disk_kobj_ptr)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
#if (defined(RHEL9) && !defined(OL9UEK7)) || LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
	*hdc_disk_kobj_ptr = bdev_kobj(bdev);
#else
	if (!bdev_is_partition(bdev)) {
		if(flt_disk_release_fn == NULL) {
			INM_BUG_ON(bdev_kobj(bdev)->ktype->release == NULL);
			flt_disk_release_fn = bdev_kobj(bdev)->ktype->release;
			disk_ktype_ptr = bdev_kobj(bdev)->ktype;
		}
		(void)xchg(&bdev_kobj(bdev)->ktype->release, &flt_disk_obj_rel);
		*hdc_disk_kobj_ptr = bdev_kobj(bdev);
	} else {
		if(flt_part_release_fn == NULL) {
			INM_BUG_ON(bdev_kobj(bdev)->ktype == NULL);
			flt_part_release_fn = bdev_kobj(bdev)->ktype->release;
			part_ktype_ptr = bdev_kobj(bdev)->ktype;
		}
		(void)xchg(&bdev_kobj(bdev)->ktype->release, &flt_part_obj_rel);
		*hdc_disk_kobj_ptr = bdev_kobj(bdev);
	}
#endif
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
	if(bdev == bdev->bd_contains) {
		if(flt_disk_release_fn == NULL) {
			INM_BUG_ON(bdev->bd_disk->part0.__dev.kobj.ktype->release == 
										NULL);
			flt_disk_release_fn = 
					bdev->bd_disk->part0.__dev.kobj.ktype->release;
			disk_ktype_ptr = 
					bdev->bd_disk->part0.__dev.kobj.ktype;
		}
		(void)xchg(&bdev->bd_disk->part0.__dev.kobj.ktype->release, 
								&flt_disk_obj_rel);
		*hdc_disk_kobj_ptr = &bdev->bd_disk->part0.__dev.kobj;
	} else {
		if(flt_part_release_fn == NULL) {
			INM_BUG_ON(bdev->bd_part->__dev.kobj.ktype == NULL);
			flt_part_release_fn = 
					bdev->bd_part->__dev.kobj.ktype->release;
			part_ktype_ptr = 
					bdev->bd_part->__dev.kobj.ktype;
		}
		(void)xchg(&bdev->bd_part->__dev.kobj.ktype->release, 
								&flt_part_obj_rel);
		*hdc_disk_kobj_ptr = &bdev->bd_part->__dev.kobj;
	}
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	if(!bdev->bd_part) {
		if(flt_disk_release_fn == NULL) {
			INM_BUG_ON(bdev->bd_disk->dev.kobj.ktype->release == 
									NULL);
			flt_disk_release_fn = 
					bdev->bd_disk->dev.kobj.ktype->release;
			disk_ktype_ptr = bdev->bd_disk->dev.kobj.ktype;
		}
		(void)xchg(&bdev->bd_disk->dev.kobj.ktype->release, 
				  			&flt_disk_obj_rel);
		*hdc_disk_kobj_ptr = &bdev->bd_disk->dev.kobj;
	} else {
		if(flt_part_release_fn == NULL) {
			INM_BUG_ON(bdev->bd_part->dev.kobj.ktype == NULL);
			flt_part_release_fn = 
					bdev->bd_part->dev.kobj.ktype->release;
			part_ktype_ptr = bdev->bd_part->dev.kobj.ktype;
		}
		(void)xchg(&bdev->bd_part->dev.kobj.ktype->release, 
				  			&flt_part_obj_rel);
		*hdc_disk_kobj_ptr = &bdev->bd_part->dev.kobj;
	}
#else
	if(!bdev->bd_part) {
		if(flt_disk_release_fn == NULL) {
			INM_BUG_ON(bdev->bd_disk->kobj.kset->ktype->release == 
									NULL);
			flt_disk_release_fn = 
				bdev->bd_disk->kobj.kset->ktype->release;
			disk_ktype_ptr = bdev->bd_disk->kobj.kset->ktype;
		} 
		(void)xchg(&bdev->bd_disk->kobj.kset->ktype->release, 
				  &flt_disk_obj_rel);
		*hdc_disk_kobj_ptr = &bdev->bd_disk->kobj;    
	} else {
		if(flt_part_release_fn == NULL) {
			INM_BUG_ON(bdev->bd_part->kobj.ktype == NULL);
			flt_part_release_fn = 
				  	bdev->bd_part->kobj.ktype->release;
			part_ktype_ptr = bdev->bd_part->kobj.ktype;
		}
		(void)xchg(&bdev->bd_part->kobj.ktype->release, 
				  			&flt_part_obj_rel);
		*hdc_disk_kobj_ptr = &bdev->bd_part->kobj;
	}
#endif
#endif
#endif
}

req_queue_info_t *
alloc_and_init_qinfo(inm_block_device_t *bdev, target_context_t *ctx)
{
	struct request_queue *q = bdev_get_queue(bdev);
	req_queue_info_t *new_q_info, *q_info;
	unsigned long lock_flag = 0;

	new_q_info = (req_queue_info_t *)INM_KMALLOC(sizeof(req_queue_info_t),
					INM_KM_SLEEP, INM_KERNEL_HEAP);
	if (!new_q_info)
		return NULL;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);
#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	q_info = get_qinfo_from_kobj(&bdev->bd_disk->queue_kobj);
#else
	q_info = get_qinfo_from_kobj(&bdev->bd_disk->queue->kobj);
#endif
	if (q_info) {
		INM_KFREE(new_q_info, sizeof(req_queue_info_t), 
				  			INM_KERNEL_HEAP);
		goto out;
	}

	q_info = new_q_info;

	INM_MEM_ZERO(q_info, sizeof(req_queue_info_t));
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) && !defined(SLES15SP3)
	q_info->orig_make_req_fn = q->make_request_fn;
#endif
	q_info->q = q;
	
#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	if (q->disk->queue_kobj.ktype) {
		memcpy_s(&(q_info->mod_kobj_type), sizeof(struct kobj_type),
			q->disk->queue_kobj.ktype, sizeof(struct kobj_type));
#else
	if (q->kobj.ktype) {
		memcpy_s(&(q_info->mod_kobj_type), sizeof(struct kobj_type),
				q->kobj.ktype, sizeof(struct kobj_type));
#endif
	} else {
		q_info->mod_kobj_type.release = NULL;
		q_info->mod_kobj_type.sysfs_ops = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
		q_info->mod_kobj_type.default_attrs = NULL;
#endif
	}
	INM_ATOMIC_SET(&q_info->ref_cnt, 0);
	INM_ATOMIC_SET(&q_info->vol_users, 0);

	q_info->mod_kobj_type.release = flt_queue_obj_rel;
#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	q_info->orig_kobj_type =  q->disk->queue_kobj.ktype;
#else
	q_info->orig_kobj_type =  q->kobj.ktype;
#endif

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
	q_info->tc = ctx;
	q_info->orig_mq_ops = q->mq_ops;
	memcpy_s(&q_info->mod_mq_ops, sizeof(struct blk_mq_ops),
			 q_info->orig_mq_ops, sizeof(struct blk_mq_ops));
	q_info->mod_mq_ops.queue_rq = inm_queue_rq;
	(void)xchg(&q->mq_ops, &q_info->mod_mq_ops);
#else
	/* now exchange pointers for make_request function and kobject type */
	(void)xchg(&q->make_request_fn, &flt_make_request_fn);
#endif
#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	(void)xchg(&q->disk->queue_kobj.ktype, &q_info->mod_kobj_type);
#else
	(void)xchg(&q->kobj.ktype, &q_info->mod_kobj_type);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
	if (driver_ctx->tunable_params.stable_pages && !TEST_STABLE_PAGES(q)) {
		q_info->rqi_flags |= INM_STABLE_PAGES_FLAG_SET;
		SET_STABLE_PAGES(q);
	}
#endif

	add_qinfo_to_dc(q_info);

out:
	get_qinfo(q_info);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);

	return q_info;
}

void
dump_bio(struct bio *bio)
{
	inm_bvec_iter_t idx;
	struct bio_vec *bvec;
	dm_bio_info_t *info = bio->bi_private;
	int vcnt = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	inm_bvec_iter_t iter;
	struct bio_vec vec;
#endif

	err("bio: %p", bio);
	if (bio->bi_end_io == flt_end_io_fn && info) { /* end io */
		err("bio->bi_idx: %d", info->bi_idx);
		err("bio->bi_sector: %llu", (inm_u64_t)info->bi_sector);
		err("bio->bi_size: %u", info->bi_size);
	} else { /* make request */
		err("bio->bi_idx: %d", INM_BUF_IDX(bio));
		err("bio->bi_sector: %llu", (inm_u64_t)INM_BUF_SECTOR(bio));
		err("bio->bi_size: %u", INM_BUF_COUNT(bio));
	}
	err("bio->bi_bdev: %p", INM_BUF_BDEV(bio));
	err("bio->bi_flags: %lu", (unsigned long)bio->bi_flags);
	err("bio->bi_rw: %lu", (unsigned long)inm_bio_rw(bio));
	err("bio->bi_vcnt: %d", bio->bi_vcnt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	bvec = &vec;        
	
	if (bio->bi_end_io == flt_end_io_fn && info) { /* end io */
		INM_BVEC_ITER_IDX(iter) = info->bi_idx;
		INM_BVEC_ITER_SECTOR(iter) = info->bi_sector;
		INM_BVEC_ITER_SZ(iter) = info->bi_size;
	} else { /* Make request */
		INM_BVEC_ITER_IDX(iter) = INM_BUF_IDX(bio);
		INM_BVEC_ITER_SECTOR(iter) = INM_BUF_SECTOR(bio);
		INM_BVEC_ITER_SZ(iter) = INM_BUF_COUNT(bio);
	}
	
	INM_BVEC_ITER_BVDONE(iter) =  INM_BVEC_ITER_BVDONE(INM_BUF_ITER(bio));

	idx = iter; /* structure assignment */
	
	__bio_for_each_segment(vec, bio, idx, iter) 
#else
	__bio_for_each_segment(bvec, bio, idx, info->bi_idx) 
#endif
	{
		err("bio->bv_page[%d]: %p", vcnt, bvec->bv_page);
		err("bio->bv_len[%d]: %u", vcnt, bvec->bv_len);
		err("bio->bv_offset[%d]: %u", vcnt, bvec->bv_offset);
		
		vcnt++;
	}
}

void
inm_handle_bad_bio(target_context_t *tgt_ctxt, inm_buf_t *bio)
{
	static int print_once = 0;
	
	telemetry_set_exception(tgt_ctxt->tc_guid, ecUnsupportedBIO,
						 INM_BIO_RW_FLAGS(bio));

	queue_worker_routine_for_set_volume_out_of_sync(tgt_ctxt,
				ERROR_TO_REG_UNSUPPORTED_IO, -EOPNOTSUPP);
	
	/* dont flood the syslog */
	if (print_once)
		return;

	dump_bio(bio);
	dump_stack();
			
	print_once = 1;

}

static struct inm_list_head *
copy_vec_to_data_pages(target_context_t *tgt_ctxt, struct bio_vec *bvec,
		inm_wdata_t *wdatap, struct inm_list_head *change_node_list,
		inm_s32_t *bytes_res_node)
{
	data_page_t *pg;
	inm_s32_t pg_rem = 0, pg_offset = 0, seg_offset = 0, seg_rem = 0;
	inm_s32_t bytes_to_copy = 0;
	inm_s32_t to_copy = 0;
	char *src,*dst;
	change_node_t *node;
	struct bio *bio = (struct bio *) wdatap->wd_privp;
	inm_s32_t org_poffset = 0;
	static int print_once = 0;

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}    

	pg_offset = 0;
	node = inm_list_entry(change_node_list, change_node_t, next);
	INM_BUG_ON(node == NULL);
	bytes_to_copy = wdatap->wd_cplen;
	if(bytes_to_copy == 0)
		goto out;

	pg = get_cur_data_pg(node, &pg_offset);
	pg_rem = (PAGE_SIZE - pg_offset);
	org_poffset = pg_offset;

	INM_BUG_ON(pg_rem <= 0);
	INM_BUG_ON(pg == NULL);
	INM_BUG_ON((void *)pg == (void *)&node->data_pg_head);

	dst = INM_KMAP_ATOMIC(pg->page, KM_SOFTIRQ1);
	dbg("Vec = %p", bvec);
	seg_offset = bvec->bv_offset;
	seg_rem = MIN(bvec->bv_len, bytes_to_copy);
	src = INM_KMAP_ATOMIC(bvec->bv_page, KM_SOFTIRQ0);
	while (seg_rem) {
		if (*bytes_res_node) {
			to_copy = MIN(seg_rem, pg_rem);
			to_copy = MIN(to_copy, *bytes_res_node);
			dbg("SPage = %p, SOffset = %d, DPage = %p, DOffset = %d copy = %d", 
				src, seg_offset, dst, pg_offset, 
				to_copy); 
			memcpy_s((char *)(dst + pg_offset), to_copy,
				(char *)(src + seg_offset), to_copy);
			seg_rem -= to_copy;
			seg_offset += to_copy;
			bytes_to_copy -= to_copy;

			pg_rem -= to_copy;
			pg_offset += to_copy;
			*bytes_res_node -= to_copy;

			INM_BUG_ON(seg_rem < 0);
			INM_BUG_ON(pg_rem < 0);
			INM_BUG_ON(seg_offset > PAGE_SIZE);
			INM_BUG_ON(pg_offset > PAGE_SIZE);
			INM_BUG_ON(bytes_to_copy < 0);

			if (!bytes_to_copy)
				break;
		}

		if (!pg_rem || !*bytes_res_node) {
			INM_KUNMAP_ATOMIC(src, KM_SOFTIRQ0);
			INM_KUNMAP_ATOMIC(dst, KM_SOFTIRQ1);
			if (!pg_rem) {
				 pg = get_next_data_page(pg->next.next, 
					&pg_rem, &pg_offset, node);
			} else {
				/* update offsets for current page in change node structure */
				update_cur_dat_pg(node, pg, pg_offset);
				INM_BUG_ON(!(node->flags & 
					KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK));
				/*
				 * Valid case for split io, node needs to be changed. Use next
				 * change node from change_node_list if current one is full
				 */
				node = inm_list_entry(node->next.next, 
							change_node_t, next);
				INM_BUG_ON(!node);
				INM_BUG_ON(!(node->flags & 
					KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK));
				/* Reset destination page offset values */
				pg = get_cur_data_pg(node, &pg_offset);
				pg_rem = (PAGE_SIZE - pg_offset);
				*bytes_res_node = node->data_free;
			}

			dst = INM_KMAP_ATOMIC(pg->page, KM_SOFTIRQ1);
			src = INM_KMAP_ATOMIC(bvec->bv_page, KM_SOFTIRQ0);
		}
	}

	INM_BUG_ON(bytes_to_copy < 0);
	INM_BUG_ON(seg_rem != 0);

	INM_KUNMAP_ATOMIC(src, KM_SOFTIRQ0);

	/* update offsets for current page in change node structure */
	update_cur_dat_pg(node, pg, pg_offset);
	INM_KUNMAP_ATOMIC(dst, KM_SOFTIRQ1);

	/* Detect any under/overrun */
	/* New offset should match old offset + len */
	if (!(node->flags & KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK) &&
		((((org_poffset + wdatap->wd_cplen) & (INM_PAGESZ - 1)) != 
		 						pg_offset) || 
		bytes_to_copy)) {

		if (!print_once) {
			err("Data copy error: Org: %d Len: %d New: %d "
				 "First: %d Last: %d Remaining: %d", 
				 org_poffset, wdatap->wd_cplen, 
				 pg_offset, 
				 CHANGE_NODE_IS_FIRST_DATA_PAGE(node, 
					 			pg),
				 CHANGE_NODE_IS_LAST_DATA_PAGE(node, 
					 			pg),
				 bytes_to_copy);

			err("bytes_res_node: %d to_copy = %d seg_rem = %d "
				 "seg_offset = %d pg_rem = %d", 
				 *bytes_res_node, to_copy, seg_rem, 
				 seg_offset, pg_rem); 
	
			print_once = 1;
		}

		inm_handle_bad_bio(tgt_ctxt, bio);
	}

out:
	return &(node->next);

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}
}

/*
 * BIO without vectors - zero the data
 */
void
copy_no_vector_bio_data_to_data_pages(target_context_t *tgt_ctxt, 
		inm_wdata_t *wdatap, struct inm_list_head *change_node_list)
{
#ifdef RHEL5
	INM_BUG_ON("Usupported op on RHEL5");
	return;
#else
	inm_buf_t *bio = wdatap->wd_privp;
	struct bio_vec vec = {0};
	inm_u32_t orglen = 0;
	inm_u32_t iolen = 0;
	change_node_t *node;
	inm_s32_t bytes_res_node = 0;

	dbg("Write Zeroes: %u", wdatap->wd_cplen);
	
	if (!(INM_IS_BIO_WOP(bio, INM_REQ_DISCARD) ||
			INM_IS_BIO_WOP(bio, INM_REQ_WRITE_ZEROES))) {
		inm_handle_bad_bio(tgt_ctxt, bio);
		return;
	}

	if (bio->bi_vcnt != 0) {
		static int print_once = 0;

		if (!print_once) {
			print_once = 1;
			err("Write Zeroes: %u", wdatap->wd_cplen);
			dump_bio(bio);
			dump_stack();
		}
	}

	vec.bv_page = ZERO_PAGE(0);
	vec.bv_offset = 0;

	orglen = iolen = wdatap->wd_cplen;
	
	node = inm_list_entry(change_node_list, change_node_t, next);
	bytes_res_node = node->data_free;

	while (iolen) {
		wdatap->wd_cplen = min(iolen, (inm_u32_t)PAGE_SIZE);
		vec.bv_len = wdatap->wd_cplen;

		change_node_list = copy_vec_to_data_pages(tgt_ctxt, &vec, 
				  wdatap, change_node_list, &bytes_res_node);
		iolen -= wdatap->wd_cplen;
	}

	wdatap->wd_cplen = orglen;
#endif
}

/*
 * BIO with single vector
 */
void
copy_single_vector_bio_data_to_data_pages(target_context_t *tgt_ctxt, 
		inm_wdata_t *wdatap, struct inm_list_head *change_node_list)
{
	inm_buf_t *bio = wdatap->wd_privp;
	dm_bio_info_t *info = bio->bi_private;
	struct bio_vec *bvec = NULL;
	inm_bvec_iter_t iter = INM_BVEC_ITER_INIT();
	inm_u32_t iolen = 0;
	inm_u32_t orglen = 0;
	change_node_t *node;
	inm_s32_t bytes_res_node = 0;

	dbg("Write Same: %u", wdatap->wd_cplen);

	if (bio->bi_vcnt != 1 || !INM_IS_BIO_WOP(bio, INM_REQ_WRITE_SAME)) {
		err("Write Same: %u", wdatap->wd_cplen);
		inm_handle_bad_bio(tgt_ctxt, bio);
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	INM_BVEC_ITER_IDX(iter) = info->bi_idx;
#else
	iter = info->bi_idx;
#endif

	bvec = bio_iovec_idx(bio, iter);

	orglen = iolen = wdatap->wd_cplen;
	wdatap->wd_cplen = bvec->bv_len;

	node = inm_list_entry(change_node_list, change_node_t, next);
	bytes_res_node = node->data_free;

	while (iolen) {
		change_node_list = copy_vec_to_data_pages(tgt_ctxt, bvec, 
				  wdatap, change_node_list, &bytes_res_node);
		iolen -= wdatap->wd_cplen;
	}
	
	wdatap->wd_cplen = orglen;
}

void
copy_normal_bio_data_to_data_pages(target_context_t *tgt_ctxt, 
		inm_wdata_t *wdatap, struct inm_list_head *change_node_list)
{
	struct bio_vec *bvec;
	data_page_t *pg;
	inm_s32_t pg_rem = 0, pg_offset = 0, seg_offset = 0, seg_rem = 0;
	inm_bvec_iter_t idx;
	inm_s32_t bytes_to_copy = 0, bytes_res_node = 0;
	inm_s32_t to_copy = 0;
	char *src,*dst;
	change_node_t *node;
	struct bio *bio = (struct bio *) wdatap->wd_privp;
	dm_bio_info_t *info = bio->bi_private;
	inm_s32_t org_poffset = 0;
	static int print_once = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	inm_bvec_iter_t iter;
	struct bio_vec vec;
#endif

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("entered");
	}    

	pg_offset = 0;
	node = inm_list_entry(change_node_list, change_node_t, next);
	INM_BUG_ON(node == NULL);
	bytes_to_copy = wdatap->wd_cplen;
	if(bytes_to_copy == 0)
		return;

	bytes_res_node = node->data_free;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	/*
	 * __bio_for_each_segment returns copy of vector 
	 * instead of vector ptr. So we get copy of vector
	 * in vec with bvec pointing to it and use bvec 
	 * pointer to access members to have common code 
	 * cross all kernels
	 */
	bvec = &vec;

	INM_BVEC_ITER_IDX(iter) = info->bi_idx;
	INM_BVEC_ITER_SECTOR(iter) = info->bi_sector;
	INM_BVEC_ITER_SZ(iter) = info->bi_size;
	INM_BVEC_ITER_BVDONE(iter) = info->bi_bvec_done;

	idx = iter; /* structure assignment */
#else
	idx = info->bi_idx;
#endif

	pg = get_cur_data_pg(node, &pg_offset);
	pg_rem = (PAGE_SIZE - pg_offset);
	org_poffset = pg_offset;

	INM_BUG_ON(pg_rem <= 0);
	INM_BUG_ON(pg == NULL);
	INM_BUG_ON((void *)pg == (void *)&node->data_pg_head);

	dst = INM_KMAP_ATOMIC(pg->page, KM_SOFTIRQ1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	__bio_for_each_segment(vec, bio, idx, iter) {
#else
	__bio_for_each_segment(bvec, bio, idx, info->bi_idx) {
#endif
		dbg("Vec = %p", bvec);
		seg_offset = bvec->bv_offset;
		seg_rem = MIN(bvec->bv_len, bytes_to_copy);
		src = INM_KMAP_ATOMIC(bvec->bv_page, KM_SOFTIRQ0);
		while (seg_rem) {
			to_copy = MIN(seg_rem, pg_rem);
			to_copy = MIN(to_copy, bytes_res_node);
			dbg("SPage = %p, SOffset = %d, DPage = %p, DOffset = %d copy = %d", 
				 src, seg_offset, dst, pg_offset, 
				 to_copy); 
			memcpy_s((char *)(dst + pg_offset), to_copy,
				 (char *)(src + seg_offset), to_copy);
			seg_rem -= to_copy;
			seg_offset += to_copy;
			bytes_to_copy -= to_copy;

			pg_rem -= to_copy;
			pg_offset += to_copy;
			bytes_res_node -= to_copy;

			INM_BUG_ON(seg_rem < 0);
			INM_BUG_ON(pg_rem < 0);
			INM_BUG_ON(seg_offset > PAGE_SIZE);
			INM_BUG_ON(pg_offset > PAGE_SIZE);
			INM_BUG_ON(bytes_to_copy < 0);

			if (!bytes_to_copy)
				 break;
			if (!pg_rem || !bytes_res_node) {
				INM_KUNMAP_ATOMIC(src, KM_SOFTIRQ0);
				INM_KUNMAP_ATOMIC(dst, KM_SOFTIRQ1);
				if (!pg_rem) {
					pg = get_next_data_page(pg->next.next, &pg_rem, &pg_offset, node);
				} else {
					/* update offsets for current page in change node structure */
					update_cur_dat_pg(node, pg, pg_offset);
					INM_BUG_ON(!(node->flags & KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK));
					/*
					 * Valid case for split io, node needs to be changed. Use next
					 * change node from change_node_list if current one is full
					 */
					node = inm_list_entry(node->next.next, change_node_t, next);
					INM_BUG_ON(!node);
					INM_BUG_ON(!(node->flags & KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK));
					/* Reset destination page offset values */
					pg = get_cur_data_pg(node, &pg_offset);
					pg_rem = (PAGE_SIZE - pg_offset);
					bytes_res_node = node->data_free;
				}

				dst = INM_KMAP_ATOMIC(pg->page, 
							KM_SOFTIRQ1);
				src = INM_KMAP_ATOMIC(bvec->bv_page, 
							KM_SOFTIRQ0);
			}
		}

		INM_BUG_ON(bytes_to_copy < 0);
		INM_BUG_ON(seg_rem != 0);

		INM_KUNMAP_ATOMIC(src, KM_SOFTIRQ0);

		if(bytes_to_copy == 0)
			break;
	}

	/* update offsets for current page in change node structure */
	update_cur_dat_pg(node, pg, pg_offset);
	INM_KUNMAP_ATOMIC(dst, KM_SOFTIRQ1);

	/* Detect any under/overrun */
	/* New offset should match old offset + len */
	pg = get_cur_data_pg(node, &pg_offset);
	if (!(node->flags & KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK) &&
		((((org_poffset + wdatap->wd_cplen) & (INM_PAGESZ - 1)) != 
					pg_offset) || bytes_to_copy)) {

		if (!print_once) {
			err("Data copy error: Org: %d Len: %d New: %d "
				 "First: %d Last: %d Remaining: %d", 
				 org_poffset, wdatap->wd_cplen, pg_offset,
				 CHANGE_NODE_IS_FIRST_DATA_PAGE(node, pg),
				 CHANGE_NODE_IS_LAST_DATA_PAGE(node, pg),
				 bytes_to_copy);

			err("bytes_res_node: %d to_copy = %d seg_rem = %d "
				 "seg_offset = %d pg_rem = %d", 
				 bytes_res_node, to_copy, seg_rem, 
				 seg_offset, pg_rem); 
		
			print_once=1;
		}

		inm_handle_bad_bio(tgt_ctxt, bio);
	}

	if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_META))){
		info("leaving");
	}
}

void
copy_bio_data_to_data_pages(target_context_t *tgt_ctxt, inm_wdata_t *wdatap, 
				struct inm_list_head *change_node_list)
{
	inm_buf_t *bio = wdatap->wd_privp;

	if (INM_IS_OFFLOAD_REQUEST_OP(bio)) {
		if (INM_IS_BIO_WOP(bio, INM_REQ_WRITE_SAME))
				copy_single_vector_bio_data_to_data_pages(tgt_ctxt, 
						wdatap, change_node_list);
		else 
				copy_no_vector_bio_data_to_data_pages(tgt_ctxt, 
						wdatap, change_node_list);
	} else {
		copy_normal_bio_data_to_data_pages(tgt_ctxt, wdatap, 
				  			change_node_list);
	}
}

inline static int 
inm_bio_supported_in_data_mode(struct bio *bio)
{
	if (!INM_IS_SUPPORTED_REQUEST_OP(bio)) {
		err("Unsupported IO Op: 0x%lx", 
				  	(unsigned long)inm_bio_op(bio));
		return 0;
	}

	if (INM_IS_OFFLOAD_REQUEST_OP(bio) &&
		INM_BUF_COUNT(bio) >= DEFAULT_MAX_DATA_SZ_PER_CHANGE_NODE) {
		err("Large offload IO: 0x%lx:%u", 
				  (unsigned long)inm_bio_op(bio), 
				INM_BUF_COUNT(bio));
		return 0;
	}

	return 1;
}

static void 
flt_copy_bio(struct bio *bio)
{
	dm_bio_info_t *bio_info = bio->bi_private;
	target_context_t *ctxt;
	host_dev_ctx_t *hdcp;
	write_metadata_t wmd;     
	inm_wdata_t wdata = {0};

	INM_BUG_ON(!bio_info);

	ctxt = (target_context_t *)bio_info->tc;
	INM_BUG_ON(!ctxt);

	hdcp = ctxt->tc_priv;

	if (INM_UNLIKELY(0 == (bio_info->bi_size - INM_BUF_COUNT(bio)))) {
		goto free_bio_info;
	}

	if (ctxt->tc_dev_type != FILTER_DEV_MIRROR_SETUP) {
		INM_GET_WMD(bio_info, wmd);
		wdata.wd_privp = (void *)bio;
		wdata.wd_cplen = (bio_info->bi_size - INM_BUF_COUNT(bio));
		wdata.wd_copy_wd_to_datapgs = copy_bio_data_to_data_pages;
		wdata.wd_chg_node = bio_info->bi_chg_node;
		wdata.wd_meta_page = NULL;
		if (INM_IS_OFFLOAD_REQUEST_OP(bio))
			wdata.wd_flag |= INM_WD_WRITE_OFFLOAD;

		if (unlikely(!inm_bio_supported_in_data_mode(bio))) {
			dbg("switching to metadata mode \n");
			set_tgt_ctxt_filtering_mode(ctxt, 
					FLT_MODE_METADATA, FALSE);

			if (ecWriteOrderStateData == ctxt->tc_cur_wostate) {
				 update_cx_product_issue(VCS_CX_UNSUPPORTED_BIO);
				 set_tgt_ctxt_wostate(ctxt, 
					ecWriteOrderStateMetadata, 
					FALSE, 
					ecWOSChangeReasonUnsupportedBIO);
			}
		}
	
		involflt_completion(ctxt, &wmd, &wdata, FALSE);
		bio_info->bi_chg_node = wdata.wd_chg_node;
	}

free_bio_info:
	while (bio_info->bi_chg_node) {
		change_node_t *node = bio_info->bi_chg_node;
		bio_info->bi_chg_node = (change_node_t *) node->next.next;
		node->next.next = NULL;
		inm_free_change_node(node);
	}

	bio->bi_end_io = bio_info->bi_end_io;
	bio->bi_private = bio_info->bi_private;

	if (INM_BUF_COUNT(bio) == 0) {
		if (bio_info->orig_bio_copy) {
			INM_KFREE(bio_info->orig_bio_copy, sizeof(struct bio), 
							INM_KERNEL_HEAP);
		}
		INM_DESTROY_SPIN_LOCK(&bio_info->bio_info_lock);
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
		inm_free_bio_info(bio_info);
#else
		INM_MEMPOOL_FREE(bio_info, hdcp->hdc_bio_info_pool);
#endif
		put_tgt_ctxt(ctxt);
		INM_ATOMIC_DEC(&ctxt->tc_nr_in_flight_ios);
	}
}

struct bio *bio_to_complete[NR_CPUS];

/*
 * flt_end_io_parent - Called for a chain parent. The function returns the 
 * bio pointer to bio_endio() in the caller to prevent stack overflow.
 */
static void
flt_end_io_parent(struct bio *bio, target_context_t *ctxt, inm_s32_t error)
{
	inm_irqflag_t flags;
	struct bio *on_child_stack = NULL;
	int cpuid = 0;

	INM_ATOMIC_DEC(&ctxt->tc_nr_chain_bios_pending);

	local_irq_save(flags);
	cpuid = smp_processor_id();
	
	on_child_stack = bio_to_complete[cpuid];
	
	if (on_child_stack) {
		INM_ATOMIC_INC(&ctxt->tc_nr_completed_in_child_stack);
		bio_to_complete[cpuid] = bio;
		dbg("PARENT(%d): %p -> %p", cpuid, on_child_stack, bio);
		local_irq_restore(flags);
	} else {
		dbg("PARENT(%d): %p", cpuid, bio); 
		INM_ATOMIC_INC(&ctxt->tc_nr_completed_in_own_stack);
		local_irq_restore(flags);
		return flt_end_io_chain(bio, error);
	}
}

static void 
flt_end_io_chain(struct bio *bio, inm_s32_t error)
{
	inm_irqflag_t flags;
	int cpuid = 0;
	struct bio *obio = NULL;
	
	local_irq_save(flags);
	cpuid = smp_processor_id();

	do {
		dbg("CHILD(%d): %p", cpuid, bio);

		/* 
		* In case we preempted another flt_end_io_chain() in execution 
		* we may not complete IO in right order
		*/
		INM_BUG_ON((obio = bio_to_complete[cpuid]));

		/* 
		* Add the bio to per cpu list so that parent endio
		* can determine if its a recursion or not
		*/
		bio_to_complete[cpuid] = bio;
		flt_orig_endio(bio, error);

		/*
		* For a chain bio, the parent bio's end_io() == flt_end_io_fn()
		* is recursively called when flt_orig_endio() is called on child bio. 
		* This can lead to a stack overflow in case of very large chains
		* where parent bio itself is a child to another bio. 
		* To prevent stack overflow for large chains, the parent bio is 
		* identified by BINFO_FLAG_CHAIN flag in its flt_end_io_fn() and 
		* is handled by flt_end_io_parent() which will place the parent bio 
		* in per-cpu list bio_to_complete after copying the change buffer, 
		* for the child endio() to call flt_orig_endio() on the parent bio
		* an complete its processing in its stack and not let the stack grow.
		*/
		
		if (bio != bio_to_complete[cpuid]) {
			dbg("CHILD: Bio from parent(%d): %p -> %p", 
					cpuid, bio, 
					bio_to_complete[cpuid]);
			bio = bio_to_complete[cpuid]; 
		} else {
			bio = NULL; /* No parent to endio() */
		}

		bio_to_complete[cpuid] = obio; 

	} while(bio);

	local_irq_restore(flags);

	dbg("Done");
}

/*
 * This function is not used for RHEL 5 (<2.6.24)
 */
static void 
flt_end_io(struct bio *bio, inm_s32_t error)
{
	dm_bio_info_t *bio_info = bio->bi_private;
	target_context_t *ctxt = (target_context_t *)bio_info->tc;
	int is_chain_bio = bio_info->dm_bio_flags & BINFO_FLAG_CHAIN;

	flt_copy_bio(bio);
	
	if (!driver_ctx->tunable_params.enable_chained_io)
		return flt_orig_endio(bio, error);

	/*
	 * bio_endio() will reset BIO_CHAIN flag. As such, we rely on our flag
	 * set during make_request() when BIO_CHAIN flag can be checked for.
	 */
	if (is_chain_bio)
		return flt_end_io_parent(bio, ctxt, error);
	else
		return flt_end_io_chain(bio, error);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)

static void
flt_orig_endio(struct bio *bio, inm_s32_t error)
{
	dbg("ENDIO: %p", bio);
	if (bio->bi_end_io)
		return bio->bi_end_io(bio);
}

void 
flt_end_io_fn(struct bio *bio)
{
	if (!inm_bio_error(bio))
		INM_BUG_ON(INM_BUF_COUNT(bio) != 0);
	
	flt_end_io(bio, inm_bio_error(bio));
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)

static void
flt_orig_endio(struct bio *bio, inm_s32_t error)
{
	if (bio->bi_end_io)
		return bio->bi_end_io(bio, error);
}

void 
flt_end_io_fn(struct bio *bio, inm_s32_t error)
{
	if (!error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
		INM_BUG_ON(INM_BUF_COUNT(bio) != 0);
#else
		INM_BUF_COUNT(bio) = 0;
#endif
	}

	flt_end_io(bio, error);
}

#else

static void
flt_orig_endio(struct bio *bio, inm_s32_t error)
{
	INM_BUG_ON(1);
}

/* No special IO handling required - take the default path */
inm_s32_t
flt_end_io_fn(struct bio *bio, inm_u32_t done, inm_s32_t error)
{
	flt_copy_bio(bio);

	if (bio->bi_end_io)
		return bio->bi_end_io(bio, done, error);
	
	return 0;
}

#endif

static void
inm_capture_in_metadata(target_context_t *ctx, struct bio *bio,
						  dm_bio_info_t *bio_info)
{
	write_metadata_t wmd;
	inm_wdata_t      wdata = {0};

	wmd.offset = (bio_info->bi_sector << 9);
	wmd.length = bio_info->bi_size;
	wdata.wd_chg_node = bio_info->bi_chg_node;
	wdata.wd_meta_page = NULL;

	volume_lock(ctx);
	dbg("switching to metadata mode \n");
	set_tgt_ctxt_filtering_mode(ctx, FLT_MODE_METADATA, FALSE);

	if (ecWriteOrderStateData == ctx->tc_cur_wostate) {
		update_cx_product_issue(VCS_CX_UNSUPPORTED_BIO);
		set_tgt_ctxt_wostate(ctx, ecWriteOrderStateMetadata, FALSE,
					ecWOSChangeReasonUnsupportedBIO);
	}

	involflt_completion(ctx, &wmd, &wdata, TRUE);

	volume_unlock(ctx);

	bio_info->bi_chg_node = wdata.wd_chg_node;
	while (bio_info->bi_chg_node) {
		change_node_t *chg_node = bio_info->bi_chg_node;
		bio_info->bi_chg_node = (change_node_t *) chg_node->next.next;
		chg_node->next.next = NULL;
		inm_free_change_node(chg_node);
	}
}
	
static_inline void
flt_save_bio_info(target_context_t *ctx, dm_bio_info_t **bio_info, 
							struct bio *bio)
{
	host_dev_ctx_t *hdcp = ctx->tc_priv;
	change_node_t *chg_node;
	int full_disk;
	int alloced_from_pool = 0;

	full_disk = 0;
	chg_node = NULL;

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
	*bio_info = INM_KMALLOC(sizeof(dm_bio_info_t), 
			 	GFP_ATOMIC | __GFP_NOWARN, INM_KERNEL_HEAP);
	if (!(*bio_info)) {
		*bio_info = inm_alloc_bioinfo();
		alloced_from_pool = 1;
	}
#else
	*bio_info = INM_MEMPOOL_ALLOC(hdcp->hdc_bio_info_pool, GFP_NOIO);

	/* Ideally we should not panic here. This bug check is here to 
	 * understand the load on _bio_info_pool. This should be removed later 
	 * and switch mode????
	 */
	INM_BUG_ON(!(*bio_info));
#endif
	if (!(*bio_info)) {
		queue_worker_routine_for_set_volume_out_of_sync(ctx,
					 ERROR_TO_REG_FAILED_TO_ALLOC_BIOINFO,
					 -ENOMEM);
		err("Mempool Alloc Failed");
		return;
	}
	INM_MEM_ZERO(*bio_info, sizeof(dm_bio_info_t));    

	if (alloced_from_pool)
		(*bio_info)->dm_bio_flags |= BINFO_ALLOCED_FROM_POOL;

	volume_lock(ctx);
	full_disk = ctx->tc_flags & VCF_FULL_DEV;
	volume_unlock(ctx);
	
	if (full_disk) {
		(*bio_info)->bi_sector  = INM_BUF_SECTOR(bio);
	}
	else {
		(*bio_info)->bi_sector  = (INM_BUF_SECTOR(bio) - 
				  			hdcp->hdc_start_sect);
	}
	(*bio_info)->bi_size    = INM_BUF_COUNT(bio);
	(*bio_info)->bi_idx     = INM_BUF_IDX(bio);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	(*bio_info)->bi_bvec_done = INM_BVEC_ITER_BVDONE(INM_BUF_ITER(bio));
#endif
	(*bio_info)->bi_flags   = bio->bi_flags;
	(*bio_info)->bi_end_io  = bio->bi_end_io;
	(*bio_info)->bi_private = bio->bi_private;
	(*bio_info)->tc         = ctx;
	(*bio_info)->orig_bio   = bio;
	INM_INIT_SPIN_LOCK(&((*bio_info)->bio_info_lock));
	if (ctx->tc_dev_type == FILTER_DEV_HOST_VOLUME) {
		unsigned long max_data_sz_per_chg_node;
		unsigned long remaining_length = (*bio_info)->bi_size;
		unsigned long length;

		max_data_sz_per_chg_node = driver_ctx->tunable_params.max_data_sz_dm_cn - \
						sv_chg_sz - sv_const_sz;

		while (remaining_length) {
			alloced_from_pool = 0;
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
			chg_node = INM_KMALLOC(sizeof(change_node_t), 
			GFP_ATOMIC | __GFP_NOWARN, INM_KERNEL_HEAP);
			if (!chg_node) {
				 chg_node = inm_alloc_chgnode();
				 alloced_from_pool = 1;
			}
#else
			chg_node = INM_KMALLOC(sizeof(change_node_t), 
						INM_KM_NOIO, INM_KERNEL_HEAP);
#endif
			if (!chg_node) {
				 queue_worker_routine_for_set_volume_out_of_sync(ctx,
						  ERROR_TO_REG_OUT_OF_MEMORY_FOR_DIRTY_BLOCKS,
						  -ENOMEM);
				 err("Change node allocation failed");
				 goto out_err;
			}

			INM_MEM_ZERO(chg_node, sizeof(change_node_t));

			if (alloced_from_pool)
				 chg_node->flags = CHANGE_NODE_ALLOCED_FROM_POOL;

			chg_node->next.next = NULL;
			if ((*bio_info)->bi_chg_node)
				 chg_node->next.next = (struct inm_list_head *) (*bio_info)->bi_chg_node;

			(*bio_info)->bi_chg_node = chg_node;

			length = min(max_data_sz_per_chg_node, remaining_length);
			remaining_length -= length;
		}
	}

	/* bio->bi_end_io == flt_end_io_fn is used an indicator that bi_private
	 * belongs to our driver. Change the checks if the following two lines 
	 * or their order need to be changed.
	 */
	bio->bi_private = (void *)*bio_info;
	bio->bi_end_io = flt_end_io_fn;
	
	if (INM_IS_CHAINED_BIO(bio)) {
	INM_ATOMIC_INC(&ctx->tc_nr_chain_bios_submitted);
	INM_ATOMIC_INC(&ctx->tc_nr_chain_bios_pending);
		dbg("CHAIN: %p", bio);
		(*bio_info)->dm_bio_flags |= BINFO_FLAG_CHAIN;
	}
#if (defined REQ_OP_WRITE_ZEROES || defined OL7UEK5)
	if (bio_op(bio) == INM_REQ_WRITE_ZEROES) {
		INM_ATOMIC_INC(&ctx->tc_nr_write_zero_bios);
	}
#endif
out:
	dbg("Write Entry Point: Offset %llu Length %d",
		(inm_u64_t)(INM_BUF_SECTOR(bio) * 512), INM_BUF_COUNT(bio));
	return;

out_err:
	if ((*bio_info)->orig_bio_copy) {
		INM_KFREE((*bio_info)->orig_bio_copy, sizeof(struct bio), 
				  			INM_KERNEL_HEAP);
	}
	while ((*bio_info)->bi_chg_node) {
		chg_node = (*bio_info)->bi_chg_node;
		(*bio_info)->bi_chg_node = 
					(change_node_t *) chg_node->next.next;
		chg_node->next.next = NULL;
	inm_free_change_node(chg_node);
	}
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
	inm_free_bio_info(*bio_info);
#else    
	INM_MEMPOOL_FREE(*bio_info, hdcp->hdc_bio_info_pool);
#endif
	*bio_info = NULL;
	goto out;
}

void
get_root_disk(struct bio *bio)
{
	target_context_t *ctx;

	INM_DOWN_READ(&driver_ctx->tgt_list_sem);

	ctx = get_tgt_ctxt_from_bio(bio);
	if (ctx) {
		volume_lock(ctx);
	
		if (!(ctx->tc_flags & 
				(VCF_VOLUME_DELETING | VCF_VOLUME_CREATING)) &&
				!(ctx->tc_flags & VCF_ROOT_DEV)) {
			info("Root Disk - %s (%s)", ctx->tc_guid, 
								ctx->tc_pname);
			driver_ctx->dc_root_disk = ctx;
			ctx->tc_flags |= VCF_ROOT_DEV;
		}

		volume_unlock(ctx);
	}

	INM_UP_READ(&driver_ctx->tgt_list_sem);
}

/* chk whether is driver doing this IO */
int
is_our_io(struct bio *biop) 
{
	struct bio_vec *bvecp = NULL;
	const inm_address_space_operations_t *a_opsp = NULL;
	inma_ops_t *t_inma_opsp = NULL;
	struct address_space *mapping = NULL;
	unsigned long lock_flag;

	INM_BUG_ON(!biop);

#if !(defined(RHEL_MAJOR) && (RHEL_MAJOR == 5))
	if (!biop->bi_vcnt || INM_IS_OFFLOAD_REQUEST_OP(biop)) {
#if (defined (RHEL8) || defined (RHEL7))
		if (unlikely(lcwModeOn &&
				strcmp(current->comm, "inmshutnotify") == 0)) {
			fstream_raw_map_bio(biop);

			/* If TrackRecursiveWrites is set, return FALSE */
			return driver_ctx->tunable_params.enable_recio ? FALSE : TRUE;
		}
#endif
		return FALSE;
	}
#endif

	bvecp = bio_iovec_idx(biop, INM_BUF_ITER(biop));
	if(!bvecp || !bvecp->bv_page)
		return FALSE;

	if (!virt_addr_valid(bvecp) || 
		!INM_VIRT_ADDR_VALID(INM_PAGE_TO_VIRT(bvecp->bv_page)))
		return FALSE;

	if (!bvecp->bv_page->mapping)
		return FALSE;

	if (!virt_addr_valid(bvecp->bv_page->mapping))
		return FALSE;

	if (PageAnon(bvecp->bv_page))
		return FALSE;

	mapping = bvecp->bv_page->mapping;

	if (unlikely(!driver_ctx->dc_root_disk) &&
		virt_addr_valid(mapping->host) &&
		virt_addr_valid(mapping->host->i_sb) &&
		mapping->host->i_sb->s_dev == driver_ctx->root_dev &&
		driver_state & DRV_LOADED_FULLY)
		get_root_disk(biop); 

#ifdef INM_RECUSIVE_ADSPC 
	a_opsp = bvecp->bv_page->mapping;
#else
	if (!bvecp->bv_page->mapping->a_ops)
		return FALSE;

	a_opsp = bvecp->bv_page->mapping->a_ops;
#endif

	lock_inmaops(FALSE, &lock_flag);
	t_inma_opsp = inm_get_inmaops_from_aops(a_opsp, 
			 			INM_DUP_ADDR_SPACE_OPS);
	unlock_inmaops(FALSE, &lock_flag);
	if (t_inma_opsp) {
#ifdef INM_RECUSIVE_ADSPC
		INM_BUG_ON(t_inma_opsp->ia_mapping != 
				  		bvecp->bv_page->mapping);
#endif
		dbg("Recursive write: Lookup = %p, Mapping = %p", 
				  			t_inma_opsp, a_opsp);
		if (driver_ctx->dc_lcw_aops == t_inma_opsp)
				fstream_raw_map_bio(biop);
		
		/* If TrackRecursiveWrites is set, return FALSE */
		return driver_ctx->tunable_params.enable_recio ? FALSE : TRUE;    
	}

	return FALSE;
}

#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(RHEL8)
#define NR_MAX_ALLOCATIONS	1024
#define NR_MAX_FREED		128
void inm_free_bio_info(dm_bio_info_t *bio_info)
{
	unsigned long lock_flag = 0;

	if (bio_info->dm_bio_flags & BINFO_ALLOCED_FROM_POOL) {
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_bioinfo_alloced);
		inm_list_add_tail(&bio_info->entry, 
				  		&driver_ctx->dc_bioinfo_list);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, 
				  				lock_flag);
	} else
		INM_KFREE(bio_info, sizeof(dm_bio_info_t), INM_KERNEL_HEAP);
}

void inm_free_bioinfo_pool(void)
{
	dm_bio_info_t *info;

	while (!inm_list_empty(&driver_ctx->dc_bioinfo_list)) {
		info = inm_list_entry(driver_ctx->dc_bioinfo_list.next, 
				  			dm_bio_info_t, entry);
		inm_list_del(&info->entry);
		INM_KFREE(info, sizeof(dm_bio_info_t), INM_KERNEL_HEAP);
	}
}

void inm_alloc_bioinfo_pool(void)
{
	dm_bio_info_t *info;
	unsigned long lock_flag = 0;

	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced) < 
			 				NR_MAX_ALLOCATIONS) {
		info = INM_KMALLOC(sizeof(dm_bio_info_t), GFP_NOIO, 
							INM_KERNEL_HEAP);
		if (!info)
			return;

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_bioinfo_alloced);
		inm_list_add_tail(&info->entry, &driver_ctx->dc_bioinfo_list);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, 
								lock_flag);
	}
}

void inm_free_chdnodes_pool(void)
{
	change_node_t *chg_node;

	while (!inm_list_empty(&driver_ctx->dc_chdnodes_list)) {
		chg_node = inm_list_entry(driver_ctx->dc_chdnodes_list.next, 
				  			change_node_t, next);
		inm_list_del(&chg_node->next);
		INM_KFREE(chg_node, sizeof(change_node_t), INM_KERNEL_HEAP);
	}
}

void inm_alloc_chdnodes_pool(void)
{
	change_node_t *chg_node;
	unsigned long lock_flag = 0;

	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced) < 
			 				NR_MAX_ALLOCATIONS) {
		chg_node = INM_KMALLOC(sizeof(change_node_t), GFP_NOIO, 
				  			INM_KERNEL_HEAP);
		if (!chg_node)
			return;

		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_chdnodes_alloced);
		inm_list_add_tail(&chg_node->next, 
					&driver_ctx->dc_chdnodes_list);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, 
								lock_flag);
	}
}

dm_bio_info_t *inm_alloc_bioinfo(void)
{
	dm_bio_info_t *info = NULL;
	unsigned long lock_flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
	if (inm_list_empty(&driver_ctx->dc_bioinfo_list)) {
		wake_up_interruptible(&driver_ctx->dc_alloc_thread_waitq);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_bioinfo_allocs_failed);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, 
				  				lock_flag);
		goto out;
	}

	info = inm_list_entry(driver_ctx->dc_bioinfo_list.next, 
			 			dm_bio_info_t, entry);
	inm_list_del(&info->entry);
	INM_ATOMIC_DEC(&driver_ctx->dc_nr_bioinfo_alloced);
	INM_ATOMIC_INC(&driver_ctx->dc_nr_bioinfo_alloced_from_pool);
	wake_up_interruptible(&driver_ctx->dc_alloc_thread_waitq);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, lock_flag);

out:
	return info;
}

change_node_t *inm_alloc_chgnode(void)
{
	change_node_t *chg_node = NULL;
	unsigned long lock_flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
	if (inm_list_empty(&driver_ctx->dc_chdnodes_list)) {
		wake_up_interruptible(&driver_ctx->dc_alloc_thread_waitq);
		INM_ATOMIC_INC(&driver_ctx->dc_nr_chgnode_allocs_failed);
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, 
				  				lock_flag);
		goto out;
	}

	chg_node = inm_list_entry(driver_ctx->dc_chdnodes_list.next, 
			 				change_node_t, next);
	inm_list_del(&chg_node->next);
	INM_ATOMIC_DEC(&driver_ctx->dc_nr_chdnodes_alloced);
	INM_ATOMIC_INC(&driver_ctx->dc_nr_chgnodes_alloced_from_pool);
	wake_up_interruptible(&driver_ctx->dc_alloc_thread_waitq);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, lock_flag);

out:
	return chg_node;
}

void inm_alloc_pools(void)
{
	unsigned long lock_flag = 0;
	int nr_bioinfos = 0;
	int nr_chgnodes = 0;
	int nr_metapages = 0;
	static int alloc_in_progress = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
	if (alloc_in_progress) {
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, 
				  				lock_flag);
		return;
	}

	alloc_in_progress = 1;

	if(INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced) < 
			 				NR_MAX_ALLOCATIONS)
		nr_bioinfos = NR_MAX_ALLOCATIONS - 
			INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced);

	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced) < 
			 				NR_MAX_ALLOCATIONS)
		nr_chgnodes = NR_MAX_ALLOCATIONS - 
			INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced);

	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced) < 
			 				NR_MAX_ALLOCATIONS)
		nr_metapages = NR_MAX_ALLOCATIONS - 
			INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced);
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, lock_flag);

	while (nr_bioinfos || nr_chgnodes || nr_metapages) {
		if (nr_bioinfos) {
			inm_alloc_bioinfo_pool();
			nr_bioinfos--;
		}

		if (nr_chgnodes) {
			inm_alloc_chdnodes_pool();
			nr_chgnodes--;
		}

		if (nr_metapages) {
			balance_page_pool(GFP_NOIO, 1);
			nr_metapages--;
		}
	}

	alloc_in_progress = 0;
}

void inm_balance_pools(void)
{
	int nr_free = 0;
	unsigned long lock_flag = 0;
	dm_bio_info_t *info;
	change_node_t *chg_node;
	inm_page_t *pg;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->page_pool_lock, lock_flag);
	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced) > 
			 				NR_MAX_ALLOCATIONS)
		nr_free = INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced) - 
							NR_MAX_ALLOCATIONS;

	if (nr_free > NR_MAX_FREED)
		nr_free = NR_MAX_FREED;

	while (nr_free) {
		info = inm_list_entry(driver_ctx->dc_bioinfo_list.next, 
							dm_bio_info_t, entry);
		inm_list_del(&info->entry);
		INM_KFREE(info, sizeof(dm_bio_info_t), INM_KERNEL_HEAP);
		nr_free--;
		INM_ATOMIC_DEC(&driver_ctx->dc_nr_bioinfo_alloced);
	}

	nr_free = 0;
	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced) > 
			 				NR_MAX_ALLOCATIONS)
		nr_free = INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced) - 
							NR_MAX_ALLOCATIONS;

	if (nr_free > NR_MAX_FREED)
		nr_free = NR_MAX_FREED;

	while (nr_free) {
		chg_node = inm_list_entry(driver_ctx->dc_chdnodes_list.next, 
							change_node_t, next);
		inm_list_del(&chg_node->next);
		INM_KFREE(chg_node, sizeof(change_node_t), INM_KERNEL_HEAP);
		nr_free--;
		INM_ATOMIC_DEC(&driver_ctx->dc_nr_chdnodes_alloced);
	}

	nr_free = 0;
	if (INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced) > 
			 				NR_MAX_ALLOCATIONS)
		nr_free = INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced) - 
							NR_MAX_ALLOCATIONS;

	if (nr_free > NR_MAX_FREED)
		nr_free = NR_MAX_FREED;

	while (nr_free) {
		pg = inm_list_entry(driver_ctx->page_pool.next, inm_page_t, 
									entry);
		inm_list_del(&pg->entry);
		INM_UNPIN(pg->cur_pg, INM_PAGESZ);
		INM_FREE_PAGE(pg->cur_pg, INM_KERNEL_HEAP);
		INM_UNPIN(pg, sizeof(inm_page_t));
		INM_KFREE(pg, sizeof(inm_page_t), INM_KERNEL_HEAP);
		nr_free--;
		INM_ATOMIC_DEC(&driver_ctx->dc_nr_metapages_alloced);
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->page_pool_lock, lock_flag);
}

int inm_alloc_thread(void *args)
{
	INM_COMPLETE(&driver_ctx->dc_alloc_thread_started);
	while (1) {
		inm_wait_event_interruptible_timeout(driver_ctx->dc_alloc_thread_waitq,
			((INM_ATOMIC_READ(&driver_ctx->dc_nr_bioinfo_alloced) < NR_MAX_ALLOCATIONS) ||
			(INM_ATOMIC_READ(&driver_ctx->dc_nr_chdnodes_alloced) < NR_MAX_ALLOCATIONS) ||
			(INM_ATOMIC_READ(&driver_ctx->dc_nr_metapages_alloced) < NR_MAX_ALLOCATIONS)),
			60 * INM_HZ);

		if (INM_ATOMIC_READ(&driver_ctx->dc_alloc_thread_quit))
			break;

		inm_alloc_pools();
		INM_DELAY(INM_HZ/1000);
		inm_balance_pools();
	}
	inm_free_bioinfo_pool();
	inm_free_chdnodes_pool();
	INM_COMPLETE(&driver_ctx->dc_alloc_thread_exit);
	info("inmallocd thread exited");
	return 0;
}

int create_alloc_thread(void)
{
	inm_pid_t pid;
	int err = 1;

	INM_INIT_COMPLETION(&driver_ctx->dc_alloc_thread_started);
	INM_INIT_WAITQUEUE_HEAD(&driver_ctx->dc_alloc_thread_waitq);
	INM_INIT_COMPLETION(&driver_ctx->dc_alloc_thread_exit);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_bioinfo_allocs_failed, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_chgnode_allocs_failed, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_metapage_allocs_failed, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_alloc_thread_quit, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_bioinfo_alloced, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_chdnodes_alloced, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_metapages_alloced, 256);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_bioinfo_alloced_from_pool, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_chgnodes_alloced_from_pool, 0);
	INM_ATOMIC_SET(&driver_ctx->dc_nr_metapages_alloced_from_pool, 0);
	INM_INIT_LIST_HEAD(&driver_ctx->dc_bioinfo_list);
	INM_INIT_LIST_HEAD(&driver_ctx->dc_chdnodes_list);

	pid = INM_KERNEL_THREAD(driver_ctx->dc_alloc_thread_task,
				 inm_alloc_thread, NULL, 0, "inmallocd");
	if (pid >= 0) {
		err = 0;
		info("inmallocd thread with pid = %d has created", pid);
		INM_WAIT_FOR_COMPLETION(&driver_ctx->dc_alloc_thread_started);
	}

	return err;
}

void destroy_alloc_thread(void)
{
	INM_ATOMIC_INC(&driver_ctx->dc_alloc_thread_quit);
	wake_up_interruptible(&driver_ctx->dc_alloc_thread_waitq);
	INM_WAIT_FOR_COMPLETION(&driver_ctx->dc_alloc_thread_exit);
	INM_KTHREAD_STOP(driver_ctx->dc_alloc_thread_task);
}

blk_status_t inm_queue_rq(struct blk_mq_hw_ctx *hctx, 
					const struct blk_mq_queue_data *bd)
{
	req_queue_info_t *q_info =  NULL;
	struct request *rq = bd->rq;
	struct request_queue *q = rq->q;
	unsigned long lock_flag = 0;
	queue_rq_fn *orig_queue_rq_fn = NULL;
	struct bio *bio;
	target_context_t *ctx;
	dm_bio_info_t *bio_info;
	inm_u32_t idx;
	sector_t end_sector;
	host_dev_ctx_t *hdcp;
	int is_resized = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);
#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	q_info = get_qinfo_from_kobj(&q->disk->queue_kobj);
#else
	q_info = get_qinfo_from_kobj(&q->kobj);
#endif
	if(q_info){
		orig_queue_rq_fn = q_info->orig_mq_ops->queue_rq;
		ctx = q_info->tc;
		get_tgt_ctxt(ctx);
	}else{
		orig_queue_rq_fn = q->mq_ops->queue_rq;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
				  				lock_flag);
		goto out_orig_queue_rq_fn;
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);

	if (!rq->bio)
		goto out;

	bio = rq->bio;

process_bio:
	/* Handling reads */
	if (!inm_bio_is_write(bio) || !INM_BUF_COUNT(bio) || 
			 			INM_IS_TEST_MIRROR(bio))
		goto next_bio;

	/* Trim requests */
	if (inm_bio_is_discard(bio) && !INM_DISCARD_ZEROES_DATA(q_info->q)) {
		dbg("Trim request: start sector = %llu, len = %d, vcnt = %d",
			(inm_u64_t)INM_BUF_SECTOR(bio), 
			INM_BUF_COUNT(bio), bio->bi_vcnt);
		goto next_bio;
	}

	/* Recursive writes (IO generated by involflt specific thread) */
	if (is_our_io(bio))
		goto next_bio;

	if (ctx->tc_flags & (VCF_VOLUME_CREATING | VCF_VOLUME_DELETING)) {
		goto out;
	}

	if(is_target_filtering_disabled(ctx)) {
		dbg("mirror paused for scsi_id %s",ctx->tc_pname);
		goto out;
	}

	if (bio->bi_end_io == flt_end_io_fn)
		goto next_bio;

	hdcp = (host_dev_ctx_t *) ctx->tc_priv;
	end_sector = INM_BUF_SECTOR(bio) + ((INM_BUF_COUNT(bio) + 511) >> 9) - 1;
	if ((INM_BUF_SECTOR(bio) >= hdcp->hdc_start_sect) &&
		(end_sector <= hdcp->hdc_end_sect))
		goto get_reference;

	volume_lock(ctx);
	if (ctx->tc_flags & VCF_FULL_DEV) {
		/* hdc_actual_end_sect contains the latest size of disk
		* extracted from gendisk. if the IO is beyond the latest
		* size, we assume the disk is resized and mark for resync.
		*/
		if (end_sector > hdcp->hdc_actual_end_sect) {
			is_resized = 1;
			queue_worker_routine_for_set_volume_out_of_sync(ctx,
				           ERROR_TO_REG_INVALID_IO, -EINVAL);
			/* Update actual_end_sect to new size so no
			 * further resyncs are queued
			 */
			hdcp->hdc_actual_end_sect = get_capacity(INM_BUF_DISK(bio)) - 1;
			err("%s: Resize: Expected: %llu, New: %llu",
				ctx->tc_guid, (inm_u64_t)hdcp->hdc_end_sect,
				(inm_u64_t)hdcp->hdc_actual_end_sect);
		}
	} else {
		if (((INM_BUF_SECTOR(bio) >= hdcp->hdc_start_sect) &&
			(INM_BUF_SECTOR(bio) <= hdcp->hdc_end_sect) &&
			(end_sector > hdcp->hdc_end_sect)) || /* Right Overlap */
			((INM_BUF_SECTOR(bio) < hdcp->hdc_start_sect) &&
			(end_sector >= hdcp->hdc_start_sect) &&
			(end_sector <= hdcp->hdc_end_sect)) ||/* left Overlap */
			((INM_BUF_SECTOR(bio) < hdcp->hdc_start_sect) &&
			(end_sector > hdcp->hdc_end_sect)) || /* Super Set    */
			((INM_BUF_SECTOR(bio) > hdcp->hdc_end_sect) &&
			(INM_BUF_SECTOR(bio) <= hdcp->hdc_actual_end_sect))) {
				is_resized = 1;
				err("Unable to handle the spanning I/O across multiple "
						  "partitions/volumes");
				queue_worker_routine_for_set_volume_out_of_sync(ctx,
					     ERROR_TO_REG_INVALID_IO, -EINVAL);
		}
	}
	volume_unlock(ctx);

	if (is_resized)
		goto out;

get_reference:
	get_tgt_ctxt(ctx);

	if (inm_bio_is_discard(bio) && bio->bi_vcnt) {
		err("Discard bio with data is seen");
		inm_handle_bad_bio(ctx, bio);
		put_tgt_ctxt(ctx);
		goto next_bio;
	}

	flt_save_bio_info(ctx, &bio_info, bio);
	if (!bio_info) {
		put_tgt_ctxt(ctx);
		goto next_bio;
	}

	idx = inm_comp_io_bkt_idx(INM_BUF_COUNT(bio));
	INM_ATOMIC_INC(&ctx->tc_stats.io_pat_writes[idx]);
	INM_ATOMIC_INC(&ctx->tc_nr_in_flight_ios);
	if (!driver_ctx->tunable_params.enable_chained_io &&
		INM_IS_CHAINED_BIO(bio)) {
		telemetry_set_exception(ctx->tc_guid, ecUnsupportedBIO,
						 INM_BIO_RW_FLAGS(bio));

		inm_capture_in_metadata(ctx, bio, bio_info);

		bio->bi_end_io = bio_info->bi_end_io;
		bio->bi_private = bio_info->bi_private;

		if (bio_info->orig_bio_copy) {
				INM_KFREE(bio_info->orig_bio_copy, 
					sizeof(struct bio), INM_KERNEL_HEAP);
		}
		INM_DESTROY_SPIN_LOCK(&bio_info->bio_info_lock);
		inm_free_bio_info(bio_info);
		put_tgt_ctxt(ctx);
		INM_ATOMIC_DEC(&ctx->tc_nr_in_flight_ios);
		goto next_bio;
	}

next_bio:
	if (bio == rq->biotail)
		goto out;

	bio = bio->bi_next;
	goto process_bio;

out:
	put_tgt_ctxt(ctx);

out_orig_queue_rq_fn:
	return orig_queue_rq_fn(hctx, bd);
}
#else
int create_alloc_thread(void)
{
	return 0;
}

void destroy_alloc_thread(void)
{
	return;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
blk_qc_t
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
void
#else
int
#endif
flt_make_request_fn(struct request_queue *q, struct bio *bio)
{
	req_queue_info_t *q_info =  NULL;
	target_context_t *ctx;
	dm_bio_info_t *bio_info;
	make_request_fn *orig_make_request_fn = NULL;
	unsigned long lock_flag = 0;
	mirror_vol_entry_t *vol_entry = NULL;
	struct request_queue *atbio_q = NULL;
	inm_mirror_atbuf *atbuf_wrap = NULL;
	inm_mirror_bufinfo_t *imbinfop = NULL;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);
	q_info = get_qinfo_from_kobj(&INM_BUF_DISK(bio)->queue->kobj);
	if(q_info){
		INM_BUG_ON(!q_info->orig_make_req_fn);
		orig_make_request_fn = q_info->orig_make_req_fn;
	}else{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0) || defined SLES12SP4 || \
				defined SLES12SP5 || defined SLES15
		struct request_queue *q = bio->bi_disk->queue;
#else
		struct request_queue *q = bdev_get_queue(bio->bi_bdev);
#endif
		orig_make_request_fn = q->make_request_fn;
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
				  				lock_flag);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
		return orig_make_request_fn(q, bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
		orig_make_request_fn(q, bio);
		return;
#else
		return orig_make_request_fn(q, bio);
#endif
	}
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_host_info.rq_list_lock, 
			 					lock_flag);

	/* Handling reads */
	if (!inm_bio_is_write(bio) || !INM_BUF_COUNT(bio) || 
			 			INM_IS_TEST_MIRROR(bio))
	goto map_and_exit;

	/* Trim requests */
	if (inm_bio_is_discard(bio) && !INM_DISCARD_ZEROES_DATA(q_info->q)) {
		dbg("Trim request: start sector = %llu, len = %d, vcnt = %d",
				(inm_u64_t)INM_BUF_SECTOR(bio), 
				INM_BUF_COUNT(bio), bio->bi_vcnt);
		goto map_and_exit;
	}

	/* Recursive writes (IO generated by involflt specific thread) */
	if(is_our_io(bio))
		goto map_and_exit;

	INM_DOWN_READ(&driver_ctx->tgt_list_sem);

	ctx = get_tgt_ctxt_from_bio(bio);
	if (ctx) {
		inm_u32_t idx = 0;

		if(is_target_filtering_disabled(ctx) || 
			(ctx->tc_dev_type == FILTER_DEV_MIRROR_SETUP && 
			 		is_target_mirror_paused(ctx))) {
				INM_UP_READ(&driver_ctx->tgt_list_sem);
				dbg("mirror paused for scsi_id %s",
								ctx->tc_pname);
				goto map_and_exit;
		}
		if(is_target_read_only(ctx)) {
			INM_UP_READ(&driver_ctx->tgt_list_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) || defined SLES12SP4 || \
				defined SLES12SP5 || defined SLES15
			bio->bi_status = BLK_STS_IOERR;
#else
			bio->bi_error = -EIO;
#endif
			bio_endio(bio);
			return BLK_QC_T_NONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
			bio_endio(bio, -EIO);
			return;
#else
			return -EIO;
#endif
		}

		get_tgt_ctxt(ctx);
		INM_UP_READ(&driver_ctx->tgt_list_sem);

		if (inm_bio_is_discard(bio) && bio->bi_vcnt) {
			err("Discard bio with data is seen");
			inm_handle_bad_bio(ctx, bio);
			put_tgt_ctxt(ctx);
			goto map_and_exit;
		}

		switch(ctx->tc_dev_type) {
		case FILTER_DEV_HOST_VOLUME:
			flt_save_bio_info(ctx, &bio_info, bio);
			balance_page_pool(INM_KM_NOIO, 0);
			idx = inm_comp_io_bkt_idx(INM_BUF_COUNT(bio));
			INM_ATOMIC_INC(&ctx->tc_stats.io_pat_writes[idx]);
			INM_ATOMIC_INC(&ctx->tc_nr_in_flight_ios);

			if (!driver_ctx->tunable_params.enable_chained_io &&
					 INM_IS_CHAINED_BIO(bio)) {
				host_dev_ctx_t *hdcp = ctx->tc_priv;

				telemetry_set_exception(ctx->tc_guid, 
						 ecUnsupportedBIO, 
						 INM_BIO_RW_FLAGS(bio));

				inm_capture_in_metadata(ctx, bio, bio_info);

				bio->bi_end_io = bio_info->bi_end_io;
				bio->bi_private = bio_info->bi_private;

				if (bio_info->orig_bio_copy) {
					INM_KFREE(bio_info->orig_bio_copy, 
							  sizeof(struct bio),
							  INM_KERNEL_HEAP);
				}
				INM_DESTROY_SPIN_LOCK(&bio_info->bio_info_lock);
				INM_MEMPOOL_FREE(bio_info, hdcp->hdc_bio_info_pool);
				put_tgt_ctxt(ctx);
				INM_ATOMIC_DEC(&ctx->tc_nr_in_flight_ios);
				goto map_and_exit;
			}

				break;
		case FILTER_DEV_MIRROR_SETUP:
			volume_lock(ctx);
			vol_entry = get_cur_vol_entry(ctx, INM_BUF_COUNT(bio));
			volume_unlock(ctx);
			if (inm_save_mirror_bufinfo(ctx, &imbinfop, &bio, vol_entry)) {
				INM_DEREF_VOL_ENTRY(vol_entry, ctx);
			} else {
				INM_BUG_ON(!imbinfop);
				atbuf_wrap = inm_list_entry(imbinfop->imb_atbuf_list.next, 
					inm_mirror_atbuf, imb_atbuf_this);
				atbio_q = bdev_get_queue(vol_entry->mirror_dev);
				if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG_MIRROR_IO))) {
					info("Intial mirror config - atio bi_sector:%llu bi_size:%d rw:%d"
						"bi_rw:%d atbuf:%p", 
						(inm_u64_t)(INM_BUF_SECTOR(&(atbuf_wrap->imb_atbuf_buf)) * 512),
						INM_BUF_COUNT(&(atbuf_wrap->imb_atbuf_buf)),
						(int)(inm_bio_is_write(&atbuf_wrap->imb_atbuf_buf)),
						(int)(inm_bio_rw(&atbuf_wrap->imb_atbuf_buf)),
						&(atbuf_wrap->imb_atbuf_buf));
				}
				atbio_q->make_request_fn(atbio_q, 
						&(atbuf_wrap->imb_atbuf_buf));
				put_tgt_ctxt(ctx);
			}
			break;
		case FILTER_DEV_FABRIC_LUN:
			INM_BUG_ON(1);

		default:
			break;
		}
	} else {
		INM_UP_READ(&driver_ctx->tgt_list_sem);
	}

map_and_exit:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	return orig_make_request_fn(q, bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	orig_make_request_fn(q, bio);
#else
	return orig_make_request_fn(q, bio);
#endif
}
#endif

static_inline void
flt_disk_removal(struct kobject *kobj)
{
	target_context_t *ctx = NULL;
	char *save_guid = NULL;

	if(!get_path_memory(&save_guid)) {
		err("Failed to get memory while removing the disk");
	}

	dbg("entered");
	if (driver_ctx->sys_shutdown) {
		dbg("disk removal ignored\n");
		if (save_guid)
			free_path_memory(&save_guid);
		return;
	}

	down_read(&(driver_ctx->tgt_list_sem));
	ctx = get_tgt_ctxt_from_kobj(kobj);
	if (ctx == NULL){
		up_read(&(driver_ctx->tgt_list_sem));
		return;
	}
	volume_lock(ctx);
	ctx->tc_flags |= VCF_VOLUME_DELETING;
	ctx->tc_filtering_disable_required = 0;
	close_disk_cx_session(ctx, CX_CLOSE_DISK_REMOVAL);
	set_tag_drain_notify_status(ctx, TAG_STATUS_DROPPED, 
						DEVICE_STATUS_REMOVED);
	volume_unlock(ctx);
	
	if (driver_ctx->dc_root_disk == ctx)
		driver_ctx->dc_root_disk = NULL;

	up_read(&(driver_ctx->tgt_list_sem));

	if (save_guid) {
		strncpy_s(save_guid, INM_PATH_MAX, ctx->tc_pname, PATH_MAX);
	}
	if (ctx->tc_bp->volume_bitmap) {
		wait_for_all_writes_to_complete(ctx->tc_bp->volume_bitmap);
		flush_and_close_bitmap_file(ctx);
	}

	tgt_ctx_force_soft_remove(ctx);
	put_tgt_ctxt(ctx);
	/* When volume goes offline and comes back up online, it should 
	 * be able to restart the filtering. To make sure that happens, 
	 * set VolumeFilteringDisabled to FALSE
	 */
	if (save_guid) {
		inm_write_guid_attr(save_guid, VolumeFilteringDisabled, 0);
		free_path_memory(&save_guid);
	}
	dbg("leaving");
}

void flt_disk_obj_rel(struct kobject *kobj)
{
	struct gendisk *disk = NULL;
	struct kobject *qkobj = NULL;
	struct device *dev = NULL;

	dbg("Disk Removal");

#if (defined(RHEL_MAJOR) && (RHEL_MAJOR == 5))
	if (!kobj->parent || !kobj->parent->name)
		goto out;

	if (strcmp(kobj->parent->name, "block"))
		goto out;

	disk = kobj_to_disk(kobj);
#else
	dev = kobj_to_dev(kobj);

	if (!dev->type || !dev->type->name)
		goto out;

	if (strcmp(dev->type->name, "disk"))
		goto out;

	disk = dev_to_disk(dev);
#endif

	if (!disk->queue)
		goto out;

#if defined(RHEL9_3) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
	qkobj = &disk->queue_kobj;
#else
	qkobj = &disk->queue->kobj;
#endif
	dbg("%s: queue = %p, kobj = %p, qkobj = %p", disk->disk_name, 
			 			disk->queue, kobj, qkobj);
	
	if (!get_qinfo_from_kobj(qkobj)) {
		info("%s: not protected", disk->disk_name);
	} else {
		info("%s: protected", disk->disk_name);
		flt_disk_removal(kobj);
	}

out:
	INM_BUG_ON(NULL == flt_disk_release_fn);
	flt_disk_release_fn(kobj);
}

void flt_part_obj_rel(struct kobject *kobj)
{
	dbg("Partition Removal:");    
	flt_disk_removal(kobj);
	INM_BUG_ON(NULL == flt_part_release_fn);
	flt_part_release_fn(kobj);    
}

void flt_queue_obj_rel(struct kobject *kobj)
{
	req_queue_info_t *req_q = NULL;

	req_q = get_qinfo_from_kobj(kobj);
	INM_BUG_ON(NULL == req_q);

	dbg("Calling Original queue release function");

	if(req_q->orig_kobj_type->release)
		req_q->orig_kobj_type->release(kobj);    
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static void completion_check_endio(struct bio *bio)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static void completion_check_endio(struct bio *bio, inm_s32_t error)
#else
static inm_s32_t completion_check_endio(struct bio *bio, inm_u32_t done, 
							inm_s32_t error)
#endif
{
	completion_chk_req_t *req;
	target_context_t *ctx;

	req = bio->bi_private;
	ctx = req->ctx;

	if(in_irq()) {
		dbg("Completion called in Interrupt context for %s", ctx->tc_guid);
		ctx->tc_lock_fn = volume_lock_irqsave;
		ctx->tc_unlock_fn = volume_unlock_irqrestore;
	} else if(in_softirq()){
		dbg("Completion called in Soft Interrupt context for %s", 
			 					ctx->tc_guid);
		ctx->tc_lock_fn = volume_lock_bh;
		ctx->tc_unlock_fn = volume_unlock_bh;
	} 
	
	__free_page(bio->bi_io_vec[0].bv_page);
	bio->bi_io_vec[0].bv_page = NULL;

	bio_put(bio);

	INM_COMPLETE(&req->comp);
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	return 0;
#endif
}

target_context_t *
flt_gendisk_to_tgt_ctxt(struct gendisk *disk)
{
	target_context_t    *tgt_ctx = NULL;
	struct kobject      *kobj = NULL;

#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 5)
	kobj = &(disk->kobj);
#else
	kobj = &((disk_to_dev(disk))->kobj);
#endif

	INM_DOWN_READ(&(driver_ctx->tgt_list_sem));
	tgt_ctx = get_tgt_ctxt_from_kobj(kobj);
	INM_UP_READ(&(driver_ctx->tgt_list_sem));

	return tgt_ctx;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
int
flt_revalidate_disk(struct gendisk *disk)
{
	target_context_t    *tgt_ctx = NULL;
	host_dev_ctx_t      *hdcp = NULL;
	host_dev_t          *hdc_dev = NULL;
	sector_t            nr_sect = 0;
	int (*org_revalidate_disk) (struct gendisk *) = NULL;
	int error = 0;

	dbg("Revalidating disk");

	tgt_ctx = flt_gendisk_to_tgt_ctxt(disk);
	if (!tgt_ctx) {
		INM_BUG_ON(!tgt_ctx);
		return -1;
	}

	hdcp = tgt_ctx->tc_priv;
	hdc_dev = inm_list_entry((hdcp->hdc_dev_list_head.next), host_dev_t, 
							  hdc_dev_list);

	/*
	 * Call the original revalidate_disk() and
	 * then check for changes in disk properties.
	 *
	 * unregister_disk_notification() can happen 
	 * on another CPU so check should be protected
	 * by volume lock. However revalidation is IO bound
	 * and cannot be called under volume spinlock
	 * so assign it to temp func ptr and call the func
	 * ptr outside the lock.
	 */
	volume_lock(tgt_ctx);
	if (hdc_dev->hdc_fops &&                
		hdc_dev->hdc_fops->revalidate_disk)
		org_revalidate_disk = hdc_dev->hdc_fops->revalidate_disk;
	volume_unlock(tgt_ctx);

	if (org_revalidate_disk)
		error = org_revalidate_disk(disk);

	nr_sect = get_capacity(disk);
  
	volume_lock(tgt_ctx);
	/*
	 * get_capacity() returns no. of 512 byte sector 
	 * irrespective of physical sector size
	 */
	if (nr_sect != (hdcp->hdc_volume_size >> 9)) {
		err("%s capacity change ... marking for resync", 
				  			tgt_ctx->tc_guid);
		queue_worker_routine_for_set_volume_out_of_sync(tgt_ctx, 
				  	ERROR_TO_REG_INVALID_IO, -EINVAL);
		/* update actual end sector so writes do not trigger another resync */
		hdcp->hdc_actual_end_sect = nr_sect - 1;
	}
	volume_unlock(tgt_ctx);
	
	put_tgt_ctxt(tgt_ctx);

	/* return error code from original revalidate_disk() */
	return error; 
}
#endif

void
unregister_disk_change_notification(target_context_t *ctx, host_dev_t *hdc_dev) 
{
	struct gendisk *disk = hdc_dev->hdc_disk_ptr;
	const struct block_device_operations *flt_fops;

	if (!hdc_dev->hdc_fops || !disk || !disk->fops) {
		dbg("Unregister disk notification not required");
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	if (disk->fops->revalidate_disk != flt_revalidate_disk) {
		INM_BUG_ON(disk->fops->revalidate_disk != 
				  			flt_revalidate_disk);
		return;
	}
#endif

	dbg("Unregistering for disk change notification");
	
	flt_fops = disk->fops;
	volume_lock(ctx);
	disk->fops = hdc_dev->hdc_fops;
	hdc_dev->hdc_fops = NULL;
	volume_unlock(ctx);
	
	INM_KFREE(flt_fops, sizeof(*flt_fops), INM_KERNEL_HEAP);
}

void
register_disk_change_notification(target_context_t *ctx, host_dev_t *hdc_dev)
{
	struct gendisk *disk = hdc_dev->hdc_disk_ptr;
	struct block_device_operations *flt_fops = NULL;
	host_dev_ctx_t      *hdcp = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	if (disk->fops->revalidate_disk == flt_revalidate_disk) {
		INM_BUG_ON(disk->fops->revalidate_disk == 
				  			flt_revalidate_disk);
		return;
	}
#endif
  
	/*
	 * If the allocation fails, we fall back to beyond range 
	 * check in make_request_fn to determine disk resize.
	 */
	flt_fops = INM_KMALLOC(sizeof(*flt_fops), INM_KM_SLEEP,
							INM_KERNEL_HEAP);
	if (!flt_fops) {
		err("Failed to allocate memory for registration");
		return;
	}

	if (memcpy_s(flt_fops, sizeof(*flt_fops), disk->fops, 
					  sizeof(*(disk->fops)))) {
		INM_KFREE(flt_fops, sizeof(*flt_fops), INM_KERNEL_HEAP);
		return;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
	flt_fops->revalidate_disk = flt_revalidate_disk;
#endif

	dbg("Registering for disk change notification");

	volume_lock(ctx);
	hdc_dev->hdc_fops = disk->fops;
	disk->fops = flt_fops;
	volume_unlock(ctx);

	/* Check if the expected and actual sizes match */
	hdcp = ctx->tc_priv;
	if (hdcp->hdc_end_sect != hdcp->hdc_actual_end_sect) {
		err("%s: Resize: Expected: %llu, New: %llu",
				ctx->tc_guid, (inm_u64_t)hdcp->hdc_end_sect, 
				(inm_u64_t)hdcp->hdc_actual_end_sect);

		set_volume_out_of_sync(ctx, ERROR_TO_REG_INVALID_IO, -EBADF);
	}
}
	
int
stack_host_dev(target_context_t *ctx, inm_dev_extinfo_t *dinfo)
{
	inm_s32_t ret = 0;
	req_queue_info_t *q_info;
	inm_s32_t found = 0;
	inm_s32_t last_char_pos = 0;
	inm_block_device_t *bdev;
	host_dev_ctx_t *hdcp;
	target_context_t *tgt_ctx;
	struct inm_list_head *ptr1, *ptr2;
	host_dev_t *hdc_dev = NULL;
	mirror_vol_entry_t *vol_entry = NULL;

	hdcp = (host_dev_ctx_t *)ctx->tc_priv;
	bdev = open_by_dev_path(dinfo->d_guid, 0); /* open by device path */
	if (!bdev) {
		dbg("Failed to convert dev path (%s) to bdev", dinfo->d_guid);
		ret = -ENODEV;
		return ret;
	}

	hdcp->hdc_bio_info_pool =
		INM_MEMPOOL_CREATE(BIO_INFO_MPOOL_SIZE, 
				INM_MEMPOOL_ALLOC_SLAB,
				INM_MEMPOOL_FREE_SLAB,
				driver_ctx->dc_host_info.bio_info_cache);
	if (!hdcp->hdc_bio_info_pool) {
		err("INM_MEMPOOL_CREATE failed");
		close_bdev(bdev, FMODE_READ);
		ret = -ENOMEM;
		return ret;
	}

	/* Check the completion context and reset the pointers accordingly.
	 * if this function fails, we have the default safer ones.
	 */
	INM_DOWN_READ(&driver_ctx->tgt_list_sem);
retry:
	__inm_list_for_each(ptr1, &driver_ctx->tgt_list) {
		tgt_ctx = inm_list_entry(ptr1, target_context_t, tc_list);
		if(tgt_ctx == ctx)
			break;

		if (tgt_ctx->tc_dev_type == FILTER_DEV_HOST_VOLUME || 
			tgt_ctx->tc_dev_type == FILTER_DEV_MIRROR_SETUP) {
			host_dev_ctx_t *hdcp_ptr = 
				  	(host_dev_ctx_t *) tgt_ctx->tc_priv;
			hdc_dev = inm_list_entry(hdcp_ptr->hdc_dev_list_head.next,
						host_dev_t, hdc_dev_list);
			INM_BUG_ON(!hdc_dev);
			if (hdc_dev->hdc_disk_ptr ==  bdev->bd_disk) {
				if (tgt_ctx->tc_flags & VCF_VOLUME_CREATING) {
					if (check_for_tc_state(tgt_ctx, 0)) {
						tgt_ctx = NULL;
						goto retry;
					}
				}
				ctx->tc_lock_fn = tgt_ctx->tc_lock_fn;
				ctx->tc_unlock_fn = tgt_ctx->tc_unlock_fn;
				found = 1;
				break;
			}
		}
	}
	INM_UP_READ(&driver_ctx->tgt_list_sem);

	switch (dinfo->d_type) {
		case FILTER_DEV_HOST_VOLUME:
			q_info = alloc_and_init_qinfo(bdev, ctx);
			if (!q_info) {
				ret = -EINVAL;
				err("Failed to allocate and initialize q_info");
				break;
			}
			hdc_dev = NULL;
			__inm_list_for_each(ptr2, 
					&hdcp->hdc_dev_list_head) {
				hdc_dev = inm_list_entry(ptr2, 
					host_dev_t, hdc_dev_list);
				if (hdc_dev->hdc_dev == bdev->bd_inode->i_rdev)
					break;
				hdc_dev = NULL;
			}
			if (hdc_dev) {
				hdc_dev->hdc_req_q_ptr = q_info;
				INM_ATOMIC_INC(&q_info->vol_users);
				init_tc_kobj(q_info, bdev, 
						&hdc_dev->hdc_disk_kobj_ptr);
			}
			else
				 ret = -EINVAL;

			break;
		case FILTER_DEV_MIRROR_SETUP:
			__inm_list_for_each(ptr1, dinfo->src_list) {
				vol_entry = inm_list_entry(ptr1, 
						mirror_vol_entry_t, next);

				__inm_list_for_each(ptr2, 
						&hdcp->hdc_dev_list_head) {
					hdc_dev = inm_list_entry(ptr2, 
						host_dev_t, hdc_dev_list);
					if (hdc_dev->hdc_dev == 
						vol_entry->mirror_dev->bd_inode->i_rdev)
						break;
					hdc_dev = NULL;
				}
				if (hdc_dev) {
					q_info = alloc_and_init_qinfo(vol_entry->mirror_dev, ctx);
					if (!q_info) {
						ret = -EINVAL;
						err("Failed to allocate and initialize q_info during mirror setup");
						break;
					}
					hdc_dev->hdc_req_q_ptr = q_info;
					INM_ATOMIC_INC(&q_info->vol_users);
				}
				else {
					err("Failed to find the hdcp device entry for volume:%s\n",
						vol_entry->tc_mirror_guid);
					ret = -EINVAL;
					break;
				}
				init_tc_kobj(q_info, vol_entry->mirror_dev, 
						&hdc_dev->hdc_disk_kobj_ptr);
			}
			break;
		case FILTER_DEV_FABRIC_LUN:
				INM_BUG_ON(1);
				break;
		default:
				err("Invalid filtering device type\n");
				INM_BUG_ON(1);
				ret = -EINVAL;
	}
	close_bdev(bdev, FMODE_READ);
	if (ret) {
		inm_rel_dev_resources(ctx, hdcp);
		return ret;
	
	}

	/* If the volume is marked for stop filtering, then use the size
	 * provided by the user-space. Otherwise, use the persistent store
	 * size
	 */
	if ((ctx->tc_flags & VCF_FILTERING_STOPPED) || 
		(ctx->tc_flags & VCF_VOLUME_STACKED_PARTIALLY)){
		host_dev_ctx_t *hdcp = ctx->tc_priv;
		hdcp->hdc_bsize = dinfo->d_bsize;
		hdcp->hdc_nblocks = dinfo->d_nblks;
		set_int_vol_attr(ctx, VolumeBsize, hdcp->hdc_bsize);
		set_unsignedlonglong_vol_attr(ctx, VolumeNblks, 
				  			hdcp->hdc_nblocks);
	}

	/* get volume size */
	hdcp->hdc_volume_size = hdcp->hdc_bsize * hdcp->hdc_nblocks;
	hdcp->hdc_end_sect = hdcp->hdc_start_sect + (hdcp->hdc_volume_size >> 9) - 1;

	volume_lock(ctx);
	/* set full disk flag */
	last_char_pos = strlen(tgt_ctx->tc_guid)-1; /* last char */
	if ( ! ((tgt_ctx->tc_guid[last_char_pos] >= '0') &&
				(tgt_ctx->tc_guid[last_char_pos] <= '9')) ) {
		ctx->tc_flags |= VCF_FULL_DEV;
	}
	volume_unlock(ctx);

	if (ctx->tc_flags & VCF_FULL_DEV) {
		/*
		 * Register for disk size change notification
		 */
		register_disk_change_notification(ctx, hdc_dev);
	}

	return 0;
}

inm_s32_t get_root_info(void)
{
	struct file *f = NULL;

	f = filp_open("/", O_RDONLY, 0400);
	if (!f) {
		err("Can't open / ");
		return -1;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	driver_ctx->root_dev = INM_HDL_TO_INODE(f)->i_sb->s_dev;
#else
	driver_ctx->root_dev = f->f_dentry->d_sb->s_dev;
#endif
	filp_close(f, current->files);
	dbg("Root dev_t = %u,%u", MAJOR(driver_ctx->root_dev), 
			MINOR(driver_ctx->root_dev));
	return 0;
}

inm_s32_t get_boot_dev_t(inm_dev_t *dev)
{
	struct file *f = NULL;

	f = filp_open("/boot", O_RDONLY, 0400);
	if (!f) {
		err("Can't open /boot");
		return -1;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
	*dev = INM_HDL_TO_INODE(f)->i_sb->s_dev;
#else
	*dev = f->f_dentry->d_sb->s_dev;
#endif
	filp_close(f, current->files);
	return 0;
}

/*
 * Indicates if disk is root disk
 * Matches the gendisk structure of passed disk against that of root/boot partition
 */
inm_s32_t 
isrootdisk(target_context_t *vcptr)
{
	inm_block_device_t *rbdev = NULL;
	host_dev_ctx_t *hdcp = NULL;
	host_dev_t *hdc_dev = NULL;
	struct inm_list_head *hptr = NULL;
	inm_s32_t isroot = 0;
	inm_dev_t boot_dev = 0;

	do {
		if (vcptr->tc_dev_type != FILTER_DEV_HOST_VOLUME &&
				vcptr->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
			break;

		if (!driver_ctx->root_dev)
			break;

		rbdev = inm_open_by_devnum(driver_ctx->root_dev, FMODE_READ);
		if (IS_ERR(rbdev))
			break;

		dbg("Root gendisk name %p = %s", 
				rbdev->bd_disk, rbdev->bd_disk->disk_name);
		hdcp = (host_dev_ctx_t *)vcptr->tc_priv;
		if (hdcp) {
			__inm_list_for_each(hptr, &hdcp->hdc_dev_list_head) {
				hdc_dev = inm_list_entry(hptr, host_dev_t, 
								hdc_dev_list);
				dbg("Disk ptr = %p = %s", 
					hdc_dev->hdc_disk_ptr, 
					hdc_dev->hdc_disk_ptr->disk_name);
				if (hdc_dev->hdc_disk_ptr == rbdev->bd_disk) {
					dbg("Root Dev = %s", vcptr->tc_guid);
					isroot = 1;
					break;
				}
				hdc_dev = NULL;
			}
		}

		close_bdev(rbdev, FMODE_READ);

		if (isroot)
			break;

		if (get_boot_dev_t(&boot_dev))
			break;

		rbdev = inm_open_by_devnum(boot_dev, FMODE_READ);
		if (IS_ERR(rbdev))
			break;

		dbg("Boot gendisk name %p = %s", 
				rbdev->bd_disk, rbdev->bd_disk->disk_name);
		hdcp = (host_dev_ctx_t *)vcptr->tc_priv;
		if (hdcp) {
			__inm_list_for_each(hptr, &hdcp->hdc_dev_list_head) {
				 hdc_dev = inm_list_entry(hptr, host_dev_t, 
						 		hdc_dev_list);
				 if (hdc_dev->hdc_disk_ptr == rbdev->bd_disk) {
					  dbg("Root Dev = %s", vcptr->tc_guid);
					  isroot = 1;
					  break;
				 }
				 hdc_dev = NULL;
			}
		}

		close_bdev(rbdev, FMODE_READ);
	} while(0);

	return isroot;
}

/*
 * Indicates if volume/partition is root volume
 * Matches dev_t of passed volume against root device
 */
inm_s32_t 
isrootvol(target_context_t *vcptr)
{
	inm_dev_t vdev = 0;
	inm_s32_t isroot = 0;

	do {
		if (vcptr->tc_dev_type != FILTER_DEV_HOST_VOLUME &&
				vcptr->tc_dev_type != FILTER_DEV_MIRROR_SETUP)
			break;

		if (!driver_ctx->root_dev)
			break;

		if (!convert_path_to_dev(vcptr->tc_guid, &vdev)) {
			if (vdev == driver_ctx->root_dev) {
				 dbg("Root Dev = %s", vcptr->tc_guid);
				 isroot = 1;
			}
		}

	} while(0);

	return isroot;
}

/* Character interface functions exported by involflt DM target module.
 */
inm_s32_t flt_open(struct inode *inode, struct file *filp)
{
	/* Nothing much to do here. */
	filp->private_data = NULL;
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
inm_s32_t flt_ioctl(struct inode *inode, struct file *filp, inm_u32_t cmd,
			 unsigned long arg)
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
long flt_ioctl(struct file *filp, inm_u32_t cmd, unsigned long arg)
#else
inm_s32_t flt_ioctl(struct file *filp, inm_u32_t cmd, unsigned long arg)
#endif
#endif
{
	inm_s32_t error = 0;

	/* if driver is getting unloaded then fail the IOCTLs */
	if (inm_mod_state & INM_ALLOW_UNLOAD) {
		err("Driver is being unloaded now");
		return INM_EINVAL;
	}

	switch(cmd) {
	case IOCTL_INMAGE_VOLUME_STACKING:
		error = process_volume_stacking_ioctl(filp, 
							(void __user *)arg);
		break;    

	case IOCTL_INMAGE_MIRROR_VOLUME_STACKING:
		error = process_mirror_volume_stacking_ioctl(filp, 
				  			(void __user *)arg);
		break;    

	case IOCTL_INMAGE_PROCESS_START_NOTIFY:
		error = process_start_notify_ioctl(filp, (void __user *)arg);
		break;    

	case IOCTL_INMAGE_SERVICE_SHUTDOWN_NOTIFY:
		error = process_shutdown_notify_ioctl(filp, 
							(void __user *) arg);
		break;

	case IOCTL_INMAGE_STOP_FILTERING_DEVICE:
		error = process_stop_filtering_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_REMOVE_FILTER_DEVICE:
		error = process_remove_filter_device_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_START_FILTERING_DEVICE_V2:
		error = process_start_filtering_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_FREEZE_VOLUME:
		error = process_freeze_volume_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_THAW_VOLUME:
		error = process_thaw_volume_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_TAG_VOLUME_V2:
		error = process_tag_volume_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_TAG_COMMIT_V2:
		error = process_commit_revert_tag_ioctl(filp, 
							(void __user *)arg);
		break;
	
	case IOCTL_INMAGE_CREATE_BARRIER_ALL:
		error = process_create_iobarrier_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_REMOVE_BARRIER_ALL:
		error = process_remove_iobarrier_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_IOBARRIER_TAG_VOLUME:
		error = process_iobarrier_tag_volume_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_START_MIRRORING_DEVICE:
		error = process_start_mirroring_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_STOP_MIRRORING_DEVICE:
		error = process_stop_mirroring_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_GET_DIRTY_BLOCKS_TRANS_V2:
		error = process_get_db_ioctl(filp, (void __user *) arg);
		break;

	case IOCTL_INMAGE_COMMIT_DIRTY_BLOCKS_TRANS:
		error = process_commit_db_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_GET_NANOSECOND_TIME:
		error = process_get_time_ioctl((void __user *)arg);
		break;

	case IOCTL_INMAGE_CLEAR_DIFFERENTIALS:
		error = process_clear_diffs_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_GET_VOLUME_FLAGS:
		error = process_get_volume_flags_ioctl(filp, 
							(void __user *)arg);
		break;
				
	case IOCTL_INMAGE_SET_VOLUME_FLAGS:
		error = process_set_volume_flags_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_WAIT_FOR_DB:
		error = process_wait_for_db_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_WAIT_FOR_DB_V2:
		error = process_wait_for_db_v2_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_UNSTACK_ALL:
		do_unstack_all();
		break;

	case IOCTL_INMAGE_SYS_SHUTDOWN:
		error = process_sys_shutdown_notify_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_SYS_PRE_SHUTDOWN:
		error = process_sys_pre_shutdown_notify_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_TAG_VOLUME:
		error = process_tag_ioctl(filp, (void __user *)arg, ASYNC_TAG);
		break;

	case IOCTL_INMAGE_SYNC_TAG_VOLUME:
		error = process_tag_ioctl(filp, (void __user *)arg, SYNC_TAG);
		break;

	case IOCTL_INMAGE_GET_TAG_VOLUME_STATUS:
		error = process_get_tag_status_ioctl(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_WAKEUP_ALL_THREADS:
		error = process_wake_all_threads_ioctl(filp,
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_GET_DB_NOTIFY_THRESHOLD:
		error = process_get_db_threshold(filp,(void __user *)arg);
		break;

	case IOCTL_INMAGE_RESYNC_START_NOTIFICATION:
		error = process_resync_start_ioctl(filp,(void __user *)arg);
		break;

	case IOCTL_INMAGE_RESYNC_END_NOTIFICATION:
		error = process_resync_end_ioctl(filp,(void __user *)arg);
		break;

	case IOCTL_INMAGE_GET_DRIVER_VERSION:
		error = process_get_driver_version_ioctl(filp,
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_SHELL_LOG:
		error = process_shell_log_ioctl(filp, (void __user *) arg);
		break;

	case IOCTL_INMAGE_AT_LUN_CREATE:
		error = process_at_lun_create(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_AT_LUN_DELETE:
		error = process_at_lun_delete(filp, (void __user *)arg);
		break;

	case IOCTL_INMAGE_AT_LUN_LAST_WRITE_VI:
		error = process_at_lun_last_write_vi(filp, 
							(void __user *) arg);
		break;

	case IOCTL_INMAGE_AT_LUN_LAST_HOST_IO_TIMESTAMP:
		error = process_at_lun_last_host_io_timestamp(filp, 
							(void __user *) arg);
		break;

	case IOCTL_INMAGE_AT_LUN_QUERY:
		error = process_at_lun_query(filp, (void __user*) arg);
		break;

	case IOCTL_INMAGE_GET_GLOBAL_STATS:
		error = process_get_global_stats_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_GLOBAL_STATS ioctl err = %d\n", error);
		break;

	case IOCTL_INMAGE_GET_VOLUME_STATS:
		error = process_get_volume_stats_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_VOLUME_STATS ioctl err = %d\n", error);
		break;

	case IOCTL_INMAGE_GET_VOLUME_STATS_V2:
		error = process_get_volume_stats_v2_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_VOLUME_STATS_V2 ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_GET_MONITORING_STATS:
		error = process_get_monitoring_stats_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_MONITORING_STATS ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_GET_PROTECTED_VOLUME_LIST:
		error = process_get_protected_volume_list_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_PROTECTED_VOLUME_LIST ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_GET_SET_ATTR:
		error = process_get_set_attr_ioctl(filp, (void __user*)arg);
		dbg("IOCTL_INMAGE_GET_SET_ATTR ioctl err = %d\n", error);
		break;

	case IOCTL_INMAGE_BOOTTIME_STACKING:
		error = process_boottime_stacking_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_BOOTTIME_STACKING ioctl err = %d\n", error);
		break;

	case IOCTL_INMAGE_VOLUME_UNSTACKING:
		error = process_volume_unstacking_ioctl(filp, 
							(void __user *)arg);
		break;

	case IOCTL_INMAGE_MIRROR_EXCEPTION_NOTIFY:
		error = process_mirror_exception_notify_ioctl(filp, 
							(void *)arg);
		dbg("IOCTL_INMAGE_MIRROR_EXCEPTION_NOTIFY ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_GET_ADDITIONAL_VOLUME_STATS:
		error = process_get_additional_volume_stats(filp, 
							(void __user *) arg);
		dbg("IOCTL_INMAGE_GET_ADDITIONAL_VOLUME_STATS ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_GET_VOLUME_LATENCY_STATS:
		error = process_get_volume_latency_stats(filp, 
							(void __user *) arg);
		dbg("IOCTL_INMAGE_GET_VOLUME_LATENCY_STATS ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_GET_VOLUME_BMAP_STATS:
		error = process_bitmap_stats_ioctl(filp, (void __user *)arg);
		dbg("IOCTL_INMAGE_GET_VOLUME_BMAP_STATS ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_SET_INVOLFLT_VERBOSITY:
		error = process_set_involflt_verbosity(filp, 
							(void __user *)arg);
		dbg("IOCTL_INMAGE_SET_INVOLFLT_VERBOSITY ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_MIRROR_TEST_HEARTBEAT:
		error = process_mirror_test_heartbeat(filp, 
							(void __user *)arg);
		dbg("IOCTL_INMAGE_MIRROR_TEST_HEARTBEAT ioctl err = %d\n", 
							error);
		break;

	case IOCTL_INMAGE_BLOCK_AT_LUN:
		error = process_block_at_lun(filp, (void __user *)arg);
		dbg("IOCTL_INMAGE_BLOCK_AT_LUN ioctl err = %d\n", error);
		break;

	case IOCTL_INMAGE_GET_BLK_MQ_STATUS:
		error = process_get_blk_mq_status_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_BLK_MQ_STATUS ioctl err = %d", error);
		break;

	case IOCTL_INMAGE_REPLICATION_STATE:
		error = process_replication_state_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_REPLICATION_STATE ioctl err = %d", error);
		break;

	case IOCTL_INMAGE_NAME_MAPPING:
		error = process_name_mapping_ioctl(filp, (void __user*)arg);
		dbg("IOCTL_INMAGE_NAME_MAPPING ioctl err = %d", error);
		break;

	case IOCTL_INMAGE_LCW:
		error = process_lcw_ioctl(filp, (void __user*)arg);
		dbg("IOCTL_INMAGE_LCW ioctl err = %d", error);
		break;

	case IOCTL_INMAGE_INIT_DRIVER_FULLY:
		error = process_init_driver_fully(filp, (void *)arg);
		dbg("IOCTL_INMAGE_INIT_DRIVER_FULLY err = %d\n", error);
		break;

	case IOCTL_INMAGE_COMMITDB_FAIL_TRANS:
		error = process_commitdb_fail_trans_ioctl(filp, 
		(void __user*)arg);
		dbg("IOCTL_INMAGE_COMMITDB_FAIL_TRANS err = %d\n", error);
		break;

	case IOCTL_INMAGE_GET_CXSTATS_NOTIFY:
		error = process_get_cxstatus_notify_ioctl(filp, 
		(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_CXSTATS_NOTIFY err = %d\n", error);
		break;

	case IOCTL_INMAGE_WAKEUP_GET_CXSTATS_NOTIFY_THREAD:
		error = process_wakeup_get_cxstatus_notify_ioctl(filp, 
		(void __user*)arg);
		dbg("IOCTL_INMAGE_WAKEUP_GET_CXSTATS_NOTIFY_THREAD err = %d\n", 
		error);
		break;

	case IOCTL_INMAGE_TAG_DRAIN_NOTIFY:
		error = process_tag_drain_notify_ioctl(filp, 
		(void __user*)arg);
		dbg("IOCTL_INMAGE_TAG_DRAIN_NOTIFY err = %d\n", error);
		break;

	case IOCTL_INMAGE_WAKEUP_TAG_DRAIN_NOTIFY_THREAD:
		error = process_wakeup_tag_drain_notify_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_WAKEUP_TAG_DRAIN_NOTIFY_THREAD err = %d\n", 
		error);
		break;

	case IOCTL_INMAGE_MODIFY_PERSISTENT_DEVICE_NAME:
		error = process_modify_persistent_device_name(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_MODIFY_PERSISTENT_DEVICE_NAME err = %d\n", 
		error);
		break;

	case IOCTL_INMAGE_GET_DRAIN_STATE:
		error = process_get_drain_state_ioctl(filp, 
							(void __user*)arg);
		dbg("IOCTL_INMAGE_GET_DRAIN_STATE err = %d\n", error);
		break;

	case IOCTL_INMAGE_SET_DRAIN_STATE:
		error = process_set_drain_state_ioctl(filp, (void __user*)arg);
		dbg("IOCTL_INMAGE_SET_DRAIN_STATE err = %d\n", error);
		break;

	default:
		err("Invalid ioctl command(%u) issued by pid %d process %s",
					cmd, current->pid, current->comm);
		error = INM_EINVAL;
	}

	return error;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,17)
#if (suse && DISTRO_VER==10 && PATCH_LEVEL==2)
int
flt_flush(struct file *filp, fl_owner_t id)
#else
inm_s32_t flt_flush(struct file *filp)
#endif
{
	/* Need to distinguish between noraml close and drainer shutdown in which
	 * we need to perform the cleanup.
	 */

	/* Perform cleanup due to drainer shutdown. private_data will be
	 * set to non-null for fd which issues PROCESS_START_NOTIFY.
	 */    

	return 0;
}
#else
inm_s32_t flt_flush(struct file *filp, fl_owner_t id)
{
	return 0;
}
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)) && defined(CONFIG_HIGHMEM)
static struct page *
inm_nopage(struct vm_area_struct *vma, unsigned long address, int *type)
{
	struct inm_list_head *ptr, *hd;
	change_node_t *chg_node = vma->vm_private_data;
	data_page_t *page;
	unsigned long pgoff;
 
	pgoff = ((address - vma->vm_start) >> PAGE_CACHE_SHIFT) + 
							vma->vm_pgoff;
 
	hd =&(chg_node->data_pg_head);
	for(ptr = hd->next; pgoff != 0; ptr = ptr->next, pgoff--);

	page = inm_list_entry(ptr, data_page_t, next);
	page_cache_get(page->page);
	return page->page;
}

struct vm_operations_struct inm_vm_ops = {
	.nopage         = inm_nopage,
};
#endif

inm_s32_t flt_mmap(struct file *filp, struct vm_area_struct *vma)
{
	change_node_t *chg_node = filp->private_data;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)) ||        \
		(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10) && \
		!defined(CONFIG_HIGHMEM))
	struct inm_list_head *ptr, *hd;
	data_page_t *page;
	inm_s32_t vm_offset = 0;
#endif
	inm_s32_t status = 0;

	if(!chg_node)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10) && defined(CONFIG_HIGHMEM)
	vma->vm_ops = &inm_vm_ops;
	vma->vm_private_data = (void *)chg_node;
#else
	hd =&(chg_node->data_pg_head);
	for(ptr = hd->next; ptr != hd; ptr = ptr->next) {
		page = inm_list_entry(ptr, data_page_t, next);
		if(REMAP_PAGE(vma, (vma->vm_start + vm_offset),
				  PAGE_2_PFN_OR_PHYS(page->page), PAGE_SIZE, 
				  PAGE_SHARED)) {
			err("remap failed");
			status = -ENOMEM;
			break;                
		}

		vm_offset += PAGE_SIZE;
	}
#endif

	return status;
}

static void
restore_sd_open()
{
	if(driver_ctx->dc_at_lun.dc_at_drv_info.status){
		free_all_at_lun_entries();
	}
	driver_ctx->dc_at_lun.dc_at_drv_info.status = 0;
	while (INM_ATOMIC_READ(&(driver_ctx->dc_at_lun.dc_at_drv_info.nr_in_flight_ops))) {
		INM_DELAY(3 * INM_HZ);
	}
}

struct file_operations flt_ops = {
	.owner     = THIS_MODULE,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
	.ioctl      = flt_ioctl,
#else
	.unlocked_ioctl = flt_ioctl,
#endif
	.open      = flt_open,
	.release = flt_release,
	.flush      = flt_flush,
	.mmap     = flt_mmap,
};

inm_s32_t
is_root_filesystem_is_rootfs(void)
{
	inm_s32_t ret = 0;
	struct file *f = NULL;

	f = filp_open("/", O_RDONLY, 0400);
	if(!f){
		goto out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
	if(!f->f_dentry){
		goto out;
	}
#endif

	if(!INM_HDL_TO_INODE(f) || (INM_HDL_TO_INODE(f))->i_sb) {
		goto out;
	}

	if(!strcmp("rootfs", INM_HDL_TO_INODE(f)->i_sb->s_type->name)) {
		ret = 1;
	}

out:
	if(f){
		filp_close(f, current->files);
	}

	return ret;
}

#ifdef INITRD_MODE 
static char *in_initrd = "no";

module_param(in_initrd, charp, 0000);
MODULE_PARM_DESC(in_initrd, "A character string");
#endif

inm_s32_t __init involflt_init(void)
{
	inm_s32_t r;
	unsigned long lock_flag = 0;

	info("Version - %u.%u.%u.%u", INMAGE_PRODUCT_VERSION_MAJOR, 
		INMAGE_PRODUCT_VERSION_MINOR, INMAGE_PRODUCT_VERSION_PRIVATE,
		INMAGE_PRODUCT_VERSION_BUILDNUM);

#ifdef INITRD_MODE 
	if (!strcmp(in_initrd, "yes") || !strcmp(in_initrd, "YES"))
		driver_state = DRV_LOADED_PARTIALLY;
#endif

	telemetry_init_exception();

	if((driver_state & DRV_LOADED_FULLY) && 
			 		is_root_filesystem_is_rootfs()){
		info("The root filesystem is rootfs and so not loading the involflt driver");
		return INM_EINVAL;
	}

	atomic_set(&inm_flt_memprint,0);
	r = init_driver_context();
	if(r)
		return r;

	r  = register_filter_target();
	if (r < 0) {
		err("Failed to register involflt target with the system");
		goto free_dc_and_exit;
	}

	/* initializes the freeze volume list */
	INM_INIT_LIST_HEAD(&driver_ctx->freeze_vol_list);

	r = alloc_chrdev_region(&driver_ctx->flt_dev, 0, 1, "involflt");
	if( r < 0 ) {
		err("Failed to allocate character major number for involflt \
				driver");
		goto free_dc_and_exit;
	}

	INM_MEM_ZERO(&driver_ctx->flt_cdev, sizeof(inm_cdev_t));    
	cdev_init(&driver_ctx->flt_cdev, &flt_ops);
	driver_ctx->flt_cdev.owner = THIS_MODULE;
	driver_ctx->flt_cdev.ops = &flt_ops;

	r = cdev_add(&driver_ctx->flt_cdev, driver_ctx->flt_dev, 1);
	if( r < 0) {
		err("Failed in cdev_add for involflt");
		goto free_chrdev_region_exit;
	}

	r = initialize_bitmap_api();
	if (r < 0) {
	err("Failed in creation iob mempools");
	goto free_chrdev_region_exit;
	}
	/* creation of service thread here */
	r = create_service_thread();

	if (r) {
	err("could not able to create service thread \n");
	goto free_chrdev_region_exit;
	}

	if (create_alloc_thread()) {
		err("could not able to create allocation thread");
		goto free_service_thread;
	}

	if(block_sd_open()){
		INM_SPIN_LOCK_IRQSAVE(&driver_ctx->clean_shutdown_lock, 
				  				lock_flag); 
		driver_ctx->dc_flags |= DRV_MIRROR_NOT_SUPPORT;
		info("Mirror capability is not supported by involflt driver");
		INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->clean_shutdown_lock, 
				  				lock_flag);
	}

	if(driver_state & DRV_LOADED_FULLY) {
		sysfs_involflt_init();
		get_root_info();
	}

	driver_ctx->flags |= DC_FLAGS_INVOLFLT_LOAD;
	init_boottime_stacking();
	driver_ctx->flags &= ~DC_FLAGS_INVOLFLT_LOAD;
	
	if (driver_state & DRV_LOADED_FULLY) {
		if (driver_ctx->clean_shutdown)
		inm_flush_clean_shutdown(UNCLEAN_SHUTDOWN); 

		telemetry_init();
		info("Successfully loaded involflt target module");
	} else {
		info("Successfully loaded involflt target module from initrd");
	}

	return 0;
free_service_thread:
	destroy_service_thread();
free_chrdev_region_exit:
	unregister_chrdev_region(driver_ctx->flt_dev, 1);
free_dc_and_exit:
	free_driver_context();
	err("Failed to load involflt target module");
	return r;
}

static inm_s32_t 
block_sd_open()
{
	VOLUME_GUID *guid = NULL;
	inm_block_device_t *bdev = NULL;
	 struct gendisk *bd_disk = NULL;
	 const struct block_device_operations *fops = NULL;
	 struct scsi_device *sdp = NULL;
	 inm_u32_t i = 0;
	 inm_u32_t error = 0;

	dbg("entered");

	guid = (VOLUME_GUID *)INM_KMALLOC(sizeof(VOLUME_GUID), INM_KM_SLEEP, 
			 			INM_KERNEL_HEAP);
	if (!guid) {
		err("INM_KMALLOC failed to allocate memory for VOLUME_GUID");
		error = -ENOMEM;
		goto out;
	}

	for(i = 0; i < 26; i++) {
		snprintf(guid->volume_guid, GUID_SIZE_IN_CHARS-1, 
				  			"/dev/sd%c", 'a' + i);
		guid->volume_guid[GUID_SIZE_IN_CHARS-1] = '\0';
		bdev = open_by_dev_path(guid->volume_guid, 0);
		if (bdev && !IS_ERR(bdev)){
			break;
		}
	}
	if (!bdev || IS_ERR(bdev)) {
		error = 1;
		goto out;
	} 
	bd_disk = bdev->bd_disk;
	if (!bd_disk || 
		!inm_get_parent_dev(bd_disk)) {
		error = 1;
		goto out;
	}
	sdp = to_scsi_device(inm_get_parent_dev(bd_disk));
	fops = bd_disk->fops;

	memcpy_s(&driver_ctx->dc_at_lun.dc_at_drv_info.mod_dev_ops,
			sizeof(struct block_device_operations),
			fops, sizeof(struct block_device_operations));

	driver_ctx->dc_at_lun.dc_at_drv_info.orig_drv_open = fops->open;
	driver_ctx->dc_at_lun.dc_at_drv_info.orig_dev_ops = fops;
	INM_ATOMIC_SET(&(driver_ctx->dc_at_lun.dc_at_drv_info.nr_in_flight_ops), 0);
	replace_sd_open();
	driver_ctx->dc_at_lun.dc_at_drv_info.status = 1;

out:
if(IS_DBG_ENABLED(inm_verbosity, (INM_IDEBUG | INM_IDEBUG_MIRROR))){
	dbg("leaving with err %d",error);
}
	if (guid){
		INM_KFREE(guid, sizeof(VOLUME_GUID), INM_KERNEL_HEAP);
	}
	return error;
}

void __exit involflt_exit(void)
{
	inm_s32_t r;

	INM_DELAY(INM_WAIT_UNLOAD * INM_HZ);
	inm_register_reboot_notifier(FALSE);
	telemetry_shutdown();

	inm_verify_free_area();

	restore_disk_rel_ptrs();

	cdev_del(&driver_ctx->flt_cdev);    
	unregister_chrdev_region(driver_ctx->flt_dev, 1);
	destroy_alloc_thread();
	destroy_service_thread();
	terminate_bitmap_api();
	r = unregister_filter_target();
	INM_BUG_ON(r < 0);
	restore_sd_open();
	free_driver_context();
	info("Successfully unloaded involflt target module");
}

void
inm_bufoff_to_fldisk(inm_buf_t *bp, target_context_t *tcp, inm_u64_t *abs_off)
{
	*abs_off = 0;
}

inm_mirror_bufinfo_t *
inm_get_imb_cached(host_dev_ctx_t *hdcp)
{
	return NULL;
}

inm_s32_t
inm_prepare_atbuf(inm_mirror_atbuf *atbuf_wrap, inm_buf_t *bp, 
				mirror_vol_entry_t *vol_entry, inm_u32_t count)
{
	inm_u32_t more = 0;
	
	memcpy_s((&(atbuf_wrap->imb_atbuf_buf)), sizeof(inm_buf_t), bp, sizeof(inm_buf_t));
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,13)
	atbuf_wrap->imb_atbuf_buf.bi_destructor = NULL;
#endif

#if ((LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0) &&         \
        LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)) ||    \
        defined SLES12SP4 || defined SLES12SP5 ||           \
        (defined SLES15 && PATCH_LEVEL <= 3))
    atbuf_wrap->imb_atbuf_buf.bi_disk = vol_entry->mirror_dev->bd_disk;
#else
    atbuf_wrap->imb_atbuf_buf.bi_bdev = vol_entry->mirror_dev;
#endif
	atbuf_wrap->imb_atbuf_buf.bi_end_io = inm_at_mirror_iodone;
	atbuf_wrap->imb_atbuf_buf.bi_next = NULL;
	atbuf_wrap->imb_atbuf_vol_entry = vol_entry;
	atbuf_wrap->imb_atbuf_iosz = 
				INM_BUF_COUNT(&(atbuf_wrap->imb_atbuf_buf));
	INM_REF_VOL_ENTRY(vol_entry);
	INM_SET_TEST_MIRROR((&atbuf_wrap->imb_atbuf_buf));

	return more;
}

void
inm_issue_atio(inm_buf_t *at_bp, mirror_vol_entry_t *vol_entry)
{
	struct request_queue *q = NULL;
	q = bdev_get_queue(vol_entry->mirror_dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) && !defined(SLES15SP3)
	q->make_request_fn(q, at_bp);
#endif
}

void
inm_cleanup_mirror_bufinfo(host_dev_ctx_t *hdcp)
{
	return;
}

module_init(involflt_init);
module_exit(involflt_exit);

MODULE_AUTHOR("Microsoft Corporation");
MODULE_DESCRIPTION("Microsoft Filter Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(BLD_DATE " [ " BLD_TIME " ]");
