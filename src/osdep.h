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

#ifndef _INM_OSDEP_H
#define _INM_OSDEP_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/wait.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/interrupt.h>
#include <asm/page.h>
#include <asm/atomic.h>
#include <asm/mman.h>
#include <asm/string.h>
#include <asm/unistd.h>
#include <linux/writeback.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <asm/div64.h>
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/mman.h>

#include "distro.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#include <linux/time.h>
#else
#include <linux/timekeeping.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#include <linux/kthread.h>
#endif

#include "involflt.h"
#include "inm_mem.h"
#include "inm_locks.h"
#include "inm_utypes.h"
#include "inm_list.h"
#include "flt_bio.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#include "linux/blk-mq.h"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
#define __GFP_WAIT __GFP_RECLAIM
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)

typedef struct _lookup {
	struct path path;
} inm_lookup_t;
#define INM_HDL_TO_INODE(file)  (file_inode(file))

#else

typedef struct nameidata inm_lookup_t;
#define INM_HDL_TO_INODE(hdlp)      (((struct file *)hdlp)->f_dentry->d_inode)

#endif

typedef struct super_block      inm_super_block_t;
typedef struct block_device     inm_block_device_t;
typedef struct timer_list       inm_timer_t;
typedef unsigned long           inm_irqflag_t;

struct _change_node;
struct _target_context;
struct _bitmap_api_tag;
struct _iobuffer_tag;
struct _tag_info;

struct _vol_info
{
	struct inm_list_head next;
	inm_block_device_t  *bdev;
	inm_super_block_t *sb;
};
typedef struct _vol_info vol_info_t;

struct _tag_volinfo
{
	struct _target_context *ctxt;
	struct inm_list_head head; /* contains list of tag_vol_info_t */
};

typedef struct _tag_volinfo tag_volinfo_t;
struct _mirror_vol_entry;

/* filtering specific section */
typedef struct _dm_bio_info
{
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	struct inm_list_head entry;
#endif
	sector_t bi_sector;
	inm_u32_t bi_flags;
	inm_u32_t bi_size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	inm_u32_t bi_idx;
	inm_u32_t bi_bvec_done;
#else
	unsigned short bi_idx;
#endif
	bio_end_io_t *bi_end_io;
	void *tc;
	void *bi_private;
	struct _change_node *bi_chg_node;
	struct bio *new_bio;
	struct bio *orig_bio;
	struct bio *orig_bio_copy;
	inm_block_device_t  *start_mirror_dev;
	inm_u32_t src_done;	
	inm_s32_t src_error;
	inm_u32_t dst_done;	
	inm_s32_t dst_error;
	inm_spinlock_t bio_info_lock;
	inm_u32_t dm_bio_flags;
	struct _mirror_vol_entry *dmbioinfo_vol_entry;
} dm_bio_info_t;

#define BINFO_FLAG_CHAIN        0x1
#define BINFO_ALLOCED_FROM_POOL 0x2

#define BIO_INFO_MPOOL_SIZE (PAGE_SIZE/sizeof(dm_bio_info_t))
#define BIO_BI_SIZE(bio)    (((struct bio *)bio)->bi_size)
#define BIO_BI_VCNT(bio)    (((struct bio *)bio)->bi_vcnt)

typedef struct _req_q_info
{
	struct inm_list_head next;
	inm_atomic_t ref_cnt;
	inm_atomic_t vol_users;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0) && !defined(SLES15SP3)
	make_request_fn *orig_make_req_fn;
#endif
	struct kobj_type mod_kobj_type;
	struct kobj_type *orig_kobj_type;
	struct request_queue *q;
	int rqi_flags;
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	struct blk_mq_ops *orig_mq_ops;
	struct blk_mq_ops mod_mq_ops;
	void *tc;
#endif
} req_queue_info_t;

#define INM_STABLE_PAGES_FLAG_SET 0x1

typedef struct _req_q_info inm_stginfo_t;

typedef struct file inm_devhandle_t;

/* Structure definition to store volume info to freeze/thaw */
typedef struct freeze_vol_info
{
	struct inm_list_head freeze_list_entry;
	char                 vol_name[TAG_VOLUME_MAX_LENGTH];
	inm_block_device_t   *bdev;
	inm_super_block_t    *sb;
} freeze_vol_info_t;

#define INM_MODULE_PUT()      module_put(THIS_MODULE)
#define INM_TRY_MODULE_GET()  try_module_get(THIS_MODULE)

extern atomic_t inm_flt_memprint;
void *inm_kmalloc(size_t size, int flags);
void inm_kfree(size_t size,const void * objp);
void *inm_kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags);
void inm_kmem_cache_free(struct kmem_cache *cachep, void *objp);
void *inm_mempool_alloc(mempool_t *pool, gfp_t gfp_mask);
void inm_mempool_free(void *element, mempool_t *pool);
void inm_vfree(const void *addr, unsigned long size);
void *inm_vmalloc(unsigned long size);
struct page *inm_alloc_page(gfp_t gfp_mask);
void inm_free_page(unsigned long addr);
unsigned long __inm_get_free_page(gfp_t gfp_mask);
void __inm_free_page(struct page *page);


void freeze_volumes(int, tag_volinfo_t *);
void unfreeze_volumes(int, tag_volinfo_t *);
void lock_volumes(int, tag_volinfo_t *);
void unlock_volumes(int, tag_volinfo_t *);
inm_s32_t is_rootfs_ro(void);

inm_s32_t map_change_node_to_user(struct _change_node *, struct file *);
inm_block_device_t *open_by_dev_path(char *, int);
inm_block_device_t *open_by_dev_path_v2(char *, int);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30) 
#define close_bdev(bdev, mode)  blkdev_put(bdev, mode);
#else 
#define close_bdev(bdev, mode)  blkdev_put(bdev);
#endif
inm_s32_t flt_release(struct inode *inode, struct file *filp);
inm_s32_t iobuffer_sync_read_physical(struct _iobuffer_tag *iob, inm_s32_t force);
inm_s32_t iobuffer_sync_flush_physical(struct _iobuffer_tag *iob);
inm_u64_t get_bmfile_granularity(struct _target_context *vcptr);
void inm_scst_unregister(struct _target_context *);
int inm_path_lookup_parent(const char *, inm_lookup_t *);
int inm_path_lookup(const char *, unsigned int, inm_lookup_t *);
void inm_path_release(inm_lookup_t *);
inm_s32_t inm_get_scsi_id(char *path);

/* ioctl specific section */
#define __INM_USER                          __user
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)) ||                       \
	 (defined RHEL8 && RHEL_MINOR >= 1)) 
#define INM_ACCESS_OK(access, arg, size)                                    \
		access_ok(arg, size)
#else
#define INM_ACCESS_OK(access, arg, size)                                    \
		access_ok(access, arg, size)
#endif
#define INM_COPYIN(dst, src, len)               copy_from_user(dst, src, len)
#define INM_COPYOUT(dst, src, len)              copy_to_user(dst, src, len)

#define IOCTL_INMAGE_VOLUME_STACKING     	_IOW(FLT_IOCTL, VOLUME_STACKING_CMD, PROCESS_VOLUME_STACKING_INPUT) 
#define IOCTL_INMAGE_PROCESS_START_NOTIFY     	_IOW(FLT_IOCTL, START_NOTIFY_CMD, PROCESS_START_NOTIFY_INPUT) 
#define IOCTL_INMAGE_SERVICE_SHUTDOWN_NOTIFY     _IOW(FLT_IOCTL, SHUTDOWN_NOTIFY_CMD, SHUTDOWN_NOTIFY_INPUT)
#define IOCTL_INMAGE_STOP_FILTERING_DEVICE      _IOW(FLT_IOCTL, STOP_FILTER_CMD, VOLUME_GUID)
#define IOCTL_INMAGE_START_FILTERING_DEVICE       _IOW(FLT_IOCTL, START_FILTER_CMD, VOLUME_GUID)
#define IOCTL_INMAGE_START_FILTERING_DEVICE_V2       _IOW(FLT_IOCTL, START_FILTER_CMD_V2, inm_dev_info_compat_t)
#define IOCTL_INMAGE_COMMIT_DIRTY_BLOCKS_TRANS  _IOW(FLT_IOCTL, COMMIT_DB_CMD, COMMIT_TRANSACTION)
#define IOCTL_INMAGE_SET_VOLUME_FLAGS        	_IOW(FLT_IOCTL, SET_VOL_FLAGS_CMD, VOLUME_FLAGS_INPUT)
#define IOCTL_INMAGE_GET_VOLUME_FLAGS        	_IOR(FLT_IOCTL, GET_VOL_FLAGS_CMD, VOLUME_FLAGS_INPUT)
#define IOCTL_INMAGE_WAIT_FOR_DB        	_IOW(FLT_IOCTL, WAIT_FOR_DB_CMD, WAIT_FOR_DB_NOTIFY)
#define IOCTL_INMAGE_CLEAR_DIFFERENTIALS    	_IOW(FLT_IOCTL, CLEAR_DIFFS_CMD, VOLUME_GUID)
#define IOCTL_INMAGE_GET_NANOSECOND_TIME    	_IOWR(FLT_IOCTL, GET_TIME_CMD, long long)
#define IOCTL_INMAGE_UNSTACK_ALL 		_IO(FLT_IOCTL, UNSTACK_ALL_CMD)
#define IOCTL_INMAGE_SYS_SHUTDOWN       	_IOW(FLT_IOCTL, SYS_SHUTDOWN_NOTIFY_CMD, SYS_SHUTDOWN_NOTIFY_INPUT)
#define IOCTL_INMAGE_TAG_VOLUME			_IOWR(FLT_IOCTL, TAG_CMD, unsigned long)
#define IOCTL_INMAGE_SYNC_TAG_VOLUME            _IOWR(FLT_IOCTL, SYNC_TAG_CMD, unsigned long)
#define IOCTL_INMAGE_GET_TAG_VOLUME_STATUS      _IOWR(FLT_IOCTL, SYNC_TAG_STATUS_CMD, unsigned long)
#define IOCTL_INMAGE_WAKEUP_ALL_THREADS     	_IO(FLT_IOCTL, WAKEUP_THREADS_CMD)
#define IOCTL_INMAGE_GET_DB_NOTIFY_THRESHOLD	_IOWR(FLT_IOCTL, GET_DB_THRESHOLD_CMD, get_db_thres_t )
#define IOCTL_INMAGE_RESYNC_START_NOTIFICATION	_IOWR(FLT_IOCTL, RESYNC_START_CMD, RESYNC_START )
#define IOCTL_INMAGE_RESYNC_END_NOTIFICATION	_IOWR(FLT_IOCTL, RESYNC_END_CMD, RESYNC_END)
#define IOCTL_INMAGE_GET_DRIVER_VERSION  	_IOWR(FLT_IOCTL, GET_DRIVER_VER_CMD, DRIVER_VERSION)
#define IOCTL_INMAGE_SHELL_LOG    		_IOWR(FLT_IOCTL, GET_SHELL_LOG_CMD, char *)
#define IOCTL_INMAGE_AT_LUN_CREATE          _IOW(FLT_IOCTL,  AT_LUN_CREATE_CMD, LUN_CREATE_INPUT)
#define IOCTL_INMAGE_AT_LUN_DELETE          _IOW(FLT_IOCTL,  AT_LUN_DELETE_CMD, LUN_DELETE_INPUT)
#define IOCTL_INMAGE_AT_LUN_LAST_WRITE_VI   _IOWR(FLT_IOCTL, AT_LUN_LAST_WRITE_VI_CMD, \
			                                      AT_LUN_LAST_WRITE_VI)
#define IOCTL_INMAGE_AT_LUN_LAST_HOST_IO_TIMESTAMP   _IOWR(FLT_IOCTL, AT_LUN_LAST_HOST_IO_TIMESTAMP_CMD, \
			                                      AT_LUN_LAST_HOST_IO_TIMESTAMP)
#define IOCTL_INMAGE_AT_LUN_QUERY           _IOWR(FLT_IOCTL, AT_LUN_QUERY_CMD, LUN_QUERY_DATA)
#define IOCTL_INMAGE_VOLUME_UNSTACKING         _IOW(FLT_IOCTL, VOLUME_UNSTACKING_CMD, VOLUME_GUID)
#define IOCTL_INMAGE_BOOTTIME_STACKING          _IO(FLT_IOCTL, BOOTTIME_STACKING_CMD)

/* target context specific sections */
struct _target_context *get_tgt_ctxt_from_bio(struct bio *);
struct _target_context *get_tgt_ctxt_from_kobj(struct kobject *);

/* proc specific sections */
typedef struct proc_dir_entry inm_proc_dir_entry;

/* change node specific sections */
/* This structure holds information about a single data page. Linked list
 * of data pages is used in data mode filtering. Also, data pages are allocated
 * for disk changes and tags.
 */
typedef struct _data_page
{
	/* To link this data page to the caller specified doubly linked list */
	struct inm_list_head next;

	/* Virtual address of the data page is stored here. */
	struct page *page;
} data_page_t;

inm_s32_t alloc_data_pages(struct inm_list_head *,  inm_u32_t, inm_u32_t *, int);
void free_data_pages(struct inm_list_head *);
void delete_data_pages(inm_u32_t);

#define PG_ENTRY(ptr) (inm_list_entry(ptr, data_page_t, next))
typedef struct task_struct inm_task_struct;

/* data mode specific sections */
#define INM_SET_PAGE_RESERVED(page)         SetPageReserved(page)
#define INM_CLEAR_PAGE_RESERVED(page)       ClearPageReserved(page)
		
#define INM_COPY_BIO_DATA_TO_DATA_PAGES(iov, listhd)                    \
		copy_bio_data_to_data_pages((struct bio *)iov, listhd)
#define INM_COPY_IOVEC_DATA_TO_DATA_PAGES(len, iov, iov_count, listhd)  \
		copy_iovec_data_to_data_pages(len,(struct iovec *)iov,  \
			                          iov_count, listhd)
#define INM_GET_WMD(info, wmd)		            \
		wmd.offset = (info->bi_sector << 9); \
		wmd.length = (info->bi_size - INM_BUF_COUNT(bio))

typedef dm_bio_info_t		inm_io_info_t;

#ifdef INM_RECUSIVE_ADSPC
struct inma_ops  {
	struct inm_list_head ia_list;
	const inm_address_space_operations_t *ia_mapping; 
};
#else
/* file-io specific sections */
struct inma_ops  {
	struct inm_list_head ia_list;
	const inm_address_space_operations_t *ia_org_aopsp; 
	inm_address_space_operations_t *ia_dup_aopsp; 
};
#endif

typedef struct inma_ops inma_ops_t;

/* Debug APIs
 */

#define dbg(format, arg...) \
	if(IS_DBG_ENABLED(inm_verbosity, INM_DEBUG_ONLY)){				\
		printk(KERN_DEBUG "%s[%s:%d (DBG)]: " format "\n" , DRIVER_NAME , 	\
			__FUNCTION__, __LINE__, ## arg);				\
	}

#define err(format, arg...) 								\
	printk(KERN_ERR "%s[%s:%d (ERR)]: " format "\n" , DRIVER_NAME, __FUNCTION__ ,	\
		__LINE__, ## arg)

#define vol_err(tcxt, format, arg...)                                       		\
	printk(KERN_ERR "%s[%s:%d (ERR)]: (%s:%s)" format "\n" , DRIVER_NAME,   	\
		   __FUNCTION__ , __LINE__, ((target_context_t *)tcxt)->tc_pname,       \
			((target_context_t *)tcxt)->tc_guid, ## arg);

#define info(format, arg...) \
	if(IS_DBG_ENABLED(inm_verbosity, (INM_DEBUG_ONLY | INM_IDEBUG | INM_IDEBUG_META | INM_IDEBUG_BMAP))){ 	\
	printk(KERN_ERR "%s[%s:%d (INFO)]: " format "\n" , DRIVER_NAME, __FUNCTION__,				\
		__LINE__, ## arg);										\
	}else { 												\
	printk(KERN_INFO "%s[%s:%d (INFO)]: " format "\n" , DRIVER_NAME, __FUNCTION__,				\
		__LINE__, ## arg);										\
	}

#define warn(format, arg...) \
	printk(KERN_WARN "%s[%s:%d (WARN)]: " format "\n" , DRIVER_NAME, __FUNCTION__, \
		__LINE__, ## arg)

#define print_dbginfo(fmt, arg...)      \
		printk(KERN_ERR fmt, ##arg)

#ifdef INM_DEBUG
#define INM_BUG_ON(EXPR) BUG_ON(EXPR)
#else
#define INM_BUG_ON(EXPR)                	\
({                                      	\
	if (EXPR){                           	\
		err("Involflt driver bug");    	\
	 }					\
})
#endif

#define INM_LIKELY(v)            likely(v)
#define INM_UNLIKELY(v)          unlikely(v)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,10)
typedef struct timespec inm_timespec;
#else
typedef struct timespec64 inm_timespec;
#endif

/* utils sections */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define INM_GET_CURRENT_TIME(now)        \
		now = CURRENT_TIME
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#define INM_GET_CURRENT_TIME(now)        \
	now = current_kernel_time()
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 10)
#define INM_GET_CURRENT_TIME(now)        getnstimeofday(&now)
#else
#define INM_GET_CURRENT_TIME(now) ktime_get_real_ts64(&now)
#endif
#endif

#define INM_MSEC_PER_SEC	     MSEC_PER_SEC

#define INM_MSECS_TO_JIFFIES(msecs)  msecs_to_jiffies(msecs)		

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define INM_GET_CURR_TIME_IN_SEC ((CURRENT_TIME).tv_sec)
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#define INM_GET_CURR_TIME_IN_SEC (current_kernel_time().tv_sec)
#else
inm_s64_t inm_current_kernel_time_secs(void);
#define INM_GET_CURR_TIME_IN_SEC inm_current_kernel_time_secs()
#endif
#endif

#define INM_HZ                   (HZ)

/* to handle freeze volume list*/
inm_s32_t freeze_root_dev(void);
inm_s32_t process_freeze_volume_ioctl(inm_devhandle_t *idhp,
			                          void __INM_USER *arg);
inm_s32_t process_thaw_volume_ioctl(inm_devhandle_t *idhp,
			                        void __INM_USER *arg);
inm_s32_t convert_path_to_dev(const char *, inm_dev_t *);
inm_s32_t get_dir(char *dir, inm_s32_t (*inm_entry_callback)(char *fname));

/* for single node crash consistency  */
inm_s32_t process_iobarrier_tag_volume_ioctl(inm_devhandle_t *idhp,
			                                 void __INM_USER *arg);
inm_s32_t process_commit_revert_tag_ioctl(inm_devhandle_t *idhp, 
			                              void __INM_USER *arg);
inm_s32_t process_remove_iobarrier_ioctl(inm_devhandle_t *idhp, 
			                             void __INM_USER *arg);
inm_s32_t process_create_iobarrier_ioctl(inm_devhandle_t *idhp, 
			                             void __INM_USER *arg);
inm_s32_t test_timer(inm_devhandle_t *idhp, void __INM_USER *arg);
/* Synchronisation wrappers */
typedef wait_queue_head_t		inm_wait_queue_head_t;
#define INM_INIT_WAITQUEUE_HEAD(event)                                  \
		init_waitqueue_head(event)
#define INM_WAKEUP(event)                                               \
		wake_up(event)
#define INM_WAKEUP_INTERRUPTIBLE(event)                                 \
		wake_up_interruptible(event)
#define INM_WAIT_EVENT_INTERRUPTIBLE_TIMEOUT(event, val, timeout)       \
		wait_event_interruptible_timeout(event, val, timeout)

typedef struct completion		inm_completion_t;
#define INM_COMPLETE(event)                                             \
		complete(event)
#define INM_INIT_COMPLETION(event)                                      \
		init_completion(event)
#define INM_DESTROY_COMPLETION(compl)
#define INM_COMPLETE_AND_EXIT(event, val)                               \
		complete_and_exit(event, val)
#define INM_WAIT_FOR_COMPLETION(event)                                  \
		wait_for_completion(event)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9) || 			\
	(defined(redhat) && (DISTRO_VER==4) && (UPDATE>=3))
#define INM_WAIT_FOR_COMPLETION_INTERRUPTIBLE(event)                    \
		wait_for_completion_interruptible(event)
#else
#define INM_WAIT_FOR_COMPLETION_INTERRUPTIBLE(event)                    \
	INM_WAIT_FOR_COMPLETION(event)
#endif

#define INM_INIT_WORKER_CHILD(compl, condition)                         \
	do {                                                            \
		*condition = 1;                                         \
		INM_COMPLETE(compl);                                    \
	} while(0)

#define INM_COMPLETE_CONDITION_LOCK(compl)

#define INM_COMPLETE_CONDITION_UNLOCK(compl)

#define __inm_wait_event_interruptible_timeout(inm_wq, inm_condition, inm_ret)      	\
	do {                                                                		\
		DEFINE_WAIT(__inm_wait);                                            	\
			                                                            	\
		for (;;) {                                                      	\
			prepare_to_wait(&inm_wq, &__inm_wait, TASK_INTERRUPTIBLE);      \
			if (inm_condition)                                              \
			    break;                                                  	\
			if (!signal_pending(current)) {                             	\
			    schedule_timeout(inm_ret);                              	\
			    inm_ret = 0;                                            	\
			    break;                                                  	\
			}                                                           	\
			inm_ret = -ERESTARTSYS;                                         \
			break;                                                      	\
		}                                                               	\
		finish_wait(&inm_wq, &__inm_wait);                                      \
	} while (0)

#define inm_wait_event_interruptible_timeout(inm_wq, inm_condition, inm_timeout) 	\
({											\
	long __inm_ret = inm_timeout;							\
	if (!(inm_condition))								\
		__inm_wait_event_interruptible_timeout(inm_wq, inm_condition, __inm_ret); \
	__inm_ret;								\
})

#define __inm_wait_event_interruptible(inm_wq, inm_condition, inm_ret)      		\
	do {                                                                		\
		DEFINE_WAIT(__inm_wait);                                            	\
			                                                            	\
		for (;;) {                                                      	\
			prepare_to_wait(&inm_wq, &__inm_wait, TASK_INTERRUPTIBLE);      \
			if (inm_condition)                                              \
			    break;                                                  	\
			if (!signal_pending(current)) {                             	\
			    schedule();                                             	\
			    break;                                                  	\
			}                                                           	\
			inm_ret = -ERESTARTSYS;                                         \
			break;                                                      	\
		}                                                               	\
		finish_wait(&inm_wq, &__inm_wait);                                      \
	} while (0)

#define inm_wait_event_interruptible(inm_wq, inm_condition) 				\
({											\
	long __inm_ret = 0;								\
	if (!(inm_condition))								\
		__inm_wait_event_interruptible(inm_wq, inm_condition, __inm_ret); 	\
	__inm_ret;									\
})

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
#define INM_KERNEL_THREAD(task, funcp, arg, len, name, ...)	kernel_thread(funcp, arg, CLONE_KERNEL)
#define	INM_KTHREAD_STOP(task)
#else
extern struct task_struct *service_thread_task;
#define INM_KERNEL_THREAD(task, funcp, arg, len, name, ...)	\
({ 								\
	pid_t __pid = -1;					\
	task = kthread_run(funcp, arg, name, ## __VA_ARGS__);	\
	if (!IS_ERR(task))					\
		__pid = task->pid;				\
			                        		\
	__pid;							\
})
#define	INM_KTHREAD_STOP(task)	kthread_stop(task)
#endif

#define INM_ETIMEDOUT               (-ETIMEDOUT)
#define INM_ENOMEM                  (-ENOMEM)
#define INM_ENOENT                  (-ENOENT)
#define INM_EINVAL                  (-EINVAL)
#define INM_EEXIST                  (-EEXIST)
#define INM_EFAULT                  (-EFAULT)
#define INM_EAGAIN                  (-EAGAIN)
#define INM_EBUSY		    (-EBUSY)
#define INM_EBADRQC                 (-EBADRQC)
#define INM_EINTR		    (-EINTR)
#define INM_EROFS                   (0)
#define INM_ENOTSUP		    (-EOPNOTSUPP)	

#define INM_RDONLY                  (O_RDONLY)
#define INM_RDWR                    (O_RDWR)
#define INM_EXCL                    (O_EXCL)
#define INM_SYNC                    (O_SYNC)
#define INM_CREAT                   (O_CREAT)
#define INM_SYNC                    (O_SYNC)
#define INM_TRUNC                   (O_TRUNC)
#define INM_LARGEFILE               (O_LARGEFILE)
#define INM_DIRECT                  (O_DIRECT)

#define INM_DO_DIV(val1, val2)      do_div(val1, val2)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
#define INM_DAEMONIZE(name, arg...) daemonize(name,##arg)
#else
#define INM_DAEMONIZE(name, arg...)
#endif
#define INM_SET_USER_NICE(val)      set_user_nice(INM_CURPROC, -val)
#define INM_IN_INTERRUPT()          (in_interrupt() || irqs_disabled()) 

#define INM_MMAP_LOCK() 	INM_DOWN_WRITE(&current->mm->mmap_sem)
#define INM_MMAP_UNLOCK()	INM_UP_WRITE(&current->mm->mmap_sem)
#define INM_MMAP_PROT_FLAGS	(PROT_READ)
#define INM_MMAP_MAPFLAG	(MAP_SHARED)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
#define INM_DO_STREAM_MAP(dh, off, sz, addr, prot, mapflag)             \
({ \
		inm_s32_t __ret = 0; \
		INM_MMAP_LOCK();	\
		addr = do_mmap_pgoff((struct file *)dh, off, sz, (prot), (mapflag), 0); \
		INM_MMAP_UNLOCK();	\
		__ret; \
})

#define INM_DO_STREAM_UNMAP(addr, len)		\
({						\
	inm_s32_t __ret = 0;			\
	INM_MMAP_LOCK();			\
	__ret = do_munmap(current->mm, addr, len); \
	INM_MMAP_UNLOCK();			\
						\
	__ret;					\
})
#else
#define INM_DO_STREAM_MAP(dh, off, sz, addr, prot, mapflag)			\
({ 										\
	inm_s32_t __ret = 0;							\
	addr = vm_mmap((struct file *)dh, addr, sz, (prot), (mapflag), off); 	\
	__ret; 									\
})

#define INM_DO_STREAM_UNMAP(addr, len)  vm_munmap(addr, len)
#endif

#define INM_FILL_MMAP_PRIVATE_DATA(idhp, cnp)                           \
		do {                                                    \
			idhp->private_data = cnp;                       \
		} while(0);

#define INM_PAGESZ          (PAGE_SIZE)
#define INM_PAGESHIFT       (PAGE_SHIFT)
#define INM_PAGEMASK        (~(PAGE_SIZE-1))
#define INM_PAGEALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#define INM_KMAP_ATOMIC(page, idx)	kmap_atomic(page)
#define INM_KUNMAP_ATOMIC(vaddr, idx)	kunmap_atomic(vaddr)
#else
#define INM_KMAP_ATOMIC(page, idx)	kmap_atomic(page, idx)
#define INM_KUNMAP_ATOMIC(vaddr, idx)	kunmap_atomic(vaddr, idx)
#endif

#define INM_PAGE_MAP(vaddr, page, irqidx)	(vaddr) = INM_KMAP_ATOMIC((page), (irqidx))
#define INM_PAGE_UNMAP(vaddr, page, irqidx)	INM_KUNMAP_ATOMIC(vaddr, (irqidx))

#ifndef INM_PATH_MAX
#define INM_PATH_MAX            (PATH_MAX)
#endif
#define INM_NAME_MAX            (NAME_MAX)

typedef struct _page_wrapper {
	struct inm_list_head entry;
	unsigned long *cur_pg;
	inm_u32_t nr_chgs;
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	inm_u32_t flags;
#endif
} inm_page_t;

#define METAPAGE_ALLOCED_FROM_POOL 0x01

/*
 *  process related macros/constants
 */
#define INM_CURPROC             current
#define INM_PROC_ADDR           (INM_CURPROC)->mm
#define INM_CURPROC_PID         (current->pid)
#define INM_CURPROC_COMM        (current->comm)
#define INM_DELAY(ticks)	set_current_state(TASK_INTERRUPTIBLE);      \
				schedule_timeout((ticks))

#define INM_PRAGMA_PUSH1        pack( push, 1 )
#define INM_PRAGMA POP          pack( pop )

#define INM_REL_DEV_RESOURCES(ctx) inm_rel_dev_resources(ctx, ctx->tc_priv) 
#define INM_GET_MINOR(dev)	MINOR((dev))
#define INM_GET_MAJOR(dev)	MAJOR((dev))
struct host_dev_context;
void inm_rel_dev_resources(struct _target_context *ctx, struct host_dev_context *hdcp);
inm_s32_t inm_get_mirror_dev(struct _mirror_vol_entry *);
void inm_free_mirror_dev(struct _mirror_vol_entry *);
inm_dev_t inm_get_dev_t_from_path(const char *);
struct _target_context;
inm_dev_t inm_dev_id_get(struct _target_context *);
inm_u64_t inm_dev_size_get(struct _target_context *);

#define INM_S_IRWXUGO	S_IRWXUGO
#define INM_S_IRUGO		S_IRUGO

#define INM_S_READ			NULL
#define INM_S_WRITE			NULL

#define	INM_MEM_ZERO(addr, size)   memset(addr, 0, size)
#define	INM_MEM_CMP(addr_src, addr_tgt, size)  memcmp(addr_src, addr_tgt, size)

#define INM_SI_MEMINFO(infop)     si_meminfo(infop)

#define INM_CLOSE_FILE(hdlp, oflag) flt_close_file(hdlp)

#define INM_WRITE_SCSI_TIMEOUT	(60 * INM_HZ)
#define INM_CNTL_SCSI_TIMEOUT	(10 * INM_HZ)

#define IS_DMA_FLAG(tcp, flag)  inm_dma_flag(tcp, &flag)

inm_s32_t validate_file(char *pathp, inm_s32_t *type);
void inm_dma_flag(struct _target_context *tcp, inm_u32_t *flag);
void print_AT_stat(struct _target_context *, char *page, inm_s32_t *len);
inm_s32_t try_reactive_offline_AT_path(struct _target_context *, unsigned char *, inm_u32_t, inm_s32_t, unsigned char *, inm_u32_t, inm_u32_t);

#define inm_claim_metadata_page(tgt_ctxt, chg_node, wdatap)

int _inm_xm_mapin(struct _target_context *, void *, char **);
#define inm_xm_mapin(tgt_ctxt, wdatap, map_addr) \
		_inm_xm_mapin(tgt_ctxt, (void *)wdatap, map_addr)

#define inm_xm_det(wdatap, map_addr)

#define INM_SET_ENDIO_FN(bi, endio_fn)  bi->bi_end_io = endio_fn
#define INM_CHAIN_BUF(cur_bi, prev_bi)
#define INM_GET_FWD_BUF(bp)  NULL

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
/*
 * For kernels > 4.4, the error comes set as part of bio
 */
#define INM_IMB_ERROR_SET(var, error_value) 
#define INM_MIRROR_IODONE(fn, bp, done, error) fn(inm_buf_t *bp)
#define INM_PT_IODONE(mbufinfo)                                                 	\
{                                                                               	\
	mbufinfo->imb_org_bp->bi_flags = mbufinfo->imb_pt_buf.bi_flags;         	\
	INM_BUF_COUNT(mbufinfo->imb_org_bp) = INM_BUF_COUNT(&(mbufinfo->imb_pt_buf));   \
	inm_bio_error(mbufinfo->imb_org_bp) = inm_bio_error(&(mbufinfo->imb_pt_buf));   \
	mbufinfo->imb_org_bp->bi_end_io(mbufinfo->imb_org_bp);                          \
}

#define INM_BUF_FAILED(bp, error) 		inm_bio_error(bp)

#else /* Else: Kernel < 4.4 */
#define INM_IMB_ERROR_SET(var, error_value) var = error_value
#define INM_MIRROR_IODONE(fn, bp, done, error) fn(inm_buf_t *bp, inm_s32_t error)
#define INM_PT_IODONE(mbufinfo)                                                 		\
{                                                                               		\
		mbufinfo->imb_org_bp->bi_flags = mbufinfo->imb_pt_buf.bi_flags;         	\
		INM_BUF_COUNT(mbufinfo->imb_org_bp) = INM_BUF_COUNT(&(mbufinfo->imb_pt_buf));   \
		mbufinfo->imb_org_bp->bi_end_io(mbufinfo->imb_org_bp, mbufinfo->imb_pt_err);	\
}
#define INM_BUF_FAILED(bp, error) 		error
#endif /* End: Kernel >= 4.4 */ 
/* Kernels > 2.6.24 */
#define INM_IMB_DONE_SET(var, done_value)
#define INM_RET_IODONE 
#define INM_MORE_IODONE_EXPECTED(bp)
#define INM_BUF_RESID(bi, done) INM_BUF_COUNT(bi)
#else /* End: Kernel > 2.6.24 */
#define INM_MIRROR_IODONE(fn, bp, done, error) fn(inm_buf_t *bp, inm_u32_t done, inm_s32_t error)
#define	INM_IMB_ERROR_SET(var, error_value) var = error_value
#define INM_IMB_DONE_SET(var, done_value)   var = done_value
#define INM_RET_IODONE 0
#define INM_PT_IODONE(mbufinfo)                                                 				\
{                                                                               				\
		mbufinfo->imb_org_bp->bi_flags = mbufinfo->imb_pt_buf.bi_flags;         			\
		mbufinfo->imb_org_bp->bi_size =  mbufinfo->imb_pt_buf.bi_size;          			\
	mbufinfo->imb_org_bp->bi_end_io(mbufinfo->imb_org_bp, mbufinfo->imb_pt_done, mbufinfo->imb_pt_err);	\
}
#define INM_MORE_IODONE_EXPECTED(bp)		\
{						\
	if(bp->bi_size){			\
		return 1;			\
	}					\
}
#define INM_BUF_RESID(bi, done) (bi->bi_size - done)
#define INM_BUF_FAILED(bp, error) 		error

#define IS_ALIGNED(x, y)    (!(x & (y - 1)))

#endif

struct block_device *inm_open_by_devnum(dev_t, unsigned);

#define INM_SET_HDEV_MXS(hdcp, val)
#define INM_GET_HDEV_MXS(hdc_dev)  0
void free_tc_global_at_lun(struct inm_list_head *dst_list);

typedef struct _inm_at_lun_reconfig{
	inm_u64_t flag;
	char      atdev_name[INM_GUID_LEN_MAX];
}inm_at_lun_reconfig_t;

typedef struct _dc_at_vol_entry
{
	struct inm_list_head dc_at_this_entry;
	char                 dc_at_name[INM_GUID_LEN_MAX];
	inm_block_device_t  *dc_at_dev;
} dc_at_vol_entry_t;

inm_s32_t process_block_at_lun(inm_devhandle_t *handle, void * arg);
void free_all_at_lun_entries(void);
dc_at_vol_entry_t * find_dc_at_lun_entry(char *);
void replace_sd_open(void);

#define DRV_LOADED_PARTIALLY    0x1
#define DRV_LOADED_FULLY    	0x2

#define TAG_COMMIT_NOT_PENDING  0
#define TAG_COMMIT_PENDING      1

inm_s32_t process_init_driver_fully(inm_devhandle_t *, void *);

#define inm_ksleep(x)   msleep_interruptible(x)

typedef struct gendisk inm_disk_t;

struct device *inm_get_parent_dev(struct gendisk *bd_disk);
inm_s32_t inm_get_user_page(void __INM_USER *, struct page **);

#ifdef INM_RECUSIVE_ADSPC 
#define INM_AOPS(mapping)           (mapping)
#else
#define INM_AOPS(mapping)           ((mapping)->a_ops)
#endif
#define INM_INODE_AOPS(inode)       INM_AOPS((inode)->i_mapping)

#if (defined(RHEL_MAJOR) && (RHEL_MAJOR == 5))
#ifndef kobj_to_disk
#define kobj_to_disk(k) container_of(k, struct gendisk, kobj)
#endif
#endif

inm_s32_t inm_register_reboot_notifier(int);
void inm_blkdev_name(inm_bio_dev_t *bdev, char *name);
inm_s32_t inm_blkdev_get(inm_bio_dev_t *bdev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
/*
 * Multiple kernels changed q->backing_dev_info from structure to pointer 
 * in same minor version (errata) so cant have kernel version based check.
 *
 * NOTE: The macros below are gcc compile time directives to choose the right 
 * expression to access the structure based on the type of q->backing_dev_info 
 * and will not work with other compilers.
 */
#define INM_BDI_IS_PTR(q)                                                  \
	__builtin_types_compatible_p(typeof(q->backing_dev_info),          \
			                     struct backing_dev_info *)

#define INM_BDI_PTR(q)                                                     \
	__builtin_choose_expr(INM_BDI_IS_PTR(q),                           \
		((q)->backing_dev_info), (&((q)->backing_dev_info)))

#define INM_BDI_CAPABILITIES(q)        ((INM_BDI_PTR(q))->capabilities)

#endif /* KERNEL_VERSION(3,9,0) */

#define INM_BDEVNAME_SIZE BDEVNAME_SIZE

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
#define INM_PAGE_TO_VIRT(page)		page_to_virt(page)
#define INM_VIRT_ADDR_VALID(vaddr)	virt_addr_valid(vaddr)
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
#ifndef pfn_to_virt
#define pfn_to_virt(pfn)		__va((pfn) << PAGE_SHIFT)
#endif

#ifndef page_to_virt
#define page_to_virt(page)		pfn_to_virt(page_to_pfn(page))
#endif

#define INM_PAGE_TO_VIRT(page)		page_to_virt(page)
#define INM_VIRT_ADDR_VALID(vaddr)	virt_addr_valid(vaddr)
#else
#define INM_VIRT_ADDR_VALID(vaddr)		(1)
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#define set_fs(a)
#define get_fs()	\
({			\
   mm_segment_t __ret;	\
   __ret;		\
})
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
#define inm_freeze_bdev(__bdev, __sb)   freeze_bdev(__bdev)
#define inm_thaw_bdev(__bdev, __sb)     thaw_bdev(__bdev)
#else
#define inm_freeze_bdev(__bdev, __sb)       \
({                                          \
	int __ret = 0;                      \
	__sb = freeze_bdev(__bdev);         \
	if (__sb && IS_ERR(__sb))           \
		__ret = PTR_ERR(__sb);      \
			                    \
	__ret;                              \
})
#define inm_thaw_bdev(__bdev, __sb)     thaw_bdev(__bdev, __sb)
#endif

#endif /* _INM_OSDEP_H */
