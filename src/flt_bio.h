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

#ifndef _FLT_BIO_H
#define _FLT_BIO_H

#include "distro.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
void flt_end_io_fn(struct bio *bio);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
void flt_end_io_fn(struct bio *bio, inm_s32_t error);
#else
inm_s32_t flt_end_io_fn(struct bio *bio, inm_u32_t done, inm_s32_t error);
#endif

typedef struct block_device inm_bio_dev_t;


#if ((LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0) &&         \
        LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)) ||    \
        defined SLES12SP4 || defined SLES12SP5 ||           \
        (defined SLES15 && PATCH_LEVEL <= 3))
#define INM_BUF_DISK(bio)   ((bio)->bi_disk)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
#define INM_BUF_BDEV(bio)    ((bio)->bi_disk->part0)
#else
#define INM_BUF_BDEV(bio)    (bdget_disk((bio)->bi_disk, 0))
#endif
#else
#define INM_BUF_DISK(bio)   ((bio)->bi_bdev->bd_disk)
#define INM_BUF_BDEV(bio)    ((bio)->bi_bdev)
#endif

#define INM_BDEVNAME_PREFIX "/dev/"

#if defined BIO_CHAIN || \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5,1,0) /* Mainline */
#define INM_IS_CHAINED_BIO(bio)       bio_flagged(bio, BIO_CHAIN)
#elif defined BIO_AUX_CHAIN /* RHEL 7                       */
#define INM_IS_CHAINED_BIO(bio)       bio_aux_flagged(bio, BIO_AUX_CHAIN)
#else                       /* unsupported = always FALSE   */
#define INM_IS_CHAINED_BIO(bio)       (0)
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)) || defined SLES12SP3
#define inm_bio_rw(bio)         ((bio)->bi_opf)
#define inm_bio_is_write(bio)   (op_is_write(bio_op(bio)))
#define inm_bio_is_discard(bio) (bio_op(bio) == REQ_OP_DISCARD)
#else
#define inm_bio_rw(bio)         ((bio)->bi_rw)
#define inm_bio_is_write(bio)   (bio_rw(bio) == WRITE)
#ifdef RHEL5
#define inm_bio_is_discard(bio) (0)
#else
#ifdef RHEL6
/* The newer kernels of RHEL6 has pulled the support for DISCARD and BIO_DISCARD
 * is defined in newer kernels but the driver is built against the base and so
 * added the same definition to compile and handle the DISCARD as well.
 */
#define BIO_RQ_DISCARD		(1 << 9)
#else
#define BIO_RQ_DISCARD		REQ_DISCARD
#endif
#define inm_bio_is_discard(bio) ((bio)->bi_rw & BIO_RQ_DISCARD)
#endif
#endif  

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0) || \
	defined SLES12SP4 || defined SLES12SP5 || defined SLES15
#define inm_bio_error(bio) ((bio)->bi_status)
#else
#define inm_bio_error(bio) ((bio)->bi_error)
#endif

#define INM_BUF_IOVEC(bio)      ((bio)->bi_io_vec)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)

typedef struct bvec_iter inm_bvec_iter_t;
/*
 * NOTE: INM_BVEC_ITER* macros follow kernel convention 
 * and take iterators as arguments and not iterator pointers 
 */
#define INM_BVEC_ITER_IDX(iter)     ((iter).bi_idx)
#define INM_BVEC_ITER_SECTOR(iter)  ((iter).bi_sector)
#define INM_BVEC_ITER_SZ(iter)      ((iter).bi_size)
#define INM_BVEC_ITER_BVDONE(iter)  ((iter).bi_bvec_done)

#if !defined RHEL8 && ((LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) &&     \
	 LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)) || defined SLES12SP4)
#define INM_BVEC_ITER_INIT()                                                \
	((struct bvec_iter) {                                               \
	    .bi_sector = 0,                                                 \
	    .bi_size = 0,                                                   \
	    .bi_idx = 0,                                                    \
	    .bi_bvec_done = 0,                                              \
	    .bi_done = 0,                                                   \
	})
#else
#define INM_BVEC_ITER_INIT()                                                \
	((struct bvec_iter) {                                               \
	    .bi_sector = 0,                                                 \
	    .bi_size = 0,                                                   \
	    .bi_idx = 0,                                                    \
	    .bi_bvec_done = 0,                                              \
	})
#endif

#define INM_BUF_ITER(bio)           ((bio)->bi_iter)
#define INM_BUF_SECTOR(bio)         INM_BVEC_ITER_SECTOR(INM_BUF_ITER(bio)) 
#define INM_BUF_COUNT(bio)          INM_BVEC_ITER_SZ(INM_BUF_ITER(bio))
#define INM_BUF_IDX(bio)            INM_BVEC_ITER_IDX(INM_BUF_ITER(bio))

#define INM_BUF_OFFSET(bio)                                                 \
	bvec_iter_offset(INM_BUF_IOVEC(bio), INM_BUF_ITER(bio))

#define bio_iovec_idx(bio, iter)    __bvec_iter_bvec((bio)->bi_io_vec, iter)

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0) */

typedef unsigned short inm_bvec_iter_t;
#define INM_BVEC_ITER_INIT()        0 

#define INM_BUF_ITER(bi)            ((bi)->bi_idx)
#define INM_BUF_SECTOR(bi)          ((bi)->bi_sector)
#define INM_BUF_COUNT(bi)           ((bi)->bi_size)
#define INM_BUF_IDX(bi)             INM_BUF_ITER(bi)

#define INM_BUF_OFFSET(bi)          bio_offset(bi)

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0) */

/*
 * Discard zeroes data
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)) &&                        \
	!defined RHEL5
/*
 * For a long time, device used to advertise capability to zero data with 
 * discard request and appications used to use the capability to zero out 
 * blocks using discard command. For correct handling, we check for this
 * capability when REQ_DISCARD flag is set and zero data on completion.
 */
#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)) && defined UEK
#define INM_DISCARD_ZEROES_DATA(q)  (0)
#else
#define INM_DISCARD_ZEROES_DATA(q)  (q->limits.discard_zeroes_data)
#endif
#else
/* New kernels remove the ambiguity of discard capability. Apps now call 
 * discard to unmap blocks while REQ_OP_WRITE_ZEROES should be explicitly 
 * used when zeroes are expected. The hardware driver may use DISCARD/WRITE_SAME
 * or any other mechanism to zero the block range but we are not bothered 
 * at our layer. So always return false as its is only true with 
 * REQ_OP_WRITE_ZEROES
 */
#define INM_DISCARD_ZEROES_DATA(q)  (0)
#endif

/*
 * Offload requests
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)) || defined SLES12SP3

#define INM_REQ_WRITE           REQ_OP_WRITE
#if (defined(RHEL9) && !defined(RHEL9_0) && !defined(OL9UEK7)) || defined(SLES15SP5) || LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
/* Defining it as 100000000 to not match with any req_op */
#define INM_REQ_WRITE_SAME      100000000
#else
#define INM_REQ_WRITE_SAME      REQ_OP_WRITE_SAME
#endif
#define INM_REQ_DISCARD         REQ_OP_DISCARD
#if (defined REQ_OP_WRITE_ZEROES || defined OL7UEK5)
#define INM_REQ_WRITE_ZEROES    REQ_OP_WRITE_ZEROES
#else
#define INM_REQ_WRITE_ZEROES    0
#endif

#define inm_bio_op(bio)         bio_op(bio)
/* INM_REQ* flags can be defined as 0 == REQ_READ. So check the op is write */
#define INM_IS_BIO_WOP(bio, op) \
	(inm_bio_is_write(bio) && (inm_bio_op(bio) == op))

inline static int
INM_IS_OFFLOAD_REQUEST_OP(struct bio *bio)
{
	switch (bio_op(bio)) {
	case INM_REQ_DISCARD:
	case INM_REQ_WRITE_SAME:
#if (defined REQ_OP_WRITE_ZEROES || defined OL7UEK5)
	case INM_REQ_WRITE_ZEROES:
#endif
		return 1;

	default:
		return 0;
	}
}

inline static int
INM_IS_SUPPORTED_REQUEST_OP(struct bio *bio)
{
	switch (bio_op(bio)) {
	case INM_REQ_WRITE:
	case INM_REQ_DISCARD:
	case INM_REQ_WRITE_SAME:
#ifdef REQ_OP_WRITE_ZEROES
	case INM_REQ_WRITE_ZEROES:
#endif 
		return 1;

	default:
		return 0;
	}
}

#else  /* LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0) */

#define INM_REQ_WRITE           REQ_WRITE

#ifdef RHEL5

#define INM_REQ_DISCARD         0
#define INM_REQ_WRITE_SAME      0
#define INM_REQ_WRITE_ZEROES    0

#else  /* !RHEL5 */

#define INM_REQ_DISCARD         BIO_RQ_DISCARD
#define INM_REQ_WRITE_ZEROES    0

#ifdef REQ_WRITE_SAME
#define INM_REQ_WRITE_SAME REQ_WRITE_SAME
#else
#define INM_REQ_WRITE_SAME 0
#endif

#endif /* !RHEL5 */

#define __INM_SUPPORTED_OFFLOAD_REQUESTS  \
	(INM_REQ_WRITE_SAME | INM_REQ_DISCARD) 

/* RHEL 7.4+ & new kernels provide bio_op() to extract ops from other flags  */
#ifdef bio_op

#define inm_bio_op(bio)         bio_op(bio)
#define __INM_SUPPORTED_REQUESTS                                              \
	((unsigned long) (INM_REQ_WRITE | __INM_SUPPORTED_OFFLOAD_REQUESTS))

#else /* bio_op */
/* 
 * For legacy kernels, we support all ops since there is no easy way to extract 
 * ops from other flags and we do not want to switch to md mode unnecessarily
 */
#define inm_bio_op(bio)         (bio->bi_rw)
#define __INM_SUPPORTED_REQUESTS  UINT_MAX

#endif /* bio_op */

/* INM_REQ* flags can be defined as 0 == REQ_READ. So check the op is write */
#define INM_IS_BIO_WOP(bio, op) \
	(inm_bio_is_write(bio) && (inm_bio_op(bio) & op))

#define INM_IS_OFFLOAD_REQUEST_OP(bio)                                      \
	(inm_bio_op(bio) & __INM_SUPPORTED_OFFLOAD_REQUESTS)

#define INM_IS_SUPPORTED_REQUEST_OP(bio)                                    \
	((inm_bio_op(bio) & __INM_SUPPORTED_REQUESTS) == inm_bio_op(bio))

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0)    */

/* 
 * For unsupported kernels, break build so we are forced to verify 
 * we are logging the right data.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0))
#define INM_BIO_RW_FLAGS(bio)   (*bio = 0)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)) || defined SLES12SP3
#define INM_BIO_RW_FLAGS(bio)   (inm_bio_rw(bio) | bio->bi_flags) 
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0))
#define INM_BIO_RW_FLAGS(bio)   (inm_bio_rw(bio) << 32 | bio->bi_flags)
#else
#define INM_BIO_RW_FLAGS(bio)   (inm_bio_rw(bio) << 32 | bio->bi_flags << 32)
#endif

#endif
