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

#include "verifier.h"

#ifdef __INM_KERNEL_DRIVERS__ 

extern driver_context_t *driver_ctx;

/* Can be called to toggle the verifier on or on change of dm file size */
inm_s32_t
inm_verify_alloc_area(inm_u32_t size, int toggle)
{
	void *old = NULL;
	inm_s32_t error = 0;
	inm_irqflag_t flag = 0;

	/* Verifier is not on and verifier is not being toggled on */
	if (!driver_ctx->dc_verifier_on && !toggle)                    
		return error;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_verifier_lock, flag);
	
	old = driver_ctx->dc_verifier_area;
	
	driver_ctx->dc_verifier_area = vmalloc(size);
	if (!driver_ctx->dc_verifier_area) {
		err("Cannot vmalloc %u", size);
		driver_ctx->dc_verifier_area = old;
		error = -ENOMEM;
	} else {
		if (old)
			   vfree(old);
	}
			   
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_verifier_lock, flag);

	return error;
}

void
inm_verify_free_area(void)
{
	inm_irqflag_t flag = 0;

	INM_SPIN_LOCK_IRQSAVE(&driver_ctx->dc_verifier_lock, flag);
	if (driver_ctx->dc_verifier_area)
		vfree(driver_ctx->dc_verifier_area);

	driver_ctx->dc_verifier_area = NULL;
	INM_SPIN_UNLOCK_IRQRESTORE(&driver_ctx->dc_verifier_lock, flag);
}

#endif /* __INM_KERNEL_DRIVERS__ */

inm_s32_t
inm_verify_change_node_data(char *buf, int bufsz, int verbose)
{
	inm_s32_t error = -EBADF;
	char *cur = NULL;
	inm_u64_t offset = 0;
	inm_u32_t *tag = 0;
	SVD_PREFIX *prefix = 0;
	SVD_TIME_STAMP_V2 *time_stamp;
	long long chglen = 0;
	SVD_DIRTY_BLOCK_V2 *dblk;
	int dbcount = 1;
	
	cur = buf;

	/* Endian Tag */
	verify_err(verbose, "Endian Tag: %c%c%c%c", cur[0], cur[1], cur[2], cur[3]);
	
	tag = (inm_u32_t *)cur;
	/*if ( *tag != inm_is_little_endian() ? SVD_TAG_LEFORMAT : SVD_TAG_BEFORMAT)*/
	if ( *tag != SVD_TAG_LEFORMAT)
		goto err;

	cur += sizeof(SVD_TAG_LEFORMAT);
	offset += sizeof(SVD_TAG_LEFORMAT);

	/* SVD Header Tag */
	prefix = (SVD_PREFIX *)cur;

	verify_err(verbose, "HDR -> Tag: %c%c%c%c Count: %d Flags: %d",
			   cur[0], cur[1], cur[2], cur[3], prefix->count, prefix->Flags);

	if (prefix->tag != SVD_TAG_HEADER1)
		goto err;

	cur += sizeof(SVD_PREFIX);
	offset += sizeof(SVD_PREFIX);

	/* SVD Header - skip for now */
	cur += sizeof(SVD_HEADER1);
	offset += sizeof(SVD_HEADER1);

	/* TOFC */
	prefix = (SVD_PREFIX *)cur;

	verify_err(verbose, "TOFC -> Tag: %c%c%c%c Count: %d Flags: %d",
			   cur[0], cur[1], cur[2], cur[3], prefix->count, prefix->Flags);

	if (prefix->tag != SVD_TAG_TIME_STAMP_OF_FIRST_CHANGE_V2)
		goto err;

	cur += sizeof(SVD_PREFIX);
	offset += sizeof(SVD_PREFIX);
	
	/* TOFC Time Stamp */
	time_stamp = (SVD_TIME_STAMP_V2 *)cur;
	
	verify_err(verbose, "TOFC Time: %llu Seq No: %llu", 
			       time_stamp->TimeInHundNanoSecondsFromJan1601, 
			       time_stamp->ullSequenceNumber);
	
	cur += sizeof(SVD_TIME_STAMP_V2);
	offset += sizeof(SVD_TIME_STAMP_V2);

	/* LODC */
	prefix = (SVD_PREFIX *)cur;

	verify_err(verbose, "LODC -> Tag: %c%c%c%c Count: %d Flags: %d",
			   cur[0], cur[1], cur[2], cur[3], prefix->count, prefix->Flags);

	if (prefix->tag != SVD_TAG_LENGTH_OF_DRTD_CHANGES)
		goto err;

	cur += sizeof(SVD_PREFIX);
	offset += sizeof(SVD_PREFIX);

	/* Change Len */
	chglen = *((long long *)cur);
	verify_err(verbose, "Change Len: %lld", chglen);
	cur += sizeof(chglen);
	offset += sizeof(chglen);

	/* Changes */
	while (chglen) {
		/* Dirty Block Prefix */
		prefix = (SVD_PREFIX *)cur;

		verify_err(verbose, "DB[%d] -> Tag: %c%c%c%c Count: %d Flags: %d",
			   dbcount, cur[0], cur[1], cur[2], cur[3], 
			   prefix->count, prefix->Flags);

		if (prefix->tag != SVD_TAG_DIRTY_BLOCK_DATA_V2)
			goto err;

		cur += sizeof(SVD_PREFIX);
		offset += sizeof(SVD_PREFIX);

		/* Dirty Block */
		dblk = (SVD_DIRTY_BLOCK_V2 *)cur;

		verify_err(verbose, "DB[%d] -> Len: %u Off: %llu TDelta: %u SDelta: %u", 
			   dbcount, dblk->Length, dblk->ByteOffset, 
			   dblk->uiTimeDelta, dblk->uiSequenceNumberDelta);

		cur += sizeof(SVD_DIRTY_BLOCK_V2);
		offset += sizeof(SVD_DIRTY_BLOCK_V2);

		/* Data */
		if (dblk->Length < bufsz - offset) {
			   cur += dblk->Length;
			   offset += dblk->Length;
		}

		/* Next dirty Block */
		chglen -= (sizeof(SVD_PREFIX) + 
			          sizeof(SVD_DIRTY_BLOCK_V2) + 
			          dblk->Length);
		dbcount++;

		if (offset > bufsz) {
			   verify_err(verbose, "Exceeded buffer");
			goto err;
		}
	}

	/* TLV2 */
	prefix = (SVD_PREFIX *)cur;

	verify_err(verbose, "TLV2 -> Tag: %c%c%c%c Count: %d Flags: %d",
			   cur[0], cur[1], cur[2], cur[3], prefix->count, prefix->Flags);

	if (prefix->tag != SVD_TAG_TIME_STAMP_OF_LAST_CHANGE_V2)
		goto err;

	cur += sizeof(SVD_PREFIX);
	offset += sizeof(SVD_PREFIX);

	/* TLV2 Time Stamp */
	time_stamp = (SVD_TIME_STAMP_V2 *)cur;
	
	verify_err(verbose, "TLV2 Time: %llu Seq No: %llu", 
			       time_stamp->TimeInHundNanoSecondsFromJan1601,
			       time_stamp->ullSequenceNumber);
	
	cur += sizeof(SVD_TIME_STAMP_V2);
	offset += sizeof(SVD_TIME_STAMP_V2);

	/* Success */
	verify_err(verbose, "File is good");
	error = 0;

out:
	return error;

err:
	if (!verbose)
		inm_verify_change_node_data(buf, bufsz, 1);
	else
		verify_err(verbose, "Bad data at offset %llu(%x)", offset, 
			          (inm_u32_t)offset);

	goto out;
}

