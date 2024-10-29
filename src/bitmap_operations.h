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
 * File       : bitmap_operations.h
 *
 * Description: This file contains bitmap mode implementation of the
 *              filter driver.
 */

#ifndef _INMAGE_BITMAP_OPERATIONS_H
#define _INMAGE_BITMAP_OPERATIONS_H

#include "involflt-common.h"

inm_u32_t find_number_of_bits_set(unsigned char *bit_buffer,
				 inm_u32_t buffer_size_in_bits);

inm_s32_t SetBitmapBitRun(unsigned char * bitBuffer,
                    inm_u32_t bitsInBitmap,
                    inm_u32_t bitsInRun,
                    inm_u32_t bitOffset,
                    inm_u32_t * nbrBytesChanged,
                    unsigned char * *firstByteChanged);
inm_s32_t ClearBitmapBitRun(unsigned char * bitBuffer,
		      inm_u32_t bitsInBitmap,
		      inm_u32_t bitsInRun,
		      inm_u32_t bitOffset,
		      inm_u32_t * nbrBytesChanged,
		      unsigned char * *firstByteChanged);

inm_s32_t InvertBitmapBitRun(unsigned char * bitBuffer,
		       inm_u32_t bitsInBitmap,
		       inm_u32_t bitsInRun,
		       inm_u32_t bitOffset,
		       inm_u32_t * nbrBytesChanged,
		       unsigned char * *firstByteChanged);

inm_s32_t GetNextBitmapBitRun(
	unsigned char * bitBuffer,
	inm_u32_t totalBitsInBitmap,
	inm_u32_t * startingBitOffset,
	inm_u32_t * bitsInRun,
	inm_u32_t * bitOffset);
#endif /* _INMAGE_BITMAP_OPERATIONS_H */
