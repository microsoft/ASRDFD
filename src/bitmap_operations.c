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
 * File       : bitmap_operations.c
 *
 * Description: This file contains bitmap mode implementation of the
 *              filter driver.
 */

#include "involflt.h"
#include "involflt-common.h"
#include "data-mode.h"
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
#include "driver-context.h"
#include "involflt_debug.h"

#include "bitmap_operations.h"

/*
 * all this code assumes bit ordering within a byte is like this:
 *              7 6 5 4 3 2 1 0  bit number within byte
 *             |x x x x x x x x| where unsigned char=0x01 would have bit 0=1 and unsigned char=0x80 would have bit 7=1
 *
 * This means bit 17(decimal) in a char[3] array would be here:
 *          23 22 21 20 19 18 17 16 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
 *         | 0  0  0  0  0  0  1  0| 0  0  0  0  0  0  0  0| 0  0  0  0  0  0  0  0|
 *         |          ch[2]        |          ch[1]        |          ch[0]        | 
 *
 * All processors do it this way, even if the WORD endian is big-endian, char arrays are not affected
 */ 


/*
 * [numberOfSetBits][bitOffsetInByte]
 * this table is for setting a nbr of bits in a byte at a specific bit offset
 */
const unsigned char bitSetTable[9][8] 
/* bit offset    0     1     2     3     4     5     6     7 */
= 	      {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* 0 bits */
   	       {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}, /* 1 bits */
   	       {0x03, 0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x00}, /* 2 bits, note that 0x00 means invalid */
   	       {0x07, 0x0E, 0x1C, 0x38, 0x70, 0xE0, 0x00, 0x00}, /* 3 bits */
   	       {0x0F, 0x1E, 0x3C, 0x78, 0xF0, 0x00, 0x00, 0x00}, /* 4 bits */
   	       {0x1F, 0x3E, 0x7C, 0xF8, 0x00, 0x00, 0x00, 0x00}, /* 5 bits */
   	       {0x3F, 0x7E, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00}, /* 6 bits */
   	       {0x7F, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* 7 bits */
   	       {0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}; /* 8 bits */


/* this table is used for searching for bit runs, it tells the bit offset of the first set bit */
const unsigned char bitSearchOffsetTable[256] = 
/*  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, */
{ 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x1x */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x2x */ 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x3x */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x4x */ 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x5x */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x6x */ 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,                              
  /* 0x7x */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x8x */ 0x07, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0x9x */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0xAx */ 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0xBx */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0xCx */ 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0xDx */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,
  /* 0xEx */ 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00,                              
  /* 0xFx */ 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00};


/* this table is used for searching for bit runs, it tells the number of bits that are contiguous from the lsb, use with shifting */

const unsigned char bitSearchCountTable[256] =  
/*  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, */
{ 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0x00 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, /* 0x10 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0x20 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x06, /* 0x30 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0x40 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, /* 0x50 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0x60 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, /* 0x70 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0x80 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, /* 0x90 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0xa0 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x06, /* 0xb0 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0xc0 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, /* 0xd0 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x04, /* 0xe0 */
  0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x08};/* 0xf0 */


/*
 * this table is used to mask the last byte in a buffer so we don't test bits we're not supposed to
 * index will be number of bits remaining as valid
 */
const unsigned char lastByteMaskTable[9] = {0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF}; 

/*
 * these are codes that are split into 4 bytes to control the bit manipulation
 * they merge an entry from bitSetTable into a byte in the desired operation
 */
#define OpValueSetBits (0xFF000000)
#define OpValueClearBits (0xFFFF00FF)
#define OpValueInvertBits (0x00FF00FF)
#define MAX_BITRUN_LEN  (0x400) //1024


/* Number of set bits for each value of a nibble; used for counting */
const unsigned char nibble_bit_count[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};



inm_s32_t ProcessBitRun(unsigned char * bitBuffer,
		  inm_u32_t bitsInBitmap,
		  inm_u32_t bitsInRun,
		  inm_u32_t bitOffset,
		  inm_u32_t * nbrBytesChanged,
		  unsigned char * *firstByteChanged,
		  inm_u32_t opValue)
{

	inm_s32_t status;
	inm_u32_t bytesTouched;
	inm_u32_t bitBufferSize;
	inm_u32_t bitsInFirstByte;
	inm_u32_t bitOffsetInFirstByte;
	unsigned char * firstByteTouched;
	unsigned char ch; /* a byte to process */
	unsigned char xor1Mask; /* first xor applied to ch */
	/* xor applied to bitSetTable entry and then xored with ch */
	unsigned char xor2Mask;
	/* final xor applied to ch */
	unsigned char xor3Mask;
       	/* and applied to bitSetTable entry and then ored with ch */
	unsigned char andMask;

	status = 0;

	/* we need to keep track of which bytes we change */
	/* so we can write the correct sectors to disk */
	bytesTouched = 0;
	firstByteTouched = bitBuffer;

	/* round up to nbr of bytes need to contain bitmap */
	bitBufferSize = (bitsInBitmap + 7) / 8;

	if (bitsInRun == 0) {
		/* don't do anything */
	} else if ((bitOffset >= bitsInBitmap) ||
		       (bitsInRun > bitsInBitmap) ||
			/* check that we don't overflow this bitmap segment */
		       ((bitOffset + bitsInRun) > bitsInBitmap)) {
		status = EOF_BMAP;
	} else {
		/* set the operation values, these are somewhat like */
		/* rasterop values used in a bitblt */
		xor1Mask = (unsigned char)(opValue & 0xFF);
		xor2Mask = (unsigned char)((opValue >> 8) & 0xFF);
		xor3Mask = (unsigned char)((opValue >> 16) & 0xFF);
		andMask = (unsigned char)((opValue >>24) & 0xFF);

		/* move the bitmap byte pointer up to the correct byte for the */
		/* first opeation */
		bitBuffer += (bitOffset / 8);

		/* handle the first possibly partial byte */
		bytesTouched = 1;
		firstByteTouched = bitBuffer;
		/* one of 8 offsets, same as % 8 */
		bitOffsetInFirstByte = ((inm_u32_t)bitOffset & 0x7);
		bitsInFirstByte = min((min(bitsInRun, (inm_u32_t)8)),
						(8 - bitOffsetInFirstByte));

		/* this code allows doing set or clear or invert of bits */
		ch = *bitBuffer;
		ch ^= xor1Mask;
		ch ^= ( bitSetTable[bitsInFirstByte][bitOffsetInFirstByte]) ^ xor2Mask;
		ch |= ( bitSetTable[bitsInFirstByte][bitOffsetInFirstByte]) & andMask;
		ch ^= xor3Mask;
		*bitBuffer = ch; /* the byte is now transformed */
		bitsInRun -= bitsInFirstByte;
		bitBuffer++;

		/* handle the middle bytes, we have already checked bitmap */
		/* bounds, so don't need to do here */
		while (bitsInRun >= 8) {
		    /* this code allows doing set or clear or invert of bits */
		    ch = *bitBuffer;
		    ch ^= xor1Mask;
		    ch ^= 0xFF ^ xor2Mask;
		    ch |= 0xFF & andMask;
		    ch ^= xor3Mask;
		    *bitBuffer = ch; /* the byte is now transformed */
		    bitsInRun -= 8;
		    bitBuffer++;
		    bytesTouched++;
		}

		/* process possible last byte (possibly less than 8 bits) */
		if (bitsInRun > 0) {
		    /* this code allows doing set or clear or invert of bits */
		    ch = *bitBuffer;
		    ch ^= xor1Mask;
		    ch ^= (bitSetTable[bitsInRun][0]) ^ xor2Mask;
		    ch |= (bitSetTable[bitsInRun][0]) & andMask;
		    ch ^= xor3Mask;
		    *bitBuffer = ch; /* the byte is now transformed */
		    bytesTouched++;
		    bitsInRun = 0;
		}
	}

	if (NULL != nbrBytesChanged) { /* this parameter is optional */
		*nbrBytesChanged = bytesTouched; 
	}

	if (NULL != firstByteChanged) {  /* this parameter is optional */
		*firstByteChanged = firstByteTouched;
	}

	return status;
}

inm_s32_t SetBitmapBitRun(unsigned char * bitBuffer,
		            inm_u32_t bitsInBitmap,
		            inm_u32_t bitsInRun,
		            inm_u32_t bitOffset,
		            inm_u32_t * nbrBytesChanged,
		            unsigned char * *firstByteChanged)
{
	return ProcessBitRun(bitBuffer, bitsInBitmap, bitsInRun, bitOffset,
			nbrBytesChanged, firstByteChanged, OpValueSetBits);
}

inm_s32_t ClearBitmapBitRun(unsigned char * bitBuffer,
		      inm_u32_t bitsInBitmap,
		      inm_u32_t bitsInRun,
		      inm_u32_t bitOffset,
		      inm_u32_t * nbrBytesChanged,
		      unsigned char * *firstByteChanged)
{
	return ProcessBitRun(bitBuffer, bitsInBitmap, bitsInRun, bitOffset,
			nbrBytesChanged, firstByteChanged, OpValueClearBits);
}

inm_s32_t InvertBitmapBitRun(unsigned char * bitBuffer,
		       inm_u32_t bitsInBitmap,
		       inm_u32_t bitsInRun,
		       inm_u32_t bitOffset,
		       inm_u32_t * nbrBytesChanged,
		       unsigned char * *firstByteChanged)
{
	return ProcessBitRun(bitBuffer, bitsInBitmap, bitsInRun, bitOffset,
			nbrBytesChanged, firstByteChanged, OpValueInvertBits);
}

/* This function is the compute intensive code for turning bitmaps back into groups of bits
 * It has a bunch of edge conditions:
 *      1) there could be no run of bits from the starting offset to the end of the bitmap
 *      2) the starting search offset can be on any bit offset of a byte
 *      3) the end of the bitmap can be at any bit offset in a byte, not just ends of bytes
 *      4) the run of bits can extend to any offset of the last byte in the buffer
 *      5) the starting byte could also be the ending byte in the bitmap (the run after #4)
 *      6) a run of bits can extend to the end of the bitmap (bounds terminate the run, not clear bit)
 *      7) the starting search offset may not be be the start of the bit run
 *      8) the run may start and end on adjacent bytes
 *      9) the starting offset is past the end of the bitmap
 *     10) the size of the bitmap could be less than 8 bits
 */
inm_s32_t GetNextBitmapBitRun(
	unsigned char * bitBuffer,
	/* in BITS not bytes */
	inm_u32_t totalBitsInBitmap,
	/* in and out parameter, set search start and is updated, relative to
	 * start of bitBuffer
	 */
	inm_u32_t * startingBitOffset,
	/* 0 means no run found, can be up to totalBitsInBitmap */
	inm_u32_t * bitsInRun,
	/* output bit offset relative to bitBuffer, meaningless value if
	 * *bitsInRun == 0
	 */
	inm_u32_t * bitOffset)
{
	inm_s32_t status;
	inm_u32_t bitsAvailableToSearch;
	inm_u32_t runOffset; 
	inm_u32_t runLength;
	inm_u32_t bitsDiscardedOnFirstByteSearched;
	inm_u32_t bitsDiscardedOnFirstByteOfRun;
	inm_u32_t bitsInLastByte;
	unsigned char ch;
	inm_u32_t BitRunBreak = FALSE;


	runOffset = *startingBitOffset; /* the minimum offset it could be */
	runLength = 0;

	if ((totalBitsInBitmap % 8) == 0)
	{
		bitsInLastByte = 8;
	} else
	{
		bitsInLastByte = (totalBitsInBitmap % 8);
	}

	status = 0;
	/* already validated this will not underflow */
	bitsAvailableToSearch = totalBitsInBitmap - *startingBitOffset;

	/* throw away full bytes from buffer that are before starting offset */
	bitBuffer += (*startingBitOffset / 8);

	/* get the first byte of buffer, this contains the starting offset bit */
	ch = *bitBuffer++;

	/* get the bits before the starting offset in the first byte
	 * shifted away
       	 * this offset is already included in the starting position of
	 * runOffset
	 */
	bitsDiscardedOnFirstByteSearched = (inm_u32_t)(*startingBitOffset & 0x7);
	/* throw away bits before starting point */
	ch = ch >> bitsDiscardedOnFirstByteSearched;

	/* check for the first byte also being the last byte */
	if (bitsAvailableToSearch < bitsInLastByte) {
		/* only partial byte to search, mask off trailing unused bits */
		ch &= lastByteMaskTable[bitsInLastByte];
	}

	do {
		/* is this the last byte of buffer */
		if (bitsAvailableToSearch <= bitsInLastByte) {
			if (ch == 0) {
				/* no runs found */
				break;
			} else {
				/* found a run in last byte */
				/* get the offset of the first bit */
				bitsDiscardedOnFirstByteOfRun = bitSearchOffsetTable[ch];
				/* align the first set bit to lsb (little-endian) */
				ch >>= bitsDiscardedOnFirstByteOfRun;
				runOffset += bitsDiscardedOnFirstByteOfRun; 
				/* get the number of bits in the run */
				runLength = bitSearchCountTable[ch];
				break;
			}
		} 
		
		/* this is not the last byte and we need to find the first
		 * byte of run
		 */
		if (ch == 0) {
			/* get aligned 
			 * get aligned to byte boundry
			 */
			bitsAvailableToSearch -= (8 - bitsDiscardedOnFirstByteSearched);
			runOffset += (8 - bitsDiscardedOnFirstByteSearched);

			/* scan for start of a run */
			ch = *bitBuffer++;
			while ((bitsAvailableToSearch > bitsInLastByte) && 
									(ch == 0)) {
				ch = *bitBuffer++;
				/* this can't underflow if the above condition passes */
				bitsAvailableToSearch -= 8;
				runOffset += 8;
			}
		}

		/* we are either at the first byte of the run or the last byte
		 * of the buffer
		 */
		if (bitsAvailableToSearch <= bitsInLastByte) {
			/* only partial byte to search, mask off trailing unused bits */
			ch &= lastByteMaskTable[bitsInLastByte];
			if (ch) {
				/* on last byte, run found
				 * get the offset of the first bit
				 */
				bitsDiscardedOnFirstByteOfRun = bitSearchOffsetTable[ch];
				/* align the first set bit to lsb (little-endian) */
				ch >>= bitsDiscardedOnFirstByteOfRun;
				runOffset += bitsDiscardedOnFirstByteOfRun; 
				/* get the number of bits in the run */
				runLength = bitSearchCountTable[ch];
				break;
			} else {
				/* on last byte of buffer, no run found */
				break;
			}
		}

		/* we must be at the start of a run, and not the end of 
		 * the buffer
	       	 * get the offset of the first bit
		 */
		bitsDiscardedOnFirstByteOfRun = bitSearchOffsetTable[ch];
	       	/* align the first set bit to lsb (little-endian) */
		ch >>= bitsDiscardedOnFirstByteOfRun;
	       	/* this will be the final runOffset position */
		runOffset += bitsDiscardedOnFirstByteOfRun;
	       	/* get the number of bits of the run in this byte */
		runLength = bitSearchCountTable[ch];
		if ((bitsDiscardedOnFirstByteOfRun + runLength) < 8) {
			/* we must have found a run that doesn't continue to the */
			/* next byte */
			break;
		} 
		
		/* the run might continue or not
		 * should be byte aligned
		 */
		ch = *bitBuffer++;
		bitsAvailableToSearch -= 8;
		while ((bitsAvailableToSearch > bitsInLastByte) &&
								(ch == 0xFF)){
			/* Check whether the # bits in next byte can fit in the
			 * current run length
			 */
			if ((runLength + 8) > MAX_BITRUN_LEN){
				BitRunBreak = TRUE;
				break;
			}
			/* full bytes are part of run */
			ch = *bitBuffer++;
			bitsAvailableToSearch -= 8;
			runLength += 8;
		}

		if (BitRunBreak == TRUE){
			break;
		}

		/* we know we're either at the end of the run or the end
		 * of the buffer
		 */
		if (bitsAvailableToSearch <= bitsInLastByte) {
			/* on last byte of buffer, mask off any bits that are
			 * past the end of the bitmap
			 * handle bitmaps of non multiple of 8 size
			 */
			ch &= lastByteMaskTable[bitsAvailableToSearch];
			/* Check whether the # bits in next byte can fit in the
			 * current run length
			 */
			if ((runLength + bitSearchCountTable[ch]) >
							MAX_BITRUN_LEN) {
				break;
			}
			/* get the number of bits starting at the lsb for this run */
			runLength += bitSearchCountTable[ch];
			break;
		}

		/* Check whether the # bits in next byte can fit in the 
		 * current  run length 
		 */
		if ((runLength + bitSearchCountTable[ch]) > MAX_BITRUN_LEN) {
			break;
		}

		/* run must end on this byte and this is not end of buffer
		 * get the number of bits in the run
		 */
		runLength += bitSearchCountTable[ch];
	} while (0);

	if (runLength == 0) {
		/* no bits past startingOffset */
		*startingBitOffset = totalBitsInBitmap;
	} else {
	       	/* update for next run search */
		*startingBitOffset = runOffset + runLength;
	}

	*bitsInRun = runLength;
	*bitOffset = runOffset;

	return status;
}

inm_u32_t find_number_of_bits_set(unsigned char *bit_buffer,
				inm_u32_t buffer_size_in_bits)
{
	unsigned char *buffer;
	inm_u32_t byte_count, remainder_bits;
	inm_u32_t total_bits;
	unsigned char remainder_byte;

	if (!bit_buffer || buffer_size_in_bits == 0)
	return 0;

	buffer = bit_buffer;
	byte_count = (buffer_size_in_bits/8)+ ((buffer_size_in_bits%8)?1:0);
	total_bits = 0;
	
	remainder_bits = buffer_size_in_bits & 0x7;
	INM_BUG_ON(byte_count==0);
	while (byte_count!=0)
	{
		/* find bits correspond to top nibble */
		total_bits += nibble_bit_count[*buffer >> 4];
		/*find bits correspond to lower nibble of byte */
		total_bits += nibble_bit_count[*buffer & 0xf];
		--byte_count;
		if (!byte_count) {
		    break;
		}
		buffer++;
	}

	remainder_byte = *buffer & lastByteMaskTable[remainder_bits];
	total_bits += nibble_bit_count[remainder_byte >> 4];
	total_bits += nibble_bit_count[remainder_byte & 0xf];

	return total_bits;
}


#define DEFAULT_MAX_DATA_SIZE_PER_NON_DATA_MODE_DIRTY_BLOCK (64 * 1024 * 1024)
void
add_chg_to_db(bmap_bit_stats_t *bbsp, int cur_chg_len)
{
	if (((bbsp->bbs_nr_chgs_in_curr_db + 1) > MAX_CHANGE_INFOS_PER_PAGE) ||
		(bbsp->bbs_nr_dbs == 0) || (bbsp->bbs_curr_db_sz + cur_chg_len
		> DEFAULT_MAX_DATA_SIZE_PER_NON_DATA_MODE_DIRTY_BLOCK)) {
		bbsp->bbs_nr_dbs++;
		bbsp->bbs_nr_chgs_in_curr_db = 1;
		bbsp->bbs_curr_db_sz = cur_chg_len;
	} else {
		bbsp->bbs_nr_chgs_in_curr_db++;
		bbsp->bbs_curr_db_sz += cur_chg_len;
	}
}

void
find_bmap_io_pat(char *buf, inm_u64_t bits_in_bmap, bmap_bit_stats_t *bbsp,
							int eobmap)
{
	int nr_bits_in_word = 8;
	int nr_byt, nr_bit;
	int cnt = 0;
	char c;
	int cur_chg_len = 0;
	inm_u64_t len = bits_in_bmap/8;
	int rem_bits = bits_in_bmap - (len *8);

	if (rem_bits && !eobmap) {
	        eobmap = 1;
	}

	if (bbsp->bbs_nr_prev_bits) {
	        cnt = bbsp->bbs_nr_prev_bits;
	}


	for (nr_byt = 0; nr_byt < len; nr_byt++) {
	        c = buf[nr_byt];

	        for (nr_bit = 0; nr_bit < nr_bits_in_word; nr_bit++)    {

	                if (c & (1 << nr_bit)) {
	                        cnt = (cnt > 0) ? cnt+1 : 1;
	                        if (cnt != bbsp->bbs_max_nr_bits_in_chg) {
	                                /* move to next change */
	                                continue;
	                        }
	                }
	                if (cnt == 0) {
	                        continue;
	                }
	                cur_chg_len = (cnt * bbsp->bbs_bmap_gran);
	                add_chg_to_db(bbsp, cur_chg_len);
	                cnt = 0;
	        }
	}

	

	c = buf[nr_byt];
	for (nr_bit = 0; nr_bit < rem_bits; nr_bit++)    {
	        if (c & (1 << nr_bit)) {
	                cnt = (cnt > 0) ? cnt+1 : 1;
	                if (cnt != bbsp->bbs_max_nr_bits_in_chg) {
	                        /* move to next change */
	                        continue;
	                }
	        }
		if (cnt == 0) {
			continue;
		}
		cur_chg_len = (cnt * bbsp->bbs_bmap_gran);
		add_chg_to_db(bbsp, cur_chg_len);
		cnt = 0;
	}
	cur_chg_len = 0;

	if (cnt) {
	        bbsp->bbs_nr_prev_bits = cnt;
	        cur_chg_len = cnt * bbsp->bbs_bmap_gran;
	}

	if (cnt && eobmap) {
	        add_chg_to_db(bbsp, cur_chg_len);
	}
}
