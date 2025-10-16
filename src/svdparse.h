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

///
/// @file svdparse.h
///
/// Define interface to SV Delta files. Delta files are a list of chunks.
/// Each chunk begins with a four character tag,
/// a length, and then that many data bytes. 
///
#ifndef SVDPARSE__H
#define SVDPARSE__H

/* ***********************************************************************
 *        THIS FILE SHOULD BE REMOVES IN FUTURE. THIS FILE SHOULD BE COMMON
 *        FOR ALL FILTER DRIVERS IRRESPECTIVE OF OS.
 * ***********************************************************************
 */
 
#define BYTEMASK(ch)    ((ch) & (0xFF))
#define INMAGE_MAKEFOURCC(ch0, ch1, ch2, ch3)                              \
                (BYTEMASK(ch0) | (BYTEMASK(ch1) << 8) |   \
                (BYTEMASK(ch2) << 16) | (BYTEMASK(ch3) << 24 ))

#define SVD_TAG_HEADER1                  INMAGE_MAKEFOURCC( 'S', 'V', 'D', '1' )
#define SVD_TAG_DIRTY_BLOCKS             INMAGE_MAKEFOURCC( 'D', 'I', 'R', 'T' )
#define SVD_TAG_DIRTY_BLOCK_DATA         INMAGE_MAKEFOURCC( 'D', 'R', 'T', 'D' )
#define SVD_TAG_DIRTY_BLOCK_DATA_V2      INMAGE_MAKEFOURCC( 'D', 'D', 'V', '2' )
#define SVD_TAG_SENTINEL_HEADER          INMAGE_MAKEFOURCC( 'S', 'E', 'N', 'T' )
#define SVD_TAG_SENTINEL_DIRT            INMAGE_MAKEFOURCC( 'S', 'D', 'R', 'T' )
#define SVD_TAG_SYNC_HASH_COMPARE_DATA   INMAGE_MAKEFOURCC( 'S', 'H', 'C', 'D' )
#define SVD_TAG_SYNC_DATA                INMAGE_MAKEFOURCC( 'S', 'D', 'A', 'T' )
#define SVD_TAG_SYNC_DATA_NEEDED_INFO    INMAGE_MAKEFOURCC( 'S', 'D', 'N', 'I' )
#define SVD_TAG_TIME_STAMP_OF_FIRST_CHANGE  INMAGE_MAKEFOURCC( 'T', 'S', 'F', 'C' )
#define SVD_TAG_TIME_STAMP_OF_FIRST_CHANGE_V2 	INMAGE_MAKEFOURCC( 'T', 'F', 'V', '2' )
#define SVD_TAG_TIME_STAMP_OF_LAST_CHANGE   INMAGE_MAKEFOURCC( 'T', 'S', 'L', 'C' )
#define SVD_TAG_TIME_STAMP_OF_LAST_CHANGE_V2    INMAGE_MAKEFOURCC( 'T', 'L', 'V', '2' )
#define SVD_TAG_LENGTH_OF_DRTD_CHANGES      INMAGE_MAKEFOURCC( 'L', 'O', 'D', 'C' )
#define SVD_TAG_USER                     INMAGE_MAKEFOURCC( 'U', 'S', 'E', 'R' )
#define SVD_TAG_BEFORMAT		INMAGE_MAKEFOURCC('D','R','T','B')
#define SVD_TAG_LEFORMAT		INMAGE_MAKEFOURCC('D','R','T','L')

typedef struct tagGUID {
	inm_u32_t    Data1;
	unsigned short  Data2;
	unsigned short  Data3;
	unsigned char   Data4[8];
} SV_GUID;

#ifdef INM_LINUX
#pragma pack( push, 1 )
#else
#ifdef INM_SOLARIS
#pragma INM_PRAGMA_PUSH1
#else
#pragma pack(1)
#endif
#endif

typedef struct 
{
	inm_u32_t tag;
	inm_u32_t count;
	inm_u32_t Flags;
}SVD_PREFIX;

typedef struct 
{
	unsigned char  MD5Checksum[16];   /* MD5 checksum of all data that follows this field */
	SV_GUID   SVId;                   /* Unique ID assigned by amethyst */
	SV_GUID   OriginHost;             /* Unique origin host id */
	SV_GUID   OriginVolumeGroup;      /* Unique origin vol group id */
	SV_GUID   OriginVolume;           /* Unique origin vol id */
	SV_GUID   DestHost;               /* Unique dest host id */
	SV_GUID   DestVolumeGroup;        /* Unique dest vol group id */
	SV_GUID   DestVolume;             /* Unique dest vol id */
} SVD_HEADER1;

typedef struct 
{
	inm_s64_t         Length;
	inm_s64_t         ByteOffset;
} SVD_DIRTY_BLOCK;

typedef struct 
{
	inm_u32_t      	Length;
	inm_u64_t	ByteOffset;
	inm_u32_t      	uiSequenceNumberDelta;
	inm_u32_t      	uiTimeDelta;
} SVD_DIRTY_BLOCK_V2;

typedef struct 
{
	SVD_DIRTY_BLOCK DirtyBlock;
	inm_u64_t DataFileOffset;
}SVD_DIRTY_BLOCK_INFO;

typedef struct 
{
	inm_s64_t         Length;
	inm_s64_t         ByteOffset;
	unsigned char     MD5Checksum[16];  /* MD5 checksum of all data that follows this field */
} SVD_BLOCK_CHECKSUM;

/* Doesn't exist anymore. Just an array of SVD_DIRTY_BLOCK followed by Length data bytes. */
typedef struct 
{
	inm_s64_t BlockCount;
}SVD_DIRTY_BLOCK_DATA;

struct SVD_TIME_STAMP_HEADER 
{
	unsigned short      usStreamRecType;
	unsigned char       ucFlags;
	unsigned char       ucLength;
};

typedef struct 
{
	struct SVD_TIME_STAMP_HEADER   Header;
	inm_u32_t                ulSequenceNumber;
	inm_u64_t            TimeInHundNanoSecondsFromJan1601;
}SVD_TIME_STAMP;

typedef struct 
{
	struct SVD_TIME_STAMP_HEADER   Header;
	inm_u64_t             ullSequenceNumber;
	inm_u64_t             TimeInHundNanoSecondsFromJan1601;
}SVD_TIME_STAMP_V2;

/* Raw sentinel dirt file header. Two blocks: SENT and SDRT */
struct SENTINEL_DIRTYFILE_HEADER
{
	inm_u32_t tagSentinelHeader;
	inm_u32_t dwSize;
	inm_u32_t dwMajorVersion, dwMinorVersion;
	inm_u64_t ullVolumeCapacity;
	inm_u32_t dwPageSize;
	inm_u32_t tagSentinelDirty;
	inm_u32_t dwDirtSize;
};
#ifdef INM_LINUX 
#pragma pack( pop )
#else
#ifdef INM_SOLARIS
#pragma INM_PRAGMA_POP
#else
#pragma pack()
#endif
#endif

#endif /* SVDPARSE__H */

