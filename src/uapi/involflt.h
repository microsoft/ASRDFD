/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */

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
 * File       : involflt.h
 *
 * Description: Header shared between linux filter driver and user-space components.
 */

#ifndef INVOLFLT_H
#define INVOLFLT_H
#include "inm_types.h"
#include "ioctl_codes.h"

#define INMAGE_FILTER_DEVICE_NAME    	"/dev/involflt"
#define GUID_SIZE_IN_CHARS 		128
#define MAX_INITIATOR_NAME_LEN		24
#define INM_GUID_LEN_MAX 		256
#define INM_MAX_VOLUMES_IN_LIST     	0xFF
#define INM_MAX_SCSI_ID_SIZE     	256
#define MAX_WWPN_SIZE 			256
#define TAG_VOLUME_MAX_LENGTH   	256
#define GUID_LEN                	36
#define TAG_MAX_LENGTH          	256

/* Version information stated with Driver Version 2.0.0.0 */
#define DRIVER_MAJOR_VERSION    0x02
#define DRIVER_MINOR_VERSION    0x03
#define DRIVER_MINOR_VERSION2   0x0f
#define DRIVER_MINOR_VERSION3   0x3f

/*freeze, thaw, tag volume return status */
#define STATUS_FREEZE_SUCCESS    0x0000
#define STATUS_FREEZE_FAILED     0x0001

#define STATUS_THAW_SUCCESS      0x0000
#define STATUS_THAW_FAILED       0x0001

#define STATUS_TAG_ACCEPTED      0x0000
#define STATUS_TAG_NOT_ACCEPTED  0x0001
#define STATUS_TAG_NOT_PROTECTED 0x0002
#define STATUS_TAG_WO_METADATA   0x0004

#define TAG_FS_FROZEN_IN_USERSPACE 0x0004

#define VACP_IOBARRIER_TIMEOUT          300     /* in ms */
#define VACP_TAG_COMMIT_TIMEOUT         300     /* in ms */
#define FS_FREEZE_TIMEOUT               60000   /* in ms */
#define VACP_APP_TAG_COMMIT_TIMEOUT     60000   /* in ms */

typedef enum {
	INM_TAG_FAILED = -1, /* ioctl returns -1 on failure*/ 
	                     /* and sets the errno         */
	INM_TAG_SUCCESS = 0, /* ioctl returns 0 on success */
	INM_TAG_PARTIAL = 1, /* indicate partial success   */
} inm_tag_status_t;

typedef enum {
	FLT_MODE_UNINITIALIZED = 0,
	FLT_MODE_METADATA,
	FLT_MODE_DATA
} flt_mode;

typedef enum _etWriterOrderState {
	ecWriteOrderStateUnInitialized = 0,
	ecWriteOrderStateBitmap = 1,
	ecWriteOrderStateMetadata = 2,
	ecWriteOrderStateData = 3,
	ecWriteOrderStateRawBitmap = 4
} etWriteOrderState, *petWriteOrderState;
 
typedef enum inm_device {
	FILTER_DEV_FABRIC_LUN = 1,
	FILTER_DEV_HOST_VOLUME = 2,
	FILTER_DEV_FABRIC_VSNAP = 3,
	FILTER_DEV_FABRIC_RESYNC = 4,
	FILTER_DEV_MIRROR_SETUP = 5,
} inm_device_t;

typedef enum vendor {
	FILTER_DEV_UNKNOWN_VENDOR = 1,
	FILTER_DEV_NATIVE = 2,
	FILTER_DEV_DEVMAPPER = 3,
	FILTER_DEV_MPXIO = 4,
	FILTER_DEV_EMC = 5,
	FILTER_DEV_HDLM = 6, 
	FILTER_DEV_DEVDID = 7,
	FILTER_DEV_DEVGLOBAL = 8, 
	FILTER_DEV_VXDMP = 9, 
	FILTER_DEV_SVM = 10,
	FILTER_DEV_VXVM = 11, 
	FILTER_DEV_LVM = 12, 
	FILTER_DEV_INMVOLPACK = 13,
	FILTER_DEV_INMVSNAP = 14, 
	FILTER_DEV_CUSTOMVENDOR = 15, 
	FILTER_DEV_ASM = 16,
}inm_vendor_t;

#define MIRROR_SETUP_PENDING_RESYNC_CLEARED_FLAG  0x0000000000000001
#define FULL_DISK_FLAG                            0x0000000000000002
#define FULL_DISK_PARTITION_FLAG                  0x0000000000000004
#define FULL_DISK_LABEL_VTOC                      0x0000000000000008
#define FULL_DISK_LABEL_EFI                       0x0000000000000010
#define INM_IS_DEVICE_MULTIPATH                   0x0000000000000100
#define MIRROR_VOLUME_STACKING_FLAG               0x00008000
#define HOST_VOLUME_STACKING_FLAG                 0x00010000

/*
 * This structure is defined for backward compatibility with older drivers
 * who accept the older structure without d_pname. This structure is only
 * used for defining the ioctl command values.
 */
typedef struct inm_dev_info_compat {
	inm_device_t d_type;
	char d_guid[INM_GUID_LEN_MAX];
	char d_mnt_pt[INM_PATH_MAX];
	inm_u64_t d_nblks;
	inm_u32_t d_bsize;
	inm_u64_t d_flags;
} inm_dev_info_compat_t;

typedef struct inm_dev_info {
	inm_device_t d_type;
	char d_guid[INM_GUID_LEN_MAX];
	char d_mnt_pt[INM_PATH_MAX];
	inm_u64_t d_nblks;
	inm_u32_t d_bsize;
	inm_u64_t d_flags;
	char d_pname[INM_GUID_LEN_MAX];
} inm_dev_info_t;

typedef enum eMirrorConfErrors
{
	MIRROR_NO_ERROR = 0,
	SRC_LUN_INVALID,
	ATLUN_INVALID,
	DRV_MEM_ALLOC_ERR,
	DRV_MEM_COPYIN_ERR,
	DRV_MEM_COPYOUT_ERR,
	SRC_NAME_CHANGED_ERR,
	ATLUN_NAME_CHANGED_ERR,
	MIRROR_STACKING_ERR,
	RESYNC_CLEAR_ERROR,
	RESYNC_NOT_SET_ON_CLEAR_ERR,
	SRC_DEV_LIST_MISMATCH_ERR,
	ATLUN_DEV_LIST_MISMATCH_ERR,
	SRC_DEV_SCSI_ID_ERR,
	DST_DEV_SCSI_ID_ERR,
	MIRROR_NOT_SETUP,
	MIRROR_NOT_SUPPORTED
} eMirrorConfErrors_t;

typedef struct _mirror_conf_info
{
	inm_u64_t d_flags;
	inm_u64_t d_nblks;
	inm_u64_t d_bsize;
	inm_u64_t startoff;
	
#ifdef INM_AIX
#ifdef __64BIT__
	/* [volume name 1]..[volume name n] */
	char *src_guid_list;
#else
	int  padding;
	/* [volume name 1]..[volume name n] */
	char *src_guid_list;
#endif

#ifdef __64BIT__
	/* [volume name 1]..[volume name n] */
	char *dst_guid_list;
#else
	int  padding_2;
	/* [volume name 1]..[volume name n] */
	char *dst_guid_list;
#endif
#else
	/* [volume name 1]..[volume name n] */
	char *src_guid_list;

	/* [volume name 1]..[volume name n] */
	char *dst_guid_list;
#endif

	eMirrorConfErrors_t d_status;
	inm_u32_t nsources;
	inm_u32_t ndestinations;
	inm_device_t d_type;
	inm_vendor_t d_vendor;

	char src_scsi_id[INM_MAX_SCSI_ID_SIZE];
	char dst_scsi_id[INM_MAX_SCSI_ID_SIZE];

	/* AT LUN id */
	char at_name[INM_GUID_LEN_MAX];
} mirror_conf_info_t;

typedef enum _etBitOperation {
	ecBitOpNotDefined = 0,
	ecBitOpSet = 1,
	ecBitOpReset = 2,
} etBitOperation;

#define PROCESS_START_NOTIFY_INPUT_FLAGS_DATA_FILES_AWARE   0x0001
#define PROCESS_START_NOTIFY_INPUT_FLAGS_64BIT_PROCESS      0x0002

#define SHUTDOWN_NOTIFY_FLAGS_ENABLE_DATA_FILTERING 0x00000001
#define SHUTDOWN_NOTIFY_FLAGS_ENABLE_DATA_FILES     0x00000002

typedef struct
{
	char volume_guid[GUID_SIZE_IN_CHARS];
} VOLUME_GUID;

typedef struct
{
	char scsi_id[INM_MAX_SCSI_ID_SIZE];
} SCSI_ID;

typedef struct _SHUTDOWN_NOTIFY_INPUT
{
	inm_u32_t ulFlags;
} SHUTDOWN_NOTIFY_INPUT, *PSHUTDOWN_NOTIFY_INPUT;

typedef SHUTDOWN_NOTIFY_INPUT SYS_SHUTDOWN_NOTIFY_INPUT;

typedef struct _PROCESS_START_NOTIFY_INPUT
{
	inm_u32_t  ulFlags;
} PROCESS_START_NOTIFY_INPUT, *PPROCESS_START_NOTIFY_INPUT;

typedef struct _PROCESS_VOLUME_STACKING_INPUT
{
	inm_u32_t  ulFlags;
} PROCESS_VOLUME_STACKING_INPUT, *PPROCESS_VOLUME_STACKING_INPUT;

typedef struct _DISK_CHANGE
{
	inm_u64_t   ByteOffset;
	inm_u32_t         Length;
	unsigned short       usBufferIndex;
	unsigned short       usNumberOfBuffers;
} DISK_CHANGE, DiskChange, *PDISK_CHANGE;

typedef struct _LUN_CREATE_INPUT
{
	char uuid[GUID_SIZE_IN_CHARS+1];
	inm_u64_t lunSize;
	inm_u64_t lunStartOff;
	inm_u32_t blockSize;
	inm_device_t lunType;
} LUN_CREATE_INPUT, LunCreateData, *PLUN_CREATE_DATA;

typedef struct _LUN_DELETE_DATA
{
	char uuid[GUID_SIZE_IN_CHARS+1];
	inm_device_t lunType;
} LUN_DELETE_INPUT, LunDeleteData, *PLUN_DELETE_DATA;

typedef struct _AT_LUN_LAST_WRITE_VI
{
	char uuid[GUID_SIZE_IN_CHARS+1];
	char initiator_name[MAX_INITIATOR_NAME_LEN];
	inm_u64_t timestamp; /* Return timestamp at which ioctl was issued */
} AT_LUN_LAST_WRITE_VI,ATLunLastWriteVI , *PATLUN_LAST_WRITE_VI;

typedef struct _WWPN_DATA
{
	/* wwpn in FC (Max. 23 bytes ex: aa:bb:cc:dd:ee:ff:gg:hh) OR
	 * iscsi iqn name (maximum length of 223 bytes
	 * iscsi eui name (Max. 20 bytes ex: eui.02004567A425678D)
	 * Using: 256 bytes long string
	 */
	char wwpn[MAX_WWPN_SIZE];
} WWPN_DATA, WwpnData, *PWWPNDATA;

typedef struct _AT_LUN_LAST_HOST_IO_TIMESTAMP
{
	char uuid[GUID_SIZE_IN_CHARS+1]; /* Input: AT lun name, Max size = GUID_SIZE_IN_CHARS+1 */
	inm_u64_t timestamp;             /* Output: Return timestamp of last successful IO done by the host */
	inm_u32_t wwpn_count;            /* Input: Number of host PI wwpns */
	WwpnData wwpn_data[1];           /* Input: each terminated by '\0', MAX size = MAX_INITIATOR_NAME_LEN ??? */
} AT_LUN_LAST_HOST_IO_TIMESTAMP, ATLunLastHostIOTimeStamp, *PAT_LUN_LAST_HOST_IO_TIMESTAMP;


typedef struct _LUN_DATA
{
	char uuid[GUID_SIZE_IN_CHARS+1];
	inm_device_t lun_type;
} LUN_DATA, LunData, *PLUNDATA;

typedef struct _LUN_QUERY_DATA
{
	inm_u32_t count;
	inm_u32_t lun_count;
	LunData lun_data[1];
} LUN_QUERY_DATA, LunQueryData, *PLUN_QUERY_DATA;

/*

Tag Structure
_________________________________________________________________________
|                   |              |                        | Padding     |
| Tag Header        |  Tag Size    | Tag Data               | (4Byte      |
|__(4 / 8 Bytes)____|____(2 Bytes)_|__(Tag Size Bytes)______|__ Alignment)|

Tag Size doesnot contain the padding.
But the length in Tag Header contains the total tag length including padding.
i.e. Tag length in header = Tag Header size + 2 bytes Tag Size + Tag Data Length  + Padding
*/

#define STREAM_REC_TYPE_START_OF_TAG_LIST   0x0001
#define STREAM_REC_TYPE_END_OF_TAG_LIST     0x0002
#define STREAM_REC_TYPE_TIME_STAMP_TAG      0x0003
#define STREAM_REC_TYPE_DATA_SOURCE         0x0004
#define STREAM_REC_TYPE_USER_DEFINED_TAG    0x0005
#define STREAM_REC_TYPE_PADDING             0x0006

#ifndef INVOFLT_STREAM_FUNCTIONS
#define INVOFLT_STREAM_FUNCTIONS
typedef struct _STREAM_REC_HDR_4B
{
	unsigned short       usStreamRecType;
	unsigned char        ucFlags;
	unsigned char        ucLength; /* Length includes size of this header too. */
} STREAM_REC_HDR_4B, *PSTREAM_REC_HDR_4B;

typedef struct _STREAM_REC_HDR_8B
{
	unsigned short       usStreamRecType;
	unsigned char        ucFlags;	/* STREAM_REC_FLAGS_LENGTH_BIT bit is set for this record. */
	unsigned char        ucReserved;
	inm_u32_t         ulLength;	/* Length includes size of this header too. */
} STREAM_REC_HDR_8B, *PSTREAM_REC_HDR_8B;

#define FILL_STREAM_HEADER_4B(pHeader, Type, Len)           	\
{                                                           	\
	((PSTREAM_REC_HDR_4B)pHeader)->usStreamRecType = Type;  \
	((PSTREAM_REC_HDR_4B)pHeader)->ucFlags = 0;             \
	((PSTREAM_REC_HDR_4B)pHeader)->ucLength = Len;          \
}

#define FILL_STREAM_HEADER_8B(pHeader, Type, Len)           			\
{                                                           			\
	((PSTREAM_REC_HDR_8B)pHeader)->usStreamRecType = Type;  		\
	((PSTREAM_REC_HDR_8B)pHeader)->ucFlags = STREAM_REC_FLAGS_LENGTH_BIT;   \
	((PSTREAM_REC_HDR_8B)pHeader)->ucReserved = 0;          		\
	((PSTREAM_REC_HDR_8B)pHeader)->ulLength = Len;          		\
}

#define STREAM_REC_FLAGS_LENGTH_BIT         0x01

#define GET_STREAM_LENGTH(pHeader)                              			\
	( (((PSTREAM_REC_HDR_4B)pHeader)->ucFlags & STREAM_REC_FLAGS_LENGTH_BIT) ?      \
	            (((PSTREAM_REC_HDR_8B)pHeader)->ulLength) :                         \
	            (((PSTREAM_REC_HDR_4B)pHeader)->ucLength))
#endif

#define FILL_STREAM_HEADER(pHeader, Type, Len)                  			\
{                                                               			\
	if((inm_u32_t )Len > (inm_u32_t )0xFF) {                              		\
	    ((PSTREAM_REC_HDR_8B)pHeader)->usStreamRecType = Type;  			\
	    ((PSTREAM_REC_HDR_8B)pHeader)->ucFlags = STREAM_REC_FLAGS_LENGTH_BIT;       \
	    ((PSTREAM_REC_HDR_8B)pHeader)->ucReserved = 0;          			\
	    ((PSTREAM_REC_HDR_8B)pHeader)->ulLength = Len;          			\
	} else {                                                    			\
	    ((PSTREAM_REC_HDR_4B)pHeader)->usStreamRecType = Type;  			\
	    ((PSTREAM_REC_HDR_4B)pHeader)->ucFlags = 0;             			\
	    ((PSTREAM_REC_HDR_4B)pHeader)->ucLength = (unsigned char )Len;   		\
	}                                                           			\
}

#define FILL_STREAM(pHeader, Type, Len, pData)                  				\
{                                                               				\
	if((inm_u32_t )Len > (inm_u32_t )0xFF) {                              			\
	    ((PSTREAM_REC_HDR_8B)pHeader)->usStreamRecType = Type;  				\
	    ((PSTREAM_REC_HDR_8B)pHeader)->ucFlags = STREAM_REC_FLAGS_LENGTH_BIT;       	\
	    ((PSTREAM_REC_HDR_8B)pHeader)->ucReserved = 0;          				\
	    ((PSTREAM_REC_HDR_8B)pHeader)->ulLength = Len;          				\
	    RtlCopyMemory(((Punsigned char )pHeader) + sizeof(PSTREAM_REC_HDR_8B), pData, Len); \
	} else {                                                    				\
	    ((PSTREAM_REC_HDR_4B)pHeader)->usStreamRecType = Type;  				\
	    ((PSTREAM_REC_HDR_4B)pHeader)->ucFlags = 0;             				\
	    ((PSTREAM_REC_HDR_4B)pHeader)->ucLength = (unsigned char )Len;   			\
	    RtlCopyMemory(((Punsigned char )pHeader) + sizeof(PSTREAM_REC_HDR_4B), pData, Len); \
	}                                                           				\
}



#define STREAM_REC_SIZE(pHeader)                              				\
	( (((PSTREAM_REC_HDR_4B)pHeader)->ucFlags & STREAM_REC_FLAGS_LENGTH_BIT) ?      \
	            (((PSTREAM_REC_HDR_8B)pHeader)->ulLength) :                         \
	            (((PSTREAM_REC_HDR_4B)pHeader)->ucLength))
#define STREAM_REC_TYPE(pHeader)    ((pHeader->usStreamRecType & TAG_TYPE_MASK) >> 0x14)
#define STREAM_REC_ID(pHeader)  (((PSTREAM_REC_HDR_4B)pHeader)->usStreamRecType)
#define STREAM_REC_HEADER_SIZE(pHeader) ( (((PSTREAM_REC_HDR_4B)pHeader)->ucFlags & STREAM_REC_FLAGS_LENGTH_BIT) ?  sizeof(STREAM_REC_HDR_8B) : sizeof(STREAM_REC_HDR_4B) )
#define STREAM_REC_DATA_SIZE(pHeader)   (STREAM_REC_SIZE(pHeader) - STREAM_REC_HEADER_SIZE(pHeader))
#define STREAM_REC_DATA(pHeader)    ((Punsigned char )pHeader + STREAM_REC_HEADER_SIZE(pHeader))

typedef struct _TIME_STAMP_TAG
{
	STREAM_REC_HDR_4B    Header;
	inm_u32_t         ulSequenceNumber;
	inm_u64_t   TimeInHundNanoSecondsFromJan1601;
} TIME_STAMP_TAG, *PTIME_STAMP_TAG;

typedef struct _TIME_STAMP_TAG_V2
{
	STREAM_REC_HDR_4B    Header;
	STREAM_REC_HDR_4B	 Reserved;
	inm_u64_t   ullSequenceNumber;
	inm_u64_t   TimeInHundNanoSecondsFromJan1601;
} TIME_STAMP_TAG_V2, *PTIME_STAMP_TAG_V2;

#define INVOLFLT_DATA_SOURCE_UNDEFINED  0x00
#define INVOLFLT_DATA_SOURCE_BITMAP     0x01
#define INVOLFLT_DATA_SOURCE_META_DATA  0x02
#define INVOLFLT_DATA_SOURCE_DATA       0x03

typedef struct _DATA_SOURCE_TAG
{
	STREAM_REC_HDR_4B   Header;
	inm_u32_t        ulDataSource;
} DATA_SOURCE_TAG, *PDATA_SOURCE_TAG;

typedef struct _VOLUME_STATS{
	VOLUME_GUID     guid;
	char            *bufp;
	inm_u32_t       buf_len;
} VOLUME_STATS;

/* Light weight stats about Tags */
typedef struct _VOLUME_TAG_STATS
{
	inm_u64_t    TagsDropped;
} VOLUME_TAG_STATS;

/* Light weight stats about write churn */
typedef struct _VOLUME_CHURN_STATS
{
	inm_s64_t    NumCommitedChangesInBytes;
} VOLUME_CHURN_STATS;

/* User passes below flag indicating required Light weight stats */
typedef enum
{
	GET_TAG_STATS  = 1,
	GET_CHURN_STATS
} ReqStatsType;

typedef struct _MONITORING_STATS{
	VOLUME_GUID VolumeGuid;
	ReqStatsType ReqStat;

	union {
	    VOLUME_TAG_STATS TagStats;
	    VOLUME_CHURN_STATS ChurnStats;
	};
} MONITORING_STATS;

typedef struct _BLK_MQ_STATUS{
	VOLUME_GUID VolumeGuid;
	int blk_mq_enabled;
} BLK_MQ_STATUS;

typedef struct _GET_VOLUME_LIST {
#ifdef INM_AIX
#ifdef __64BIT__
	char		*bufp;
#else
	int		padding;
	char		*bufp;
#endif
#else
	char		*bufp;
#endif
	inm_u32_t	buf_len;
} GET_VOLUME_LIST;

typedef struct _inm_attribute{
	inm_u32_t       type;
	inm_u32_t       why;
	VOLUME_GUID     guid;
	char            *bufp;
	inm_u32_t       buflen;
}inm_attribute_t;

#define MAX_DIRTY_CHANGES 256

#ifdef __sparcv9
#define MAX_DIRTY_CHANGES_V2 409
#else
#define MAX_DIRTY_CHANGES_V2 204
#endif

#define UDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE     0x00000001
#define UDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE      0x00000002
#define UDIRTY_BLOCK_FLAG_END_OF_SPLIT_CHANGE       0x00000004
#define UDIRTY_BLOCK_FLAG_DATA_FILE                 0x00000008
#define UDIRTY_BLOCK_FLAG_SVD_STREAM                0x00000010			
#define UDIRTY_BLOCK_FLAG_VOLUME_RESYNC_REQUIRED    0x80000000
#define UDIRTY_BLOCK_FLAG_TSO_FILE                  0x00000020

#define COMMIT_TRANSACTION_FLAG_RESET_RESYNC_REQUIRED_FLAG  0x00000001

typedef struct _UDIRTY_BLOCK
{
#define UDIRTY_BLOCK_HEADER_SIZE    0x200   		/* 512 Bytes */
#define UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE  0x80    	/* 128 Bytes */
#define UDIRTY_BLOCK_TAGS_SIZE      0xE00   		/* 7 * 512 Bytes */
/* UDIRTY_BLOCK_MAX_FILE_NAME is UDIRTY_BLOCK_TAGS_SIZE / sizeof(unsigned char ) - 1(for length field) */
#define UDIRTY_BLOCK_MAX_FILE_NAME  0x6FF   /* (0xE00 /2) - 1 */
	/* uHeader is .5 KB and uTags is 3.5 KB, uHeader + uTags = 4KB */
	union {
		struct {
			inm_u64_t      		uliTransactionID;
			inm_u64_t      		ulicbChanges;
			inm_u32_t            	cChanges;
			inm_u32_t            	ulTotalChangesPending;
			inm_u64_t      		ulicbTotalChangesPending;
			inm_u32_t            	ulFlags;
			inm_u32_t            	ulSequenceIDforSplitIO;
			inm_u32_t            	ulBufferSize;
			unsigned short          usMaxNumberOfBuffers;
			unsigned short          usNumberOfBuffers;
			inm_u32_t		ulcbChangesInStream;

			/* This is actually a pointer to memory and not an array of pointers. 
			 * It contains Changes in linear memorylocation.
			 */
			void                    **ppBufferArray; 
			inm_u32_t            	ulcbBufferArraySize;

			/* resync flags */
			unsigned long 		ulOutOfSyncCount;
			unsigned char           ErrorStringForResync[UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE]; 
			unsigned long           ulOutOfSyncErrorCode;
			inm_u64_t      		liOutOfSyncTimeStamp;
			inm_u32_t   		ulPrevEndSequenceNumber;
			inm_u64_t   		ullPrevEndTimeStamp;
			inm_u32_t   		ulPrevSequenceIDforSplitIO;
			etWriteOrderState    	eWOState;

		} Hdr;
		unsigned char  BufferReservedForHeader[UDIRTY_BLOCK_HEADER_SIZE];
	} uHdr;

	/* Start of Markers */
	union {
		struct {
			STREAM_REC_HDR_4B   	TagStartOfList;
			STREAM_REC_HDR_4B   	TagPadding;
			TIME_STAMP_TAG      	TagTimeStampOfFirstChange;
			TIME_STAMP_TAG      	TagTimeStampOfLastChange;
			DATA_SOURCE_TAG     	TagDataSource;
			STREAM_REC_HDR_4B   	TagEndOfList;
		} TagList;
		struct {
			unsigned short   	usLength; /* Filename length in bytes not including NULL */
			unsigned char    	FileName[UDIRTY_BLOCK_MAX_FILE_NAME];
		} DataFile;
		unsigned char  BufferForTags[UDIRTY_BLOCK_TAGS_SIZE];
	} uTagList;

	inm_sll64_t ChangeOffsetArray[MAX_DIRTY_CHANGES];	
	inm_u32_t ChangeLengthArray[MAX_DIRTY_CHANGES];	
} UDIRTY_BLOCK, *PUDIRTY_BLOCK;

typedef struct _UDIRTY_BLOCK_V2
{
#define UDIRTY_BLOCK_HEADER_SIZE    		0x200   	/* 512 Bytes */
#define UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE  	0x80    	/* 128 Bytes */
#define UDIRTY_BLOCK_TAGS_SIZE      		0xE00   	/* 7 * 512 Bytes */
/* UDIRTY_BLOCK_MAX_FILE_NAME is UDIRTY_BLOCK_TAGS_SIZE / sizeof(unsigned char ) - 1(for length field) */
#define UDIRTY_BLOCK_MAX_FILE_NAME  		0x6FF   	/* (0xE00 /2) - 1 */
	/* uHeader is .5 KB and uTags is 3.5 KB, uHeader + uTags = 4KB */
	union {
		struct {
			inm_u64_t      		uliTransactionID;
			inm_u64_t      		ulicbChanges;
			inm_u32_t       	cChanges;
			inm_u32_t       	ulTotalChangesPending;
			inm_u64_t      		ulicbTotalChangesPending;
			inm_u32_t       	ulFlags;
			inm_u32_t       	ulSequenceIDforSplitIO;
			inm_u32_t       	ulBufferSize;
			unsigned short  	usMaxNumberOfBuffers;
			unsigned short  	usNumberOfBuffers;
			inm_u32_t		ulcbChangesInStream;

			/* This is actually a pointer to memory and not an array of pointers. 
			 * It contains Changes in linear memorylocation.
			 */
			void            	**ppBufferArray; 
			inm_u32_t       	ulcbBufferArraySize;

			/* resync flags */
			unsigned long 		ulOutOfSyncCount;
			unsigned char   	ErrorStringForResync[UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE]; 
			unsigned long   	ulOutOfSyncErrorCode;
			inm_u64_t      		liOutOfSyncTimeStamp;
			inm_u64_t   		ullPrevEndSequenceNumber;
			inm_u64_t   		ullPrevEndTimeStamp;
			inm_u32_t   		ulPrevSequenceIDforSplitIO;
			etWriteOrderState    	eWOState;

		} Hdr;
		unsigned char  BufferReservedForHeader[UDIRTY_BLOCK_HEADER_SIZE];
	} uHdr;

	/* Start of Markers */
	union {
		struct {
			STREAM_REC_HDR_4B   	TagStartOfList;
			STREAM_REC_HDR_4B   	TagPadding;
			TIME_STAMP_TAG_V2      	TagTimeStampOfFirstChange;
			TIME_STAMP_TAG_V2      	TagTimeStampOfLastChange;
			DATA_SOURCE_TAG     	TagDataSource;
			STREAM_REC_HDR_4B   	TagEndOfList;
		} TagList;
		struct {
			/* Filename length in bytes not including NULL */
			unsigned short   	usLength;
			unsigned char    	FileName[UDIRTY_BLOCK_MAX_FILE_NAME];
		} DataFile;
		unsigned char  BufferForTags[UDIRTY_BLOCK_TAGS_SIZE];
	} uTagList;

	inm_ull64_t ChangeOffsetArray[MAX_DIRTY_CHANGES_V2];	
	inm_u32_t ChangeLengthArray[MAX_DIRTY_CHANGES_V2];	
	inm_u32_t TimeDeltaArray[MAX_DIRTY_CHANGES_V2];
	inm_u32_t SequenceNumberDeltaArray[MAX_DIRTY_CHANGES_V2];
} UDIRTY_BLOCK_V2, *PUDIRTY_BLOCK_V2;

typedef struct _COMMIT_TRANSACTION
{
	unsigned char   VolumeGUID[GUID_SIZE_IN_CHARS];
	inm_u64_t   	ulTransactionID;
	inm_u32_t     	ulFlags;
} COMMIT_TRANSACTION, *PCOMMIT_TRANSACTION;

typedef struct _VOLUME_FLAGS_INPUT
{
	unsigned char	VolumeGUID[GUID_SIZE_IN_CHARS];
	// if eOperation is BitOpSet the bits in ulVolumeFlags will be set
	// if eOperation is BitOpReset the bits in ulVolumeFlags will be unset
	etBitOperation  eOperation;
	inm_u32_t    	ulVolumeFlags;
} VOLUME_FLAGS_INPUT, *PVOLUME_FLAGS_INPUT;

typedef struct _VOLUME_FLAGS_OUTPUT
{
	inm_u32_t    ulVolumeFlags;
} VOLUME_FLAGS_OUTPUT, *PVOLUME_FLAGS_OUTPUT;

#define DRIVER_FLAG_DISABLE_DATA_FILES                  0x00000001
#define DRIVER_FLAG_DISABLE_DATA_FILES_FOR_NEW_VOLUMES  0x00000002
#define DRIVER_FLAGS_VALID                              0x00000003

typedef struct _DRIVER_FLAGS_INPUT
{
	/* if eOperation is BitOpSet the bits in ulFlags will be set
	 * if eOperation is BitOpReset the bits in ulFlags will be unset
	 */
	etBitOperation  eOperation;
	inm_u32_t    	ulFlags;
} DRIVER_FLAGS_INPUT, *PDRIVER_FLAGS_INPUT;

typedef struct _DRIVER_FLAGS_OUTPUT
{
	inm_u32_t    ulFlags;
} DRVER_FLAGS_OUTPUT, *PDRIVER_FLAGS_OUTPUT;

typedef struct 
{
	unsigned char	VolumeGUID[GUID_SIZE_IN_CHARS]; 
	/* Maximum time to wait in the kernel */
	inm_s32_t       Seconds;
} WAIT_FOR_DB_NOTIFY;

typedef struct 
{
	unsigned char	VolumeGUID[GUID_SIZE_IN_CHARS]; 
	inm_u32_t	threshold;
} get_db_thres_t;

typedef struct
{
	unsigned char 	VolumeGUID[GUID_SIZE_IN_CHARS];
	inm_u64_t 	TimeInHundNanoSecondsFromJan1601;
	inm_u32_t 	ulSequenceNumber;
	inm_u32_t 	ulReserved;
} RESYNC_START;
typedef struct
{
	unsigned char 	VolumeGUID[GUID_SIZE_IN_CHARS];
	inm_u64_t 	TimeInHundNanoSecondsFromJan1601;
	inm_u64_t 	ullSequenceNumber;
} RESYNC_START_V2;

typedef struct
{
	unsigned char 	VolumeGUID[GUID_SIZE_IN_CHARS];
	inm_u64_t 	TimeInHundNanoSecondsFromJan1601;
	inm_u32_t 	ulSequenceNumber;
	inm_u32_t 	ulReserved;
} RESYNC_END;
typedef struct
{
	unsigned char 	VolumeGUID[GUID_SIZE_IN_CHARS];
	inm_u64_t 	TimeInHundNanoSecondsFromJan1601;
	inm_u64_t 	ullSequenceNumber;
} RESYNC_END_V2;

typedef struct _DRIVER_VERSION
{
	unsigned short  ulDrMajorVersion;
	unsigned short  ulDrMinorVersion;
	unsigned short  ulDrMinorVersion2;
	unsigned short  ulDrMinorVersion3;
	unsigned short  ulPrMajorVersion;
	unsigned short  ulPrMinorVersion;
	unsigned short  ulPrMinorVersion2;
	unsigned short  ulPrBuildNumber;
} DRIVER_VERSION, *PDRIVER_VERSION;

#define TAG_VOLUME_INPUT_FLAGS_ATOMIC_TO_VOLUME_GROUP 0x0001
#define TAG_FS_CONSISTENCY_REQUIRED		      0x0002
#define TAG_ALL_PROTECTED_VOLUME_IOBARRIER            0x0004

/* Structure definition to freeze */
typedef struct volume_info
{
	int           flags;  /* Fill it with 0s, will be used in future */
	int           status; /* Status of the volume */
	char          vol_name[TAG_VOLUME_MAX_LENGTH]; /* volume name */
} volume_info_t;

typedef struct freeze_info
{
	int                   nr_vols;    /* No. of volumes */
	int                   timeout;    /* timeout in terms of seconds */
	volume_info_t         *vol_info;  /* array of volume_info_t object */
	char                  tag_guid[GUID_LEN];/* one guid fro set of volumes*/
} freeze_info_t;

/* Structure definition to thaw */
typedef struct thaw_info
{
	int                   nr_vols;    /* No. of volumes */
	volume_info_t         *vol_info;  /* array of volume_info_t object */
	char                  tag_guid[GUID_LEN];
} thaw_info_t;

typedef struct tag_names
{
	unsigned short  tag_len;/*tag length header plus name*/
	char            tag_name[TAG_MAX_LENGTH]; /* volume name */
} tag_names_t;

/* Structure definition to tag */
typedef struct tag_info
{
	int                   flags;/* Fill it with 0s, will be used in future */
	int                   nr_vols;
	int                   nr_tags;
	int                   timeout;/*time to not drain the dirty block has tag*/
	char                  tag_guid[GUID_LEN];/* one guid fro set of volumes*/
	volume_info_t         *vol_info;  /* Array of volume_info_t object */
	tag_names_t           *tag_names; /* Arrays of tag names */
	                                  /* each of length TAG_MAX_LENGTH */
} tag_info_t_v2;

/*
 * IO Barriers for Crash Consistency
 */
typedef struct flt_barrier_create {
	char    fbc_guid[GUID_LEN];
	int     fbc_timeout_ms;
	int     fbc_flags;
} flt_barrier_create_t;

typedef struct flt_barrier_remove {
	char    fbr_guid[GUID_LEN];
	int     fbr_flags;
} flt_barrier_remove_t;

typedef enum _TAG_COMMIT_STATUS_T {
	TAG_REVOKE = 0,
	TAG_COMMIT = 1
} TAG_COMMIT_STATUS_T;

typedef struct flt_tag_commit {
	char                 ftc_guid[GUID_LEN];
	TAG_COMMIT_STATUS_T  ftc_flags;
} flt_tag_commit_t;

#define INM_VOL_NAME_MAP_GUID 0x1
#define INM_VOL_NAME_MAP_PNAME 0x2

typedef struct vol_pname{
	int  vnm_flags;
	char vnm_request[INM_GUID_LEN_MAX];
	char vnm_response[INM_GUID_LEN_MAX];
} vol_name_map_t;


typedef struct _COMMIT_DB_FAILURE_STATS {
	VOLUME_GUID    DeviceID;
	inm_u64_t      ulTransactionID;
	inm_u64_t      ullFlags;
	inm_u64_t      ullErrorCode;
} COMMIT_DB_FAILURE_STATS;

#define COMMITDB_NETWORK_FAILURE     0x00000001

#define DEFAULT_NR_CHURN_BUCKETS 11
typedef struct _DEVICE_CXFAILURE_STATS {
	VOLUME_GUID    DeviceId;
	inm_u64_t      ullFlags;
	inm_u64_t      ChurnBucketsMBps[DEFAULT_NR_CHURN_BUCKETS];
	inm_u64_t      ExcessChurnBucketsMBps[DEFAULT_NR_CHURN_BUCKETS];
	inm_u64_t      CxStartTS;
	inm_u64_t      ullMaxDiffChurnThroughputTS;
	inm_u64_t      firstNwFailureTS;
	inm_u64_t      lastNwFailureTS;
	inm_u64_t      firstPeakChurnTS;
	inm_u64_t      lastPeakChurnTS;
	inm_u64_t      CxEndTS;

	inm_u64_t      ullLastNWErrorCode;
	inm_u64_t      ullMaximumPeakChurnInBytes;
	inm_u64_t      ullDiffChurnThroughputInBytes;
	inm_u64_t      ullMaxDiffChurnThroughputInBytes;
	inm_u64_t      ullTotalNWErrors;
	inm_u64_t      ullNumOfConsecutiveTagFailures;
	inm_u64_t      ullTotalExcessChurnInBytes;
	inm_u64_t      ullMaxS2LatencyInMS;
} DEVICE_CXFAILURE_STATS, *PDEVICE_CXFAILURE_STATS;

/* Disk Level Flags */
#define DISK_CXSTATUS_NWFAILURE_FLAG           0x00000001
#define DISK_CXSTATUS_PEAKCHURN_FLAG           0x00000002
#define DISK_CXSTATUS_CHURNTHROUGHPUT_FLAG     0x00000004
#define DISK_CXSTATUS_EXCESS_CHURNBUCKET_FLAG  0x00000008
#define DISK_CXSTATUS_MAX_CHURNTHROUGHPUT_FLAG 0x00000010
#define DISK_CXSTATUS_DISK_NOT_FILTERED        0x00000020
#define DISK_CXSTATUS_DISK_REMOVED             0x00000040

typedef struct _GET_CXFAILURE_NOTIFY {
	inm_u64_t    ullFlags;
	inm_u64_t    ulTransactionID;
	inm_u64_t    ullMinConsecutiveTagFailures;
	inm_u64_t    ullMaxVMChurnSupportedMBps;
	inm_u64_t    ullMaxDiskChurnSupportedMBps;
	inm_u64_t    ullMaximumTimeJumpFwdAcceptableInMs;
	inm_u64_t    ullMaximumTimeJumpBwdAcceptableInMs;
	inm_u32_t    ulNumberOfOutputDisks;
	inm_u32_t    ulNumberOfProtectedDisks;
	VOLUME_GUID  DeviceIdList[1];
} GET_CXFAILURE_NOTIFY, *PGET_CXFAILURE_NOTIFY;

#define CXSTATUS_COMMIT_PREV_SESSION 0x00000001

typedef struct _VM_CXFAILURE_STATS {
	inm_u64_t    ullFlags;
	inm_u64_t    ulTransactionID;
	inm_u64_t    ChurnBucketsMBps[DEFAULT_NR_CHURN_BUCKETS];

	inm_u64_t    ExcessChurnBucketsMBps[DEFAULT_NR_CHURN_BUCKETS];

	inm_u64_t    CxStartTS;
	inm_u64_t    ullMaxChurnThroughputTS;
	inm_u64_t    firstPeakChurnTS;
	inm_u64_t    lastPeakChurnTS;
	inm_u64_t    CxEndTS;

	inm_u64_t    ullMaximumPeakChurnInBytes;
	inm_u64_t    ullDiffChurnThroughputInBytes;

	inm_u64_t    ullMaxDiffChurnThroughputInBytes;
	inm_u64_t    ullTotalExcessChurnInBytes;

	inm_u64_t    TimeJumpTS;
	inm_u64_t    ullTimeJumpInMS;

	inm_u64_t    ullNumOfConsecutiveTagFailures;

	inm_u64_t    ullMaxS2LatencyInMS;

	inm_u32_t    ullNumDisks;
	DEVICE_CXFAILURE_STATS DeviceCxStats[1];
} VM_CXFAILURE_STATS, *PVM_CXFAILURE_STATS;

/* VM Level Flags */
#define VM_CXSTATUS_PEAKCHURN_FLAG           0x00000001
#define VM_CXSTATUS_CHURNTHROUGHPUT_FLAG     0x00000002
#define VM_CXSTATUS_TIMEJUMP_FWD_FLAG        0x00000004
#define VM_CXSTATUS_TIMEJUMP_BCKWD_FLAG      0x00000008
#define VM_CXSTATUS_EXCESS_CHURNBUCKETS_FLAG 0x00000010
#define VM_CXSTATUS_MAX_CHURNTHROUGHPUT_FLAG 0x00000020

/* IOCTL codes for involflt driver in linux.
 */
#define FLT_IOCTL 0xfe

enum {
	STOP_FILTER_CMD = 0,
	START_FILTER_CMD,
	START_NOTIFY_CMD,
	SHUTDOWN_NOTIFY_CMD,
	GET_DB_CMD,
	COMMIT_DB_CMD,
	SET_VOL_FLAGS_CMD,
	GET_VOL_FLAGS_CMD,
	WAIT_FOR_DB_CMD,
	CLEAR_DIFFS_CMD,
	GET_TIME_CMD,
	UNSTACK_ALL_CMD,
	SYS_SHUTDOWN_NOTIFY_CMD,
	TAG_CMD,	
	WAKEUP_THREADS_CMD,
	GET_DB_THRESHOLD_CMD,	
	VOLUME_STACKING_CMD,
	RESYNC_START_CMD,
	RESYNC_END_CMD,
	GET_DRIVER_VER_CMD,
	GET_SHELL_LOG_CMD,
	AT_LUN_CREATE_CMD,
	AT_LUN_DELETE_CMD,
	AT_LUN_LAST_WRITE_VI_CMD,
	AT_LUN_QUERY_CMD,
	GET_GLOBAL_STATS_CMD,
	GET_VOLUME_STATS_CMD,
	GET_PROTECTED_VOLUME_LIST_CMD,
	GET_SET_ATTR_CMD,
	BOOTTIME_STACKING_CMD,
	VOLUME_UNSTACKING_CMD,
	START_FILTER_CMD_V2,
	SYNC_TAG_CMD,
	SYNC_TAG_STATUS_CMD,
	START_MIRROR_CMD,
	STOP_MIRROR_CMD,
	MIRROR_VOLUME_STACKING_CMD,
	MIRROR_EXCEPTION_NOTIFY_CMD,
	AT_LUN_LAST_HOST_IO_TIMESTAMP_CMD,
	GET_DMESG_CMD,
	BLOCK_AT_LUN_CMD,
	BLOCK_AT_LUN_ACCESS_CMD,
	MAX_XFER_SZ_CMD,
	GET_ADDITIONAL_VOLUME_STATS_CMD,
	GET_VOLUME_LATENCY_STATS_CMD,
	GET_VOLUME_BMAP_STATS_CMD,
	SET_INVOLFLT_VERBOSITY_CMD,
	MIRROR_TEST_HEARTBEAT_CMD,
	INIT_DRIVER_FULLY_CMD,
	VOLUME_FREEZE_CMD,
	TAG_CMD_V2,
	VOLUME_THAW_CMD,
	TAG_CMD_V3,
	CREATE_BARRIER,
	REMOVE_BARRIER,
	TAG_COMMIT_V2,
	SYS_PRE_SHUTDOWN_NOTIFY_CMD,
	GET_MONITORING_STATS_CMD,
	GET_BLK_MQ_STATUS_CMD,
	GET_VOLUME_STATS_V2_CMD,
	REPLICATION_STATE,
	NAME_MAPPING,
	COMMITDB_FAIL_TRANS,
	GET_CXSTATS_NOTIFY,
	WAKEUP_GET_CXSTATS_NOTIFY_THREAD,
	LCW,
	WAIT_FOR_DB_CMD_V2,
	TAG_DRAIN_NOTIFY,
	WAKEUP_TAG_DRAIN_NOTIFY_THREAD,
	MODIFY_PERSISTENT_DEVICE_NAME,
	GET_DRAIN_STATE_CMD,
	SET_DRAIN_STATE_CMD,
	GET_DB_CMD_V2
};


/* Error numbers to report out of sync */
#define ERROR_TO_REG_BITMAP_READ_ERROR                      0x0002
#define ERROR_TO_REG_BITMAP_WRITE_ERROR                     0x0003
#define ERROR_TO_REG_BITMAP_OPEN_ERROR                      0x0004
#define ERROR_TO_REG_BITMAP_OPEN_FAIL_CHANGES_LOST          (0x0005)
#define ERROR_TO_REG_OUT_OF_BOUND_IO                        0x0006
#define ERROR_TO_REG_INVALID_IO                             0x0007
#define ERROR_TO_REG_DESCRIPTION_IN_EVENT_LOG               0x0008
#define ERROR_TO_REG_NO_MEM_FOR_WORK_QUEUE_ITEM             0x0009
#define ERROR_TO_REG_WRITE_TO_CNT_IOC_PATH                  0x000a
#define ERROR_TO_REG_VENDOR_CDB_ERR                         0x000b
#define RESYNC_DUE_TO_ERR_INJECTION                         0x000c
#define ERROR_TO_REG_AT_PATHS_FAILURE                       0x000d
#define ERROR_TO_REG_BAD_AT_DEVICE_LIST                     0x000e
#define ERROR_TO_REG_FAILED_TO_ALLOC_BIOINFO                0x000f
#define ERROR_TO_REG_NEW_SOURCE_PATH_ADDED                  0x0010
#define ERROR_TO_REG_UNCLEAN_SYS_SHUTDOWN                   0x0011
#define ERROR_TO_REG_PTIO_CANCEL_FAILED                     0x0012
#define ERROR_TO_REG_OOD_ISSUE                              0x0013
#define ERROR_TO_REG_IO_SIZE_64MB_METADATA		    0x0014
#define ERROR_TO_REG_BITMAP_DEVOBJ_NOT_FOUND                0x0015
#define ERROR_TO_REG_LEARN_PHYSICAL_IO_FAILURE              0x0016
#define ERROR_TO_REG_PRESHUTDOWN_BITMAP_FLUSH_FAILURE       0x0017
#define ERROR_TO_REG_UNCLEAN_SYS_BOOT                       0x0018
#define ERROR_TO_REG_UNSUPPORTED_IO                         0x0019
#define ERROR_TO_REG_MAX_ERROR ERROR_TO_REG_UNCLEAN_SYS_BOOT

#define EXTRA_PROTECTED_VOLUME		4096 * 10
#define INITIAL_BUFSZ_FOR_VOL_LIST	4096 * 500

/* Macros to denote clean/unclean shutdown */
#define UNCLEAN_SHUTDOWN 0
#define CLEAN_SHUTDOWN 1

#ifdef INM_LINUX
#include <linux/version.h>
#if (defined(redhat) && (DISTRO_VER==5) && (UPDATE>=4))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
typedef struct address_space_operations inm_address_space_operations_t;
#else
typedef struct address_space_operations_ext inm_address_space_operations_t;
#endif
#else
#ifdef INM_RECUSIVE_ADSPC 
typedef struct address_space inm_address_space_operations_t;
#else
typedef struct address_space_operations inm_address_space_operations_t;
#endif
#endif
#endif

enum TagStatus
{
	STATUS_PENDING = 1,	/* Tag is pending */
	STATUS_COMMITED,	/* Tag is commited by drainer */
	STATUS_DELETED,		/* Tag is deleted due to stop filtering or clear diffs */
	STATUS_DROPPED,		/* Tag is dropped due to write in bitmap file */
	STATUS_FAILURE,		/* Some error occured while adding tag */
};

typedef struct _inm_resync_notify_info {
	inm_u64_t rsin_out_of_sync_count;
	inm_u64_t rsin_resync_err_code;
	inm_u64_t rsin_out_of_sync_time_stamp;
	inm_u64_t rsin_flag;
	inm_u64_t rsin_out_of_sync_err_status;
	inm_s32_t timeout_in_sec;
	char rsin_src_scsi_id[INM_MAX_SCSI_ID_SIZE];
	char rsin_err_string_resync[UDIRTY_BLOCK_MAX_ERROR_STRING_SIZE];
	eMirrorConfErrors_t rstatus;
} inm_resync_notify_info_t;

#define INM_SET_RESYNC_REQ_FLAG     0x1
#define INM_RESET_RESYNC_REQ_FLAG   0x2

/* driver states */
#define INM_ALLOW_UNLOAD	0x00000001
#define INM_PREVENT_UNLOAD	0x00000002
#define INM_FAILED_UNLOAD	0x00000004
#define INM_ALL_FREE		255

/* Wait in seconds to drain outstanding IOs */
#define INM_WAIT_UNLOAD     10

#define ADD_AT_LUN_GLOBAL_LIST 1
#define DEL_AT_LUN_GLOBAL_LIST 2

typedef struct _VOLUME_STATS_ADDITIONAL_INFO
{
	VOLUME_GUID VolumeGuid;
	inm_u64_t ullTotalChangesPending;
	inm_u64_t ullOldestChangeTimeStamp;
	inm_u64_t ullDriverCurrentTimeStamp;
}VOLUME_STATS_ADDITIONAL_INFO, *PVOLUME_STATS_ADDITIONAL_INFO;

/* structure for latency distribution */
#define INM_LATENCY_DIST_BKT_CAPACITY   12
#define INM_LATENCY_LOG_CAPACITY        12

typedef struct __VOLUME_LATENCY_STATS
{
	VOLUME_GUID	VolumeGuid;
	    inm_u64_t       s2dbret_bkts[INM_LATENCY_DIST_BKT_CAPACITY];
	    inm_u32_t       s2dbret_freq[INM_LATENCY_DIST_BKT_CAPACITY];
	    inm_u32_t       s2dbret_nr_avail_bkts;
	    inm_u64_t       s2dbret_log_buf[INM_LATENCY_LOG_CAPACITY];
	    inm_u64_t       s2dbret_log_min;
	    inm_u64_t       s2dbret_log_max;

	    inm_u64_t       s2dbwait_notify_bkts[INM_LATENCY_DIST_BKT_CAPACITY];
	    inm_u32_t       s2dbwait_notify_freq[INM_LATENCY_DIST_BKT_CAPACITY];
	    inm_u32_t       s2dbwait_notify_nr_avail_bkts;
	    inm_u64_t       s2dbwait_notify_log_buf[INM_LATENCY_LOG_CAPACITY];
	    inm_u64_t       s2dbwait_notify_log_min;
	    inm_u64_t       s2dbwait_notify_log_max;

	    inm_u64_t       s2dbcommit_bkts[INM_LATENCY_DIST_BKT_CAPACITY];
	    inm_u32_t       s2dbcommit_freq[INM_LATENCY_DIST_BKT_CAPACITY];
	    inm_u32_t       s2dbcommit_nr_avail_bkts;
	    inm_u64_t       s2dbcommit_log_buf[INM_LATENCY_LOG_CAPACITY];
	    inm_u64_t       s2dbcommit_log_min;
	    inm_u64_t       s2dbcommit_log_max;
} VOLUME_LATENCY_STATS;

typedef struct __VOLUME_BMAP_STATS 
{
	VOLUME_GUID	VolumeGuid;
	inm_u64_t	bmap_gran;
	inm_u64_t	bmap_data_sz;
	inm_u32_t	nr_dbs;
} VOLUME_BMAP_STATS;

#define INM_DEBUG_ONLY                  0x1
#define INM_IDEBUG                      0x2
#define INM_IDEBUG_BMAP                 0x4
#define INM_IDEBUG_MIRROR               0x8
#define INM_IDEBUG_MIRROR_IO            0x10
#define INM_IDEBUG_META                 0x20
#define INM_IDEBUG_REF                  0x40
#define INM_IDEBUG_IO                   0x80

#define IS_DBG_ENABLED(verbosity, flag) ((verbosity & flag) == flag)
#ifndef  FLT_VERBOSITY
#define FLT_VERBOSITY
extern inm_u32_t inm_verbosity;
#endif

typedef struct _inm_user_max_xfer_sz{
	inm_u32_t mxs_flag;
	char mxs_devname[INM_GUID_LEN_MAX];
	inm_u32_t mxs_max_xfer_sz;
}inm_user_max_xfer_sz_t;

enum common_prams_idx {
	DataPoolSize,
	DefaultLogDirectory,
	FreeThresholdForFileWrite,
	CommonVolumeThresholdForFileWrite,
	DirtyBlockHighWaterMarkServiceNotStarted,
	DirtyBlockLowWaterMarkServiceRunning,
	DirtyBlockHighWaterMarkServiceRunning,
	DirtyBlockHighWaterMarkServiceShutdown,
	DirtyBlocksToPurgeWhenHighWaterMarkIsReached,
	MaximumBitmapBufferMemory,
	Bitmap512KGranularitySize,
	CommonVolumeDataFiltering,
	CommonVolumeDataFilteringForNewVolumes,
	CommonVolumeDataFiles,
	CommonVolumeDataFilesForNewVolumes,
	CommonVolumeDataToDiskLimitInMB,
	CommonVolumeDataNotifyLimit,
	SequenceNumber,
	MaxDataSizeForDataModeDirtyBlock,
	CommonVolumeResDataPoolSize,
	MaxDataPoolSize,
	CleanShutdown,
	MaxCoalescedMetaDataChangeSize,
	PercentChangeDataPoolSize,
	TimeReorgDataPoolSec,
	TimeReorgDataPoolFactor,
	VacpIObarrierTimeout,
	FsFreezeTimeout,
	VacpAppTagCommitTimeout
};

enum volume_params_idx {
	VolumeFilteringDisabled,
	VolumeBitmapReadDisabled,
	VolumeBitmapWriteDisabled,
	VolumeDataFiltering,
	VolumeDataFiles,
	VolumeDataToDiskLimitInMB,
	VolumeDataNotifyLimitInKB,
	VolumeDataLogDirectory,
	VolumeBitmapGranularity,
	VolumeResyncRequired,
	VolumeOutOfSyncErrorCode,
	VolumeOutOfSyncErrorStatus,
	VolumeOutOfSyncCount,
	VolumeOutOfSyncTimestamp,
	VolumeOutOfSyncErrorDescription,
	VolumeFilterDevType,
	VolumeNblks,
	VolumeBsize,
	VolumeResDataPoolSize,
	VolumeMountPoint,
	VolumePrevEndTimeStamp,
	VolumePrevEndSequenceNumber,
	VolumePrevSequenceIDforSplitIO,
	VolumePTPath,
	VolumeATDirectRead,
	VolumeMirrorSourceList,
	VolumeMirrorDestinationList,
	VolumeMirrorDestinationScsiID,
	VolumeDiskFlags,
	VolumeIsDeviceMultipath,
	VolumeDeviceVendor,
	VolumeDevStartOff,
	VolumePTpathList,
	VolumePerfOptimization,
	VolumeMaxXferSz,
	VolumeRpoTimeStamp,
	VolumeDrainBlocked
};

#define	GET_ATTR	1
#define	SET_ATTR	2

#define GET_SET_ATTR_BUF_LEN	(0x2000)

#define REPLICATION_STATE_DIFF_SYNC_THROTTLED 0x1
#define REPLICATION_STATES_SUPPORTED          (REPLICATION_STATE_DIFF_SYNC_THROTTLED)

typedef struct _REPLICATION_STATE{
	VOLUME_GUID   DeviceId;
	inm_u64_t     ulFlags;
	inm_u64_t     Timestamp;
	char          Data[1];
}replication_state_t;

typedef enum _svc_state {
	SERVICE_UNITIALIZED = 0x00,
	SERVICE_NOTSTARTED  = 0x01,
	SERVICE_RUNNING     = 0x02,
	SERVICE_SHUTDOWN    = 0x03,
	MAX_SERVICE_STATES  = 0x04,
} svc_state_t;
	
typedef enum _etDriverMode {
	UninitializedMode = 0,
	NoRebootMode,
	RebootMode
} etDriverMode;

#define VOLUME_STATS_DATA_MAJOR_VERSION         0x0003
#define VOLUME_STATS_DATA_MINOR_VERSION         0x0000

typedef struct _VOLUME_STATS_DATA {
	    unsigned short          usMajorVersion;
	    unsigned short          usMinorVersion;
	    unsigned long           ulVolumesReturned;
	    unsigned long           ulNonPagedMemoryLimitInMB;
	    unsigned long           LockedDataBlockCounter;
	    unsigned long           ulTotalVolumes;
	    unsigned short          ulNumProtectedDisk;
	    svc_state_t             eServiceState;
	    etDriverMode            eDiskFilterMode;
	    char                    LastShutdownMarker;
	    int                     PersistentRegistryCreated;
	    unsigned long           ulDriverFlags;
	    long                    ulCommonBootCounter;
	    unsigned long long      ullDataPoolSizeAllocated;
	    unsigned long long      ullPersistedTimeStampAfterBoot;
	    unsigned long long      ullPersistedSequenceNumberAfterBoot;
} VOLUME_STATS_DATA;

typedef struct _LARGE_INTEGER {
	long long QuadPart;
} LARGE_INTEGER;

typedef struct _ULARGE_INTEGER {
	unsigned long long QuadPart;
} ULARGE_INTEGER;

typedef struct _VOLUME_STATS_V2 {
	char                VolumeGUID[GUID_SIZE_IN_CHARS];
	unsigned long long  ullDataPoolSize;
	LARGE_INTEGER       liDriverLoadTime;
	long long           llTimeJumpDetectedTS;
	long long           llTimeJumpedTS;
	LARGE_INTEGER       liLastS2StartTime;
	LARGE_INTEGER       liLastS2StopTime;
	LARGE_INTEGER       liLastAgentStartTime;
	LARGE_INTEGER       liLastAgentStopTime;
	LARGE_INTEGER       liLastTagReq;
	LARGE_INTEGER       liStopFilteringAllTimeStamp;

	/* per disk stats */
	unsigned long long  ullTotalTrackedBytes;
	ULARGE_INTEGER      ulVolumeSize;
	unsigned long       ulVolumeFlags;
	LARGE_INTEGER       liVolumeContextCreationTS;
	LARGE_INTEGER       liStartFilteringTimeStamp;
	LARGE_INTEGER       liStartFilteringTimeStampByUser;
	LARGE_INTEGER       liStopFilteringTimeStamp;
	LARGE_INTEGER       liStopFilteringTimestampByUser;
	LARGE_INTEGER       liClearDiffsTimeStamp;
	LARGE_INTEGER       liCommitDBTimeStamp;
	LARGE_INTEGER       liGetDBTimeStamp;
} VOLUME_STATS_V2;

typedef struct _TELEMETRY_VOL_STATS
{
	VOLUME_STATS_DATA  drv_stats;
	VOLUME_STATS_V2    vol_stats;
} TELEMETRY_VOL_STATS;

enum LCW_OP {
	LCW_OP_NONE,
	LCW_OP_BMAP_MAP_FILE,
	LCW_OP_BMAP_SWITCH_RAWIO,
	LCW_OP_BMAP_CLOSE,
	LCW_OP_BMAP_OPEN,
	LCW_OP_MAP_FILE,
	LCW_OP_MAX
};

typedef struct lcw_op
{
	enum LCW_OP lo_op;
	VOLUME_GUID lo_name;
} lcw_op_t;

typedef enum {
	TAG_STATUS_UNINITALIZED,
	TAG_STATUS_INPUT_VERIFIED,
	TAG_STATUS_TAG_REQUEST_NOT_RECEIVED,
	TAG_STATUS_INSERTED,
	TAG_STATUS_INSERTION_FAILED,
	TAG_STATUS_DROPPED,
	TAG_STATUS_COMMITTED,
	TAG_STATUS_UNKNOWN
}TAG_DEVICE_COMMIT_STATUS;

typedef enum {
	DEVICE_STATUS_SUCCESS = 0,
	DEVICE_STATUS_NON_WRITE_ORDER_STATE,
	DEVICE_STATUS_FILTERING_STOPPED,
	DEVICE_STATUS_REMOVED,
	DEVICE_STATUS_DISKID_CONFLICT,
	DEVICE_STATUS_NOT_FOUND,
	DEVICE_STATUS_DRAIN_BLOCK_FAILED,
	DEVICE_STATUS_DRAIN_ALREADY_BLOCKED,
	DEVICE_STATUS_UNKNOWN
}DEVICE_STATUS;

typedef struct _TAG_COMMIT_STATUS {
	VOLUME_GUID              DeviceId;
	DEVICE_STATUS            Status;
	TAG_DEVICE_COMMIT_STATUS TagStatus;
	inm_u64_t                TagInsertionTime;
	inm_u64_t                TagSequenceNumber;
	DEVICE_CXFAILURE_STATS   DeviceCxStats;
} TAG_COMMIT_STATUS, *PTAG_COMMIT_STATUS;

#define TAG_COMMIT_NOTIFY_BLOCK_DRAIN_FLAG      0x00000001

typedef struct _TAG_COMMIT_NOTIFY_INPUT {
	char               TagGUID[GUID_LEN];
	inm_u64_t          ulFlags;
	inm_u64_t          ulNumDisks;
	VOLUME_GUID        DeviceId[1];
} TAG_COMMIT_NOTIFY_INPUT, *PTAG_COMMIT_NOTIFY_INPUT;

typedef struct _TAG_COMMIT_NOTIFY_OUTPUT{
	char               TagGUID[GUID_LEN];
	inm_u64_t          ulFlags;
	VM_CXFAILURE_STATS vmCxStatus;
	inm_u64_t          ulNumDisks;
	TAG_COMMIT_STATUS  TagStatus[1];
} TAG_COMMIT_NOTIFY_OUTPUT, *PTAG_COMMIT_NOTIFY_OUTPUT;

typedef struct _SET_DRAIN_STATE_INPUT {
	inm_u64_t   ulFlags;
	inm_u64_t   ulNumDisks;
	VOLUME_GUID DeviceId[1];
} SET_DRAIN_STATE_INPUT, *PSET_DRAIN_STATE_INPUT;

typedef enum {
	SET_DRAIN_STATUS_SUCCESS = 0,
	SET_DRAIN_STATUS_DEVICE_NOT_FOUND,
	SET_DRAIN_STATUS_PERSISTENCE_FAILED,
	SET_DRAIN_STATUS_UNKNOWN
} ERROR_SET_DRAIN_STATUS;

typedef struct _SET_DRAIN_STATUS {
	VOLUME_GUID             DeviceId;
	inm_u64_t               ulFlags;
	ERROR_SET_DRAIN_STATUS  Status;
	inm_u64_t               ulInternalError;
} SET_DRAIN_STATUS, *PSET_DRAIN_STATUS;

typedef struct _SET_DRAIN_STATE_OUTPUT {
	inm_u64_t           ulFlags;
	inm_u64_t           ulNumDisks;
	SET_DRAIN_STATUS    diskStatus[1];
} SET_DRAIN_STATE_OUTPUT, *PSET_DRAIN_STATE_OUTPUT;

typedef struct _GET_DISK_STATE_INPUT {
	inm_u64_t   ulNumDisks;
	VOLUME_GUID DeviceId[1];
} GET_DISK_STATE_INPUT, *PGET_DISK_STATE_INPUT;

typedef struct _DISK_STATE {
	VOLUME_GUID DeviceId;
	inm_u64_t   Status;
	inm_u64_t   ulFlags;
} DISK_STATE;

#define DISK_STATE_FILTERED          0x00000001
#define DISK_STATE_DRAIN_BLOCKED     0x00000002

typedef struct _GET_DISK_STATE_OUTPUT {
	inm_u64_t   ulSupportedFlags;
	inm_u64_t   ulNumDisks;
	DISK_STATE  diskState[1];
} GET_DISK_STATE_OUTPUT, *PGET_DISK_STATE_OUTPUT;

typedef struct _MODIFY_PERSISTENT_DEVICE_NAME_INPUT {
	VOLUME_GUID DevName;
	VOLUME_GUID OldPName;
	VOLUME_GUID NewPName;
} MODIFY_PERSISTENT_DEVICE_NAME_INPUT, *PMODIFY_PERSISTENT_DEVICE_NAME_INPUT;

#endif /* ifndef INVOLFLT_H */
