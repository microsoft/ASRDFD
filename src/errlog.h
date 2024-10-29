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

#ifndef _INMAGE_ERRLOG_H
#define _INMAGE_ERRLOG_H

/*
 * MessageId: LINVOLFLT_ERR_NO_NPAGED_POOL_FOR_DIRTYBLOCKS
 *
 * MessageText:
 *
 *  Not enough memory was available to store changes to volume %2 (GUID = %3). This usually indicates
 *  a shortage of non-paged pool memory.
 */
#define LINVOLFLT_ERR_NO_NPAGED_POOL_FOR_DIRTYBLOCKS ((inm_u32_t)0xE1120001)

/*
 * MessageId: LINVOLFLT_ERR_VOLUME_WRITE_PAST_EOV
 *
 * MessageText:
 *
 *  A write attempt past the end of the volume was detected on volume %2 (GUID = %3). This may
 *  indicate the volume has dynamically been grown. 
 */
#define LINVOLFLT_ERR_VOLUME_WRITE_PAST_EOV ((inm_u32_t)0xA1120002)

/*
 * MessageId: LINVOLFLT_ERR_NO_MEMORY
 *
 * MessageText:
 *
 *  Not enough memory was available to perform an operation, as a result replication on
 *  volume %2 (GUID = %3) has failed.
 */
#define LINVOLFLT_ERR_NO_MEMORY           ((inm_u32_t)0xE112000B)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_CANT_OPEN
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) could not be opened.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_CANT_OPEN ((inm_u32_t)0xE112000C)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_CANT_UPDATE_HEADER
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) could not be written to.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_CANT_UPDATE_HEADER ((inm_u32_t)0xE112000D)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_CANT_READ
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) could not be read. Check for
 *  disk errors on the device.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_CANT_READ ((inm_u32_t)0xE112000E)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_LOG_DAMAGED
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) is damaged and could not
 *  be automatically repaired.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_LOG_DAMAGED ((inm_u32_t)0xE112000F)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_CANT_APPLY_SHUTDOWN_CHANGES
 *
 * MessageText:
 *
 *  Changes on volume %2 (GUID = %3)that occured at the previous system shutdown could not be merged with
 *  current changes.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_CANT_APPLY_SHUTDOWN_CHANGES ((inm_u32_t)0xE1120010)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_CREATED
 *
 * MessageText:
 *
 *  A new file used to store change information for volume %2 (GUID = %3) is created.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_CREATED ((inm_u32_t)0x61120011)

/*
 * MessageId: LINVOLFLT_ERR_LOST_SYNC_SYSTEM_CRASHED
 *
 * MessageText:
 *
 *  The system crashed or experienced a non-controlled shutdown. Replication sync on
 *  volume %2 (GUID = %3) will need to be reestablished.
 */
#define LINVOLFLT_ERR_LOST_SYNC_SYSTEM_CRASHED ((inm_u32_t)0xA1120012)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_NAME_ERROR
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) could not be opened
 *  because of a naming problem.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_NAME_ERROR ((inm_u32_t)0xE1120013)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_WRITE_ERROR
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) could not be written to.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_WRITE_ERROR ((inm_u32_t)0xE1120014)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_CANT_INIT
 *
 * MessageText:
 *
 *  The file used to store change information for  volume %2 (GUID = %3) could not be initialized.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_CANT_INIT ((inm_u32_t)0xE1120015)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_LOG_FIXED
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) was repaired, but the volume
 *  needs to be resynchronized.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_LOG_FIXED ((inm_u32_t)0xA1120016)

/*
 * MessageId: LINVOLFLT_ERR_TOO_MANY_LAST_CHANCE
 *
 * MessageText:
 *
 *  The file used to store change information for volume %2 (GUID = %3) did not have sufficent reserved
 *  space to store all changes at system shutdown.
 */
#define LINVOLFLT_ERR_TOO_MANY_LAST_CHANCE ((inm_u32_t)0xE1120017)

/*
 * MessageId: LINVOLFLT_ERR_IN_SYNC
 *
 * MessageText:
 *
 *  The replication on volume %2 (GUID = %3) has resumed correctly.
 */
#define LINVOLFLT_ERR_IN_SYNC             ((inm_u32_t)0x61120018)

/*
 * MessageId: LINVOLFLT_ERR_FINAL_HEADER_VALIDATE_FAILED
 *
 * MessageText:
 *
 *  The final write to store change information for volume %2 (GUID = %3) failed header validation.
 */
#define LINVOLFLT_ERR_FINAL_HEADER_VALIDATE_FAILED ((inm_u32_t)0xE1120019)

/*
 * MessageId: LINVOLFLT_ERR_FINAL_HEADER_DIRECT_WRITE_FAILED
 *
 * MessageText:
 *
 *  The final direct write to store change information for volume %2 (GUID = %3) failed.
 */
#define LINVOLFLT_ERR_FINAL_HEADER_DIRECT_WRITE_FAILED ((inm_u32_t)0xE1120020)

/*
 * MessageId: LINVOLFLT_ERR_FINAL_HEADER_FS_WRITE_FAILED
 *
 * MessageText:
 *
 *  The final file system write to store change information for volume %2 (GUID = %3) failed.
 */
#define LINVOLFLT_ERR_FINAL_HEADER_FS_WRITE_FAILED ((inm_u32_t)0xE1120021)

/*
 * MessageId: LINVOLFLT_ERR_FINAL_HEADER_READ_FAILED
 *
 * MessageText:
 *
 *  The final direct read to store change information for volume %2 (GUID = %3) failed.
 */
#define LINVOLFLT_ERR_FINAL_HEADER_READ_FAILED ((inm_u32_t)0xE1120022)

/*
 * MessageId: LINVOLFLT_ERR_DELETE_BITMAP_FILE_NO_NAME
 *
 * MessageText:
 *
 *  Deleting the file used to store changes on volume %2 (GUID = %3) failed because the filename was not set.
 */
#define LINVOLFLT_ERR_DELETE_BITMAP_FILE_NO_NAME ((inm_u32_t)0xE1120023)

/*
 * MessageId: LINVOLFLT_ERR_BITMAP_FILE_EXCEEDED_MEMORY_LIMIT
 *
 * MessageText:
 *
 *  The memory limit for storing changes on volume %2 (GUID = %3) has exceeded. Increase memory limit or increase
 *  change granularity using appropriate registry entries.
 */
#define LINVOLFLT_ERR_BITMAP_FILE_EXCEEDED_MEMORY_LIMIT ((inm_u32_t)0xE1120024)

/*
 * MessageId: LINVOLFLT_ERR_VOLUME_SIZE_SEARCH_FAILED
 *
 * MessageText:
 *
 *  The driver was unable to determine the correct size of volume %2 (GUID = %3) using a last sector search.
 */
#define LINVOLFLT_ERR_VOLUME_SIZE_SEARCH_FAILED ((inm_u32_t)0xE1120025)

/*
 * MessageId: LINVOLFLT_ERR_VOLUME_GET_LENGTH_INFO_FAILED
 *
 * MessageText:
 *
 *  The driver was unable to determine the correct size of volume %2 (GUID = %3) using IOCTL_DISK_GET_LENGTH_INFO.
 */
#define LINVOLFLT_ERR_VOLUME_GET_LENGTH_INFO_FAILED ((inm_u32_t)0xE1120026)

/*
 * MessageId: LINVOLFLT_ERR_TOO_MANY_EVENT_LOG_EVENTS
 *
 * MessageText:
 *
 *  The driver has written too many events to the system event log recently. Events will be discarded for 
 *  the next time interval.
 */
#define LINVOLFLT_ERR_TOO_MANY_EVENT_LOG_EVENTS ((inm_u32_t)0xE1120027)

/*
 * MessageId: LINVOLFLT_WARNING_FIRST_FAILURE_TO_OPEN_BITMAP
 *
 * MessageText:
 *
 *  The driver failed to open bitmap file for volume %2 (GUID = %3) on its first attempt.
 */
#define LINVOLFLT_WARNING_FIRST_FAILURE_TO_OPEN_BITMAP ((inm_u32_t)0xA1120028)

/*
 * MessageId: LINVOLFLT_SUCCESS_OPEN_BITMAP_AFTER_RETRY
 *
 * MessageText:
 *
 *  The driver succeeded to open bitmap file for volume %2 (GUID = %3) after %4 retries. 
 *  TimeInterval between first failure and success to open bitmap is %5 seconds.
 */
#define LINVOLFLT_SUCCESS_OPEN_BITMAP_AFTER_RETRY ((inm_u32_t)0x21120029)

/*
 * MessageId: LINVOLFLT_INFO_OPEN_BITMAP_CALLED_PRIOR_TO_OBTAINING_GUID
 *
 * MessageText:
 *
 *  The driver is opening bitmap for volume prior to symbolic link with GUID is created.
 */
#define LINVOLFLT_INFO_OPEN_BITMAP_CALLED_PRIOR_TO_OBTAINING_GUID ((inm_u32_t)0x61120030)

/*
 * MessageId: LINVOLFLT_ERR_FAILED_TO_ALLOCATE_DATA_POOL
 *
 * MessageText:
 *
 *  The driver has failed to allocate memory required for data pool.
 */
#define LINVOLFLT_ERR_FAILED_TO_ALLOCATE_DATA_POOL ((inm_u32_t)0xE1120031)

/*
 * MessageId: LINVOLFLT_THREAD_SHUTDOWN_IN_PROGRESS
 *
 * MessageText:
 *
 *  Thread shutdown is in progess.
 */
#define LINVOLFLT_THREAD_SHUTDOWN_IN_PROGRESS ((inm_u32_t)0xE1120032)

/*
 * MessageId: LINVOLFLT_DATA_FILE_OPEN_FAILED
 *
 * MessageText:
 *
 *  Data file open failed for volume %2 (GUID = %3) with status %4
 */
#define LINVOLFLT_DATA_FILE_OPEN_FAILED   ((inm_u32_t)0xE1120033)

/*
 * MessageId: LINVOLFLT_WRITE_TO_DATA_FILE_FAILED
 *
 * MessageText:
 *
 *  Write to data file %4 for volume %2 (GUID = %3) failed with status %5
 */
#define LINVOLFLT_WRITE_TO_DATA_FILE_FAILED ((inm_u32_t)0xE1120034)

/*
 * MessageId: LINVOLFLT_WARNING_STATUS_NO_MEMORY
 *
 * MessageText:
 *
 *  Allocation of memory of size %4 type %2 failed in file %3 line %5
 */
#define LINVOLFLT_WARNING_STATUS_NO_MEMORY ((inm_u32_t)0xA1120035)

/*
 * MessageId: LINVOLFLT_DELETE_FILE_FAILED
 *
 * MessageText:
 *
 *  Deletion of data file for volume %2 (GUID = %3) failed with  error %4
 */
#define LINVOLFLT_DELETE_FILE_FAILED      ((inm_u32_t)0xA1120036)


#endif /* _INMAGE_ERRLOG_H */
