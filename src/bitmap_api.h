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

#ifndef _INMAGE_BITMAP_API_H
#define _INMAGE_BITMAP_API_H

#include "involflt-common.h"
#include "change-node.h"
#include "iobuffer.h"

/* thse are flags used in the bitmap file header */
#define BITMAP_FILE_VERSION1              (0x00010004)
#define BITMAP_FILE_VERSION2              (0x0001000C)
#define BITMAP_FILE_VERSION               BITMAP_FILE_VERSION2
#define BITMAP_FILE_ENDIAN_FLAG           (0x000000FF)

#define MAX_WRITE_GROUPS_IN_BITMAP_HEADER (31)
#define MAX_CHANGES_IN_WRITE_GROUP        (64)
#define DISK_SECTOR_SIZE                  (512)
#define HEADER_CHECKSUM_SIZE              (16)
#define HEADER_CHECKSUM_DATA_SIZE (sizeof(bitmap_header_t) - \
						HEADER_CHECKSUM_SIZE)
#define LOG_HEADER_SIZE ((DISK_SECTOR_SIZE * \
		MAX_WRITE_GROUPS_IN_BITMAP_HEADER) + DISK_SECTOR_SIZE)
#define LOG_HEADER_OFFSET                 (LOG_HEADER_SIZE)

struct _volume_bitmap;
struct _target_context;

/** log header 
 *   +--------------------------------------------------------------------+
 *   | validation_checksum | endian | header_size | version | data_offset |
 *   +--------------------------------------------------------------------+
 *   | bitmap_offset | bitmap_size | bitmap_granularity                   |
 *   +--------------------------------------------------------------------+
 *   | volume_size | recovery_state | last_chance_changes | boot_cycles   |
 *   + -------------------------------------------------------------------+
 *   | changes_lost | resync_required | resync_errcode | resync_errstatus |
 *   +--------------------------------------------------------------------+
 */
 
typedef struct _logheader_tag
{
	inm_u8_t     validation_checksum[HEADER_CHECKSUM_SIZE];
	inm_u32_t    endian;
	inm_u32_t    header_size;
	inm_u32_t    version;
	inm_u32_t    data_offset;
	inm_u64_t    bitmap_offset;
	inm_u64_t    bitmap_size;
	inm_u64_t    bitmap_granularity;
	int64_t     volume_size;
	inm_u32_t    recovery_state;
	inm_u32_t    last_chance_changes;
	inm_u32_t    boot_cycles;
	inm_u32_t    changes_lost;
	/* V2 */
	inm_u32_t    resync_required;
	inm_u32_t    resync_errcode;
	inm_u64_t    resync_errstatus;
} logheader_t;

#define BITMAP_HDR1_SIZE    offsetof(logheader_t, resync_required)
#define BITMAP_HDR2_SIZE    sizeof(logheader_t)

/* recovery states */
#define BITMAP_LOG_RECOVERY_STATE_UNINITIALIZED   0
#define BITMAP_LOG_RECOVERY_STATE_CLEAN_SHUTDOWN  1
#define BITMAP_LOG_RECOVERY_STATE_DIRTY_SHUTDOWN  2
#define BITMAP_LOG_RECOVERY_STATE_LOST_SYNC       3

typedef struct _last_chance_changes_tag
{
	union 
	{
	inm_u64_t length_offset_pair[MAX_CHANGES_IN_WRITE_GROUP];
	inm_u8_t sector_fill[DISK_SECTOR_SIZE];
	}un;

} last_chance_changes_t;

/* Last two bytes are marked 00 to make len = 0 for length_offset_pair */
#define BITMAP_LCW_SIGNATURE_SUFFIX 0x57434C000000 /* LCW00 */
#define BITMAP_LCW_SIGNATURE_PREFIX_SZ 3 /* bytes */

/** Bitmap header 
 *   +----------------------------------+
 *   | log header  		        |
 *   +----------------------------------+
 *   | length and offset pair group 1 --+-----------+
 *   +----------------------------------+           |
 *   | length and offset pair group 2 --+------+    |
 *   +----------------------------------+      |    |
 *   |  ...                             |      |    |
 *   +----------------------------------+      |    |
 *   | length and offset pair group 31--+--+   |    |
 *   +----------------------------------+  |   |    |
 *                                         |   |    |
 *    +------------------------------------+   |    |
 *    |   +------------------------------------+    V
 *    |   |         +---------------------------------------------------------------------+
 *    |   |         | length_offset_pair1 | length_offset_pair2 | .. length_offset_pair64 |
 *    |   |         +---------------------------------------------------------------------+
 *    |   |
 *    |   |     +---------------------------------------------------------------------+
 *    |   + --->| length_offset_pair1 | length_offset_pair2 | .. length_offset_pair64 |
 *    |         +---------------------------------------------------------------------+
 *    |        ...
 *    |        ...
 *    |        ...
 *    |    +---------------------------------------------------------------------+
 *    +--->| length_offset_pair1 | length_offset_pair2 | .. length_offset_pair64 |
 *         +---------------------------------------------------------------------+
 */

typedef struct _bitmap_header_tag
{
	union {
	logheader_t    header;
	inm_u8_t        sector_fill[DISK_SECTOR_SIZE];
	}un;

	last_chance_changes_t  change_groups[MAX_WRITE_GROUPS_IN_BITMAP_HEADER];
} bitmap_header_t;



/*   Bitrun data structure
 * 
 *   +----------------------------------+
 *   | final_status | nbr_runs_processed|
 *   +----------------------------------+
 *   | context 1 | context 2            |
 *   +----------------------------------+
 *   |  completion_callback             |
 *   +----------------------------------+
 *   | # of runs (nbr_runs)             |
 *   +----------------------------------+
 *   | meta_page_list                   |
 *   +----------------------------------+         +-------------------+
 *   | disk change 1            --------+-------->| offset   | length |
 *   +----------------------------------+         +-------------------+
 *   | disk change 2            --------+--+
 *   +----------------------------------+  |      +-------------------+
 *   | ...                              |  +----->| offset   | length |
 *   +----------------------------------+         +-------------------+
 *   | disk change N            --------+--+          ...
 *   +----------------------------------+  |      +-------------------+
 *                                         +----->| offset   | length |
 *                                                +-------------------+
 */
struct _disk_chg;

typedef struct _bitruns_tag
{
	inm_u32_t    final_status;
	inm_u32_t    nbr_runs_processed;
	void        *context1;
	void        *context2;
	void        (*completion_callback)(struct _bitruns_tag *runs);
	inm_ull64_t    nbr_runs;
	struct inm_list_head meta_page_list;
	disk_chg_t  *runs;
} bitruns_t;


typedef struct _bitmap_api_tag
{
	inm_u64_t     volume_size;
	inm_u32_t     bitmap_granularity;
	inm_u32_t     bitmap_size_in_bytes;
	inm_u32_t     bitmap_offset;
	inm_u32_t     nr_bits_in_bitmap;

	inm_u32_t     bitmap_file_state;
	inm_sem_t    sem;

	segmented_bitmap_t *sb;
	fstream_t    *fs;
	fstream_segment_mapper_t *fssm;

	inm_u8_t      corrupt_bitmap;
	inm_u8_t      empyt_bitmap;
	inm_u8_t      new_bitmap;
	inm_u8_t      volume_insync;
	inm_s32_t     err_causing_outofsync;
	
	char          bitmap_filename[INM_NAME_MAX + 1];
	bitmap_header_t bitmap_header;
	iobuffer_t   *io_bitmap_header;

	inm_u32_t     segment_cache_limit;

	char          volume_name[INM_NAME_MAX + 1];
	inm_dev_t     bmapdev;
} bitmap_api_t;
	

/* bitmap file state */
#define BITMAP_FILE_STATE_UNINITIALIZED   0
#define BITMAP_FILE_STATE_OPENED          1
#define BITMAP_FILE_STATE_RAWIO           2
#define BITMAP_FILE_STATE_CLOSED          3
		
/* bitmap api operations */
bitmap_api_t *bitmap_api_ctr(void);

void bitmap_api_dtr(bitmap_api_t *bmap);

inm_s32_t initialize_bitmap_api(void);

inm_s32_t terminate_bitmap_api(void);

inm_s32_t bitmap_api_open(bitmap_api_t *bapi, struct _target_context *vcptr,
	inm_u32_t granularity, inm_u32_t offset, inm_u64_t volume_size,
	char *volume_name, inm_u32_t segment_cache_limit,
	inm_s32_t *detailed_status);

inm_s32_t bitmap_api_load_bitmap_header_from_filestream(bitmap_api_t *bapi,
		inm_s32_t *detailed_status, inm_s32_t was_created);

inm_s32_t bitmap_api_is_volume_insync(bitmap_api_t *bapi,
		inm_u8_t *volume_in_sync, inm_s32_t *out_of_sync_err_code);

inm_s32_t bitmap_api_is_bitmap_closed(bitmap_api_t *bapi);

inm_s32_t bitmap_api_close(bitmap_api_t *bapi, inm_s32_t *close_status);

inm_s32_t bitmap_api_setbits(bitmap_api_t *bapi, bitruns_t *bruns, 
		                     struct _volume_bitmap *vbmap);

inm_s32_t bitmap_api_clearbits(bitmap_api_t *bapi, bitruns_t *bruns);

inm_s32_t bitmap_api_get_first_runs(bitmap_api_t *bapi, bitruns_t *bruns);

inm_s32_t bitmap_api_get_next_runs(bitmap_api_t *bapi, bitruns_t *bruns);

inm_s32_t bitmap_api_clear_all_bits(bitmap_api_t *bapi);


inm_s32_t move_rawio_changes_to_bitmap(bitmap_api_t *bapi,
		inm_s32_t *inmage_open_status);

inm_s32_t bitmap_api_verify_bitmap_header(bitmap_header_t *bh);

inm_s32_t bitmap_api_init_bitmap_file(bitmap_api_t *bapi,
		inm_s32_t *inmage_status);

inm_s32_t bitmap_api_commit_bitmap_internal(bitmap_api_t *, int, inm_s32_t *);

inm_s32_t bitmap_api_fast_zero_bitmap(bitmap_api_t *bapi);

inm_s32_t bitmap_api_commit_header(bitmap_api_t *bapi,
	inm_s32_t verify_existing_hdr_for_raw_io, inm_s32_t *inmage_status);

void bitmap_api_calculate_hdr_integrity_checksums(bitmap_header_t *bhdr);

inm_s32_t bitmap_api_read_and_verify_bitmap_header(bitmap_api_t *bapi,
					     inm_s32_t *inmage_status);

inm_s32_t bitmap_api_verify_header(bitmap_api_t *bapi,
				bitmap_header_t *bheader);

inm_s32_t is_volume_in_sync(bitmap_api_t *bapi, inm_s32_t *vol_in_sync,
		      inm_s32_t *out_of_sync_err_code);

inm_s32_t bitmap_api_open_bitmap_stream(bitmap_api_t *bapi,
		struct _target_context *vcptr, inm_s32_t *detailed_status);

inm_s32_t is_bmaphdr_loaded(struct _volume_bitmap *vbmap);

struct bmap_bit_stats {
	unsigned long long      bbs_bmap_gran;
	int                     bbs_nr_prev_bits;
	int                     bbs_max_nr_bits_in_chg;
	int                     bbs_nr_dbs;
	unsigned long long      bbs_curr_db_sz;
	int                     bbs_nr_chgs_in_curr_db;
};

typedef struct bmap_bit_stats bmap_bit_stats_t;
inm_u64_t bitmap_api_get_dat_bytes_in_bitmap(bitmap_api_t *bapi,
						bmap_bit_stats_t *);
inm_s32_t bitmap_api_map_file_blocks(bitmap_api_t *, fstream_raw_hdl_t **);
inm_s32_t bitmap_api_switch_to_rawio_mode(bitmap_api_t *, inm_u64_t *);
void bitmap_api_set_volume_out_of_sync(bitmap_api_t *, inm_u64_t, inm_u32_t);

#endif /* _INMAGE_BITMAP_API_H */

