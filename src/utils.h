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

#ifndef LINVOLFLT_UTILS_H
#define LINVOLFLT_UTILS_H

#include "involflt-common.h"

#define bytes_to_pages(bytes) (INM_PAGEALIGN(bytes) >> INM_PAGESHIFT)
#define pages_to_bytes(pages) ((pages) << INM_PAGESHIFT)

#define HUNDREDS_OF_NANOSEC_IN_SECOND 10000000LL
#define INMAGE_MAX_TS_SEQUENCE_NUMBER 0xFFFFFFFFFFFFFFFEULL
#define INM_IS_DSKPART(flag)          (!(flag & FULL_DISK_FLAG))
#define INM_IS_FULLDISK(flags)        (flags & (FULL_DISK_FLAG | FULL_DISK_PARTITION_FLAG))
#define INM_TGT_CTXT_LOCK             0x1
#define NO_SKIPS_AFTER_ERROR          100

#define inm_div_up(nr, sz)     (((nr) + (sz) - 1) / (sz))
struct _target_context;
struct _wqentry;

struct inm_ts_delta {
	inm_u32_t	td_time;
	inm_u32_t	td_seqno;
	inm_u32_t	td_oflow;	/* indicates either td_time or td_seqno overflow */
	char		reserved[4];
};

typedef struct inm_ts_delta inm_tsdelta_t;

static_inline void inm_list_splice_at_tail(struct inm_list_head *oldhead,
				       struct inm_list_head *newhead)
{
	 struct inm_list_head *nhlast = newhead->prev;
	 struct inm_list_head *ohfirst = oldhead->next;
	 struct inm_list_head *ohlast = oldhead->prev;

	 INM_BUG_ON(inm_list_empty(oldhead));

	 nhlast->next = ohfirst;
	 ohfirst->prev = nhlast;
	 ohlast->next = newhead;
	 newhead->prev = ohlast;
}

static_inline void list_change_head(struct inm_list_head *newhead,
				    struct inm_list_head *oldhead)
{
	 INM_INIT_LIST_HEAD(newhead);
	
	 if(inm_list_empty(oldhead))
		return;

	 newhead->next = oldhead->next;
	 newhead->prev = oldhead->prev;
	 newhead->prev->next = newhead;
	 newhead->next->prev = newhead;
}

struct host_dev_context;
void get_time_stamp(inm_u64_t *);
void get_time_stamp_tag(TIME_STAMP_TAG_V2 *);
inm_s32_t validate_path_for_file_name(char *);
inm_s32_t validate_pname(char *);
inm_s32_t get_volume_size(int64_t *vol_size, inm_s32_t *inmage_status);
inm_s32_t default_granularity_from_volume_size(inm_u64_t volume_size);
char *convert_path(char *path_name);
long inm_mkdir(char *dirname, inm_s32_t mode);
inm_u32_t inm_atoi(const char *);
inm_u64_t inm_atoi64(const char *);
inm_ull64_t inm_atoull64(const char *);
char *convert_str_to_path(char *str);
void chg_psname_as_inmageproc(char *psname);
inm_s32_t is_digit(const char *, int);
inm_s32_t get_path_memory(char **);
void free_path_memory(char **);
inm_device_t filter_dev_type_get(char *);
char * filter_guid_name_string_get(char *guid, char *name, inm_s32_t len);
inm_s32_t filter_dev_type_set(struct _target_context *, inm_device_t );
inm_s32_t read_value_from_file(char *, inm_s32_t *);
char * read_string_from_file(char *fname, char *buf, inm_s32_t len);
void inm_flush_ts_and_seqno(struct _wqentry *wqep);
inm_s32_t inm_flush_clean_shutdown(inm_u32_t);
void inm_flush_ts_and_seqno_to_file(inm_u32_t force);
void inm_close_ts_and_seqno_file(void);
inm_u32_t inm_comp_io_bkt_idx(inm_u32_t);
inm_s32_t write_vol_attr(struct _target_context * ctxt, const char *file_name, void *buf, inm_s32_t len);
void inm_free_host_dev_ctx(struct host_dev_context *hdcp);
inm_u32_t is_AT_blocked(void);
struct _tag_info* cnvt_tag_info2stream(struct _tag_info *, inm_s32_t, inm_u32_t);
struct _tag_info* cnvt_stream2tag_info(struct _tag_info *, inm_s32_t);
inm_s32_t inm_all_AT_cdb_send(struct _target_context *, unsigned char *, inm_u32_t, 
	                inm_s32_t, unsigned char *, inm_u32_t, inm_u32_t);
inm_s32_t inm_form_tag_cdb(struct _target_context *, tag_info_t *, inm_s32_t);
inm_s32_t inm_heartbeat_cdb(struct _target_context *);
inm_s32_t inm_erase_resync_info_from_persistent_store(char *);
void inm_get_tag_marker_guid(char *, inm_u32_t, char *, inm_u32_t);
#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 5)
int sprintf_s(char *buf, size_t bufsz, const char *fmt, ...);
#endif

#define GET_TIME_STAMP_IN_USEC(tsp) do { get_time_stamp(&tsp); INM_DO_DIV(tsp, 10);} while(0)
#endif
