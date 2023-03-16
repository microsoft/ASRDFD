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
 * File       : change-node.h
 */

#ifndef LINVOLFLT_CHANGE_NODE_H
#define LINVOLFLT_CHANGE_NODE_H
#include "utils.h"
#include "osdep.h"
#include "telemetry-types.h"

extern const inm_s32_t sv_chg_sz;
extern const inm_s32_t sv_const_sz;

struct _target_context;
struct _wqentry;
struct _write_metadata_tag;

#define KDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE 0x00000001
#define KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE  0x00000002
#define KDIRTY_BLOCK_FLAG_END_OF_SPLIT_CHANGE   0x00000004
#define KDIRTY_BLOCK_FLAG_SPLIT_CHANGE_MASK     \
		(KDIRTY_BLOCK_FLAG_START_OF_SPLIT_CHANGE | \
		 KDIRTY_BLOCK_FLAG_PART_OF_SPLIT_CHANGE |  \
		 KDIRTY_BLOCK_FLAG_END_OF_SPLIT_CHANGE)
#define CHANGE_NODE_FLAGS_QUEUED_FOR_DATA_WRITE 0x00000008
#define CHANGE_NODE_FLAGS_ERROR_IN_DATA_WRITE   0x00000010
#define CHANGE_NODE_RESYNC_FLAG_SENT_TO_S2	0x00000020
#define CHANGE_NODE_DATA_STREAM_FINALIZED       0x00000040
#define CHANGE_NODE_DATA_PAGES_MAPPED_TO_S2     0x00000080
#define CHANGE_NODE_TAG_IN_STREAM               0x00000100
#define CHANGE_NODE_ORPHANED                    0x00000200
#define CHANGE_NODE_COMMITTED                   0x00000400
#define CHANGE_NODE_IN_NWO_CLOSED               0x00000800
#define CHANGE_NODE_DRAIN_BARRIER               0x00001000
#define CHANGE_NODE_FAILBACK_TAG                0x00002000
#define CHANGE_NODE_BLOCK_DRAIN_TAG             0x00004000
#define CHANGE_NODE_ALLOCED_FROM_POOL           0x00008000
#define KDIRTY_BLOCK_FLAG_PREPARED_FOR_USERMODE 0x80000000
#define MAX_KDIRTY_CHANGES                     (MAX_CHANGE_INFOS_PER_PAGE)
#define NOT_IN_IO_PATH                          0x0001
#define IN_IO_PATH                              0x0002
#define IN_IOCTL_PATH                           0x0004
#define IN_GET_DB_PATH                          0x0008
#define IN_BMAP_READ_PATH                       0x0010

/* Change node types */
typedef enum 
{
	NODE_SRC_UNDEFINED = 0,
	NODE_SRC_DATA = 1,
	NODE_SRC_METADATA = 2,
	NODE_SRC_TAGS = 3,
	NODE_SRC_DATAFILE = 4,
}node_type_t;


/* disk_chg_t is required to seperately for metadata, since it is possible that
 * we can store double entries in a single change node
 */
struct _disk_chg
{
	inm_u64_t offset;
	inm_u32_t length;
	inm_u32_t seqno_delta;
	inm_u32_t time_delta;
};

typedef struct _disk_chg  disk_chg_t;

typedef struct
{
	TIME_STAMP_TAG_V2 start_ts;
	TIME_STAMP_TAG_V2 end_ts;
	struct inm_list_head md_pg_list;    /* metadata page(inm_page_t) list */
	unsigned long *cur_md_pgp;          /* curr meta data page */
	inm_s32_t num_data_pgs;
	inm_s32_t bytes_changes;
	unsigned short change_idx;
} disk_chg_head_t;

#define MAX_CHANGE_INFOS_PER_PAGE (INM_PAGESZ/sizeof(disk_chg_t))

struct _target_context;

struct _change_node
{
	inm_atomic_t ref_cnt;
	node_type_t type;
	etWriteOrderState wostate;
	inm_s32_t flags;	
	inm_s64_t transaction_id;
	inm_s32_t mutext_initialized;
	/* This mutex protects the data pages shared
	 * between data mode and data file mode.
	 */
	inm_sem_t mutex;
	struct inm_list_head next;
	struct inm_list_head nwo_dmode_next;
	struct inm_list_head data_pg_head;
	data_page_t *cur_data_pg;
	inm_s32_t cur_data_pg_off;
	inm_s32_t data_free;	
	inm_addr_t mapped_address;
	inm_task_struct *mapped_thread;
	char *data_file_name;	
	inm_s32_t data_file_size;	
	inm_s32_t stream_len;
	disk_chg_head_t changes;
	struct _target_context *vcptr;
	/* for splitted change nodes */
	inm_u32_t seq_id_for_split_io;
	tag_guid_t *tag_guid;
	inm_s32_t tag_status_idx;
	inm_u64_t dbret_ts_in_usec;
	tag_history_t *cn_hist;
};

typedef struct _change_node change_node_t;

#define IS_CHANGE_NODE_DRAIN_BARRIER(c)                                     \
		((c)->flags & CHANGE_NODE_DRAIN_BARRIER)

#define get_drtd_len(node) (((change_node_t *)node)->changes.bytes_changes + \
		(((change_node_t *)node)->changes.change_idx * sv_chg_sz))
#define get_strm_len(node) (sv_const_sz + get_drtd_len(node))

#define CHANGE_NODE_IS_FIRST_DATA_PAGE(node, pg)                            \
	((void *)PG_ENTRY(pg->next.prev) == (void *)&node->data_pg_head)

#define CHANGE_NODE_IS_LAST_DATA_PAGE(node, pg)                            \
	((void *)PG_ENTRY(pg->next.next) == (void *)&node->data_pg_head)

#ifndef INM_AIX
static_inline void unmap_change_node(change_node_t *chg_node)
{
	inm_s32_t _len = 0, ret = 0;

	if(!chg_node->mapped_address || !chg_node->changes.num_data_pgs)
		return;

	_len = pages_to_bytes(chg_node->changes.num_data_pgs);
	ret = INM_DO_STREAM_UNMAP(chg_node->mapped_address, _len);
	if (ret) {
		err("INM_DO_STREAM_UNMAP() failed w/ err = %d", ret);
	} else {
		dbg("Unmapped user address 0x%p len %d\n",
			(unsigned long *)chg_node->mapped_address, _len);
	}
}
#endif

void cleanup_change_node(change_node_t *);

static_inline void ref_chg_node(change_node_t *node)
{
	INM_ATOMIC_INC(&node->ref_cnt);
}

static_inline void deref_chg_node(change_node_t *node)
{
	if(INM_ATOMIC_DEC_AND_TEST(&node->ref_cnt)) {
	cleanup_change_node(node);
	}
}

struct inm_writedata;

change_node_t *get_oldest_change_node(struct _target_context *, inm_s32_t *);
change_node_t *get_oldest_datamode_change_node(struct _target_context *);
change_node_t *get_change_node_to_update(struct _target_context *,
		struct inm_writedata *, inm_tsdelta_t *);
void cleanup_change_nodes(struct inm_list_head *, etTagStateTriggerReason);
void free_changenode_list(struct _target_context *ctxt,
					etTagStateTriggerReason);
void changenode_cleanup_routine(struct _wqentry *wqe);
void change_node_cleanup_worker_routine(struct _wqentry *wqe);
inm_s32_t queue_changenode_cleanup_worker_routine(change_node_t *cnode, 
						etTagStateTriggerReason);
inm_s32_t queue_worker_routine_for_change_node_cleanup(change_node_t *);
inm_s32_t init_change_node(change_node_t *, int, int, struct inm_writedata *);
change_node_t *get_change_node_to_save_as_file(struct _target_context *);
change_node_t *get_change_node_for_usertag(struct _target_context *,
				struct inm_writedata *, int commit_pending);
void commit_change_node(change_node_t *change_node);
inm_page_t *get_page_from_page_pool(int, int, struct inm_writedata *);
change_node_t *inm_alloc_change_node(struct inm_writedata *, unsigned);
void inm_free_change_node(change_node_t *);
void inm_free_metapage(inm_page_t *);
void update_change_node(change_node_t *chg_node,
		struct _write_metadata_tag *wmd, inm_tsdelta_t *tdp);
void inm_get_ts_and_seqno_deltas(change_node_t *, inm_tsdelta_t *);
void close_change_node(change_node_t *, inm_u32_t);
void print_chg_info(change_node_t *cnp, unsigned short idx);
inm_s32_t fill_udirty_block(struct _target_context *ctxt,
		UDIRTY_BLOCK_V2 *udirty, inm_devhandle_t *filp);
inm_s32_t perform_commit(struct _target_context *ctxt,
		COMMIT_TRANSACTION *commit, inm_devhandle_t *filp);
inm_s32_t commit_usertag(struct _target_context  *ctxt);
void revoke_usertag(struct _target_context *ctxt, int timedout);

static_inline data_page_t *
get_next_data_page(struct inm_list_head *node, inm_s32_t *pg_free,
	inm_s32_t *pg_offset, change_node_t *chg_node)
{
	if (node == &chg_node->data_pg_head)
		return NULL;
	*pg_free = INM_PAGESZ;
	*pg_offset = 0;
	return inm_list_entry(node, data_page_t, next);    
}
inm_s32_t verify_change_node_file(change_node_t *cnode);

void do_perf_changes(struct _target_context *tgt_ctxt, 
				change_node_t *recent_cnode, int path);
#if defined(SLES15SP3) || LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
void do_perf_changes_all(struct _target_context *tgt_ctxt, int path);
void move_chg_nodes_to_drainable_queue(void);
#endif

#endif
