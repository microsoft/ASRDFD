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

#ifndef _INM_LIST_H
#define _INM_LIST_H

#include <linux/list.h>

#define inm_list_head list_head
typedef struct list_head inm_list_head_t;


#define inm_container_of	container_of
#define INM_LIST_HEAD_INIT	LIST_HEAD_INIT
#define INM_INIT_LIST_HEAD	INIT_LIST_HEAD
#define INM_LIST_HEAD		LIST_HEAD
#define INIT_LIST_HEAD		INIT_LIST_HEAD
#define inm_list_add		list_add
#define inm_list_add_tail	list_add_tail
#define inm_list_del		list_del
#define inm_list_replace	list_replace
#define inm_list_replace_init	list_replace_init
#define inm_list_del_init	list_del_init
#define inm_list_move		list_move
#define inm_list_is_last	list_is_last
#define inm_list_empty		list_empty
#define inm_list_splice		list_splice
#define inm_list_splice_init	list_splice_init

static inline inm_list_head_t *
inm_list_first(inm_list_head_t *head)
{
	return head->next;
}

static inline inm_list_head_t *
inm_list_last(inm_list_head_t *head)
{
	return head->prev;
}

#define inm_list_entry			list_entry
#define inm_list_first_entry		list_first_entry
#define __inm_list_for_each		list_for_each
#define inm_list_for_each_safe		list_for_each_safe
#endif /* _INM_LIST_H */
