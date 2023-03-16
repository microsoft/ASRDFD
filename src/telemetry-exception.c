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

#include "involflt.h"
#include "work_queue.h"
#include "utils.h"
#include "filestream.h"
#include "filestream_segment_mapper.h"
#include "segmented_bitmap.h"
#include "VBitmap.h"
#include "change-node.h"
#include "data-file-mode.h"
#include "target-context.h"
#include "data-mode.h"
#include "driver-context.h"
#include "file-io.h"
#include "osdep.h"
#include "telemetry-types.h"
#include "telemetry-exception.h"
#include "telemetry.h"
#include "telemetry-exception.h"

static inm_spinlock_t  exception_lock;
static inm_list_head_t exception_list;
static inm_u32_t       exception_gen = 0;

exception_buf_t exception_enomem = { 
	.eb_refcnt = 1, 
	.eb_gen = 0, 
	.eb_buf = "{\\\"Exception\\\":[{\\\"Seq\\\":\\\"0\\\",\\\"Err\\\":\\\"ENOMEM\\\"}]}" 
};

exception_buf_t exception_none = { 
	.eb_refcnt = 1, 
	.eb_gen = 0, 
	.eb_buf = "{\\\"Exception\\\":[{\\\"Seq\\\":\\\"0\\\",\\\"Err\\\":\\\"0\\\"}]}" 
};

static void
telemetry_reset_exception(exception_t *exception)
{
	INM_MEM_ZERO(exception->e_tag, sizeof(exception->e_tag));
	exception->e_first_time = 0;
	exception->e_last_time = 0;
	exception->e_error = excSuccess;
	exception->e_count = 0;
	exception->e_data = 0;
}

void
telemetry_init_exception(void)
{
	exception_t *exception = NULL;
	int i = 0;

	INM_INIT_LIST_HEAD(&exception_list);
	INM_INIT_SPIN_LOCK(&exception_lock);

	for (i = 0; i < INM_EXCEPTION_MAX; i++) {
		exception = INM_KMALLOC(sizeof(exception_t), INM_KM_SLEEP, 
				                INM_KERNEL_HEAP );
		if (!exception) {
			err("Cannot allocate memory for exceptions data");
			continue;
		}

		telemetry_reset_exception(exception);
		
		INM_INIT_LIST_HEAD(&exception->e_list);
		inm_list_add(&exception->e_list, &exception_list);
	}
}

void
telemetry_set_exception(char *tag, etException error, inm_u64_t data)
{
	exception_t *exception = NULL;
	inm_irqflag_t flag = 0;
	struct inm_list_head *cur = NULL;
	char *default_tag = "NA";

	if (!tag)
		tag = default_tag;

	if (inm_list_empty(&exception_list))
		return;

	INM_SPIN_LOCK_IRQSAVE(&exception_lock, flag);

	__inm_list_for_each(cur, &exception_list) {
		exception = inm_list_entry(cur, exception_t, e_list);
		if (exception->e_error == error &&
			!strcmp(tag, exception->e_tag)) {
			get_time_stamp(&exception->e_last_time);
			break;
		}
	}

	/* If no matching exception, reuse the oldest exception */
	if (cur == &exception_list) {
		cur = cur->prev;
		exception = inm_list_entry(cur, exception_t, e_list);
		telemetry_reset_exception(exception);
		get_time_stamp(&exception->e_first_time);
		exception->e_last_time = exception->e_first_time;
	}

	exception->e_error = error;
	exception->e_data = data;
	exception->e_count++;

	strcpy_s(exception->e_tag, sizeof(exception->e_tag), tag);

	/* Maintain LRU of exceptions */
	inm_list_del_init(&exception->e_list);
	inm_list_add(&exception->e_list, &exception_list);

	exception_gen++;

	INM_SPIN_UNLOCK_IRQRESTORE(&exception_lock, flag);
}

void
telemetry_put_exception(exception_buf_t *buf)
{
	if (INM_ATOMIC_DEC_AND_TEST(&buf->eb_refcnt)) {
		if (buf == &exception_none || buf == &exception_enomem) {
			err("Trying to put default exception");
			INM_BUG_ON(buf == &exception_none ||  
						buf == &exception_enomem);
		} else {
			INM_KFREE(buf, sizeof(exception_buf_t), 
							INM_KERNEL_HEAP);
		}
	}
}

exception_buf_t *
telemetry_get_exception(void)
{
	static exception_buf_t *buf = NULL;
	exception_t *exception = NULL;
	inm_irqflag_t flag = 0;
	struct inm_list_head *cur = NULL;
	int offset = 0;
	int count = 0;
	exception_buf_t *ret = NULL;

	INM_SPIN_LOCK_IRQSAVE(&exception_lock, flag);

	if (buf) {
		if (buf->eb_gen == exception_gen) {
			ret = buf;
			goto out;
		} else {
			telemetry_put_exception(buf);
			buf = NULL;
		}
	}
   
	INM_BUG_ON(buf);

	if (exception_gen) /* Exceptions */
		buf = INM_KMALLOC(sizeof(exception_buf_t), INM_KM_NOSLEEP | 
					INM_KM_NOIO, INM_KERNEL_HEAP);
	if (buf) {
		ret = buf;
		INM_ATOMIC_SET(&buf->eb_refcnt, 1);
		buf->eb_gen = exception_gen;

		/* Generate exception string to be pushed to telemetry */
		offset += sprintf_s(buf->eb_buf, INM_EXCEPTION_BUFSZ - offset, 
				            "{\\\"Exception\\\":[");

		__inm_list_for_each(cur, &exception_list) {
			exception = inm_list_entry(cur, exception_t, e_list);
			if (!exception->e_error)
				break;

			offset += sprintf_s(buf->eb_buf + offset, 
				              INM_EXCEPTION_BUFSZ - offset,
				          "{\\\"Seq\\\":\\\"%d\\\",\\\"Err\\\":\\\"%d\\\","
				          "\\\"Cnt\\\":\\\"%u\\\",\\\"Data\\\":\\\"%llu\\\","
				          "\\\"First\\\":\\\"%llu\\\",\\\"Last\\\":\\\"%llu\\\","
				          "\\\"Tag\\\":\\\"%s\\\"}",
				              exception_gen - count,
				              exception->e_error, 
				              exception->e_count, 
				              exception->e_data, 
				              exception->e_first_time, 
				              exception->e_last_time, 
				              exception->e_tag);
			count++;
		}
	
		sprintf_s(buf->eb_buf + offset, 
					INM_EXCEPTION_BUFSZ - offset, "]}");
	} else {
		if (exception_gen)
			ret = &exception_enomem;
		else
			ret = &exception_none;
	}
   
out: 
	INM_ATOMIC_INC(&ret->eb_refcnt);
	INM_SPIN_UNLOCK_IRQRESTORE(&exception_lock, flag);
	
	return ret;
}
