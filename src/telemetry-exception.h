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

#ifndef _TELE_EXC_H
#define _TELE_EXC_H

/* Limit the number of exceptions to limit telemetry data to PAGE_SIZE */
#define INM_EXCEPTION_MAX   5
#define INM_EXCEPTION_BUFSZ 2048

typedef enum _etException {
	excSuccess = 0,
	/* Global Exception - MSB 0 */
	/* Per Volume Exception - MSB 1 */
	ecUnsupportedBIO = 2147483649,
	ecResync,
} etException;

typedef struct exception {
	inm_list_head_t         e_list;
	char                    e_tag[INM_GUID_LEN_MAX];
	inm_u64_t               e_first_time;
	inm_u64_t               e_last_time;
	etException             e_error;
	inm_u32_t               e_count;
	inm_u64_t               e_data;
} exception_t;

typedef struct exception_buf {
	inm_u32_t   eb_refcnt;
	inm_u32_t   eb_gen;
	char        eb_buf[2040]; /* align to 2048 */
} exception_buf_t;

void telemetry_init_exception(void);
void telemetry_set_exception(char *, etException, inm_u64_t);
exception_buf_t *telemetry_get_exception(void);
void telemetry_put_exception(exception_buf_t *);

#endif
