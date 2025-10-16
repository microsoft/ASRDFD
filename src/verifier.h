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

#ifndef _VERIFIER_H
#define _VERIFIER_H

#ifndef __INM_KERNEL_DRIVERS__  /* User Mode */

#include "verifier_user.h"
#define verify_err(verbose, format, arg...)             \
do {                                                \
	if (verbose)                                    \
		printf("INFO: %llu: " format "\n", offset, ## arg);   \
} while(0)

#else                           /* Kernel Mode */

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
#include "filter_host.h"
#include "metadata-mode.h"
#include "tunable_params.h"
#include "svdparse.h"
#include "db_routines.h"

inm_s32_t inm_verify_alloc_area(inm_u32_t size, int toggle);
void inm_verify_free_area(void);

#define verify_err(verbose, format, arg...) (verbose ? err(format, ## arg) : 0)

#endif                          /* Kernel Mode */

#include "svdparse.h"

inm_s32_t inm_verify_change_node_data(char *buf, int bufsz, int verbose);

#endif
