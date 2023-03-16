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

#include "involflt-common.h"
#include "change-node.h"
#include "target-context.h"
#define IDEBUG_METADATA 1
#ifndef LINVOLFLT_DEBUG_H
#define LINVOLFLT_DEBUG_H
#define DEBUG_LEVEL 1

void print_target_context(target_context_t *);
void print_disk_change_head(disk_chg_head_t *);
void print_change_node(change_node_t *);
void print_disk_change(disk_chg_t *);

#endif
