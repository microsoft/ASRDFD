git d/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */

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

#ifndef INM_TYPES_H
#define	INM_TYPES_H 

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif
#include <linux/version.h>


/* signed types */
typedef long long               inm_sll64_t;
typedef int64_t                 inm_s64_t;
typedef int32_t                 inm_s32_t;
typedef int16_t                 inm_s16_t;
typedef int8_t                  inm_s8_t;
typedef char                    inm_schar;

/* unsigned types */
typedef unsigned long long      inm_ull64_t;
typedef uint64_t                inm_u64_t;
typedef uint32_t                inm_u32_t;
typedef uint16_t                inm_u16_t;
typedef uint8_t                 inm_u8_t;
typedef unsigned char           inm_uchar;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
typedef void                    inm_iodone_t;
#else
typedef int                     inm_iodone_t;
#endif

#endif /* INM_TYPES_H */
