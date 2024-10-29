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

#ifndef _DISTRO_H
#define _DISTRO_H

/* Ubuntu */
#if (defined ubuntu)
#if (DISTRO_VER == 18)
#define UBUNTU1804
#elif (DISTRO_VER == 20)
#define UBUNTU2004
#elif (DISTRO_VER == 22)
#define UBUNTU2204
#endif
#endif

/* SLES 11 */
#if (defined suse && DISTRO_VER == 11)
#define SLES11
#if (PATCH_LEVEL == 3)
#define SLES11SP3
#elif (PATCH_LEVEL == 4)
#define SLES11SP4
#endif
#endif

/* SLES 12 */
#if (defined suse && DISTRO_VER == 12)
#define SLES12
#if (PATCH_LEVEL == 1)
#define SLES12SP1
#elif (PATCH_LEVEL == 2)
#define SLES12SP2
#elif (PATCH_LEVEL == 3)
#define SLES12SP3
#elif (PATCH_LEVEL == 4)
#define SLES12SP4
#elif (PATCH_LEVEL == 5)
#define SLES12SP5
#endif 
#endif

#if (defined suse && DISTRO_VER == 15)
#define SLES15
#if (PATCH_LEVEL == 1)
#define SLES15SP1
#elif (PATCH_LEVEL == 2)
#define SLES15SP2
#elif (PATCH_LEVEL == 3)
#define SLES15SP3
#elif (PATCH_LEVEL == 4)
#define SLES15SP4
#elif (PATCH_LEVEL == 5)
#define SLES15SP5
#elif (PATCH_LEVEL == 6)
#define SLES15SP6
#endif
#endif

/* RHEL */
#if (defined redhat && DISTRO_VER == 9)
#define RHEL9
#elif (defined redhat && DISTRO_VER == 8)
#define RHEL8
#elif (defined redhat && DISTRO_VER == 7)
#define RHEL7
#elif (defined redhat && DISTRO_VER == 6)
#define RHEL6
#elif (defined redhat && DISTRO_VER == 5)
#define RHEL5
#endif

#ifndef RHEL5
#define INITRD_MODE
#endif

#endif

