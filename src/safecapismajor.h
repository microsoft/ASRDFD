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

#ifndef __SAFE_C_APIS_MAJOR_H__
#define __SAFE_C_APIS_MAJOR_H__

#ifdef __INM_KERNEL_DRIVERS__

#ifdef INM_LINUX
#include <linux/stddef.h>
#include <linux/types.h>
#else
#include <sys/types.h>
#include <inttypes.h>
#endif

#else

#include <inttypes.h>
#include <stdio.h>
#include <wchar.h>
#include <stdarg.h>

#endif /* __INM_KERNEL_DRIVERS__ */

/* Error Values */
#define	INM_ERR_SUCCESS		0	/* Success */
#define	INM_ERR_INVALID		1	/* Invalid Argument */
#define	INM_ERR_OVERLAP		2	/* Overlap */
#define INM_ERR_UNTERM		3	/* Unterminated */
#define INM_ERR_NOSPC		4	/* No Space */

/* 
 * RHEL 5 gcc compiler does not support inline functions with variable args. 
 * As such, same function is copied as non inline variant in driver code as
 * a workaround. Any bug fixes here should be made there as well.
 */
#if !(defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && __INM_KERNEL_DRIVERS__)
/* Make sure compiler does printf style format checking */
static inline int sprintf_s(char *buf, size_t bufsz, 
		const char *fmt, ...) __attribute__ ((format(printf, 3, 4)));

static inline int
sprintf_s(char *buf, size_t bufsz, const char *fmt, ...)
{
	int retval = -1;
	va_list args;

	if( buf && bufsz > 0 && fmt ) {
		va_start(args, fmt);

		retval = vsnprintf(buf, bufsz, fmt, args);
		/* If buffer not adequate, return error */
		if( retval >= bufsz )
			retval = -1;

		va_end(args);
	}

	if( retval == -1 ) {
		if( buf && bufsz )
			*buf = '\0';
	}

	return retval;
}

static inline int
vsnprintf_s(char *buf, size_t bufsz, const char *fmt, va_list args)
{
	int retval = -1;

	if( buf && bufsz > 0 && fmt ) {

		retval = vsnprintf(buf, bufsz, fmt, args);
		/* If buffer not adequate, return error */
		if( retval >= bufsz )
			retval = -1;
	}

	if( retval == -1 ) {
		if( buf && bufsz )
			*buf = '\0';
	}

	return retval;
}

#endif

static inline int
memcpy_s(void *dest, size_t d_count, const void *src, size_t s_count)
{
	uint8_t		*destp;
	const uint8_t	*srcp;

	destp = (uint8_t *)dest;
	srcp = (const uint8_t   *)src;


	/* nothing to copy*/
	if (s_count == 0) {
		return INM_ERR_SUCCESS;
	}

	/* Validations:
	 * 1. dest and src shouldn't be NULL
	 * 2. d_count and s_count shouldn't be 0
	 * 3. s_count shouldn't be greater than d_count
	 */
	if (destp == NULL || d_count == 0 || srcp == NULL ||
			s_count > d_count) {
		return INM_ERR_INVALID;
	}

	/* Check for overlap of dest and src */
	if (((srcp > destp) && (srcp < (destp + d_count))) ||
		((destp > srcp) && (destp < (srcp + s_count)))) {
		return INM_ERR_OVERLAP;
	}

	/* Copy the data from src to dest */
	do {
		*destp++ = *srcp++;
		
	} while (--s_count);

	return INM_ERR_SUCCESS;
}

static inline int
strcat_s(char *str_dest, size_t d_count, const char *str_src)
{
	int		ret = INM_ERR_NOSPC;
	const char	*overlap_pos, *overlap_buf;
	char		*str_dest_orig = str_dest;
	const char	*str_src_orig = str_src;

	/* Validations:
	 * 1. str_dest & str_src shouldn't be NULL
	 * 2. d_count shouldn't be 0
	 */
	if (str_dest == NULL || d_count == 0 || str_src == NULL)
		return INM_ERR_INVALID;

	/* Find the end of str_dest */
	while (*str_dest != '\0') {
		/* Check for overlap */
		if (str_dest == str_src) {
			ret = INM_ERR_OVERLAP;
			goto out;
		}

		str_dest++;
		d_count--;

		if (d_count == 0) {
			ret = INM_ERR_UNTERM;
			goto out;
		}
	}

	if (str_dest_orig < str_src_orig)
		overlap_pos = str_src_orig;
	else
		overlap_pos = str_dest_orig;

	while (d_count > 0) {
		if (str_dest_orig < str_src_orig)
			overlap_buf = str_dest;
		else
			overlap_buf = str_src;

		/* Check for overlap */
		if (overlap_buf == overlap_pos){
			ret = INM_ERR_OVERLAP;
			goto out;
		}

		*str_dest = *str_src;
		if (*str_dest == '\0')
			return INM_ERR_SUCCESS;

		str_dest++;
		str_src++;
		d_count--;
	}

out:
	*str_dest_orig = '\0';
	return ret;
}

static inline int
strncat_s(char *str_dest, size_t d_count, const char *str_src, size_t s_count)
{
	int		ret = INM_ERR_NOSPC;
	const char	*overlap_pos, *overlap_buf;
	char		*str_dest_orig = str_dest;
	const char	*str_src_orig = str_src;

	/* Validations:
	 * 1. str_dest & str_src shouldn't be NULL
	 * 2. d_count shouldn't be 0
	 */
	if (str_dest == NULL || d_count == 0 || str_src == NULL)
		return INM_ERR_INVALID;

	/* Find the end of str_dest */
	while (*str_dest != '\0') {
		/* Check for overlap */
		if (str_dest == str_src) {
			ret = INM_ERR_OVERLAP;
			goto out;
		}

		str_dest++;
		d_count--;

		if (d_count == 0){
			ret = INM_ERR_UNTERM;
			goto out;
		}
	}

	if (str_dest_orig < str_src_orig)
		overlap_pos = str_src_orig;
	else
		overlap_pos = str_dest_orig;

	while (d_count > 0) {
		if (str_dest_orig < str_src_orig)
			overlap_buf = str_dest;
		else
			overlap_buf = str_src;

		/* Check for overlap */
		if (overlap_buf == overlap_pos) {
			ret = INM_ERR_OVERLAP;
			goto out;
		}

		if (s_count == 0) {
			*str_dest = '\0';
			return INM_ERR_SUCCESS;
		}

		*str_dest = *str_src;
		if (*str_dest == '\0')
			return INM_ERR_SUCCESS;

		str_dest++;
		str_src++;
		d_count--;
		s_count--;
	}

out:
	*str_dest_orig = '\0';
	return ret;
}

/*
 * api to safely copy the string from src to tgt.
 * INPUT:
 *      tgt: poiter to target buffer.
 *      src: pointer to string need to be copied.
 *      tgtmax: max aize of the target buffer
 * RETURN:
 *      0  : success of string copy.
 *      >0 : see failure cases defined above.
 */

static inline int
strcpy_s(char *tgt, size_t tgtmax, const char *src)
{
	const char *overlap_sensor;
	int ret;
	int src_high_mem = 0;
	char *tgt_orig = tgt;

	/* Validate argument */
	if(tgt == NULL || tgtmax == 0)
		return INM_ERR_INVALID;

	if (src == NULL) {
		ret = INM_ERR_INVALID;
		goto out;
	}

	if (tgt < src) {
		overlap_sensor = src;
		src_high_mem = 1;
	} else {
		overlap_sensor = tgt;
	}

	do {
		if (!tgtmax) {
			ret = INM_ERR_NOSPC;
			goto out;
		}
		if (src_high_mem) {
			if(tgt == overlap_sensor) {
				ret = INM_ERR_OVERLAP;
				goto out;
			}
		} else {
			if (src == overlap_sensor) {
				ret = INM_ERR_OVERLAP;
				goto out;
			}
		}
		--tgtmax;
	} while((*tgt++ = *src++));

	/*zero_out_remaining*/
	while(tgtmax) {
		 *tgt = '\0'; tgtmax--; tgt++;
	}

	return INM_ERR_SUCCESS;

out:
	*tgt_orig = '\0';
	return ret;
}

/*
 * api to safe copy the n bytes from source to target.
 * INPUT:
 *     tgt : poiter to target buffer.
 *     src : pointer to string need to be copied.
 *     tgtmax: max aize of the target buffer
 *     len : lenght of the bytes need to be copied.
 * RETURN:
 *     0 : success of string copy.
 *     >0: see failure cases defined above.
 * RUNTIME CONSTRAINTS:
 * If len is either greater than or equal to tgtmax, then tgtmax
 * should be more than strnlen(src,dmax)
 *
 */
static inline int
strncpy_s(char *tgt, size_t tgtmax, const char *src, size_t len)
{
	const char *overlap_sensor;
	int ret;
	int src_high_mem = 0;
	char *tgt_orig = tgt;

	/* validate argument */
	if(tgt == NULL || tgtmax == 0)
		return INM_ERR_INVALID;

	if (src == NULL) {
		ret = INM_ERR_INVALID;
		goto out;
	}

	if (tgt < src) {
		overlap_sensor = src;
		src_high_mem = 1;
	} else {
		overlap_sensor = tgt;
	}

	do {
		if (!tgtmax) {
			ret = INM_ERR_NOSPC;
			goto out;
		}
		if (src_high_mem) {
			if(tgt == overlap_sensor) {
				ret = INM_ERR_OVERLAP;
				goto out;
			}
		} else {
			if (src == overlap_sensor) {
				ret = INM_ERR_OVERLAP;
				goto out;
			}
		}
		if(!len) {
			goto zero_out_remaining;
		}

		--tgtmax;
		--len;
	} while((*tgt++ = *src++));

zero_out_remaining:
	while(tgtmax) {
		*tgt = '\0'; tgtmax--; tgt++;
	}

	return INM_ERR_SUCCESS;

out:
	*tgt_orig = '\0';
	return ret;
}

#ifndef __INM_KERNEL_DRIVERS__
static inline int
wcscat_s(wchar_t *str_dest, size_t d_count, const wchar_t *str_src)
{
	int		ret = INM_ERR_NOSPC;
	const wchar_t	*overlap_pos, *overlap_buf;
	wchar_t		*str_dest_orig = str_dest;
	const wchar_t	*str_src_orig = str_src;

	/* Validations:
	 * 1. str_dest & str_src shouldn't be NULL
	 * 2. d_count shouldn't be 0
	 */
	if (str_dest == NULL || d_count == 0 || str_src == NULL)
		return INM_ERR_INVALID;

	/* Find the end of str_dest */
	while (*str_dest != L'\0') {
		/* Check for overlap */
		if (str_dest == str_src) {
			ret = INM_ERR_OVERLAP;
			goto out;
		}

		str_dest++;
		d_count--;

		if (d_count == 0) {
			ret = INM_ERR_UNTERM;
			goto out;
		}
	}

	if (str_dest_orig < str_src_orig)
		overlap_pos = str_src_orig;
	else
		overlap_pos = str_dest_orig;

	while (d_count > 0) {
		if (str_dest_orig < str_src_orig)
			overlap_buf = str_dest;
		else
			overlap_buf = str_src;

		/* Check for overlap */
		if (overlap_buf == overlap_pos) {
			ret = INM_ERR_OVERLAP;
			goto out;
		}

		*str_dest = *str_src;
		if (*str_dest == L'\0')
			return INM_ERR_SUCCESS;

		str_dest++;
		str_src++;
		d_count--;
	}

out:
	*str_dest_orig = L'\0';
	return ret;
}

/*
 * api to safe copy the wchar bytes from src to tgt.
 * INPUT:
 *      tgt: poiter to target buffer.
 *      src: pointer to string need to be copied.
 *      tgtmax: max aize of the target buffer.
 * RETURN:
 *      0  : success of string copy.
 *      >0 : see failure cases defined above.
 *
 */
static inline int
wcscpy_s(wchar_t *tgt, size_t tgtmax, const wchar_t *src)
{
	const wchar_t *overlap_sensor;
	int ret;
	int src_high_mem = 0;
	wchar_t *tgt_orig = tgt;

	/* Validate argument */
	if (tgt == NULL || tgtmax  == 0)
		return INM_ERR_INVALID;

	if (src == NULL) {
		ret = INM_ERR_INVALID;
		goto out;
	}

	if (tgt < src) {
		overlap_sensor = src;
		src_high_mem = 1;
	} else {
		overlap_sensor = tgt;
	}

	do {
		if (!tgtmax) {
			ret = INM_ERR_NOSPC;
			goto out;
		}
		if (src_high_mem) {
			if(tgt == overlap_sensor) {
				ret = INM_ERR_OVERLAP;
				goto out;
			}
		} else {
			if (src == overlap_sensor) {
				ret = INM_ERR_OVERLAP;
				goto out;
			}
		}
		--tgtmax;
	} while(*tgt++ = *src++);

	/*zero_out_remaining*/
	while(tgtmax) {
		*tgt = L'\0'; tgtmax--; tgt++;
	}
	return INM_ERR_SUCCESS;

out:
	*tgt_orig = L'\0';
	return ret;
}
#endif /* __INM_KERNEL_DRIVERS__ */
#endif /* __SAFE_C_APIS_MAJOR_H__ */
