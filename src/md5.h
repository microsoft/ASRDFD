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
 * Define functions used to compute MD5 checksum
 */
#ifndef MD5__H
#define MD5__H

#ifdef __alpha
typedef unsigned inm_s32_t uint32;
#else
//typedef unsigned long uint32;
/* changed to inm_u32_t, on 64 bit m/c unsigned long is 64 bit */
typedef inm_u32_t uint32;
#endif

#define MD5TEXTSIGLEN 32

typedef struct MD5Context {
	uint32 buf[4];
	uint32 bits[2];
	unsigned char in[64];
} MD5Context;

typedef struct MD5Context MD5_CTX;

#ifdef __cplusplus
extern "C" {
#endif

	void byteReverse(unsigned char *buf, unsigned longs);
	void MD5Transform(uint32 buf[4], uint32 in[16]);
	void MD5Init(MD5Context *ctx);
	void MD5Update(MD5Context *ctx, unsigned char *buf, unsigned len);
	void MD5Final(unsigned char digest[16], struct MD5Context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* !MD5__H */
