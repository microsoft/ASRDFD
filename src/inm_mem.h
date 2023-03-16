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

#ifndef _INM_MEM_H
#define _INM_MEM_H

#define INM_KM_NORETRY		__GFP_NORETRY
#define INM_KM_NOWARN		__GFP_NOWARN
#define INM_KM_HIGHMEM		__GFP_HIGHMEM	

#define INM_KM_SLEEP		GFP_KERNEL
#define INM_KM_NOSLEEP		GFP_ATOMIC
#define INM_KM_NOIO         GFP_NOIO
#define INM_UMEM_SLEEP		GFP_KERNEL
#define	INM_UMEM_NOSLEEP	GFP_ATOMIC

#define INM_SLAB_HWCACHE_ALIGN	SLAB_HWCACHE_ALIGN


#define CHECK_OVERFLOW(size)\
({\
	int ret;\
	unsigned long long tmp = (unsigned long long)size;\
	if(tmp < ((size_t) - 1)){\
		ret = 0;\
	}else {\
		ret = -1;\
	}\
	ret;\
})

#define INM_KMALLOC(size, flag, heap)\
({\
	void *rptr = NULL;\
	if(!CHECK_OVERFLOW(size)) {\
		rptr = inm_kmalloc(size, flag);\
	}\
	rptr;\
})

#define INM_KFREE(ptr, size, heap)    inm_kfree(size, ptr)

static inline 
int INM_PIN(void *addr, size_t size)
{
	return 0;
}

static inline 
int INM_UNPIN(void *addr, size_t size)
{
	return 0;
}

#define INM_VMALLOC(size, flag, heap) \
({\
	void *rptr = NULL;\
	if(!CHECK_OVERFLOW(size)) {\
		rptr = inm_vmalloc(size);\
	}\
	rptr;\
})

#define INM_VFREE(ptr, size, heap)    inm_vfree(ptr, size)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define INM_KMEM_CACHE_CREATE(cache_name, obj_size, align, flags, ctor, dtor, nr_objs, min_nr, pinned)	\
		kmem_cache_create(cache_name, obj_size, align, flags, ctor)
#else
#define INM_KMEM_CACHE_CREATE(cache_name, obj_size, align, flags, ctor, dtor, nr_objs, min_nr, pinned)	\
		kmem_cache_create(cache_name, obj_size, align, flags, ctor, dtor)
#endif
#define INM_KMEM_CACHE_DESTROY(cachep)          kmem_cache_destroy(cachep)
#define INM_KMEM_CACHE_ALLOC(cachep, flags)     inm_kmem_cache_alloc(cachep, flags)
#define INM_KMEM_CACHE_ALLOC_PATH(cachep, flags, size, heap)			\
						INM_KMEM_CACHE_ALLOC(cachep, flags)
#define INM_KMEM_CACHE_FREE(cachep, objp)       inm_kmem_cache_free(cachep, objp)
#define INM_KMEM_CACHE_FREE_PATH(cachep, objp, heap)				\
						INM_KMEM_CACHE_FREE(cachep, objp)

#define INM_MEMPOOL_CREATE(min_nr, alloc_slab, free_slab, cachep)	\
	mempool_create(min_nr, alloc_slab, free_slab, cachep)
#define INM_MEMPOOL_FREE(objp, poolp)           inm_mempool_free(objp, poolp)
#define	INM_MEMPOOL_ALLOC(poolp, flag)          inm_mempool_alloc(poolp, flag)
#define INM_MEMPOOL_DESTROY(poolp)              mempool_destroy(poolp)

#define	INM_ALLOC_PAGE(flag)                    inm_alloc_page(flag)
#define	__INM_FREE_PAGE(pagep)                  __inm_free_page(pagep)
#define	INM_ALLOC_MAPPABLE_PAGE(flag)           inm_alloc_page(flag)
#define	INM_FREE_MAPPABLE_PAGE(page, heap)     	__inm_free_page(page)

#define	__INM_GET_FREE_PAGE(flag, heap)         __inm_get_free_page(flag)
/* This removes any protection we get from compiler against 
 * passing pointers of other unexpected types.
 */
#define	INM_FREE_PAGE(pagep, heap)              inm_free_page((unsigned long)pagep)

#define	INM_MEMPOOL_ALLOC_SLAB                  mempool_alloc_slab
#define	INM_MEMPOOL_FREE_SLAB                   mempool_free_slab

#define INM_MMAP_PGOFF(filp, addr, len, prot, flags, pgoff)	\
		do_mmap_pgoff(filp, addr, len, prot, flags, pgoff) 
	
typedef	unsigned     inm_kmalloc_flag;
typedef	struct kmem_cache inm_kmem_cache_t;
typedef mempool_t    inm_mempool_t;
typedef	unsigned long inm_kmem_cache_flags;
typedef	mempool_alloc_t	inm_mempool_alloc_t;

#endif /* end of _INM_MEM_H */
