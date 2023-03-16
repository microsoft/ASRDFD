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

#ifndef _INM_LOCKS_H
#define _INM_LOCKS_H
/*
#include <asm/semaphore.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <asm/atomic.h>
*/

typedef struct mutex inm_mutex_t;
typedef spinlock_t inm_spinlock_t;
typedef rwlock_t  inm_rw_spinlock_t;
typedef struct rw_semaphore inm_rwsem_t;
typedef struct semaphore inm_sem_t;
typedef atomic_t inm_atomic_t;

/* mutex lock apis */
#define INM_MUTEX_INIT(lock)            mutex_init((struct mutex*)lock)
#define INM_MUTEX_LOCK(lock)            mutex_lock((struct mutex*)lock)
#define INM_MUTEX_UNLOCK(lock)          mutex_unlock((struct mutex*)lock)

/* spin lock api */
#define INM_INIT_SPIN_LOCK(lock)        spin_lock_init((spinlock_t*)lock)
#define INM_DESTROY_SPIN_LOCK(lock)	
#define INM_SPIN_LOCK(lock)             spin_lock((spinlock_t*)lock)
#define INM_SPIN_UNLOCK(lock)           spin_unlock((spinlock_t*)lock)


#define INM_SPIN_LOCK_BH(lock)          spin_lock_bh((spinlock_t*)lock)
#define INM_SPIN_UNLOCK_BH(lock)        spin_unlock_bh((spinlock_t*)lock)

#define INM_SPIN_LOCK_IRQSAVE(lock, flag) \
                                        spin_lock_irqsave((spinlock_t*)lock, flag)
#define INM_SPIN_UNLOCK_IRQRESTORE(lock, flag) \
                                        spin_unlock_irqrestore((spinlock_t*)lock, flag)
#define INM_IS_SPINLOCK_HELD(lock_addr)	spin_is_locked(lock_addr)

#define INM_SPIN_LOCK_WRAPPER(lock, flag) INM_SPIN_LOCK(lock)
#define INM_SPIN_UNLOCK_WRAPPER(lock, flag) INM_SPIN_UNLOCK(lock)

/* semahore apis */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
#define INM_INIT_SEM(sem)               init_MUTEX((struct semaphore*)sem)
#define INM_INIT_SEM_LOCKED(sem)        init_MUTEX_LOCKED((struct semaphore*)sem)
#else
#define INM_INIT_SEM(sem)		sema_init((struct semaphore*)sem, 1)
#define INM_INIT_SEM_LOCKED(sem)	sema_init((struct semaphore*)sem, 0)
#endif

#define INM_DOWN(sem)                   down((struct semaphore*)sem)
#define INM_DOWN_INTERRUPTIBLE(sem)     down_interruptible((struct semaphore*)sem)
#define INM_DOWN_TRYLOCK(sem)           down_trylock((struct semaphore*)sem)
#define INM_UP(sem)                     up((struct semaphore*)sem)
#define INM_DESTROY_SEM(sem)


/* read write semahore apis */
#define INM_RW_SEM_INIT(rw_sem)         init_rwsem((struct rw_semaphore*)rw_sem)
#define INM_RW_SEM_DESTROY(rw_sem)	

#define INM_DOWN_READ(rw_sem)           down_read((struct rw_semaphore*)rw_sem)
#define INM_DOWN_READ_TRYLOCK(rw_sem)   down_read_trylock((struct rw_semaphore*)rw_sem)
#define INM_UP_READ(rw_sem)             up_read((struct rw_semaphore*)rw_sem)
#define INM_DOWN_WRITE(rw_sem)          down_write((struct rw_semaphore*)rw_sem)
#define INM_UP_WRITE(rw_sem)            up_write((struct rw_semaphore*)rw_sem)
#define INM_DOWNGRADE_WRITE(rw_sem)     downgrade_write((struct rw_semaphore*)rw_sem)


/* atomic operations */

#define INM_ATOMIC_SET(var, val)        atomic_set((atomic_t*)var, val)
#define INM_ATOMIC_INC(var)             atomic_inc((atomic_t*)var)
#define INM_ATOMIC_DEC(var)             atomic_dec((atomic_t*)var)
#define INM_ATOMIC_READ(var)            atomic_read((atomic_t*)var)
#define INM_ATOMIC_DEC_AND_TEST(var)    atomic_dec_and_test((atomic_t*)var)
#define INM_VOL_LOCK(lock, flag)	\
	if(irqs_disabled()) {	\
		INM_SPIN_LOCK_IRQSAVE(lock, flag); \
	} else { \
		INM_SPIN_LOCK_BH(lock); \
	}

#define INM_VOL_UNLOCK(lock, flag)	\
	if(irqs_disabled()) {	\
		INM_SPIN_UNLOCK_IRQRESTORE(lock, flag);\
	} else { \
		INM_SPIN_UNLOCK_BH(lock);\
	}

#define INM_DESTROY_WAITQUEUE_HEAD(eventp)
#define INM_ATOMIC_DEC_RET(var)		atomic_dec_return(var)


#endif  /* _INM_LOCKS_H */
