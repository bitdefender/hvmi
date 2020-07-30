/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SPINLOCK_H_
#define _SPINLOCK_H_

#include "vetypes.h"

typedef unsigned __int32 SPINLOCK, *PSPINLOCK;
typedef unsigned __int32 RWSPINLOCK, *PRWSPINLOCK;

void
SpinLockInit(
    PSPINLOCK SpinLock
    );

void
SpinLockAcquire(
    PSPINLOCK Lock
    );

void
SpinLockRelease(
    PSPINLOCK Lock
    );

void
RwSpinLockInit(
    PRWSPINLOCK SpinLock
    );

void
RwSpinLockAcquireShared(
    PRWSPINLOCK SpinLock
    );

void
RwSpinLockAcquireExclusive(
    PRWSPINLOCK SpinLock
    );

void
RwSpinLockReleaseShared(
    PRWSPINLOCK SpinLock
    );

void
RwSpinLockReleaseExclusive(
    PRWSPINLOCK SpinLock
    );

#endif // _SPINLOCK_H_
