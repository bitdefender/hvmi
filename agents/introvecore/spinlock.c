/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "spinlock.h"
#include "asmlib.h"


//
// SpinLockInit
//
void
SpinLockInit(
    PSPINLOCK SpinLock
    )
{
    *SpinLock = 0;
}


//
// SpinLockAcquire
//
void
SpinLockAcquire(
    PSPINLOCK Lock
    )
{
    AsmSpinLockAcquire(Lock);
}


//
// SpinLockRelease
//
void
SpinLockRelease(
    PSPINLOCK Lock
    )
{
    AsmSpinLockRelease(Lock);
}


//
// RwSpinLockInit
//
void
RwSpinLockInit(
    PRWSPINLOCK SpinLock
    )
{
    *SpinLock = 0;
}


//
// RwSpinLockAcquireShared
//
void
RwSpinLockAcquireShared(
    PRWSPINLOCK SpinLock
    )
{
    AsmRwSpinLockAcquireShared(SpinLock);
}


//
// RwSpinLockAcquireExclusive
//
void
RwSpinLockAcquireExclusive(
    PRWSPINLOCK SpinLock
    )
{
    AsmRwSpinLockAcquireExclusive(SpinLock);
}


//
// RwSpinLockReleaseShared
//
void
RwSpinLockReleaseShared(
    PRWSPINLOCK SpinLock
    )
{
    AsmRwSpinLockReleaseShared(SpinLock);
}


//
// RwSpinLockReleaseExclusive
//
void
RwSpinLockReleaseExclusive(
    PRWSPINLOCK SpinLock
    )
{
    AsmRwSpinLockReleaseExclusive(SpinLock);
}
