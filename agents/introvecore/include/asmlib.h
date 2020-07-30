/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ASMLIB_H_
#define _ASMLIB_H_

#include "vetypes.h"

void
AsmVmcall(
    QWORD *Eax,
    QWORD *Ebx,
    QWORD *Ecx,
    QWORD *Edx,
    QWORD *Edi,
    QWORD *Esi
    );

void
AsmSpinLockAcquire(
    void *SpinLock
    );

void
AsmSpinLockRelease(
    void *SpinLock
    );

void
AsmRwSpinLockAcquireShared(
    void *SpinLock
    );

void
AsmRwSpinLockReleaseShared(
    void *SpinLock
    );

void
AsmRwSpinLockAcquireExclusive(
    void *SpinLock
    );

void
AsmRwSpinLockReleaseExclusive(
    void *SpinLock
    );

#endif // _ASMLIB_H_
