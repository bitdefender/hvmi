/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PTWRITES_H_
#define _PTWRITES_H_

#include "thread_safeness.h"

INTSTATUS
IntPtiHandleInt3(
    void
    );

void
IntPtiDumpStats(
    void
    );

BOOLEAN
IntPtiIsPtrInAgent(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    );

INTSTATUS
IntPtiCacheRemove(
    _In_ QWORD Gpa
    );

INTSTATUS
IntPtiCacheAdd(
    _In_ QWORD Gpa
    );

INTSTATUS
IntPtiInjectPtFilter(
    void
    );

INTSTATUS
IntPtiRemovePtFilter(
    _In_ DWORD AgOpts
    );

QWORD
IntPtiGetAgentAddress(
    void
    );

QWORD
IntPtiAllocMemtableSpace(
    _In_ QWORD Rip,
    _In_ DWORD Size
    );

void
IntPtiHandleGuestResumeFromSleep(
    void
    );

INTSTATUS
IntPtiRemoveInstruction(
    _In_ QWORD Rip
    );

#endif // _PTWRITES_H_
