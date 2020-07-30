/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VECORE_H_
#define _VECORE_H_

#include "thread_safeness.h"


INTSTATUS
IntVeHandleHypercall(
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntVeDeployAgent(
    void
    );

INTSTATUS
IntVeRemoveAgent(
    _In_ DWORD AgOpts
    );

QWORD
IntVeGetDriverAddress(
    void
    );

BOOLEAN
IntVeIsPtrInAgent(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    );

BOOLEAN
IntVeIsCurrentRipInAgent(
    void
    );

INTSTATUS
IntVeInit(
    void
    );

INTSTATUS
IntVeUnInit(
    void
    );

void
IntVeDumpVeInfoPages(
    void
    );

void
IntVeDumpStats(
    void
    );

INTSTATUS
IntVeHandleEPTViolationInProtectedView(
    _In_ IG_EPT_ACCESS AccessType,
    _Out_ INTRO_ACTION *Action
    );

void
IntVeHandleGuestResumeFromSleep(
    void
    );

INTSTATUS
IntVeUpdateCacheEntry(
    _In_ QWORD Address,
    _In_ BOOLEAN Monitored
    );

BOOLEAN
IntVeIsAgentRemapped(
    _In_ QWORD Gla
    );

#endif // _VECORE_H_
