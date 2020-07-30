/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _AGENT_H_
#define _AGENT_H_

#include "thread_safeness.h"

//
// Agent state.
//
typedef enum _AG_WAITSTATE
{
    agNone,     ///< No active/pending agents.
    agActive,   ///< We have an active agent, currently injected inside the guest.
    agWaiting,  ///< We have at least pending agent waiting to be injected inside the guest.
} AG_WAITSTATE;


INTSTATUS
IntAgentHandleInt3(
    _In_ QWORD Rip,
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntAgentHandleVmcall(
    _In_ QWORD Rip
    );

INTSTATUS
IntAgentActivatePendingAgent(
    void
    );

void
IntAgentDisablePendingAgents(
    void
    );

AG_WAITSTATE
IntAgentGetState(
    _Out_opt_ DWORD *Tag
    );

INTSTATUS
IntAgentEnableInjection(
    void
    );

BOOLEAN
IntAgentIsPtrInTrampoline(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    );

#endif // _AGENT_H_
