/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "agent.h"
#include "winagent.h"
#include "lixagent.h"
#include "guests.h"


INTSTATUS
IntAgentHandleInt3(
    _In_ QWORD Rip,
    _In_ DWORD CpuNumber
    )
///
/// @brief Dispatch a breakpoint event to the Windows or Linux agent breakpoint handler.
///
/// @param[in]  Rip         The RIP the breakpoint took place at.
/// @param[in]  CpuNumber   The VCPU number.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the OS is not recognized.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentHandleInt3(Rip, CpuNumber);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixAgentHandleInt3(Rip);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntAgentHandleVmcall(
    _In_ QWORD Rip
    )
///
/// @brief Dispatch a VMCALL event to the Windows or Linux agent VMCALL handler.
///
/// @param[in]  Rip The RIP the VMCALL took place at.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the OS is not recognized.
///
{
    if (gGuest.OSType == introGuestLinux)
    {
        return IntLixAgentHandleVmcall(Rip);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentHandleVmcall(Rip);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntAgentActivatePendingAgent(
    void
    )
///
/// @brief Activate a pending Windows or Linux agent.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the guest OS is not initialized.
/// @retval #INT_STATUS_NOT_SUPPORTED If the OS is not recognized.
///
{
    if (gGuest.OSType == introGuestUnknown)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentActivatePendingAgent();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixAgentActivatePendingAgent();
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}


void
IntAgentDisablePendingAgents(
    void
    )
///
/// @brief Disable the Windows or Linux pending agents.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        IntWinAgentDisablePendingAgents();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntLixAgentDisablePendingAgents();
    }
}


AG_WAITSTATE
IntAgentGetState(
    _Out_opt_ DWORD *Tag
    )
///
/// @brief Get the current Windows or Linux agent state.
///
/// @param[out] Tag Optional active agent tag.
///
/// @returns The current agent state.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentGetState(Tag);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixAgentGetState(Tag);
    }
    else
    {
        if (Tag != NULL)
        {
            *Tag = 0;
        }
        return agNone;
    }
}


INTSTATUS
IntAgentEnableInjection(
    void
    )
///
/// @brief Enable Windows or Linux agent injection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the OS is not recognized.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentEnableInjection();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntLixAgentEnableInjection();

        return INT_STATUS_SUCCESS;
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}


BOOLEAN
IntAgentIsPtrInTrampoline(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    )
///
/// @brief Check if the provided pointer points inside the Windows trampoline code.
///
/// @param[in]  Ptr     The pointer to be checked.
/// @param[in]  Type    Pointer type - live RIP or stack value.
///
/// @returns True if the provided pointer points inside the trampoline code, false otherwise.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentIsPtrInTrampoline(Ptr, Type);
    }

    return FALSE;
}
