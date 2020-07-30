/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hnd_remediation.h"
#include "alerts.h"
#include "guests.h"


INTSTATUS
IntAgentHandleRemediationVmcall(
    _In_opt_ void *Reserved,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Handle a VMCALL issued by a remediation agent.
///
/// This handler will froward all the info reported by the in-guest agent to the integrator. The remediation
/// agent will provide detection and disinfection information which will be forwarded to the integrator.
///
/// @param[in]  Reserved    Reserved.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If the agent did not provide any data.
/// @retval #INT_STATUS_NOT_SUPPORTED If the OS version is not supported or if the VMCALL interface version mismatched.
///
{
    INTSTATUS status;
    QWORD dataAddr;
    DWORD retLen;
    PEVENT_AGENT_EVENT agentEvent;
    AGENT_REM_EVENT_HEADER header;

    UNREFERENCED_PARAMETER(Reserved);

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    retLen = 0;
    agentEvent = &gAlert.Agent;
    memset(agentEvent, 0, sizeof(*agentEvent));
    memset(&header, 0, sizeof(header));

    // Data address will be in RCX on x64 and ESI on x86.
    dataAddr = gGuest.Guest64 ? Registers->Rbx : (Registers->Rsi & 0xFFFFFFFF);

    if (0 == dataAddr)
    {
        ERROR("[ERROR] Data address is 0!\n");
        return INT_STATUS_NOT_FOUND;
    }

    // Read the event structure.
    agentEvent->AgentTag = IG_AGENT_TAG_REMEDIATION_TOOL;
    agentEvent->Event = agentMessage;
    agentEvent->ErrorCode = 0;

    if (gGuest.OSType == introGuestWindows)
    {
        IntAlertFillWinProcessCurrent(&agentEvent->CurrentProcess);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntAlertFillLixCurrentProcess(&agentEvent->CurrentProcess);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    // Pause the VCPUs while we read.
    IntPauseVcpus();

    status = IntVirtMemRead(dataAddr, sizeof(AGENT_REM_EVENT_HEADER), Registers->Cr3, &header, &retLen);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        goto resume_and_exit;
    }

    if (header.Version != REM_EVENT_VERSION)
    {
        ERROR("[ERROR] Version mismatch: %x (read) vs %x (known).\n", header.Version, REM_EVENT_VERSION);
        status = INT_STATUS_NOT_SUPPORTED;
        goto resume_and_exit;
    }

    if (header.Size != REM_EVENT_SIZE)
    {
        ERROR("[ERROR] Size mismatch: %d (read) vs %lu (known).\n", header.Size, REM_EVENT_SIZE);
        status = INT_STATUS_NOT_SUPPORTED;
        goto resume_and_exit;
    }

    status = IntVirtMemRead(dataAddr, sizeof(AGENT_REM_EVENT), Registers->Cr3, &agentEvent->RemediationEvent, &retLen);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        goto resume_and_exit;
    }

    if (retLen != sizeof(AGENT_REM_EVENT))
    {
        ERROR("[ERROR] Read only %d bytes, needed %zu!\n", retLen, sizeof(AGENT_REM_EVENT));
        status = INT_STATUS_INVALID_DATA_SIZE;
        goto resume_and_exit;
    }

    // Log
    switch (agentEvent->RemediationEvent.Header.EventType)
    {
    case remEventDetection:
        TRACE("[REMTOOL] Detection: %s infected with %s, flags %d\n",
              utf16_for_log(agentEvent->RemediationEvent.DetectionEvent.ObjectPath),
              utf16_for_log(agentEvent->RemediationEvent.DetectionEvent.Detection),
              agentEvent->RemediationEvent.DetectionEvent.DetectionFlag);
        break;
    case remEventDisinfection:
        TRACE("[REMTOOL] Disinfection: %s infected with %s, status %d\n",
              utf16_for_log(agentEvent->RemediationEvent.DetectionEvent.ObjectPath),
              utf16_for_log(agentEvent->RemediationEvent.DetectionEvent.Detection),
              agentEvent->RemediationEvent.DetectionEvent.ActionResult);
        break;
    case remEventStart:
        TRACE("[REMTOOL] Scan start: %d\n",
              agentEvent->RemediationEvent.StartEvent.ScanStatus);
        break;
    case remEventFinish:
        TRACE("[REMTOOL] Scan finish: %d\n",
              agentEvent->RemediationEvent.FinishEvent.ScanResult);
        break;
    case remEventProgress:
        TRACE("[REMTOOL] Progress: %d\n",
              agentEvent->RemediationEvent.ProgressEvent.Progress);
        break;
    case remEventReboot:
        TRACE("[REMTOOL] Reboot: %d\n",
              agentEvent->RemediationEvent.RebootEvent.RebootNeeded);
        break;
    default:
        TRACE("Unknown event: %d\n", agentEvent->RemediationEvent.Header.EventType);
    }

    status = INT_STATUS_SUCCESS;

resume_and_exit:
    IntResumeVcpus();

    if (INT_SUCCESS(status))
    {
        status = IntNotifyIntroEvent(introEventAgentEvent, agentEvent, sizeof(*agentEvent));
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntNotifyIntroEvent failed: 0x%08x\n", status);
            return status;
        }
    }

    return status;
}
