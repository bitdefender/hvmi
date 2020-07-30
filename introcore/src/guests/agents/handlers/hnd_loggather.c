/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hnd_loggather.h"
#include "alerts.h"
#include "guests.h"


INTSTATUS
IntAgentHandleLogGatherVmcall(
    _In_opt_ void *Reserved,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Handle a VMCALL issued by a log gather agent.
///
/// This handler will froward all the info reported by the in-guest agent to the integrator. The log gather agent
/// collects log data from the guest and reports it back to the integrator.
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
    AGENT_LGT_EVENT_HEADER header;

    UNREFERENCED_PARAMETER(Reserved);

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    retLen = 0;
    agentEvent = &gAlert.Agent;
    memset(agentEvent, 0, sizeof(*agentEvent));
    memset(&header, 0, sizeof(header));

    // Data address will be in RBX on x64 and ESI on x86.
    dataAddr = gGuest.Guest64 ? Registers->Rbx : (Registers->Rsi & 0xFFFFFFFF);

    if (0 == dataAddr)
    {
        ERROR("[ERROR] Data address is 0!\n");
        return INT_STATUS_NOT_FOUND;
    }

    // Read the event structure.
    agentEvent->AgentTag = IG_AGENT_TAG_LOG_GATHER_TOOL;
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

    status = IntVirtMemRead(dataAddr, sizeof(AGENT_LGT_EVENT_HEADER), Registers->Cr3, &header, &retLen);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        goto resume_and_exit;
    }

    if (header.Version != LGT_EVENT_VERSION)
    {
        ERROR("[ERROR] Version mismatch: %x (read) vs %x (known).\n", header.Version, LGT_EVENT_VERSION);
        status = INT_STATUS_NOT_SUPPORTED;
        goto resume_and_exit;
    }

    if (header.Size != LGT_EVENT_SIZE)
    {
        ERROR("[ERROR] Size mismatch: %d (read) vs %lu (known).\n", header.Size, LGT_EVENT_SIZE);
        status = INT_STATUS_NOT_SUPPORTED;
        goto resume_and_exit;
    }

    status = IntVirtMemRead(dataAddr, sizeof(AGENT_LGT_EVENT), Registers->Cr3, &agentEvent->LogGatherEvent, &retLen);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        goto resume_and_exit;
    }

    if (retLen != sizeof(AGENT_LGT_EVENT))
    {
        ERROR("[ERROR] Read only %d bytes, needed %zu!\n", retLen, sizeof(AGENT_LGT_EVENT));
        status = INT_STATUS_INVALID_DATA_SIZE;
        goto resume_and_exit;
    }

    // Log
    switch (header.EventType)
    {
    case lgtEventData:
        TRACE("[LOGTOOL] Data from %s: %d bytes\n",
              utf16_for_log(agentEvent->LogGatherEvent.DataEvent.FileName),
              agentEvent->LogGatherEvent.DataEvent.DataSize);
        break;
    case lgtEventError:
        TRACE("[LOGTOOL] Error: 0x%08x\n", agentEvent->LogGatherEvent.ErrorEvent.ErrorCode);
        break;
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
