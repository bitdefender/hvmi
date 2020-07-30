/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windeployer.h"
#include "winagent.h"
#include "alerts.h"
#include "guests.h"
#include "winagent_dummy_Win32.h"
#include "winagent_dummy_x64.h"
#include "winagent_gather_Win32.h"
#include "winagent_gather_x64.h"
#include "winagent_killer_Win32.h"
#include "winagent_killer_x64.h"
#include "winpe.h"
#include "winprocesshp.h"


static INTSTATUS
IntWinDepDeploy(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Boot agent deployment callback.
///
/// This is the injection callback called once the boot driver has been successfully injected inside the guest.
/// This function will send an #introEventAgentEvent, indicating that the agent has been injected via the
/// #agentInjected event type.
/// NOTE: This event does not indicate that the injected agent has actually started. That may still fail!
///
/// @param[in]  GuestVirtualAddress     Gla where the boot driver has been injected.
/// @param[in]  AgentTag                The agent tag.
/// @param[in]  Context                 Optional context.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    PEVENT_AGENT_EVENT event = &gAlert.Agent;
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
#if LOG_LEVEL == 0
    UNREFERENCED_PARAMETER(GuestVirtualAddress);
#endif

    LOG("[DEPLOYER] Agent with tag %d at 0x%016llx has just been injected!\n", AgentTag, GuestVirtualAddress);

    memzero(event, sizeof(*event));

    event->AgentTag = AgentTag;
    event->Event = agentInjected;

    status = IntNotifyIntroEvent(introEventAgentEvent, event, sizeof(*event));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%x\n", status);
    }

    // over-write the status
    status = INT_STATUS_SUCCESS;

    return status;
}


static INTSTATUS
IntWinDepComplete(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD ErrorCode,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Called once the boot driver finishes starting the agent inside the guest.
///
/// This callback is called once the boot driver has finished execution. On success (ErrorCode 0), this means
/// that either the process agent has been started, or the file agent has been written on disk.
///
/// @param[in]  GuestVirtualAddress Unused.
/// @param[in]  ErrorCode           Injection error code. 0 indicates success.
/// @param[in]  AgentTag            The agent tag.
/// @param[in]  Context             The optional context.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    PEVENT_AGENT_EVENT event = &gAlert.Agent;
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

#if LOG_LEVEL == 0
    UNREFERENCED_PARAMETER(GuestVirtualAddress);
#endif

    memzero(event, sizeof(*event));

    LOG("[DEPLOYER] Agent with tag %d at 0x%016llx has just been initialized, error: 0x%08x! "
        "The process may still be running...\n", AgentTag, GuestVirtualAddress, ErrorCode);

    event->Event = agentInitialized;
    event->AgentTag = AgentTag;
    event->ErrorCode = ErrorCode;

    status = IntNotifyIntroEvent(introEventAgentEvent, event, sizeof(*event));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%x\n", status);
    }

    // don't return the status from IntNotifyIntroEvent
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinFormatAgentKillerCommandLine(
    _Out_writes_bytes_(Length) char *CommandLine,
    _In_ DWORD Length
    )
///
/// @brief Formats the agent killer command line.
///
/// @param[in]  CommandLine The agent killer command line.
/// @param[in]  Length      The command line length.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    return IntWinProcGetAgentsAsCli(CommandLine, Length);
}


INTSTATUS
IntWinDepInjectProcess(
    _In_ DWORD AgentTag,
    _In_opt_ PBYTE AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_ const CHAR *Name,
    _In_opt_ const CHAR *Args
    )
///
/// @brief Inject a process inside a Windows guest.
///
/// Inject a process inside the Windows guest. The executable file will be written inside the %System% folder, so make
/// sure you use a name that will not conflict with existing files inside that folder. The process will be started
/// under the SYSTEM user by default.
///
/// @param[in]  AgentTag        Tag used to identify the agent. Some tags are predefined and reserved:
///                             - #IG_AGENT_TAG_DUMMY_TOOL - used to test the injection;
///                             - #IG_AGENT_TAG_LOG_GATHER_TOOL - the log gather tool;
///                             - #IG_AGENT_TAG_AGENT_KILLER_TOOL - the agent killer;
///                             Other agents must have another tag, which can later be used to identify the agent.
/// @param[in]  AgentContent    Unless AgentTag indicates a predefined agent, this must be supplied.
/// @param[in]  AgentSize       Size of the AgentContent buffer.
/// @param[in]  Name            Agent name. The process will have this name inside the guest.
/// @param[in]  Args            Optional arguments to be passed to the agent.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    DWORD procSize;
    PBYTE procContent;
    CHAR localArgs[MAX_PATH] = { 0 };
    BOOLEAN agint;

    procContent = NULL;
    procSize = 0;
    agint = FALSE;

    if (NULL == AgentContent)
    {
        agint = TRUE;

        if (IG_AGENT_TAG_DUMMY_TOOL == AgentTag)
        {
            if (gGuest.Guest64)
            {
                procSize = sizeof(gDummyToolx64);
                procContent = gDummyToolx64;
            }
            else
            {
                procSize = sizeof(gDummyToolx86);
                procContent = gDummyToolx86;
            }
        }
        else if (IG_AGENT_TAG_LOG_GATHER_TOOL == AgentTag)
        {
            if (gGuest.Guest64)
            {
                procSize = sizeof(gGatherAgentx64);
                procContent = gGatherAgentx64;
            }
            else
            {
                procSize = sizeof(gGatherAgentWin32);
                procContent = gGatherAgentWin32;
            }
        }
        else if (IG_AGENT_TAG_AGENT_KILLER_TOOL == AgentTag)
        {
            if (gGuest.Guest64)
            {
                procSize = sizeof(gAgentKillerx64);
                procContent = gAgentKillerx64;
            }
            else
            {
                procSize = sizeof(gAgentKillerWin32);
                procContent = gAgentKillerWin32;
            }

            if (NULL == Args)
            {
                status = IntWinFormatAgentKillerCommandLine(localArgs, sizeof(localArgs));
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntFormatAgentKillerCommandLine failed: %08x\n", status);
                    return status;
                }

                if (0 == strlen(localArgs))
                {
                    return INT_STATUS_NOT_NEEDED_HINT;
                }

                Args = localArgs;

                TRACE("[KILLER] Will use `%s` as a command line\n", localArgs);
            }
        }
        else
        {
            agint = FALSE; // override this, if we call GetAgentContent, it will become external.

            status = IntGetAgentContent(AgentTag, gGuest.Guest64, &procSize, &procContent);
            if (!INT_SUCCESS(status) || (0 == procContent))
            {
                ERROR("[ERROR] IntGetAgentContent failed: 0x%08x\n", status);
                return status;
            }
        }
    }
    else
    {
        procContent = AgentContent;
        procSize = AgentSize;
    }

    if ((NULL == procContent) || (0 == procSize))
    {
        ERROR("[ERROR] No proper agent found!\n");
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // Before moving on, make sure the injected executable matches the guest architecture. Needed on Windows, on Linux,
    // we only support 64 bit guests.
    INTRO_PE_INFO peInfo = { 0 };

    status = IntPeValidateHeader(0, procContent, procSize, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] The provided agent does not look like a valid MZ/PE: 0x%08x\n", status);
        return status;
    }

    if (peInfo.Image64Bit && !gGuest.Guest64)
    {
        ERROR("[ERROR] The provided agent does not match the OS arch: %s bit\n", gGuest.Guest64 ? "64" : "32");
        return INT_STATUS_INVALID_PARAMETER;
    }

    // Schedule the injection
    status = IntWinAgentInject(IntWinDepDeploy, IntWinDepComplete, NULL, NULL, procContent, procSize, agint, AgentTag,
                               AGENT_TYPE_PROCESS, Name, 0, Args, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntAgentInject failed: 0x%08x\n", status);
        return status;
    }

    LOG("[DEPLOYER] Agent with tag %d was scheduled for injection, waiting...\n", AgentTag);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDepInjectFile(
    _In_ PBYTE FileContent,
    _In_ DWORD FileSize,
    _In_ const CHAR *Name
    )
///
/// @brief Inject a file inside the Windows guest.
///
/// This function will inject a file inside the guest. The file will be written inside the %System% folder, so make
/// sure you use a name that will not conflict with potential existing files.
///
/// @param[in]  FileContent     The file contents to be injected.
/// @param[in]  FileSize        The file size.
/// @param[in]  Name            The file name.
///
/// @retval INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    // Schedule the injection
    status = IntWinAgentInject(IntWinDepDeploy, IntWinDepComplete, NULL, NULL, FileContent, FileSize, FALSE, 0,
                               AGENT_TYPE_FILE, Name, 0, NULL, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntAgentInject failed: 0x%08x\n", status);
        return status;
    }

    LOG("[DEPLOYER] File scheduled for injection!\n");

    return INT_STATUS_SUCCESS;
}
