/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "deployer.h"
#include "guests.h"
#include "windeployer.h"
#include "lixdeployer.h"


INTSTATUS
IntDepInjectProcess(
    _In_ DWORD AgentTag,
    _In_opt_ BYTE *AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_ const CHAR *Name,
    _In_opt_ const CHAR *Args
    )
///
/// @brief Injects a process inside the guest.
///
/// This function will inject the provided content inside the guest and it will run it as a process.
/// The provided content must represent a valid executable file.
///
/// @param[in]  AgentTag        The agent tag.
/// @param[in]  AgentContent    The contents of the agent. Must be a valid executable. If NULL, Introcore will check
///                             if it has the contents itself. Normally, only the killer agent and log gather tool
///                             can be injected directly by Introcore, without providing the contents. Their tags are
///                             IG_AGENT_TAG_LOG_GATHER_TOOL and IG_AGENT_TAG_AGENT_KILLER_TOOL.
/// @param[in]  AgentSize       The size of the agent contents.
/// @param[in]  Name            Agent name.
/// @param[in]  Args            Optional arguments to be passed to the agent when starting it inside the guest.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the guest OS is not recognized.
///
{
    LOG("[DEPLOYER] Injecting agent process '%s' command line '%s'\n", Name, Args);

    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinDepInjectProcess(AgentTag, AgentContent, AgentSize, Name, Args);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixDepInjectProcess(AgentTag, AgentContent, AgentSize, Name, Args);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntDepInjectFile(
    _In_ BYTE *FileContent,
    _In_ DWORD FileSize,
    _In_ const CHAR *Name
    )
///
/// @brief Inject a file inside the guest.
///
/// Inject a file inside the guest. The file will be written inside the %YSTEM% folder on Windows,
/// and inside the root folder on Linux. If the file already exists, it will be overwritten, so take
/// great care to avoid overwriting existing/system files!
///
/// @param[in]  FileContent     The file contents.
/// @param[in]  FileSize        The file size.
/// @param[in]  Name            The file name.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the OS is not recognized.
///
{
    LOG("[DEPLOYER] Injecting agent file '%s'\n", Name);

    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinDepInjectFile(FileContent, FileSize, Name);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixDepInjectFile(FileContent, FileSize, Name);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntDepRunCommand(
    _In_ const CHAR *CommandLine
    )
///
/// @brief Run a command inside the guest.
///
/// NOTE: This function can only be called for a Linux guest.
///
/// @param[in]  CommandLine     The command line to be executed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the guest is not Linux.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixDepRunCommand(CommandLine);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }
}
