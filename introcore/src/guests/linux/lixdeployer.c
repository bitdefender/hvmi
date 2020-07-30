/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixdeployer.h"
#include "guests.h"
#include "kernvm.h"
#include "alerts.h"
#include "lixfiles.h"
#include "lixagent_ondemand.h"



static INTSTATUS
IntLixDepComplete(
    _In_ LIX_AGENT *Agent)
{
    LOG("[LIX-DEPLOYER] Agent with tag %d has just been initialized, error: 0x%08x.",
        Agent->TagEx, 0);

    IntLixAgentSendEvent(agentInitialized, Agent->TagEx, 0);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixDepRunCommandComplete(
    _In_ LIX_AGENT *Agent)
{
    LOG("[LIX-DEPLOYER] Agent with tag %d has just been initialized, error: 0x%08x.",
        Agent->TagEx, 0);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixDepGetInternalContent(
    _In_ DWORD Tag,
    _Out_ BYTE **Address,
    _Out_ DWORD *Length)
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    switch (Tag)
    {
    case IG_AGENT_TAG_LOG_GATHER_TOOL:
    {
        *Address = gLixGatherAgentx64;
        *Length = sizeof(gLixGatherAgentx64);

        break;
    }

    case IG_AGENT_TAG_AGENT_KILLER_TOOL:
    {
        *Address = gLixKillerAgentx64;
        *Length = sizeof(gLixKillerAgentx64);

        break;
    }

    default:
    {
        status = IntGetAgentContent(Tag, gGuest.Guest64, Length, Address);
        if (!INT_SUCCESS(status) || (*Address == NULL))
        {
            ERROR("[ERROR] IntGetAgentContent failed with status: 0x%08x.", status);
            return status;
        }

        break;
    }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixDepGetInternalArgs(
    _In_ DWORD Tag,
    _In_ DWORD Length,
    _Out_ char *Args)
{
    switch (Tag)
    {
    case IG_AGENT_TAG_AGENT_KILLER_TOOL:
    {
        INTSTATUS status = IntLixTaskGetAgentsAsCli(Args, Length);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixTaskGetAgentsAsCli failed with status: 0x%08x.", status);
            return status;
        }

        break;
    }

    default:
        ERROR("[LIX-DEPLOYER] Found an invalid agent tag %d ...", Tag);
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixDepDeployFileHypercall(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Writes a chunk of the file into a allocated buffer by the agent.
///
/// This function provide to the agent the number of bytes written.
///
/// @param[in]  Agent The running agent.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT_THREAD *pThread = Agent->Thread;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    DWORD writeLength = 0;
    DWORD maxWriteLength = PAGE_SIZE_2M;

    if (pThread->Content.CurrentOffset == pThread->Content.Size)
    {
        TRACE("[LIX-DEPLOYER] File '%s' deployed.", Agent->Name);
        pRegs->Rax = writeLength;
        goto _exit;
    }
    else if (pThread->Content.Size - pThread->Content.CurrentOffset > maxWriteLength)
    {
        writeLength = maxWriteLength;
    }
    else if (pThread->Content.Size - pThread->Content.CurrentOffset < maxWriteLength)
    {
        writeLength = pThread->Content.Size - pThread->Content.CurrentOffset;
    }

    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                 pRegs->R8,
                                 writeLength,
                                 pThread->Content.Address + pThread->Content.CurrentOffset,
                                 IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemWrite failed with status: 0x%08x.", status);

        pRegs->Rax = (QWORD)(-1);
        goto _exit;
    }

    pThread->Content.CurrentOffset += writeLength;

    pRegs->Rax = writeLength;

_exit:
    status = IntSetGprs(gVcpu->Index, pRegs);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDepInjectFile(
    _In_ BYTE *Content,
    _In_ DWORD Size,
    _In_ const CHAR *Name
    )
///
/// @brief Injects an agent that deploy a file with the provided content and name on the disk.
///
/// This function deploy the file to the root (/) directory. If there's another file with the same name, the existing
/// file will be replaced.
///
/// @param[in]  Content The content of the file.
/// @param[in]  Size    The size of the content.
/// @param[in]  Name    The name of the file.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If the content of the file is null.
/// @retval     INT_STATUS_INVALID_PARAMETER_2      If the size of the file is 0.
/// @retval     INT_STATUS_INVALID_PARAMETER_3      If the name of the file is null.
/// @retval     INT_STATUS_NOT_FOUND                If the handler of the agent is not found.
/// @retval     INT_STATUS_ALREADY_INITIALIZED_HINT If another agent is already running.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT_HANDLER *pHandler = NULL;
    LIX_AGENT_THREAD_DEPLOY_FILE_ARGS *pArgs = NULL;

    if (Content == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Size == 0)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (Name == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pHandler = IntLixAgentThreadGetHandlerByTag(lixAgTagCreateThread, lixAgThreadTagDeployFile);
    if (pHandler == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    pArgs = pHandler->Args.Content;

    pArgs->KernelVersion = gLixGuest->Version.Value;

    if (gGuest.OSVersion < LIX_CREATE_VERSION(3, 0, 0))
    {
        pArgs->Umh.UhmWaitExec = 0;
        pArgs->Umh.UhmWaitProc = 1;
    }
    else
    {
        pArgs->Umh.UhmWaitExec = 1;
        pArgs->Umh.UhmWaitProc = 2;
    }

    strlcpy(pArgs->FilePath.Name, Name, sizeof(pArgs->FilePath.Name));

    status = IntLixAgentThreadInject(lixAgThreadTagDeployFile,
                                     0,
                                     AGENT_TYPE_FILE,
                                     IntLixDepDeployFileHypercall,
                                     IntLixDepComplete,
                                     Name,
                                     Content,
                                     Size);
    if (INT_STATUS_ALREADY_INITIALIZED_HINT == status)
    {
        TRACE("[LIX-DEPLOYER] A file with already running or pending.\n");
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentThreadInject failed with status: 0x%08x\n", status);
        return status;
    }

    LOG("[LIX-DEPLOYER] File '%s' scheduled for injection ...", Name);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDepRunCommand(
    _In_ const CHAR *CommandLine
    )
///
/// @brief Injects an agent that creates a process that will execute the provided command line.
///
/// @param[in]  CommandLine The command line to be executed.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If the command line is null.
/// @retval     INT_STATUS_NOT_FOUND                If the handler of the agent is not found.
/// @retval     INT_STATUS_ALREADY_INITIALIZED_HINT If another agent is already running.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT_HANDLER *pHandler = NULL;
    LIX_AGENT_THREAD_RUN_CLI_ARGS *pArgs = NULL;

    if (CommandLine == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pHandler = IntLixAgentThreadGetHandlerByTag(lixAgTagCreateThread, lixAgThreadTagRunCommand);
    if (pHandler == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    pArgs = pHandler->Args.Content;

    if (gGuest.OSVersion < LIX_CREATE_VERSION(3, 0, 0))
    {
        pArgs->Umh.UhmWaitExec = 0;
        pArgs->Umh.UhmWaitProc = 1;
    }
    else
    {
        pArgs->Umh.UhmWaitExec = 1;
        pArgs->Umh.UhmWaitProc = 2;
    }

    strlcpy(pArgs->Exec.Args, CommandLine, sizeof(pArgs->Exec.Args));

    status = IntLixAgentThreadInject(lixAgThreadTagRunCommand,
                                     0,
                                     AGENT_TYPE_FILE,
                                     NULL,
                                     IntLixDepRunCommandComplete,
                                     NULL,
                                     NULL,
                                     0);
    if (INT_STATUS_ALREADY_INITIALIZED_HINT == status)
    {
        TRACE("[LIX-DEPLOYER] A file already running or pending...\n");
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentThreadInject failed with status: 0x%08x\n", status);
        return status;
    }

    LOG("[LIX-DEPLOYER] Command line '%s' scheduled for execution...", CommandLine);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDepInjectProcess(
    _In_ DWORD AgentTag,
    _In_opt_ BYTE *Content,
    _In_ DWORD Size,
    _In_ const char *Name,
    _In_opt_ const char *Args
    )
///
/// @brief Injects an agent that deploy a file to the disk and creates a process that execute the deployed file.
///
/// This function deploy the file to the root (/) directory. If there's another file with the same name,
/// the existing file will be replaced.
/// The deployed file is the first argument of the newly created process and the next arguments is provided by the
/// caller, if any.
///
/// @param[in]      AgentTag    The tag used by the integrator.
/// @param[in]      Content     The content of the file.
/// @param[in]      Size        The size of the file.
/// @param[in]      Name        The name of the file.
/// @param[in, out] Args        The arguments used by the created process.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_3      If the name of the file is null.
/// @retval     INT_STATUS_NOT_FOUND                If the handler of the agent is not found.
/// @retval     INT_STATUS_NOT_NEEDED_HINT          If the content of the file is empty and we decide that no agent
///                                                 should be deployed.
/// @retval     INT_STATUS_ALREADY_INITIALIZED_HINT If another agent is already running.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT_HANDLER *pHandler = NULL;
    LIX_AGENT_THREAD_DEPLOY_FILE_EXEC_ARGS *pArgs = NULL;
    BYTE *pContent = NULL;
    DWORD contentSize = 0;
    char pArgsLocal[LIX_MAX_PATH] = { 0 };

    TRACE("[LIX-DEPLOYER] Requested to inject agent with tag '%d' ...", AgentTag);

    if (Name == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Content == NULL)
    {
        status = IntLixDepGetInternalContent(AgentTag, &pContent, &contentSize);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixDepGetInternalContent failed with status: 0x%08x.", status);
            return status;
        }

        if (Args == NULL)
        {
            status = IntLixDepGetInternalArgs(AgentTag, sizeof(pArgsLocal), pArgsLocal);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixDepGetInternalArgs failed with status: 0x%08x.", status);
                return status;
            }

            if (strlen(pArgsLocal) == 0)
            {
                return INT_STATUS_NOT_NEEDED_HINT;
            }
        }
        else
        {
            strlcpy(pArgsLocal, Args, sizeof(pArgsLocal));
        }

    }
    else
    {
        pContent = Content;
        contentSize = Size;
        strlcpy(pArgsLocal, Args, sizeof(pArgsLocal));
    }

    if ((pContent == NULL) || (contentSize == 0))
    {
        ERROR("[ERROR] No proper agent found.");
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pHandler = IntLixAgentThreadGetHandlerByTag(lixAgTagCreateThread, lixAgThreadTagDeployFileExec);
    if (pHandler == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    pArgs = pHandler->Args.Content;
    pArgs->KernelVersion = gLixGuest->Version.Value;
    pArgs->FilePathOffset = (QWORD)LIX_FIELD(Ungrouped, FilePath);

    if (gGuest.OSVersion < LIX_CREATE_VERSION(3, 0, 0))
    {
        pArgs->Umh.UhmWaitExec = 0;
        pArgs->Umh.UhmWaitProc = 1;
    }
    else
    {
        pArgs->Umh.UhmWaitExec = 1;
        pArgs->Umh.UhmWaitProc = 2;
    }


    strlcpy(pArgs->FilePath.Name, Name, sizeof(pArgs->FilePath.Name));
    snprintf(pArgs->Exec.Args, LIX_AGENT_MAX_ARGS_LENGTH, "%c%s %s", pArgs->FilePath.Root, Name, pArgsLocal);

    status = IntLixAgentThreadInject(lixAgThreadTagDeployFileExec,
                                     AgentTag,
                                     AGENT_TYPE_PROCESS,
                                     IntLixDepDeployFileHypercall,
                                     IntLixDepComplete,
                                     Name,
                                     pContent,
                                     contentSize);
    if (INT_STATUS_ALREADY_INITIALIZED_HINT == status)
    {
        TRACE("[DEPLOYER] A file already running or pending...\n");
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentThreadInject failed with status: 0x%08x\n", status);
        return status;
    }

    LOG("[LIX-DEPLOYER] File '%s' scheduled for execution using command line '%s' ...", Name, pArgs->Exec.Args);

    return INT_STATUS_SUCCESS;
}
