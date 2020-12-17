/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixagent.h"
#include "alerts.h"
#include "callbacks.h"
#include "glue.h"
#include "guests.h"
#include "hnd_remediation.h"
#include "hnd_loggather.h"
#include "icache.h"
#include "memcloak.h"
#include "slack.h"
#include "lixksym.h"


static INTSTATUS
IntLixAgentCreateThreadHypercall(
    _In_ LIX_AGENT *Agent
    );

static INTSTATUS
IntLixAgentCreateThreadCompletion(
    _In_ LIX_AGENT *Agent
    );


///
/// @brief Describes the name of an injected process agent.
///
/// Whenever a named agent is injected, we allocate such an entry.
/// Whenever a process is created, we check if its name matches the name of an injected agent; if it does, it will
/// be flagged as being an agent. Therefore, it is advisable to use complicated names for the agents, in order
/// to avoid having regular processes marked as agents.
///
typedef struct _LIX_AGENT_NAME
{
    LIST_ENTRY Link;                ///< List entry element.

    LIX_AGENT_TAG AgentTag;         ///< Agent tag.
    DWORD Agid;                     ///< Agent ID.

    char Name[IMAGE_BASE_NAME_LEN]; ///< Image base name.
    size_t Length;                  ///< Name length.

    DWORD RefCount;                 ///< Number of times this name has been used by agents.
} LIX_AGENT_NAME;


///
/// @brief The global agents state.
///
typedef struct _LIX_AGENT_STATE
{
    LIST_HEAD   PendingAgents;          ///< List of agents waiting to be injected.
    LIST_HEAD   AgentNames;             ///< List of agent names.

    LIX_AGENT   *ActiveAgent;           ///< The active agent at any given moment. This is the one.

    DWORD       CompletingAgentsCount;  ///< Number of agents that are yet to complete execution.
    DWORD       CurrentId;              ///< Used to generate unique agent IDs.

    BOOLEAN     SafeToInjectProcess;    ///< Will be true the moment it's safe to inject agents (the OS has booted).
    BOOLEAN     Initialized;            ///< True if the agents state has been initialized.
} LIX_AGENT_STATE;


static LIX_AGENT_STATE gLixAgentState =
{
    .PendingAgents = LIST_HEAD_INIT(gLixAgentState.PendingAgents),
    .AgentNames = LIST_HEAD_INIT(gLixAgentState.AgentNames)
};



static QWORD
IntLixAgentGetToken(
    void
    )
///
/// @brief Randomly select a token to be used by the agent code when issuing hyper calls.
///
/// @retval The selected token.
///
{
    return __rdtsc();
}


static INTSTATUS
IntLixAgentFindInstruction(
    _In_ BYTE MinLen,
    _Out_ QWORD *InstructionVa,
    _Out_ BYTE *InstructionLen,
    _Out_writes_bytes_(ND_MAX_INSTRUCTION_LENGTH) BYTE *InstructionBytes
    )
///
/// @brief Searches for a suitable instruction to replace with a INT3 instruction.
///
/// Will try to find, starting with the SYSCALL/SYSENTER address, the first "STI" instruction and then the first
/// instruction that's at least 5 bytes in length.
///
/// @param[in]  MinLen              Unused.
/// @param[in]  InstructionVa       The guest virtual address where a suitable instruction was found.
/// @param[in]  InstructionLen      The length of the identified instruction.
/// @param[in]  InstructionBytes    Actual instruction bytes.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_INVALID_PARAMETER       If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES  If a memory alloc fails.
///
{
    INTSTATUS status;
    BYTE *pSyscallCode = NULL;
    QWORD syscallGva = 0;
    size_t parsed = 0;
    BYTE stiCount, neededStiCount;
    BOOLEAN bFound, bStiFound;

    UNREFERENCED_LOCAL_VARIABLE(MinLen);

    bFound = bStiFound = FALSE;
    neededStiCount = 1;
    stiCount = 0;

    pSyscallCode = HpAllocWithTag(PAGE_SIZE, IC_TAG_ALLOC);
    if (NULL == pSyscallCode)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    if (LIX_FIELD(Info, HasAlternateSyscall))
    {
        syscallGva = gLixGuest->PropperSyscallGva;
    }
    else
    {
        syscallGva = gLixGuest->SyscallAddress;
    }

    status = IntKernVirtMemRead(syscallGva, PAGE_SIZE, pSyscallCode, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for syscall 0x%016llx: 0x%08x\n", syscallGva, status);
        goto _exit;
    }

    while (parsed + 16 < PAGE_SIZE)
    {
        INSTRUX instrux;

        NDSTATUS ndstatus = NdDecodeEx(&instrux, pSyscallCode + parsed, PAGE_SIZE - parsed, ND_CODE_64, ND_DATA_64);
        if (!ND_SUCCESS(ndstatus))
        {
            ERROR("[ERROR] NdDecodeEx failed at 0x%016llx: 0x%08x\n", syscallGva + parsed, ndstatus);

            status = INT_STATUS_DISASM_ERROR;
            goto _exit;
        }

        if (!bStiFound)
        {
            if (ND_INS_STI == instrux.Instruction)
            {
                if (++stiCount == neededStiCount)
                {
                    bStiFound = TRUE;
                }
            }
        }
        else if ((instrux.Length >= MinLen) && !ND_HAS_PREDICATE(&instrux)) // Avoid conditional instructions.
        {
            bFound = TRUE;

            *InstructionVa = syscallGva + parsed;
            *InstructionLen = instrux.Length;

            memcpy(InstructionBytes, instrux.InstructionBytes, ND_MAX_INSTRUCTION_LENGTH);

            break;
        }

        parsed += instrux.Length;
    }

    if (bFound)
    {
        status = INT_STATUS_SUCCESS;
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
    }

_exit:
    HpFreeAndNullWithTag(&pSyscallCode, IC_TAG_ALLOC);

    return status;
}


static BOOLEAN
IntLixAgentNameIsRunning(
    _In_ const char *Name
    )
///
/// @brief Iterates through all agent names to check if an agent with the provided name is running.
///
/// @param[in]  Name    The name of the agent.
///
/// @retval     True if an agent with the provided name is running, otherwise false.
///
{
    size_t nameLength = MIN(strlen(Name), IMAGE_BASE_NAME_LEN - 1);

    list_for_each (gLixAgentState.AgentNames, LIX_AGENT_NAME, pName)
    {
        if (memcmp_len(pName->Name, Name, pName->Length, nameLength) == 0)
        {
            ERROR("[ERROR] An agent with the name '%s' is already injected!\n", Name);
            return TRUE;
        }
    }

    return FALSE;
}


static INTSTATUS
IntLixAgentNameCreate(
    _In_ const char *Name,
    _In_ DWORD Tag,
    _In_ DWORD Agid,
    _Out_ LIX_AGENT_NAME **AgentName
    )
///
/// @brief  Create an agent name and insert the newly create agent-name to linked list.
///
/// @param[in]  Name        The name of the agent.
/// @param[in]  Tag         The agent tag.
/// @param[in]  Agid        The agent ID.
/// @param[out] AgentName   On success, contains the newly create agent name object.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If a memory alloc fails.
///
{
    LIX_AGENT_NAME *pName = HpAllocWithTag(sizeof(LIX_AGENT_NAME), IC_TAG_AGNN);
    if (pName == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    strlcpy(pName->Name, Name, sizeof(pName->Name));
    pName->Length = strlen(pName->Name);
    pName->Agid = Agid;
    pName->AgentTag = Tag;
    pName->RefCount = 0;

    *AgentName = pName;

    InsertTailList(&gLixAgentState.AgentNames, &pName->Link);

    return INT_STATUS_SUCCESS;
}


static void
IntLixAgentNameRemove(
    _In_ LIX_AGENT_NAME *Name
    )
///
/// @brief  Frees and removes from our list the provided #LIX_AGENT_NAME.
///
/// @param[in]  Name    The agent-name entry.
///
{
    RemoveEntryList(&Name->Link);
    HpFreeAndNullWithTag(&Name, IC_TAG_AGNN);
}


void
IntLixAgentNameRemoveByAgid(
    _In_ DWORD Agid
    )
///
/// @brief Iterates through all agent names and removes the entry that contains the provided ID.
///
/// @param[in]  Agid    The agent ID.
///
{
    if (IsListEmpty(&gLixAgentState.AgentNames))
    {
        return;
    }

    list_for_each (gLixAgentState.AgentNames, LIX_AGENT_NAME, pName)
    {
        if (Agid == pName->Agid)
        {
            IntLixAgentNameRemove(pName);

            return;
        }
    }
}


DWORD
IntLixAgentNameGetTagByAgid(
    _In_ DWORD Agid
    )
///
/// @brief Iterates through all agent names and returns the tag of the agent that has the provided agent ID.
///
/// @param[in]  Agid    The agent ID.
///
/// @retval   The tag of the agent that has the provided agent ID.
///
{
    if (IsListEmpty(&gLixAgentState.AgentNames))
    {
        return lixAgTagNone;
    }

    list_for_each (gLixAgentState.AgentNames, LIX_AGENT_NAME, pName)
    {
        if (Agid == pName->Agid)
        {
            return pName->AgentTag;
        }
    }

    return lixAgTagNone;
}


static INTSTATUS
IntLixAgentThreadFree(
    _In_ LIX_AGENT_THREAD *Thread
    )
///
/// @brief Remove the provided agent-thread.
///
/// Frees the data allocated by the thread-agent and the thread-agent entry.
///
/// @param[in]  Thread The agent-thread entry.
///
/// @retval INT_STATUS_SUCCESS On success.
///
{
    if (Thread->Data.Code != NULL)
    {
        HpFreeAndNullWithTag(&Thread->Data.Code, IC_TAG_LAGE);
    }

    if (Thread->Content.Address)
    {
        IntReleaseBuffer(Thread->Content.Address, Thread->Content.Size);
    }

    HpFreeAndNullWithTag(&Thread, IC_TAG_LAGE);

    return INT_STATUS_SUCCESS;
}


static void
IntLixAgentFree(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Remove the provided agent.
///
/// If the provided agent has a thread-agent assigned, the thread-agent entry is removed.
/// If the agent used slack memory, it is freed and the code of the agent is over-written with 'NOP' instructions.
/// Frees the data allocated by the agent and the agent entry.
///
/// @param[in]  Agent The agent entry.
///
{
    INTSTATUS status;
    BYTE *pSlack = NULL;

    if (Agent == NULL)
    {
        return;
    }

    if (Agent->Data.Address == 0)
    {
        goto _exit;
    }

    status = IntSlackFree(Agent->Data.Address);
    if (status == INT_STATUS_NOT_FOUND)
    {
        goto _exit;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSlackFree failed with status: 0x%08x.", status);
    }

    status = IntVirtMemMap(Agent->Data.Address, Agent->Data.Size, gGuest.Mm.SystemCr3, 0, &pSlack);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed with status: 0x%08x. Cannot fill slack with NOPs...", status);
    }
    else
    {
        memset(pSlack, 0x90, Agent->Data.Size);
        IntVirtMemUnmap(&pSlack);
    }

_exit:
    if (Agent->Thread)
    {
        IntLixAgentThreadFree(Agent->Thread);
        Agent->Thread = NULL;
    }

    if (Agent->Data.Code)
    {
        HpFreeAndNullWithTag(&Agent->Data.Code, IC_TAG_LAGE);
    }

    HpFreeAndNullWithTag(&Agent, IC_TAG_LAGE);
}


static INTSTATUS
IntLixAgentFillDataFromMemory(
    _Inout_ LIX_AGENT_DATA *Data,
    _In_ LIX_AGENT_TAG Tag
    )
///
/// @brief Fetch the content of the agent with the provided #LIX_AGENT_TAG from memory.
///
/// Read the #LIX_AGENT_HEADER from guest (deployed by the 'init' agent) and checks if the provided Tag is equal with
/// Header->Tag; if true the information required by the agent is gathered (Data->Header, Data->Code, Data->Address,
/// Data->Size), otherwise the next header is read.
///
/// @param[in]          Data    The data that contains information about the agent code/data from guest.
/// @param[in]          Tag     The #LIX_AGENT_TAG identifier of the agent.
///
/// @retval INT_STATUS_SUCCESS                  On success.
/// @retval INT_STATUS_NOT_FOUND                If the entry with the provided tag is not found.
/// @retval INT_STATUS_INSUFFICIENT_RESOURCES   If the memory alloc fails.
///
{
    QWORD crtAddress = gLixGuest->MmAlloc.Agent.Address;

    while (crtAddress <= gLixGuest->MmAlloc.Agent.Address + gLixGuest->MmAlloc.Agent.Length)
    {
        INTSTATUS status;
        LIX_AGENT_HEADER header = { 0 };

        status = IntVirtMemRead(crtAddress,
                                sizeof(LIX_AGENT_HEADER),
                                gGuest.Mm.SystemCr3,
                                &header,
                                NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemRead failed with status: 0x%08x.", status);
            return status;
        }

        if (header.Tag == (DWORD)(Tag))
        {
            Data->Code = HpAllocWithTag((size_t)header.CodeSize + header.DataSize, IC_TAG_LAGE);
            if (Data->Code == NULL)
            {
                return INT_STATUS_INSUFFICIENT_RESOURCES;
            }

            memcpy(&Data->Header, &header, sizeof(LIX_AGENT_HEADER));

            status = IntVirtMemRead(crtAddress,
                                    header.CodeSize + header.DataSize,
                                    gGuest.Mm.SystemCr3,
                                    Data->Code,
                                    NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemRead failed with status: 0x%08x.", status);
                return status;
            }

            Data->Address = crtAddress;
            Data->Size = header.CodeSize + header.DataSize;

            return INT_STATUS_SUCCESS;
        }

        crtAddress += (QWORD)header.CodeSize + header.DataSize;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixAgentFillDataFromHandler(
    _Inout_ LIX_AGENT_DATA *Data,
    _In_ LIX_AGENT_HANDLER *Handler
    )
///
/// @brief Fetch the content of the agent with the provided #LIX_AGENT_TAG from the corresponding #LIX_AGENT_HANDLER
/// structure.
///
/// The handlers are located in the lixaghnd.c file.
///
/// @param[in]          Data    The data that contains information about the agent code/data from guest.
/// @param[in]          Handler The #LIX_AGENT_HANDLER structure corresponding to the current agent.
///
/// @retval INT_STATUS_SUCCESS                  On success.
/// @retval INT_STATUS_INSUFFICIENT_RESOURCES   If the memory alloc fails.
///
{
    Data->Code = HpAllocWithTag(Handler->Code.Length, IC_TAG_LAGE);
    if (Data->Code == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(Data->Code, Handler->Code.Content, Handler->Code.Length);
    memcpy(&Data->Header, Handler->Code.Content, sizeof(LIX_AGENT_HEADER));

    Data->Size = Handler->Code.Length;
    Data->Address = 0;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentFillData(
    _Inout_ LIX_AGENT_DATA *Data,
    _In_ LIX_AGENT_HANDLER *Handler
    )
///
/// @brief Fetch the content of the agent.
///
/// The function calls the corresponding function (#IntLixAgentFillDataFromHandler/#IntLixAgentFillDataFromMemory) to
/// fetch the information.
///
/// @param[in]          Data    The data that contains information about the agent code/data from guest.
/// @param[in]          Handler The #LIX_AGENT_HANDLER structure corresponding to the current agent.
///
/// @retval INT_STATUS_SUCCESS                  On success.
/// @retval INT_STATUS_INSUFFICIENT_RESOURCES   If the memory alloc fails.
///
{
    if (Handler->Code.Length != 0)
    {
        return IntLixAgentFillDataFromHandler(Data, Handler);
    }
    else
    {
        return IntLixAgentFillDataFromMemory(Data, Handler->Tag);
    }
}


__forceinline BOOLEAN
IntLixAgentMatchVersion(
    _In_ LIX_AGENT_FUNCTIONS *Function
    )
///
/// @brief Checks if the provided #LIX_AGENT_FUNCTIONS match the current guest version.
///
/// @param[in]  Function    Contains a list of function required by the current agent.
///
/// @retval     True if the #LIX_AGENT_FUNCTIONS version matches the current guest version, otherwise false.
///
{
    return ((Function->Version.Version == gLixGuest->Version.Version ||
             Function->Version.Version == BYTE_MAX) &&
            (Function->Version.Patch == gLixGuest->Version.Patch ||
             Function->Version.Patch == BYTE_MAX) &&
            (Function->Version.Sublevel == gLixGuest->Version.Sublevel ||
             Function->Version.Sublevel == WORD_MAX) &&
            (Function->Version.Backport == gLixGuest->Version.Backport ||
             Function->Version.Backport == WORD_MAX));
}


static INTSTATUS
IntLixAgentResolveOffset(
    _In_ LIX_AGENT_DATA *Data,
    _In_ LIX_AGENT_HANDLER *Handler
    )
///
/// @brief Search the functions and complete the args/tokens required by the agent.
///
/// This function fill the external data of the agent:
///
/// 1. Copy the hypercall/completion/error tokens to the agent code/data buffer.
///
/// 2. Each function name is assigned to a list that contains the number of the functions and the required functions
/// by the agent, because on different kernel versions a function has different signature but the purpose of it is the
/// same. For example on kernel version 2.6.x, to write a file from kernel the 'kernel_write' function is used and on
/// kernel version 4.x.x the '__kernel_write' function is used, and that's why we search the both function. For that
/// example the required field is set to 1 and the count is set to 2 -> only one function must be found.
///
/// If the any #LIX_AGENT_FUNCTIONS match the current guest version, then for each entry that contains a function name,
/// #IntKsymFindByName is called to get the address; if the kallsym is found the address is copied to the agent buffer,
/// otherwise the 'NULL' value is copied.
///
/// 3. Copy the provided arguments to the agent code/data buffer.
///
/// @param[in]      Data    The data that contains information about the agent code/data from guest.
/// @param[in]      Handler The #LIX_AGENT_HANDLER structure corresponding to the current agent.
///
/// @retval INT_STATUS_SUCCESS          On success.
/// @retval INT_STATUS_NOT_FOUND        If the #LIX_AGENT_FUNCTIONS data is not found or if the function address is not
///                                     found.
///
{
    LIX_AGENT_FUNCTIONS *pFunctions = NULL;
    DWORD currentFunc = 0;

    memcpy(&Data->Code[sizeof(LIX_AGENT_HEADER)], &Data->Token, sizeof(LIX_AGENT_TOKEN));

    for (DWORD index = 0; index < Handler->Functions.Count; index++)
    {
        if (IntLixAgentMatchVersion(&Handler->Functions.Content[index]))
        {
            pFunctions = &Handler->Functions.Content[index];
            break;
        }
    }

    if (pFunctions == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    for (DWORD index = 0; index < pFunctions->Count; index++)
    {
        DWORD required = pFunctions->List[index].Required;
        DWORD match = 0;
        for (DWORD item = 0; item < pFunctions->List[index].Count; item++)
        {
            QWORD kallsymAddr = IntKsymFindByName(pFunctions->List[index].Name[item], NULL);
            if (kallsymAddr)
            {
                TRACE("[LIX-AGENT] Found '%s' ksym @ 0x%16llx.", pFunctions->List[index].Name[item], kallsymAddr);
                match++;
            }
            else
            {
                kallsymAddr = 0;
                WARNING("[WARNING] IntLixGuestFindKsymByName failed for `%s`\n", pFunctions->List[index].Name[item]);
            }

            *(QWORD *)(&Data->Code[sizeof(LIX_AGENT_HEADER) +
                       sizeof(LIX_AGENT_TOKEN) + sizeof(QWORD) * currentFunc]) = kallsymAddr;
            currentFunc++;
        }

        if (required > match)
        {
            ERROR("[ERROR] Failed to find required kallsyms for agent.\n");
            return INT_STATUS_NOT_FOUND;
        }
    }

    memcpy(&Data->Code[sizeof(LIX_AGENT_HEADER) + sizeof(LIX_AGENT_TOKEN) + sizeof(QWORD) * currentFunc],
           Handler->Args.Content, Handler->Args.Length);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentAllocate(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Allocate a memory zone for the content of the agent.
///
/// This function check if the provided agent has an address assigned; if the agent address is NULL, #IntSlackAlloc
/// is called.
///
/// This slack memory is used only for the 'init'/'uninit' agents.
///
/// @param[in]  Agent    The current agent structure.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    if (Agent->Data.Address == 0)
    {
        INTSTATUS status = IntSlackAlloc(gGuest.KernelVa, FALSE, Agent->Data.Size, &Agent->Data.Address, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSlackAlloc failed with status: 0x%08x.", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


__forceinline static DWORD
IntLixAgentGetId(
    void
    )
///
/// @brief  Generate a new ID.
///
/// @retval The newly generated ID.
///
{
    return gLixAgentState.CurrentId++;
}


static INTSTATUS
IntLixAgentCreate(
    _In_ LIX_AGENT_TAG Tag,
    _In_ DWORD TagEx,
    _In_opt_ PFUNC_AgentCallbackHypercall HypercallCallback,
    _In_opt_ PFUNC_AgentCallbackCompletion CompletionCallback,
    _Out_ LIX_AGENT **Agent
    )
///
/// @brief Create an agent entry.
///
/// This function allocates a #LIX_AGENT entry and fill the required information.
///
/// Function #IntLixAgentGetToken is called to generate tokens for hypercall/completion/error.
/// Function #IntLixAgentFillData is called to gather the agent code/data.
/// Function #IntLixAgentResolveOffset is called to fill the agent code/data buffer with the information gathered
/// before.
///
/// @param[in]      Tag                 The internal #LIX_AGENT_TAG of the agent.
/// @param[in]      TagEx               The tag provided by the integrator.
/// @param[in]      HypercallCallback   This callback can be called during the agent execution.
/// @param[in]      CompletionCallback  This callback is called when the agent has finished execution.
/// @param[out]     Agent               On success, contains the handle to the newly created agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_FOUND               If the #LIX_AGENT_HANDLER is not found.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the memory alloc fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT *pAgent = NULL;
    LIX_AGENT_HANDLER *pHandler = NULL;

    TRACE("[LIX-AGENT] Create agent with tag %d ...", Tag);

    pHandler = IntLixAgentGetHandlerByTag(Tag);
    if (pHandler == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    pAgent = HpAllocWithTag(sizeof(LIX_AGENT), IC_TAG_LAGE);
    if (pAgent == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pAgent->Data.Token.Completion = IntLixAgentGetToken();
    pAgent->Data.Token.Hypercall = IntLixAgentGetToken();
    pAgent->Data.Token.Error = IntLixAgentGetToken();

    status = IntLixAgentFillData(&pAgent->Data, pHandler);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentFillContent failed: 0x%x", status);
        goto _free_and_exit;
    }

    status = IntLixAgentResolveOffset(&pAgent->Data, pHandler);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentResolveOffset failed: 0x%x", status);
        goto _free_and_exit;
    }

    pAgent->Tag = Tag;
    pAgent->TagEx = TagEx;
    pAgent->HypercallType = pHandler->HypercallType;
    pAgent->Callback.Hypercall = HypercallCallback;
    pAgent->Callback.Completion = CompletionCallback;
    pAgent->Instruction.CloakHandle = NULL;
    pAgent->Instruction.Address = 0;
    pAgent->Instruction.Length = 0;
    pAgent->Instruction.Restored = TRUE;
    pAgent->Agid = IntLixAgentGetId();

    *Agent = pAgent;

    return INT_STATUS_SUCCESS;

_free_and_exit:
    HpFreeAndNullWithTag(&pAgent, IC_TAG_LAGE);

    return status;
}


static INTSTATUS
IntLixAgentThreadCreate(
    _In_ LIX_AGENT_TAG Tag,
    _In_opt_ PFUNC_AgentCallbackHypercall HypercallCallback,
    _In_opt_ PFUNC_AgentCallbackCompletion CompletionCallback,
    _In_opt_ BYTE *ContentAddress,
    _In_opt_ DWORD ContentSize,
    _Out_ LIX_AGENT_THREAD **Thread
    )
///
/// @brief Create an agent-thread entry.
///
/// This function allocates a #LIX_AGENT_THREAD entry and fill the required information.
///
/// Function #IntLixAgentGetToken is called to generate tokens for hypercall/completion/error.
/// Function #IntLixAgentFillData is called to gather the agent code/data.
/// Function #IntLixAgentResolveOffset is called to fill the agent code/data buffer with the information gathered
/// before.
///
/// @param[in]      Tag                 The internal #LIX_AGENT_TAG of the agent.
/// @param[in]      HypercallCallback   This callback can be called during the agent execution.
/// @param[in]      CompletionCallback  This callback is called when the agent has finished execution.
/// @param[in]      ContentAddress      Pointer to a memory area containing the actual agent.
/// @param[in]      ContentSize         The size of the agent, in bytes.
/// @param[out]     Thread              On success, contains the handle to the newly created agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_FOUND               If the #LIX_AGENT_HANDLER is not found.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the memory alloc fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT_THREAD *pThread = NULL;
    LIX_AGENT_HANDLER *pHandler = NULL;

    pHandler = IntLixAgentThreadGetHandlerByTag(lixAgTagCreateThread, Tag);
    if (pHandler == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    pThread = HpAllocWithTag(sizeof(LIX_AGENT_THREAD), IC_TAG_LAGE);
    if (pThread == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pThread->Data.Token.Completion = IntLixAgentGetToken();
    pThread->Data.Token.Hypercall = IntLixAgentGetToken();
    pThread->Data.Token.Error = IntLixAgentGetToken();

    status = IntLixAgentFillData(&pThread->Data, pHandler);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentFillContent failed: 0x%x", status);
        goto _free_and_exit;
    }

    status = IntLixAgentResolveOffset(&pThread->Data, pHandler);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentResolveOffset failed: 0x%x", status);
        goto _free_and_exit;
    }

    pThread->Tag = Tag;
    pThread->HypercallType = pHandler->HypercallType;
    pThread->Callback.Hypercall = HypercallCallback;
    pThread->Callback.Completion = CompletionCallback;
    pThread->Content.Address = ContentAddress;
    pThread->Content.Size = ContentSize;

    *Thread = pThread;

    return INT_STATUS_SUCCESS;

_free_and_exit:
    HpFreeAndNullWithTag(&pThread, IC_TAG_LAGE);

    return status;
}


INTSTATUS
IntLixAgentInject(
    _In_ LIX_AGENT_TAG Tag,
    _In_opt_ PFUNC_AgentCallbackHypercall HypercallCallback,
    _In_opt_ PFUNC_AgentCallbackCompletion CompletionCallback
    )
///
/// @brief Schedule an agent injection inside the guest.
///
/// This function schedule the injection of an agent identified by the #LIX_AGENT_TAG inside the guest space.
/// This function is used directly only for internal agents (init/uninit).
///
/// @param[in]      Tag                 The internal #LIX_AGENT_TAG of the agent.
/// @param[in]      HypercallCallback   This callback can be called during the agent execution.
/// @param[in]      CompletionCallback  This callback is called when the agent has finished execution.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED         If the agent state is not initialized.
/// @retval     #INT_STATUS_NOT_FOUND               If the #LIX_AGENT_HANDLER is not found.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the memory alloc fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT *pAgent = NULL;

    if (!gLixAgentState.Initialized)
    {
        WARNING("[WARNING] Tried to create an agent but the agent state not initialized.");
        return INT_STATUS_NOT_INITIALIZED;
    }

    status = IntLixAgentCreate(Tag, 0, HypercallCallback, CompletionCallback, &pAgent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentCreateAgent failed with status: 0x%08x.", status);
        goto _exit;
    }

    InsertTailList(&gLixAgentState.PendingAgents, &pAgent->Link);

    TRACE("[AGENT] Linux agent allocated and initialized!\n");

    status = IntLixAgentActivatePendingAgent();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentActivatePendingAgent failed with status: 0x%08x.", status);
        return status;
    }

    return INT_STATUS_SUCCESS;

_exit:
    IntLixAgentFree(pAgent);

    return status;
}


INTSTATUS
IntLixAgentThreadInject(
    _In_ LIX_AGENT_TAG Tag,
    _In_ DWORD TagEx,
    _In_ AGENT_TYPE AgentType,
    _In_opt_ PFUNC_AgentCallbackHypercall HypercallCallback,
    _In_opt_ PFUNC_AgentCallbackCompletion CompletionCallback,
    _In_opt_ const char *Name,
    _In_opt_ BYTE *ContentAddress,
    _In_ DWORD ContentSize
    )
///
/// @brief Schedule an thread-agent injection inside the guest.
///
/// A thread-agent is a bootstrap that creates a kthread and allocate a zone of memory; the provided content is copied
/// to the allocated memory zone and the kthread will execute the deployed content.
///
/// This function schedule the injection of an thread-agent identified by the #LIX_AGENT_TAG inside the guest space.
///
/// @param[in]      Tag                 The internal #LIX_AGENT_TAG of the agent.
/// @param[in]      TagEx               The tag provided by the integrator.
/// @param[in]      AgentType           The type of the injected agent (#AGENT_TYPE).
/// @param[in]      HypercallCallback   This callback can be called during the agent execution.
/// @param[in]      CompletionCallback  This callback is called when the agent has finished execution.
/// @param[in]      Name                The agent name.
/// @param[in]      ContentAddress      Pointer to a memory area containing the actual agent.
/// @param[in]      ContentSize         The size of the agent, in bytes.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED         If the agent state is not initialized; if is not safe to inject the
///                                                 agent; if the bootstrap agent data/code is not deployed yet.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED     If an agent with the same name is already running.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the memory alloc fails.
///
{
    INTSTATUS status;
    LIX_AGENT *pAgent = NULL;
    LIX_AGENT_NAME *pName = NULL;

    if (!gLixAgentState.Initialized)
    {
        WARNING("[WARNING] Tried to create an agent but the agent state not initialized.");
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (!gLixGuest->MmAlloc.Agent.Initialized)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }


    if (!gLixAgentState.SafeToInjectProcess)
    {
        WARNING("[WARNING] Tried to create an agent but the agent state not initialized.");
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (Name != NULL && IntLixAgentNameIsRunning(Name))
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    status = IntLixAgentCreate(lixAgTagCreateThread,
                               TagEx,
                               IntLixAgentCreateThreadHypercall,
                               IntLixAgentCreateThreadCompletion,
                               &pAgent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentCreateAgent failed with status: 0x%08x.", status);
        goto _exit;
    }

    status = IntLixAgentThreadCreate(Tag,
                                     HypercallCallback,
                                     CompletionCallback,
                                     ContentAddress,
                                     ContentSize,
                                     &pAgent->Thread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentThreadCreate failed with status: 0x%08x.", status);
        goto _exit;
    }

    if (Name != NULL)
    {
        strlcpy(pAgent->Name, Name, sizeof(pAgent->Name));

        if (AgentType == AGENT_TYPE_PROCESS)
        {
            status = IntLixAgentNameCreate(Name, pAgent->TagEx, pAgent->Agid, &pName);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixAgentNameCreate failed with status: 0x%08x.", status);
                goto _exit;
            }
        }
    }

    InsertTailList(&gLixAgentState.PendingAgents, &pAgent->Link);

    TRACE("[AGENT] Linux agent allocated and initialized!\n");

    status = IntLixAgentActivatePendingAgent();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentActivatePendingAgent failed with status: 0x%08x.", status);
        return status;
    }

    return INT_STATUS_SUCCESS;

_exit:
    if (pAgent != NULL)
    {
        IntLixAgentFree(pAgent);
    }

    if (pName != NULL)
    {
        IntLixAgentNameRemove(pName);
    }

    return status;
}


INTSTATUS
IntLixAgentActivatePendingAgent(
    void
    )
///
/// @brief Activates a pending agent that waits to be injected.
///
/// The steps required to activate a pending agent are:
///     - allocate slack space (used by init/uninit agents) if the agent is not already deployed.
///     - deploy the agent buffer that contains all the required data resolved (function addresses, args, tokens).
///     - find a suitable instruction of length 1
///     - replace the instruction with a INT3 instruction
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED         If is not safe to inject the agent;
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If no agent waits to be injected; if an agent is already running.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED     If an agent with the same name is already running.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the memory alloc fails.
///
{
    INTSTATUS status;
    LIX_AGENT *pAgent = NULL;
    BYTE instrux[ND_MAX_INSTRUCTION_LENGTH];

    if (!gLixAgentState.SafeToInjectProcess)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (gLixAgentState.CompletingAgentsCount != 0)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (IsListEmpty(&gLixAgentState.PendingAgents))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pAgent = CONTAINING_RECORD(gLixAgentState.PendingAgents.Flink, LIX_AGENT, Link);
    memset(&instrux, 0x90, sizeof(instrux));

    TRACE("[LIX-AGENT] Found pending agent with tag %d.", pAgent->Tag);

    IntPauseVcpus();

    status = IntEnableBreakpointNotifications();
    if (!INT_SUCCESS(status))
    {
        goto _exit;
    }

    status = IntLixAgentFindInstruction(1, &pAgent->Instruction.Address, &pAgent->Instruction.Length,
                                        pAgent->Instruction.Bytes);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntAgentFindInstruction failed with status: 0x%08x\n", status);
        goto _exit;
    }

    status = IntLixAgentAllocate(pAgent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[LIX-AGENT] IntLixAgentAllocate failed with status: 0x%08x.", status);
        goto _exit;
    }

    // The agent is Introcore allocated, so it's safe to use IntKernVirtMemWrite instead of IntVirtMemSafeWrite.
    status = IntKernVirtMemWrite(pAgent->Data.Address, pAgent->Data.Size, pAgent->Data.Code);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed with status: 0x%x", status);
        goto _exit;
    }

    instrux[0] = 0xCC;
    status = IntMemClkCloakRegion(pAgent->Instruction.Address,
                                  0,
                                  pAgent->Instruction.Length,
                                  MEMCLOAK_OPT_APPLY_PATCH,
                                  pAgent->Instruction.Bytes,
                                  instrux,
                                  NULL,
                                  &pAgent->Instruction.CloakHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed cloaking region 0x%016llx: 0x%08x\n", pAgent->Instruction.Address, status);
        goto _exit;
    }

    pAgent->Instruction.Restored = FALSE;

    IntIcFlushAddress(gGuest.InstructionCache, pAgent->Instruction.Address, IC_ANY_VAS);

    TRACE("[LIX-AGENT] Agent with tag %d deployed...", pAgent->Tag);

    RemoveEntryList(&pAgent->Link);

    gLixAgentState.CompletingAgentsCount++;
    gLixAgentState.ActiveAgent = pAgent;

    status = INT_STATUS_SUCCESS;

_exit:
    IntResumeVcpus();

    return status;
}


static INTSTATUS
IntLixAgentError(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called when an error occurred while the running the current agent.
///
/// This function dumps the information about the error, send an event that contains the error and remove the name of
/// the agent from the #LIX_AGENT_NAME list.
///
/// @param[in]  Agent   The active agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
///
{
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
#ifdef DEBUG
    INTSTATUS status = INT_STATUS_SUCCESS;
    char ksymbol[LIX_SYMBOL_NAME_LEN] = {0};

    ERROR("[ERROR] Error occurred while running the agent with tag '%d' (%d)...", Agent->Tag, Agent->TagEx);

    status = IntKsymFindByAddress(pRegs->R8, sizeof(ksymbol), ksymbol, NULL, NULL);
    if (INT_SUCCESS(status))
    {
        LOG("[LIX-AGENT] '%s' failed with status: %llx", ksymbol, pRegs->R9);
    }

    IntDumpArchRegs(pRegs);
#endif

    IntLixAgentSendEvent(agentError, Agent->TagEx, (DWORD)(pRegs->R15));

    IntLixAgentNameRemoveByAgid(Agent->Agid);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentStart(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called when the INT3 instruction from SYSCALL is hit.
///
/// The function unlocks the replaced instruction from SYSCALL and set the RIP to our agent memory zone.
///
/// @param[in]  Agent   The active agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NO_DETOUR_EMU           The callbacks mechanism should not emulate the current instruction.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;

    status = IntMemClkUncloakRegion(Agent->Instruction.CloakHandle, MEMCLOAK_OPT_APPLY_PATCH);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkUncloakRegion failed with status: 0x%08x\n", status);
        IntEnterDebugger();
    }

    Agent->Instruction.CloakHandle = NULL;
    Agent->Instruction.Restored = TRUE;

    pRegs->Rip = Agent->Data.Address + Agent->Data.Header.DataSize;

    TRACE("[LIX-AGENT] Deployed agent @ 0x%llx and entry point @ %llx", Agent->Data.Address, pRegs->Rip);

    status = IntSetGprs(gVcpu->Index, pRegs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed with status: 0x%08x.\n", status);
        ERROR("[ERROR] Remove agent with tag '%d' (%d) ...", Agent->Tag, Agent->TagEx);

        IntLixAgentSendEvent(agentError, Agent->TagEx, 0);
        IntLixAgentFree(Agent);

        return INT_STATUS_NO_DETOUR_EMU;
    }

    LOG("[LIX-AGENT] Agent with tag '%d' (%d) start execution on VCPU %d at RIP %llx ...",
        Agent->Tag, Agent->TagEx, gVcpu->Index, pRegs->Rip);

    return INT_STATUS_NO_DETOUR_EMU;
}


static INTSTATUS
IntLixAgentExit(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called when the agent is terminating.
///
/// The function set the RIP to the instruction from SYSCALL that was replaced.
/// The current agent is removed and a waiting agent is scheduled.
///
/// @param[in]  Agent   The active agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NO_DETOUR_EMU           The callbacks mechanism should not emulate the current instruction.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;

    if (!Agent->Instruction.Restored)
    {
        ERROR("[LIX-AGENT] Original instruction not restored at exit stage...");
        IntEnterDebugger();
    }

    pRegs->Rip = Agent->Instruction.Address;

    status = IntSetGprs(gVcpu->Index, pRegs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        IntEnterDebugger();
    }

    if (Agent->Thread == NULL)
    {
        gLixAgentState.ActiveAgent = NULL;
        gLixAgentState.CompletingAgentsCount--;

        IntDisableBreakpointNotifications();

        IntLixAgentFree(Agent);

        if (!INT_SUCCESS(IntLixAgentActivatePendingAgent()))
        {
            ERROR("[ERROR] IntAgentActivatePendingAgent failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_NO_DETOUR_EMU;
}


static INTSTATUS
IntLixAgentHandleBreakpoint(
    _In_ LIX_AGENT *Agent,
    _In_ QWORD Rip
    )
///
/// @brief Called when a INT3 instruction from the current running agent is hit.
///
/// This function calls the proper function to dispatch the breakpoint.
///
/// @param[in]  Agent   The active agent.
/// @param[in]  Rip     The address of the INT3 instruction.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_FOUND               If the breakpoint is generated from an unrecognized RIP.
///
{
    INTSTATUS status;
    QWORD token = gVcpu->Regs.Rax;

    if (Agent->Data.Token.Hypercall == token)
    {
        if (Agent->Callback.Hypercall == NULL)
        {
            return INT_STATUS_SUCCESS;
        }

        status = Agent->Callback.Hypercall(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] Agent callback failed with status %0x08x.", status);
        }

        return status;
    }

    if (Agent->Data.Token.Completion == token)
    {
        if (Agent->Callback.Completion == NULL)
        {
            return INT_STATUS_SUCCESS;
        }

        status = Agent->Callback.Completion(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] Agent callback failed with status %0x08x.", status);
        }

        return status;
    }

    if (Agent->Data.Token.Error == token)
    {
        status = IntLixAgentError(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] IntLixAgentError failed with status: 0x%08x.", status);
        }

        return status;
    }

    if (Rip == (Agent->Data.Address + Agent->Data.Header.ExitOffset))
    {
        status = IntLixAgentExit(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] IntLixAgentExit failed with status: 0x%08x.", status);
        }

        return status;
    }

    ERROR("[ERROR] Breakpoint generated an exit from unrecognized rip ...");
    IntDumpArchRegs(&gVcpu->Regs);

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixAgentThreadError(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called when an error occurred while the running the current thread-agent.
///
/// This function dumps the information about the error, send an event that contains the error and remove the name of
/// the agent from the #LIX_AGENT_NAME list.
///
/// @param[in]  Agent   The active agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
///
{
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
#ifdef DEBUG
    INTSTATUS status = INT_STATUS_SUCCESS;
    char ksymbol[LIX_SYMBOL_NAME_LEN] = {0};

    ERROR("[ERROR] Error occurred while running the agent-thread with tag '%d' (%d)...",
          Agent->Thread->Tag, Agent->TagEx);

    status = IntKsymFindByAddress(pRegs->R8, sizeof(ksymbol), ksymbol, NULL, NULL);
    if (INT_SUCCESS(status))
    {
        LOG("[LIX-AGENT] '%s' failed with status: %llx", ksymbol, pRegs->R9);
    }

    IntDumpArchRegs(pRegs);
#endif

    IntLixAgentSendEvent(agentError, Agent->TagEx, (DWORD)(pRegs->R9));

    IntLixAgentNameRemoveByAgid(Agent->Agid);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentThreadExit(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called when the thread-agent is terminating.
///
/// The function set the RIP to the instruction from SYSCALL that was replaced.
/// The current agent is removed and a waiting agent is scheduled.
///
/// @param[in]  Agent   The active agent.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NO_DETOUR_EMU           The callbacks mechanism should not emulate the current instruction.
///
{
    LOG("[LIX-AGENT] Agent-thread with tag '%d' (%d) completed ...", Agent->Thread->Tag, Agent->TagEx);

    gLixAgentState.ActiveAgent = NULL;
    gLixAgentState.CompletingAgentsCount--;

    IntLixAgentFree(Agent);

    IntDisableBreakpointNotifications();

    if (!INT_SUCCESS(IntLixAgentActivatePendingAgent()))
    {
        ERROR("[ERROR] IntAgentActivatePendingAgent failed");
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentThreadHandleBreakpoint(
    _In_ LIX_AGENT *Agent,
    _In_ QWORD Rip
    )
///
/// @brief Called when a INT3 instruction from the current running thread-agent is hit.
///
/// This function calls the proper function to dispatch the breakpoint.
///
/// @param[in]  Agent   The active agent.
/// @param[in]  Rip     The address of the INT3 instruction.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_FOUND               If the breakpoint is generated from an unrecognized RIP.
///
{
    INTSTATUS status;
    LIX_AGENT_THREAD *pThread = Agent->Thread;
    QWORD token = gVcpu->Regs.Rax;

    if (pThread->Data.Token.Hypercall == token)
    {
        if (pThread->Callback.Hypercall == NULL)
        {
            return INT_STATUS_SUCCESS;
        }

        status = pThread->Callback.Hypercall(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] Agent callback failed with status %0x08x.", status);
        }

        return status;
    }

    if (pThread->Data.Token.Completion == token)
    {
        if (pThread->Callback.Completion == NULL)
        {
            return INT_STATUS_SUCCESS;
        }

        status = pThread->Callback.Completion(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] Agent callback failed with status %0x08x.", status);
        }

        return status;
    }

    if (pThread->Data.Token.Error == token)
    {
        status = IntLixAgentThreadError(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[LIX-AGENT] IntLixAgentThreadError failed with status %0x08x.", status);
        }

        return status;
    }

    if (Rip == (pThread->Data.Address + pThread->Data.Header.ExitOffset))
    {
        status = IntLixAgentThreadExit(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixAgentThreadExit failed with status: 0x%08x.", status);
        }

        return status;
    }

    ERROR("[ERROR] Breakpoint generated an exit from unrecognized rip inside agent-thread '%d'...",
          pThread->Tag);
    IntDumpArchRegs(&gVcpu->Regs);

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntLixAgentHandleInt3(
    _In_ QWORD Rip
    )
///
/// @brief Called when a INT3 instruction from the current running agent is executed.
///
/// This function checks if the INT3 instruction is the previously replaced instruction. If true and the instruction
/// is not restored the #IntLixAgentStart is called to start the current agent (the instruction is restored only if
/// another CPU already restored the instruction). Otherwise the function checks if the RIP comes from our agents and
/// handles the breakpoint.
///
/// @param[in]  Rip     The address of the INT3 instruction.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_FOUND               If the breakpoint is generated from an unrecognized RIP.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT *pAgent = NULL;
    DWORD crtRing = 0;

    status = IntGetCurrentRing(gVcpu->Index, &crtRing);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    if (crtRing != IG_CS_RING_0)
    {
        return INT_STATUS_NOT_FOUND;
    }

    pAgent = gLixAgentState.ActiveAgent;
    if (pAgent == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    if (pAgent->Instruction.Address == Rip)
    {
        if (pAgent->Instruction.Restored)
        {
            return INT_STATUS_NO_DETOUR_EMU;
        }
        else
        {
            status = IntLixAgentStart(pAgent);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixAgentStart failed with status: 0x%08x.", status);
            }

            return status;
        }
    }

    if (IN_RANGE_LEN(Rip, pAgent->Data.Address, pAgent->Data.Size))
    {
        status = IntLixAgentHandleBreakpoint(pAgent, Rip);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixAgentHandleBreakpoint failed with status: 0x%08x.", status);
        }

        return status;
    }

    if (pAgent->Thread != NULL &&
        IN_RANGE_LEN(Rip, pAgent->Thread->Data.Address, pAgent->Thread->Data.Size))
    {
        status = IntLixAgentThreadHandleBreakpoint(pAgent, Rip);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixAgentThreadHandleBreakpoint failed with status: 0x%08x.", status);
        }

        return status;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixAgentHandleKernelVmcall(
    void
    )
///
/// @brief Called when a VMCALL instruction from the current running agent is executed.
///
/// @retval     #INT_STATUS_NOT_SUPPORTED       This function is not supported.
///
{
    ERROR("[ERROR] VMCALL executed from kernel mode. Rip 0x%016llx.", gVcpu->Regs.Rip);

    return INT_STATUS_NOT_SUPPORTED;
}


static INTSTATUS
IntLixAgentHandleUserVmcall(
    void
    )
///
/// @brief Handles a VMCALL issued by a process that has been injected inside the guest.
///
/// Each injected application should have its own private VMCALL structure, depending on what information
/// it wants to report. Currently, Introcore can digest VMCALLs from two types of applications:
/// 1. #AGENT_HCALL_REM_TOOL - the remediation tool. This is used to send scan statuses (detections, disinfections,
///    etc.) to Introcore and to the integrator.
/// 2. #AGENT_HCALL_GATHER_TOOL - the log gather tool. This tool is used to gather logs from the target virtual
///    machine and this VMCALL is used to send to log chunks to Introcore and the integrator.
/// NOTE: If the current process has not been marked as an agent (if it was not started directly by us or by a process
/// which we injected), all the VMCALLs will be silently discarded.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///

{
    INTSTATUS status = INT_STATUS_SUCCESS;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    QWORD arg1 = pRegs->Rcx;
    QWORD arg2 = pRegs->Rbx;
    QWORD op = pRegs->Rdx;

    if (AGENT_HCALL_INTERNAL == op)
    {
        EVENT_AGENT_EVENT *pEvent = &gAlert.Agent;

        pEvent->Event = agentError;
        pEvent->ErrorCode = (DWORD)(arg2);
        pEvent->AgentTag = IntLixAgentNameGetTagByAgid((DWORD)(arg1));

        IntLixAgentNameRemoveByAgid((DWORD)(arg1));

        LOG("[LIX-AGENT] User-mode stub reports error for agent with tag %d: 0x%08x\n",
            pEvent->AgentTag, pEvent->ErrorCode);

        status = IntNotifyIntroEvent(introEventAgentEvent, pEvent, sizeof(*pEvent));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%x\n", status);
        }
    }
    else
    {
        LIX_TASK_OBJECT *pTask = IntLixTaskFindByCr3(pRegs->Cr3);
        if (pTask == NULL)
        {
            LOG("[WARNING] VMCALL coming from outside a process with CR3 %llx\n", pRegs->Cr3);
            return INT_STATUS_SUCCESS;
        }

        if (!pTask->AgentTag || pTask->IsPreviousAgent)
        {
            TRACE("[AGENT-LIX] VMCALL with op = %lld from `%s` (PID = %d) which is not an agent (previous = %d), "
                  "will ignore\n", op, pTask->Comm, pTask->Pid, pTask->IsPreviousAgent);
            return INT_STATUS_SUCCESS;
        }

        if (AGENT_HCALL_REM_TOOL == op)
        {
            status = IntAgentHandleRemediationVmcall(NULL, pRegs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntAgentHandleRemediationVmcall failed: 0x%08x\n", status);
                return status;
            }
        }
        else if (AGENT_HCALL_GATHER_TOOL == op)
        {
            status = IntAgentHandleLogGatherVmcall(NULL, pRegs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntAgentHandleLogGatherVmcall failed: 0x%08x\n", status);
                return status;
            }
        }
    }

    return status;
}


INTSTATUS
IntLixAgentHandleVmcall(
    _In_ QWORD Rip
    )
///
/// @brief Handle a VMCALL that was executed inside the guest.
///
/// This function handles VMCALLs that took place inside the guest.
///
/// @param[in]  Rip     The address of the VMCALL instruction.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
///
{
    INTSTATUS status;
    DWORD crtRing = 0;

    status = IntGetCurrentRing(gVcpu->Index, &crtRing);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    if (crtRing == IG_CS_RING_0)
    {
        LIX_AGENT *pAgent = gLixAgentState.ActiveAgent;
        if (pAgent == NULL)
        {
            ERROR("[LIX-AGENT] VMCALL with no active agent from RIP 0x%016llx.", Rip);
        }

        status = IntLixAgentHandleKernelVmcall();
    }
    else
    {
        status = IntLixAgentHandleUserVmcall();
    }

    return status;
}


_Success_(return != agNone)
AG_WAITSTATE
IntLixAgentGetState(
    _Out_opt_ DWORD *Tag
    )
///
/// @brief Gets the global agents state.
///
/// @param[out] Tag Optional agent tag, if an agent is active or pending.
///
/// @retval #agActive If there's an active agent.
/// @retval #agWaiting If there's a pending agent.
/// @retval #agNone If there are no active or pending agents.
///
{
    if (gLixAgentState.ActiveAgent)
    {
        if (NULL != Tag)
        {
            LIX_AGENT *pAgent = gLixAgentState.ActiveAgent;
            *Tag = pAgent->Tag;
        }

        return agActive;
    }

    if (!IsListEmpty(&gLixAgentState.PendingAgents))
    {
        if (NULL != Tag)
        {
            LIX_AGENT *pAgent = CONTAINING_RECORD(gLixAgentState.PendingAgents.Flink, LIX_AGENT, Link);
            *Tag = pAgent->Tag;
        }

        return agWaiting;
    }

    return agNone;
}


void
IntLixAgentDisablePendingAgents(
    void
    )
///
/// @brief Disables all pending agents.
///
/// This function should be called during the uninit phase, as it will disable all the pending agents. These
/// agents will never be injected inside the guest.
///
{
    if (!gLixAgentState.Initialized)
    {
        return;
    }

    list_for_each (gLixAgentState.PendingAgents, LIX_AGENT, pAgent)
    {
        RemoveEntryList(&pAgent->Link);

        IntLixAgentFree(pAgent);
    }
}


LIX_AGENT_TAG
IntLixAgentIncProcRef(
    _In_ const char *Name
    )
///
/// @brief Checks if a process is an agent or not, and increments the ref count of that name.
///
/// Each time a process is created, we check if its name matches the name of a previously injected agent. If
/// it does, we flag that process as an agent, and we increment the reference count of the name.
///
/// @param[in]  Name   The image name of the process which is checked.
///
/// @retval The agent tag, if the process is found to be an agent.
///
{
    SIZE_T length;

    if (IsListEmpty(&gLixAgentState.AgentNames))
    {
        return lixAgTagNone;
    }

    length = strlen(Name);

    list_for_each (gLixAgentState.AgentNames, LIX_AGENT_NAME, pName)
    {
        if (0 == strncmp(Name, pName->Name, length))
        {
            pName->RefCount++;

            return pName->AgentTag;
        }
    }

    return lixAgTagNone;
}


LIX_AGENT_TAG
IntLixAgentDecProcRef(
    _In_ const char *Name,
    _Out_ BOOLEAN *Removed
    )
///
/// @brief Checks if a process is an agent or not, and decrements the ref count of that name.
///
/// Each time a process terminates, we check if it was an agent, and we decrement the reference count if its name.
/// Once the reference count of an agent name reaches 0, it will be removed.
///
/// @param[in]  Name        The image name of the process which is checked.
/// @param[out] Removed     True if the agent was removed.
///
/// @retval The agent tag, if the process is found to be an agent.
///
{
    SIZE_T length;

    *Removed = FALSE;

    if (IsListEmpty(&gLixAgentState.AgentNames))
    {
        return lixAgTagNone;
    }

    length = strlen(Name);

    list_for_each (gLixAgentState.AgentNames, LIX_AGENT_NAME, pName)
    {
        if (memcmp_len(Name, pName->Name, length, pName->Length) == 0)
        {
            LIX_AGENT_TAG tag = pName->AgentTag;

            if (pName->RefCount > 0)
            {
                --pName->RefCount;
            }
            else
            {
                WARNING("[WARNING] Agent %s already done by our logic!\n", pName->Name);
            }

            if (pName->RefCount == 0)
            {
                IntLixAgentNameRemove(pName);
                *Removed = TRUE;
            }

            return tag;
        }
    }

    return lixAgTagNone;
}


void
IntLixAgentEnableInjection(
    void
    )
///
/// @brief Enables agent injections.
///
{
    gLixAgentState.SafeToInjectProcess = TRUE;

    IntLixAgentActivatePendingAgent();
}


void
IntLixAgentInit(
    void
    )
///
/// @brief Initialize the agents state.
///
{
    memzero(&gLixAgentState, sizeof(gLixAgentState));

    InitializeListHead(&gLixAgentState.PendingAgents);
    InitializeListHead(&gLixAgentState.AgentNames);

    gLixAgentState.Initialized = TRUE;

    LOG("[LIX-AGENT] Linux agent state initialized.\n");
}


INTSTATUS
IntLixAgentUninit(
    void
    )
///
/// @brief Uninit the agents state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the agents state has not been initialized yet.
///
{
    if (gGuest.OSType != introGuestLinux)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    //
    // In case we inject our agent and the system is no longer running or it's hanged, the uninit agent may
    // remain allocated.
    //
    if (gLixAgentState.ActiveAgent)
    {
        IntLixAgentFree(gLixAgentState.ActiveAgent);
    }

    memzero(&gLixAgentState, sizeof(gLixAgentState));

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentCreateThreadHypercall(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called by the thread-agent to deploy the content of the kthread previously created.
///
/// This function writes the content of the kthread at the allocated memory (by the agent) and returns in RAX the entry
/// point of the kthread.
///
/// @param[in]  Agent   The current agent.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_AGENT_THREAD *pThread = Agent->Thread;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;

    if (pRegs->R8 == 0)
    {
        goto _exit;
    }

    pThread->Data.Header.Address = pRegs->R8;
    pThread->Data.Address = pRegs->R8;

    memcpy(pThread->Data.Code, &pThread->Data.Header, sizeof(LIX_AGENT_HEADER));

    status = IntVirtMemWrite(pThread->Data.Address,
                             pThread->Data.Size,
                             gGuest.Mm.SystemCr3,
                             pThread->Data.Code);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemWrite failed with status: 0x%08x.", status);
        goto _exit;
    }

    pRegs->Rax = pThread->Data.Address + pThread->Data.Header.DataSize;
    status = IntSetGprs(gVcpu->Index, pRegs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed with status: 0x%08x.", status);
        goto _exit;
    }

    return INT_STATUS_SUCCESS;

_exit:
    IntLixAgentSendEvent(agentError, Agent->TagEx, 0);

    IntLixAgentThreadFree(Agent->Thread);
    Agent->Thread = NULL;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixAgentCreateThreadCompletion(
    _In_ LIX_AGENT *Agent
    )
///
/// @brief Called by the thread-agent when the kthread started.
///
/// An event is sent to integrator with the state of the agent.
///
/// @param[in]  Agent   The current agent.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    DWORD errorCode = 0;

    if (pRegs->Rax == 0)
    {
        errorCode = 1;
        goto _exit;
    }

    LOG("[DEPLOYER] Agent with tag %d has just been injected, error: 0x%08x.", Agent->TagEx, errorCode);

_exit:
    IntLixAgentSendEvent(agentInjected, Agent->TagEx, errorCode);

    return INT_STATUS_SUCCESS;
}


void
IntLixAgentSendEvent(
    _In_ AGENT_EVENT_TYPE Event,
    _In_ DWORD AgentTag,
    _In_ DWORD ErrorCode
    )
///
/// @brief Send an event to the integrator that contains the #AGENT_EVENT_TYPE, tag of the agent and the last error
/// code.
///
/// @param[in]  Event       The type of the event.
/// @param[in]  AgentTag    The tag of the agent
/// @param[in]  ErrorCode   The last error-code of the agent.
///
{
    INTSTATUS status;
    EVENT_AGENT_EVENT *pEvent = &gAlert.Agent;

    memzero(pEvent, sizeof(*pEvent));

    pEvent->Event = Event;
    pEvent->AgentTag = AgentTag;
    pEvent->ErrorCode = ErrorCode;

    status = IntNotifyIntroEvent(introEventAgentEvent, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%x\n", status);
    }
}
