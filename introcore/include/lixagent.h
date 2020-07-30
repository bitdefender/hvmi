/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIX_AGENT_H_
#define _LIX_AGENT_H_

#include "aghcall.h"
#include "agent.h"

#define LIX_AGENT_MAX_FUNCTIONS         256

#define LIX_AGENT_MAX_NAME_LENGTH       128
#define LIX_AGENT_MAX_ARGS_LENGTH       1024


typedef struct _LIX_TASK_OBJECT LIX_TASK_OBJECT;

///
/// @brief Hypercall callback prototype.
///
/// @param[in]  Context     The running agent.
///

typedef INTSTATUS
(*PFUNC_AgentCallbackHypercall)(
    _In_opt_ void *Context
    );



///
/// @brief Completion callback prototype.
///
/// @param[in]  Context     The running agent.
///
typedef INTSTATUS
(*PFUNC_AgentCallbackCompletion)(
    _In_opt_ void *Context
    );

///
/// @brief Agent hypercall type.
///
typedef enum _LIX_AGENT_HYPERCALL
{
    lixAgentHypercallNone = 0,  ///< Invalid hypercall type.
    lixAgentHypercallVmcall,    ///< Hypercall using VMCALL instruction.
    lixAgentHypercallInt3       ///< Hypercall using INT3 instruction.
} LIX_AGENT_HYPERCALL;


///
/// @brief Tag used to identify an agent with a handler.
///
typedef enum _LIX_AGENT_TAG
{
    // NOTE: Never change this to anything other than 0
    lixAgTagNone = 0,

    // Tags used for agents without threads
    lixAgTagInit,                       ///< The init agent.
    lixAgTagUninit,                     ///< The uninit agent.
    lixAgTagCreateThread,               ///< The create thread agent.

    // Tags used for agents with threads
    lixAgThreadTagDeployFile,           ///< Deploy a file.
    lixAgThreadTagDeployFileExec,       ///< Execute a file (process).
    lixAgThreadTagRunCommand            ///< Run a custom command.

} LIX_AGENT_TAG;


///
/// @brief Header with information about running code inside the guest.
///
#pragma pack(push)
#pragma pack(1)
typedef struct _LIX_AGENT_HEADER
{
    DWORD   Tag;                ///< The #LIX_AGENT_TAG.
    WORD    DataSize;           ///< The size (bytes) of the data.
    WORD    ExitOffset;         ///< The offset of the INT3 instruction that represent the exit point.
    WORD    CodeSize;           ///< The size (byes) of the code.
    QWORD   Address;            ///< The address of the kthread.
} LIX_AGENT_HEADER, *PLIX_AGENT_HEADER;
#pragma pack(pop)


///
/// @brief The tokens used by an agent.
///
typedef struct _LIX_AGENT_TOKEN
{
    QWORD Hypercall;            ///< The token used by hypercall callback.
    QWORD Completion;           ///< The token used by completion callback.
    QWORD Error;                ///< The token used by error callback.
} LIX_AGENT_TOKEN;


///
/// @brief Describes the data of an agent.
///
typedef struct _LIX_AGENT_DATA
{
    LIX_AGENT_HEADER    Header;     ///< The header of the agent's data.
    LIX_AGENT_TOKEN     Token;      ///< The tokens of the agent.

    BYTE                *Code;      ///< A buffer that contains the in-guest agent code/data.
    QWORD               Address;    ///< The guest virtual address of the injected agent.
    DWORD               Size;       ///< The size (bytes) of the injected agent.

} LIX_AGENT_DATA, *PLIX_AGENT_DATA;


///
/// @brief Describes an agent-thread running inside the guest.
///
typedef struct _LIX_AGENT_THREAD
{
    LIX_AGENT_TAG           Tag;                    ///< The internal tag.
    LIX_AGENT_HYPERCALL     HypercallType;          ///< The hypercall type used.

    LIX_AGENT_DATA          Data;                   ///< The data used by the agent.

    struct
    {
        PFUNC_AgentCallbackHypercall    Hypercall;  ///< Hypercall callback.
        PFUNC_AgentCallbackCompletion   Completion; ///< Completion callback.
    } Callback;

    struct
    {
        BYTE    *Address;                           ///< A pointer to the content provided by the integrator.
        DWORD   Size;                               ///< The size of the content provided by the integrator.

        /// @brief  Used when the HypecallCallback is called as an offset in the content buffer.
        DWORD   CurrentOffset;
    } Content;

    void        *Context;                           ///< Unused.

} LIX_AGENT_THREAD, *PLIX_AGENT_THREAD;


///
/// @brief Describe an agent running inside the guest.
///
typedef struct _LIX_AGENT
{
    LIST_ENTRY          Link;                           ///< List entry element.

    LIX_AGENT_TAG       Tag;                            ///< The internal tag.
    DWORD               TagEx;                          ///< The tag provided by the integrator.

    DWORD               Agid;                           ///< The agent ID.

    LIX_AGENT_HYPERCALL HypercallType;                  ///< The hypercall type.
    LIX_AGENT_DATA      Data;                           ///< The data used by the agent.
    LIX_AGENT_THREAD    *Thread;                        ///< A pointer to a agent-thread, if any.

    CHAR                Name[IG_MAX_AGENT_NAME_LENGTH]; ///< The name of the agent.

    struct
    {
        PFUNC_AgentCallbackHypercall    Hypercall;      ///< Hypercall callback.
        PFUNC_AgentCallbackCompletion   Completion;     ///< Completion callback.
    } Callback;

    struct
    {
        QWORD   Address;                                ///< Address of the detoured instruction.

        BYTE    Bytes[16];                              ///< Detoured instruction bytes.
        BYTE    Length;                                 ///< Detoured instruction length.

        void    *CloakHandle;                           ///< Cloak handle used to hide the detoured instruction.

        BOOLEAN Restored;                               ///< True if the detours instruction has been restored.
    } Instruction;

} LIX_AGENT, *PLIX_AGENT;


///
/// @brief A list of functions required by agent.
///
typedef struct _LIX_AGENT_FUNCTIONS_LIST
{
    DWORD   Required;           ///< The number of required function addresses for the 'Name' array.
    DWORD   Count;              ///< The number of function names.
    char    *Name[256];         ///< The function name.
} LIX_AGENT_FUNCTIONS_LIST, *PLIX_AGENT_FUNCTIONS_LIST;


///
/// @brief The functions required by the agent.
///
typedef struct _LIX_AGENT_FUNCTINS
{
    struct
    {
        WORD                    Sublevel;
        BYTE                    Patch;
        BYTE                    Version;
        WORD                    Backport;
    } Version;                                  ///< Kernel version required to use this functions.

    DWORD                       Count;          ///< The number of the functions list.
    LIX_AGENT_FUNCTIONS_LIST    List[20];       ///< An array that contains #LIX_AGENT_FUNCTIONS_LIST entries.

} LIX_AGENT_FUNCTIONS, *PLIX_AGENT_FUNCTIONS;

///
/// @brief Describes a handlers that contains the data required by the agent.
///
typedef struct _LIX_AGENT_HANDLER
{
    enum _LIX_AGENT_TAG       Tag;              ///< The #LIX_AGENT_TAG.
    enum _LIX_AGENT_HYPERCALL HypercallType;    ///< The hypercall type.

    struct
    {
        WORD    Length;                         ///< The size (bytes) of the arguments.
        void    *Content;                       ///< The content of the arguments.
    } Args;

    struct
    {
        WORD    Length;                         ///< The size (bytes) of the agent code.
        void    *Content;                       ///< The content of the agent code.
    } Code;

    struct
    {
        DWORD                Count;             ///< The number of the functions.
        LIX_AGENT_FUNCTIONS *Content;           ///< An array that contains #LIX_AGENT_FUNCTIONS entries.
    } Functions;

    struct
    {
        DWORD                        Count;     ///< The number of threads that can be used by the agent.
        struct _LIX_AGENT_HANDLER   *Content;   ///< An array that contains #LIX_AGENT_HANDLER entries.
    } Threads;

} LIX_AGENT_HANDLER, *PLIX_AGENT_HANDLER;


#pragma pack(push)
#pragma pack(1)

///
/// @brief Arguments of the init agent.
///
typedef struct _LIX_AGENT_INIT_ARGS
{
    struct
    {
        QWORD ModuleLength;         ///< The module memory allocation size.
        QWORD PerCpuLength;         ///< The per-CPU memory allocation size.
    } Allocate;
} LIX_AGENT_INIT_ARGS, *PLIX_AGENT_INIT_ARGS;


///
/// @brief Arguments of the uninit agent.
///
typedef struct _LIX_AGENT_UNINIT_ARGS
{
    struct
    {
        QWORD ModuleAddress;        ///< The address of the allocated memory (module).
        QWORD PerCpuAddress;        ///< The address of the allocated memory (per-CPU).
    } Free;

    struct
    {
        QWORD MaskClear;            ///< The page attributes that must be cleared.
        QWORD MaskSet;              ///< The page attributes that must be set.
    } Attr;
} LIX_AGENT_UNINIT_ARGS, *PLIX_AGENT_UNINIT_ARGS;


///
/// @brief Arguments of the create-thread agent.
///
typedef struct _LIX_AGENT_CREATE_THREAD_ARGS
{
    struct
    {
        QWORD Length;               ///< The allocation size of the kthread data.
    } Allocate;
} LIX_AGENT_CREATE_THREAD_ARGS, *PLIX_AGENT_CREATE_THREAD_ARGS;


///
/// @brief Arguments of the deploy-file agent.
///
typedef struct _LIX_AGENT_THREAD_DEPLOY_FILE_ARGS
{
    QWORD KernelVersion;                        ///< The current guest kernel version.

    struct
    {
        /// @brief  The memory allocation size to deploy the provided content; to deploy the file, we use chunks.
        QWORD   Length;
    } Allocate;

    struct
    {
        char    Root;                               ///< The root directory (eg. '/')
        char    Name[LIX_AGENT_MAX_NAME_LENGTH];    ///< The name of the deployed file.
    } FilePath;

    struct
    {
        QWORD   UhmWaitProc;                    ///< The value of UMH_WAIT_PROC of current guest.
        QWORD   UhmWaitExec;                    ///< The value of UMH_WAIT_EXEC of current guest.
    } Umh;

} LIX_AGENT_THREAD_DEPLOY_FILE_ARGS, *PLIX_AGENT_THREAD_DEPLOY_FILE_ARGS;


///
/// @brief Arguments of the exec agent.
///
typedef struct _LIX_AGENT_THREAD_DEPLOY_FILE_EXEC_ARGS
{
    QWORD       KernelVersion;                      ///< The current guest kernel version.
    QWORD       FilePathOffset;                     ///< The offset of struct file.path.

    struct
    {
        /// @brief  The memory allocation size to deploy the provided content; to deploy the file, we use chunks.
        QWORD   Length;
    } Allocate;

    struct
    {
        char    Root;                               ///< The root directory (eg. '/')
        char    Name[LIX_AGENT_MAX_NAME_LENGTH];    ///< The name of the deployed file.
    } FilePath;


    struct
    {
        char    Args[LIX_AGENT_MAX_ARGS_LENGTH];    ///< The arguments given to the process.
    } Exec;

    struct
    {
        QWORD   UhmWaitProc;                        ///< The value of UMH_WAIT_PROC of current guest.
        QWORD   UhmWaitExec;                        ///< The value of UMH_WAIT_EXEC of current guest.
    } Umh;

} LIX_AGENT_THREAD_DEPLOY_FILE_EXEC_ARGS, *PLIX_AGENT_THREAD_DEPLOY_FILE_EXEC_ARGS;


///
/// @brief Arguments of the run command-line agent.
///
typedef struct _LIX_AGENT_THREAD_RUN_CLI_ARGS
{
    struct
    {
        char    Args[LIX_AGENT_MAX_ARGS_LENGTH];    ///< The command line to be executed.
    } Exec;

    struct
    {
        QWORD   UhmWaitProc;                        ///< The value of UMH_WAIT_PROC of current guest.
        QWORD   UhmWaitExec;                        ///< The value of UMH_WAIT_EXEC of current guest.
    } Umh;

} LIX_AGENT_THREAD_RUN_CLI_ARGS, *PLIX_AGENT_THREAD_RUN_CLI_ARGS;
#pragma pack(pop)


INTSTATUS
IntLixAgentInject(
    _In_ LIX_AGENT_TAG Tag,
    _In_opt_ PFUNC_AgentCallbackHypercall HypercallCallback,
    _In_opt_ PFUNC_AgentCallbackCompletion CompletionCallback
    );

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
    );

INTSTATUS
IntLixAgentActivatePendingAgent(
    void
    );

void
IntLixAgentEnableInjection(
    void
    );

_Success_(return != agNone)
AG_WAITSTATE
IntLixAgentGetState(
    _Out_opt_ DWORD *Tag
    );

void
IntLixAgentDisablePendingAgents(
    void
    );

void
IntLixAgentNameRemoveByAgid(
    _In_ DWORD Agid
    );

DWORD
IntLixAgentNameGetTagByAgid(
    _In_ DWORD Agid
    );

LIX_AGENT_TAG
IntLixAgentIncProcRef(
    _In_ const char *Name
    );

LIX_AGENT_TAG
IntLixAgentDecProcRef(
    _In_ const char *Name,
    _Out_ BOOLEAN *Removed
    );

INTSTATUS
IntLixAgentHandleInt3(
    _In_ QWORD Rip
    );

INTSTATUS
IntLixAgentHandleVmcall(
    _In_ QWORD Rip
    );

void
IntLixAgentInit(
    void
    );

INTSTATUS
IntLixAgentUninit(
    void
    );

LIX_AGENT_HANDLER *
IntLixAgentGetHandlerByTag(
    _In_ LIX_AGENT_TAG AgentTag
    );

LIX_AGENT_HANDLER *
IntLixAgentThreadGetHandlerByTag(
    _In_ LIX_AGENT_TAG AgentTag,
    _In_ LIX_AGENT_TAG ThreadTag
    );

void
IntLixAgentSendEvent(
    _In_ AGENT_EVENT_TYPE Event,
    _In_ DWORD AgentTag,
    _In_ DWORD ErrorCode
    );

#endif // !_LIX_AGENT_H_
