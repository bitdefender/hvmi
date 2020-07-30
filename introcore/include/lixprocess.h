/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXPROCESS_H_
#define _LIXPROCESS_H_

#include "introtypes.h"
#include "update_guests.h"
#include "lixagent.h"
#include "lixddefs.h"

#define LIX_COMM_SIZE                       16u   ///< The maximum size of the process comm.

#define LIX_PROCESSES_MAX_COUNT             65536 ///< The maximum number of processes allowed.

typedef struct _LIX_CREDS       LIX_CREDS;

///
/// @brief Describes a path cache entry.
///
typedef struct _LIX_TASK_PATH
{
    LIST_ENTRY  Link;       ///< The list node.

    char        *Path;      ///< The full path string.
    char        *Name;      ///< The path base name.

    QWORD       DentryGva;  ///< The guest virtual address of the "dentry" structure associated with this path.

    size_t      PathLength; ///< The size of the path.
    size_t      NameLength; ///< The size of the base name.

    DWORD       RefCount;   ///< The number of references for this cache entry.
} LIX_TASK_PATH;


typedef struct _LIX_TASK_OBJECT
{
    LIST_ENTRY  Link;                   ///< Linkage in the global task list

    QWORD       Gva;                    ///< The guest virtual address of the task_struct

    char        Comm[LIX_COMM_SIZE];    ///< The short name of the executable

    char        *Interpreter;           ///< If this was a script executed through an interpretor

    char        *CmdLine;               ///< The process command line.

    LIX_TASK_PATH *Path;                ///< The path of the file executed.

    /// @brief  The process name that is always valid. It's set depending which info is  available in order: Path, Comm.
    /// Never free, it's just a reference.
    char        *ProcName;

    QWORD       RealParent;             ///< The process which called fork()
    QWORD       Parent;                 ///< Depends if this is a thread or a process.
    QWORD       ActualParent;           ///< The parent, based on tgid. Only relevant for threads.

    QWORD       ExeFileDentry;          ///< The guest virtual address of the executable file's "dentry" structure.

    SIZE_T      ProcNameLength;         ///< The length of the ProcName field.
    DWORD       InterpLength;           ///< The length of the Interpreter field.
    DWORD       CmdLineLength;          ///< The length of the CmdLine field.
    DWORD       CommHash;               ///< The CRC32 checksum of the Comm field.

    LIST_ENTRY  ExploitProtProcLink;    ///< Linkage in the protected processes list

    QWORD       MmGva;                  ///< The guest virtual address of the "mm_struct".
    QWORD       Cr3;                    ///< The CR3 for this process.

    DWORD       Pid;                    ///< The task PID.
    DWORD       Tgid;                   ///< The task Thread-Group-ID.

    QWORD       CreationTime;           ///< The creation timestamp for this process.

    //
    // Introspection-specific fields
    //
    LIST_HEAD       Vmas;               ///< The list head for the VMAs from the memory space of this process.

    struct
    {
        QWORD       Mask;               ///< The protection flags enabled for this process.
        QWORD       Beta;               ///< The protection flags for this process that are in beta mode.
        QWORD       Feedback;           ///< The protection flags for this process that are in feedback-only mode.
    } Protection;                       ///< Protection specific flags.

    QWORD           RootProtectionMask; ///< The protection that children will inherit.
    QWORD           Context;            ///< Context from integrator.

    void            *HookObject;        ///< The HookObject used for EPT hooks set inside this process's memory space.

    DWORD           StaticDetected: 1;  ///< TRUE if the process was detected using a static scan (during static init).
    DWORD           Exec: 1;            ///< TRUE if the process did exec at least once.
    DWORD           IsThread: 1;        ///< TRUE if it's a thread, not a process.
    DWORD           KernelMode: 1;      ///< TRUE if this process/thread is inside kernel mode.
    DWORD           IsPreviousAgent: 1; ///< TRUE if this process is an agent remaining from a previous session.
    DWORD           Protected: 1;       ///< TRUE if the process is protected.
    DWORD           ReExecToSelf: 1;    ///< TRUE if the process is re-executed to self (exec to same executable).
    DWORD           MustKill: 1;        ///< Will kill the process with the first occasion.

    LIX_AGENT_TAG   AgentTag;           ///< The agent tag, if this process is an agent.

    LIX_CREDS       *Creds;             ///< The #LIX_CREDS reference for the credentials of this process.

    struct
    {
        QWORD       Base;               ///< The user mode stack base.
        QWORD       Limit;              ///< The user mode stack limit.
        BOOLEAN     Valid;              ///< TRUE if the values inside this structure are valid.
    } UserStack;                        ///< User stack information.

    struct
    {
        BOOLEAN     IsPivoted;          ///< TRUE if this process stack is pivoted (used for DPI)
        BOOLEAN     StolenTokens;       ///< TRUE if credentials for this process have been altered
    } Dpi;                              ///< DPI related information.

} LIX_TASK_OBJECT;


static __forceinline QWORD
IntLixProcGetProtOption(
    _In_ const LIX_TASK_OBJECT *Process
    )
///
/// @brief Returns the introcore options related to user mode protection.
///
/// @param[in] Process The Linux process. (currently ignored)
///
/// @returns The introcore options for user mode protection.
///
{
    UNREFERENCED_PARAMETER(Process);

    return INTRO_OPT_PROT_UM_MISC_PROCS;
}

static __forceinline BOOLEAN
IntLixProcPolicyIsBeta(
    _In_ const LIX_TASK_OBJECT *Process,
    _In_ QWORD Flag
    )
///
/// @brief Verifies whether a specific process protection flag is in beta mode or not for a Linux process.
///
/// @param[in] Process The Linux process.
/// @param[in] Flag    The process protection flag.
///
/// @returns TRUE  If the flag provided is in beta mode.
/// @returns FALSE Otherwise.
///
{
    return (Process->Protection.Mask & PROC_OPT_BETA) != 0 ||
           IntPolicyCoreIsOptionBeta(IntLixProcGetProtOption(Process)) ||
           (Process->Protection.Beta & Flag) != 0;
}

static __forceinline BOOLEAN
IntLixProcPolicyIsFeedback(
    _In_ const LIX_TASK_OBJECT *Process,
    _In_ QWORD Flag
    )
///
/// @brief Verifies whether a specific process protection flag is in feedback only mode or not for a Linux process.
///
/// @param[in] Process The Linux process.
/// @param[in] Flag    The process protection flag.
///
/// @returns TRUE  If the flag provided is in feedback only mode.
/// @returns FALSE Otherwise.
///
{
    return ((Process->Protection.Feedback & Flag) ||
            (IntPolicyIsCoreOptionFeedback(IntLixProcGetProtOption(Process))));
}

///
/// Callback for iterating internally available Linux processes.
///
typedef INTSTATUS
(*PFUNC_LixTaskIterateTasks)(
    _In_ LIX_TASK_OBJECT *Task
    );

INTSTATUS
IntLixTaskGetUserStack(
    _In_ LIX_TASK_OBJECT *Task,
    _Out_opt_ QWORD *StackPointer,
    _Out_opt_ QWORD *StackBase,
    _Out_opt_ QWORD *StackLimit
    );

INTSTATUS
IntLixGetInitTask(
    _Out_ QWORD *InitTask
    );

LIX_TASK_OBJECT *
IntLixTaskGetCurrent(
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntLixTaskGetCurrentTaskStruct(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *TaskStruct
    );

QWORD
IntLixGetKernelCr3(
    _In_ QWORD Cr3
    );

LIX_TASK_OBJECT *
IntLixTaskFindByCr3(
    _In_ QWORD Cr3
    );

LIX_TASK_OBJECT *
IntLixTaskFindByGva(
    _In_ QWORD TaskStruct
    );

LIX_TASK_OBJECT *
IntLixTaskProtFindByMm(
    _In_ QWORD MmGva
    );

LIX_TASK_OBJECT *
IntLixTaskFindByMm(
    _In_ QWORD MmGva
    );

LIX_TASK_OBJECT *
IntLixTaskFindByPid(
    _In_ DWORD Pid
    );

INTSTATUS
IntLixTaskGetTrapFrame(
    _In_ const LIX_TASK_OBJECT *Task,
    _Out_ LIX_TRAP_FRAME *TrapFrame
    );

DWORD
IntLixTaskGetExecCount(
    void
    );

INTSTATUS
IntLixTaskHandleFork(
    _In_ void *Detour
    );

INTSTATUS
IntLixTaskHandlePtrace(
    _In_ void *Detour
    );

INTSTATUS
IntLixTaskHandleVmRw(
    _In_ void *Detour
    );

INTSTATUS
IntLixTaskHandleExec(
    _In_ void *Detour
    );

INTSTATUS
IntLixTaskHandleDoExit(
    _In_ void *Detour
    );

INTSTATUS
IntLixTaskIterateGuestTasks(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    );

INTSTATUS
IntLixTaskAdd(
    _In_ QWORD TaskGva,
    _In_ QWORD StaticDetected
    );

INTSTATUS
IntLixTaskAddProtected(
    _In_ const char *ProcessName,
    _In_ QWORD ProtectionMask,
    _In_ QWORD Context
    );

INTSTATUS
IntLixTaskRemoveProtected(
    _In_ const char *ProcessName
    );

void
IntLixTaskUpdateProtection(
    void
    );

INTSTATUS
IntLixTaskGetAgentsAsCli(
    _Out_writes_bytes_(Length) char *CommandLine,
    _In_ DWORD Length
    );

void
IntLixTaskUninit(
    void
    );

void
IntLixTaskDumpAsTree(
    void
    );

void
IntLixTaskDump(
    void
    );

void
IntLixTaskDumpProtected(
    void
    );

INTSTATUS
IntLixTaskIterateTasks(
    _In_ PFUNC_LixTaskIterateTasks Callback
    );

void
IntLixTaskEnum(
    _Out_ DWORD *Pids,
    _In_ DWORD BufferSize
    );

BOOLEAN
IntLixTaskGuestTerminating(
    void
    );

void
IntLixProcUpdateProtectedProcess(
    _In_ const void *Name,
    _In_ const CAMI_STRING_ENCODING Encoding,
    _In_ const CAMI_PROT_OPTIONS *Options
    );

INTSTATUS
IntLixAccessRemoteVmHandler(
    _In_ void *Detour
    );

INTSTATUS
IntLixTaskIsUserStackPivoted(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ QWORD Ptr,
    _Out_ BOOLEAN *IsPivoted
    );

#endif // _LIXPROCESS_H_
