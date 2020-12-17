/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winprocess.h"
#include "alerts.h"
#include "crc32.h"
#include "gpacache.h"
#include "icache.h"
#include "kernvm.h"
#include "ptfilter.h"
#include "swapmem.h"
#include "winagent.h"
#include "winobj.h"
#include "winpfn.h"
#include "winprocesshp.h"
#include "winselfmap.h"
#include "wincmdline.h"
#include "windpi.h"
#include "wintoken.h"
#include "winpe.h"
#include "winsecdesc.h"

/// @brief The maximum length (in bytes) of the data read from the guest when reading the command line of a process
/// that is not protected with the #PROC_OPT_PROT_SCAN_CMD_LINE.
///
/// This is usually a process from the #gCmdLineProcesses list.
/// Note that this must always be an even number because it represents the length of a WCHAR string.
#define CMDLINE_LEN_NO_SCAN           ALERT_CMDLINE_MAX_LEN

/// @brief The maximum length (in bytes) of the data read from the guest when reading the command line of a process
/// protected with #PROC_OPT_PROT_SCAN_CMD_LINE.
///
/// Note that this must always be an even number because it represents the length of a WCHAR string.
/// This is enough to cover the 32767 maximum character limit imposed by CreateProcess.
/// See https://devblogs.microsoft.com/oldnewthing/20031210-00/?p=41553 for details.
#define CMDLINE_MAX_LEN               (WORD_MAX - 1)

extern LIST_HEAD gWinProcesses;
extern RBTREE gWinProcTreeCr3;
extern RBTREE gWinProcTreeUserCr3;
extern RBTREE gWinProcTreeEprocess;

///
/// @file winprocess.c
///
/// @brief This file handles Windows Processes related events (Creation, Termination, Copy Memory, etc.).
///
/// In order to protect Windows processes, introcore places some hooks (see winhkhnd.c) on functions such as
/// "PspInserProcess" (used for process creation) or "MmCleanProcessAddressSpace" (used for process termination) in
/// order to keep a list of all the running processes (#gWinProcesses). When a process is being started, DPI (Deep
/// Process Inspection) checks are being carries out in order to determine if the creation should be allowed or
/// not (see windpi.c). Also at process creation, the protection for the newly created process is enabled (according
/// to the protection flags (WINPROC_PROT_MASK_*). Apart from process creation/termination, this file contains
/// the detour functions that handle process memory reads/writes (IPC).
///


///
/// @brief      A list with all the protected processes (containing #PROTECTED_PROCESS_INFO elements).
///
static LIST_HEAD gWinProtectedProcesses = LIST_HEAD_INIT(gWinProtectedProcesses);

///
/// @brief      The total number of protected processes.
///
static DWORD gTotalProtectedProcs = 0;

///
/// @brief      The system path.
///
const WCHAR gSystemPath[] = u"\\windows\\system32\\";

///
/// @brief      The syswow path (32 bit process on a 64 bit OS).
///
const WCHAR gSysWowPath[] = u"\\windows\\syswow64\\";

///
/// @brief      This is a list with system processes and their default protection mask.
///
const PROTECTED_PROCESS_INFO gSystemProcesses[] =
{
    {
        .ImageBaseNamePattern = "smss.exe",
        .Protection = { .Original = PROC_OPT_PROT_INJECTION, .Current  = PROC_OPT_PROT_INJECTION },
        .FullPathPattern = u"c:\\windows\\system32\\smss.exe",
        .FullNamePattern = u"smss.exe"
    },

    {
        .ImageBaseNamePattern = "csrss.exe",
        .Protection = { .Original = PROC_OPT_PROT_INJECTION, .Current  = PROC_OPT_PROT_INJECTION },
        .FullPathPattern = u"c:\\windows\\system32\\csrss.exe",
        .FullNamePattern = u"csrss.exe"
    },

    {
        .ImageBaseNamePattern = "wininit.exe",
        .Protection = { .Original = PROC_OPT_PROT_INJECTION, .Current  = PROC_OPT_PROT_INJECTION },
        .FullPathPattern = u"c:\\windows\\system32\\wininit.exe",
        .FullNamePattern = u"wininit.exe"
    },

    {
        .ImageBaseNamePattern = "winlogon.exe",
        .Protection = { .Original = PROC_OPT_PROT_INJECTION, .Current  = PROC_OPT_PROT_INJECTION },
        .FullPathPattern = u"c:\\windows\\system32\\winlogon.exe",
        .FullNamePattern = u"winlogon.exe"
    },

    {
        .ImageBaseNamePattern = "lsass.EXE",
        .Protection = { .Original = PROC_OPT_PROT_INJECTION, .Current  = PROC_OPT_PROT_INJECTION },
        .FullPathPattern = u"c:\\windows\\system32\\lsass.EXE",
        .FullNamePattern = u"lsass.exe"
    },

    {
        .ImageBaseNamePattern = "services.EXE",
        .Protection = { .Original = PROC_OPT_PROT_INJECTION, .Current  = PROC_OPT_PROT_INJECTION },
        .FullPathPattern = u"c:\\windows\\system32\\services.EXE",
        .FullNamePattern = u"services.exe"
    },
};


///
/// @brief      This is a list with non system processes that have a default protection mask.
///
const PROTECTED_PROCESS_INFO gWinForcedProtectedProcesses[] =
{
    {
        .ImageBaseNamePattern = "powershell.exe",
        .Protection = { .Original = PROC_OPT_PROT_SCAN_CMD_LINE, .Current = PROC_OPT_PROT_SCAN_CMD_LINE },
        .FullPathPattern = u"c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
        .FullNamePattern = u"powershell.exe"
    },
};


///
/// @brief      This is a list of processes for which we want to read the command line (not to be confused with
/// #PROC_OPT_PROT_SCAN_CMD_LINE.
///
static const char *gCmdLineProcesses[] =
{
    "svchost.exe",
    "chrome.exe",           // Needed in order to detect NaCl instances

    // these are rather generic processes that host external code which may generate alerts (especially injections)
    "rundll32.exe",
    "dllhost.exe",

    "winword.exe",
    "excel.exe",
    "powerpnt.exe",

    "wscript.exe",
    "mshta.exe",
};


static INTSTATUS
IntWinProcDeleteProcessObject(
    _In_ QWORD EprocessAddress,
    _In_ QWORD Cr3,
    _In_ DWORD Pid
    );

static INTSTATUS
IntWinProcRemoveProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    );

static INTSTATUS
IntWinProcCreateProcessSubsystem(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Out_ WIN_PROCESS_SUBSYSTEM **Subsystem,
    _In_ BYTE SubsystemType
    );


static BOOLEAN
IntWinProcIsExploitGuardEnabled(
    _In_ QWORD EprocessAddress,
    _In_ BYTE *Eprocess
    )
///
/// @brief      Checks if the exploit guard is enabled for a certain process.
///
/// @param[in]  EprocessAddress   The eprocess - GVA.
/// @param[in]  Eprocess          The eprocess - Introcore mapped value.
///
/// @retval     TRUE    If the exploit guard is enabled.
/// @retval     FALSE   If the exploit guard is disabled.
///
{
    WIN_MITIGATION_FLAGS2 flags2 = { 0 };

    // If older than Windows 10 Redstone 3
    if (gGuest.OSVersion < 16299)
    {
        return FALSE;
    }

    if (0 == WIN_KM_FIELD(Process, MitigationFlags2))
    {
        WARNING("[WARNING] MitigationFlags2 Offset in Eprocess is not known for Windows version %d!\n",
                gGuest.OSVersion);

        return FALSE;
    }

    memcpy(&flags2, Eprocess + WIN_KM_FIELD(Process, MitigationFlags2), sizeof(flags2));

    TRACE("[WINPROC] Process @ 0x%016llx has Mitigation Flags 2 = 0x%08x\n", EprocessAddress, flags2.Flags);

    return flags2.Flags != 0;
}


static INTSTATUS
IntWinProcEnforceProcessDep(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Enables DEP (Data Execution Prevention) for a certain process.
///
/// @param[in]  Process   The process to enable DEP for.
///
/// @retval     #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    DWORD offset;
    BYTE execopts;

    // Assume that DEP is not enforced
    Process->EnforcedDep = FALSE;

    // Not protected against exploits, leave it be.
    if (!Process->ProtExploits)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // If the process flags enable beta detections, don't do the DEP enforcement as it will crash the application.
    if (IntPolicyProcIsBeta(Process, 0))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // There is no way to not have DEP for a 64-bit process, so there's nothing left for us to do
    if (gGuest.Guest64 && !Process->Wow64Process)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    offset = WIN_KM_FIELD(Process, KexecOptions);
    if (0 == offset)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = IntKernVirtMemRead(Process->EprocessAddress + offset, 1, &execopts, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed fetching the _KEXECUTE_OPTIONS from %llx: 0x%08x\n", Process->EprocessAddress, status);
        return status;
    }

    // Make sure we clear ExecuteEnable and set ExecuteDisable and Permanent flags.
    execopts &= ~KEXEC_OPT_EXEC_ENABLE;
    execopts |= KEXEC_OPT_EXEC_DISABLE | KEXEC_OPT_PERMANENT;

    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, Process->EprocessAddress + offset, 1, &execopts, IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed patching the _KEXECUTE_OPTIONS at %llx: 0x%08x\n", Process->EprocessAddress, status);
        return status;
    }

    Process->EnforcedDep = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcPatchSpareValue(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Saves the process protection info within an EPROCESS spare field.
///
/// It uses an EPROCESS spare field to store the protection info for a given process (the first byte is '*',
/// while the second one saves the protection information as a bitmask).
///
/// @param[in]  Process   The process to save the information for.
///
/// @retval     #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    char c[2];

    if (!Process->Protected)
    {
        memcpy(c, &Process->OriginalSpareValue, 2);
    }
    else
    {
        c[0] = '*';
        c[1] = 0;

        if (Process->MonitorVad)
        {
            c[1] |= winProcExitVad;
        }

        if (Process->ProtWriteMem)
        {
            c[1] |= winProcExitWriteMemory;

            if (Process->Lsass)
            {
                c[1] |= winProcExitReadMemory;
            }
        }

        if (Process->ProtThreadCtx)
        {
            c[1] |= winProcExitThreadCtx;
        }

        if (Process->ProtQueueApc)
        {
            c[1] |= winProcExitQueueApc;
        }

        if (Process->ProtInstrument)
        {
            c[1] |= winProcExitSetProcInfo;
        }
    }

    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                 Process->EprocessAddress + WIN_KM_FIELD(Process, Spare),
                                 sizeof(c),
                                 &c,
                                 IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcMarkAgent(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BOOLEAN Mark
    )
///
/// @brief      Mark the given process as being an agent.
///
/// In order to improve performance, we will store a '?' character in the ImageName[14] for the
/// agent processes. In case the Introcore will start again, we will know this is an agent.
///
/// @param[in]  Process   The agent process.
/// @param[in]  Mark      TRUE if the process needs to be marked, FALSE otherwise.
///
/// @retval     #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    CHAR c;

    c = Mark ? '?' : '\0';

    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                 Process->EprocessAddress + WIN_KM_FIELD(Process, Name) + 14,
                                 1,
                                 &c,
                                 IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcSendAgentEvent(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BOOLEAN Created
    )
///
/// @brief      Send a process creation/termination event that symbolizes an agent.
///
/// If the current process is and agent, send an agent process creation/termination event.
///
/// @param[in]  Process   The agent process.
/// @param[in]  Created   TRUE if the process was created, FALSE otherwise.
///
/// @retval     #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    PEVENT_AGENT_EVENT pAgentEvent;

    if (!Process->IsAgent)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pAgentEvent = &gAlert.Agent;
    memzero(pAgentEvent, sizeof(*pAgentEvent));

    pAgentEvent->Event = Created ? agentStarted : agentTerminated;
    pAgentEvent->AgentTag = Process->AgentTag;

    if (!Created)
    {
        pAgentEvent->ErrorCode = Process->ExitStatus;
    }

    IntAlertFillWinProcessCurrent(&pAgentEvent->CurrentProcess);

    status = IntNotifyIntroEvent(introEventAgentEvent, pAgentEvent, sizeof(*pAgentEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcSendProcessEvent(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BOOLEAN Created,
    _In_ BOOLEAN Crashed
    )
///
/// @brief      Send a process creation/termination event.
///
/// If #INTRO_OPT_EVENT_PROCESSES is set, send a process creation/termination event.
///
/// @param[in]  Process   The process to send the event for.
/// @param[in]  Created   TRUE if the process was created, FALSE otherwise.
/// @param[in]  Crashed   TRUE if the process was terminated because a crash occurred.
///
/// @retval     #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    PEVENT_PROCESS_EVENT pProcEvent;
    WIN_PROCESS_OBJECT *pParent;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_PROCESSES))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pProcEvent = &gAlert.Process;
    memzero(pProcEvent, sizeof(*pProcEvent));

    pProcEvent->Created = Created;
    pProcEvent->Protected = Process->Protected ? TRUE : FALSE;
    pProcEvent->Crashed = Crashed;
    pProcEvent->ExitStatus = Process->ExitStatus;

    IntAlertFillWinProcessCurrent(&pProcEvent->CurrentProcess);

    IntAlertFillWinProcess(Process, &pProcEvent->Child);

    pParent = IntWinProcFindObjectByEprocess(Process->ParentEprocess);
    if (NULL != pParent)
    {
        IntAlertFillWinProcess(pParent, &pProcEvent->Parent);
    }
    else
    {
        pProcEvent->Parent.Valid = FALSE;
    }

    status = IntNotifyIntroEvent(introEventProcessEvent, pProcEvent, sizeof(*pProcEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntWinProcSendProcessExceptionEvent(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Send a process exception event.
///
/// If #INTRO_OPT_EVENT_PROCESS_CRASH is set, send a process exception event.
///
/// @param[in]  Process   The process to send the event for.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     If there was no exception or the event is not activated.
///
{
    INTSTATUS status;
    PEVENT_EXCEPTION_EVENT pExceptionEvent;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_PROCESS_CRASH))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (0 == Process->LastException)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    LOG("[PROCESS] Last exception encountered in %s: 0x%08x @ RIP 0x%016llx\n",
        Process->Name, Process->LastException, Process->LastExceptionRip);

    pExceptionEvent = &gAlert.Exception;
    memzero(pExceptionEvent, sizeof(*pExceptionEvent));

    pExceptionEvent->Continuable = Process->LastExceptionContinuable;
    pExceptionEvent->ExceptionCode = Process->LastException;
    pExceptionEvent->Rip = Process->LastExceptionRip;

    IntAlertFillWinProcess(Process, &pExceptionEvent->CurrentProcess);

    status = IntNotifyIntroEvent(introEventExceptionEvent, pExceptionEvent, sizeof(*pExceptionEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static void
IntWinProcFillSystemPath(
    _In_ WIN_PROCESS_SUBSYSTEM *Subsystem
    )
///
/// @brief      Fill the system directory path for the given subsystem.
///
/// @param[in]  Subsystem   The subsystem to for which the system directory path needs to be filled.
///
{
    if (gGuest.Guest64 && (winSubsys32Bit == Subsystem->SubsystemType))
    {
        Subsystem->SystemDirPath = gSysWowPath;
    }
    else
    {
        Subsystem->SystemDirPath = gSystemPath;
    }
}


INTSTATUS
IntWinProcCreateProcessSubsystem(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Out_ WIN_PROCESS_SUBSYSTEM **Subsystem,
    _In_ BYTE SubsystemType
    )
///
/// @brief      Create a process subsystem for the given process.
///
/// @param[in]  Process         The process to create the subsystem for.
/// @param[out] Subsystem       The allocated subsystem.
/// @param[in]  SubsystemType   The subsystem type (SUBSYSTEM_32BIT or SUBSYSTEM_64BIT).
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the memory allocation failed.
///
{
    WIN_PROCESS_SUBSYSTEM *pSubs = HpAllocWithTag(sizeof(*pSubs), IC_TAG_SUBS);
    if (NULL == pSubs)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSubs->Process = Process;
    pSubs->SubsystemType = SubsystemType;

    InitializeListHead(&pSubs->ProcessModules);

    IntWinProcFillSystemPath(pSubs);

    *Subsystem = pSubs;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcRemoveSubsystem(
    _In_ WIN_PROCESS_SUBSYSTEM *Subsystem
    )
///
/// @brief      Removes a process subsystem.
///
/// @param[in] Subsystem       The subsystem to be removed.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the Subsystem parameter is NULL.
///
{
    LIST_ENTRY *listMod;
    PWIN_PROCESS_MODULE pMod;

    if (NULL == Subsystem)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    listMod = Subsystem->ProcessModules.Flink;
    while (listMod != &Subsystem->ProcessModules)
    {
        pMod = CONTAINING_RECORD(listMod, WIN_PROCESS_MODULE, Link);

        listMod = listMod->Flink;

        RemoveEntryList(&pMod->Link);

        IntWinModUnHookModule(pMod);

        IntWinModRemoveModule(pMod);
    }

    HpFreeAndNullWithTag(&Subsystem, IC_TAG_SUBS);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinGetProcCmdLineHandleBufferInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      Called from within #IntSwapMemReadData when the command line buffer of a process has been fully read.
///
/// This function will copy the command line to the #WIN_PROCESS_OBJECT::CommandLine
/// and inspect it if #PROC_OPT_PROT_SCAN_CMD_LINE is set for the process in questions.
///
/// @param[in]  Context             The #WIN_PROCESS_OBJECT structure.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WIN_PROCESS_OBJECT *pProcess = NULL;
    PCHAR pCmdLine = NULL;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pProcess = (PWIN_PROCESS_OBJECT)Context;

    pProcess->CmdBufSwapHandle = NULL;

    // The command line is a WCHAR buffer that is not necessarily NULL-terminated. Introcore saves it as a
    // NULL-terminated CHAR buffer, so allocate half the size + 1 extra CHAR for the NULL-terminator;
    // there's no need to explicitly add the NULL-terminator at the end, as the allocator already gives
    // as a 0-filled buffer.
    pProcess->CommandLineSize = DataSize / sizeof(WCHAR) + 1;

    pCmdLine = HpAllocWithTag(pProcess->CommandLineSize, IC_TAG_PCMD);
    if (NULL == pCmdLine)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // It is ok to pass CommandLineSize here as the function will stop at CommandLineSize - 1
    pProcess->CommandLine = utf16tolowerutf8(pCmdLine, Data, pProcess->CommandLineSize);

    TRACE("[PROCESS] Process `%s` with PID %d and EPROCESS `0x%016llx` started with command line `%s`\n",
          pProcess->Name, pProcess->Pid, pProcess->EprocessAddress, pProcess->CommandLine);

    // For chrome.exe, check if this is a NaCl instance
    if (0 == strcasecmp(pProcess->Name, "chrome.exe"))
    {
#define NACL_CMD_LINE       "--type=nacl-loader"   // NaCl processes have this switch in the command line

        if (strstr(pProcess->CommandLine, NACL_CMD_LINE))
        {
            LOG("[WINPROC] Process `%s` (%d) with command line `%s` has NaCl enabled!\n",
                pProcess->Name, pProcess->Pid, pProcess->CommandLine);
            pProcess->HasNaClEnabled = TRUE;
        }
    }

    if (pProcess->ProtectionMask & PROC_OPT_PROT_SCAN_CMD_LINE)
    {
        status = IntWinInspectCommandLine(pProcess);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPsInspectCommandLine failed: 0x%x\n", status);
        }
    }

    return status;
}


static INTSTATUS
IntWinGetPrcoCmdLineHandleCmdLineInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      Called from within #IntSwapMemReadData when the #UNICODE_STRING32 or #UNICODE_STRING64 structure
/// that contains the command line buffer of a process has been read.
///
/// @param[in]  Context             The #WIN_PROCESS_OBJECT structure.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WIN_PROCESS_OBJECT *pProcess = Context;
    DWORD readLength;
    QWORD gva;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pProcess->CmdLineSwapHandle = NULL;

    readLength = (pProcess->ProtectionMask & PROC_OPT_PROT_SCAN_CMD_LINE) ?
                 CMDLINE_MAX_LEN : (CMDLINE_LEN_NO_SCAN * sizeof(WCHAR));

    if ((gGuest.Guest64 && pProcess->Wow64Process) || (!gGuest.Guest64))
    {
        UNICODE_STRING32 *pUsCmdLine = (UNICODE_STRING32 *)Data;

        readLength = MIN(readLength, pUsCmdLine->Length);
        gva = pUsCmdLine->Buffer;
    }
    else
    {
        UNICODE_STRING64 *pUsCmdLine = (UNICODE_STRING64 *)Data;

        readLength = MIN(readLength, pUsCmdLine->Length);
        gva = pUsCmdLine->Buffer;
    }

    status = IntSwapMemReadData(pProcess->Cr3, gva, readLength, SWAPMEM_OPT_UM_FAULT, Context, 0,
                                IntWinGetProcCmdLineHandleBufferInMemory, NULL, &pProcess->CmdBufSwapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%x\n", status);
    }

    return status;
}


static INTSTATUS
IntWinGetPrcoCmdLineHandleUserParamsInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      Called from within #IntSwapMemReadData when the #RTL_USER_PROCESS_PARAMETERS32
/// or #RTL_USER_PROCESS_PARAMETERS64 structure of the process (Context) has been read.
///
/// @param[in]  Context             The #WIN_PROCESS_OBJECT structure.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT *pProcess = Context;
    DWORD readSize;
    QWORD usersParamsGva;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    pProcess->ParamsSwapHandle = NULL;

    if ((gGuest.Guest64 && pProcess->Wow64Process) || (!gGuest.Guest64))
    {
        usersParamsGva = *(DWORD *)Data;
        usersParamsGva += FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS32, CommandLine);
        readSize = sizeof(UNICODE_STRING32);
    }
    else
    {
        usersParamsGva = *(QWORD *)Data;
        usersParamsGva += FIELD_OFFSET(RTL_USER_PROCESS_PARAMETERS64, CommandLine);

        readSize = sizeof(UNICODE_STRING64);
    }

    // read UserParameters.CommandLine
    status = IntSwapMemReadData(pProcess->Cr3, usersParamsGva, readSize, SWAPMEM_OPT_UM_FAULT, Context,
                                0, IntWinGetPrcoCmdLineHandleCmdLineInMemory, NULL, &pProcess->CmdLineSwapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%x\n", status);
    }

    return status;
}


INTSTATUS
IntWinProcReadCommandLine(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Reads the command line of the given process using #IntSwapMemReadData.
///
/// @param[in]  Process     The process to read the command line from.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
///
{
    INTSTATUS status;
    QWORD gva;
    DWORD readSize;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if ((gGuest.Guest64 && Process->Wow64Process) || (!gGuest.Guest64))
    {
        if (0 == Process->Peb32Address)
        {
            WARNING("[WARNING] Peb32 is NULL!\n");
            return INT_STATUS_NOT_INITIALIZED_HINT;
        }

        gva = Process->Peb32Address + FIELD_OFFSET(PEB32, ProcessParameters);
        readSize = sizeof(DWORD);
    }
    else
    {
        if (0 == Process->Peb64Address)
        {
            WARNING("[WARNING] Peb64 is NULL!\n");
            return INT_STATUS_NOT_INITIALIZED_HINT;
        }

        gva = Process->Peb64Address + FIELD_OFFSET(PEB64, ProcessParameters);

        readSize = sizeof(QWORD);
    }

    // Read Peb.RtlUserProcessParameters
    status = IntSwapMemReadData(Process->Cr3, gva, readSize, SWAPMEM_OPT_UM_FAULT, Process, 0,
                                IntWinGetPrcoCmdLineHandleUserParamsInMemory, NULL, &Process->ParamsSwapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%x\n", status);
    }

    return status;
}


static void
IntWinProcGetImageBaseNameFromPath(
    _In_ const WCHAR *FullPath,
    _Out_writes_z_(IMAGE_BASE_NAME_LEN) CHAR *BaseName,
    _Out_ const WCHAR **FullName
    )
///
/// @brief      Get the BaseName and FullName of an image from the FullPath.
///
/// @param[in]  FullPath     The full path of an image.
/// @param[out] BaseName     The base name of an image (limited to #IMAGE_BASE_NAME_LEN).
/// @param[out] FullName     The full name of an image.
///
{
    SIZE_T fplen, len;
    DWORD i;
    const WCHAR *pivot;

    len = 0;
    fplen = wstrlen(FullPath);

    // copy the base name locally.
    pivot = FullPath + fplen;

    do
    {
        pivot--;
    } while ((pivot >= FullPath) && (*pivot != u'\\'));

    pivot++;

    *FullName = pivot;

    for (i = 0; (i < 15) && (pivot[i] != 0); i++)
    {
        BaseName[i] = (CHAR)pivot[i]; // This is what the kernel does internally, so we're safe.
    }

    BaseName[i] = 0;

    while ((len < IMAGE_BASE_NAME_LEN) && (BaseName[len] != 0))
    {
        len++;
    }

    // Fill in the end of the name with NULLs.
    if (len < IMAGE_BASE_NAME_LEN)
    {
        memset(BaseName + len, 0, IMAGE_BASE_NAME_LEN - len);
    }

    BaseName[14] = 0;
}


static const PROTECTED_PROCESS_INFO *
IntWinProcGetProtectedInfo(
    _In_ CHAR BaseName[IMAGE_BASE_NAME_LEN],
    _In_ BOOLEAN IsSystem
    )
///
/// @brief      Returns a pointer to the #PROTECTED_PROCESS_INFO structure for the given process BaseName.
///
/// @param[in]  BaseName    The name of the process.
/// @param[in]  IsSystem    TRUE if the process is system process, FALSE otherwise.
///
/// @retval #PROTECTED_PROCESS_INFO If the process is protected.
/// @retval NULL If the process is NOT protected.
///
{
    LIST_ENTRY *list;

    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_MISC_PROCS))
    {
        for (DWORD i = 0; i < ARRAYSIZE(gWinForcedProtectedProcesses); i++)
        {
            if (IntMatchPatternUtf8(gWinForcedProtectedProcesses[i].ImageBaseNamePattern,
                                    BaseName,
                                    INTRO_MATCH_TRUNCATED))
            {
                return &gWinForcedProtectedProcesses[i];
            }
        }

        list = gWinProtectedProcesses.Flink;
        while (list != &gWinProtectedProcesses)
        {
            const PROTECTED_PROCESS_INFO *pProc = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

            list = list->Flink;

            if (IntMatchPatternUtf8(pProc->ImageBaseNamePattern, BaseName, INTRO_MATCH_TRUNCATED))
            {
                return pProc;
            }
        }
    }

    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_SYS_PROCS) && IsSystem)
    {
        for (DWORD i = 0; i < ARRAYSIZE(gSystemProcesses); i++)
        {
            if (IntMatchPatternUtf8(gSystemProcesses[i].ImageBaseNamePattern, BaseName, INTRO_MATCH_TRUNCATED))
            {
                return &gSystemProcesses[i];
            }
        }
    }

    return NULL;
}


const PROTECTED_PROCESS_INFO *
IntWinProcGetProtectedInfoEx(
    _In_ PWCHAR Path,
    _In_ BOOLEAN IsSystem
    )
///
/// @brief      Returns a pointer to the #PROTECTED_PROCESS_INFO structure for the given process Path.
///
/// @param[in]  Path        The path of the process.
/// @param[in]  IsSystem    TRUE if the process is system process, FALSE otherwise.
///
/// @retval #PROTECTED_PROCESS_INFO If the process is protected.
/// @retval NULL If the process is NOT protected.
///
{
    LIST_ENTRY *list;
    CHAR baseName[16];
    const WCHAR *fullName;
    BOOLEAN match;

    fullName = NULL;

    IntWinProcGetImageBaseNameFromPath(Path, baseName, &fullName);

    // Search the misc process list.
    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_MISC_PROCS))
    {
        for (DWORD i = 0; i < ARRAYSIZE(gWinForcedProtectedProcesses); i++)
        {
            // Make sure the image base name matches.
            match = IntMatchPatternUtf8(gWinForcedProtectedProcesses[i].ImageBaseNamePattern,
                                        baseName,
                                        INTRO_MATCH_TRUNCATED);

            // Make sure the full name matches.
            match = match && IntMatchPatternUtf16(gWinForcedProtectedProcesses[i].FullNamePattern, fullName, 0);

            if (match)
            {
                return &gWinForcedProtectedProcesses[i];
            }
        }

        list = gWinProtectedProcesses.Flink;
        while (list != &gWinProtectedProcesses)
        {
            const PROTECTED_PROCESS_INFO *pProc = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

            list = list->Flink;

            // Make sure the image base name matches.
            match = IntMatchPatternUtf8(pProc->ImageBaseNamePattern, baseName, INTRO_MATCH_TRUNCATED);

            // Make sure the full name matches.
            match = match && IntMatchPatternUtf16(pProc->FullNamePattern, fullName, 0);

            // Make sure the full path matches, if present.
            if ((0 != (gGuest.CoreOptions.Current & INTRO_OPT_FULL_PATH)) &&
                (0 == (pProc->Flags & PROT_PROC_FLAG_NO_PATH)))
            {
                match = match && IntMatchPatternUtf16(pProc->FullPathPattern, Path, 0);
            }

            if (match)
            {
                return pProc;
            }
        }
    }

    // Search the system process list,
    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_UM_SYS_PROCS) && IsSystem)
    {
        for (DWORD i = 0; i < ARRAYSIZE(gSystemProcesses); i++)
        {
            // Make sure the image base name matches.
            match = IntMatchPatternUtf8(gSystemProcesses[i].ImageBaseNamePattern, baseName, INTRO_MATCH_TRUNCATED);

            // Make sure the full name matches.
            match = match && IntMatchPatternUtf16(gSystemProcesses[i].FullNamePattern, fullName, 0);

            if (match)
            {
                return &gSystemProcesses[i];
            }
        }
    }

    return NULL;
}


INTSTATUS
IntWinProcUpdateProtection(
    void
    )
///
/// @brief      Iterates trough the global process list (#gWinProcesses) in order to update the protection state for
/// each process.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    LIST_ENTRY *pList = gWinProcesses.Flink;
    while (pList != &gWinProcesses)
    {
        INTSTATUS status;
        WIN_PROCESS_OBJECT *pProc = CONTAINING_RECORD(pList, WIN_PROCESS_OBJECT, Link);
        const PROTECTED_PROCESS_INFO *pProtInfo;

        pList = pList->Flink;

        if (pProc->SystemProcess && pProc->Protected)
        {
            pProc->BetaDetections = gGuest.SysprocBetaDetections;
        }

        // Check if the process is protected or not.
        if (NULL != pProc->Path)
        {
            pProtInfo = IntWinProcGetProtectedInfoEx(pProc->Path->Path, !!pProc->SystemProcess);
        }
        else
        {
            pProtInfo = IntWinProcGetProtectedInfo(pProc->Name, !!pProc->SystemProcess);
        }

        if (NULL != pProtInfo)
        {
            // We can end up with an inconsistent state if we attempt to re-protect a process (we could deactivate
            // the protection and then re-activate it with the new flags).
            // Note that the next time a process with the given name will start, the flags provided now will be used
            // to protect it.
            if (pProc->Context != pProtInfo->Context)
            {
                pProc->Context = pProtInfo->Context;
            }

            pProc->FeedbackMask = pProtInfo->Protection.Feedback;
            pProc->BetaMask = pProtInfo->Protection.Beta;

            if (pProc->Protected && (pProtInfo->Protection.Current != pProc->ProtectionMask))
            {
                // Process is already protected, but with other flags.
                LOG("[PROCESS] Changing protection flags for process %s (Eprocess %llx): 0x%x -> 0x%x\n",
                    pProc->Name, pProc->EprocessAddress, pProc->ProtectionMask, pProtInfo->Protection.Original);

                status = IntWinProcChangeProtectionFlags(pProc, pProc->ProtectionMask, pProtInfo->Protection.Original);
                if (!INT_SUCCESS(status))
                {
                    INTSTATUS status2;

                    status2 = IntWinProcUnprotect(pProc);
                    if (!INT_SUCCESS(status2))
                    {
                        ERROR("[ERROR] IntWinProcUnprotect failed: 0x%08x\n", status2);
                    }

                    memset(&gErrorContext, 0, sizeof(gErrorContext));
                    IntAlertFillWinProcess(pProc, &gErrorContext.ProcessProtection.Process);
                    gErrorContext.ProcessProtection.Count = gTotalProtectedProcs;

                    IntNotifyIntroErrorState(INT_STATUS_INSUFFICIENT_RESOURCES == status ?
                                             intErrProcNotProtectedNoMemory : intErrProcNotProtectedInternalError,
                                             &gErrorContext);
                }
            }
            else if (!pProc->Protected)
            {
                LOG("[PROCESS] Process %s (Eprocess %llx) has already started, will activate static protection\n",
                    pProc->Name, pProc->EprocessAddress);

                pProc->LateProtection = TRUE;
                pProc->ProtectionMask = pProtInfo->Protection.Current;

                pProc->Protected = TRUE;
                pProc->Context = pProtInfo->Context;

                status = IntWinProcProtect(pProc);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinProcActivateProtection failed: 0x%x\n", status);
                }
            }
        }
        else
        {
            if (pProc->Protected)
            {
                LOG("[PROCESS] Deactivating protection for process %s (Pid %d, Cr3 0x%016llx)\n",
                    pProc->Name, pProc->Pid, pProc->Cr3);

                status = IntWinProcUnprotect(pProc);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinProcUnhookProcess failed for 0x%016llx (Cr3 0x%016llx): 0x%08x\n",
                          pProc->EprocessAddress, pProc->Cr3, status);
                }
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static void
IntWinProcHandleDuplicate(
    _In_ QWORD Cr3,
    _In_ QWORD Eprocess
    )
///
/// @brief  Ensures that a newly created process does not exist already.
///
/// Duplicates are searched by Cr3 and Eprocess GLA. If one exists, it is removed as it's probably terminated by now.
/// Note that we don't need to invalidate caches or terminate protection, as this scenario only happens on resume
/// from hibernate, where we iterate the process list, and we identify a process that has been terminated, but it
/// wasn't removed from the process list just yet. We will remove it from our list as soon as another process with the
/// same CR3 is created. Until then, it can simply remain there, as it doesn't pose any issues.
///
/// @param[in]  Cr3         The Cr3 of the newly created process. For process for which KPTI is on this is the kernel
///                         Cr3.
/// @param[in]  Eprocess    The GLA of the newly created EPROCESS.
///
{
    WIN_PROCESS_OBJECT *duplicate;

    duplicate = IntWinProcFindObjectByCr3(Cr3);
    if (NULL != duplicate)
    {
        INTSTATUS status;

        ERROR("[ERROR] Duplicate process for CR3 0x%016llx: '%s', will remove it.\n", Cr3, duplicate->Name);

        status = IntWinProcDeleteProcessObject(duplicate->EprocessAddress, Cr3, duplicate->Pid);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcDeleteProcessObject failed: 0x%08x\n", status);
        }
    }

    duplicate = IntWinProcFindObjectByEprocess(Eprocess);
    if (NULL != duplicate)
    {
        INTSTATUS status;

        ERROR("[ERROR] Duplicate process for EPROCESS 0x%016llx: '%s', will remove it.\n", Eprocess, duplicate->Name);

        status = IntWinProcDeleteProcessObject(Eprocess, duplicate->Cr3, duplicate->Pid);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcDeleteProcessObject failed: 0x%08x\n", status);
        }
    }
}


static void
IntWinProcSetUserCr3(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ const BYTE *EprocessBuffer
    )
///
/// @brief  Sets the User CR3 value for a newly created process.
///
/// Handles all possible cases.
///
/// @param[in, out] Process         The process object for which to set the #WIN_PROCESS_OBJECT.UserCr3 field. For
///                                 64-bit guests with KPTI active, this is the value of the UserCr3 EPROCESS field
///                                 (see #winKmFieldProcessUserCr3), as long as it is at least 0x1000. For 32-bit
///                                 processes, this will be the kernel Cr3 or'ed with 0x20. If KPTI is not active
///                                 this will have the same value as the kernel Cr3.
/// @param[in]      EprocessBuffer  A buffer that maps the EPROCESS structure. The buffer should be large enough
///                                 to fir the UserCr3 field.
///
{
    if (gGuest.KptiActive)
    {
        if (gGuest.Guest64)
        {
            Process->UserCr3 = *(QWORD const *)(EprocessBuffer + WIN_KM_FIELD(Process, UserCr3));

            if (Process->UserCr3 < PAGE_SIZE)
            {
                Process->UserCr3 = Process->Cr3;
            }
        }
        else
        {
            if (Process->Pid != 4)
            {
                Process->UserCr3 = Process->Cr3 | 0x20;
            }
            else
            {
                Process->UserCr3 = Process->Cr3;
            }
        }
    }
    else
    {
        Process->UserCr3 = Process->Cr3;
    }
}


static INTSTATUS
IntWinProcLockCr3(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Locks the kernel and user Cr3 of a process in memory.
///
/// We do not want the OS to change the process CR3.
/// If this fails, introcore is disabled.
///
/// Locking is done using #IntWinPfnLockGpa.
///
/// @param[in, out] Process The process for which to lock the CR3. The #WIN_PFN_LOCK handle will be saved inside
///                         the process object.
///
/// @returns        #INT_STATUS_SUCCESS in case of success, or an appropriate #INTSTATUS value in case of error.
///
{
    INTSTATUS status;

    status = IntWinPfnLockGpa(Process->Cr3, (WIN_PFN_LOCK **)&Process->Cr3PageLockObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinPfnLockGpa failed for process '%s', eprocess %llx, cr3 %llx: 0x%08x\n",
              Process->Name, Process->EprocessAddress, Process->Cr3, status);

        gGuest.DisableOnReturn = TRUE;

        return status;
    }

    if ((Process->UserCr3 != Process->Cr3) && (Process->UserCr3 >= PAGE_SIZE))
    {
        status = IntWinPfnLockGpa(Process->UserCr3, (PWIN_PFN_LOCK *)&Process->UserCr3PageLockObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnLockGpa failed for process '%s', eprocess %llx, user cr3 %llx: 0x%08x\n",
                  Process->Name, Process->EprocessAddress, Process->UserCr3, status);

            gGuest.DisableOnReturn = TRUE;

            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcUnlockCr3(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Unlocks the kernel and user Cr3 of a process in memory.
///
/// Unlocking is done using #IntWinPfnRemoveLock.
///
/// @param[in, out] Process The process for which to unlock the CR3. The #WIN_PFN_LOCK handle will be saved inside
///                         the process object.
///
/// @returns        #INT_STATUS_SUCCESS in case of success, or an appropriate #INTSTATUS value in case of error.
///
{
    INTSTATUS status;

    if (NULL != Process->Cr3PageLockObject)
    {
        status = IntWinPfnRemoveLock(Process->Cr3PageLockObject, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnRemoveLock failed: 0x%08x\n", status);
        }

        Process->Cr3PageLockObject = NULL;
    }

    if (NULL != Process->UserCr3PageLockObject)
    {
        status = IntWinPfnRemoveLock(Process->UserCr3PageLockObject, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnRemoveLock failed: 0x%08x\n", status);
        }

        Process->UserCr3PageLockObject = NULL;
    }

    return INT_STATUS_SUCCESS;
}


static void
IntWinProcMarkAsSystemProcess(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ const WIN_PROCESS_OBJECT *Parent
    )
///
/// @brief  Mark the process as being a system process.
///
/// A process is considered system if:
///     1. it is inside the gSystemProcesses array
///     2. it is started by another System process.
///
/// Initially, the System is the only System process, so he is the root of all system processes.
///
/// @param[in, out] Process     The process to be checked. The #WIN_PROCESS_OBJECT.SystemProcess field will be set
///                             to TRUE if the process is a system process.
/// @param[in]      Parent      The parent process.
///
{
    for (DWORD i = 0; i < ARRAYSIZE(gSystemProcesses); i++)
    {
        if (0 == strcasecmp(Process->Name, gSystemProcesses[i].ImageBaseNamePattern))
        {
            // We've found a system process name. Make sure it was started by another system process.
            // Special case is services.exe, which although is flagged as system, can't spawn other system processes.
            // If it could, it would be trivial to register a service 'c:\csrss.exe', which would be started by
            // services.exe, and would be flagged as system.
            if ((NULL != Parent) && (Parent->SystemProcess))
            {
                if (0 == strcasecmp("services.exe", Parent->Name))
                {
                    WARNING("[WARNING] Process '%s' is started by services.exe! Will not be flagged as system!\n",
                            Process->Name);
                }
                else
                {
                    Process->SystemProcess = TRUE;
                }
            }
            else if (NULL == Parent && 0 == Process->ParentEprocess)
            {
                // This is an important thing: if we are being initialized from within the OS or after hibernation,
                // we CAN'T safely determine if a process is system or not. Therefore, we will do a hack: whenever
                // a process with a system name is created, and that process is not in fact a system process, we will
                // slightly patch it's name, so that it won't match anymore on resume from hibernation.
                // Right here we assume that all processes that have a system name are actually legitimate. If we're
                // being started from within the OS, we can assume anything - the system may well be very infected
                // already. Note that we will have a parent when we monitor process creation, but we don't have the
                // parent when getting the already created list of processes. In that case, the parent will be 0.
                Process->SystemProcess = TRUE;
            }

            // We had name match, but the process isn't in fact system. We have to patch the name.
            if (!Process->SystemProcess)
            {
                BYTE c = '!';
                INTSTATUS status;

                WARNING("[WARNING] Process '%s' is not in fact system; parent is 0x%016llx\n",
                        Process->Name, Process->ParentEprocess);

                // Scramble the name inside the EPROCESS.
                status = IntVirtMemSafeWrite(0, Process->EprocessAddress + WIN_KM_FIELD(Process, Name),
                                             1, &c, IG_CS_RING_0);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
                }
            }

            break;
        }
    }
}


INTSTATUS
IntWinProcCreateProcessObject(
    _Out_ WIN_PROCESS_OBJECT **Process,
    _In_ QWORD EprocessAddress,
    _In_ PBYTE EprocessBuffer,
    _In_ QWORD ParentEprocess,
    _In_ QWORD RealParentEprocess,
    _In_ QWORD Cr3,
    _In_ DWORD Pid,
    _In_ BOOLEAN StaticScan
    )
///
/// @brief      Allocates a #WIN_PROCESS_OBJECT structure for the given process.
///
/// This function is responsible for allocating a #WIN_PROCESS_OBJECT structure for the given process, reading its
/// command line if necessary, importing its main module VAD, protecting the process, sending a notification to the
/// integrator, etc.
///
/// If the process is swapped-out we no longer:
///     - lock the CR3
///     - read the command line
///     - check the self-map bits
///     - import the main module vad
///     - activate protection
///
/// The protection is activated when the process is swapped-in (IntWinProcSwapIn).
///
/// @param[out] Process             The internally allocate process object.
/// @param[in]  EprocessAddress     The EPROCESS address of the process.
/// @param[in]  EprocessBuffer      The address of the EPROCESS mapping.
/// @param[in]  ParentEprocess      The EPROCESS address of the parent process.
/// @param[in]  RealParentEprocess  The EPROCESS address of the real parent process.
/// @param[in]  Cr3                 The address space.
/// @param[in]  Pid                 The process identifier.
/// @param[in]  StaticScan          TRUE if the process already existed but was found only now (when initializing the
///                                 introspection), FALSE if this process was just created.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    BOOLEAN isAgent;
    WIN_PROCESS_OBJECT *pProc, *pParent, *pRealParent;
    const BOOLEAN protTokenPtr = 0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PTR);
    const BOOLEAN protTokenPrivs = 0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS);
    DWORD flags = 0;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == EprocessAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == EprocessBuffer)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    IntWinProcHandleDuplicate(Cr3, EprocessAddress);

    pProc = HpAllocWithTag(sizeof(*pProc), IC_TAG_POBJ);
    if (NULL == pProc)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    flags = *(DWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Flags));
    pProc->Outswapped = !!(flags & WIN_KM_FIELD(EprocessFlags, OutSwapped));

    // Now we can actually initialize the process.
    STATIC_ASSERT(IMAGE_BASE_NAME_LEN == 2 * sizeof(QWORD), "QWORD by QWORD copy of process name will fail");

    *(QWORD *)(pProc->Name) = *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Name));
    *(QWORD *)(pProc->Name + sizeof(QWORD)) = *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Name) + sizeof(QWORD));

    pProc->Name[CSTRLEN(pProc->Name)] = 0;

    // Workaround for system process, which doesn't have a ImageName
    if ((pProc->Name[0] == 0) && (4 == Pid))
    {
        strlcpy(pProc->Name, "system", sizeof(pProc->Name));
    }

    IntWinVadProcessInit(pProc);

    strlower_utf8(pProc->Name, strlen(pProc->Name));

    pProc->NameHash = Crc32String(pProc->Name, INITIAL_CRC_VALUE);
    pProc->Cr3 = Cr3;
    pProc->Pid = Pid;
    pProc->EprocessAddress = EprocessAddress;
    pProc->ParentEprocess = ParentEprocess;
    pProc->RealParentEprocess = RealParentEprocess;
    pProc->StaticDetected = StaticScan;
    pProc->LateProtection = StaticScan;

    IntWinProcSetUserCr3(pProc, EprocessBuffer);


    if (!pProc->Outswapped)
    {
        // Lock the CR3 of this process in memory. We don't want the OS to mangle with the CR3, since it is used
        // for exceptions.
        // NOTE: This is a hard-error, we disable Introcore if this fails.
        status = IntWinProcLockCr3(pProc);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }
    }

    if (4 != Pid)
    {
        pProc->CreationTime = *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, CreateTime));
    }
    else
    {
        // Workaround for the System process: when the System process is originally created, it has
        // CreationTime 0. Sometimes after that, the kernel will modify it to reflect the actual creation
        // time, but it's too late for us. In order to ensure that we will always have the same uuid for the
        // System process, we force the Creationtime to 0.
        pProc->CreationTime = 0;
    }

    if (gGuest.Guest64)
    {
        if (0 != WIN_KM_FIELD(Process, SectionBase))
        {
            pProc->MainModuleAddress = *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, SectionBase));
        }

        pProc->OriginalTokenPtr = EX_FAST_REF_TO_PTR(TRUE, *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Token)));

        if (4 != Pid)
        {
            pProc->Peb64Address = *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Peb));
            pProc->Peb32Address = *(QWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, WoW64));

            // Starting with Windows 10, build > 10240 (TH1), WoW64Process doesn't point directly to the
            // PEB32, but instead to a _EWOW64PROCESS, which contains the PEB address (first 8 bytes) and the
            // machine type (next 2 bytes).
            if (pProc->Peb32Address && gGuest.OSVersion > WIN_BUILD_10_TH1)
            {
                status = IntKernVirtMemFetchQword(pProc->Peb32Address, &pProc->Peb32Address);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx (EWOW64): 0x%08x\n",
                          pProc->Peb32Address,
                          status);

                    goto cleanup_and_exit;
                }
            }

            if (0 != pProc->Peb32Address && gGuest.Guest64)
            {
                pProc->Wow64Process = TRUE;
            }
        }
    }
    else
    {
        if (0 != WIN_KM_FIELD(Process, SectionBase))
        {
            pProc->MainModuleAddress = *(DWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, SectionBase));
        }

        pProc->OriginalTokenPtr = EX_FAST_REF_TO_PTR(FALSE, *(DWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Token)));

        if (4 != Pid)
        {
            pProc->Peb64Address = *(DWORD *)(EprocessBuffer + WIN_KM_FIELD(Process, Peb));
            pProc->Peb32Address = pProc->Peb64Address;

            pProc->Wow64Process = FALSE;
        }
    }

    // Protect the token privileges, if needed.
    status = IntWinTokenPrivsProtectOnProcess(pProc);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinTokenPrivsProtectOnProcess failed: 0x%08x\n", status);
    }

    status = IntWinSDProtectSecDesc(pProc);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinSDProtectSecDesc failed: 0x%08x\n", status);
    }

    // Get the original spare value. Applying the protection will overwrite the Spare field
    // in in-guest EPROCESS so we should save it before.
    status = IntKernVirtMemRead(pProc->EprocessAddress + WIN_KM_FIELD(Process, Spare),
                                sizeof(pProc->OriginalSpareValue), &pProc->OriginalSpareValue, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (0 != pProc->OriginalSpareValue)
    {
        WARNING("[WARNING] Spare value for eprocess 0x%016llx at offset %x is not 0! (0x%04x)\n",
                pProc->EprocessAddress, WIN_KM_FIELD(Process, Spare), pProc->OriginalSpareValue);
    }

    // pParent and pRealParent will be NULL if ParentEprocess, or RealParentEprocess are 0
    pParent = IntWinProcFindObjectByEprocess(pProc->ParentEprocess);
    pRealParent = IntWinProcFindObjectByEprocess(pProc->RealParentEprocess);

    if (protTokenPtr && !StaticScan)
    {
        if (pParent != NULL)
        {
            status = IntWinTokenPtrCheckIntegrityOnProcess(pParent);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinTokenPtrCheckIntegrityOnProcess failed for parent 0x%016llx: 0x%x\n",
                        pParent->EprocessAddress, status);
            }
        }

        if (pRealParent != NULL)
        {
            status = IntWinTokenPtrCheckIntegrityOnProcess(pRealParent);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinTokenPtrCheckIntegrityOnProcess failed for real parent 0x%016llx: 0x%x\n",
                        pRealParent->EprocessAddress, status);
            }
        }
    }

    if (protTokenPrivs && !StaticScan)
    {
        if (pParent != NULL)
        {
            status = IntWinTokenPrivsCheckIntegrityOnProcess(pParent);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinTokenPrivsCheckIntegrityOnProcess failed for parent 0x%016llx: 0x%x\n",
                        pParent->EprocessAddress, status);
            }
        }

        if (pRealParent != NULL)
        {
            status = IntWinTokenPrivsCheckIntegrityOnProcess(pRealParent);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinTokenPrivsCheckIntegrityOnProcess failed for real parent 0x%016llx: 0x%x\n",
                        pRealParent->EprocessAddress, status);
            }
        }
    }

    if (4 == Pid)
    {
        // The initial System process is always marked as system.
        pProc->SystemProcess = TRUE;

        if (pProc->Cr3 != gGuest.Mm.SystemCr3)
        {
            WARNING("[WARNING] Possible System CR3 (0x%016llx) mismatch: "
                    "System process (0x%016llx) has CR3 0x%016llx\n",
                    gGuest.Mm.SystemCr3, pProc->EprocessAddress, pProc->Cr3);
        }
    }

    IntWinProcMarkAsSystemProcess(pProc, pParent);

    // If this is the "services.exe" process, than this means the we can now safely inject remediation agents.
    if (0 == strcasecmp(pProc->Name, "services.exe"))
    {
        status = IntAgentEnableInjection();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAgentEnableInjection failed: 0x%08x\n", status);
        }

        status = IntWinGuestFindDriversNamespace();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinGuestFindDriversNamespace: 0x%08x\n", status);
        }

        if (gGuest.CoreOptions.Current & INTRO_OPT_IN_GUEST_PT_FILTER)
        {
            IntPtiInjectPtFilter();
        }
    }

    if (0 == strcasecmp(pProc->Name, "lsass.exe"))
    {
        pProc->Lsass = 1;
    }

    IntWinAgentCheckIfProcessAgentAndIncrement(pProc->Name, &isAgent, &pProc->AgentTag);

    pProc->IsAgent = isAgent;

    if (gGuest.Guest64)
    {
        // If we're on 64 bit windows than we will surely have 64 bit subsystem.
        status = IntWinProcCreateProcessSubsystem(pProc, &pProc->Subsystemx64, winSubsys64Bit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcCreateProcessSubsystem failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        pProc->Subsystemx64->PebAddress = pProc->Peb64Address;

        if (NULL != pParent && pParent->Wow64Process)
        {
            if (!pProc->Wow64Process)
            {
                TRACE("------------> Special case %s (0x%016llx) / 32 -> %s (0x%016llx) / 64\n",
                      pParent->Name, pParent->EprocessAddress, pProc->Name, pProc->EprocessAddress);
            }

            pProc->ParentWow64 = TRUE;
        }
    }

    if (!gGuest.Guest64 || pProc->Wow64Process)
    {
        // 32 bit guests and Wow64 processes also have a 32 bit subsystem.
        status = IntWinProcCreateProcessSubsystem(pProc, &pProc->Subsystemx86, winSubsys32Bit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcCreateProcessSubsystem failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        pProc->Subsystemx86->PebAddress = pProc->Peb32Address;
    }

    // Determine if the process will be protected or not. A process will be protected if:
    // 1. It is inside the list of protected processes.
    // 2. It is a system process
    // 3. The flag INTRO_OPT_ENABLE_PROTECTION_ALL was used at creation.
    // Note: we don't care about static protection; that must be enabled & used by default from now on!
    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_ENABLE_UM_PROTECTION))
    {
        const PROTECTED_PROCESS_INFO *pProtInfo = IntWinProcGetProtectedInfo(pProc->Name, !!pProc->SystemProcess);
        if (NULL != pProtInfo)
        {
            pProc->Protected = TRUE;
            pProc->ProtectionMask = pProtInfo->Protection.Current;
            pProc->BetaMask = pProtInfo->Protection.Beta;
            pProc->FeedbackMask = pProtInfo->Protection.Feedback;
            pProc->Context = pProtInfo->Context;
        }
    }

    // If we are running on Napoca, we don`t want to obtain the entire command line for multiple reasons:
    //      1) Napoca does not support the scan engines, so they can not call our callback function
    //         (resulting in a memory leak since the callback function is used to free the command line buffer).
    //      2) Reading the command line using #PF can bring an unnecessary performance penalty.
    if (!pProc->Outswapped)
    {
        if ((pProc->ProtectionMask & PROC_OPT_PROT_SCAN_CMD_LINE) && GlueIsScanEnginesApiAvailable())
        {
            status = IntWinProcReadCommandLine(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcReadCommandLine failed: 0x%x\n", status);
            }
        }
        else
        {
            for (DWORD i = 0; i < ARRAYSIZE(gCmdLineProcesses); i++)
            {
                if (0 == strncmp(pProc->Name, gCmdLineProcesses[i], strlen(pProc->Name)))
                {
                    status = IntWinProcReadCommandLine(pProc);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntWinProcReadCommandLine failed: 0x%x\n", status);
                    }

                    break;
                }
            }
        }
    }

    if (pProc->LateProtection || pProc->StaticDetected || pProc->SystemProcess)
    {
        pProc->StartInitializing = TRUE;
        pProc->Initialized = TRUE;

        // don't allow one time exceptions for static detected processes
        pProc->OneTimeInjectionDone = TRUE;
    }

    if (pProc->Protected)
    {
        pProc->ExploitGuardEnabled = IntWinProcIsExploitGuardEnabled(EprocessAddress, EprocessBuffer);
        TRACE("[WINPROC] Process `%s` has Exploit Guard %s\n",
              pProc->Name, pProc->ExploitGuardEnabled ? "Enabled" : "Disabled");
    }

    IntWinProcLstInsertProcess(pProc);

    if (pProc->StaticDetected && !pProc->IsAgent)
    {
        pProc->IsAgent = pProc->IsPreviousAgent = '?' == pProc->Name[14];
    }

    if (!pProc->Outswapped)
    {
        status = IntWinSelfMapGetAndCheckSelfMapEntry(pProc);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcGetAndCheckSelfMapEntry failed: 0x%08x\n", status);
        }
    }

    if (__unlikely(4 == pProc->Pid))
    {
        status = IntWinSelfMapProtectSelfMapIndex(pProc);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcProtectSelfMapIndex failed: 0x%08x\n", status);
        }
    }

    if (!pProc->Outswapped)
    {
        status = IntWinProcProtect(pProc);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcProtect failed: 0x%08x\n", status);
        }
    }

    if (!pProc->MonitorVad && !pProc->Outswapped)
    {
        // NOTE: The VAD tree is not imported when the process is out-swapped because the #WIN_PROCESS_OBJECT will be
        // deleted and a new #WIN_PROCESS_OBJECT will be created.
        status = IntWinVadProcImportMainModuleVad(pProc);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcImportMainModuleVad failed: 0x%08x\n", status);
        }
    }

    status = IntWinProcSendProcessEvent(pProc, TRUE, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcSendProcessEvent failed: 0x%08x\n", status);
    }

    status = IntWinProcSendAgentEvent(pProc, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcSendAgentEvent failed: 0x%08x\n", status);
    }

    TRACE("[PROCESS] '%s' (%08x), path %s, pid %d, EPROCESS 0x%016llx, CR3 0x%016llx, "
          "UserCR3 0x%016llx, parent at 0x%016llx/0x%016llx; %s, %s %s\n",
          pProc->Name, pProc->NameHash, pProc->Path ? utf16_for_log(pProc->Path->Path) : "<invalid>",
          Pid, pProc->EprocessAddress, pProc->Cr3, pProc->UserCr3, ParentEprocess, RealParentEprocess,
          pProc->SystemProcess ? "SYSTEM" : "not system", pProc->IsAgent ? "AGENT" : "not agent",
          pProc->Outswapped ? ", Outswapped" : "");

    *Process = pProc;

    return INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (NULL != pProc)
    {
        IntWinProcRemoveProcess(pProc);
    }

    return status;
}


static INTSTATUS
IntWinProcRemoveProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Used to free the memory allocations and swap memory transactions used by a #PWIN_PROCESS_OBJECT.
///
///     This function is responsible for restoring the EPROCESS spare value, removing any pending swap memory
/// transactions and freeing the #WIN_PROCESS_OBJECT structure.
///
/// @param[in] Process      The process object to be removed.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status;

    if (NULL != Process->Cr3PageLockObject)
    {
        status = IntWinPfnRemoveLock(Process->Cr3PageLockObject, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnRemoveLock failed: 0x%08x\n", status);
        }

        Process->Cr3PageLockObject = NULL;
    }

    if (NULL != Process->UserCr3PageLockObject)
    {
        status = IntWinPfnRemoveLock(Process->UserCr3PageLockObject, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnRemoveLock failed: 0x%08x\n", status);
        }

        Process->UserCr3PageLockObject = NULL;
    }

    // Restore the first two letters in the spare
    status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                 Process->EprocessAddress + WIN_KM_FIELD(Process, Spare),
                                 2,
                                 &Process->OriginalSpareValue,
                                 IG_CS_RING_0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
    }

    // Remove the command line swap handle.
    if (NULL != Process->CmdBufSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Process->CmdBufSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Process->CmdBufSwapHandle = NULL;
    }

    if (NULL != Process->CmdLineSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Process->CmdLineSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Process->CmdLineSwapHandle = NULL;
    }

    if (NULL != Process->ParamsSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(Process->ParamsSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }

        Process->ParamsSwapHandle = NULL;
    }

    if (NULL != Process->Subsystemx64)
    {
        status = IntWinProcRemoveSubsystem(Process->Subsystemx64);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcRemoveSubsystem failed: 0x%08x\n", status);
        }

        Process->Subsystemx64 = NULL;
    }

    if (NULL != Process->Subsystemx86)
    {
        status = IntWinProcRemoveSubsystem(Process->Subsystemx86);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcRemoveSubsystem failed: 0x%08x\n", status);
        }

        Process->Subsystemx86 = NULL;
    }

    if (NULL != Process->MainModuleVad)
    {
        IntWinVadDestroyObject((VAD **)&Process->MainModuleVad);
    }

    IntWinTokenPrivsUnprotectOnProcess(Process);

    // This must be the last thing done - we must call this AFTER removing all the other transactions
    // (those with handle) otherwise we may cause a use-after-free. Also, this must be done for TIB swaps - on
    // suspicious page executions, sometimes we need to swap in the TIB; there is no way to cleanly save handles for
    // those, since a page may be executed in the context of multiple threads, which would mean that it could be
    // possible to request multiple TIB swaps for the same page.
    status = IntSwapMemRemoveTransactionsForVaSpace(Process->Cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemRemoveTransactionsForVaSpace failed: 0x%08x\n", status);
    }

    if (NULL != Process->VadPages)
    {
        HpFreeAndNullWithTag(&Process->VadPages, IC_TAG_VADP);
    }

    if (NULL != Process->CommandLine)
    {
        HpFreeAndNullWithTag(&Process->CommandLine, IC_TAG_PCMD);
    }

    HpFreeAndNullWithTag(&Process, IC_TAG_POBJ);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinProcDeleteProcessObject(
    _In_ QWORD EprocessAddress,
    _In_ QWORD Cr3,
    _In_ DWORD Pid
    )
///
/// @brief      Used to delete the process from the Introcore internal structures.
///
/// This function is responsible for finding the process in the internal list (#gWinProcesses), sending any
/// necessary notifications to the integrator (process terminated, process crashed or agent process terminated),
/// disabling the protection, deleting the process object, etc.
///
/// @param[in] EprocessAddress      The address of the eprocess to be deleted.
/// @param[in] Cr3                  The address space.
/// @param[in] Pid                  The process identifier.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If the process was not found in the internal list (#gWinProcesses).
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BOOLEAN bFound = FALSE;
    BOOLEAN isAgent = FALSE;

    LIST_ENTRY *list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        list = list->Flink;

        // Reset the parent EPROCESS for every process that has the terminated process as a parent.
        if (pProc->ParentEprocess == EprocessAddress)
        {
            pProc->ParentEprocess = 0;
        }

        if (pProc->RealParentEprocess == EprocessAddress)
        {
            pProc->RealParentEprocess = 0;
        }

        if ((pProc->Pid == Pid) && (pProc->EprocessAddress == EprocessAddress) && (pProc->Cr3 == Cr3))
        {
            BOOLEAN bCrashed = FALSE;
            BOOLEAN lastAgent = FALSE;

            bFound = TRUE;
            pProc->Terminating = TRUE;

            // Get the crashed flag from the EPROCESS.
            if (0 != WIN_KM_FIELD(Process, Flags3))
            {
                DWORD flags3 = 0;

                status = IntKernVirtMemFetchDword(pProc->EprocessAddress + WIN_KM_FIELD(Process, Flags3), &flags3);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchDword failed for 0x%016llx: 0x%08x\n",
                          pProc->EprocessAddress + WIN_KM_FIELD(Process, Flags3), status);
                }
                else
                {
                    bCrashed = 0 != (WIN_KM_FIELD(EprocessFlags, 3Crashed) & flags3);
                }
            }

            if (0 != WIN_KM_FIELD(Process, ExitStatus))
            {
                status = IntKernVirtMemFetchDword(EprocessAddress + WIN_KM_FIELD(Process, ExitStatus),
                                                  &pProc->ExitStatus);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchDword failed for 0x%016llx: 0x%08x\n",
                          EprocessAddress + WIN_KM_FIELD(Process, ExitStatus), status);
                }
            }

            if (bCrashed)
            {
                TRACE("[PROCESS] Process `%d` with Eprocess at 0x%016llx and Cr3 0x%016llx crashed.\n",
                      pProc->Pid, pProc->EprocessAddress, pProc->Cr3);
            }

            IntWinAgentCheckIfProcessAgentAndDecrement(pProc->Name, &isAgent, &pProc->AgentTag, &lastAgent);
            pProc->IsAgent = isAgent;

            TRACE("[PROCESS] '%s', pid %d, EPROCESS 0x%016llx, CR3 0x%016llx, UserCR3 0x%016llx just terminated\n",
                  pProc->Name, pProc->Pid, pProc->EprocessAddress, pProc->Cr3, pProc->UserCr3);

            status = IntWinProcSendProcessExceptionEvent(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcSendProcessExceptionEvent failed: 0x%08x\n", status);
            }

            status = IntWinProcSendProcessEvent(pProc, FALSE, bCrashed);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcSendProcessEvent failed: 0x%08x\n", status);
            }

            if (lastAgent)
            {
                status = IntWinProcSendAgentEvent(pProc, FALSE);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinProcSendAgentEvent failed: 0x%08x\n", status);
                }
            }

            IntWinProcLstRemoveProcess(pProc);

            status = IntWinSelfMapUnprotectSelfMapIndex(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcUnprotectSelfMapIndex failed: 0x%08x\n", status);
            }

            if (pProc->Protected)
            {
                status = IntWinProcUnprotect(pProc);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinProcUnprotect failed: 0x%08x\n", status);
                }
            }

            // validate one last time the token privileges
            if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PRIVS))
            {
                status = IntWinTokenPrivsCheckIntegrityOnProcess(pProc);
                if (!INT_SUCCESS(status) && (INT_STATUS_PAGE_NOT_PRESENT != status))
                {
                    ERROR("[ERROR] IntWinTokenPrivsCheckIntegrityOnProcess failed: 0x%08x\n", status);
                }
            }

            // Validate one last time token and self map integrity
            if ((0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_TOKEN_PTR)))
            {
                status = IntWinTokenPtrCheckIntegrityOnProcess(pProc);
                if (!INT_SUCCESS(status) && (INT_STATUS_PAGE_NOT_PRESENT != status))
                {
                    ERROR("[ERROR] IntWinProcTokenCheckIntegrityInternal failed: 0x%08x\n", status);
                }
            }

            status = IntWinSelfMapGetAndCheckSelfMapEntry(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinSelfMapGetAndCheckSelfMapEntry failed: 0x%08x\n", status);
            }

            status = IntWinProcRemoveProcess(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcRemoveProcess failed: 0x%08x\n", status);
            }
        }
    }

    // Remove this process's entries from the list of pending UDs as this process terminated
    IntUDRemoveAllEntriesForCr3(Cr3);

    if (!bFound)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return status;
}


INTSTATUS
IntWinProcPatchPspInsertProcess86(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This functions is responsible for patching the detour that handles the "PspInsertProcess".
///
/// This function is invoked every time "PspInsertProcess" is called (a process is created)
/// but before the actual handler #IntWinProcHandleCreate, its purpose being to modify the hook code
/// (see winhkhnd.c). On some 32 Bit versions of the Windows, the a RET N instructions is used so the code must
/// take that into account when blocking a process creation.
///
/// @param[in]  FunctionAddress         The address of the function.
/// @param[in]  Handler                 An #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor              Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    PAPI_HOOK_HANDLER pHandler = Handler;
    DWORD offsetRetn = 0x09;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.OSVersion == 7600 || gGuest.OSVersion == 9200)
    {
        pHandler->Code[offsetRetn] = 0x1C;
    }

    if (gGuest.OSVersion == 7601 || gGuest.OSVersion == 7602)
    {
        pHandler->Code[offsetRetn] = 0x20;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcPatchSwapOut64(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This functions is responsible for patching the detour that handles the "KiOutSwapProcesses".
///
/// @param[in]  FunctionAddress         The address of the function.
/// @param[in]  Handler                 An #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor              Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    PAPI_HOOK_HANDLER pHandler = Handler;
    PAPI_HOOK_DESCRIPTOR pDescriptor = Descriptor;
    DWORD offset = 0x01;
    BYTE instruction[7] = { 0 };

    UNREFERENCED_PARAMETER(FunctionAddress);

    instruction[0] = 0x48;
    instruction[1] = 0x8b;

    switch (pDescriptor->Arguments.Argv[0])
    {
        case NDR_RBX:
            instruction[2] = 0x83;
            break;

        case NDR_RDI:
            instruction[2] = 0x87;
            break;

        case NDR_RSI:
            instruction[2] = 0x86;
            break;

        case NDR_RBP:
            instruction[1] = 0x85;
            break;

        default:
            return INT_STATUS_NOT_SUPPORTED;
    }

    *(DWORD *)(instruction + 3) = WIN_KM_FIELD(Process, Flags);

    memcpy(pHandler->Code + offset, instruction, sizeof(instruction));

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcPatchSwapOut32(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This functions is responsible for patching the detour that handles the "KiOutSwapProcesses".
///
/// @param[in]  FunctionAddress         The address of the function.
/// @param[in]  Handler                 An #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor              Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    PAPI_HOOK_HANDLER pHandler = Handler;
    PAPI_HOOK_DESCRIPTOR pDescriptor = Descriptor;
    BYTE instruction[6] = { 0 };
    DWORD offset = 0x01;

    UNREFERENCED_PARAMETER(FunctionAddress);

    instruction[0] = 0x8b;

    switch (pDescriptor->Arguments.Argv[0])
    {
        case NDR_RSI:
            instruction[1] = 0x86;
            break;

        case NDR_RBX:
            instruction[1] = 0x83;
            break;

        case NDR_RDI:
            instruction[1] = 0x87;
            break;

        default:
            return INT_STATUS_NOT_SUPPORTED;
    }

    *(DWORD *)(instruction + 2) = WIN_KM_FIELD(Process, Flags);

    memcpy(pHandler->Code + offset, instruction, sizeof(instruction));

    return INT_STATUS_SUCCESS;
}


static WIN_PROCESS_OBJECT *
IntWinProcHandleCreateInternal(
    _In_ QWORD NewEprocess,
    _In_ QWORD ParentEprocess,
    _In_ QWORD DebugHandle,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Handles process creation for Windows guests.
///
/// This function extracts the needed information from the newly created EPROCESS and created a new #WIN_PROCESS_OBJECT
/// using #IntWinProcCreateProcessObject.
/// It also triggers the deep process inspection checks using #IntWinDpiGatherDpiInfo.
///
/// @param[in]  NewEprocess     The guest virtual address of the EPROCESS structure of the newly created process.
/// @param[in]  ParentEprocess  The guest virtual address of the EPROCESS structure of the parent process, as set
///                             by the Windows kernel.
/// @param[in]  DebugHandle     The debug handle used for this process. Can be 0.
/// @param[out] Action          The action to be taken. Will be #introGuestNotAllowed if this process creation is not
///                             allowed (either due to the #PROC_OPT_PROT_PREVENT_CHILD_CREATION process protection
///                             option, or due to one of the #INTRO_OPT_PROT_DPI options).
///
/// @returns    A pointer to the newly created #WIN_PROCESS_OBJECT in case of success, or NULL in case of error.
///
{
    INTSTATUS status;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    DWORD pid = 0;
    QWORD cr3, realParentEproc;
    PBYTE eprocessBuffer = NULL;
    WIN_PROCESS_OBJECT *pProc, *pParent;
    INTRO_ACTION action = introGuestAllowed;
    BOOLEAN skipChecks = FALSE;

    pProc = pParent = NULL;

    status = IntWinProcMapEprocess(NewEprocess, &eprocessBuffer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcMapEprocess failed: 0x%08x\n", status);
        goto _set_action_and_leave;
    }

    pid = *(DWORD *)(eprocessBuffer + WIN_KM_FIELD(Process, Id));

    if (gGuest.Guest64)
    {
        cr3 = *(QWORD *)(eprocessBuffer + WIN_KM_FIELD(Process, Cr3));
    }
    else
    {
        cr3 = *(DWORD *)(eprocessBuffer + WIN_KM_FIELD(Process, Cr3));
    }

    // First, try to get the real parent (by current Cr3)
    pParent = IntWinProcFindObjectByCr3(pRegs->Cr3);
    if (NULL == pParent)
    {
        // In case this fails, try to get it by the eprocess that Windows considers the parent
        pParent = IntWinProcFindObjectByEprocess(ParentEprocess);
        if (__unlikely(NULL == pParent && 4 == pid))
        {
            // System process does not have a parent
            skipChecks = TRUE;
        }
        else if (NULL == pParent)
        {
            CRITICAL("[ERROR] Both the real parent (Cr3 = 0x%016llx) and the parent "
                     "(eprocess = 0x%016llx) are NULL for pid %d!\n", pRegs->Cr3, ParentEprocess, pid);

            goto _cleanup_and_leave;
        }
    }

    realParentEproc = pParent ? pParent->EprocessAddress : 0;

    status = IntWinProcCreateProcessObject(&pProc, NewEprocess, eprocessBuffer, ParentEprocess,
                                           realParentEproc, cr3, pid, FALSE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcCreateProcessObject failed: 0x%08x\n", status);
        goto _cleanup_and_leave;
    }

    if (skipChecks)
    {
        INFO("[INFO] Process %s (%d/0x%016llx) doesn't have either parent or real parent, will skip all checks\n",
             pProc->Name, pProc->Pid, pProc->EprocessAddress);
        goto _cleanup_and_leave;
    }

    if (__likely(pParent->Pid != 4))
    {
        STATS_ENTER(statsDpiGatherInfo);

        IntWinDpiGatherDpiInfo(pProc, pParent, DebugHandle);

        STATS_EXIT(statsDpiGatherInfo);
    }

    STATS_ENTER(statsProcessCreationCheck);

    action = IntWinDpiCheckCreation(pProc, pParent);

    STATS_EXIT(statsProcessCreationCheck);

_cleanup_and_leave:
    IntVirtMemUnmap(&eprocessBuffer);

_set_action_and_leave:
    *Action = action;

    return pProc;
}


INTSTATUS
IntWinProcHandleCreate(
    _In_ void *Detour
    )
///
/// @brief      Detour handler for the PspInsertProcess Windows kernel API.
/// @ingroup    group_detours
///
/// The actual process creation is handled by #IntWinProcHandleCreateInternal. This function establishes the context
/// of the creation and, if needed, blocks the process creation.
///
/// @param[in]  Detour  The detour.
///
/// @retval     #INT_STATUS_SUCCESS Always.
///
{
    INTSTATUS status;
    QWORD args[3] = { 0 };
    QWORD eprocess, parentEproc;
    QWORD possibleDebugHandle;
    INTRO_ACTION action;
    WIN_PROCESS_OBJECT *newProc;

    status = IntDetGetArguments(Detour, ARRAYSIZE(args), args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        return INT_STATUS_SUCCESS;
    }

    eprocess = args[0];
    parentEproc = args[1];
    possibleDebugHandle = args[2];

    newProc = IntWinProcHandleCreateInternal(eprocess, parentEproc, possibleDebugHandle, &action);
    if (newProc == NULL)
    {
        ERROR("[ERROR] IntWinProcHandleCreateInternal failed for 0x%016llx\n", eprocess);
        return INT_STATUS_SUCCESS;
    }

    if (introGuestNotAllowed == action)
    {
        IG_ARCH_REGS *pRegs = &gVcpu->Regs;

        status = IntWinProcDeleteProcessObject(newProc->EprocessAddress, newProc->Cr3, newProc->Pid);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcDeleteProcessObject failed: 0x%08x\n", status);
        }

        // IntWinProcHandleCreate is the callback for when PspInsertProcess
        // is invoked. After the INT3 that causes the VmExit, there is a JMP
        // that sets the RIP to where the real PspInsertProcess call is - in case
        // the creation is allowed. On the other hand, blocking a process will be
        // done by incrementing the RIP (2 bytes) over the JMP (0xEB, 0x06), thus
        // setting the EAX to STATUS_ACCESS_DENIED and returning. For more information,
        // please consult "winhkhnd.c".

        pRegs->Rip += 0x02;

        status = IntSetGprs(gVcpu->Index, pRegs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcHandleTerminate(
    _In_ void *Detour
    )
///
/// @brief      This functions handles the termination of a Windows process.
/// @ingroup    group_detours
///
/// This function is invoked every time "MmCleanProcessAddressSpace" is called (a process is being terminated) and is
/// responsible for removing the process from all the internal structures.
///
/// @param[in]  Detour         The detour.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    DWORD pid;
    QWORD eprocess, pdbrBase;

    pid = 0;
    pdbrBase = 0;

    status = IntDetGetArgument(Detour, 0, NULL, 0, &eprocess);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArgument failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntKernVirtMemFetchDword(eprocess + WIN_KM_FIELD(Process, Id), &pid);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchDword failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // Get the PDBR base.
    status = IntKernVirtMemFetchQword(eprocess + WIN_KM_FIELD(Process, Cr3), &pdbrBase);
    if (!INT_SUCCESS(status))
    {
        ERROR("IntKernVirtMemFetchQword failed for 0x%016llx: 0x%08x\n",
              eprocess + WIN_KM_FIELD(Process, Cr3), status);
        goto cleanup_and_exit;
    }

    if (!gGuest.Guest64)
    {
        pdbrBase &= 0xFFFFFFFF;
    }

    status = IntWinProcDeleteProcessObject(eprocess, pdbrBase, pid);
    if (!INT_SUCCESS(status) && (INT_STATUS_NOT_FOUND != status))
    {
        ERROR("[ERROR] IntWinProcDeleteProcessObject failed for EPROCESS %llx, CR3 %llx, pid %d: 0x%08x\n",
              eprocess, pdbrBase, pid, status);
    }

cleanup_and_exit:

    return status;
}


INTSTATUS
IntWinProcPatchCopyMemoryDetour(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This functions is responsible for patching the detour that handles the "MmCopyVirtualMemory".
/// @ingroup    group_detours
///
/// This function is invoked every time "MmCopyVirtualMemory" is called (a process is writing/reading another process)
/// but before the actual handler #IntWinProcHandleCopyMemory, its purpose being to modify the hook code
/// (see winhkhnd.c).
///
/// @param[in]  FunctionAddress         The address of the function.
/// @param[in]  Handler                 An #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor              Pointer to a structure that describes the hook and the detour handler.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    PAPI_HOOK_HANDLER pHandler = Handler;

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    if (gGuest.Guest64)
    {
        *(DWORD *)(pHandler->Code + 0xD) = WIN_KM_FIELD(Process, Cr3);

        *(DWORD *)(pHandler->Code + 0x16) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(pHandler->Code + 0x21) = WIN_KM_FIELD(Process, Spare);

        *(DWORD *)(pHandler->Code + 0x2c) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(pHandler->Code + 0x36) = WIN_KM_FIELD(Process, Spare);
    }
    else
    {
        *(DWORD *)(pHandler->Code + 0x14) = WIN_KM_FIELD(Process, Cr3);

        *(DWORD *)(pHandler->Code + 0x1c) = WIN_KM_FIELD(Process, Spare);
        *(DWORD *)(pHandler->Code + 0x2f) = WIN_KM_FIELD(Process, Spare);
    }

    return INT_STATUS_SUCCESS;
}


static BOOLEAN
IntWinProcHandleReadFromLsass(
    _In_ QWORD SourceAddress,
    _In_ DWORD ReadSize,
    _In_ const WIN_PROCESS_OBJECT *Lsass,
    _Out_ WIN_PROCESS_MODULE **VictimModule
    )
///
/// @brief  Handles reads from lsass.exe.
///
/// @param[in]  SourceAddress   The guest linear address from where data is read.
/// @param[in]  ReadSize        The size of the memory copy operation.
/// @param[in]  Lsass           Pointer to the lsass.exe #WIN_PROCESS_OBJECT structure.
/// @param[out] VictimModule    Will contain a pointer to the module loaded inside lsass.exe from which data is read.
///                             If data is not copied from any module will be NULL.
///
/// @retval     True if this read should be allowed without doing any extra checks.
/// @retval     False if this read should be further analyzed.
///
{
    QWORD srcEnd = SourceAddress + ReadSize - 1;
    LIST_ENTRY *list, *head;
    WIN_PROCESS_MODULE *pLsassMod = NULL;

    // LSASS will only exist in either 64 or 32 bit form, depending on the OS.
    if (Lsass->Subsystemx64)
    {
        head = &Lsass->Subsystemx64->ProcessModules;
    }
    else
    {
        head = &Lsass->Subsystemx86->ProcessModules;
    }

    // We assume one cannot read more than a single module at one time. If someone does that, we'll block it.
    list = head->Flink;
    while (list != head)
    {
        pLsassMod = CONTAINING_RECORD(list, WIN_PROCESS_MODULE, Link);

        list = list->Flink;

        // Ignore the MZ/PE headers.
        if (((SourceAddress >= pLsassMod->VirtualBase + PAGE_SIZE) &&
             (SourceAddress < pLsassMod->VirtualBase + pLsassMod->Size)) ||
            ((srcEnd >= pLsassMod->VirtualBase + PAGE_SIZE) &&
             (srcEnd < pLsassMod->VirtualBase + pLsassMod->Size)))
        {
            break;
        }

        pLsassMod = NULL;
    }

    *VictimModule = pLsassMod;

    if (NULL != pLsassMod)
    {
        // If this is ntdll or the main module, bail out.
        if (pLsassMod->Path->NameHash == NAMEHASH_NTDLL || pLsassMod->IsMainModule)
        {
            return TRUE;
        }
    }
    else
    {
        // Allow reads from everything that is not a module - a lot of legitimate reads are done from various heap
        // locations from lsass, and that can cause performance problems; blocking reads from modules is enough
        // for blocking credential stealing.
        return TRUE;
    }

    return FALSE;
}


INTSTATUS
IntWinProcHandleCopyMemory(
    _In_ void *Detour
    )
///
/// @brief      This functions is responsible handling process read/write operations.
/// @ingroup    group_detours
///
/// This function is invoked every time "MmCopyVirtualMemory" is called (a process is writing/reading another process),
/// its purpose being to block malicious operations, such as a credential dump (reading from lsass.exe).
///
/// @param[in]  Detour       The detour.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
///
{
    INTSTATUS status;
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    PIG_ARCH_REGS pRegs;
    QWORD srcCr3, dstCr3;
    QWORD srcEproc, dstEproc;
    QWORD srcAddress, dstAddress;
    DWORD size;
    QWORD args[5];
    WIN_PROCESS_OBJECT *pSrcProc, *pDstProc;
    BOOLEAN isLsass, isRead;
    EXCEPTION_UM_ORIGINATOR originator;
    EXCEPTION_VICTIM_ZONE victim;
    PWIN_PROCESS_MODULE pLsassMod;

    action = introGuestAllowed;
    reason = introReasonUnknown;
    pSrcProc = pDstProc = NULL;
    isLsass = FALSE;
    pLsassMod = NULL;

    pRegs = &gVcpu->Regs;

    STATS_ENTER(statsCopyMemoryTotal);

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_ENABLE_UM_PROTECTION))
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    status = IntDetGetArguments(Detour, 5, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    srcEproc = args[0];
    srcAddress = args[1];
    dstEproc = args[2];
    dstAddress = args[3];
    size = (DWORD)args[4];

    // If a write comes from the kernel, there's nothing we can do. We will simply allow it
    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, srcAddress))
    {
        goto cleanup_and_exit;
    }

    pDstProc = IntWinProcFindObjectByEprocess(dstEproc);
    if (NULL == pDstProc)
    {
        // If the process isn't found, than it has been terminated. We can safely leave.
        WARNING("[WARNING] IntWinProcFindObjectByEprocess failed for process 0x%016llx, "
                "current CR3 0x%016llx: 0x%08x\n",
                dstEproc, pRegs->Cr3, status);

        goto cleanup_and_exit;
    }

    pSrcProc = IntWinProcFindObjectByEprocess(srcEproc);
    if (NULL == pSrcProc)
    {
        goto cleanup_and_exit;
    }

    dstCr3 = pDstProc->Cr3;

    srcCr3 = pSrcProc->Cr3;

    // If source CR3 is the same as the destination CR3, then we have a ReadProcessMemory inside our own VA space,
    // which can be safely allowed.
    if (srcCr3 == dstCr3)
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    if (dstCr3 == pRegs->Cr3)
    {
        // We have a copy from p1 inside p2, and we are inside the context of p2 -> this is a read: p2 is
        // reading from p1.
        isRead = TRUE;
    }
    else
    {
        isRead = FALSE;
    }

    STATS_ENTER(isRead ? statsCopyMemoryRead : statsCopyMemoryWrite);

    /// BitDefender quick scan does this, but we will allow every agent (since they're injected by us).
    if (isRead && pDstProc->IsAgent)
    {
        action = introGuestAllowed;
        goto _stats_exit;
    }

    // Handle malicious process reads: check for processes attempting to read lsass.exe memory. We will ignore all
    // the other reads, as we're not interested in them.
    if (pSrcProc->Lsass && isRead)
    {
        isLsass = TRUE;

        if (IntWinProcHandleReadFromLsass(srcAddress, size, pSrcProc, &pLsassMod))
        {
            action = introGuestAllowed;
            goto _stats_exit;
        }
    }
    else
    {
        // We allow other process reads for now
        if (isRead)
        {
            status = INT_STATUS_SUCCESS;
            goto _stats_exit;
        }

        if (!pDstProc->Protected || !pDstProc->ProtWriteMem)
        {
            status = INT_STATUS_SUCCESS;
            goto _stats_exit;
        }

        // Mark the start of process initialization
        if (!pDstProc->StartInitializing && !pDstProc->Initialized)
        {
            if (0 == strcasecmp(pSrcProc->Name, "csrss.exe"))
            {
                pDstProc->StartInitializing = TRUE;
            }
            else
            {
                goto check_injection;
            }
        }

        // Allow every injection until the process starts to initialize (some come from kernel-mode,
        // and we have no way to except that)
        if (!pDstProc->StartInitializing && !pDstProc->Initialized)
        {
            status = INT_STATUS_SUCCESS;
            goto _stats_exit;
        }
    }

check_injection:
    STATS_ENTER(isRead ? statsCopyMemoryProtectedRead : statsCopyMemoryProtectedWrite);

    // If this is a read from lsass.exe, switch the source and the destination from now on, as we want to go through
    // the exceptions mechanism with the source of the attack being the destination process and the victim being
    // the source process (lsass.exe).
    if (isLsass)
    {
        void *auxproc;
        QWORD auxaddr;

        auxproc = pSrcProc;
        pSrcProc = pDstProc;
        pDstProc = auxproc;

        auxaddr = srcAddress;
        srcAddress = dstAddress;
        dstAddress = auxaddr;
    }

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    STATS_ENTER(statsExceptionsUser);

    status = IntExceptUserGetOriginator(pSrcProc, FALSE, srcAddress, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        action = introGuestNotAllowed;

        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        goto _stop_count_and_notify;
    }

    status = IntExceptGetVictimProcess(pDstProc, dstAddress, size, isRead ? ZONE_READ : ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        action = introGuestNotAllowed;

        ERROR("[ERROR] Failed getting modified zone: 0x%08x\n", status);
        goto _stop_count_and_notify;
    }

    // The IntExceptGetVictimProcess either returns a valid VAD for the whole range, or NULL.
    // If there is no VAD (guest space was already scanned), we will still pass through exceptions and let the
    // guest handle the case (if allowed).
    if (NULL == victim.Object.Vad && pDstProc->MonitorVad)
    {
        WARNING("[WARNING] Injection (read: %d) from %s (%u) into %s "
                "(%u) for VA %llx with ""size %d (which has no VAD)!\n",
                isRead, pSrcProc->Name, pSrcProc->Pid, pDstProc->Name,
                pDstProc->Pid, dstAddress, size);

        for (QWORD currentDst = dstAddress; currentDst < dstAddress + size;)
        {
            VAD *pNewVad = IntWinVadFindAndUpdateIfNecessary(pDstProc, currentDst, 1);
            if (pNewVad)
            {
                WARNING("[WARNING] Vad-> [%llx -> %llx] (path: %s, stack: %d)\n",
                        pNewVad->StartPage, pNewVad->EndPage,
                        pNewVad->Path ? utf16_for_log(pNewVad->Path->Path) : "(none)", pNewVad->IsStack);
                currentDst += pNewVad->PageCount * PAGE_SIZE;
            }
            else
            {
                currentDst += PAGE_SIZE;
            }
        }
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventInjectionViolation);

_stop_count_and_notify:
    STATS_EXIT(statsExceptionsUser);

    STATS_ENTER(isRead ? statsCopyMemoryProtectedRead : statsCopyMemoryProtectedWrite);

    // Print lsass read details only if not allowed
    if (introGuestNotAllowed == action && isLsass && isRead && (NULL != pLsassMod))
    {
        LOG("[WINPROCESS] Suspicious read from lsass.exe: %s from process %s at address %llx:%d\n",
            utf16_for_log(pLsassMod->Path->Name), pSrcProc->Name, srcAddress, size);
    }

    if (IntPolicyProcTakeAction(PROC_OPT_PROT_WRITE_MEM, pDstProc, &action, &reason))
    {
        EVENT_MEMCOPY_VIOLATION *pInjEvent = &gAlert.Injection;

        memzero(pInjEvent, sizeof(*pInjEvent));

        LOG("[ALERT] [INJECTION DETECTED] Injection took place from EPROCESS 0x%016llx with CR3 0x%016llx in " \
            "EPROCESS 0x%016llx with CR3 0x%016llx. CR3: 0x%016llx, IsRead: %s\n",
            srcEproc, srcCr3, dstEproc, dstCr3, pRegs->Cr3, isRead ? "yes" : "no");

        pInjEvent->Header.Action = action;
        pInjEvent->Header.Reason = reason;

        if (isRead && isLsass)
        {
            pInjEvent->Header.MitreID = idCredDump;
        }
        else
        {
            pInjEvent->Header.MitreID = idProcInject;
        }

        IntAlertFillCpuContext(FALSE, &pInjEvent->Header.CpuContext);
        IntAlertFillWinProcess(pSrcProc, &pInjEvent->Originator.Process);
        IntAlertFillWinProcess(pDstProc, &pInjEvent->Victim.Process);
        IntAlertFillWinProcessByCr3(pInjEvent->Header.CpuContext.Cr3, &pInjEvent->Header.CurrentProcess);

        if (victim.Object.Library.Module)
        {
            IntAlertFillWinUmModule(victim.Object.Library.Module, &pInjEvent->Victim.Module);
        }

        if (victim.Object.Library.Export != NULL)
        {
            WIN_PROCESS_MODULE *pModule = victim.Object.Library.Module;
            WINUM_CACHE_EXPORT *pExport = victim.Object.Library.Export;

            for (DWORD export = 0; export < pExport->NumberOfOffsets; export++)
            {
                strlcpy(pInjEvent->Export.Name[export], pExport->Names[export],
                        MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[export] + 1));

                pInjEvent->Export.Hash[export] = Crc32String(pExport->Names[export], INITIAL_CRC_VALUE);
            }

            strlcpy(pInjEvent->FunctionName,
                    pExport->Names[0],
                    MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[0] + 1));

            pInjEvent->FunctionNameHash = Crc32String(pExport->Names[0], INITIAL_CRC_VALUE);

            if (pModule != NULL)
            {
                pInjEvent->Export.Delta =
                    (DWORD)(dstAddress - pModule->VirtualBase - victim.Object.Library.Export->Rva);

                pInjEvent->Delta =
                    (DWORD)(dstAddress - pModule->VirtualBase - victim.Object.Library.Export->Rva);
            }
        }

        pInjEvent->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_WRITE_MEM, pDstProc, reason, 0);

        // If the the destination process is a system process, a flag will be set
        if (pDstProc->SystemProcess)
        {
            pInjEvent->Header.Flags |= ALERT_FLAG_SYSPROC;
        }

        // Injection violations are always from RING 3.
        pInjEvent->Header.Flags |= ALERT_FLAG_NOT_RING0;

        // Set the internal information
        pInjEvent->DestinationVirtualAddress = dstAddress;
        pInjEvent->SourceVirtualAddress = srcAddress;
        pInjEvent->CopySize = size;
        pInjEvent->ViolationType = isRead ? memCopyViolationRead : memCopyViolationWrite;

        // read maximum 512 bytes form the source address into the alert. If this is a read, we won't include a buffer,
        // since we may end up sending sensitive info (see Mimikatz reading credentials from lsass memory).
        if (!isRead)
        {
            status = IntVirtMemRead(srcAddress,
                                    MIN(size, sizeof(pInjEvent->RawDump)),
                                    srcCr3,
                                    &pInjEvent->RawDump,
                                    NULL);
            if (INT_SUCCESS(status))
            {
                pInjEvent->DumpValid = TRUE;
            }
        }

        IntAlertFillVersionInfo(&pInjEvent->Header);

        status = IntNotifyIntroEvent(introEventInjectionViolation, pInjEvent, sizeof(*pInjEvent));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        status = INT_STATUS_SUCCESS;
    }

_stats_exit:
    STATS_EXIT(isRead ? statsCopyMemoryRead : statsCopyMemoryWrite);

cleanup_and_exit:
    STATS_EXIT(statsCopyMemoryTotal);

    if (pDstProc != NULL)
    {
        IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_WRITE_MEM, pDstProc, &action);
    }

    status = IntDetSetReturnValue(Detour,
                                  pRegs,
                                  (introGuestNotAllowed == action) ? WIN_STATUS_ACCESS_DENIED : WIN_STATUS_SUCCESS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetSetReturnValue failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntWinProcUnprotect(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Remove a process from protection.
///
/// @param[in]  Process      The process to be removed from protection.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the process is NULL.
///
{
    INTSTATUS status;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Process->Protected)
    {
        gTotalProtectedProcs--;
    }

    Process->Context = 0;

    // Remove the protection.
    status = IntWinProcChangeProtectionFlags(Process, Process->ProtectionMask, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcChangeProtectionFlags failed: 0x%08x\n", status);
    }

    IntExceptInvCbCacheByCr3(Process->Cr3);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcProtect(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      Protects a new process.
///
/// @param[in]  Process      The process to be protected.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the process is NULL.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If the process is already protected.
///
{
    INTSTATUS status;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!Process->Protected)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // It is ok to do this here because if this function fails, it calls IntWinProcUnprotect which will decrement
    // the counter
    gTotalProtectedProcs++;

    // Make sure enough memory is available.
    if (!IntWinProcIsEnoughHeapAvailable())
    {
        WARNING("[WARNING] Not enough heap is available. Will NOT protect the process '%s'.\n", Process->Name);
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    TRACE("[PROCESS] Protecting process %s with CR3 0x%016llx, EPROC 0x%016llx, WOW64 %d, PEB at 0x%016llx," \
          "PEB32 at 0x%016llx, Parent 0x%016llx, ProtMask: 0x%08x, the process is %s.\n",
          Process->Name,
          Process->Cr3,
          Process->EprocessAddress,
          Process->Wow64Process,
          Process->Peb64Address,
          Process->Peb32Address,
          Process->ParentEprocess,
          Process->ProtectionMask,
          Process->StaticDetected ? "already created" : "being created");

    // Activate the protection.
    status = IntWinProcChangeProtectionFlags(Process, 0, Process->ProtectionMask);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcChangeProtectionFlags failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        INTSTATUS status2;

        status2 = IntWinProcUnprotect(Process);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntWinProcUnprotect failed: 0x%08x\n", status2);
        }

        memset(&gErrorContext, 0, sizeof(gErrorContext));
        IntAlertFillWinProcess(Process, &gErrorContext.ProcessProtection.Process);
        gErrorContext.ProcessProtection.Count = gTotalProtectedProcs;

        IntNotifyIntroErrorState(INT_STATUS_INSUFFICIENT_RESOURCES == status ?
                                 intErrProcNotProtectedNoMemory : intErrProcNotProtectedInternalError,
                                 &gErrorContext);
    }

    return status;
}


TIMER_FRIENDLY INTSTATUS
IntWinProcValidateSystemCr3(
    void
    )
///
/// @brief      This function checks if the system CR3 value was modified and if #GUEST_STATE::KernelBetaDetections
/// is NOT set, it restores the original value.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_FOUND               If the system process was not found within the #gWinProcesses.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT    If the introcore is not fully initialized.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT *pProc;
    VA_TRANSLATION tr;
    QWORD cr3;
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) || (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SYSTEM_CR3)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    cr3 = 0;
    action = introGuestNotAllowed;
    reason = introReasonUnknown;

    // Make sure we have at least one process.
    if (IsListEmpty(&gWinProcesses))
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    // Get the System process, which is always the first one.
    pProc = (PWIN_PROCESS_OBJECT)gWinProcesses.Flink;
    if (4 != pProc->Pid)
    {
        ERROR("[ERROR] First process is not System: PID = %d\n", pProc->Pid);
        return INT_STATUS_NOT_FOUND;
    }

    // Translate the system EPROCESS to a physical address.
    status = IntTranslateVirtualAddressEx(pProc->EprocessAddress + WIN_KM_FIELD(Process, Cr3),
                                          gGuest.Mm.SystemCr3,
                                          TRFLG_PG_MODE,
                                          &tr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
        return status;
    }

    if (0 == (tr.Flags & PT_P))
    {
        return INT_STATUS_PAGE_NOT_PRESENT;
    }

    // Fetch the active PDBR for the System process.
    status = IntGpaCacheFetchAndAdd(gGuest.GpaCache, tr.PhysicalAddress, gGuest.WordSize, (PBYTE)&cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheFetchAndAdd failed: 0x%08x\n", status);
        return status;
    }

    if (!gGuest.Guest64)
    {
        // Note that CR3 is 32 bit wide in legacy paging mode and PAE mode.
        cr3 &= 0xFFFFFFFF;
    }

    if (cr3 != pProc->Cr3)
    {
        PEVENT_TRANSLATION_VIOLATION pTrViol;

        IntPauseVcpus();

        // Restore the original, if no BETA
        if (!gGuest.KernelBetaDetections)
        {
            action = introGuestNotAllowed;
            reason = introReasonNoException;

            status = IntVirtMemSafeWrite(0,
                                         pProc->EprocessAddress + WIN_KM_FIELD(Process, Cr3),
                                         gGuest.Guest64 ? sizeof(QWORD) : sizeof(DWORD),
                                         &pProc->Cr3,
                                         IG_CS_RING_0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%x\n", status);
            }
        }
        else
        {
            // The action will be BETA detected, it will be allowed by default, so there is no use of
            // specifying it in the reason while the BETA flag is specified in the alert.
            action = introGuestAllowed;
            reason = introReasonAllowed;
        }

        pTrViol = &gAlert.Translation;
        memzero(pTrViol, sizeof(*pTrViol));

        pTrViol->Header.Flags = 0;

        pTrViol->Header.Flags |= ALERT_FLAG_ASYNC;
        if (gGuest.KernelBetaDetections)
        {
            pTrViol->Header.Flags |= ALERT_FLAG_BETA;
        }

        pTrViol->Header.CpuContext.Valid = FALSE;
        pTrViol->Header.Action = action;
        pTrViol->Header.Reason = reason;
        pTrViol->Header.MitreID = idRootkit;

        IntAlertFillWinProcessCurrent(&pTrViol->Header.CurrentProcess);

        // If VirtualAddress is -1, this means that we're dealing with an invalid CR3 modification. VirtualAddress
        // must be != -1 for all other types of translation violations.
        pTrViol->Victim.VirtualAddress = 0xFFFFFFFFFFFFFFFF;
        pTrViol->WriteInfo.OldValue[0] = pProc->Cr3;
        pTrViol->WriteInfo.NewValue[0] = cr3;
        pTrViol->WriteInfo.Size = sizeof(QWORD);
        pTrViol->ViolationType = transViolationProcessCr3;

        IntAlertFillVersionInfo(&pTrViol->Header);

        status = IntNotifyIntroEvent(introEventTranslationViolation, pTrViol, sizeof(*pTrViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    return INT_STATUS_SUCCESS;
}


static BOOLEAN
IntWinProcIsFullPath(
    _In_ const WCHAR *Path
    )
///
/// @brief      This function checks if the provided path is a full path.
///
/// @retval     #TRUE       The provided path is a full path.
/// @retval     #FALSE      The provided path is a NOT full path.
///
{
    SIZE_T i = 0;

    while (Path[i] != 0)
    {
        if ((Path[i] == u'\\') || (Path[i] == u'/'))
        {
            return TRUE;
        }

        i++;
    }

    return FALSE;
}


static BOOLEAN
IntWinProcExistsProtectedProcess(
    _In_ CHAR BaseName[IMAGE_BASE_NAME_LEN],
    _In_ const WCHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ QWORD Context
    )
///
/// @brief      This function checks if the provided process is already protected with the given flags.
///
/// This function iterates trough the #gWinProtectedProcesses and looks for the given process. If the BaseName,
/// FullPath and ProtectionMask match, the #PROTECTED_PROCESS_INFO::Context is set to the given Context.
///
/// @param[in]  BaseName        The name of the process (limited to #IMAGE_BASE_NAME_LEN)
/// @param[in]  FullPath        The full process path.
/// @param[in]  ProtectionMask  The process protection mask.
/// @param[in]  Context         Protection policy context.
///
/// @retval     #TRUE           The process is already protected using the given protection mask and context.
/// @retval     #FALSE          The process is NOT protected at all or with a different protection mask.
///
{
    LIST_ENTRY *list, *pList;

    list = gWinProtectedProcesses.Flink;
    while (list != &gWinProtectedProcesses)
    {
        PPROTECTED_PROCESS_INFO pProc = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

        list = list->Flink;

        if ((0 == strcasecmp(pProc->ImageBaseNamePattern, BaseName)) &&
            (0 == wstrcasecmp(pProc->FullPathPattern, FullPath)) &&
            (pProc->Protection.Current == ProtectionMask))
        {
            // Change the context and bail out early on if the protection mask is the same
            if (pProc->Context != Context)
            {
                pProc->Context = Context;

                pList = gWinProcesses.Flink;
                while (pList != &gWinProcesses)
                {
                    WIN_PROCESS_OBJECT *pProcObject = CONTAINING_RECORD(pList, WIN_PROCESS_OBJECT, Link);

                    pList = pList->Flink;

                    if (!strcasecmp(pProcObject->Name, BaseName))
                    {
                        pProcObject->Context = Context;
                    }
                }
            }

            return TRUE;
        }
    }

    return FALSE;
}


static INTSTATUS
IntWinProcRemoveProtectedProcessInternal(
    _In_ CHAR BaseName[IMAGE_BASE_NAME_LEN],
    _In_ const WCHAR *FullPath
    )
///
/// @brief      This function removes the protection for the given process.
///
/// This function iterates trough the #gWinProtectedProcesses and looks for the given process. If the BaseName and
/// FullPath match, the process is removed from the list.
///
/// @param[in]  BaseName        The name of the process (limited to #IMAGE_BASE_NAME_LEN)
/// @param[in]  FullPath        The full process path.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
///
{
    LIST_ENTRY *list;

    list = gWinProtectedProcesses.Flink;
    while (list != &gWinProtectedProcesses)
    {
        PROTECTED_PROCESS_INFO *pProc = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

        list = list->Flink;

        if ((0 == strcasecmp(pProc->ImageBaseNamePattern, BaseName)) &&
            (0 == wstrcasecmp(pProc->FullPathPattern, FullPath)))
        {
            memset(pProc->ImageBaseNamePattern, 0, IMAGE_BASE_NAME_LEN);

            HpFreeAndNullWithTag(&pProc->FullPathPattern, IC_TAG_PATH);

            RemoveEntryList(&pProc->Link);

            HpFreeAndNullWithTag(&pProc, IC_TAG_PPIF);
        }
    }

    return INT_STATUS_SUCCESS;
}


void
IntWinProcUpdateProtectedProcess(
    _In_ const void *Name,
    _In_ const CAMI_STRING_ENCODING Encoding,
    _In_ const CAMI_PROT_OPTIONS *Options
    )
///
/// @brief      This function updates the protection for the given process.
///
/// @param[in]  Name        The name of the process.
/// @param[in]  Encoding    The encoding used by the Name variable.
/// @param[in]  Options     The protection options to be applied.
///
{
    LIST_ENTRY *list = gWinProtectedProcesses.Flink;
    while (list != &gWinProtectedProcesses)
    {
        PROTECTED_PROCESS_INFO *pProcess = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);
        BOOLEAN match = FALSE;

        list = list->Flink;

        switch (Encoding)
        {
        case CAMI_STRING_ENCODING_UTF8:
            if (IntMatchPatternUtf8(Name, pProcess->ImageBaseNamePattern, 0))
            {
                match = TRUE;
            }
            break;
        case CAMI_STRING_ENCODING_UTF16:
            if (IntMatchPatternUtf16(Name, pProcess->FullNamePattern, 0))
            {
                match = TRUE;
            }
            break;
        default:
            WARNING("[WARNING] Unsupported string encoding: %d\n", Encoding);
        }

        if (match)
        {
            pProcess->Protection.Current = pProcess->Protection.Original & ~(Options->ForceOff);
            pProcess->Protection.Beta = Options->ForceBeta;
            pProcess->Protection.Feedback = Options->ForceFeedback;

            TRACE("[CAMI] Protected process info updated '%s'. Original : 0x%x, "
                  "Current : 0x%x, Beta : 0x%llx, Feedback : 0x%llx\n",
                  pProcess->ImageBaseNamePattern, pProcess->Protection.Original,
                  pProcess->Protection.Current, pProcess->Protection.Beta, pProcess->Protection.Feedback);
        }
    }
}


INTSTATUS
IntWinProcAddProtectedProcess(
    _In_ const WCHAR *Path,
    _In_ DWORD ProtectionMask,
    _In_ QWORD Context
    )
///
/// @brief      This function adds the provided process to the protected process list.
///
/// @param[in]  Path            The full process path.
/// @param[in]  ProtectionMask  The process protection mask.
/// @param[in]  Context         Protection policy context.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status;
    PPROTECTED_PROCESS_INFO pProc;
    SIZE_T fplen;
    CHAR baseName[IMAGE_BASE_NAME_LEN] = { 0 };
    const WCHAR *fullName;

    if (NULL == Path)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pProc = NULL;

    // Remove the drive name from the path.
    if ((Path[0] | 0x20) >= 'a' && (Path[0] | 0x20) <= 'z' && Path[1] == ':')
    {
        Path += 2;
    }

    fplen = wstrlen(Path);
    if ((0 == fplen) || (fplen >= 0x10000))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntWinProcGetImageBaseNameFromPath(Path, baseName, &fullName);

    strlower_utf8(baseName, sizeof(baseName));

    // Check if an identical policy already exists. If so, bail out now.
    if (IntWinProcExistsProtectedProcess(baseName, Path, ProtectionMask, Context))
    {
        TRACE("[INFO] A policy for process '%s', base name '%s', flags 0x%08x already exits.\n",
              utf16_for_log(Path), baseName, ProtectionMask);
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    // First of all, remove any instance of this process from the protected list.
    IntWinProcRemoveProtectedProcessInternal(baseName, Path);

    // Now add a new one.
    pProc = HpAllocWithTag(sizeof(*pProc), IC_TAG_PPIF);
    if (NULL == pProc)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pProc->FullPathPattern = HpAllocWithTag(fplen * sizeof(WCHAR) + 2, IC_TAG_PATH);
    if (NULL == pProc->FullPathPattern)
    {
        HpFreeAndNullWithTag(&pProc, IC_TAG_PPIF);
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pProc->Protection.Original = ProtectionMask;
    pProc->Protection.Current = ProtectionMask;
    pProc->Protection.Beta = 0;
    pProc->Protection.Feedback = 0;

    memcpy(pProc->ImageBaseNamePattern, baseName, IMAGE_BASE_NAME_LEN);

    memcpy(pProc->FullPathPattern, Path, fplen * sizeof(WCHAR));
    strlower_utf16(pProc->FullPathPattern, fplen);

    pProc->FullNamePattern = pProc->FullPathPattern + (fullName - Path);

    if (!IntWinProcIsFullPath(Path))
    {
        pProc->Flags |= PROT_PROC_FLAG_NO_PATH;
    }
    else
    {
        pProc->Flags = 0;
    }

    pProc->Context = Context;

    IntCamiUpdateProcessProtectionInfo(pProc);

    InsertTailList(&gWinProtectedProcesses, &pProc->Link);

    // UM introspection is not active, just leave.
    if (!(gGuest.CoreOptions.Current & INTRO_OPT_ENABLE_UM_PROTECTION))
    {
        return INT_STATUS_SUCCESS;
    }

    status = IntWinProcUpdateProtection();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcUpdateProtection failed: 0x%08x\n", status);
        return status;
    }

    return status;
}


INTSTATUS
IntWinProcRemoveProtectedProcess(
    _In_ const WCHAR *Path
    )
///
/// @brief      This function removed the provided process from the protected process list.
///
/// @param[in]  Path            The full process path.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    CHAR baseName[IMAGE_BASE_NAME_LEN] = {0};
    const WCHAR *fullName;

    if (NULL == Path)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // Remove the drive name from the path.
    if ((Path[0] | 0x20) >= 'a' && (Path[0] | 0x20) <= 'z' && Path[1] == ':')
    {
        Path += 2;
    }

    if (0 == wstrlen(Path))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    IntWinProcGetImageBaseNameFromPath(Path, baseName, &fullName);

    status = IntWinProcRemoveProtectedProcessInternal(baseName, Path);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcRemoveProtectedProcessInternal failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntWinProcUpdateProtection();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcUpdateProtection failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:

    return status;
}


INTSTATUS
IntWinProcRemoveAllProtectedProcesses(
    void
    )
///
/// @brief      This function removed all the processes from the protected process list.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    LIST_ENTRY *list;

    list = gWinProtectedProcesses.Flink;
    while (list != &gWinProtectedProcesses)
    {
        PPROTECTED_PROCESS_INFO pProc = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

        list = list->Flink;

        memset(pProc->ImageBaseNamePattern, 0, IMAGE_BASE_NAME_LEN);

        HpFreeAndNullWithTag(&pProc->FullPathPattern, IC_TAG_PATH);

        RemoveEntryList(&pProc->Link);

        HpFreeAndNullWithTag(&pProc, IC_TAG_PPIF);
    }

    return INT_STATUS_SUCCESS;
}


void
IntWinProcDumpProtected(
    void
    )
///
/// @brief      Log all the protected processes.
///
{
    DWORD i = 0;

    for (LIST_ENTRY *list = gWinProtectedProcesses.Flink;
         list != &gWinProtectedProcesses;
         list = list->Flink)
    {
        const PROTECTED_PROCESS_INFO *pProc = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

        LOG("# %04d %s, %08x, '%s':'%s'\n",
            i,
            pProc->ImageBaseNamePattern,
            pProc->Protection.Original,
            utf16_for_log(pProc->FullPathPattern),
            utf16_for_log(pProc->FullNamePattern));

        i++;
    }
}


void
IntWinProcUninit(
    void
    )
///
/// @brief      This function removes all process objects from the list, and registers the calls the cleanup
/// function for each process.
///
{
    LIST_ENTRY *list;
    INTSTATUS status;

    list = gWinProtectedProcesses.Flink;
    while (list != &gWinProtectedProcesses)
    {
        PPROTECTED_PROCESS_INFO pTarget = CONTAINING_RECORD(list, PROTECTED_PROCESS_INFO, Link);

        list = list->Flink;

        if (NULL != pTarget->FullPathPattern)
        {
            HpFreeAndNullWithTag(&pTarget->FullPathPattern, IC_TAG_PATH);
        }

        RemoveEntryList(&pTarget->Link);

        HpFreeAndNullWithTag(&pTarget, IC_TAG_PPIF);
    }

    list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        list = list->Flink;

        pProc->Terminating = TRUE;

        if (!gGuest.ShutDown && pProc->IsAgent)
        {
            IntWinProcMarkAgent(pProc, TRUE);
        }

        IntWinProcLstRemoveProcess(pProc);

        if (pProc->Protected)
        {
            status = IntWinProcUnprotect(pProc);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcUnprotect failed: 0x%08x\n", status);
            }
        }

        status = IntWinProcRemoveProcess(pProc);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcRemoveProcess failed: 0x%08x\n", status);
        }
    }
}


INTSTATUS
IntWinProcGetObjectByPid(
    _In_ DWORD Pid,
    _Outptr_ WIN_PROCESS_OBJECT **Process
    )
///
/// @brief      This function looks for a process with the given PID inside #gWinProcesses
/// and returns its #WIN_PROCESS_OBJECT.
///
/// @param[in]  Pid         The process identifier.
/// @param[out] Process     The process object for the given PID.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If the process was not found.
///
{
    LIST_ENTRY *list = NULL;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    list = gWinProcesses.Flink;
    while (list != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProc = CONTAINING_RECORD(list, WIN_PROCESS_OBJECT, Link);

        if (pProc->Pid == Pid)
        {
            *Process = pProc;

            return INT_STATUS_SUCCESS;
        }

        list = list->Flink;
    }

    return INT_STATUS_NOT_FOUND;
}



INTSTATUS
IntWinProcChangeProtectionFlags(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ DWORD OldMask,
    _In_ DWORD NewMask
    )
///
/// @brief      This function changes the protection flags for the given process.
///
/// @param[in]  Process         The process to update the protection flags for.
/// @param[in]  OldMask         The old protection flag mask.
/// @param[in]  NewMask         The new protection flag mask.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     The process object is NULL.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         The masks are identical.
///
{
    INTSTATUS status;
    BOOLEAN vadWasMonitored;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (OldMask == NewMask)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    vadWasMonitored = !!Process->MonitorVad;

    Process->ProtectionMask = NewMask;
    Process->Protected = NewMask != 0;

    if (!Process->Protected)
    {
        // Invalidate all the entries inside the ICACHE associated to this process,
        // since the CR3 will not be hooked anymore.
        status = IntIcFlushVaSpace(gGuest.InstructionCache, Process->Cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcFlushVaSpace failed: 0x%08x\n", status);
        }
    }

    // Set the BetaDetections policy
    if (Process->SystemProcess)
    {
        Process->BetaDetections = gGuest.SysprocBetaDetections;
    }
    else
    {
        Process->BetaDetections = !!(Process->ProtectionMask & PROC_OPT_BETA);
    }

    if (NewMask == 0)
    {
        Process->MonitorModules = FALSE;
        Process->MonitorVad = FALSE;
    }
    else
    {
        Process->MonitorModules = (!!(gGuest.CoreOptions.Current & INTRO_OPT_ENABLE_FULL_PATH) &&
                                   !Process->SystemProcess) ||
                                  (Process->ProtCoreModules || Process->ProtWsockModules || Process->ProtUnpack ||
                                   Process->Lsass || Process->ProtDoubleAgent);

        // Global per process flag that indicates if VAD is interesting for this process or not.
        Process->MonitorVad = (Process->MonitorModules || Process->ProtExploits);
    }

    // We must patch the in-guest protection indicator (used to be the first two characters in ImageName, now we use
    // some unused spare values) BEFORE actually trying to enable/disable protection. Otherwise, we may end up with a
    // process which has an altered spare value, which does not reflect the actual protection policy.
    status = IntWinProcPatchSpareValue(Process);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcPatchSpareValue failed: 0x%08x\n", status);
        return status;
    }

    if ((OldMask & PROC_OPT_PROT_INJECTION) != (NewMask & PROC_OPT_PROT_INJECTION))
    {
        // we assume that if LateProtection and we must protect the injection, process is already initialized
        if ((NewMask & PROC_OPT_PROT_INJECTION) != 0 && Process->LateProtection)
        {
            Process->Initialized = TRUE;
        }
    }

    if ((OldMask & PROC_OPT_PROT_EXPLOIT) != (NewMask & PROC_OPT_PROT_EXPLOIT))
    {
        if (OldMask & PROC_OPT_PROT_EXPLOIT)
        {
            IntWinVadStopExploitMonitor(Process);
        }
        else
        {
            status = IntWinProcEnforceProcessDep(Process);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinProcEnforceProcessDep failed: 0x%08x\n", status);
                return status;
            }
        }
    }

    if ((OldMask & (PROC_OPT_PROT_CORE_HOOKS | PROC_OPT_PROT_WSOCK_HOOKS | PROC_OPT_PROT_UNPACK)) !=
        (NewMask & (PROC_OPT_PROT_CORE_HOOKS | PROC_OPT_PROT_WSOCK_HOOKS | PROC_OPT_PROT_UNPACK)))
    {
        if (NULL != Process->Subsystemx86)
        {
            IntWinModulesChangeProtectionFlags(Process->Subsystemx86);
        }

        if (NULL != Process->Subsystemx64)
        {
            IntWinModulesChangeProtectionFlags(Process->Subsystemx64);
        }
    }

    if (vadWasMonitored && !Process->MonitorVad)
    {
        // We did VAD monitoring, but now we don't need to monitor the VAD - we can uninit the VAD tree.
        status = IntWinVadRemoveProcessTree(Process);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadRemoveProcessTree failed: 0x%08x\n", status);
            return status;
        }
    }
    else if (!vadWasMonitored && Process->MonitorVad)
    {
        // VAD monitoring was off, but we need to turn it on, so read all the VADs from the guest space.
        status = IntWinVadImportProcessTree(Process);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinVadImportProcessTree failed: 0x%08x\n", status);
            return status;
        }
    }

    // Remove or add hook on self map index
    if (Process->Protected && NULL == Process->SelfMapHook)
    {
        status = IntWinSelfMapProtectSelfMapIndex(Process);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcProtectSelfMapIndex failed: 0x%08x\n", status);
            return status;
        }
    }
    else if (!Process->Protected && NULL != Process->SelfMapHook)
    {
        status = IntWinSelfMapUnprotectSelfMapIndex(Process);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcUnprotectSelfMapIndex failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcSwapIn(
    _In_ void *Detour
    )
///
/// @brief      Detour handler for the MmInSwapProcess Windows kernel API.
/// @ingroup    group_detours
///
/// The detour on MmInSwapProcess is set inside the function after/before the EPROCESS.OutSwapped bit is disabled.
/// The guest virtual address of EPROCESS structure is stored in a register and is provided by 'IntDetGetArgument'.
/// An example for an instruction that is detoured is 'lock and dword ptr [rbx+440h],0FFFFFF7Fh'; in this case the
/// guest virtual address of the EPROCESS is stored in RBX register.
///
/// When the process is swapped-in, the #WIN_PROCESS_OBJECT is destroyed and a new one is created because some
/// information about EPROCESS may change.
///
/// At this point, the process is swapped-in and the protection is activated.
///
/// @param[in]  Detour  The detour.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_DATA_TYPE   If the callback is called and the process was not swapped-out.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WIN_PROCESS_OBJECT *pProcess = NULL;
    QWORD eprocessAddr = 0;
    BYTE *pEprocessBuffer = NULL;
    QWORD eprocessParentAddr = 0;
    QWORD eprocessRealParentAddr = 0;
    QWORD cr3 = 0;
    DWORD pid = 0;

    status = IntDetGetArgument(Detour, 0, NULL, 0, &eprocessAddr);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    pProcess = IntWinProcFindObjectByEprocess(eprocessAddr);
    if (!pProcess)
    {
        ERROR("[ERROR] IntWinProcFindObjectByEprocess failed for Eprocess 0x%016llx with status: 0x%08x",
               eprocessAddr, status);
        return status;
    }

    if (!pProcess->Outswapped)
    {
        ERROR("[ERROR] Process '%s' swapped-in, but not swapped out!", pProcess->Name);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    pProcess->Outswapped = FALSE;

    TRACE("[PROCESS-SWAP] Swapped in: '%s' (%08x), path %s, pid %d, EPROCESS 0x%016llx, CR3 0x%016llx, "
          "UserCR3 0x%016llx, parent at 0x%016llx/0x%016llx; %s, %s\n",
          pProcess->Name, pProcess->NameHash, pProcess->Path ? utf16_for_log(pProcess->Path->Path) : "<invalid>",
          pProcess->Pid, pProcess->EprocessAddress, pProcess->Cr3, pProcess->UserCr3, pProcess->ParentEprocess, pProcess->RealParentEprocess,
          pProcess->SystemProcess ? "SYSTEM" : "not system", pProcess->IsAgent ? "AGENT" : "not agent");

    eprocessParentAddr = pProcess->ParentEprocess;
    eprocessRealParentAddr = pProcess->RealParentEprocess;
    pid = pProcess->Pid;

    status = IntWinProcDeleteProcessObject(pProcess->EprocessAddress, pProcess->Cr3, pProcess->Pid);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcDeleteProcessObject failed with status: 0x%08x\n", status);
    }

    pProcess = NULL;

    status = IntWinProcMapEprocess(eprocessAddr, &pEprocessBuffer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcMapEprocess failed: 0x%08x\n", status);
        return status;
    }

    pid = *(DWORD *)(pEprocessBuffer + WIN_KM_FIELD(Process, Id));

    if (gGuest.Guest64)
    {
        cr3 = *(QWORD *)(pEprocessBuffer + WIN_KM_FIELD(Process, Cr3));
    }
    else
    {
        cr3 = *(DWORD *)(pEprocessBuffer + WIN_KM_FIELD(Process, Cr3));
    }

    status = IntWinProcCreateProcessObject(&pProcess, eprocessAddr, pEprocessBuffer, eprocessParentAddr,
                                           eprocessRealParentAddr, cr3, pid, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcCreateProcessObject failed with status: 0x%08x\n", status);
    }

    IntVirtMemUnmap(&pEprocessBuffer);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcSwapOut(
    _In_  void *Detour
    )
///
/// @brief      Detour handler for the KiOutSwapProcess Windows kernel API.
/// @ingroup    group_detours
///
/// The detour on KiOutSwapProcess is set after the MiOutSwapProcess is called (e.g. 'xor r15b, r15b').
/// The guest virtual address of EPROCESS structure is stored in a register and is provided by 'IntDetGetArgument'.
/// An example for that is detoured sequence is 'mov rcx, rbx / call nt!MmOutSwapProcess / xor r15b, r15b' ; in this case
/// the guest virtual address of the EPROCESS is stored in RBX register.
///
/// When the process is swapped-out, the #WIN_PROCESS_OBJECT is marked as swapped-out.
/// The protection for this process is deactivated and all swap-mem transactions are removed.
///
/// @param[in]  Detour  The detour.
///
/// @retval     #INT_STATUS_SUCCESS Always.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WIN_PROCESS_OBJECT *pProcess = NULL;
    QWORD eprocessAddr = 0;

    status = IntDetGetArgument(Detour, 0, NULL, 0, &eprocessAddr);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    pProcess = IntWinProcFindObjectByEprocess(eprocessAddr);
    if (!pProcess)
    {
        ERROR("[ERROR] IntWinProcFindObjectByEprocess failed for Eprocess 0x%016llx with status: 0x%08x",
               eprocessAddr, status);
        return status;
    }

    if (pProcess->Outswapped)
    {
        ERROR("[ERROR] Process '%s' already outswapped!", pProcess->Name);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    pProcess->Outswapped = TRUE;

    status = IntWinProcUnlockCr3(pProcess);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcUnlockCr3 failed for 0x%016llx with status: 0x%08x\n", pProcess->Cr3, status);
    }

    if (NULL != pProcess->CmdBufSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(pProcess->CmdBufSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }
        else
        {
            pProcess->CmdBufSwapHandle = NULL;
        }
    }

    if (NULL != pProcess->ParamsSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(pProcess->ParamsSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }
        else
        {
            pProcess->ParamsSwapHandle = NULL;
        }
    }

    if (NULL != pProcess->CmdLineSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(pProcess->CmdLineSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }
        else
        {
            pProcess->CmdLineSwapHandle = NULL;
        }
    }

    status = IntWinProcUnprotect(pProcess);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcUnprotect failed: 0x%08x\n", status);
    }

    status = IntSwapMemRemoveTransactionsForVaSpace(pProcess->Cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemRemoveTransactionsForVaSpace failed for CR3 0x%016llx with status: 0x%08x\n",
              pProcess->Cr3, status);
    }

    TRACE("[PROCESS-SWAP] Swapped out: '%s' (%08x), path %s, pid %d, EPROCESS 0x%016llx, CR3 0x%016llx, "
          "UserCR3 0x%016llx, parent at 0x%016llx/0x%016llx; %s, %s\n",
          pProcess->Name, pProcess->NameHash, pProcess->Path ? utf16_for_log(pProcess->Path->Path) : "<invalid>",
          pProcess->Pid, pProcess->EprocessAddress, pProcess->Cr3, pProcess->UserCr3, pProcess->ParentEprocess, pProcess->RealParentEprocess,
          pProcess->SystemProcess ? "SYSTEM" : "not system", pProcess->IsAgent ? "AGENT" : "not agent");

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinProcHandleInstrument(
    _In_ void *Detour
    )
///
/// @brief      Handles an exit on NtSetInformationProcess calls where the InformationClass argument is 40 (instrumentation callback).
/// @ingroup    group_detours
///
/// The originator is considered to be the current process (by cr3).
/// The victim is taken from the first argument of the API call, which is a handle to the target process. However, we
/// receive an _EPROCESS address thanks to the hook handler.
///
/// Since this is an injection technique, we consider the address of the desired callback to be the address of the injected
/// buffer and, since we don't have a size for it, the buffer is always considerd to have a PAGE_SIZE size.
///
/// This will check wether or not the instrumentation attempt is valid or not via exceptions and take propper action.
/// If the attempt is deemed malicious, we will set the guest to return from the function with a STATUS_ACCESS_DENIED or to
/// continue normal execution otherwise.
///
/// @param[in]  Detour  The detour.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    WIN_PROCESS_OBJECT *pOrig;
    WIN_PROCESS_OBJECT *pVic;

    IG_ARCH_REGS *regs;

    QWORD rip;

    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;

    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };

    EVENT_MEMCOPY_VIOLATION *evt;

    INTSTATUS status;

    union
    {
        struct
        {
            QWORD DstEproc;
            QWORD Class;
            QWORD Information;
        };

        QWORD Array[3];
    } args = { 0 };

    STATS_ENTER(statsSetProcInfo);

    regs = &gVcpu->Regs;

    action = introGuestAllowed;
    reason = introReasonAllowed;

    rip = 0;
    pVic = NULL;

    status = IntDetGetArguments(Detour, ARRAYSIZE(args.Array), args.Array);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    pOrig = IntWinProcFindObjectByCr3(regs->Cr3);
    if (NULL == pOrig)
    {
        ERROR("[ERROR] Failed to get source process by cr3 0x%016llx\n", regs->Cr3);
        status = INT_STATUS_NOT_FOUND;
        goto _cleanup_and_exit;
    }

    pVic = IntWinProcFindObjectByEprocess(args.DstEproc);
    if (NULL == pVic)
    {
        ERROR("[ERROR] Failed to get destination process by eprocess 0x%016llx\n", args.DstEproc);
        status = INT_STATUS_NOT_FOUND;
        goto _cleanup_and_exit;
    }

    // The structure passed to NtSetInformationProcess in order to place an instrumentation callback
    // seems to have a structure as follows:
    // WoW64:  { VOID *Callback; ULONG Version; ULONG Reserved; }
    // Native: { ULONG Version; ULONG Reserved; VOID *Callback; }
    if (pVic->Wow64Process)
    {
        status = IntVirtMemFetchDword(args.Information, pOrig->Cr3, (DWORD *)&rip);
    }
    else
    {
        status = IntVirtMemFetchWordSize(args.Information + 8, pOrig->Cr3, &rip);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemFetchWordSize failed: 0x%08x\n", status);
        goto _cleanup_and_exit;
    }

    STATS_ENTER(statsExceptionsUser);

    status = IntExceptUserGetOriginator(pOrig, FALSE, 0, NULL, &originator);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptUserGetOriginator failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        goto _send_notification;
    }

    status = IntExceptGetVictimProcess(pVic, rip, PAGE_SIZE, ZONE_PROC_INSTRUMENT | ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[EROR] IntExceptGetVictimProcess failed: 0x%08x\n", status);
        reason = introReasonInternalError;
        goto _send_notification;
    }

    IntExcept(&victim, &originator, exceptionTypeUm, &action, &reason, introEventInjectionViolation);

_send_notification:
    STATS_EXIT(statsExceptionsUser);

    if (!IntPolicyProcTakeAction(PROC_OPT_PROT_INSTRUMENT, pVic, &action, &reason))
    {
        goto _cleanup_and_exit;
    }

    evt = &gAlert.Injection;

    memzero(evt, sizeof(*evt));

    LOG("[INSTRUMENTATION] From process '%s' into process '%s' to rip 0x%016llx\n", pOrig->Name, pVic->Name, rip);

    evt->Header.Action = action;
    evt->Header.Reason = reason;
    evt->Header.MitreID = idProcInject;
    evt->Header.Flags = IntAlertProcGetFlags(PROC_OPT_PROT_INSTRUMENT, pVic, reason, 0);

    status = IntVirtMemRead(rip & PAGE_MASK, sizeof(evt->RawDump), pVic->UserCr3, evt->RawDump, NULL);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntVirtMemRead failed: 0x%08x\n", status);
        evt->DumpValid = FALSE;
    }
    else
    {
        evt->DumpValid = TRUE;
        evt->CopySize = sizeof(evt->RawDump);
        IntDumpBuffer(evt->RawDump, 0, sizeof(evt->RawDump), 16, 1, 0, 0);
    }

    IntAlertFillCpuContext(FALSE, &evt->Header.CpuContext);
    IntAlertFillWinProcess(pOrig, &evt->Originator.Process);
    IntAlertFillWinProcess(pVic, &evt->Victim.Process);

    evt->DestinationVirtualAddress = rip;
    evt->ViolationType = memCopyViolationInstrument;

    IntAlertFillVersionInfo(&evt->Header);

    status = IntNotifyIntroEvent(introEventInjectionViolation, evt, sizeof(*evt));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

_cleanup_and_exit:
    if (NULL != pVic)
    {
        IntPolicyProcForceBetaIfNeeded(PROC_OPT_PROT_INSTRUMENT, pVic, &action);
    }

    status = IntDetSetReturnValue(Detour, &gVcpu->Regs,
                                 (action == introGuestNotAllowed) ? WIN_STATUS_ACCESS_DENIED : WIN_STATUS_SUCCESS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetSetReturnValue failed: 0x%08x\n", status);
    }

    STATS_EXIT(statsSetProcInfo);

    return status;
}


INTSTATUS
IntWinProcPrepareInstrument(
    _In_ QWORD FunctionAddress,
    _In_ void *Handler,
    _In_ void *Descriptor
    )
///
/// @brief      This function is responsible for patching the detour that handles "NtSetInformationProcess".
///
/// This function is called before the hook is placed in the guest memory in order "patch" the values of
/// any exports or field offsets that it may need. Specifically, this patches PsProcessType, ObReferenceObjectByHandle,
/// ObDereferenceObject and the offset to Spare in the _EPROCESS structure.
///
/// @param[in]  FunctionAddress     The guest virtual address of the hooked function.
/// @param[in]  Handler             Optional pointer to a #API_HOOK_HANDLER structure.
/// @param[in]  Descriptor          Pointer to a structure that describes the hook and the detour handler.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    API_HOOK_HANDLER *h = Handler;

    struct
    {
        const char *Name;
        void *Addr;
    } exports[] =
    {
        { .Name = "PsProcessType",             .Addr = &h->Code[gGuest.Guest64 ? 0x1f : 0x34] },
        { .Name = "ObReferenceObjectByHandle", .Addr = &h->Code[gGuest.Guest64 ? 0x3b : 0x3c] },
        { .Name = "ObDereferenceObject",       .Addr = &h->Code[gGuest.Guest64 ? 0x81 : 0x60] },
    };

    UNREFERENCED_PARAMETER(FunctionAddress);
    UNREFERENCED_PARAMETER(Descriptor);

    for (size_t i = 0; i < ARRAYSIZE(exports); i++)
    {
        INTSTATUS status;
        QWORD addr;

        status = IntPeFindKernelExport(exports[i].Name, &addr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPeFindKernelExport failed for %s: 0x%08x\n", exports[i].Name, status);
            return status;
        }

        TRACE("[INFO] Export %s found at gva 0x%016llx\n", exports[i].Name, addr);

        if (gGuest.Guest64)
        {
            *(QWORD *)(exports[i].Addr) = addr;
        }
        else
        {
            *(DWORD *)(exports[i].Addr) = (DWORD)addr;
        }
    }

    *(DWORD *)(void *)(&h->Code[gGuest.Guest64 ? 0x59 : 0x4c]) = WIN_KM_FIELD(Process, Spare);

    return INT_STATUS_SUCCESS;
}

