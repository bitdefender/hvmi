/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "alerts.h"
#ifdef INT_COMPILER_MSVC
#include "../../autogen/ver.h"
#endif // INT_COMPILER_MSVC
#include "codeblocks.h"
#include "crc32.h"
#include "guests.h"
#include "visibility.h"
#include "windrv_protected.h"
#include "winpe.h"
#include "winprocesshp.h"
#include "winthread.h"

/// @brief  Global alert buffer.
///
/// There is no point in allocating a new alert buffer every time an alert is sent. Two threads can not send an
/// alert at the same time, so this global buffer can be safely used. According to the
/// #GLUE_IFACE.NotifyIntrospectionAlert documentation, the alert buffer is no longer valid after the function
/// returns, so the integrator must not use this buffer after control is given back to Introcore.
///
/// Users of this buffer must zero it before using it, in order to make sure that previously sent information will
/// not be included in a new alert.
GENERIC_ALERT gAlert = {0};


INTSTATUS
IntAlertFillExecContext(
    _In_ QWORD Cr3,
    _Out_ INTRO_EXEC_CONTEXT *ExecContext
    )
///
/// @brief      Fills the current execution context.
///
/// This will save the current execution mode, guest registers, and the code in the memory page in which the guest
/// RIP resides.
///
/// @param[in]  Cr3         The guest CR3 to be used in order to read code from the guest. If 0, the CR3 saved in the
///                         #gVcpu register cache will be used.
/// @param[out] ExecContext On success, will contain the guest execution context.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    IG_ARCH_REGS const *pRegs = &gVcpu->Regs;

    if (0 == Cr3)
    {
        Cr3 = pRegs->Cr3;
    }

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &ExecContext->CsType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    memcpy(&ExecContext->Registers, pRegs, sizeof(ExecContext->Registers));

    return IntVirtMemRead(pRegs->Rip & PAGE_MASK, sizeof(ExecContext->RipCode),
                          Cr3, ExecContext->RipCode, NULL);
}


INTSTATUS
IntAlertFillCodeBlocks(
    _In_ QWORD Rip,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Execute,
    _Out_ INTRO_CODEBLOCKS *CodeBlocks
    )
///
/// @brief      Fills the code blocks pattern for an alert.
///
/// Code blocks are extracted for the page in which Rip resides.
///
/// @param[in]  Rip         The guest RIP for which to extract code blocks.
/// @param[in]  Cr3         The CR3 used to read the guest memory.
/// @param[in]  Execute     True if this is an execution alert; for execute alerts the function extracts
///                         EXCEPTION_CODEBLOCKS_OFFSET (0x250) even if more than one page must be mapped, otherwise
///                         the function extracts codeblocks only from the RIP page.
/// @param[out] CodeBlocks  On success, will contain the code blocks extracted.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    static CODE_BLOCK gCodeBlocks[PAGE_SIZE / sizeof(CODE_BLOCK)];
    static CODE_BLOCK_PATTERN gPatterns[PAGE_SIZE / sizeof(CODE_BLOCK_PATTERN)];
    INTSTATUS status;
    DWORD startOffset, endOffset, totalSize;
    DWORD patternSize, cbCount, csType;
    DWORD ripCb, startCb;
    BYTE level;
    void *pCode;

    startOffset = endOffset = Rip & PAGE_OFFSET;
    patternSize = ripCb = cbCount = 0;

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    if ((csType != IG_CS_TYPE_32B) && (csType != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", csType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (!Execute)
    {
        if (startOffset > EXCEPTION_CODEBLOCKS_OFFSET)
        {
            if (endOffset + EXCEPTION_CODEBLOCKS_OFFSET < PAGE_SIZE)
            {
                startOffset -= EXCEPTION_CODEBLOCKS_OFFSET;
                endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
            }
            else
            {
                startOffset = PAGE_SIZE - (EXCEPTION_CODEBLOCKS_OFFSET * 2);
                endOffset = PAGE_SIZE - 1;
            }
        }
        else
        {
            startOffset = 0;
            endOffset = (EXCEPTION_CODEBLOCKS_OFFSET * 2) - 1;
        }
    }
    else
    {
        endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, Rip))
        {
            level = cbLevelNormal;
        }
        else
        {
            level = cbLevelMedium;
        }
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        if (IS_KERNEL_POINTER_LIX(Rip))
        {
            level = cbLevelNormal;
        }
        else
        {
            level = cbLevelMedium;
        }
    }
    else
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    totalSize = endOffset - startOffset;

    memzero(gCodeBlocks, sizeof(gCodeBlocks));
    memzero(gPatterns, sizeof(gPatterns));

    status = IntVirtMemMap((Rip & PAGE_MASK) + startOffset, totalSize, Cr3, 0, &pCode);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntVirtMemMap failed for RIP %llx and cr3 %llx: 0x%08x\n",
                Rip & PAGE_MASK, Cr3, status);
        return status;
    }

    status = IntFragExtractCodePattern(pCode,
                                       startOffset,
                                       totalSize,
                                       csType,
                                       level,
                                       PAGE_SIZE / sizeof(CODE_BLOCK_PATTERN),
                                       gPatterns,
                                       &patternSize);
    if (!INT_SUCCESS(status))
    {
        if (status == INT_STATUS_DATA_BUFFER_TOO_SMALL)
        {
            WARNING("[WARNNING] Buffer too small to extract codeblocks (size %d): 0x%08x\n", totalSize, status);
        }
        else
        {
            ERROR("[ERROR] IntFragExtractCodePattern: 0x%08x\n", status);
        }

        goto unmap_and_leave;
    }

    if (patternSize < CODE_BLOCK_CHUNKS_COUNT)
    {
        WARNING("[WARNING] Could not extract enough code-blocks from RIP %llx: %d\n", Rip, patternSize);
        status = INT_STATUS_DATA_BUFFER_TOO_SMALL;
        goto unmap_and_leave;
    }

    for (DWORD i = 0; i < patternSize - CODE_BLOCK_CHUNKS_COUNT; i++)
    {
        if (cbLevelNormal == level &&
            (codeInsCall != gPatterns[i].Value &&
             codeInsJmp != gPatterns[i].Value))
        {
            continue;
        }

        if (cbLevelMedium == level &&
            (codeInsCall != gPatterns[i].Value &&
             codeInsJmp != gPatterns[i].Value &&
             codeInsMovMem != gPatterns[i].Value &&
             codeInsMovFsGs != gPatterns[i].Value))
        {
            continue;
        }

        gCodeBlocks[cbCount].PivotInstruction = gPatterns[i].Value;
        gCodeBlocks[cbCount].OffsetStart = gPatterns[i].Offset;

        // Extract from offset, CODE_BLOCK_CHUNKS_COUNT forward
        for (DWORD j = 0; j < CODE_BLOCK_CHUNKS_COUNT; j++)
        {
            gCodeBlocks[cbCount].Chunks[j] = gPatterns[i + j].Value;
            gCodeBlocks[cbCount].Size++;
        }

        ++cbCount;

        if (cbCount >= sizeof(gCodeBlocks) / sizeof(gCodeBlocks[0]))
        {
            break;
        }
    }

    if (!Execute)
    {
        DWORD previous = gCodeBlocks[0].OffsetStart;
        DWORD ripOffset = Rip & PAGE_OFFSET;

        // We must find where the RIP is inside the extracted codeblocks
        for (DWORD i = 0; i < cbCount; i++)
        {
            if (i == 0 && gCodeBlocks[i].OffsetStart >= ripOffset)
            {
                ripCb = 0;
                break;
            }
            else if (i == cbCount - 1 || (previous <= ripOffset && ripOffset <= gCodeBlocks[i].OffsetStart))
            {
                ripCb = i;
                break;
            }

            previous = gCodeBlocks[i].OffsetStart;
        }

        if (cbCount <= ALERT_MAX_CODEBLOCKS || (ripCb <= ALERT_MAX_CODEBLOCKS / 2))
        {
            // [0; MIN(ALERT_MAX_CODEBLOCKS, cbCount)]
            startCb = 0;
        }
        else if (cbCount - ripCb < ALERT_MAX_CODEBLOCKS)
        {
            // [cbCount - ALERT_MAX_CODEBLOCKS; cbCount]
            startCb = cbCount >= ALERT_MAX_CODEBLOCKS ? cbCount - ALERT_MAX_CODEBLOCKS : 0;
        }
        else
        {
            // save before & after RIP
            startCb = ripCb - (ALERT_MAX_CODEBLOCKS / 2);
        }
    }
    else
    {
        startCb = 0;
    }

    CodeBlocks->StartAddress = (Rip & PAGE_MASK) + gCodeBlocks[startCb].OffsetStart;
    CodeBlocks->Rip = Rip;
    CodeBlocks->Count = 0;

    for (DWORD i = startCb; i < cbCount; i++)
    {
        CodeBlocks->CodeBlocks[CodeBlocks->Count].Offset = (WORD)gCodeBlocks[i].OffsetStart;
        CodeBlocks->CodeBlocks[CodeBlocks->Count].Pivot = gCodeBlocks[i].PivotInstruction;
        CodeBlocks->CodeBlocks[CodeBlocks->Count].Value = Crc32Compute(gCodeBlocks[i].Chunks,
                                                                       CODE_BLOCK_CHUNKS_COUNT,
                                                                       INITIAL_CRC_VALUE);
        if (i == ripCb)
        {
            CodeBlocks->RipCbIndex = CodeBlocks->Count;
        }

        CodeBlocks->Count++;

        if (CodeBlocks->Count >= ALERT_MAX_CODEBLOCKS)
        {
            break;
        }
    }

    CodeBlocks->Valid = TRUE;

    status = INT_STATUS_SUCCESS;

unmap_and_leave:
    IntVirtMemUnmap(&pCode);

    return status;
}


void
IntAlertFillVersionInfo(
    _Out_ INTRO_VIOLATION_HEADER *Header
    )
///
/// @brief      Fills version information for an alert.
///
/// @param[out] Header  The header of the event. Will contain information about the current versions of Introcore,
///                     exceptions, and CAMI.
///
{
    INTSTATUS status;

    if (gGuest.Exceptions)
    {
        Header->VerInfo.ExceptionBuild = gGuest.Exceptions->Version.Build;
        Header->VerInfo.ExceptionMajor = gGuest.Exceptions->Version.Major;
        Header->VerInfo.ExceptionMinor = gGuest.Exceptions->Version.Minor;
    }

    Header->VerInfo.IntroMajor = INTRO_VERSION_MAJOR;
    Header->VerInfo.IntroMinor = INTRO_VERSION_MINOR;
    Header->VerInfo.IntroRevision = INTRO_VERSION_REVISION;
    Header->VerInfo.IntroBuildNumber = INTRO_VERSION_BUILDNUMBER;

    Header->VerInfo.OsVer = gGuest.OSVersion;

    Header->ViolationVersion = INTRO_VIOLATION_VERSION;

    status = IntCamiGetVersion(&Header->VerInfo.CamiMajor,
                               &Header->VerInfo.CamiMinor,
                               &Header->VerInfo.CamiBuildNumber);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntCamiGetVersion failed: 0x%08x\n", status);
    }
}


QWORD
IntAlertCoreGetFlags(
    _In_ QWORD ProtectionFlag,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      Returns the flags for an alert.
///
/// @param[in]  ProtectionFlag  The core protection flag for each the alert was generated. This is one of the
///                             @ref group_options values.
/// @param[in]  Reason          The reason for which the alert was generated.
///
/// @returns    The alert flags for the alert. A combination of @ref group_alert_flags values.
///
{
    INTSTATUS status;
    QWORD flags;
    DWORD ring;

    flags = 0;
    ring = 0;

    // Get the current ring.
    status = IntGetCurrentRing(gVcpu->Index, &ring);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntGetCurrentRing failed: 0x%08x\n", status);
        ring = IG_CS_RING_0;
    }

    if (IG_CS_RING_0 != ring)
    {
        flags |= ALERT_FLAG_NOT_RING0;
    }

    if (gGuest.OSType == introGuestLinux)
    {
        flags |= ALERT_FLAG_LINUX;
    }

    if (Reason == introReasonAllowedFeedback || IntPolicyIsCoreOptionFeedback(ProtectionFlag))
    {
        flags |= ALERT_FLAG_FEEDBACK_ONLY;
    }

    if (IntPolicyCoreIsOptionBeta(ProtectionFlag))
    {
        flags |= ALERT_FLAG_BETA;
    }

    if (ProtectionFlag == INTRO_OPT_PROT_UM_SYS_PROCS)
    {
        flags |= ALERT_FLAG_SYSPROC;
    }

    return flags;
}


QWORD
IntAlertProcGetFlags(
    _In_ QWORD ProtectionFlag,
    _In_opt_ const void *Process,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ QWORD AdditionalFlags
    )
///
/// @brief      Returns the flags for an alert.
///
/// @param[in]  ProtectionFlag  The process protection flag for each the alert was generated. This is one of the
///                             @ref group_process_options values.
/// @param[in]  Process         The process for which the alert was generated. For Windows guests this is a pointer
///                             to a #WIN_PROCESS_OBJECT structure, for Linux guests this is a pointer to a
///                             #LIX_TASK_OBJECT structure.
/// @param[in]  Reason          The reason for which the alert was generated.
/// @param[in]  AdditionalFlags Additional flags to be set in the returned value.
///
/// @returns    The alert flags for the alert. A combination of @ref group_alert_flags values.
///
{
    INTSTATUS status;
    QWORD flags;
    DWORD ring;

    flags = 0;
    ring = 0;

    // Get the current ring.
    status = IntGetCurrentRing(gVcpu->Index, &ring);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntGetCurrentRing failed: 0x%08x\n", status);
        ring = IG_CS_RING_0;
    }

    if (IG_CS_RING_0 != ring)
    {
        flags |= ALERT_FLAG_NOT_RING0;
    }

    if (gGuest.OSType == introGuestLinux)
    {
        flags |= ALERT_FLAG_LINUX;
    }

    if (Reason == introReasonAllowedFeedback || IntPolicyProcIsFeedback(Process, ProtectionFlag))
    {
        flags |= ALERT_FLAG_FEEDBACK_ONLY;
    }

    if (IntPolicyProcIsBeta(Process, ProtectionFlag))
    {
        flags |= ALERT_FLAG_BETA;
    }

    if (IntPolicyGetProcProt(Process) == INTRO_OPT_PROT_UM_SYS_PROCS)
    {
        flags |= ALERT_FLAG_SYSPROC;
    }

    flags |= AdditionalFlags;

    return flags;
}


void
IntAlertFillCpuContext(
    _In_ BOOLEAN CopyInstruction,
    _Out_ INTRO_CPUCTX *CpuContext
    )
///
/// @brief      Fills the current CPU context for an alert.
///
/// @param[in]  CopyInstruction     True if the textual form of the instruction that generated this even must be
///                                 included in the alert.
/// @param[out] CpuContext          The CPU context. If CopyInstruction is False, the #INTRO_CPUCTX.Instruction field
///                                 will not be valid.
///
{
    CpuContext->Valid = TRUE;
    CpuContext->Rip = gVcpu->Regs.Rip;
    CpuContext->Cr3 = gVcpu->Regs.Cr3;
    CpuContext->Cpu = gVcpu->Index;

    if (CopyInstruction)
    {
        NdToText(&gVcpu->Instruction,
                 CpuContext->Rip,
                 sizeof(CpuContext->Instruction),
                 CpuContext->Instruction);
    }
}


void
IntAlertFillWriteInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ INTRO_WRITE_INFO *WriteInfo
    )
///
/// @brief      Fills the write information for an alert.
///
/// @param[in]  Victim      The information about the victim inside the alert.
/// @param[out] WriteInfo   The original and the new written value for the alert.
///
{
    if (NULL == Victim)
    {
        return;
    }

    WriteInfo->Size = Victim->WriteInfo.AccessSize;

    memcpy(WriteInfo->NewValue, Victim->WriteInfo.NewValue, MIN(sizeof(WriteInfo->NewValue), WriteInfo->Size));
    memcpy(WriteInfo->OldValue, Victim->WriteInfo.OldValue, MIN(sizeof(WriteInfo->OldValue), WriteInfo->Size));
}


void
IntAlertFillReadInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ INTRO_READ_INFO *ReadInfo
    )
///
/// @brief      Fills the read information for an alert.
///
/// @param[in]  Victim      The information about the victim inside the alert.
/// @param[out] ReadInfo    The read value for the alert.
///
{
    if (NULL == Victim)
    {
        return;
    }

    ReadInfo->Size = Victim->ReadInfo.AccessSize;

    memcpy(ReadInfo->Value, Victim->ReadInfo.Value, MIN(sizeof(ReadInfo->Value), ReadInfo->Size));
}


void
IntAlertFillExecInfo(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ INTRO_EXEC_INFO *ExecInfo
    )
///
/// @brief      Fills the execution information for an alert.
///
/// @param[in]  Victim      The information about the victim inside the alert.
/// @param[out] ExecInfo    The execution info for the alert.
///
{
    if (NULL == Victim)
    {
        return;
    }

    ExecInfo->Length = Victim->ExecInfo.Length;
    ExecInfo->Rsp = Victim->ExecInfo.Rsp;
    ExecInfo->StackBase = Victim->ExecInfo.StackBase;
    ExecInfo->StackLimit = Victim->ExecInfo.StackLimit;
}


void
IntAlertFillDriverObject(
    _In_ const WIN_DRIVER_OBJECT *DriverObject,
    _Out_ INTRO_DRVOBJ *EventDrvObj
    )
///
/// @brief      Saves driver object information inside an alert. Available only for Windows guests.
///
/// @param[in]  DriverObject    The driver object to be saved.
/// @param[out] EventDrvObj     Alert driver object information.
///
{
    if (NULL == DriverObject)
    {
        return;
    }

    wstrlcpy(EventDrvObj->Name, DriverObject->Name, ARRAYSIZE(EventDrvObj->Name));

    EventDrvObj->Valid = TRUE;
    EventDrvObj->Address = DriverObject->DriverObjectGva;
    EventDrvObj->Owner = DriverObject->Owner;
}


void
IntAlertFillWinKmModule(
    _In_opt_ const KERNEL_DRIVER *Driver,
    _Out_ INTRO_MODULE *EventModule
    )
///
/// @brief      Saves kernel module information inside an alert.
///
/// @param[in]  Driver      The kernel driver for which the information will be saved.
/// @param[out] EventModule Alert driver object information.
///
{
    if (NULL == Driver)
    {
        EventModule->Valid = FALSE;
        return;
    }

    if (NULL != Driver->Win.Path && Driver->Win.Path[0] != u'\0')
    {
        wstrlcpy(EventModule->Path, Driver->Win.Path, ARRAYSIZE(EventModule->Path));
    }

    if (NULL != Driver->Name && *(WCHAR *)Driver->Name != u'\0')
    {
        wstrlcpy(EventModule->Name, Driver->Name, ARRAYSIZE(EventModule->Name));
    }

    EventModule->Base = Driver->BaseVa;
    EventModule->Size = (DWORD)Driver->Size;
    EventModule->TimeDateStamp = Driver->Win.TimeDateStamp;

    EventModule->Valid = TRUE;
}


void
IntAlertFillWinUmModule(
    _In_opt_ const WIN_PROCESS_MODULE *Module,
    _Out_ INTRO_MODULE *EventModule
    )
///
/// @brief      Fills information about a user mode module inside an alert.
///
/// @param[in]  Module      The module to be saved inside the alert.
/// @param[out] EventModule The module information saved inside the alert.
///
{
    if (NULL == Module)
    {
        EventModule->Valid = FALSE;
        return;
    }

    if (NULL != Module->Path && Module->Path->Path[0] != u'\0')
    {
        wstrlcpy(EventModule->Path, Module->Path->Path, ARRAYSIZE(EventModule->Path));
        wstrlcpy(EventModule->Name, Module->Path->Name, ARRAYSIZE(EventModule->Name));
    }

    EventModule->Base = Module->VirtualBase;
    EventModule->Size = Module->Size;

    if (Module->Cache)
    {
        EventModule->TimeDateStamp = Module->Cache->Info.TimeDateStamp;
    }

    EventModule->Valid = TRUE;
}


void
IntAlertFillWinProcess(
    _In_ const WIN_PROCESS_OBJECT *Process,
    _Out_ INTRO_PROCESS *EventProcess
    )
///
/// @brief      Saves information about a windows process inside an alert.
///
/// @param[in]  Process         The process to be saved.
/// @param[out] EventProcess    The information saved inside the alert.
///
{
    INTSTATUS status;
    QWORD ethreadGva = 0;

    if (NULL == Process)
    {
        return;
    }

    EventProcess->Cr3 = Process->Cr3;
    EventProcess->CreationTime = Process->CreationTime;
    EventProcess->Pid = Process->Pid;

    strlcpy(EventProcess->ImageName, Process->Name, sizeof(EventProcess->ImageName));

    if (NULL != Process->Path)
    {
        wstrlcpy(EventProcess->Path, Process->Path->Path, ARRAYSIZE(EventProcess->Path));
    }

    EventProcess->Valid = TRUE;

    status = IntWinThrGetCurrentThread(IG_CURRENT_VCPU, &ethreadGva);
    if (INT_SUCCESS(status))
    {
        status = IntWinGetAccesTokenFromThread(ethreadGva, &EventProcess->SecurityInfo.WindowsToken);
        if (INT_SUCCESS(status))
        {
            EventProcess->SecurityInfo.WindowsToken.ImpersonationToken = TRUE;
            goto _skip_process_token;
        }
    }

    status = IntWinGetAccessTokenFromProcess(Process->Pid,
                                             Process->EprocessAddress,
                                             &EventProcess->SecurityInfo.WindowsToken);
    if (!INT_SUCCESS(status))
    {
        EventProcess->SecurityInfo.WindowsToken.Valid = FALSE;
    }
    else
    {
        EventProcess->SecurityInfo.WindowsToken.Valid = TRUE;
    }

_skip_process_token:
    if (Process->CommandLine != NULL)
    {
        strlcpy(EventProcess->CmdLine, Process->CommandLine, sizeof(EventProcess->CmdLine));
    }

    EventProcess->Context = Process->Context;
    EventProcess->Wow64 = !!Process->Wow64Process;
}


void
IntAlertFillWinProcessByCr3(
    _In_ QWORD ProcessCr3,
    _Out_ INTRO_PROCESS *EventProcess
    )
///
/// @brief      Saves information about a Windows process inside an alert. The process is searched by its kernel CR3.
///
/// If no process is found, #INTRO_PROCESS.Valid will be set to False.
///
/// @param[in]  ProcessCr3      The kernel CR3 of the process.
/// @param[out] EventProcess    The information saved inside the alert.
///
{
    WIN_PROCESS_OBJECT *pProc = IntWinProcFindObjectByCr3(ProcessCr3);
    if (NULL == pProc)
    {
        EventProcess->Valid = FALSE;
        return;
    }

    IntAlertFillWinProcess(pProc, EventProcess);
}


void
IntAlertFillWinProcessCurrent(
    _Out_ INTRO_PROCESS *EventProcess
    )
///
/// @brief      Saves information about the current Windows process inside an alert.
///
/// The process is searched by using the currently loaded kernel CR3.
///
/// @param[out] EventProcess    The information saved inside the alert.
///
{
    INTSTATUS status;
    QWORD cr3 = 0;

    status = IntCr3Read(IG_CURRENT_VCPU, &cr3);
    if (!INT_SUCCESS(status))
    {
        EventProcess->Valid = FALSE;
        return;
    }

    IntAlertFillWinProcessByCr3(cr3, EventProcess);
}


void
IntAlertEptFillFromUmOriginator(
    _In_ const EXCEPTION_UM_ORIGINATOR *Originator,
    _Out_ EVENT_EPT_VIOLATION *EptViolation
    )
///
/// @brief      Fills user mode originator information inside an EPT alert.
///
/// This will save the originator user mode module and, if it exists, the return module.
///
/// @param[in]  Originator      Information about who generated the alert.
/// @param[out] EptViolation    The event in which the information is saved.
///
{
    IntAlertFillWinUmModule(Originator->Library, &EptViolation->Originator.Module);

    if (Originator->Return.Library)
    {
        IntAlertFillWinUmModule(Originator->Return.Library, &EptViolation->Originator.ReturnModule);

        EptViolation->ReturnRip = Originator->Return.Rip;
    }
}


void
IntAlertEptFillFromKmOriginator(
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_EPT_VIOLATION *EptViolation
    )
///
/// @brief      Fills kernel mode originator information inside an EPT alert.
///
/// This will save the originator kernel mode module and, if it exists, the return module.
///
/// @param[in]  Originator      Information about who generated the alert.
/// @param[out] EptViolation    The event in which the information is saved.
///
{
    if (Originator->Original.Driver)
    {
        IntAlertFillWinKmModule(Originator->Original.Driver, &EptViolation->Originator.Module);

        memcpy(EptViolation->RipSectionName,
               Originator->Original.Section,
               sizeof(EptViolation->RipSectionName));
    }

    if (Originator->Return.Driver)
    {
        IntAlertFillWinKmModule(Originator->Return.Driver, &EptViolation->Originator.ReturnModule);

        memcpy(EptViolation->ReturnRipSectionName,
               Originator->Return.Section,
               sizeof(EptViolation->ReturnRipSectionName));
    }

    EptViolation->ReturnRip = Originator->Return.Rip;
}


void
IntAlertEptFillFromVictimZone(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ EVENT_EPT_VIOLATION *EptViolation
    )
///
/// @brief      Fills the victim information inside an EPT alert.
///
/// Based on the #INTRO_OBJECT_TYPE of the victim, different information is saved.
///
/// @param[in]  Victim          Information about the victim.
/// @param[out] EptViolation    The event in which the information is saved.
{
    switch (Victim->Object.Type)
    {
    case introObjectTypeVeAgent:
    case introObjectTypeSsdt:
    case introObjectTypeExTable:
    case introObjectTypeKmModule:
    {
        if (gGuest.OSType == introGuestLinux)
        {
            break;
        }

        if (Victim->Object.Module.Module)
        {
            KERNEL_DRIVER *pDriver = Victim->Object.Module.Module;
            PWCHAR pModName = pDriver->Name;

            IntAlertFillWinKmModule(pDriver, &EptViolation->Victim.Module);

            if (IntWinDrvIsProtectedAv(pModName))
            {
                EptViolation->Header.Flags |= ALERT_FLAG_ANTIVIRUS;
            }

            memcpy(EptViolation->ModifiedSectionName,
                   Victim->Object.Module.SectionName,
                   sizeof(EptViolation->ModifiedSectionName));
        }

        // It shouldn't write more than 8 bytes...
        if ((Victim->ZoneFlags & ZONE_LIB_IMPORTS) &&
            IS_KERNEL_POINTER_WIN(gGuest.Guest64, Victim->WriteInfo.OldValue[0]))
        {
            KERNEL_DRIVER *pDriver;
            INTSTATUS status;

            pDriver = IntDriverFindByAddress(Victim->WriteInfo.OldValue[0]);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntDriverFindByAddress for GVA 0x%016llx\n", Victim->WriteInfo.OldValue[0]);
                break;
            }

            if (pDriver->BaseVa != gGuest.KernelVa)
            {
                status = IntPeGetExportNameByRva(pDriver->BaseVa,
                                                 NULL,
                                                 (DWORD)(Victim->WriteInfo.OldValue[0] - pDriver->BaseVa),
                                                 ALERT_MAX_FUNCTION_NAME_LEN,
                                                 EptViolation->FunctionName);
            }
            else
            {
                status = IntPeGetExportNameByRvaInBuffer(pDriver->BaseVa,
                                                         gWinGuest->KernelBuffer,
                                                         gWinGuest->KernelBufferSize,
                                                         (DWORD)(Victim->WriteInfo.OldValue[0] - pDriver->BaseVa),
                                                         ALERT_MAX_FUNCTION_NAME_LEN,
                                                         EptViolation->FunctionName);
            }

            if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
            {
                WARNING("[WARNING] IntPeGetExportNameByRva failed for module 0x%016llx, "
                        "RVA %x, GVA 0x%016llx: 0x%08x\n",
                        pDriver->BaseVa,
                        (DWORD)(Victim->WriteInfo.OldValue[0] - pDriver->BaseVa),
                        Victim->WriteInfo.OldValue[0],
                        status);
            }
        }
        else if (Victim->Object.Type == introObjectTypeKmModule)
        {
            DWORD functionStart;
            INTSTATUS status;

            if (Victim->Object.BaseAddress != gGuest.KernelVa)
            {
                status = IntPeFindFunctionStart(Victim->Object.BaseAddress,
                                                NULL,
                                                (DWORD)(Victim->Ept.Gva - Victim->Object.BaseAddress),
                                                &functionStart);
            }
            else
            {
                // It's safe to use WinGuest->KernelBuffer here, as we already checked the OS type
                // (and bailed out if we were on Linux)
                status = IntPeFindFunctionStartInBuffer(Victim->Object.BaseAddress,
                                                        gWinGuest->KernelBuffer,
                                                        gWinGuest->KernelBufferSize,
                                                        (DWORD)(Victim->Ept.Gva - Victim->Object.BaseAddress),
                                                        &functionStart);
            }

            if (!INT_SUCCESS(status))
            {
                // maybe it's an exported variable
                functionStart = (DWORD)(Victim->Ept.Gva - Victim->Object.BaseAddress);
            }

            if (Victim->Object.BaseAddress != gGuest.KernelVa)
            {
                status = IntPeGetExportNameByRva(Victim->Object.BaseAddress,
                                                 NULL,
                                                 functionStart,
                                                 ALERT_MAX_FUNCTION_NAME_LEN,
                                                 EptViolation->FunctionName);
            }
            else
            {
                status = IntPeGetExportNameByRvaInBuffer(Victim->Object.BaseAddress,
                                                         gWinGuest->KernelBuffer,
                                                         gWinGuest->KernelBufferSize,
                                                         functionStart,
                                                         ALERT_MAX_FUNCTION_NAME_LEN,
                                                         EptViolation->FunctionName);
            }
            if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
            {
                WARNING("[WARNING] IntPeGetExportNameByRva failed for module 0x%016llx, "
                        "RVA %x, GVA 0x%016llx: 0x%08x\n",
                        Victim->Object.BaseAddress,
                        (DWORD)(Victim->Ept.Gva - Victim->Object.BaseAddress),
                        Victim->Ept.Gva,
                        status);
            }
        }

        break;
    }

    case introObjectTypeFastIoDispatch:
    case introObjectTypeDriverObject:
    {
        PWIN_DRIVER_OBJECT pDrvObj = Victim->Object.DriverObject;

        IntAlertFillDriverObject(pDrvObj, &EptViolation->Victim.DriverObject);

        if (IntWinDrvObjIsProtectedAv(pDrvObj->Name))
        {
            EptViolation->Header.Flags |= ALERT_FLAG_ANTIVIRUS;
        }

        break;
    }

    case introObjectTypeHalIntController:
    case introObjectTypeSelfMapEntry:
    case introObjectTypeKmLoggerContext:
    case introObjectTypeTokenPrivs:
    case introObjectTypeSudExec:
    case introObjectTypeHalHeap:
    case introObjectTypeSecDesc:
    case introObjectTypeAcl:
        break;

    case introObjectTypeIdt:
    {
        EptViolation->Victim.IdtEntry = (BYTE)((Victim->Ept.Gva - Victim->Object.BaseAddress) /
                                               (gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32));
        break;
    }

    case introObjectTypeUmModule:
    {
        WIN_PROCESS_MODULE *pModule = Victim->Object.Library.Module;

        if (pModule != NULL)
        {
            IntAlertFillWinUmModule(pModule, &EptViolation->Victim.Module);
        }

        if (NULL != pModule && NULL == Victim->Object.Library.Export)
        {
            WINUM_CACHE_EXPORT *pExport = IntWinUmCacheGetExportFromRange(pModule, Victim->Ept.Gva, 0x20);
            if (pExport != NULL)
            {
                for (DWORD export = 0; export < MIN(ALERT_MAX_FUNCTIONS, pExport->NumberOfOffsets); export++)
                {
                    strlcpy(EptViolation->Export.Name[export],
                            pExport->Names[export],
                            MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[export] + 1));

                    EptViolation->Export.Hash[export] = Crc32String(pExport->Names[export], INITIAL_CRC_VALUE);
                }

                EptViolation->Export.Delta = (DWORD)(Victim->Ept.Gva - pModule->VirtualBase - pExport->Rva);

                strlcpy(EptViolation->FunctionName, pExport->Names[0],
                        MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[0] + 1));
                EptViolation->Delta = (DWORD)(Victim->Ept.Gva - pModule->VirtualBase - pExport->Rva);
                EptViolation->FunctionNameHash = Crc32String(pExport->Names[0], INITIAL_CRC_VALUE);
            }
        }
        else if (Victim->Object.Library.Export != NULL)
        {
            WINUM_CACHE_EXPORT *pExport = Victim->Object.Library.Export;

            for (DWORD export = 0; export < MIN(ALERT_MAX_FUNCTIONS, pExport->NumberOfOffsets); export++)
            {
                strlcpy(EptViolation->Export.Name[export], pExport->Names[export],
                        MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[export] + 1));
                EptViolation->Export.Hash[export] = Crc32String(pExport->Names[export], INITIAL_CRC_VALUE);
            }

            strlcpy(EptViolation->FunctionName,
                    pExport->Names[0],
                    MIN(ALERT_MAX_FUNCTION_NAME_LEN, pExport->NameLens[0] + 1));

            EptViolation->FunctionNameHash = Crc32String(pExport->Names[0], INITIAL_CRC_VALUE);

            if (pModule != NULL)
            {
                EptViolation->Export.Delta = (DWORD)(Victim->Ept.Gva - pModule->VirtualBase - pExport->Rva);
                EptViolation->Delta =
                    (DWORD)(Victim->Ept.Gva - pModule->VirtualBase - Victim->Object.Library.Export->Rva);
            }
        }

        if (0 == EptViolation->FunctionName[0] && !IntWinUmCacheIsExportDirRead(pModule))
        {
            strlcpy(EptViolation->FunctionName, "<not_read>", sizeof(EptViolation->FunctionName));
        }

        break;
    }

    case introObjectTypeUmGenericNxZone:
        break;

    default:
        WARNING("[WARNING] Shouldn't reach here (for now). Type is %d...\n", Victim->Object.Type);
        return;
    }

    EptViolation->Victim.Type = Victim->Object.Type;

    EptViolation->Offset = Victim->Ept.Gva & PAGE_OFFSET;
    EptViolation->VirtualPage = Victim->Ept.Gva & PAGE_MASK;
    EptViolation->PhysicalPage = Victim->Ept.Gpa & PHYS_PAGE_MASK;
    EptViolation->HookStartVirtual = Victim->Object.BaseAddress;

    IntTranslateVirtualAddress(EptViolation->HookStartVirtual,
                               gVcpu->Regs.Cr3,
                               &EptViolation->HookStartPhysical);

    EptViolation->ZoneTypes = Victim->ZoneFlags;

    if (Victim->ZoneFlags & ZONE_EXECUTE)
    {
        EptViolation->Violation = IG_EPT_HOOK_EXECUTE;

        IntAlertFillExecInfo(Victim, &EptViolation->ExecInfo);
    }
    else if (Victim->ZoneFlags & ZONE_WRITE)
    {
        EptViolation->Violation = IG_EPT_HOOK_WRITE;

        IntAlertFillWriteInfo(Victim, &EptViolation->WriteInfo);
    }
    else if (Victim->ZoneFlags & ZONE_READ)
    {
        EptViolation->Violation = IG_EPT_HOOK_READ;

        IntAlertFillReadInfo(Victim, &EptViolation->ReadInfo);
    }
}


void
IntAlertMsrFill(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_MSR_VIOLATION *MsrViolation
    )
///
/// @brief      Saves information about a MSR write attempt in an event.
///
/// This will save the modified MSR, it's original and new value, and the driver that made the change, as well as
/// the driver in which it returns, if one exists.
///
/// @param[in]  Victim          Information about the victim.
/// @param[in]  Originator      Information about the originator.
/// @param[out] MsrViolation    Information to be included in the alert.
///
{
    MsrViolation->Victim.Msr = Victim->Msr.Msr;

    IntAlertFillWriteInfo(Victim, &MsrViolation->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &MsrViolation->Originator.Module);
    IntAlertFillWinKmModule(Originator->Return.Driver, &MsrViolation->Originator.ReturnModule);
}


void
IntAlertDtrFill(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_DTR_VIOLATION *DtrViolation
    )
///
/// @brief      Saves information about a DTR write attempt in an event.
///
/// This will save the modified DTR (IDTR, GDTR), it's original and new value, and the driver that made the change,
/// as well as the driver in which it returns, if one exists.
///
/// @param[in]  Victim          Information about the victim.
/// @param[in]  Originator      Information about the originator.
/// @param[out] DtrViolation    Information to be included in the alert.
///
{
    DtrViolation->Victim.Type = Victim->Dtr.Type;

    IntAlertFillWriteInfo(Victim, &DtrViolation->WriteInfo);

    if (gGuest.OSType == introGuestWindows)
    {
        IntAlertFillWinKmModule(Originator->Original.Driver, &DtrViolation->Originator.Module);
        IntAlertFillWinKmModule(Originator->Return.Driver, &DtrViolation->Originator.ReturnModule);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntAlertFillLixKmModule(Originator->Original.Driver, &DtrViolation->Originator.Module);
        IntAlertFillLixKmModule(Originator->Return.Driver, &DtrViolation->Originator.ReturnModule);
    }
}


void
IntAlertCrFill(
    _In_ const EXCEPTION_VICTIM_ZONE *Victim,
    _In_ const EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ EVENT_CR_VIOLATION *CrViolation
    )
///
/// @brief      Saves information about a CR write attempt in an event.
///
/// This will save the modified CR, it's original and new value, and the driver that made the change, as well as the
/// driver in which it returns, if one exists.
///
/// @param[in]  Victim      Information about the victim.
/// @param[in]  Originator  Information about the originator.
/// @param[out] CrViolation Information to be included in the alert.
///
{
    CrViolation->Victim.Cr = Victim->Cr.Cr;
    IntAlertFillWriteInfo(Victim, &CrViolation->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &CrViolation->Originator.Module);
    IntAlertFillWinKmModule(Originator->Return.Driver, &CrViolation->Originator.ReturnModule);
}


void
IntAlertFillLixKmModule(
    _In_ const KERNEL_DRIVER *Driver,
    _Out_ INTRO_MODULE *EventModule
    )
///
/// @brief      Saves information about a kernel module inside an alert.
///
/// @param[in]  Driver      The kernel module to save.
/// @param[out] EventModule The kernel module saved in the event.
///
{
    if (NULL == Driver)
    {
        return;
    }

    if (Driver->NameLength > 0 && *(char *)Driver->Name)
    {
        utf8toutf16(EventModule->Name, Driver->Name, ARRAYSIZE(EventModule->Name));
    }

    EventModule->Base = Driver->BaseVa;
    EventModule->Size = (DWORD)Driver->Size;

    EventModule->Valid = TRUE;
}


void
IntAlertFillLixProcess(
    _In_ const LIX_TASK_OBJECT *Task,
    _Out_ INTRO_PROCESS *EventProcess
    )
///
/// @brief      Saves information about a Linux process inside an event.
///
/// @param[in]  Task            The process to save.
/// @param[out] EventProcess    The process saved in the event.
///
{
    if (NULL == Task)
    {
        return;
    }

    EventProcess->Valid = TRUE;
    EventProcess->Cr3 = Task->Cr3;
    EventProcess->CreationTime = Task->CreationTime;
    EventProcess->Pid = Task->Pid;

    // NOTE: If this is really invalid, something critical happened
    if (Task->Comm[0] != 0)
    {
        strlcpy(EventProcess->ImageName, Task->Comm, sizeof(EventProcess->ImageName));
    }
    else if (Task->Path)
    {
        strlcpy(EventProcess->ImageName, Task->Path->Name, sizeof(EventProcess->ImageName));
    }

    if (Task->CmdLine)
    {
        strlcpy(EventProcess->CmdLine, Task->CmdLine, sizeof(EventProcess->CmdLine));
    }

    if (Task->Path)
    {
        utf8toutf16(EventProcess->Path, Task->Path->Path, ARRAYSIZE(EventProcess->Path));
    }

    EventProcess->Context = Task->Context;
}


void
IntAlertFillLixCurrentProcess(
    _Out_ INTRO_PROCESS *EventProcess
    )
///
/// @brief      Saves the current Linux process inside an event.
///
/// @param[out] EventProcess    The saved process.
///
{
    const LIX_TASK_OBJECT *pTask = IntLixTaskGetCurrent(gVcpu->Index);
    if (NULL == pTask)
    {
        EventProcess->Valid = FALSE;
        return;
    }

    IntAlertFillLixProcess(pTask, EventProcess);
}


void
IntAlertFillConnection(
    _In_ const INTRONET_ENDPOINT *Connection,
    _Out_ EVENT_CONNECTION_EVENT *Event
    )
///
/// @brief      Saves information about a guest connection in an event.
///
/// @param[in]  Connection  Connection to save.
/// @param[out] Event       The event.
///
{
    if (NULL == Connection)
    {
        return;
    }

    memzero(Event, sizeof(*Event));

    Event->Family = Connection->AddressFamily;
    Event->State = Connection->State;

    Event->LocalPort = Connection->LocalPort;
    Event->RemotePort = Connection->RemotePort;

    memcpy(&Event->LocalAddress, &Connection->LocalAddress, sizeof(Event->LocalAddress));

    memcpy(&Event->RemoteAddress, &Connection->RemoteAddress, sizeof(Event->RemoteAddress));

    if (introGuestWindows == gGuest.OSType)
    {
        IntAlertFillWinProcess(Connection->OwnerProcess, &Event->Owner);
    }
    else if (introGuestLinux == gGuest.OSType)
    {
        IntAlertFillLixProcess(Connection->OwnerTask, &Event->Owner);
    }
}


INTSTATUS
IntAlertFillDpiExtraInfo(
    _In_ DPI_EXTRA_INFO *CollectedExtraInfo,
    _In_ INTRO_PC_VIOLATION_TYPE PcType,
    _In_ WIN_PROCESS_OBJECT *VictimProcess,
    _Out_ INTRO_DPI_EXTRA_INFO *ExtraInfo
    )
///
/// @brief  Fills the collected DPI extra information.
///
/// @param[in]  CollectedExtraInfo  The #DPI_EXTRA_INFO structure containing the collected information.
/// @param[in]  PcType              The #INTRO_PC_VIOLATION_TYPE of the triggered alert.
/// @param[in]  VictimProcess       The victim process object of the violation.
/// @param[out] ExtraInfo           The #INTRO_DPI_EXTRA_INFO to be filled.
///
{
    if (NULL == CollectedExtraInfo)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == VictimProcess)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (PcType == INT_PC_VIOLATION_DPI_DEBUG_FLAG)
    {
        WIN_PROCESS_OBJECT *pDebugger = IntWinProcFindObjectByEprocess(VictimProcess->CreationInfo.DebuggerEprocess);

        IntAlertFillWinProcess(pDebugger, &ExtraInfo->DpiDebugFlag.Debugger);
    }
    else if (PcType == INT_PC_VIOLATION_DPI_PIVOTED_STACK)
    {
        DWORD sz = gGuest.Guest64 ? sizeof(KTRAP_FRAME64) : sizeof(KTRAP_FRAME32);

        ExtraInfo->DpiPivotedStack.CurrentStack = CollectedExtraInfo->DpiPivotedStackExtraInfo.CurrentStack;
        ExtraInfo->DpiPivotedStack.StackBase = CollectedExtraInfo->DpiPivotedStackExtraInfo.StackBase;
        ExtraInfo->DpiPivotedStack.StackLimit = CollectedExtraInfo->DpiPivotedStackExtraInfo.StackLimit;
        ExtraInfo->DpiPivotedStack.Wow64CurrentStack = CollectedExtraInfo->DpiPivotedStackExtraInfo.CurrentWow64Stack;
        ExtraInfo->DpiPivotedStack.Wow64StackBase = CollectedExtraInfo->DpiPivotedStackExtraInfo.Wow64StackBase;
        ExtraInfo->DpiPivotedStack.Wow64StackLimit = CollectedExtraInfo->DpiPivotedStackExtraInfo.Wow64StackLimit;

        IntVirtMemRead(CollectedExtraInfo->DpiPivotedStackExtraInfo.TrapFrameAddress,
                       MIN(sz, sizeof(ExtraInfo->DpiPivotedStack.TrapFrameContent)),
                       gGuest.Mm.SystemCr3,
                       ExtraInfo->DpiPivotedStack.TrapFrameContent,
                       NULL);
    }
    else if (PcType == INT_PC_VIOLATION_DPI_STOLEN_TOKEN)
    {
        WIN_PROCESS_OBJECT *pStolenFrom = IntWinProcFindObjectByEprocess(
                                              CollectedExtraInfo->DpiStolenTokenExtraInfo.StolenFromEprocess);

        IntAlertFillWinProcess(pStolenFrom, &ExtraInfo->DpiStolenToken.StolenFrom);
    }
    else if (PcType == INT_PC_VIOLATION_DPI_HEAP_SPRAY)
    {
        WORD maxNumberOfHeapVals = 0;
        DWORD detectedPage = 0, maxPageHeapVals = 0;

        ExtraInfo->DpiHeapSpray.ShellcodeFlags = CollectedExtraInfo->DpiHeapSprayExtraInfo.ShellcodeFlags;

        for (DWORD val = 1; val <= HEAP_SPRAY_NR_PAGES; val++)
        {
            DWORD checkedPage = ((val << 24) | (val << 16) | (val << 8) | val) & PAGE_MASK;

            ExtraInfo->DpiHeapSpray.HeapPages[val - 1].Mapped =
                CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped;
            ExtraInfo->DpiHeapSpray.HeapPages[val - 1].Detected =
                CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected;
            ExtraInfo->DpiHeapSpray.HeapPages[val - 1].HeapValCount =
                CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount;
            ExtraInfo->DpiHeapSpray.HeapPages[val - 1].Offset =
                CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].Offset;
            ExtraInfo->DpiHeapSpray.HeapPages[val - 1].Executable =
                CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].Executable;

            if (CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected)
            {
                detectedPage = checkedPage;
            }

            // Use >= so that we are sure that we will get at least one page even if there are no heap values.
            if (CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount >= maxNumberOfHeapVals &&
                CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped)
            {
                maxNumberOfHeapVals = (WORD)CollectedExtraInfo->DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount;
                maxPageHeapVals = checkedPage;
            }
        }

        // At this point we might not have any detected page, but only pages exceeding the max heap values heuristic,
        // so don't bother to complete it if not needed.
        if (0 != detectedPage)
        {
            IntVirtMemRead(detectedPage, PAGE_SIZE, VictimProcess->Cr3, ExtraInfo->DpiHeapSpray.DetectedPage, NULL);
        }

        IntVirtMemRead(maxPageHeapVals,
                       PAGE_SIZE,
                       VictimProcess->Cr3,
                       ExtraInfo->DpiHeapSpray.MaxHeapValPageContent,
                       NULL);
    }
    else if (PcType == INT_PC_VIOLATION_DPI_TOKEN_PRIVS)
    {
        ExtraInfo->DpiTokenPrivs.OldEnabled = CollectedExtraInfo->DpiTokenPrivsExtraInfo.OldEnabled;
        ExtraInfo->DpiTokenPrivs.OldPresent = CollectedExtraInfo->DpiTokenPrivsExtraInfo.OldPresent;
        ExtraInfo->DpiTokenPrivs.NewEnabled = CollectedExtraInfo->DpiTokenPrivsExtraInfo.NewEnabled;
        ExtraInfo->DpiTokenPrivs.NewPresent = CollectedExtraInfo->DpiTokenPrivsExtraInfo.NewPresent;
    }
    else if (PcType == INT_PC_VIOLATION_DPI_THREAD_START)
    {
        ExtraInfo->DpiThreadStart.ShellcodeFlags = CollectedExtraInfo->DpiThreadStartExtraInfo.ShellcodeFlags;
        ExtraInfo->DpiThreadStart.StartAddress = CollectedExtraInfo->DpiThreadStartExtraInfo.StartAddress;

        IntVirtMemRead(CollectedExtraInfo->DpiThreadStartExtraInfo.StartAddress & PAGE_MASK,
                       PAGE_SIZE,
                       VictimProcess->Cr3,
                       ExtraInfo->DpiThreadStart.StartPage,
                       NULL);
    }
    else if (PcType == INT_PC_VIOLATION_DPI_SEC_DESC ||
             PcType == INT_PC_VIOLATION_DPI_ACL_EDIT)
    {
         if (PcType == INT_PC_VIOLATION_DPI_SEC_DESC)
         {
             IntAlertFillWinProcess(IntWinProcFindObjectByEprocess(
                 CollectedExtraInfo->DpiSecDescAclExtraInfo.SecDescStolenFromEproc),
                 &ExtraInfo->DpiSecDescAcl.SecDescStolenFrom);
         
             ExtraInfo->DpiSecDescAcl.NewPointerValue = CollectedExtraInfo->DpiSecDescAclExtraInfo.NewPtrValue;
             ExtraInfo->DpiSecDescAcl.OldPointerValue = CollectedExtraInfo->DpiSecDescAclExtraInfo.OldPtrValue;
         }
         
         COPY_ACL_TO_INTRO_ACL(CollectedExtraInfo->DpiSecDescAclExtraInfo.NewSacl,
             ExtraInfo->DpiSecDescAcl.NewSacl);
         
         COPY_ACL_TO_INTRO_ACL(CollectedExtraInfo->DpiSecDescAclExtraInfo.NewDacl,
             ExtraInfo->DpiSecDescAcl.NewDacl);
         
         COPY_ACL_TO_INTRO_ACL(CollectedExtraInfo->DpiSecDescAclExtraInfo.OldSacl,
             ExtraInfo->DpiSecDescAcl.OldSacl);
         
         COPY_ACL_TO_INTRO_ACL(CollectedExtraInfo->DpiSecDescAclExtraInfo.OldDacl,
             ExtraInfo->DpiSecDescAcl.OldDacl);
    }
    else
    {
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    return INT_STATUS_SUCCESS;
}
