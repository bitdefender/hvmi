/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       exceptions_user.c
/// @ingroup    group_exceptions
/// @brief      User mode exceptions
///


#include "exceptions.h"
#include "guests.h"
#include "winpe.h"
#include "winprocesshp.h"
#include "winstack.h"
#include "winuser_checks.h"


extern char gExcLogLine[2 * ONE_KILOBYTE];


static char *
IntExceptUserGetPcTypeString(
    _In_ INTRO_PC_VIOLATION_TYPE Type
    )
///
/// @brief Returns a string that contains the descriptions of the porovided process creation violation type.
///
/// @param[in]  Type        The type of the violation.
///
/// @retval     The description of the violation type.
///
{
    switch(Type)
    {
        case INT_PC_VIOLATION_NORMAL_PROCESS_CREATION:
            return "Normal";

        case INT_PC_VIOLATION_DPI_DEBUG_FLAG:
            return "Debug";

        case INT_PC_VIOLATION_DPI_PIVOTED_STACK:
            return "Pivoted Stack";

        case INT_PC_VIOLATION_DPI_STOLEN_TOKEN:
            return "Stolen token";

        case INT_PC_VIOLATION_DPI_HEAP_SPRAY:
            return "Heap spray";

        case INT_PC_VIOLATION_DPI_TOKEN_PRIVS:
            return "Token Privs";

        case INT_PC_VIOLATION_DPI_THREAD_START:
            return "Thread Start";

        case INT_PC_VIOLATION_DPI_SEC_DESC:
            return "Security Descriptor";

        case INT_PC_VIOLATION_DPI_ACL_EDIT:
            return "ACL Edit";

        default:
            return "<Unknown>";
    }
}


int
IntExceptPrintLixTaskInfo(
    _In_opt_ const LIX_TASK_OBJECT *Task,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    )
///
/// @brief Print the information about the provided #LIX_TASK_OBJECT.
///
/// @param[in]  Task            The task object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
/// @param[in]  NameAlignment   The alignment of the chars in the buffer.
///
/// @retval     The number of written chars.
///
{
    int ret, total = 0;

    if (NULL == Task)
    {
        return total;
    }

    if (NameAlignment)
    {
        ret = snprintf(Line, MaxLength, "%s(%-*s", Header, NameAlignment, Task->ProcName);
    }
    else
    {
        ret = snprintf(Line, MaxLength, "%s(%s", Header, Task->ProcName);
    }

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, " '%s' [0x%08x], %016llx, %016llx, %016llx, %d/%d",
                   Task->Comm, Task->CommHash, Task->Gva, Task->Cr3, Task->MmGva, Task->Pid, Task->Tgid);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    if (Task->CmdLine)
    {
        ret = snprintf(Line, MaxLength, ", CLI:`%s`", Task->CmdLine);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    return total;
}


static void
IntExceptUserLogLinuxInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a violation (Linux guest).
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    DWORD procNameAlignment;
    char *l;
    int ret, rem;

    // This cannot be NULL! Everything must happen inside a process in user-mode
    if (NULL == Originator->LixProc)
    {
        ERROR("[ERROR] Originator process is NULL!\n");
        return;
    }

    procNameAlignment = 0;
    if (Victim->Object.LixProc)
    {
        procNameAlignment = (DWORD)MIN(MAX_PATH,
                                       MAX(Victim->Object.LixProc->ProcNameLength,
                                           Originator->LixProc->ProcNameLength));
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if ((Victim->ZoneType == exceptionZoneProcess) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone))
    {
        ret = IntExceptPrintLixTaskInfo(Originator->LixProc, "Originator-> Process: ", l, rem, procNameAlignment);
        rem -= ret;
        l += ret;

        if (Victim->ZoneType == exceptionZoneProcess)
        {
            ret = snprintf(l, rem, ", VA: %016llx", Originator->SourceVA);
        }
        else
        {
            ret = snprintf(l, rem, ", RIP: %016llx", Originator->Rip);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintLixTaskInfo(IntLixTaskFindByGva(Originator->LixProc->Parent), ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->ZoneType == exceptionZonePc)
    {
        ret = IntExceptPrintLixTaskInfo(Originator->LixProc, "Originator-> Process: ", l, rem, procNameAlignment);
        rem -= ret;
        l += ret;

        ret = snprintf(l, rem, ", Type: %s (0x%08x)", IntExceptUserGetPcTypeString(Originator->PcType),
                       Originator->PcType);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintLixTaskInfo(IntLixTaskFindByGva(Originator->LixProc->Parent), ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }
    else if ((Victim->Object.Type == introObjectTypeVdso) ||
             (Victim->Object.Type == introObjectTypeVsyscall))
    {
        ret = IntExceptPrintLixTaskInfo(Originator->LixProc, "Originator-> Process: ", l, rem, procNameAlignment);
        rem -= ret;
        l += ret;

        ret = snprintf(l, rem, ", RIP: %016llx", Originator->Rip);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintLixTaskInfo(IntLixTaskFindByGva(Originator->LixProc->Parent),
                                        ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if ((Victim->ZoneType == exceptionZoneProcess) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone))
    {
        ret = IntExceptPrintLixTaskInfo(Victim->Object.LixProc, "Victim    -> Process: ", l, rem, procNameAlignment);
        rem -= ret;
        l += ret;

        if (Victim->ZoneType == exceptionZoneProcess)
        {
            ret = snprintf(l, rem, ", InjInfo: (%u, %016llx)",
                           Victim->Injection.Length, Victim->Injection.Gva);
        }
        else
        {
            ret = snprintf(l, rem, ", ExecInfo: (%016llx, %016llx), Stack: (0x%016llx, 0x%16llx), RSP = 0x%016llx",
                           Victim->Ept.Gva, Victim->Ept.Gpa, Victim->ExecInfo.StackBase, Victim->ExecInfo.StackLimit,
                           Victim->ExecInfo.Rsp);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintLixTaskInfo(IntLixTaskFindByGva(Victim->Object.LixProc->Parent),
                                        ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }
    if (Victim->ZoneType == exceptionZonePc)
    {
        ret = IntExceptPrintLixTaskInfo(Victim->Object.LixProc, "Victim    -> Process: ", l, rem, procNameAlignment);
        rem -= ret;
        l += ret;

        ret = IntExceptPrintLixTaskInfo(IntLixTaskFindByGva(Victim->Object.LixProc->Parent), ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }
    else if ((Victim->Object.Type == introObjectTypeVdso) ||
             (Victim->Object.Type == introObjectTypeVsyscall))
    {
        const char *libName = (Victim->Object.Type == introObjectTypeVdso) ? "[vdso]" : "[vsyscall]";

        ret = IntExceptPrintLixTaskInfo(Victim->Object.LixProc, "Victim    -> Process: ", l, rem, procNameAlignment);
        rem -= ret;
        l += ret;

        ret = snprintf(l, rem, ", Address: (%0llx, %0llx), Lib: %s, WriteInfo: (%u, %016llx -> %016llx)",
                       Victim->Ept.Gva, Victim->Ept.Gpa,
                       libName, Victim->WriteInfo.AccessSize,
                       Victim->WriteInfo.OldValue[0],
                       Victim->WriteInfo.NewValue[0]);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);
    }

    if (Action == introGuestNotAllowed)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        ret = snprintf(l, rem, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^%sMALWARE (user-mode) ",
                       (Victim->Object.LixProc && Victim->Object.LixProc->Protection.Mask & PROC_OPT_BETA) ?
                       " (B) " : " ");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        switch (Reason)
        {
        case introReasonSignatureNotMatched:
            ret = snprintf(l, rem, "(no sig)");
            break;
        case introReasonNoException:
            ret = snprintf(l, rem, "(no exc)");
            break;
        case introReasonExtraChecksFailed:
            ret = snprintf(l, rem, "(extra)");
            break;
        case introReasonInternalError:
            ret = snprintf(l, rem, "(error)");
            break;
        case introReasonValueNotMatched:
            ret = snprintf(l, rem, "(value)");
            break;
        case introReasonValueCodeNotMatched:
            ret = snprintf(l, rem, "(value code)");
            break;
        case introReasonIdtNotMatched:
            ret = snprintf(l, rem, "(idt)");
            break;
        case introReasonVersionOsNotMatched:
            ret = snprintf(l, rem, "(version os)");
            break;
        case introReasonVersionIntroNotMatched:
            ret = snprintf(l, rem, "(version intro)");
            break;
        case introReasonExportNotMatched:
            ret = snprintf(l, rem, "(export)");
            break;
        case introReasonProcessCreationNotMatched:
            ret = snprintf(l, rem, "(process creation)");
            break;
        case introReasonUnknown:
            ret = snprintf(l, rem, "(unknown)");
            break;
        default:
            ret = snprintf(l, rem, "(%d)", Reason);
            break;
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n\n", gExcLogLine);
    }
}


int
IntExceptPrintWinProcInfo(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    )
///
/// @brief Print the data from the provided #WIN_PROCESS_OBJECT.
///
/// @param[in]  Process         The process object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
/// @param[in]  NameAlignment   The alignment of the chars in the buffer.
///
/// @retval     The number of written chars.
///
{
    int ret, total = 0;

    if (NULL == Process)
    {
        return total;
    }

    if (NameAlignment)
    {
        ret = snprintf(Line, MaxLength, "%s(%-*s", Header, NameAlignment, Process->Name);
    }
    else
    {
        ret = snprintf(Line, MaxLength, "%s(%s", Header, Process->Name);
    }

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, " [0x%08x], %0*llx, %0*llx, %u, F%x",
                   Process->NameHash, gGuest.WordSize * 2, Process->EprocessAddress,
                   gGuest.WordSize * 2, Process->Cr3, Process->Pid, Process->Flags);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    if (Process->Wow64Process)
    {
        ret = snprintf(Line, MaxLength, ", WOW64");

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    if (Process->SystemProcess)
    {
        ret = snprintf(Line, MaxLength, ", SYS");

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    if (Process->Peb64Address)
    {
        ret = snprintf(Line, MaxLength, ", PEB64: %0*llx", gGuest.WordSize * 2, Process->Peb64Address);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    if (Process->Peb32Address)
    {
        ret = snprintf(Line, MaxLength, ", PEB32: %0*llx", gGuest.WordSize * 2, Process->Peb32Address);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    if (Process->CommandLine)
    {
        ret = snprintf(Line, MaxLength, ", CLI:`%s`", Process->CommandLine);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }
    return total;
}


int
IntExceptPrintWinModInfo(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    )
///
/// @brief Print the data from the provided #WIN_PROCESS_MODULE.
///
/// @param[in]  Module          The module object.
/// @param[in]  Header          The header of the output buffer.
/// @param[in]  Line            The output buffer.
/// @param[in]  MaxLength       The maximum number chars that can be written.
/// @param[in]  NameAlignment   The alignment of the chars in the buffer.
///
/// @retval     The number of written chars.
///
{
    int ret, total = 0;
    WCHAR *wName;
    DWORD nameHash;
    char name[MAX_PATH];

    if (NULL == Module)
    {
        return snprintf(Line, MaxLength, "%s(%s)", Header, EXCEPTION_NO_NAME);
    }

    if (Module->Path)
    {
        wName = Module->Path->Path;
        nameHash = Module->Path->NameHash;
    }
    else
    {
        wName = NULL;
        nameHash = INITIAL_CRC_VALUE;
    }

    if (wName)
    {
        utf16toutf8(name, wName, sizeof(name));
    }
    else
    {
        memcpy(name, EXCEPTION_NO_NAME, sizeof(EXCEPTION_NO_NAME));
    }

    if (NameAlignment)
    {
        ret = snprintf(Line, MaxLength, "%s(%-*s", Header, NameAlignment, name);
    }
    else
    {
        ret = snprintf(Line, MaxLength, "%s(%s", Header, name);
    }

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    ret = snprintf(Line, MaxLength, " [0x%08x], %0*llx, F%x",
                   nameHash, gGuest.WordSize * 2, Module->VirtualBase, Module->Flags);

    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    if (Module->Cache && Module->Cache->Info.TimeDateStamp)
    {
        ret = snprintf(Line, MaxLength, ", VerInfo: %x:%x",
                       Module->Cache->Info.TimeDateStamp, Module->Cache->Info.SizeOfImage);

        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    if (Module->Cache && (Module->Cache->Info.IatRva || Module->Cache->Info.IatSize))
    {
        ret = snprintf(Line, MaxLength, ", IAT: %x:%x",
                       Module->Cache->Info.IatRva, Module->Cache->Info.IatSize);
        if (ret < 0 || ret >= MaxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
        }
        else
        {
            Line += ret;
            total += ret;
            MaxLength -= ret;
        }
    }

    ret = snprintf(Line, MaxLength, ")");
    if (ret < 0 || ret >= MaxLength)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, MaxLength);
    }
    else
    {
        Line += ret;
        total += ret;
        MaxLength -= ret;
    }

    return total;
}


static void
IntExceptUserLogWindowsInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a violation (windows guest).
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    DWORD modNameAlignment;
    char *l;
    int ret, rem;

    // This cannot be NULL! Everything must happen inside a process in user-mode
    if (NULL == Originator->WinProc)
    {
        ERROR("[ERROR] Originator process is NULL!\n");
        return;
    }

    // We will log only the first double agent alert, afterwards we'll only check exceptions
    if ((Victim->ZoneFlags & ZONE_MODULE_LOAD) != 0 &&
        Originator->WinLib->DoubleAgentAlertSent)
    {
        return;
    }

    modNameAlignment = 0;
    if (Victim->Object.Type == introObjectTypeUmModule)
    {
        if (Victim->Object.Library.WinMod && Originator->WinLib)
        {
            modNameAlignment = MIN(MAX_PATH,
                                   MAX(Victim->Object.Library.WinMod->Path->PathSize,
                                       Originator->WinLib->Path->PathSize) >> 1);
        }
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if ((Victim->ZoneType == exceptionZoneProcess) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone) ||
        (Victim->Object.Type == introObjectTypeSudExec))
    {
        WIN_PROCESS_OBJECT *pParent = IntWinProcFindObjectByEprocess(Originator->WinProc->ParentEprocess);

        ret = IntExceptPrintWinProcInfo(Originator->WinProc, "Originator-> Process: ", l, rem, 14);
        rem -= ret;
        l += ret;

        if (Victim->ZoneType == exceptionZoneProcess)
        {
            ret = snprintf(l, rem, ", VA: %0*llx", gGuest.WordSize * 2, Originator->SourceVA);
        }
        else
        {
            ret = snprintf(l, rem, ", RIP: %0*llx", gGuest.WordSize * 2, Originator->Rip);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintWinProcInfo(pParent, ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);

        if ((Victim->Object.Type == introObjectTypeUmGenericNxZone ||
            Victim->Object.Type == introObjectTypeSudExec) &&
            Originator->Return.Library &&
            Originator->Return.Rip != Originator->Rip)
        {
            l = gExcLogLine;
            rem = sizeof(gExcLogLine);

            ret = IntExceptPrintWinModInfo(Originator->Return.WinLib,
                                           "Return    -> Module: ",
                                           l,
                                           rem,
                                           modNameAlignment);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            ret = snprintf(l, rem, ", RIP %0*llx", gGuest.WordSize * 2, Originator->Return.Rip);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            LOG("%s\n", gExcLogLine);
        }
    }
    else if (Victim->ZoneType == exceptionZonePc)
    {
        WIN_PROCESS_OBJECT *pParent = IntWinProcFindObjectByEprocess(Originator->WinProc->ParentEprocess);

        ret = IntExceptPrintWinProcInfo(Originator->WinProc, "Originator-> Process: ", l, rem, 14);
        rem -= ret;
        l += ret;

        ret = snprintf(l, rem, ", Type: %s (0x%08x)", IntExceptUserGetPcTypeString(Originator->PcType),
                       Originator->PcType);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintWinProcInfo(pParent, ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeUmModule)
    {
        CHAR instr[ND_MIN_BUF_SIZE];
        NDSTATUS ndstatus;

        ndstatus = NdToText(Originator->Instruction, Originator->Rip, sizeof(instr), instr);
        if (!ND_SUCCESS(ndstatus))
        {
            memcpy(instr, EXPORT_NAME_UNKNOWN, sizeof(EXPORT_NAME_UNKNOWN));
        }

        ret = IntExceptPrintWinModInfo(Originator->WinLib, "Originator-> Module: ", l, rem, modNameAlignment);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, ", RIP %0*llx", gGuest.WordSize * 2, Originator->Rip);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintWinProcInfo(Originator->WinProc, ", Process: ", l, rem, 0);
        rem -= ret;
        l += ret;

        ret = snprintf(l, rem, ", Instr: %s", instr);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n", gExcLogLine);

        if (Originator->Return.Library && Originator->Return.Rip != Originator->Rip)
        {
            l = gExcLogLine;
            rem = sizeof(gExcLogLine);

            ret = IntExceptPrintWinModInfo(Originator->Return.WinLib,
                                           "Return    -> Module: ",
                                           l,
                                           rem,
                                           modNameAlignment);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            ret = snprintf(l, rem, ", RIP %0*llx", gGuest.WordSize * 2, Originator->Return.Rip);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            LOG("%s\n", gExcLogLine);
        }
    }

    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if ((Victim->ZoneType == exceptionZoneProcess) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone) ||
        (Victim->Object.Type == introObjectTypeSudExec))
    {
        WIN_PROCESS_OBJECT *pParent = IntWinProcFindObjectByEprocess(Victim->Object.WinProc->ParentEprocess);

        ret = IntExceptPrintWinProcInfo(Victim->Object.WinProc, "Victim    -> Process: ", l, rem, 14);
        rem -= ret;
        l += ret;

        if (Victim->ZoneType == exceptionZoneProcess)
        {
            ret = snprintf(l, rem, ", InjInfo: (%u, %0*llx), Init: (%u, %u)",
                           Victim->Injection.Length, gGuest.WordSize * 2,
                           Victim->Injection.Gva, Victim->Object.WinProc->StartInitializing,
                           Victim->Object.WinProc->Initialized);
        }
        else if (Victim->Object.Type == introObjectTypeUmGenericNxZone)
        {

            ret = snprintf(l, rem, ", ExecInfo: (0x%0*llx, 0x%0*llx), Stack: (0x%0*llx, 0x%0*llx), SP = 0x%0*llx",
                           gGuest.WordSize * 2, Victim->Ept.Gva, gGuest.WordSize * 2, Victim->Ept.Gpa,
                           gGuest.WordSize * 2, Victim->ExecInfo.StackBase, gGuest.WordSize * 2,
                           Victim->ExecInfo.StackLimit, gGuest.WordSize * 2, Victim->ExecInfo.Rsp);
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = IntExceptPrintWinProcInfo(pParent, ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);

        if (Victim->Object.Vad)
        {
            PWCHAR path = EXCEPTION_NO_WNAME;

            if (Victim->Object.Vad->Path)
            {
                path = Victim->Object.Vad->Path->Path;
            }
            else if (Victim->Object.Vad->IsStack)
            {
                path = u"<stack>";
            }

            LOG("Victim    -> VAD: [%llx - %llx], Prot: %x, VadProt: %x, Type: %d, Name: %s\n",
                Victim->Object.Vad->StartPage, Victim->Object.Vad->EndPage, Victim->Object.Vad->Protection,
                Victim->Object.Vad->VadProtection, Victim->Object.Vad->VadType, utf16_for_log(path));
        }

        if (Victim->Object.Library.WinMod)
        {
            QWORD startGva, exportGva;
            WINUM_CACHE_EXPORT *pExport = NULL;

            l = gExcLogLine;
            rem = sizeof(gExcLogLine);

            ret = IntExceptPrintWinModInfo(Victim->Object.Library.WinMod, "Victim    -> Module: ", l, rem, 0);
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            if (Victim->ZoneType == exceptionZoneProcess)
            {
                startGva = exportGva = Victim->Injection.Gva;
            }
            else
            {
                startGva = exportGva = Victim->Ept.Gva;
            }

            if (Victim->Object.Library.Export == NULL)
            {
                pExport = IntWinUmCacheGetExportFromRange(Victim->Object.Library.WinMod, startGva, 0x20);
            }
            else
            {
                pExport = Victim->Object.Library.Export;
            }

            if (pExport != NULL)
            {
                ret = snprintf(l, rem, ", Exports (%u) : [", pExport->NumberOfOffsets);

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }

                for (DWORD export = 0; export < pExport->NumberOfOffsets; export++)
                {
                    if (export == pExport->NumberOfOffsets - 1)
                    {
                        ret = snprintf(l, rem, "'%s'", pExport->Names[export]);
                    }
                    else
                    {
                        ret = snprintf(l, rem, "'%s',", pExport->Names[export]);
                    }

                    if (ret < 0 || ret >= rem)
                    {
                        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    }
                    else
                    {
                        rem -= ret;
                        l += ret;
                    }
                }

                ret = snprintf(l, rem, "], Delta: +%02x, ",
                               (DWORD)(Victim->Ept.Gva - Victim->Object.Library.WinMod->VirtualBase - pExport->Rva));

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }
            }

            LOG("%s\n", gExcLogLine);
        }
    }
    else if (Victim->ZoneType == exceptionZonePc)
    {
        WIN_PROCESS_OBJECT *pParent = IntWinProcFindObjectByEprocess(Victim->Object.WinProc->ParentEprocess);

        ret = IntExceptPrintWinProcInfo(Victim->Object.WinProc, "Victim    -> Process: ", l, rem, 14);
        rem -= ret;
        l += ret;

        ret = IntExceptPrintWinProcInfo(pParent, ", Parent: ", l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }
    else if (Victim->Object.Type == introObjectTypeUmModule)
    {
        WINUM_CACHE_EXPORT *pExport = NULL;

        ret = IntExceptPrintWinModInfo(Victim->Object.Library.WinMod,
                                       "Victim    -> Module: ",
                                       l,
                                       rem,
                                       modNameAlignment);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }


        if (Victim->Object.Library.Export == NULL)
        {
            pExport = IntWinUmCacheGetExportFromRange(Victim->Object.Library.WinMod, Victim->Ept.Gva, 0x20);
        }
        else
        {
            pExport = Victim->Object.Library.Export;
        }

        if (pExport != NULL)
        {
            ret = snprintf(l, rem, ", Exports (%u) : [", pExport->NumberOfOffsets);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }

            for (DWORD export = 0; export < pExport->NumberOfOffsets; export++)
            {
                if (export == pExport->NumberOfOffsets - 1)
                {
                    ret = snprintf(l, rem, "'%s'", pExport->Names[export]);
                }
                else
                {
                    ret = snprintf(l, rem, "'%s',", pExport->Names[export]);
                }

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                }
                else
                {
                    rem -= ret;
                    l += ret;
                }

            }

            ret = snprintf(l, rem, "], Delta: +%02x, ",
                           (DWORD)(Victim->Ept.Gva - Victim->Object.Library.WinMod->VirtualBase - pExport->Rva));

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        ret = snprintf(l, rem, ", Address: (%0*llx, %0*llx)",
                       gGuest.WordSize * 2, Victim->Ept.Gva,
                       gGuest.WordSize * 2, Victim->Ept.Gpa);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, ", WriteInfo: (%u, %016llx -> %016llx)",
                       Victim->WriteInfo.AccessSize,
                       Victim->WriteInfo.OldValue[0],
                       Victim->WriteInfo.NewValue[0]);

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        if (Victim->ZoneFlags)
        {
            ret = snprintf(l, rem, ", Flags:%s%s%s%s%s (0x%llx)",
                           (Victim->ZoneFlags & ZONE_LIB_IMPORTS) ? " IMPORTS" : "",
                           (Victim->ZoneFlags & ZONE_LIB_EXPORTS) ? " EXPORTS" : "",
                           (Victim->ZoneFlags & ZONE_LIB_CODE) ? " CODE" : "",
                           (Victim->ZoneFlags & ZONE_LIB_DATA) ? " DATA" : "",
                           (Victim->ZoneFlags & ZONE_LIB_RESOURCES) ? " RSRC" : "",
                           (unsigned long long)Victim->ZoneFlags);

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            }
            else
            {
                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", gExcLogLine);
    }

    if (Action == introGuestNotAllowed)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        ret = snprintf(l, rem, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^%sMALWARE (user-mode) ",
                       (Victim->Object.WinProc->BetaDetections) ? " (B) " : " ");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        switch (Reason)
        {
        case introReasonSignatureNotMatched:
            ret = snprintf(l, rem, "(no sig)");
            break;
        case introReasonNoException:
            ret = snprintf(l, rem, "(no exc)");
            break;
        case introReasonExtraChecksFailed:
            ret = snprintf(l, rem, "(extra)");
            break;
        case introReasonInternalError:
            ret = snprintf(l, rem, "(error)");
            break;
        case introReasonValueNotMatched:
            ret = snprintf(l, rem, "(value)");
            break;
        case introReasonValueCodeNotMatched:
            ret = snprintf(l, rem, "(value code)");
            break;
        case introReasonExportNotMatched:
            ret = snprintf(l, rem, "(export)");
            break;
        case introReasonIdtNotMatched:
            ret = snprintf(l, rem, "(idt)");
            break;
        case introReasonVersionOsNotMatched:
            ret = snprintf(l, rem, "(version os)");
            break;
        case introReasonVersionIntroNotMatched:
            ret = snprintf(l, rem, "(version intro)");
            break;
        case introReasonProcessCreationNotMatched:
            ret = snprintf(l, rem, "(process creation)");
            break;
        case introReasonUnknown:
            ret = snprintf(l, rem, "(unknown)");
            break;
        default:
            ret = snprintf(l, rem, "(%d)", Reason);
            break;
        }

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        ret = snprintf(l, rem, " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
        }
        else
        {
            rem -= ret;
            l += ret;
        }

        LOG("%s\n\n", gExcLogLine);
    }

    if (Victim->Object.Type == introObjectTypeProcessCreationDpi)
    {
        if (Originator->PcType == INT_PC_VIOLATION_DPI_DEBUG_FLAG)
        {
            WIN_PROCESS_OBJECT *pDebugged = Victim->Object.Process;
            WIN_PROCESS_OBJECT *pDebugger;

            pDebugger = IntWinProcFindObjectByEprocess(pDebugged->CreationInfo.DebuggerEprocess);
            if (NULL == pDebugger)
            {
                LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) is debugged by process %s!\n",
                    pDebugged->Name, pDebugged->NameHash, pDebugged->Pid, pDebugged->EprocessAddress, "<unknown>");
            }
            else
            {
                LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) is debugged by process %s [0x%08x] (%d, 0x%016llx)!\n",
                    pDebugged->Name, pDebugged->NameHash, pDebugged->Pid, pDebugged->EprocessAddress,
                    pDebugger->Name, pDebugger->NameHash, pDebugger->Pid, pDebugger->EprocessAddress);
            }
        }
        else if (Originator->PcType == INT_PC_VIOLATION_DPI_PIVOTED_STACK)
        {
            WIN_PROCESS_OBJECT *pParent = Victim->Object.Process;
            WIN_PROCESS_OBJECT *pStarted = Originator->Process;

            LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) attempted to start process %s [0x%08x] "
                "(%d, 0x%016llx) with a pivoted stack!\n",
                pParent->Name, pParent->NameHash, pParent->Pid, pParent->EprocessAddress,
                pStarted->Name, pStarted->NameHash, pStarted->Pid, pStarted->EprocessAddress);

            LOG("[DPI] Current stack 0x%016llx [base 0x%016llx, limit 0x%016llx], wow64 "
                "stack 0x%016llx [base 0x%016llx, limit 0x%016llx]\n",
                pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.CurrentStack,
                pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.StackBase,
                pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.StackLimit,
                pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.CurrentWow64Stack,
                pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.Wow64StackBase,
                pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.Wow64StackLimit);

            if (gGuest.Guest64)
            {
                KTRAP_FRAME64 *trapFrame = NULL;
                INTSTATUS status;

                status = IntVirtMemMap(pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.TrapFrameAddress,
                                       sizeof(*trapFrame),
                                       gGuest.Mm.SystemCr3,
                                       0,
                                       &trapFrame);

                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n",
                          pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.TrapFrameAddress,
                          status);

                    goto _skip_trap_frame;
                }

                IntDumpWinTrapFrame64(trapFrame);

                IntVirtMemUnmap(&trapFrame);
            }
            else
            {
                KTRAP_FRAME32 *trapFrame = NULL;
                INTSTATUS status;

                status = IntVirtMemMap(pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.TrapFrameAddress,
                                       sizeof(*trapFrame),
                                       gGuest.Mm.SystemCr3,
                                       0,
                                       &trapFrame);

                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n",
                          pStarted->DpiExtraInfo.DpiPivotedStackExtraInfo.TrapFrameAddress,
                          status);

                    goto _skip_trap_frame;
                }

                IntDumpWinTrapFrame32(trapFrame);

                IntVirtMemUnmap(&trapFrame);
            }

_skip_trap_frame:
            ;
        }
        else if (Originator->PcType == INT_PC_VIOLATION_DPI_STOLEN_TOKEN)
        {
            WIN_PROCESS_OBJECT *pOriginator = Originator->Process;
            WIN_PROCESS_OBJECT *pStolenFrom =
                IntWinProcFindObjectByEprocess(pOriginator->DpiExtraInfo.DpiStolenTokenExtraInfo.StolenFromEprocess);

            LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) started with "
                "a stolen token from %s [0x%08x] (%d, 0x%016llx)!\n",
                pOriginator->Name, pOriginator->NameHash, pOriginator->Pid, pOriginator->EprocessAddress,
                pStolenFrom->Name, pStolenFrom->NameHash, pStolenFrom->Pid, pStolenFrom->EprocessAddress);
        }
        else if (Originator->PcType == INT_PC_VIOLATION_DPI_HEAP_SPRAY)
        {
            WIN_PROCESS_OBJECT *pHeapSprayed = Victim->Object.Process;
            WIN_PROCESS_OBJECT *pOriginator = Originator->Process;
            WORD maxNumberOfHeapVals = 0;
            DWORD detectedPage = 0, maxPageHeapVals = 0;

            LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) started from %s "
                "[0x%08x] (%d, 0x%016llx) after it has been heap sprayed! (shell code flags: 0x%016llx)\n",
                pOriginator->Name,
                pOriginator->NameHash,
                pOriginator->Pid,
                pOriginator->EprocessAddress,
                pHeapSprayed->Name,
                pHeapSprayed->NameHash,
                pHeapSprayed->Pid,
                pHeapSprayed->EprocessAddress,
                pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.ShellcodeFlags);

            for (DWORD val = 1; val <= HEAP_SPRAY_NR_PAGES; val++)
            {
                DWORD checkedPage = ((val << 24) | (val << 16) | (val << 8) | val) & PAGE_MASK;

                LOG("[DPI] For page 0x%08x, %s %s %s (offset 0x%03x), number of heap values: %d\n",
                    checkedPage,
                    pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped ?
                    "was mapped" : "was not mapped",
                    pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected ?
                    "was detected" : "was not detected",
                    pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Executable ?
                    "executable" : "not executable",
                    pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Offset,
                    pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount);

                if (pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Detected)
                {
                    detectedPage = checkedPage;
                }

                // Use >= so that we are sure that we will get at least one page even if there are no heap values.
                if (pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount
                    >= maxNumberOfHeapVals &&
                    pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].Mapped)
                {
                    maxNumberOfHeapVals =
                        (WORD)pOriginator->DpiExtraInfo.DpiHeapSprayExtraInfo.HeapPages[val - 1].HeapValCount;
                    maxPageHeapVals = checkedPage;
                }
            }

            LOG("[INFO] Page detected: 0x%08x, maximum number of heap values: 0x%08x (%d)\n",
                detectedPage, maxPageHeapVals, maxNumberOfHeapVals);

            // At this point we might not have a detected page, but only pages that exceed the max heap values
            // heuristic, so don't bother to dump it if it is equal to zero.
            if (0 != detectedPage)
            {
                LOG("[INFO] Dumping page: 0x%08x...\n", detectedPage);

                IntDumpGva(detectedPage, PAGE_SIZE, pHeapSprayed->Cr3);
            }

            if (detectedPage != maxPageHeapVals)
            {
                LOG("[INFO] Dumping page: 0x%08x...\n", maxPageHeapVals);

                IntDumpGva(maxPageHeapVals, PAGE_SIZE, pHeapSprayed->Cr3);
            }
        }
        else if (Originator->PcType == INT_PC_VIOLATION_DPI_TOKEN_PRIVS)
        {
            WIN_PROCESS_OBJECT *pVictim = Victim->Object.Process;
            WIN_PROCESS_OBJECT *pOriginator = Originator->Process;

            LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) started from %s [0x%08x] (%d, 0x%016llx) "
                "after it didn't pass privileges checks!\n",
                pOriginator->Name,
                pOriginator->NameHash,
                pOriginator->Pid,
                pOriginator->EprocessAddress,
                pVictim->Name,
                pVictim->NameHash,
                pVictim->Pid,
                pVictim->EprocessAddress);

            LOG("[DPI] Privileges: Enabled: old: 0x%016llx, new: 0x%016llx, Present: old: 0x%016llx, new: 0x%016llx\n",
                pOriginator->DpiExtraInfo.DpiTokenPrivsExtraInfo.OldEnabled,
                pOriginator->DpiExtraInfo.DpiTokenPrivsExtraInfo.NewEnabled,
                pOriginator->DpiExtraInfo.DpiTokenPrivsExtraInfo.OldPresent,
                pOriginator->DpiExtraInfo.DpiTokenPrivsExtraInfo.NewPresent);
        }
        else if (Originator->PcType == INT_PC_VIOLATION_DPI_THREAD_START)
        {
            WIN_PROCESS_OBJECT *pVictim = Victim->Object.Process;
            WIN_PROCESS_OBJECT *pOriginator = Originator->Process;

            LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) started from %s "
                "[0x%08x] (%d, 0x%016llx) from a thread considered suspicious (start 0x%016llx, shellcode flags: 0x%016llx)!\n",
                pOriginator->Name,
                pOriginator->NameHash,
                pOriginator->Pid,
                pOriginator->EprocessAddress,
                pVictim->Name,
                pVictim->NameHash,
                pVictim->Pid,
                pVictim->EprocessAddress,
                pOriginator->DpiExtraInfo.DpiThreadStartExtraInfo.StartAddress,
                pOriginator->DpiExtraInfo.DpiThreadStartExtraInfo.ShellcodeFlags);

            IntDumpGva(pOriginator->DpiExtraInfo.DpiThreadStartExtraInfo.StartAddress & PAGE_MASK,
                       PAGE_SIZE,
                       pVictim->Cr3);
        }
        else if (Originator->PcType == INT_PC_VIOLATION_DPI_SEC_DESC ||
                 Originator->PcType == INT_PC_VIOLATION_DPI_ACL_EDIT)
        {
             WIN_PROCESS_OBJECT *pVictim = Victim->Object.Process;
             WIN_PROCESS_OBJECT *pOriginator = Originator->Process;
             WIN_PROCESS_OBJECT *pStolenFrom = IntWinProcFindObjectByEprocess(
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.SecDescStolenFromEproc);

             if (Originator->PcType == INT_PC_VIOLATION_DPI_SEC_DESC)
             {
                 LOG("[DPI] Process %s [0x%08x] (%d, 0x%016llx) was created by %s [0x%08x] (%d, 0x%016llx) "
                     "using an altered SD (stolen from process %s [0x%08x] (%d, 0x%016llx))\n",
                     pOriginator->Name,
                     pOriginator->NameHash,
                     pOriginator->Pid,
                     pOriginator->EprocessAddress,
                     pVictim->Name,
                     pVictim->NameHash,
                     pVictim->Pid,
                     pVictim->EprocessAddress,
                     pStolenFrom ? pStolenFrom->Name : "NULL",
                     pStolenFrom ? pStolenFrom->NameHash : 0,
                     pStolenFrom ? pStolenFrom->Pid : 0,
                     pStolenFrom ? pStolenFrom->EprocessAddress : 0);
             }
             else
             {
                 LOG("[DPI] SACL/DACL for process 0x%llx (%d / %s) have been modified\n",
                     pVictim->EprocessAddress, pVictim->Pid, pVictim->Name);
             }

             // By having a different security descriptor pointer, the contents will almost certainly be different.
             LOG("[DPI] Old SACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "New SACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "Old DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x "
                 "New DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x\n",
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl.AclSize,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl.AceCount,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.OldSacl.AclRevision,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl.AclSize,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl.AceCount,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.NewSacl.AclRevision,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl.AclSize,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl.AceCount,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.OldDacl.AclRevision,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl.AclSize,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl.AceCount,
                 pVictim->DpiExtraInfo.DpiSecDescAclExtraInfo.NewDacl.AclRevision);
        }
        else
        {
            ERROR("[ERROR] Victim has type introObjectTypeProcessCreationDpi but no known flag was given, "
                  "flags: 0x%x\n", Originator->PcType);
        }
    }
}


static __inline BOOLEAN
IntExceptUserMatchZoneFlags(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ DWORD ZoneFlags
    )
///
/// @brief Checks if the zone-flags of the current exception match the zone flags of the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  ZoneFlags       The zone-flags of the current exception.
///
/// @retval     True if the zone-flags match, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if ((ZoneFlags & EXCEPTION_FLG_READ) &&
        (Victim->ZoneFlags & ZONE_READ))
    {
        match = TRUE;
    }

    if ((ZoneFlags & EXCEPTION_FLG_EXECUTE) &&
        (Victim->ZoneFlags & ZONE_EXECUTE))
    {
        match = TRUE;
    }

    if ((ZoneFlags & EXCEPTION_FLG_WRITE) &&
        (Victim->ZoneFlags & ZONE_WRITE))
    {
        match = TRUE;
    }

    return match;
}



static __inline BOOLEAN
IntExceptUserMatchZoneType(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ UM_EXCEPTION_OBJECT ZoneType
    )
///
/// @brief Checks if the zone-type of the current exception matches the zone-type of the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  ZoneType        The zone-type of the current exception.
///
/// @retval     True if the zone-type matches, otherwise false.
///
{
    BOOLEAN match = FALSE;

    switch (ZoneType)
    {
    case umObjAny:
        match = TRUE;
        break;

    // We want to match only object_type process, not thread-context, thread-apc or instrument.
    case umObjProcess:
        if (Victim->ZoneType == exceptionZoneProcess &&
            (Victim->ZoneFlags & (ZONE_PROC_THREAD_CTX | ZONE_PROC_THREAD_APC | ZONE_PROC_INSTRUMENT)) == 0)
        {
            match = TRUE;
        }
        break;

    case umObjModule:
        if (Victim->Object.Type == introObjectTypeUmModule)
        {
            match = TRUE;
        }
        break;

    case umObjModuleImports:
        if ((Victim->Object.Type == introObjectTypeUmModule) &&
            (Victim->ZoneFlags & ZONE_LIB_IMPORTS))
        {
            match = TRUE;
        }
        break;

    case umObjNxZone:
        if (Victim->Object.Type == introObjectTypeUmGenericNxZone)
        {
            match = TRUE;
        }
        break;

    case umObjSharedUserData:
        if (Victim->Object.Type == introObjectTypeSudExec)
        {
            match = TRUE;
        }
        break;

    case umObjModuleExports:
        if ((Victim->Object.Type == introObjectTypeUmModule) &&
            (Victim->ZoneFlags & ZONE_LIB_EXPORTS))
        {
            match = TRUE;
        }
        break;

    case umObjProcessThreadContext:
        if ((Victim->ZoneType == exceptionZoneProcess) &&
            (Victim->ZoneFlags & ZONE_PROC_THREAD_CTX))
        {
            match = TRUE;
        }
        break;

    case umObjProcessApcThread:
        if ((Victim->ZoneType == exceptionZoneProcess) &&
            (Victim->ZoneFlags & ZONE_PROC_THREAD_APC))
        {
            match = TRUE;
        }
        break;

    case umObjProcessInstrumentation:
        if ((Victim->ZoneType == exceptionZoneProcess) &&
            (Victim->ZoneFlags & ZONE_PROC_INSTRUMENT))
        {
            match = TRUE;
        }
        break;

    case umObjProcessPeb32:
        if (Victim->Injection.Gva >= Victim->Object.WinProc->Peb32Address &&
            Victim->Injection.Gva < Victim->Object.WinProc->Peb32Address + WIN_UM_FIELD(Peb, 32Size))
        {
            match = TRUE;
        }
        break;

    case umObjProcessPeb64:
        if (Victim->Injection.Gva >= Victim->Object.WinProc->Peb64Address &&
            Victim->Injection.Gva < Victim->Object.WinProc->Peb64Address + WIN_UM_FIELD(Peb, 64Size))
        {
            match = TRUE;
        }
        break;

    case umObjProcessCreation:
        if (Victim->Object.Type == introObjectTypeProcessCreation &&
            Victim->ZoneType == exceptionZonePc)
        {
            match = TRUE;
        }
        break;

    case umObjProcessCreationDpi:
        if (Victim->Object.Type == introObjectTypeProcessCreationDpi &&
            Victim->ZoneType == exceptionZonePc)
        {
            match = TRUE;
        }
        break;

    case umObjModuleLoad:
        if ((Victim->ZoneType == exceptionZoneProcess) &&
            (Victim->ZoneFlags & ZONE_MODULE_LOAD))
        {
            match = TRUE;
        }
        break;

    default:
        LOG("[ERROR] This is a corruption in the update/exception. Type = %d!\n", ZoneType);
        break;
    }

    return match;
}


static __inline BOOLEAN
IntExceptUserMatchArchitecture(
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ DWORD ExceptionFlags
    )
///
/// @brief Checks if the architecture-flags of the current exception match the architecture-flags of the originator.
///
/// @param[in]  Originator      The originator object.
/// @param[in]  ExceptionFlags  The architecture-flags of the current exception.
///
/// @retval     True if the zone-flags match, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if ((ExceptionFlags & EXCEPTION_FLG_32) &&
        (ExceptionFlags & EXCEPTION_FLG_64))
    {
        match = TRUE;
    }
    else
    {
        if (gGuest.OSType == introGuestWindows)
        {
            if (ExceptionFlags & EXCEPTION_FLG_32)
            {
                // 32-bit windows OR a 32-bit process in a 64-bit system
                match = !gGuest.Guest64 || Originator->WinProc->Wow64Process;
            }
            else if (ExceptionFlags & EXCEPTION_FLG_64)
            {
                // 64-bit windows AND a 64-bit process
                match = gGuest.Guest64 && !Originator->WinProc->Wow64Process;
            }
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            // Only Linux don't check the process subsystem
            if (ExceptionFlags & EXCEPTION_FLG_32)
            {
                match = !gGuest.Guest64;
            }
            else if (ExceptionFlags & EXCEPTION_FLG_64)
            {
                match = gGuest.Guest64;
            }
        }
    }

    return match;
}



static __inline BOOLEAN
IntExceptUserMatchChild(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ DWORD ExceptionFlags
    )
///
/// @brief Checks if the victim is a child of the originator.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  ExceptionFlags  The flags of the current exception.
///
/// @retval     True if the victim is a child of the originator, otherwise false.
///
{
    BOOLEAN match = TRUE;

    if ((Victim->ZoneType == exceptionZoneProcess || Victim->ZoneType == exceptionZonePc) &&
        (ExceptionFlags & EXCEPTION_UM_FLG_CHILD_PROC))
    {
        if (gGuest.OSType == introGuestWindows)
        {
            if (Victim->Object.WinProc->ParentEprocess != Originator->WinProc->EprocessAddress)
            {
                return FALSE;
            }
        }
        else
        {
            if (Victim->Object.LixProc->ActualParent != Originator->LixProc->Gva)
            {
                return FALSE;
            }
        }
    }

    return match;
}



static __inline BOOLEAN
IntExceptUserMatchSystemProcess(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ DWORD ExceptionFlags
    )
///
/// @brief Checks if the originator is a system process; for process-creation violation this function checks if the
/// victim is a system process.
///
/// This function also checks if the victim is 'apphelp', 'one-time-injection' and 'module load'.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  ExceptionFlags  The flags of the current exception.
///
/// @retval     True if the originator/victim is a system process, otherwise false.
///
{
    if ((gGuest.OSType == introGuestWindows) && (ExceptionFlags & EXCEPTION_UM_FLG_SYS_PROC))
    {
        //
        // This exception only matches if the originator process is a system process
        //
        if (Victim->Object.Type == introObjectTypeProcessCreation)
        {
            if (!Victim->Object.WinProc->SystemProcess)
            {
                return FALSE;
            }
        }
        else
        {
            if (!Originator->WinProc->SystemProcess)
            {
                return FALSE;
            }
        }
    }

    if ((gGuest.OSType == introGuestWindows) && (ExceptionFlags & EXCEPTION_UM_FLG_LIKE_APPHELP))
    {
        if ((Victim->Object.WinProc->InjectedApphelpAddress != Victim->Injection.Gva) ||
            (Victim->Object.WinProc->InjectedAppHelpSize != Victim->Injection.Length))
        {
            return FALSE;
        }
    }

    if ((gGuest.OSType == introGuestWindows) && (ExceptionFlags & EXCEPTION_UM_FLG_ONETIME))
    {
        if (Victim->Object.Type == introObjectTypeProcessCreation)
        {
            if (Originator->WinProc->OneTimeInjectionDone)
            {
                return FALSE;
            }
            else
            {
                Originator->WinProc->OneTimeInjectionDone = TRUE;
            }
        }
        else
        {
            if (Victim->Object.WinProc->OneTimeInjectionDone)
            {
                return FALSE;
            }
            else
            {
                Victim->Object.WinProc->OneTimeInjectionDone = TRUE;
            }
        }
    }

    return TRUE;
}


static __inline BOOLEAN
IntExceptUserMatchNameGlob(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ UM_EXCEPTION_GLOB *Exception
    )
///
/// @brief Checks if the exception glob-name of the current exception matches the glob-name of the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the glob-name matches, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if (Victim->ZoneFlags & (ZONE_LIB_CODE | ZONE_LIB_EXPORTS | ZONE_LIB_IMPORTS | ZONE_LIB_DATA))
    {
        // We use WCHAR for module names
        match = glob_match_utf16(Exception->Victim.NameGlob, Victim->Object.NameWide, TRUE, TRUE);
    }
    else
    {
        match = glob_match_utf8(Exception->Victim.NameGlob, Victim->Object.Name, TRUE, TRUE);
    }

    return match;
}


static __inline BOOLEAN
IntExceptUserMatchProcessGlob(
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION_GLOB *Exception
    )
///
/// @brief Checks if the exception process glob-name of the current exception matches the process glob-name of the
/// victim.
///
/// @param[in]  Originator      The originator object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the process glob-name matches, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if (gGuest.OSType == introGuestWindows)
    {
        match = glob_match_utf8(Exception->Victim.ProcessGlob, Originator->WinProc->Name, TRUE, TRUE);
    }
    else if (Originator->LixProc->Path)
    {
        match = glob_match_utf8(Exception->Victim.ProcessGlob, Originator->LixProc->Path->Name, TRUE, TRUE);
    }

    return match;
}



static __inline BOOLEAN
IntExceptUserMatchNameHash(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ UM_EXCEPTION *Exception
    )
///
/// @brief Checks if the exception name-hash of the current exception matches the name-hash of the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the name-hash matches, otherwise false.
///
{
    return (Exception->Victim.NameHash == umExcNameAny ||
            Exception->Victim.NameHash == Victim->Object.NameHash);
}


static __inline BOOLEAN
IntExceptUserMatchProcessHash(
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    )
///
/// @brief Checks if the exception process name-hash of the current exception matches the process name-hash of the
/// victim.
///
/// @param[in]  Originator      The originator object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the process name-hash matches, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if (Exception->Victim.ProcessHash == umExcNameAny)
    {
        match = TRUE;
    }
    else
    {
        if (gGuest.OSType == introGuestWindows)
        {
            match = Exception->Victim.ProcessHash == Originator->WinProc->NameHash;
        }
        else
        {
            match = Exception->Victim.ProcessHash == Originator->LixProc->CommHash;
        }
    }

    return match;
}



static __forceinline BOOLEAN
IntExceptUserIsGlobItem(
    _In_ char Item
    )
///
/// @brief Checks if the provided char is a glob char.
///
/// @param[in]  Item    The char to be checked.
///
/// @retval     True if char is a glob item, otherwise false.
///
{
    return ((Item == '*') || (Item == '?') || (Item == ']') || (Item == '[') || (Item == '/'));
}


void
IntExceptUserLogInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a user-mode violation, dumps the code-blocks and the injection buffer, if any.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    if ((introGuestNotAllowed != Action) && (introReasonAllowedFeedback != Reason))
    {
        return;
    }

    if (Victim->Object.Type == introObjectTypeUmGenericNxZone && gVcpu->Regs.Cr3 != Victim->Object.WinProc->Cr3)
    {
        return;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        IntExceptUserLogWindowsInformation(Victim, Originator, Action, Reason);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntExceptUserLogLinuxInformation(Victim, Originator, Action, Reason);
    }

    if ((Victim->Object.Type == introObjectTypeUmModule) ||
        (Victim->Object.Type == introObjectTypeUmGenericNxZone) ||
        (Victim->Object.Type == introObjectTypeSudExec))
    {
        IntExceptDumpSignatures(Originator, Victim, FALSE, FALSE);
    }

    BOOLEAN logInjection = (Victim->ZoneType == exceptionZoneProcess);

    // Don't dump lsass reads (we don't want our log to be mimikatz)
    if (logInjection && gGuest.OSType == introGuestWindows)
    {
        if (Victim->Object.WinProc->Lsass && (Victim->ZoneFlags & ZONE_READ))
        {
            logInjection = FALSE;
        }
    }

    if (logInjection && Originator->Process)
    {
        QWORD cr3 = 0;

        if (gGuest.OSType == introGuestWindows)
        {
            cr3 = Originator->WinProc->Cr3;
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            cr3 = Originator->LixProc->Cr3;
        }

        // If we could read the whole buffer when checking for value signatures, dump that
        if (Victim->Injection.Buffer &&
            Victim->Injection.BufferSize == Victim->Injection.Length)
        {
            IntDumpBuffer(Victim->Injection.Buffer,
                          Originator->SourceVA,
                          Victim->Injection.BufferSize,
                          16,
                          sizeof(BYTE),
                          TRUE,
                          TRUE);
        }
        else if ((Victim->ZoneFlags &
            (ZONE_PROC_THREAD_CTX | ZONE_PROC_THREAD_APC | ZONE_PROC_INSTRUMENT | ZONE_MODULE_LOAD | ZONE_READ)) == 0)
        {
            IntDumpGva(Originator->SourceVA,
                       Victim->Injection.Length,
                       cr3);
        }
    }
}


INTSTATUS
IntExceptUserGetExecOriginator(
    _In_ void *Process,
    _Out_ EXCEPTION_UM_ORIGINATOR *Originator
    )
///
/// @brief This function is used to get the originator for heap execution.
///
/// @param[in]  Process          The process in which the execution occurred.
/// @param[out] Originator       The exception object.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    STACK_TRACE stack;
    STACK_ELEMENT stackElements[8];

    Originator->Process = Process;
    Originator->Library = NULL;
    Originator->Rip = gVcpu->Regs.Rip;
    Originator->Execute = TRUE;
    Originator->NameHash = INITIAL_CRC_VALUE;                           // The code is executed from the heap

    if (introGuestWindows == gGuest.OSType)
    {
        INTSTATUS status;

        memzero(&stack, sizeof(stack));
        stack.Traces = stackElements;

        status = IntWinStackTraceGetUser(&gVcpu->Regs, Process, ARRAYSIZE(stackElements), &stack);
        if (!INT_SUCCESS(status) && 0 == stack.NumberOfTraces)
        {
            WARNING("[WARNING] IntWinStackTraceGetUser failed: %08x\n", status);
        }

        if (stack.NumberOfTraces > 0)
        {
            Originator->Return.Rip = stack.Traces[0].ReturnAddress;
            Originator->Return.Library = stack.Traces[0].ReturnModule;
            Originator->Return.NameHash = ((PWIN_PROCESS_MODULE)stack.Traces[0].ReturnModule)->Path->NameHash;
            Originator->Return.NameWide = ((PWIN_PROCESS_MODULE)stack.Traces[0].ReturnModule)->Path->Name;
        }
    }

    Originator->Instruction = &gVcpu->Instruction;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntExceptUserHandleMemoryFunctions(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_opt_ WIN_PROCESS_MODULE *Module,
    _Inout_ EXCEPTION_UM_ORIGINATOR *Originator
    )
///
/// @brief This function is used to check if the write has been made using a function that write/read memory
/// (eg. memcpy, memset, etc).
///
/// We can't except a function that write/read memory because is too generic. To solve this issue, this function get the
/// stack-trace and set the first module found as a originator's return module.
///
/// @param[in]  Process          The process in which the violation occurred.
/// @param[in]  Module           The module object.
/// @param[out] Originator       The originator object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     If the function that modified the memory zone is not a function that
///                                                 write/read memory.
///
{
    INTSTATUS status;
    STACK_ELEMENT stackElements[8];
    STACK_TRACE stack;
    BOOLEAN isUcrtbase = FALSE;

    if (NULL == Module)
    {
        goto _get_stack;
    }

#define MEMORY_FUNC_SIZE 0x400

    isUcrtbase = 0 == wstrcasecmp(Module->Path->Name, u"ucrtbase.dll");

    if (Module->Path->NameHash == NAMEHASH_NTDLL)
    {
        DWORD rva = (DWORD)(Originator->Rip - Module->VirtualBase);
        BOOLEAN foundMemFunc = FALSE;

        if (NULL == Module->Cache || !Module->Cache->MemoryFuncsRead)
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }

        for (DWORD i = 0; i < ARRAYSIZE(Module->Cache->MemFuncs.FuncArray); i++)
        {
            if (0 == Module->Cache->MemFuncs.FuncArray[i])
            {
                continue;
            }

            if (rva > Module->Cache->MemFuncs.FuncArray[i] &&
                rva < Module->Cache->MemFuncs.FuncArray[i] + MEMORY_FUNC_SIZE)
            {
                foundMemFunc = TRUE;
            }
        }

        if (!foundMemFunc)
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }
    }
    // Note: here we want to match "the first N bytes", not to match the whole module
    else if (((Module->Path->NameSize < 10 || 0 != memcmp(Module->Path->Name, u"msvcr", 10)) &&
              (Module->Path->NameSize < 18 || 0 != memcmp(Module->Path->Name, u"vcruntime", 18))) &&
             !isUcrtbase)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

_get_stack:
    memzero(&stack, sizeof(stack));
    stack.Traces = stackElements;

    status = IntWinStackTraceGetUser(&gVcpu->Regs,
                                     Process,
                                     ARRAYSIZE(stackElements),
                                     &stack);
    if (!INT_SUCCESS(status) &&
        stack.NumberOfTraces == 0)
    {
        // Don't log an error if we are checking an invalid originator or if the stack is swapped out.
        // For the first case it is very possible we wouldn't find anything anyway, and for the second case,
        // we'll handle this case by injecting a #PF and retrying if needed, on returning from this function.
        // Note that, in case we found at least a trace, we would not bother with the stack swapped out
        // case, as the information gathered should be enough for the exception mechanism to work properly.
        if (Module != NULL && status != INT_STATUS_STACK_SWAPPED_OUT)
        {
            ERROR("[ERROR] IntWinStackTraceGetUser failed: %08x\n", status);
        }

        return status;
    }

    if (stack.Bits64 && !isUcrtbase && !Process->ExploitGuardEnabled)
    {
        // On 64-bit we can only trust the first return
        if (stack.Traces[0].ReturnModule == Module)
        {
            return INT_STATUS_SUCCESS;
        }

        Originator->Return.Rip = stack.Traces[0].ReturnAddress;
        Originator->Return.Library = stack.Traces[0].ReturnModule;
        Originator->Return.NameHash = ((PWIN_PROCESS_MODULE)stack.Traces[0].ReturnModule)->Path->NameHash;

        Originator->Return.NameWide = ((PWIN_PROCESS_MODULE)stack.Traces[0].ReturnModule)->Path->Name;

        return INT_STATUS_SUCCESS;
    }

    // Dirty little hack for Exploit Guard. Some hooks are set by payloadrestrictions.dll using ucrtbase!memset
    // In these cases we can see other modules on the stack, besides payloadrestrictions.dll so first we search for it
    // and if that fails, we go with the first module we found
    if (isUcrtbase && Process->ExploitGuardEnabled)
    {
        for (DWORD i = 0; i < stack.NumberOfTraces; i++)
        {
            PWIN_PROCESS_MODULE pModule = (WIN_PROCESS_MODULE *)stack.Traces[i].ReturnModule;

            if (stack.Traces[i].ReturnModule == Module)
            {
                continue;
            }

            if (wstrcasecmp(pModule->Path->Name, u"payloadrestrictions.dll"))
            {
                continue;
            }

            Originator->Return.Rip = stack.Traces[i].ReturnAddress;
            Originator->Return.Library = pModule;
            Originator->Return.NameHash = pModule->Path->NameHash;
            Originator->Return.NameWide = pModule->Path->Name;            // Module names are saved as WCHAR

            return INT_STATUS_SUCCESS;
        }
    }

    for (DWORD i = 0; i < stack.NumberOfTraces; i++)
    {
        // NOTE: Only on msvcr* it's relevant like this. On ntdll we must be able to know memcpy*, memset*, memmov*.
        if (stack.Traces[i].ReturnModule == Module)
        {
            continue;
        }

        Originator->Return.Rip = stack.Traces[i].ReturnAddress;
        Originator->Return.Library = stack.Traces[i].ReturnModule;
        Originator->Return.NameHash = ((PWIN_PROCESS_MODULE)stack.Traces[i].ReturnModule)->Path->NameHash;
        Originator->Return.NameWide = ((PWIN_PROCESS_MODULE)stack.Traces[i].ReturnModule)->Path->Name;

        break;
    }

    return INT_STATUS_SUCCESS;

#undef MEMORY_FUNC_SIZE
}


INTSTATUS
IntExceptUserGetOriginator(
    _In_ void *Process,
    _In_ BOOLEAN ModuleWrite,
    _In_ QWORD Address,
    _In_opt_ INSTRUX *Instrux,
    _Out_ EXCEPTION_UM_ORIGINATOR *Originator
    )
///
/// @brief This function is used to get the information about the user-mode originator.
///
/// @param[in]  Process         The process in which the violation occurred.
/// @param[in]  ModuleWrite     If the violation is write.
/// @param[in]  Address         The modified address.
/// @param[in]  Instrux         The instruction that caused the violation, if any.
/// @param[out] Originator      The originator object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 If the provided process is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_5 If the provided originator object is invalid.
///
{
    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Originator)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    Originator->Process = Process;
    Originator->Library = NULL;
    Originator->Execute = FALSE;

    if (ModuleWrite && gGuest.OSType == introGuestWindows)
    {
        INTSTATUS status;
        WIN_PROCESS_MODULE *pMod = IntWinUmModFindByAddress(Process, Address);

        Originator->Rip = Address;
        Originator->Instruction = Instrux;

        Originator->Library = pMod;
        if (NULL != Originator->Library)
        {
            Originator->NameHash = Originator->WinLib->Path->NameHash;
            Originator->NameWide = Originator->WinLib->Path->Name;
        }
        else
        {
            Originator->NameHash = INITIAL_CRC_VALUE;
            Originator->Name = NULL;
        }

        status = IntExceptUserHandleMemoryFunctions(Process, pMod, Originator);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntExceptUserHandleMemoryFunctions failed: %08x\n", status);

            // Propagate the INT_STATUS_STACK_SWAPPED_OUT status so that the caller would handle it
            // properly by injecting #PF on the stack and retrying the instruction if needed.
            if (status == INT_STATUS_STACK_SWAPPED_OUT)
            {
                return status;
            }
        }
    }
    else if (ModuleWrite && gGuest.OSType == introGuestLinux)
    {
        Originator->Rip = Address;
        Originator->Instruction = Instrux;

        Originator->NameHash = INITIAL_CRC_VALUE;
        Originator->Name = NULL;
    }
    else if (!ModuleWrite)
    {
        Originator->SourceVA = Address;

        if (gGuest.OSType == introGuestWindows)
        {
            Originator->NameHash = ((WIN_PROCESS_OBJECT *)Process)->NameHash;
            Originator->Name = ((WIN_PROCESS_OBJECT *)Process)->Name;            // Process names are saved as char
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            Originator->NameHash = ((LIX_TASK_OBJECT *)Process)->CommHash;
            Originator->Name = ((LIX_TASK_OBJECT *)Process)->Comm;               // Linux uses only char
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptGetVictimProcessCreation(
    _In_ void *Process,
    _In_ INTRO_OBJECT_TYPE ObjectType,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function is used to get the information about the victim for process-creation violation.
///
/// @param[in]  Process         The process in which the violation occurred.
/// @param[in]  ObjectType      The process-creation violation type.
/// @param[out] Victim          The victim object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 If the provided process is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 If the provided object-type is not #introObjectTypeProcessCreation
///                                             or #introObjectTypeProcessCreationDpi.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 If the provided victim object is invalid.
///
{
    if (Process == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (ObjectType != introObjectTypeProcessCreation && ObjectType != introObjectTypeProcessCreationDpi)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (Victim == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    Victim->Object.Type = ObjectType;
    Victim->Object.Process = Process;

    Victim->ZoneFlags = ZONE_EXECUTE;
    Victim->ZoneType = exceptionZonePc;

    if (gGuest.OSType == introGuestWindows)
    {
        WIN_PROCESS_OBJECT *pProcess = (WIN_PROCESS_OBJECT *)(Process);

        Victim->Object.BaseAddress = pProcess->Cr3;
        Victim->Object.NameHash = pProcess->NameHash;
        Victim->Object.Name = pProcess->Name;
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        LIX_TASK_OBJECT *pTask = (LIX_TASK_OBJECT *)(Process);

        Victim->Object.BaseAddress = pTask->Cr3;
        Victim->Object.NameHash = pTask->CommHash;
        Victim->Object.Name = pTask->Comm;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptGetVictimProcess(
    _In_ void *Process,
    _In_ QWORD DestinationGva,
    _In_ DWORD Length,
    _In_ QWORD ZoneFlags,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function is used to get the information about the victim process for injection violations.
///
/// @param[in]  Process             The process in which the injection occurred.
/// @param[in]  DestinationGva      The guest virtual address at which the injection violation occurred.
/// @param[in]  Length              The length (bytes) of the injection.
/// @param[in]  ZoneFlags           The flags of the memory zone at which the injection violation occurred.
/// @param[out] Victim              The victim object.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 If the provided process is invalid.
/// @retval     #INT_STATUS_INVALID_PARAMETER_5 If the provided victim object is invalid.
///
{
    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    Victim->ZoneType = exceptionZoneProcess;

    Victim->ZoneFlags = ZoneFlags;

    Victim->Injection.Gva = DestinationGva;
    Victim->Injection.Length = Length;

    Victim->Object.Process = Process;

    if (gGuest.OSType == introGuestWindows)
    {
        WIN_PROCESS_OBJECT *pProc = Process;

        Victim->Object.BaseAddress = pProc->Cr3;
        Victim->Object.NameHash = pProc->NameHash;
        Victim->Object.Name = pProc->Name;              // Process names are saved as CHAR

        if (pProc->MonitorVad)
        {
            Victim->Object.Vad = IntWinVadFindAndUpdateIfNecessary(pProc, DestinationGva, Length);
        }

        if (pProc->MonitorModules && (!pProc->MonitorVad || Victim->Object.Vad))
        {
            WIN_PROCESS_MODULE *pMod = IntWinUmModFindByAddress(pProc, DestinationGva);
            Victim->Object.Library.Module = pMod;

            if (pMod != NULL)
            {
                Victim->Object.Library.Export = IntWinUmCacheGetExportFromRange(pMod, DestinationGva, 0x20);
            }
        }
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        LIX_TASK_OBJECT *pTask = Process;

        Victim->Object.BaseAddress = pTask->Cr3;
        Victim->Object.NameHash = pTask->CommHash;
        Victim->Object.Name = pTask->Comm;            // Linux uses only CHAR
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptUserVerifyExtra(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    )
///
/// @brief This function is used as an extra step in exception mechanism that verify the initialization flags of a
/// process.
///
/// @param[in]  Victim      The victim object.
/// @param[in]  Originator  The originator object.
/// @param[in]  Exception   The current exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_CHECKS_OK     On success.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        if ((Exception->Type == umObjProcess) &&
            (Exception->Flags & EXCEPTION_FLG_INIT))
        {
            return IntWinUmCheckInitializationInjection(Victim, Originator);
        }
    }

    return INT_STATUS_EXCEPTION_CHECKS_OK;
}


INTSTATUS
IntExceptUserVerifyExtraGlobMatch(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION_GLOB *Exception
    )
///
/// @brief This function is used as an extra step in exception mechanism that verify the initialization flags of a
/// process.
///
/// @param[in]  Victim      The victim object.
/// @param[in]  Originator  The originator object.
/// @param[in]  Exception   The current exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_CHECKS_OK     On success.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        if ((Exception->Type == umObjProcess) &&
            (Exception->Flags & EXCEPTION_FLG_INIT))
        {
            return IntWinUmCheckInitializationInjection(Victim, Originator);
        }
    }

    return INT_STATUS_EXCEPTION_CHECKS_OK;
}


INTSTATUS
IntExceptUserMatchVictim(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ void *Exception,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief This function checks if the exception matches the originator and the modified zone.
///
/// The following are verified:
///     - the zone flags
///     - the zone type
///     - the modified name-hash / glob-name
///     - the process name-hash / glob-name
///     - the architecture flags
///     - the child flags
///     - the system-process flags
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Exception       The current exception object.
/// @param[in]  ExceptionType   The type of the exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_NOT_MATCHED   If any check fails.
/// @retval     #INT_STATUS_EXCEPTION_ALLOW         If all checks have passed.
/// @retval     #INT_STATUS_NOT_SUPPORTED           If ExceptionType value is invalid.
///
{
    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchZoneFlags(Victim, ((UM_EXCEPTION *)Exception)->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;
    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchZoneFlags(Victim, ((UM_EXCEPTION_GLOB *)Exception)->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchNameHash(Victim, Exception))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchNameGlob(Victim, Exception))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // Check if we are in the right process. This makes sense only for EPT violations (injections are cross-process,
    // so the ProcessHash will be forced to umExcNameAny). In cases of EPT violations, the originator process and
    // modified process are the same, so take the process name from the originator.
    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchProcessHash(Originator, Exception))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchProcessGlob(Originator, (UM_EXCEPTION_GLOB *)(Exception)))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchZoneType(Victim, ((UM_EXCEPTION *)(Exception))->Type))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchZoneType(Victim, ((UM_EXCEPTION_GLOB *)(Exception))->Type))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchArchitecture(Originator, ((UM_EXCEPTION *)(Exception))->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchArchitecture(Originator, ((UM_EXCEPTION_GLOB *)(Exception))->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchChild(Victim, Originator, ((UM_EXCEPTION *)(Exception))->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchChild(Victim, Originator, ((UM_EXCEPTION_GLOB *)(Exception))->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeUm:
        if (!IntExceptUserMatchSystemProcess(Victim, Originator, ((UM_EXCEPTION *)(Exception))->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    case exceptionTypeUmGlob:
        if (!IntExceptUserMatchSystemProcess(Victim, Originator, ((UM_EXCEPTION_GLOB *)(Exception))->Flags))
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Exception Type is %d...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // If we get here, then allow the action. Anyway, the extra checks & signatures mechanism will actually allow it
    return INT_STATUS_EXCEPTION_ALLOW;
}


INTSTATUS
IntExceptUser(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief This function iterates through exception lists and tries to find an exception that matches the originator
/// and the victim.
///
/// NOTE: If the exceptions binary is not loaded any violation is allowed.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[out] Action          The action that was taken.
/// @param[out] Reason          The reason for which Action was taken.
///
/// @retval #INT_STATUS_INVALID_PARAMETER_1     If the victim object is invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_2     If the originator object is invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_3     If the action is invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_4     If the reason is invalid.
/// @retval #INT_STATUS_EXCEPTION_ALLOW         If the violation is allowed.
/// @retval #INT_STATUS_EXCEPTION_NOT_MATCHED   If the violation is not allowed.
///
{
    INTSTATUS status;
    static BOOLEAN showNotLoadedWarning = TRUE;
    BYTE id;

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Originator)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Reason)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == gGuest.Exceptions || !gGuest.Exceptions->Loaded)
    {
        if (showNotLoadedWarning)
        {
            LOG("**************************************************\n");
            LOG("************Exceptions are not loaded*************\n");
            LOG("**************************************************\n");

            showNotLoadedWarning = FALSE;
        }

        *Action = introGuestAllowed;
        *Reason = introReasonExceptionsNotLoaded;

        return INT_STATUS_EXCEPTION_ALLOW;
    }

    *Action = introGuestNotAllowed;
    *Reason = introReasonNoException;

    status = INT_STATUS_EXCEPTION_NOT_MATCHED;

    // In some cases the Old/New values are the same - allow them by default.
    if (__unlikely(Victim->ZoneType == exceptionZoneEpt && !!(Victim->ZoneFlags & ZONE_WRITE) &&
        !memcmp(Victim->WriteInfo.OldValue, Victim->WriteInfo.NewValue,
                MIN(Victim->WriteInfo.AccessSize, sizeof(Victim->WriteInfo.NewValue)))))
    {
        *Action = introGuestAllowed;
        *Reason = introReasonSameValue;

        return INT_STATUS_EXCEPTION_ALLOW;
    }

    for_each_um_exception(gGuest.Exceptions->UserAlertExceptions, pEx)
    {
        if (pEx->OriginatorNameHash == umExcNameAny)
        {
            // For now, we do not support exceptions from the alert that has originator umExcNameAny.
            // If an exception from the alert has no originator, umExcNoName will be used as the exception originator
            goto _match_ex_alert;
        }

        if (Originator->NameHash == INITIAL_CRC_VALUE && pEx->OriginatorNameHash == umExcNameNone)
        {
            goto _match_ex_alert;
        }

        if (pEx->OriginatorNameHash > Originator->NameHash)
        {
            break;
        }
        else if (pEx->OriginatorNameHash != Originator->NameHash)
        {
            continue;
        }

_match_ex_alert:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    if (Victim->Object.Type == introObjectTypeProcessCreation)
    {
        for_each_um_exception(gGuest.Exceptions->ProcessCreationAlertExceptions, pEx)
        {
            if (pEx->OriginatorNameHash == umExcNameAny)
            {
                goto _match_ex_alert_process;
            }

            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->OriginatorNameHash > Originator->NameHash)
            {
                break;
            }
            else if (pEx->OriginatorNameHash < Originator->NameHash)
            {
                continue;
            }

_match_ex_alert_process:
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }

        for_each_um_exception(gGuest.Exceptions->ProcessCreationExceptions, pEx)
        {
            if (pEx->OriginatorNameHash == umExcNameAny)
            {
                goto _match_ex_process;
            }

            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->OriginatorNameHash > Originator->NameHash)
            {
                break;
            }
            else if (pEx->OriginatorNameHash < Originator->NameHash)
            {
                continue;
            }

_match_ex_process:
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }

    if (Originator->NameHash == INITIAL_CRC_VALUE)
    {
        // Check the no name exceptions
        for_each_um_exception(gGuest.Exceptions->NoNameUserExceptions, pEx)
        {
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                RemoveEntryList(&pEx->Link);
                InsertHeadList(&gGuest.Exceptions->NoNameUserExceptions, &pEx->Link);

                return status;
            }
        }
    }
    else
    {
        // Check the generic exceptions (all of them, since originator matches anything)
        for_each_um_exception(gGuest.Exceptions->GenericUserExceptions, pEx)
        {
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                RemoveEntryList(&pEx->Link);
                InsertHeadList(&gGuest.Exceptions->GenericUserExceptions, &pEx->Link);

                return status;
            }
        }
    }

    if (Originator->Name != NULL)
    {
        STATS_ENTER(statsExceptionsGlobMatch);

        for_each_um_glob_exception(gGuest.Exceptions->GlobUserExceptions, pEx)
        {
            if ((Originator->Name[0] < pEx->OriginatorNameGlob[0]) &&
                !IntExceptUserIsGlobItem(pEx->OriginatorNameGlob[0]))
            {
                break;
            }

            if ((Originator->Name[0] != pEx->OriginatorNameGlob[0]) &&
                !IntExceptUserIsGlobItem(pEx->OriginatorNameGlob[0]))
            {
                continue;
            }

            if (Originator->Library == NULL && Originator->Name != NULL)
            {
                if (!glob_match_utf8(pEx->OriginatorNameGlob, Originator->Name, TRUE, TRUE))
                {
                    continue;
                }
            }
            else if (Originator->Library != NULL && Originator->NameWide != NULL)
            {
                if (!glob_match_utf16(pEx->OriginatorNameGlob, Originator->NameWide, TRUE, TRUE))
                {
                    continue;
                }
            }
            else
            {
                continue;
            }

            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUmGlob, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                TRACE("[EXCEPTION] IntExceptMatchException (GLOB) returned INT_STATUS_EXCEPTION_ALLOW.");
                return status;
            }
        }

        STATS_EXIT(statsExceptionsGlobMatch);
    }

    if (Originator->NameHash != INITIAL_CRC_VALUE)
    {
        id = EXCEPTION_TABLE_ID(Originator->NameHash);

        for_each_um_exception(gGuest.Exceptions->UserExceptions[id], pEx)
        {
            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->OriginatorNameHash > Originator->NameHash)
            {
                break;
            }
            else if (pEx->OriginatorNameHash < Originator->NameHash)
            {
                continue;
            }

            if (pEx->Flags & EXCEPTION_FLG_RETURN)
            {
                continue;
            }

            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }

    if (Originator->Library && Originator->Return.Library &&
        (Originator->Rip == Originator->Return.Rip))
    {
        goto _beta_exceptions;
    }

    id = EXCEPTION_TABLE_ID(Originator->Return.NameHash);
    for_each_um_exception(gGuest.Exceptions->UserExceptions[id], pEx)
    {
        // Every list is ordered, so break when we got to a hash bigger than ours
        if (pEx->OriginatorNameHash > Originator->Return.NameHash)
        {
            break;
        }
        else if (pEx->OriginatorNameHash < Originator->Return.NameHash)
        {
            continue;
        }

        if (0 == (pEx->Flags & EXCEPTION_FLG_RETURN))
        {
            continue;
        }

        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

_beta_exceptions:
    for_each_um_exception(gGuest.Exceptions->UserFeedbackExceptions, pEx)
    {
        if (pEx->OriginatorNameHash == umExcNameAny)
        {
            goto _match_ex;
        }

        if (Originator->NameHash == INITIAL_CRC_VALUE && pEx->OriginatorNameHash == umExcNameNone)
        {
            goto _match_ex;
        }

        if (pEx->Flags & EXCEPTION_FLG_RETURN)
        {
            if (pEx->OriginatorNameHash != Originator->Return.NameHash)
            {
                continue;
            }
        }
        else
        {
            if (pEx->OriginatorNameHash != Originator->NameHash)
            {
                continue;
            }
        }

_match_ex:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    for_each_um_exception(gGuest.Exceptions->ProcessCreationFeedbackExceptions, pEx)
    {
        if (pEx->OriginatorNameHash == umExcNameAny)
        {
            goto _match_process_beta_ex;
        }

        if (Originator->NameHash == INITIAL_CRC_VALUE && pEx->OriginatorNameHash == umExcNameNone)
        {
            goto _match_process_beta_ex;
        }

        if (pEx->Flags & EXCEPTION_FLG_RETURN)
        {
            if (pEx->OriginatorNameHash != Originator->Return.NameHash)
            {
                continue;
            }
        }
        else
        {
            if (pEx->OriginatorNameHash != Originator->NameHash)
            {
                continue;
            }
        }

_match_process_beta_ex:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeUm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    return status;
}
