/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       exceptions_krnusr.c
/// @ingroup    group_exceptions
///

#include "exceptions.h"
#include "codeblocks.h"
#include "crc32.h"
#include "decoder.h"
#include "hook.h"
#include "winpe.h"


extern char gExcLogLine[2 * ONE_KILOBYTE];


static void
IntExceptKernelUserLogWindowsInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a kernel-user mode violation (windows guest).
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Action          The action that was taken.
/// @param[in]  Reason          The reason for which Action was taken.
///
{
    KERNEL_DRIVER *pDriver = NULL;
    KERNEL_DRIVER *pRetDriver = NULL;
    DWORD modNameAlignment;
    char *l;
    int ret, rem;
    char instr[ND_MIN_BUF_SIZE];

    pDriver = Originator->Original.Driver;
    pRetDriver = Originator->Return.Driver;

    modNameAlignment = 0;
    l = gExcLogLine;
    rem = sizeof(gExcLogLine);

    if (Originator->Instruction)
    {
        NDSTATUS ndstatus = NdToText(Originator->Instruction, Originator->Original.Rip, sizeof(instr), instr);
        if (!ND_SUCCESS(ndstatus))
        {
            memcpy(instr, EXPORT_NAME_UNKNOWN, sizeof(EXPORT_NAME_UNKNOWN));
        }
    }
    else
    {
        memcpy(instr, EXCEPTION_NO_INSTRUCTION, sizeof(EXCEPTION_NO_INSTRUCTION));
    }

    ret = IntExceptPrintWinKmModInfo(pDriver, "Originator-> Module: ", l, rem, modNameAlignment);
    rem -= ret;
    l += ret;

    ret = snprintf(l, rem, ", RIP %0*llx", gGuest.WordSize * 2, Originator->Original.Rip);

    if (ret < 0 || ret >= rem)
    {
        ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
    }
    else
    {
        rem -= ret;
        l += ret;
    }

    if (Originator->Original.Section[0] != 0)
    {
        ret = snprintf(l, rem, " (%s)", Originator->Original.Section);

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

    if (instr[0] != 0)
    {
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
    }

    ret = snprintf(l, rem, ", IsInjection: %s %s",
                   (Originator->Injection.User || Originator->Injection.Kernel) ? "yes" : "no",
                   Originator->Injection.User ? "(user-mode)" :
                   Originator->Injection.Kernel ? "(kernel-mode)" : "");

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

    if (Originator->Return.Driver && Originator->Original.Rip != Originator->Return.Rip)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        ret = IntExceptPrintWinKmModInfo(pRetDriver, "Return    -> Module: ", l, rem, modNameAlignment);
        rem -= ret;
        l += ret;

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

        if (Originator->Return.Section[0] != 0)
        {
            ret = snprintf(l, rem, "(%s)", Originator->Return.Section);

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

    if (Originator->Process.Process != NULL)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        if (gGuest.OSType == introGuestWindows)
        {
            ret = IntExceptPrintWinProcInfo(Originator->Process.WinProc, "Originator Process:  ", l, rem, 0);
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            ret = IntExceptPrintLixTaskInfo(Originator->Process.LixProc, "Originator Process:  ", l, rem, 0);
        }

        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);
    }

    if (Victim->Object.Type == introObjectTypeUmModule)
    {
        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        ret = IntExceptPrintWinProcInfo(Victim->Object.Library.WinMod->Subsystem->Process, "Process:             ",
                                        l, rem, 0);
        rem -= ret;
        l += ret;

        LOG("%s\n", gExcLogLine);

        l = gExcLogLine;
        rem = sizeof(gExcLogLine);

        WINUM_CACHE_EXPORT *pExport = NULL;

        ret = IntExceptPrintWinModInfo(Victim->Object.Library.WinMod, "Victim    -> Module: ", l, rem, modNameAlignment);
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

        ret = snprintf(l, rem, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^%sROOTKIT (kernel-user mode) ",
                        Victim->Object.Library.WinMod->Subsystem->Process->BetaDetections ? " (B) " : " ");
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
        case introReasonExportNotMatched:
            ret = snprintf(l, rem, "(export)");
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

        snprintf(l, rem, " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

        LOG("%s\n\n", gExcLogLine);
    }
    for (DWORD t = 0; t < Originator->StackTrace.NumberOfTraces; t++)
    {
        if (NULL != Originator->StackTrace.Traces[t].ReturnModule)
        {
            LOG("[STACK TRACE] [at 0x%016llx] returning to [%s at 0x%016llx]\n",
                Originator->StackTrace.Traces[t].CurrentRip,
                utf16_for_log(((KERNEL_DRIVER *)Originator->StackTrace.Traces[t].ReturnModule)->Name),
                Originator->StackTrace.Traces[t].ReturnAddress);
        }
        else
        {
            LOG("[STACK TRACE] [at 0x%016llx]\n", Originator->StackTrace.Traces[t].CurrentRip);
        }
    }
}


void
IntExceptKernelUserLogInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Print the information about a kernel-user mode violation and dumps the code-blocks.
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

    if (gGuest.OSType == introGuestWindows)
    {
        IntExceptKernelUserLogWindowsInformation(Victim, Originator, Action, Reason);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return;
    }

    if (!(Victim->ZoneFlags & ZONE_INTEGRITY))
    {
        IntExceptDumpSignatures(Originator, Victim, TRUE, FALSE);
        IntExceptDumpSignatures(Originator, Victim, TRUE, TRUE);
    }

}


static __inline BOOLEAN
IntExceptKernelUserMatchZoneFlags(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ KUM_EXCEPTION *Exception
    )
///
/// @brief Checks if the zone-flags of the current exception match the zone flags of the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the zone-flags match, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if ((Exception->Flags & EXCEPTION_FLG_READ) &&
        (Victim->ZoneFlags & ZONE_READ))
    {
        match = TRUE;
    }

    if ((Exception->Flags & EXCEPTION_FLG_EXECUTE) &&
        (Victim->ZoneFlags & ZONE_EXECUTE))
    {
        match = TRUE;
    }

    if ((Exception->Flags & EXCEPTION_FLG_WRITE) &&
        (Victim->ZoneFlags & ZONE_WRITE))
    {
        match = TRUE;
    }

    return match;
}


static __inline BOOLEAN
IntExceptKernelUserMatchArch(
    _In_ KUM_EXCEPTION *Exception
    )
///
/// @brief Checks if the architecture-flags of the current exception match the architecture-flags of the originator.
///
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the arch match, otherwise false.
///
{
    BOOLEAN match = FALSE;

    if ((Exception->Flags & EXCEPTION_FLG_32) &&
        (Exception->Flags & EXCEPTION_FLG_64))
    {
        match = TRUE;
    }
    else if ((Exception->Flags & EXCEPTION_FLG_64) &&
             gGuest.Guest64)
    {
        match = TRUE;
    }
    else if ((Exception->Flags & EXCEPTION_FLG_32) &&
             !gGuest.Guest64)
    {
        match = TRUE;
    }

    return match;
}


static __inline BOOLEAN
IntExceptKernelUserMatchNameHash(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ KUM_EXCEPTION *Exception
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
   if (Exception->Victim.NameHash == umExcNameAny ||
       Exception->Victim.NameHash == Victim->Object.NameHash)
    {
        return TRUE;
    }

    return FALSE;
}


static __inline BOOLEAN
IntExceptKernelUserMatchProcessHash(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ KUM_EXCEPTION *Exception
    )
///
/// @brief Checks if the exception process name-hash of the current exception matches the process name-hash of the
/// victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the process name-hash matches, otherwise false.
///
{
    if (Exception->Victim.ProcessHash == umExcNameAny)
    {
        return TRUE;
    }
    else
    {
        if (gGuest.OSType == introGuestWindows)
        {
            return (Exception->Victim.ProcessHash == Victim->Object.Library.WinMod->Subsystem->Process->NameHash);
        }
        else
        {
            WARNING("[WARNING] Not supported for Linux guest!\n");
        }
    }

    return FALSE;
}


static __inline BOOLEAN
IntExceptKernelUserMatchObjectType(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ KUM_EXCEPTION *Exception
    )
///
/// @brief Checks if the zone-type of the current exception matches the object-type of the victim.
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Exception       The exception object.
///
/// @retval     True if the object-type matches, otherwise false.
///
{
    switch (Exception->Type)
    {
        case kumObjAny:
            return TRUE;

        case kumObjModule:
            if (Victim->Object.Type == introObjectTypeUmModule)
            {
                return TRUE;
            }
            break;

        case kumObjModuleImports:
            if ((Victim->Object.Type == introObjectTypeUmModule) &&
                (Victim->ZoneFlags & ZONE_LIB_IMPORTS))
            {
                return TRUE;
            }
            break;

        case kumObjModuleExports:
            if ((Victim->Object.Type == introObjectTypeUmModule) &&
                (Victim->ZoneFlags & ZONE_LIB_EXPORTS))
            {
                return TRUE;
            }
            break;

        default:
            LOG("[ERROR] This is a corruption in the update/exception. Type = %d!\n", Exception->Type);
            break;
    }

    return FALSE;
}


INTSTATUS
IntExceptKernelUserMatchVictim(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ KUM_EXCEPTION *Exception
    )
///
/// @brief This function checks if the exception matches the originator and the modified zone.
///
/// The following are verified:
///     - the zone flags
///     - the zone type
///     - the exception flags
///     - the modified name-hash
///     - the process name-hash
///     - the architecture flags
///     - the initialization type
///     - the return driver
///
/// @param[in]  Victim          The victim object.
/// @param[in]  Originator      The originator object.
/// @param[in]  Exception       The current exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_NOT_MATCHED   If any check fails.
/// @retval     #INT_STATUS_EXCEPTION_ALLOW         If all checks have passed.
///
{
    BOOLEAN match = FALSE;

    // If the current write is due to an injection but the exception doesn't have any of the
    // kernel/user injection flags then don't match it.
    if ((Originator->Injection.User || Originator->Injection.Kernel) &&
        (Exception->Flags & (EXCEPTION_KUM_FLG_KERNEL | EXCEPTION_KUM_FLG_USER)) == 0)
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    // If the current write is not due to an injection but the exception has any of the
    // kernel/user injection flags then don't match it.
    if ((!Originator->Injection.User && !Originator->Injection.Kernel) &&
        (Exception->Flags & (EXCEPTION_KUM_FLG_KERNEL | EXCEPTION_KUM_FLG_USER)) != 0)
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    // Finally match the kernel/user injection flags if needed.
    if (((Exception->Flags & EXCEPTION_KUM_FLG_KERNEL) && Originator->Injection.User) ||
        ((Exception->Flags & EXCEPTION_KUM_FLG_USER) && Originator->Injection.Kernel))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (!IntExceptKernelUserMatchZoneFlags(Victim, Exception))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (!IntExceptKernelUserMatchArch(Exception))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (!IntExceptKernelUserMatchNameHash(Victim, Exception))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (!IntExceptKernelUserMatchProcessHash(Victim, Exception))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (!IntExceptKernelUserMatchObjectType(Victim, Exception))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if ((Exception->Flags & EXCEPTION_KM_FLG_NON_DRIVER) &&
        (Originator->Original.Driver != NULL))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    if (Exception->Flags & EXCEPTION_FLG_INIT)
    {
        match = FALSE;

        // a. On integrity zones, this is all we can check
        if ((Victim->ZoneType == exceptionZoneIntegrity) &&
            (Victim->WriteInfo.OldValue[0] == 0))
        {
            match = TRUE;
        }
        // b. Kernel's INIT section writes
        else if ((Exception->Flags & EXCEPTION_KM_FLG_RETURN_DRV) &&
                 (Originator->Return.NameHash == kmExcNameKernel))
        {
            // match anything that starts with init/INIT
            if (gGuest.OSType == introGuestWindows)
            {
                match = 0 == memcmp(Originator->Return.Section, "INIT", 4);
            }
            else
            {
                match = 0 == memcmp(Originator->Return.Section, "init", 4);
            }
        }
        else if (Originator->Original.NameHash == kmExcNameKernel)
        {
            // match anything that starts with init/INIT
            if (gGuest.OSType == introGuestWindows)
            {
                match = 0 == memcmp(Originator->Original.Section, "INIT", 4);
            }
            else
            {
                match = 0 == memcmp(Originator->Original.Section, "init", 4);
            }
        }
        // c. RIP is in EntryPoint
        else if (Originator->IsEntryPoint)
        {
            match = TRUE;
        }
        // d. Old value was 0
        else if (Victim->WriteInfo.OldValue[0] == 0)
        {
            match = TRUE;
        }

        if (!match)
        {
            return INT_STATUS_EXCEPTION_NOT_MATCHED;
        }
    }

    // If we get here, then allow the action. Anyway, the extra checks & signatures mechanism will actually allow it
    return INT_STATUS_EXCEPTION_ALLOW;
}


INTSTATUS
IntExceptKernelUser(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief This function iterates through exception lists and tries to find an exception that matches the originator
/// and the victim.
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
    INTSTATUS status = INT_STATUS_EXCEPTION_NOT_MATCHED;
    BOOLEAN sameRip = FALSE;
    DWORD hash = INITIAL_CRC_VALUE;
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

    *Action = introGuestNotAllowed;
    *Reason = introReasonNoException;

    // In some cases the Old/New values are the same - allow them by default.
    if (__unlikely(Victim->ZoneType == exceptionZoneEpt && !!(Victim->ZoneFlags & ZONE_WRITE) &&
        !memcmp(Victim->WriteInfo.OldValue, Victim->WriteInfo.NewValue,
                MIN(Victim->WriteInfo.AccessSize, sizeof(Victim->WriteInfo.NewValue)))))
    {
        *Action = introGuestAllowed;
        *Reason = introReasonSameValue;

        return INT_STATUS_EXCEPTION_ALLOW;
    }

    if (Originator->Injection.User)
    {
        if (gGuest.OSType == introGuestWindows)
        {
            hash = Originator->Process.WinProc->NameHash;
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            hash = Originator->Process.LixProc->CommHash;
        }
        else
        {
            ERROR("[ERROR] Unsupported guest type '%d'! Abort ...\n", gGuest.OSType);
            return INT_STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        if (Originator->Injection.Kernel)
        {
            hash = Originator->Return.NameHash;
        }
        else
        {
            hash = Originator->Original.NameHash;
        }
    }

    for_each_kum_exception(gGuest.Exceptions->KernelUserAlertExceptions, pEx)
    {
        if (((pEx->Flags & EXCEPTION_KUM_FLG_KERNEL) && Originator->Injection.User) ||
            ((pEx->Flags & EXCEPTION_KUM_FLG_USER) && Originator->Injection.Kernel))
        {
            continue;
        }

        if (pEx->Originator.NameHash == kumExcNameAny)
        {
            // For now, we do not support exceptions from the alert that has originator kmExcNameAny.
            // If an exception from the alert has no originator, kumExcNameNone will be used as the exception originator
            goto _match_ex_alert;
        }

        if (!Originator->Injection.User &&
            Originator->Original.NameHash == INITIAL_CRC_VALUE &&
            pEx->Originator.NameHash == kumExcNameNone)
        {
            goto _match_ex_alert;
        }

        if (pEx->Originator.NameHash > hash)
        {
            break;
        }
        else if (pEx->Originator.NameHash != hash)
        {
            continue;
        }

_match_ex_alert:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKmUm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    if (!Originator->Injection.User && Originator->Original.NameHash == INITIAL_CRC_VALUE)
    {
        // Check the no name exceptions, and skip the generic ones
        for_each_kum_exception(gGuest.Exceptions->NoNameKernelUserExceptions, pEx)
        {
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKmUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }
    else
    {
        // Check the generic exceptions (all of them, since originator matches anything)
        for_each_kum_exception(gGuest.Exceptions->GenericKernelUserExceptions, pEx)
        {
            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKmUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }

    if (Originator->Injection.Kernel &&
        Originator->Original.Driver &&
        Originator->Return.Driver &&
        Originator->Original.Rip == Originator->Return.Rip)
    {
        // Don't check by RIP since it may be in different sections
        sameRip = TRUE;
    }

    if (hash != INITIAL_CRC_VALUE)
    {
        id = EXCEPTION_TABLE_ID(hash);

        for_each_kum_exception(gGuest.Exceptions->KernelUserExceptions[id], pEx)
        {
            if (((pEx->Flags & EXCEPTION_KUM_FLG_KERNEL) && Originator->Injection.User) ||
                ((pEx->Flags & EXCEPTION_KUM_FLG_USER) && Originator->Injection.Kernel))
            {
                continue;
            }

            // Here we only check exceptions by the name, so that cannot be missing.
            // And the return flag must be missing.
            if ((pEx->Flags & EXCEPTION_KUM_FLG_KERNEL) &&
                (pEx->Originator.NameHash == INITIAL_CRC_VALUE ||
                 ((pEx->Flags & EXCEPTION_KM_FLG_RETURN_DRV) &&
                  !sameRip)))
            {
                continue;
            }

            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->Originator.NameHash > hash)
            {
                break;
            }
            else if (pEx->Originator.NameHash != hash)
            {
                continue;
            }

            // The EXCEPTION_KM_FLG_RETURN_DRV will be deleted, so do the same verification again
            if ((pEx->Flags & EXCEPTION_FLG_RETURN) && !sameRip)
            {
                continue;
            }

            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKmUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }

        if (sameRip)
        {
            // No point in doing the same thing again
            goto _beta_exceptions;
        }
    }

    // Try and match the original driver by name
    if (!Originator->Injection.User && Originator->Return.NameHash != INITIAL_CRC_VALUE)
    {
        id = EXCEPTION_TABLE_ID(Originator->Return.NameHash);
        for_each_kum_exception(gGuest.Exceptions->KernelUserExceptions[id], pEx)
        {
            if (pEx->Flags & EXCEPTION_KUM_FLG_USER)
            {
                continue;
            }

            // Here we only check exceptions by the name, so that cannot be missing
            // And the return flag must be set
            if (pEx->Originator.NameHash == INITIAL_CRC_VALUE ||
                (0 == (pEx->Flags & EXCEPTION_KM_FLG_RETURN_DRV)))
            {
                continue;
            }

            // Every list is ordered, so break when we got to a hash bigger than ours
            if (pEx->Originator.NameHash > Originator->Return.NameHash)
            {
                break;
            }
            else if (pEx->Originator.NameHash != Originator->Return.NameHash)
            {
                continue;
            }

            // The EXCEPTION_KM_FLG_RETURN_DRV will be deleted, so do the same verification again
            if (0 == (pEx->Flags & EXCEPTION_FLG_RETURN))
            {
                continue;
            }

            status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKmUm, Action, Reason);
            if (status == INT_STATUS_EXCEPTION_ALLOW)
            {
                return status;
            }
        }
    }

_beta_exceptions:
    for_each_kum_exception(gGuest.Exceptions->KernelUserFeedbackExceptions, pEx)
    {
        if (((pEx->Flags & EXCEPTION_KUM_FLG_KERNEL) && Originator->Injection.User) ||
            ((pEx->Flags & EXCEPTION_KUM_FLG_USER) && Originator->Injection.Kernel))
        {
            continue;
        }

        if (pEx->Originator.NameHash == kmExcNameAny)
        {
            goto _match_ex;
        }

        if (!Originator->Injection.User &&
            Originator->Original.NameHash == INITIAL_CRC_VALUE &&
            pEx->Originator.NameHash == kumExcNameNone)
        {
            goto _match_ex;
        }

        if (pEx->Flags & EXCEPTION_FLG_RETURN)
        {
            if (!Originator->Injection.User && pEx->Originator.NameHash != Originator->Return.NameHash)
            {
                continue;
            }
        }
        else
        {
            if (!Originator->Injection.User && pEx->Originator.NameHash != Originator->Original.NameHash)
            {
                continue;
            }

            if (Originator->Injection.User)
            {
                if (gGuest.OSType == introGuestWindows)
                {
                    if (pEx->Originator.NameHash != Originator->Process.WinProc->NameHash)
                    {
                        continue;
                    }
                }
                else if (gGuest.OSType == introGuestLinux)
                {
                    if (pEx->Originator.NameHash != Originator->Process.LixProc->CommHash)
                    {
                        continue;
                    }
                }
            }
        }
_match_ex:
        status = IntExceptMatchException(Victim, Originator, pEx, exceptionTypeKmUm, Action, Reason);
        if (status == INT_STATUS_EXCEPTION_ALLOW)
        {
            return status;
        }
    }

    return status;
}


INTSTATUS
IntExceptKernelUserVerifyExtra(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    )
///
/// @brief This function is used as an extra step in exception mechanism.
///
/// @param[in]  Victim      The victim object.
/// @param[in]  Originator  The originator object.
/// @param[in]  Exception   The current exception object.
///
/// @retval     #INT_STATUS_EXCEPTION_CHECKS_OK     On success.
///
{
    UNREFERENCED_PARAMETER(Victim);
    UNREFERENCED_PARAMETER(Originator);
    UNREFERENCED_PARAMETER(Exception);

    return INT_STATUS_EXCEPTION_CHECKS_OK;
}
