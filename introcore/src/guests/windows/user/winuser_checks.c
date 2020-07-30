/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winuser_checks.h"
#include "guests.h"

///
/// @file winuser_checks.c
///
/// @brief This file handles initialization injections into Windows processes.
///


// This field is used only on Windows 7 and it is at the same offset on all service packs so it doesn't makes sense to
// add it to the OsSpecificFields structure.

#define PEB32_PCONTEXT_OFFSET       0x238       ///< The PEB32 (Process Environment Block) context offset.
#define PEB64_PCONTEXT_OFFSET       0x368       ///< The PEB64 (Process Environment Block) context offset.

__forceinline
static BOOLEAN
IsPeb32Write(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD Address,
    _In_ DWORD Size,
    _In_ DWORD PebSize
    )
///
/// @brief This function checks if the current injection targets the PEB32 (Process Environment Block) structure.
///
/// @param[in]  Process     The #WIN_PROCESS_OBJECT structure of the initializing process.
/// @param[in]  Address     The written address.
/// @param[in]  Size        The write size.
/// @param[in]  PebSize     The size of the PEB (Process Environment Block).
///
/// @retval     TRUE        The injection is a write into the PEB32 (#WIN_PROCESS_OBJECT.Peb32Address).
/// @retval     FALSE       The injection is NOT a write into the PEB32 (#WIN_PROCESS_OBJECT.Peb32Address).
///
{
    if (Process->Peb32Address <= Address &&
        Process->Peb32Address + PebSize > Address)
    {
        // Additional check for pContextData
        if (PEB32_PCONTEXT_OFFSET + Process->Peb32Address == Address && sizeof(DWORD) == Size)
        {
            Process->Peb32ContextWritten = TRUE;
        }

        // The start is inside PEB. Is the end still there?
        Address += Size;

        if (Process->Peb32Address <= Address &&
            Process->Peb32Address + PebSize > Address)
        {
            return TRUE;
        }
    }

    // 64-bit process with 32-bit parent
    if (!Process->Wow64Process && Process->ParentWow64)
    {
        if (Process->PebWrittenCount == 1)
        {
            return TRUE;
        }
    }

    return FALSE;
}


__forceinline
static BOOLEAN
IsPeb64Write(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD Address,
    _In_ DWORD Size,
    _In_ DWORD PebSize
    )
///
/// @brief This function checks if the current injection targets the PEB64 (Process Environment Block) structure.
///
/// @param[in]  Process     The #WIN_PROCESS_OBJECT structure of the initializing process.
/// @param[in]  Address     The written address.
/// @param[in]  Size        The write size.
/// @param[in]  PebSize     The size of the PEB (Process Environment Block).
///
/// @retval     TRUE        The injection is a write into the PEB64 (#WIN_PROCESS_OBJECT.Peb64Address).
/// @retval     FALSE       The injection is NOT a write into the PEB64 (#WIN_PROCESS_OBJECT.Peb64Address).
///
{
    if (Process->Peb64Address <= Address &&
        Process->Peb64Address + PebSize > Address)
    {
        // Additional check for pContextData
        if (PEB64_PCONTEXT_OFFSET + Process->Peb64Address == Address && sizeof(QWORD) == Size)
        {
            Process->Peb64ContextWritten = TRUE;
        }

        // The start is inside PEB. Is the end still there?
        Address += Size;

        if (Process->Peb64Address <= Address &&
            Process->Peb64Address + PebSize > Address)
        {
            return TRUE;
        }
    }

    return FALSE;
}


__forceinline
static BOOLEAN
ShouldIgnoreInjection(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ QWORD Address,
    _In_ DWORD Size
    )
///
/// @brief This function checks if the current injection should be ignored or not (based on the
/// #WIN_PROCESS_OBJECT.InjectionsCount and #WIN_PROCESS_OBJECT.InjectedApphelp).
///
/// @param[in]  Process     The #WIN_PROCESS_OBJECT structure of the initializing process.
/// @param[in]  Address     The written address.
/// @param[in]  Size        The write size.
///
/// @retval     TRUE       The injection should be ignored (#WIN_PROCESS_OBJECT.InjectionsCount should not change).
/// @retval     FALSE      The injection should NOT be ignored (increment #WIN_PROCESS_OBJECT.InjectionsCount).
///

{
    if (Process->InjectionsCount == 1 && !Process->InjectedApphelp)
    {
        if (Size == 4)
        {
            return TRUE;
        }

        if (gGuest.OSVersion < 9200 && Size == 0x20)
        {
            return TRUE;
        }

        if (Size > 1000)
        {
            Process->InjectedApphelp = TRUE;
            Process->InjectedApphelpAddress = Address;
            Process->InjectedAppHelpSize = Size;

            return TRUE;
        }
    }

    return FALSE;
}


__forceinline
static BOOLEAN
IsInitializationDone(
    _In_ PWIN_PROCESS_OBJECT Process
    )
///
/// @brief  This function checks if all the initialization steps of a process are done.
///
/// @param[in]  Process     The #WIN_PROCESS_OBJECT structure of the initializing process.
///
/// @retval     TRUE        The initialization is done.
/// @retval     FALSE       The initialization is NOT done.
///
///
{
    // on Windows 7 x64, initialization isn't done until PEB.pContextData is written
    if (gGuest.Guest64 && gGuest.OSVersion <= 7602 && Process->InjectedApphelp)
    {
        if (Process->Subsystemx64 && Process->Subsystemx86)
        {
            if (Process->Peb64ContextWritten && Process->Peb32ContextWritten)
            {
                return TRUE;
            }
            else
            {
                return FALSE;
            }
        }
        else if (Process->Subsystemx64 && Process->Peb64ContextWritten)
        {
            return TRUE;
        }
        else if (Process->Subsystemx86 && Process->Peb32ContextWritten)
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    if (gGuest.Guest64)
    {
        // 32-bit process parent which injects apphelp, it does the PEB write 4 times
        if (Process->PebWrittenCount == 2 && Process->Wow64Process && Process->ParentWow64 &&
            Process->InjectedApphelp && gGuest.OSVersion < 9200)
        {
            Process->InjectedApphelp = FALSE;
            Process->InjectionsCount = 0;
            Process->PebWrittenCount = 0;

            return FALSE;
        }

        if (Process->PebWrittenCount == 2)
        {
            return TRUE;
        }

        if (!Process->Wow64Process && Process->PebWrittenCount == 1)
        {
            if (gGuest.OSVersion >= 14393 && Process->ParentWow64)
            {
                return TRUE;
            }

            if (gGuest.OSVersion >= 9200 && Process->ParentWow64)
            {
                return FALSE;
            }

            return TRUE;
        }
    }
    else
    {
        if (Process->PebWrittenCount == 1)
        {
            if (Process->InjectedApphelp && gGuest.OSVersion < 9200)
            {
                Process->InjectedApphelp = FALSE;
                Process->InjectionsCount = 0;
                Process->PebWrittenCount = 0;

                return FALSE;
            }

            return TRUE;
        }
    }

    return FALSE;
}


INTSTATUS
IntWinUmCheckInitializationInjection(
    _In_ PEXCEPTION_VICTIM_ZONE Victim,
    _In_ PEXCEPTION_UM_ORIGINATOR Originator
    )
///
/// @brief  This function is used by the exception mechanism in order to verify the initialization state of a process
/// (during initialization some legitimate injections take place and have to be excepted).
///
/// @param[in]  Victim      The victim object.
/// @param[in]  Originator  The originator object.
///
/// @retval     #INT_STATUS_EXCEPTION_CHECKS_OK         On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1         The Victim is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2         The Originator is NULL.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE      The Victim object must contain a process
///                                                     (#EXCEPTION_VICTIM_ZONE.Object).
///
/// @retval     #INT_STATUS_EXCEPTION_CHECKS_FAILED     If the given process did not start initializing
///                                                     (#WIN_PROCESS_OBJECT.StartInitializing is not set) or the
///                                                     process is fully initialized (#WIN_PROCESS_OBJECT.Initialized
///                                                     and #WIN_PROCESS_OBJECT.LastPebWriteDone are both set).
///
///
{
    WIN_PROCESS_OBJECT *pProc;
    DWORD pebSize, pebWriteCount;

    if (NULL == Victim)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Originator)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pProc = Victim->Object.WinProc;
    if (NULL == pProc)
    {
        ERROR("[ERROR] Victim zone cannot have NULL process!\n");
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    if (!pProc->StartInitializing)
    {
        return INT_STATUS_EXCEPTION_CHECKS_FAILED;
    }

    if (pProc->Initialized)
    {
        if (!pProc->LastPebWriteDone)
        {
            QWORD address = Victim->Injection.Gva;
            DWORD size = Victim->Injection.Length;

            if (gGuest.OSVersion <= 7602 && pProc->Wow64Process)
            {
                if (PEB64_PCONTEXT_OFFSET + pProc->Peb64Address == address &&
                    sizeof(QWORD) == size)
                {
                    pProc->LastPebWriteDone = TRUE;
                    return INT_STATUS_EXCEPTION_CHECKS_OK;
                }

                if (PEB32_PCONTEXT_OFFSET + pProc->Peb32Address == address &&
                    sizeof(DWORD) == size)
                {
                    pProc->LastPebWriteDone = TRUE;
                    return INT_STATUS_EXCEPTION_CHECKS_OK;
                }
            }
        }

        return INT_STATUS_EXCEPTION_CHECKS_FAILED;
    }

    pebWriteCount = pProc->PebWrittenCount;
    pProc->InjectionsCount++;

    if (ShouldIgnoreInjection(pProc, Victim->Injection.Gva, Victim->Injection.Length))
    {
        pProc->InjectionsCount--;

        return INT_STATUS_EXCEPTION_CHECKS_OK;
    }

    if (gGuest.Guest64)
    {
        pebSize = WIN_UM_FIELD(Peb, 64Size);

        if (IsPeb64Write(pProc, Victim->Injection.Gva, Victim->Injection.Length, pebSize))
        {
            pProc->PebWrittenCount++;
        }
        else
        {
            pebSize = WIN_UM_FIELD(Peb, 32Size);

            if (IsPeb32Write(pProc, Victim->Injection.Gva, Victim->Injection.Length, pebSize))
            {
                pProc->PebWrittenCount++;
            }
        }
    }
    else
    {
        pebSize = WIN_UM_FIELD(Peb, 32Size);

        if (IsPeb32Write(pProc, Victim->Injection.Gva, Victim->Injection.Length, pebSize))
        {
            pProc->PebWrittenCount++;
        }
    }

    //
    // On pre-windows 10, everything until PEB writes are OK
    //
    if (gGuest.OSVersion < 10240)
    {
        if (pebWriteCount == pProc->PebWrittenCount)
        {
            return INT_STATUS_EXCEPTION_CHECKS_OK;
        }
    }

    if (IsInitializationDone(pProc))
    {
        TRACE("[PROCESS] '%s' with EPROC: 0x%016llx is fully initialized!\n", pProc->Name, pProc->EprocessAddress);
        pProc->Initialized = TRUE;
    }

    return INT_STATUS_EXCEPTION_CHECKS_OK;
}
