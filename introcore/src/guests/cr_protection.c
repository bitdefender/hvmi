/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cr_protection.h"
#include "alerts.h"
#include "guests.h"
#include "hook_cr.h"

/// @brief  The Cr4 hook handle
///
/// Created in #IntCr4Protect and destroyed in #IntCr4Unprotect
static HOOK_CR *gCr4Hook = NULL;


static void
IntCrSendAlert(
    _In_ EXCEPTION_VICTIM_ZONE const *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR const *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      Sends a CR violation alert
///
/// This will send an #introEventCrViolation event to the integrator. These alerts are controlled by the
/// #INTRO_OPT_ENABLE_CR_PROTECTION options.
///
/// @param[in]  Victim      The victim information. This is obtained from #IntExceptGetVictimCr.
/// @param[in]  Originator  Information about the attacker. This is obtained from #IntExceptKernelGetOriginator.
/// @param[in]  Action      The action that was taken
/// @param[in]  Reason      The reason for which Action was taken
///
{
    INTSTATUS status;
    EVENT_CR_VIOLATION *pCrViol = &gAlert.Cr;

    memzero(pCrViol, sizeof(*pCrViol));

    pCrViol->Header.Action = Action;
    pCrViol->Header.Reason = Reason;
    if (Victim->Cr.Smap || Victim->Cr.Smep)
    {
        pCrViol->Header.MitreID = idExploitPrivEsc;
    }
    else
    {
        pCrViol->Header.MitreID = idRootkit;
    }

    pCrViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_CR4, Reason);

    IntAlertCrFill(Victim, Originator, pCrViol);

    IntAlertFillCpuContext(TRUE, &pCrViol->Header.CpuContext);

    if (gGuest.OSType == introGuestWindows)
    {
        IntAlertFillWinProcessByCr3(pCrViol->Header.CpuContext.Cr3, &pCrViol->Header.CurrentProcess);

        pCrViol->Header.CurrentProcess.SecurityInfo.WindowsToken.ImpersonationToken = FALSE;
        pCrViol->Header.CurrentProcess.SecurityInfo.WindowsToken.Valid = TRUE;
    }
    else
    {
        IntAlertFillLixCurrentProcess(&pCrViol->Header.CurrentProcess);
    }

    IntAlertFillExecContext(gGuest.Mm.SystemCr3, &pCrViol->ExecContext);
    IntAlertFillCodeBlocks(Originator->Original.Rip, gGuest.Mm.SystemCr3, FALSE, &pCrViol->CodeBlocks);

    IntAlertFillVersionInfo(&pCrViol->Header);

    status = IntNotifyIntroEvent(introEventCrViolation, pCrViol, sizeof(*pCrViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static INTSTATUS
IntCrWinHandleWrite(
    _In_opt_ void *Context,
    _In_ DWORD Cr,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief      Handles a control register write attempt done by a Windows guest
///
/// Will analyze the write and will decide if it is malicious. If the SMEP or SMAP bits are disabled it will generate
/// an alert, unless an exception matches this write.
///
/// @param[in]  Context     Ignored
/// @param[in]  Cr          The written control register. This will always be 4
/// @param[in]  OldValue    The old, original value of the register. If the action is blocked, the register will keep
///                         this value
/// @param[in]  NewValue    The written value
/// @param[out] Action      The action that must be taken
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTRO_ACTION_REASON reason;
    BOOLEAN exitAfterInformation = FALSE;
    BOOLEAN smap = (OldValue & CR4_SMAP) != 0 && (NewValue & CR4_SMAP) == 0;
    BOOLEAN smep = (OldValue & CR4_SMEP) != 0 && (NewValue & CR4_SMEP) == 0;

    UNREFERENCED_PARAMETER(Context);

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    // We allow writes that aren't on SMEP/SMAP or aren't deactivation of SMEP/SMAP
    if (!smap && !smep)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsExceptionsKern);

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimCr(NewValue, OldValue, Cr, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventCrViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_CR4,  Action, &reason))
    {
        IntCrSendAlert(&victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_CR4, Action);

    return status;
}


static INTSTATUS
IntCrLixHandleWrite(
    _In_opt_ void *Context,
    _In_ DWORD Cr,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief      Handles a control register write attempt done by a Linux guest
///
/// Will analyze the write and will decide if it is malicious. If the SMEP or SMAP bits are disabled it will generate
/// an alert, unless an exception matches this write.
///
/// @param[in]  Context     Ignored
/// @param[in]  Cr          The written control register. This will always be 4
/// @param[in]  OldValue    The old, original value of the register. If the action is blocked, the register will keep
///                         this value
/// @param[in]  NewValue    The written value
/// @param[out] Action      The action that must be taken
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    BOOLEAN exitAfterInformation, smep, smap;
    KERNEL_DRIVER *pOrigDriver;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTRO_ACTION_REASON reason;

    UNREFERENCED_PARAMETER(Context);

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    smap = (OldValue & CR4_SMAP) != 0 && (NewValue & CR4_SMAP) == 0;
    smep = (OldValue & CR4_SMEP) != 0 && (NewValue & CR4_SMEP) == 0;

    // We allow writes that aren't on SMEP/SMAP or aren't deactivation of SMEP/SMAP
    if (!smap && !smep)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    pOrigDriver = IntDriverFindByAddress(gVcpu->Regs.Rip);
    if (NULL == pOrigDriver)
    {
        WARNING("[WARNING] RIP 0x%016llx is not inside any module!\n", gVcpu->Regs.Rip);
    }

    STATS_ENTER(statsExceptionsKern);

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    exitAfterInformation = FALSE;

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimCr(NewValue, OldValue, Cr, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventCrViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_CR4, Action, &reason))
    {
        IntCrSendAlert(&victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_CR4, Action);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCr4HandleWrite(
    _In_opt_ void *Context,
    _In_ DWORD Cr,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief      Handles CR4 writes
///
/// This is the hook handler set by #IntCr4Protect. The handle is #gCr4Hook. Will delegate the actual handling to
/// a guest-specific handler: #IntCrWinHandleWrite or #IntCrLixHandleWrite.
///
/// @param[in]  Context     The context set by the function that hooked the CR. Nothing in this case
/// @param[in]  Cr          The number of the written register. Will always be 4.
/// @param[in]  OldValue    The original value of the register
/// @param[in]  NewValue    The value that the guest attempted to write
/// @param[out] Action      The action that must be taken
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntCrWinHandleWrite(Context, Cr, OldValue, NewValue, Action);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntCrLixHandleWrite(Context, Cr, OldValue, NewValue, Action);
    }

    return INT_STATUS_NOT_SUPPORTED;
}


INTSTATUS
IntCr4Protect(
    void
    )
///
/// @brief      Activates the Cr4 protection
///
/// Enables exits for Cr4 writes and sets #IntCr4HandleWrite as the hook handler.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (NULL != gCr4Hook)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    TRACE("[CR4] Adding protection on CR4.SMEP and CR4.SMAP...\n");

    status = IntHookCrSetHook(4, 0, IntCr4HandleWrite, NULL, &gCr4Hook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCrSetHook failed: 0x%08x!\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCr4Unprotect(
    void
    )
///
/// @brief      Disables the CR4 protection
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    if (NULL == gCr4Hook)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[CR4] Removing protection on CR4.SMEP and CR4.SMAP...\n");

    INTSTATUS status = IntHookCrRemoveHook(gCr4Hook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCrRemoveHook failed: 0x%08x\n", status);
        return status;
    }

    gCr4Hook = NULL;

    return INT_STATUS_SUCCESS;
}
