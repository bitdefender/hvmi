/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "msr_protection.h"
#include "alerts.h"
#include "guests.h"
#include "hook_msr.h"


static BOOLEAN gMsrHookSet;     ///< True if the SYSCALL/SYSENTER MSRs are protected.
static void *gSysenterEipHook;  ///< IA32_SYSENTER_EIP hook.
static void *gSysenterEspHook;  ///< IA32_SYSENTER_ESP hook.
static void *gSysenterCsHook;   ///< IA32_SYSENTER_CS hook.
static void *gSyscallLstarHook; ///< IA32_LSTAR hook.
static void *gSyscallStarHook;  ///< IA32_STAR hook.


static INTSTATUS
IntWinMsrSendAlert(
    _In_ PEXCEPTION_VICTIM_ZONE Victim,
    _In_ PEXCEPTION_KM_ORIGINATOR Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Send an MSR alert.
///
/// This will send an #introEventMsrViolation to the integrator. These alerts are controlled by the
/// #INTRO_OPT_ENABLE_MSR_PROTECTION option.
///
/// @param[in]  Victim      The victim zone, which identifies the written MSR.
/// @param[in]  Originator  The attacker, who modified the MSR.
/// @param[in]  Action      The desired action.
/// @param[in]  Reason      The action reason.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PEVENT_MSR_VIOLATION pMsrViol;

    pMsrViol = &gAlert.Msr;
    memzero(pMsrViol, sizeof(*pMsrViol));

    pMsrViol->Header.Action = Action;
    pMsrViol->Header.Reason = Reason;

    pMsrViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_MSR_SYSCALL, Reason);
    pMsrViol->Header.MitreID = idRootkit;

    IntAlertMsrFill(Victim, Originator, pMsrViol);

    IntAlertFillCpuContext(TRUE, &pMsrViol->Header.CpuContext);

    IntAlertFillWinProcessByCr3(pMsrViol->Header.CpuContext.Cr3, &pMsrViol->Header.CurrentProcess);

    IntAlertFillCodeBlocks(Originator->Original.Rip, gGuest.Mm.SystemCr3, FALSE, &pMsrViol->CodeBlocks);
    IntAlertFillExecContext(gGuest.Mm.SystemCr3, &pMsrViol->ExecContext);

    IntAlertFillVersionInfo(&pMsrViol->Header);

    status = IntNotifyIntroEvent(introEventMsrViolation, pMsrViol, sizeof(*pMsrViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntLixMsrHandleWrite(
    _In_ DWORD Msr,
    _In_ DWORD Flags,
    _Out_ INTRO_ACTION *Action,
    _In_opt_ void *Context,
    _In_opt_ QWORD OriginalValue,
    _In_opt_ const QWORD *NewValue
    )
///
/// @brief Handles a model specific register write attempt done by a Linux guest.
///
/// Will analyze the write and will decide if it is malicious. If the attempt is deemed malicious, Introcore will send
/// an alert, unless an exception matches this write.
///
/// @param[in]  Msr             The written MSR.
/// @param[in]  Flags           Access flags.
/// @param[out] Action          The action that must be taken.
/// @param[in]  Context         Unused.
/// @param[in]  OriginalValue   The old, original value of the register. If the action is blocked, the register will
///                             keep this value.
/// @param[in]  NewValue        The written value.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    BOOLEAN exitAfterInformation;
    INTRO_ACTION_REASON reason;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Context);

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == NewValue)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    // If the MSR is sysenter/syscall MSR, and the OldValue is zero, we allow the write.
    if (((Msr == IG_IA32_SYSENTER_CS) || (Msr == IG_IA32_SYSENTER_EIP) ||
         (Msr == IG_IA32_SYSENTER_ESP) || (Msr == IG_IA32_STAR) || (Msr == IG_IA32_LSTAR)) &&
        (0 == OriginalValue))
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    // If the same value is written again in the MSR, we're done.
    if (OriginalValue == *NewValue)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsExceptionsKern);

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;
    exitAfterInformation = FALSE;

    memzero(&originator, sizeof(originator));
    memzero(&victim, sizeof(victim));

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimMsr(*NewValue, OriginalValue, Msr, &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventMsrViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_MSR_SYSCALL, Action, &reason))
    {
        EVENT_MSR_VIOLATION *pMsrViol = &gAlert.Msr;

        memzero(pMsrViol, sizeof(*pMsrViol));

        pMsrViol->Header.Action = *Action;
        pMsrViol->Header.Reason = reason;

        IntAlertFillCpuContext(TRUE, &pMsrViol->Header.CpuContext);

        pMsrViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_MSR_SYSCALL, reason);
        pMsrViol->Header.MitreID = idRootkit;

        IntAlertFillLixCurrentProcess(&pMsrViol->Header.CurrentProcess);

        IntAlertFillLixKmModule(originator.Original.Driver, &pMsrViol->Originator.Module);
        IntAlertFillLixKmModule(originator.Return.Driver, &pMsrViol->Originator.ReturnModule);

        pMsrViol->Victim.Msr = Msr;

        pMsrViol->WriteInfo.NewValue[0] = *NewValue;
        pMsrViol->WriteInfo.OldValue[0] = OriginalValue;

        IntAlertFillVersionInfo(&pMsrViol->Header);

        IntAlertFillCodeBlocks(originator.Original.Rip, gGuest.Mm.SystemCr3, FALSE, &pMsrViol->CodeBlocks);
        IntAlertFillExecContext(gGuest.Mm.SystemCr3, &pMsrViol->ExecContext);

        status = IntNotifyIntroEvent(introEventMsrViolation, pMsrViol, sizeof(*pMsrViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_MSR_SYSCALL, Action);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinMsrHandleWrite(
    _In_ DWORD Msr,
    _In_ DWORD Flags,
    _Out_ INTRO_ACTION *Action,
    _In_opt_ void *Context,
    _In_opt_ QWORD OriginalValue,
    _In_opt_ const QWORD *NewValue
    )
///
/// @brief Handles a model specific register write attempt done by a Windows guest.
///
/// Will analyze the write and will decide if it is malicious. If the attempt is deemed malicious, Introcore will send
/// an alert, unless an exception matches this write.
///
/// @param[in]  Msr             The written MSR.
/// @param[in]  Flags           Access flags.
/// @param[out] Action          The action that must be taken.
/// @param[in]  Context         Unused.
/// @param[in]  OriginalValue   The old, original value of the register. If the action is blocked, the register will
///                             keep this value.
/// @param[in]  NewValue        The written value.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    BOOLEAN exitAfterInformation;
    INTRO_ACTION_REASON reason;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(Context);

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == NewValue)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    // LAN: If the MSR is sysenter/syscall MSR, and the OldValue is zero, we allow the write.
    if (((Msr == IG_IA32_SYSENTER_CS) || (Msr == IG_IA32_SYSENTER_EIP) ||
         (Msr == IG_IA32_SYSENTER_ESP) || (Msr == IG_IA32_STAR) || (Msr == IG_IA32_LSTAR)) &&
        (0 == OriginalValue))
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    // If the same value is written again in the MSR, we're done.
    if (OriginalValue == *NewValue)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsExceptionsKern);

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    // By default we do not allow this
    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;
    exitAfterInformation = FALSE;

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimMsr(*NewValue, OriginalValue, Msr, &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventMsrViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_MSR_SYSCALL, Action, &reason))
    {
        IntWinMsrSendAlert(&victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_MSR_SYSCALL, Action);

    return status;
}


INTSTATUS
IntMsrSyscallProtect(
    void
    )
///
/// @brief Enable protection for all SYSCALL and SYSENTER MSRs.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If the MSR hooks have already been set.
///
{
    INTSTATUS status;
    BOOLEAN hookX64Msrs, hookX86Msrs;
    PFUNC_MsrReadWriteHookCallback pCallback;

    if (gMsrHookSet)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        hookX64Msrs = gGuest.Guest64;
        hookX86Msrs = !hookX64Msrs;

        pCallback = IntWinMsrHandleWrite;
    }
    else
    {
        hookX64Msrs = hookX86Msrs = TRUE;

        pCallback = IntLixMsrHandleWrite;
    }

    if (hookX86Msrs)
    {
        TRACE("[MSR] Adding protection on MSR IA32_SYSENTER_EIP...\n");

        status = IntHookMsrSetHook(IG_IA32_SYSENTER_EIP, IG_MSR_HOOK_WRITE, pCallback, NULL, &gSysenterEipHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking the MSR!\n");
            return status;
        }


        TRACE("[MSR] Adding protection on MSR IA32_SYSENTER_ESP...\n");

        status = IntHookMsrSetHook(IG_IA32_SYSENTER_ESP, IG_MSR_HOOK_WRITE, pCallback, NULL, &gSysenterEspHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking the MSR!\n");
            return status;
        }


        TRACE("[MSR] Adding protection on MSR IA32_SYSENTER_CS...\n");

        status = IntHookMsrSetHook(IG_IA32_SYSENTER_CS, IG_MSR_HOOK_WRITE, pCallback, NULL, &gSysenterCsHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking the MSR!\n");
            return status;
        }
    }

    if (hookX64Msrs)
    {
        TRACE("[MSR] Adding protection on MSR IA32_STAR...\n");

        status = IntHookMsrSetHook(IG_IA32_STAR, IG_MSR_HOOK_WRITE, pCallback, NULL, &gSyscallStarHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking the MSR!\n");
            return status;
        }

        TRACE("[MSR] Adding protection on MSR IA32_LSTAR...\n");

        status = IntHookMsrSetHook(IG_IA32_LSTAR, IG_MSR_HOOK_WRITE, pCallback, NULL, &gSyscallLstarHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking the MSR!\n");
            return status;
        }
    }

    gMsrHookSet = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntMsrSyscallUnprotect(
    void
    )
///
/// @brief Remove protection from all protected MSRs.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the MSRs have not been hooked yet.
///
{
    if (!gMsrHookSet)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL != gSyscallLstarHook)
    {
        TRACE("[MSR] Removing protection on MSR IA32_LSTAR...\n");

        IntHookMsrRemoveHook(gSyscallLstarHook);

        gSyscallLstarHook = NULL;
    }

    if (NULL != gSyscallStarHook)
    {
        TRACE("[MSR] Removing protection on MSR IA32_STAR...\n");

        IntHookMsrRemoveHook(gSyscallStarHook);

        gSyscallStarHook = NULL;
    }

    if (NULL != gSysenterCsHook)
    {
        TRACE("[MSR] Removing protection on MSR IA32_SYSENTER_CS...\n");

        IntHookMsrRemoveHook(gSysenterCsHook);

        gSysenterCsHook = NULL;
    }

    if (NULL != gSysenterEipHook)
    {
        TRACE("[MSR] Removing protection on MSR IA32_SYSENTER_Eip...\n");

        IntHookMsrRemoveHook(gSysenterEipHook);

        gSysenterEipHook = NULL;
    }

    if (NULL != gSysenterEspHook)
    {
        TRACE("[MSR] Removing protection on MSR IA32_SYSENTER_ESP...\n");

        IntHookMsrRemoveHook(gSysenterEspHook);

        gSysenterEspHook = NULL;
    }

    gMsrHookSet = FALSE;

    return INT_STATUS_SUCCESS;
}
