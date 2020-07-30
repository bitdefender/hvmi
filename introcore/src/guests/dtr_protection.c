/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "dtr_protection.h"
#include "alerts.h"
#include "guests.h"
#include "hook_dtr.h"
#include "introcpu.h"
#include "winidt.h"
#include "lixidt.h"


static void *gIdtrHook; ///< The IDTR hook.
static void *gGdtrHook; ///< The GDTR hook.


static QWORD
IntDtrGetProtOption(
    _In_ INTRO_OBJECT_TYPE DtrType
    )
///
/// @brief Given a DTR object type, return the protection option which controls it.
///
/// @param[in]  DtrType The descriptor table register type.
///
/// @returns The protection option which enables/disables protection on that descriptor table register.
///
{
    switch (DtrType)
    {
    case introObjectTypeIdtr:
        return INTRO_OPT_PROT_KM_IDTR;
    case introObjectTypeGdtr:
        return INTRO_OPT_PROT_KM_GDTR;

    default:
        ERROR("[ERROR] Invalid dtr type: %d\n", DtrType);
    }

    return 0;
}


static INTSTATUS
IntDtrSendAlert(
    _In_ PEXCEPTION_VICTIM_ZONE Victim,
    _In_ PEXCEPTION_KM_ORIGINATOR Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Send an DTR alert.
///
/// This will send an #introEventDtrViolation to the integrator. These alerts are controlled by the
/// #INTRO_OPT_PROT_KM_IDTR and #INTRO_OPT_PROT_KM_GDTR options.
///
/// @param[in]  Victim      The victim zone, which identifies the written DTR.
/// @param[in]  Originator  The attacker, who modified the DTR.
/// @param[in]  Action      The desired action.
/// @param[in]  Reason      The action reason.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    EVENT_DTR_VIOLATION *pDtrViol = &gAlert.Dtr;

    memzero(pDtrViol, sizeof(*pDtrViol));

    pDtrViol->Header.Action = Action;
    pDtrViol->Header.Reason = Reason;

    pDtrViol->Header.Flags = IntAlertCoreGetFlags(IntDtrGetProtOption(Victim->Dtr.Type), Reason);
    pDtrViol->Header.MitreID = idRootkit;

    IntAlertDtrFill(Victim, Originator, pDtrViol);

    IntAlertFillCpuContext(TRUE, &pDtrViol->Header.CpuContext);

    if (introGuestLinux == gGuest.OSType)
    {
        IntAlertFillLixCurrentProcess(&pDtrViol->Header.CurrentProcess);
    }
    else if (introGuestWindows == gGuest.OSType)
    {
        IntAlertFillWinProcessByCr3(pDtrViol->Header.CpuContext.Cr3, &pDtrViol->Header.CurrentProcess);
    }

    IntAlertFillCodeBlocks(Originator->Original.Rip, gGuest.Mm.SystemCr3, FALSE, &pDtrViol->CodeBlocks);

    IntAlertFillVersionInfo(&pDtrViol->Header);

    IntAlertFillExecContext(pDtrViol->Header.CpuContext.Cr3, &pDtrViol->ExecContext);

    status = IntNotifyIntroEvent(introEventDtrViolation, pDtrViol, sizeof(*pDtrViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntDtrHandleWrite(
    _In_ DTR *OldDtr,
    _In_ DTR *NewDtr,
    _In_ DWORD Flags,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle an IDTR or GDTR modification.
///
/// This function will inspect if the IDTR or GDTR is being modified in a malicious way. In order to do so, it will
/// try to match the hard-coded PatchGuard signatures, and, if a match is not found, the exceptions mechanism will
/// be invoked. If a match is not found, the action will be blocked, and an alert will be sent.
///
/// @param[in]  OldDtr      Old DTR value.
/// @param[in]  NewDtr      New DTR value.
/// @param[in]  Flags       DTR access flags - see #IG_DESC_ACCESS.
/// @param[out] Action      The desired action.
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
    INTRO_OBJECT_TYPE type;

    UNREFERENCED_PARAMETER(Flags);

    exitAfterInformation = FALSE;

    // By default we do not allow this
    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    if (!!(Flags & IG_DESC_ACCESS_GDTR))
    {
        type = introObjectTypeGdtr;
    }
    else if (!!(Flags & IG_DESC_ACCESS_IDTR))
    {
        type = introObjectTypeIdtr;
    }
    else
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, EXCEPTION_KM_ORIGINATOR_OPT_DO_NOT_BLOCK);
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

    status = IntExceptGetVictimDtr(NewDtr, OldDtr, type, &victim);
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
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventDtrViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(IntDtrGetProtOption(type), Action, &reason))
    {
        IntDtrSendAlert(&victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(IntDtrGetProtOption(type), Action);

    if (introGuestNotAllowed != *Action)
    {
        if (introObjectTypeIdtr == type)
        {
            // Remove on this CPU the old IDT protection because the IDT base will be outdated
            if (introGuestLinux == gGuest.OSType)
            {
                IntLixIdtUnprotectAll();
            }
            else if (introGuestWindows == gGuest.OSType)
            {
                IntWinIdtUnprotectOnCpu(gVcpu->Index);
            }

            gVcpu->IdtBase = NewDtr->Base;
            gVcpu->IdtLimit = NewDtr->Limit;

            // Add on this CPU the new IDT protection with the updated IDT base
            if (introGuestLinux == gGuest.OSType)
            {
                status = IntLixIdtProtectAll();
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntLixIdtProtectAll failed. Status: %d\n", status);
                }
            }
            else if (introGuestWindows == gGuest.OSType)
            {
                IntWinIdtProtectOnCpu(gVcpu->Index);
            }
        }
        else if (introObjectTypeGdtr == type)
        {
            gVcpu->GdtBase = NewDtr->Base;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIdtrProtect(
    void
    )
///
/// @brief Enable IDTR protection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If DTR events are not supported.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If IDTR is already protected.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    PFUNC_DtrReadWriteHookCallback pCallback = NULL;

    if (!gGuest.SupportDTR)
    {
        WARNING("[WARNING] DTR events are not supported by the HV, will NOT protect IDTR!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL != gIdtrHook)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    pCallback = IntDtrHandleWrite;

    TRACE("[DTR] Adding protection on IDTR...\n");

    status = IntHookDtrSetHook(IG_DESC_ACCESS_IDTR | IG_DESC_ACCESS_WRITE, pCallback, &gIdtrHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed hooking the IDTR!\n");
        return status;
    }

    return status;
}


INTSTATUS
IntGdtrProtect(
    void
    )
///
/// @brief Enable GDTR protection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If DTR events are not supported.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT If GDTR is already protected.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    PFUNC_DtrReadWriteHookCallback pCallback = NULL;

    if (!gGuest.SupportDTR)
    {
        WARNING("[WARNING] DTR events are not supported by the HV, will NOT protect GDTR!\n");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL != gGdtrHook)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    pCallback = IntDtrHandleWrite;

    TRACE("[DTR] Adding protection on GDTR...\n");

    status = IntHookDtrSetHook(IG_DESC_ACCESS_GDTR | IG_DESC_ACCESS_WRITE, pCallback, &gGdtrHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed hooking the GDTR!\n");
        return status;
    }

    return status;
}


INTSTATUS
IntIdtrUnprotect(
    void
    )
///
/// @brief Remove the IDTR protection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If IDTR is not protected.
///
{
    if (NULL == gIdtrHook)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DTR] Removing protection on IDTR...\n");

    IntHookDtrRemoveHook(gIdtrHook);

    gIdtrHook = NULL;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGdtrUnprotect(
    void
    )
///
/// @brief Remove the GDTR protection.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If GDTR is not protected.
///
{
    if (NULL == gGdtrHook)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DTR] Removing protection on GDTR...\n");

    IntHookDtrRemoveHook(gGdtrHook);

    gGdtrHook = NULL;

    return INT_STATUS_SUCCESS;
}
