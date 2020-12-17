/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winidt.h"
#include "alerts.h"
#include "hook.h"


static INTSTATUS
IntWinIdtSendIntegrityAlert(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      Sends an #introEventIntegrityViolation alert for an IDT entry.
///
/// @param[in]  Victim      The victim information, as obtained from the exception mechanism.
/// @param[in]  Originator  Originator information, as obtained from the exception mechanism.
/// @param[in]  Action      The action that was taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    EVENT_INTEGRITY_VIOLATION *pEvent;

    pEvent = &gAlert.Integrity;
    memzero(pEvent, sizeof(*pEvent));

    pEvent->BaseAddress = Victim->Integrity.StartVirtualAddress;
    pEvent->VirtualAddress = Victim->Integrity.StartVirtualAddress + Victim->Integrity.Offset;
    pEvent->Size = gGuest.Guest64 ? IDT_DESC_SIZE64 : IDT_DESC_SIZE32;
    pEvent->Victim.IdtEntry = (BYTE)(Victim->Integrity.Offset / pEvent->Size);
    pEvent->Victim.Type = introObjectTypeIdt;

    // No valid CPU context and no valid current process can be obtained for this, as it is
    // an integrity alert.
    pEvent->Header.CpuContext.Valid = FALSE;
    pEvent->Header.CurrentProcess.Valid = FALSE;

    pEvent->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_IDT, Reason);
    pEvent->Header.Flags |= ALERT_FLAG_ASYNC;

    pEvent->Header.Action = Action;
    pEvent->Header.Reason = Reason;
    pEvent->Header.MitreID = idRootkit;

    memcpy(pEvent->Victim.Name, VICTIM_IDT, sizeof(VICTIM_IDT));

    IntAlertFillWriteInfo(Victim, &pEvent->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &pEvent->Originator.Module);

    IntAlertFillVersionInfo(&pEvent->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}

static INTSTATUS
IntWinIdtHandleModification(
    _Inout_ INTEGRITY_REGION *IntegrityRegion
    )
///
/// @brief          Handles IDT modifications detected by the integrity mechanism. This is the integrity callback set
/// by #IntWinIdtProtectOnCpuIntegrity.
///
/// When this callback is invoked, we know for sure that a change to the IDT was made, but we don't know exactly
/// what changed. This function will find the modified region, revert the changes and report the violation.
/// If the #INTRO_OPT_KM_BETA_DETECTIONS option is active, or if the IDT protection is set to log-only or feedback-only
/// the changes will not be reverted.
///
/// If the changes are allowed, the new contents of the protected region will be considered to be the original ones,
/// so if a further change is done (for example, if the guest restore the previous contents), a new alert will be
/// triggered.
///
/// @param[in, out] IntegrityRegion The integrity region that protects the IDT.
///
/// @returns        #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BOOLEAN recalculate = FALSE;

    STATS_ENTER(statsExceptionsKern);

    // Search for modifications
    for (DWORD offset = 0; offset < IntegrityRegion->Length;)
    {
        EXCEPTION_VICTIM_ZONE victim = { 0 };
        EXCEPTION_KM_ORIGINATOR originator = { 0 };
        INTRO_ACTION action = introGuestNotAllowed;
        INTRO_ACTION_REASON reason = introReasonUnknown;

        status = IntExceptGetVictimIntegrity(IntegrityRegion, &offset, &victim);
        if (INT_STATUS_NOT_FOUND == status)
        {
            // We are done with the modifications, so exit
            status = INT_STATUS_SUCCESS;
            break;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting integrity zone: 0x%08x\n", status);
            break;
        }

        status = IntExceptGetOriginatorFromModification(&victim, &originator);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
            break;
        }

        IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

        if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_IDT, &action, &reason))
        {
            IntWinIdtSendIntegrityAlert(&victim, &originator, action, reason);
        }

        if (IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_IDT, &action))
        {
            reason = introReasonAllowed;
        }

        if (action == introGuestAllowed)
        {
            recalculate = TRUE;
        }
        else if (action == introGuestNotAllowed)
        {
            IntPauseVcpus();

            status = IntKernVirtMemWrite(IntegrityRegion->Gva + victim.Integrity.Offset,
                                         victim.WriteInfo.AccessSize,
                                         (BYTE *)IntegrityRegion->OriginalContent + victim.Integrity.Offset);
            IntResumeVcpus();

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemWrite failed for gva 0x%016llx: 0x%08x\n",
                      IntegrityRegion->Gva + victim.Integrity.Offset, status);
                goto cleanup_and_exit;
            }
        }
    }

    if (recalculate)
    {
        IntIntegrityRecalculate(IntegrityRegion);
    }

cleanup_and_exit:
    STATS_EXIT(statsExceptionsKern);

    return status;
}


_Function_class_(PFUNC_EptViolationCallback)
static INTSTATUS
IntWinIdtWriteHandler(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief          Handles IDT modifications detected by the EPT mechanism. This is the EPT callback set
/// by #IntWinIdtProtectOnCpuEpt.
///
/// This function will check the exceptions mechanism and will decide if the write should be blocked and reported.
/// If the #INTRO_OPT_KM_BETA_DETECTIONS option is active, or if the IDT protection is set to log-only or feedback-only
/// the changes will not be reverted.
///
/// @param[in]  Context     Ignored.
/// @param[in]  Hook        The hook for which this callback was invoked. Ignored.
/// @param[in]  Address     The written guest physical address. Ignored.
/// @param[out] Action      The action that will be taken.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 if Action is NULL.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if we can not find a valid IDT for the guest linear address from #gVcpu.
///             In this case Action will be #introGuestAllowed.
///
{
    INTSTATUS status;
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTRO_ACTION_REASON reason;
    QWORD idtBase;
    QWORD idtLimit;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    status = IntGuestGetIdtFromGla(gVcpu->Gla, &idtBase, &idtLimit);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGuestGetIdtFromGla failed: 0x%08x, the write on 0x%016llx "
              "(gpa 0x%016llx) from cpu %d seems to be outside any idt!\n",
              status, gVcpu->Gla, gVcpu->Gpa, gVcpu->Index);

        *Action = introGuestAllowed;

        return INT_STATUS_NOT_NEEDED_HINT;
    }

    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;

    STATS_ENTER(statsExceptionsKern);

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
    }

    status = IntExceptGetVictimEpt(&idtBase,
                                   gVcpu->Gpa,
                                   gVcpu->Gla,
                                   introObjectTypeIdt,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        reason = introReasonInternalError;
    }

    IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_IDT, Action, &reason))
    {
        PEVENT_EPT_VIOLATION pEptViol = &gAlert.Ept;
        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idRootkit;

        pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_IDT, reason);

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        if (originator.Original.Driver)
        {
            IntAlertFillWinKmModule(originator.Original.Driver, &pEptViol->Originator.Module);
        }
        if (originator.Return.Driver)
        {
            IntAlertFillWinKmModule(originator.Return.Driver, &pEptViol->Originator.ReturnModule);
        }

        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        IntAlertFillWinProcessByCr3(gVcpu->Regs.Cr3, &pEptViol->Header.CurrentProcess);

        IntAlertFillCodeBlocks(originator.Original.Rip, gVcpu->Regs.Cr3, FALSE, &pEptViol->CodeBlocks);
        IntAlertFillExecContext(0, &pEptViol->ExecContext);

        IntAlertFillVersionInfo(&pEptViol->Header);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_IDT, Action);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinIdtProtectOnCpuEpt(
    _In_ DWORD CpuNumber
    )
///
/// @brief      Protects the IDT on a guest CPU against writes using an EPT hook.
///
/// This will set #IntWinIdtWriteHandler as the EPT violation handler and will protect the first 32 entries of the
/// IDT (or up to the IDT limit, if less than 32 entries are valid).
///
/// @param[in]  CpuNumber   The CPU on which to protect the IDT. Can not be #IG_CURRENT_VCPU.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the IDT for the given CPU is already protected.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD size;

    if (gGuest.VcpuArray[CpuNumber].IdtHookObject != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    TRACE("[HOOK] Adding IDT protection (EPT) on CPU %d at 0x%016llx (limit 0x%x)...\n",
          CpuNumber, gGuest.VcpuArray[CpuNumber].IdtBase, gGuest.VcpuArray[CpuNumber].IdtLimit);

    status = IntHookObjectCreate(introObjectTypeIdt, 0, &gGuest.VcpuArray[CpuNumber].IdtHookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        return status;
    }

    size = MIN((gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32) * 0x20,
               gGuest.VcpuArray[CpuNumber].IdtLimit + 1);

    status = IntHookObjectHookRegion(gGuest.VcpuArray[CpuNumber].IdtHookObject,
                                     0,
                                     gGuest.VcpuArray[CpuNumber].IdtBase,
                                     size,
                                     IG_EPT_HOOK_WRITE,
                                     IntWinIdtWriteHandler,
                                     NULL,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed hooking IDT at 0x%016llx for CPU %d: 0x%08x\n",
              gGuest.VcpuArray[CpuNumber].IdtBase, CpuNumber, status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinIdtProtectOnCpuIntegrity(
    _In_ DWORD CpuNumber
    )
///
/// @brief      Protects the IDT on a guest CPU against writes using the integrity mechanism.
///
/// This will set #IntWinIdtHandleModification as the EPT violation handler and will protect the first 32 entries of
/// the IDT (or up to the IDT limit, if less than 32 entries are valid).
///
/// @param[in]  CpuNumber   The CPU on which to protect the IDT. Can not be #IG_CURRENT_VCPU.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the IDT for the given CPU is already protected.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD size;

    if (gGuest.VcpuArray[CpuNumber].IdtIntegrityObject != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    TRACE("[HOOK] Adding IDT protection (Integrity) on CPU %d at 0x%016llx (limit 0x%x)...\n",
          CpuNumber, gGuest.VcpuArray[CpuNumber].IdtBase, gGuest.VcpuArray[CpuNumber].IdtLimit);

    size = MIN((gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32) * 0x20,
               gGuest.VcpuArray[CpuNumber].IdtLimit + 1);

    status = IntIntegrityAddRegion(gGuest.VcpuArray[CpuNumber].IdtBase,
                                   size,
                                   introObjectTypeIdt,
                                   NULL,
                                   IntWinIdtHandleModification,
                                   TRUE,
                                   &gGuest.VcpuArray[CpuNumber].IdtIntegrityObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to add IDT to integrity checks: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinIdtUnprotectOnCpuEpt(
    _In_ DWORD CpuNumber
    )
///
/// @brief      Removes the EPT write protection for a IDT.
///
/// This removes the hook set by #IntWinIdtProtectOnCpuEpt.
///
/// @param[in]  CpuNumber   The CPU on which to remove the protection.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the IDT is not protected using the EPT on this CPU.
///
{
    INTSTATUS status;

    if (gGuest.VcpuArray[CpuNumber].IdtHookObject == NULL)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[HOOK] Removing IDT protection (EPT) on CPU %d at 0x%016llx...\n", CpuNumber,
          gGuest.VcpuArray[CpuNumber].IdtBase);

    status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gGuest.VcpuArray[CpuNumber].IdtHookObject, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed removing idt hook object: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinIdtUnprotectOnCpuIntergity(
    _In_ DWORD CpuNumber
    )
///
/// @brief      Removes the integrity protection for a IDT.
///
/// This removes the integrity region set by #IntWinIdtProtectOnCpuIntegrity.
///
/// @param[in]  CpuNumber   The CPU on which to remove the protection.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the IDT is not protected using the EPT on this CPU.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (gGuest.VcpuArray[CpuNumber].IdtIntegrityObject == NULL)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[HOOK] Removing IDT protection (Integrity) on CPU %d at 0x%016llx...\n",
          CpuNumber, gGuest.VcpuArray[CpuNumber].IdtBase);

    status = IntIntegrityRemoveRegion(gGuest.VcpuArray[CpuNumber].IdtIntegrityObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08x\n", status);
        return status;
    }

    gGuest.VcpuArray[CpuNumber].IdtIntegrityObject = NULL;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinIdtProtectOnCpu(
    _In_ DWORD CpuNumber
    )
///
/// @brief      Protects the IDT against writes on a CPU.
///
/// For Windows versions older than 16299 or for 32-bit Windows versions the integrity mechanism is used because
/// the IDT and the GDT are placed in the same page on those versions, and the GDT is written very often, which will
/// end up causing performance problems, due to the high amount of VMEXITs that will be generated. The integrity
/// mechanism will not be able to catch a change as soon as it is done, as it does the checks periodically, and will
/// not be able to consult the exceptions mechanism.
/// For all the other Windows versions, an EPT write hook is placed on the IDT. We can do that because on those
/// versions the IDT is in its own page, so we can hook it without expecting a large number of VMEXITs, as the IDT
/// is not written very often.
///
/// @param[in]  CpuNumber   The CPU for which the IDT will be protected. Can not be #IG_CURRENT_VCPU.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     INT_STATUS_INVALID_PARAMETER_2 if CpuNumber is not valid.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the base of the IDT on the given CPU is not a valid kernel pointer.
///
{
    if (CpuNumber >= gGuest.CpuCount)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, gGuest.VcpuArray[CpuNumber].IdtBase))
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    // Windows version >= 16299
    if (gGuest.OSVersion >= 16299 && gGuest.Guest64)
    {
        return IntWinIdtProtectOnCpuEpt(CpuNumber);
    }
    else
    {
        return IntWinIdtProtectOnCpuIntegrity(CpuNumber);
    }
}


INTSTATUS
IntWinIdtUnprotectOnCpu(
    _In_ DWORD CpuNumber
    )
///
/// @brief      Removes the IDT write protection for a CPU.
///
/// @param[in]  CpuNumber   The CPU for which the protection is removed. Can not be #IG_CURRENT_VCPU.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     INT_STATUS_INVALID_PARAMETER_2 if CpuNumber is not valid.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if the base of the IDT on the given CPU is not a valid kernel pointer.
///
{
    if (CpuNumber >= gGuest.CpuCount)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, gGuest.VcpuArray[CpuNumber].IdtBase))
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (gGuest.OSVersion >= 16299 && gGuest.Guest64)
    {
        return IntWinIdtUnprotectOnCpuEpt(CpuNumber);
    }
    else
    {
        return IntWinIdtUnprotectOnCpuIntergity(CpuNumber);
    }
}


INTSTATUS
IntWinIdtProtectAll(
    void
    )
///
/// @brief      Activates the IDT protection for all the guest CPUs.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    DWORD i;
    INTSTATUS status;
    INTSTATUS failStatus;

    // In case there are no CPU's (which is never!)
    failStatus = INT_STATUS_NOT_NEEDED_HINT;

    for (i = 0; i < gGuest.CpuCount; i++)
    {
        status = IntWinIdtProtectOnCpu(i);
        if (!INT_SUCCESS(status))
        {
            failStatus = status;
            continue;
        }
    }

    return failStatus;
}


INTSTATUS
IntWinIdtUnprotectAll(
    void
    )
///
/// @brief      Removes the IDT protection for all the guest CPUs.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    DWORD i;
    INTSTATUS status;
    INTSTATUS failStatus;

    // In case there are no CPU's (which is never!)
    failStatus = INT_STATUS_NOT_NEEDED_HINT;

    for (i = 0; i < gGuest.CpuCount; i++)
    {
        status = IntWinIdtUnprotectOnCpu(i);
        if (!INT_SUCCESS(status))
        {
            failStatus = status;
            continue;
        }
    }

    return failStatus;
}
