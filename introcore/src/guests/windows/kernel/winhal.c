/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "drivers.h"
#include "winhal.h"
#include "alerts.h"
#include "decoder.h"
#include "hook.h"
#include "winpe.h"
#include "swapmem.h"

#define HAL_HEAP_PROT_PAGES_EXEC    0x20    ///< The number of HAL heap pages to protect against executions

/// @brief  The HAL information.
static WIN_HAL_DATA gHalData = { 0 };


static void
IntWinHalSendAlert(
    _In_ EXCEPTION_VICTIM_ZONE const *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR const *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief  Sends an #introEventEptViolation for HAL alerts.
///
/// @param[in]  Victim      Victim information.
/// @param[in]  Originator  Originator information.
/// @param[in]  Action      The action taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
{
    INTSTATUS status;
    PEVENT_EPT_VIOLATION pEptViol;
    PIG_ARCH_REGS regs;

    regs = &gVcpu->Regs;

    pEptViol = &gAlert.Ept;
    memzero(pEptViol, sizeof(*pEptViol));

    pEptViol->Header.Action = Action;
    pEptViol->Header.Reason = Reason;
    pEptViol->Header.MitreID = idRootkit;

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

    IntAlertEptFillFromKmOriginator(Originator, pEptViol);
    IntAlertEptFillFromVictimZone(Victim, pEptViol);

    pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_HAL_INT_CTRL, Reason);

    IntAlertFillWinProcessByCr3(regs->Cr3, &pEptViol->Header.CurrentProcess);

    IntAlertFillCodeBlocks(Originator->Original.Rip, regs->Cr3, FALSE, &pEptViol->CodeBlocks);
    IntAlertFillExecContext(0, &pEptViol->ExecContext);

    IntAlertFillVersionInfo(&pEptViol->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static INTSTATUS
IntWinHalHandleHalIntCtrlWrite(
    _Inout_ KERNEL_DRIVER *Context,
    _In_ HOOK_GPA const *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief      Handles writes done over the HAL interrupt controller.
///
/// This is the EPT write hook set by #IntWinHalProtectHalIntCtrl.
///
/// @param[in]  Context     The context set by #IntWinHalProtectHalIntCtrl. This will be the hal.dll #KERNEL_DRIVER.
/// @param[in]  Hook        The hook for which this callback was invoked.
/// @param[in]  Address     The accessed physical address.
/// @param[out] Action      The action to be taken.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Context is NULL.
///
{
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTSTATUS status;
    INTRO_ACTION_REASON reason;
    BOOLEAN exitAfterInformation;

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
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
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(Context,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeHalIntController,
                                   ZONE_WRITE,
                                   &victim);
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
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_HAL_INT_CTRL, Action, &reason))
    {
        IntWinHalSendAlert(&victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_HAL_INT_CTRL, Action);

    return status;
}


static INTSTATUS
IntWinHalHandleHalHeapExec(
    _In_opt_ void *Context,
    _Inout_ HOOK_GPA *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief          Handles execution attempts from the HAL heap.
///
/// This is the EPT hook handler set by #IntWinHalProtectHalHeapExecs. If execution comes from a CPU that is in
/// real mode it is allowed, as it will be the result of an IPI sent at boot in order to wake up an AP.
/// If there is an exception for the executed code, the execution is allowed, and the hook will be removed.
///
/// @param[in]      Context The context set by #IntWinHalProtectHalHeapExecs. Ignored.
/// @param[in, out] Hook    The hook for which this callback was invoked.
/// @param[in]      Address The accessed physical address.
/// @param[out]     Action  The action to be taken.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    QWORD gva;
    EXCEPTION_KM_ORIGINATOR originator;
    EXCEPTION_VICTIM_ZONE victim;
    INTRO_ACTION_REASON reason;
    PBYTE memoryArea;
    DWORD memAreaLength;
    DWORD csType;
    DWORD instructionStart;
    BOOLEAN foundVMCALL;
    BYTE buffer[1] = { 0xC3 };
    BOOLEAN exitAfterInformation = FALSE;

    UNREFERENCED_PARAMETER(Context);

    gva = IntHookGetGlaFromGpaHook(Hook, Address);
    memoryArea = NULL;
    memAreaLength = 0;
    foundVMCALL = FALSE;
    *Action = introGuestNotAllowed;
    reason = introReasonNoException;

    LOG("[HAL] Code from hal heap (GVA 0x%016llx --- GPA 0x%016llx) has been executed from 0x%016llx.\n",
        gva, Address, gVcpu->Regs.Rip
       );

    status = IntGetCurrentMode(gVcpu->Index, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
    }

    // When there are multiple processors, IPIs are sent between them and real mode execution may occur.
    // for now, allow these executions
    // Also check cs type. If it's 16 bits it is probably the AP bootloader.
    if ((gVcpu->Regs.Cr0 & CR0_PE) == 0 || csType == IG_CS_TYPE_16B)
    {
        TRACE("[HAL] Real mode execution detected.\n");
        IntHookRemoveChain(Hook);
        *Action = introGuestRetry;
        return INT_STATUS_SUCCESS;
    }

    // Allocate 2 pages, but only scan one. avoid problems with instructions spanned over 2 pages.
    memoryArea = HpAllocWithTag(2 * PAGE_SIZE, IC_TAG_HAL_HEAP);
    if (NULL == memoryArea)
    {
        goto no_vmcall;
    }

    status = IntKernVirtMemRead(gva & PAGE_MASK, 2 * PAGE_SIZE, memoryArea, &memAreaLength);
    if ((!INT_SUCCESS(status)) && (0 == memAreaLength))
    {
        WARNING("[WARNING] IntKernVirtMemRead failed: %08x\n", status);
        HpFreeAndNullWithTag(&memoryArea, IC_TAG_HAL_HEAP);
        goto no_vmcall;
    }

    memAreaLength = MIN(memAreaLength, PAGE_SIZE);

    instructionStart = Address & PAGE_OFFSET;

    while (instructionStart < memAreaLength)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstructionFromBuffer(memoryArea + instructionStart,
                                                   memAreaLength - instructionStart, csType, &instrux);
        if (!INT_SUCCESS(status))
        {
            instructionStart++;
            continue;
        }

        if (ND_INS_VMCALL == instrux.Instruction)
        {
            foundVMCALL = TRUE;
            break;
        }

        instructionStart += instrux.Length;
    }

    HpFreeAndNullWithTag(&memoryArea, IC_TAG_HAL_HEAP);

    // We found a VMCALL, suppose it is the hypercall page. disable the hook on this specific page.
    if (foundVMCALL)
    {
        LOG("[HAL] Page %llx (physical %llx) seems to be the hypercall page. Will stop monitoring it...\n",
            gva, Address);
        IntHookRemoveChain(Hook);
        *Action = introGuestRetry;
        return INT_STATUS_SUCCESS;
    }

no_vmcall:
    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptKernelGetOriginator failed: %08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(Hook, Address, gva, introObjectTypeHalHeap, ZONE_EXECUTE, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed: %08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_HAL_HEAP_EXEC, Action, &reason))
    {
        EVENT_EPT_VIOLATION *pEptViol = &gAlert.Ept;
        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idExploitRemote;

        pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_HAL_HEAP_EXEC, reason);

        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        IntAlertEptFillFromKmOriginator(&originator, pEptViol);

        // Do not fill code blocks, as there are not enough instructions (no code should normally be there)

        IntAlertFillExecContext(gGuest.Mm.SystemCr3, &pEptViol->ExecContext);
        IntAlertFillVersionInfo(&pEptViol->Header);
        IntAlertFillWinProcessCurrent(&pEptViol->Header.CurrentProcess);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_HAL_HEAP_EXEC, Action);

    if (introGuestNotAllowed == *Action)
    {
        // Inject a ret instruction and let it execute
        status = IntKernVirtMemWrite(gva, sizeof(buffer), buffer);
        if (INT_SUCCESS(status))
        {
            LOG("[HAL] Injecting ret instruction @ GVA 0x%016llx\n", gva);
            *Action = introGuestAllowed;
            reason = introReasonAllowed;
        }
        else
        {
            ERROR("[ERROR] Could not inject ret! Status: %08x\n", status);
            *Action = introGuestNotAllowed;
            reason = introReasonNoException;
        }
    }
    else if (!IntPolicyCoreIsOptionBeta(INTRO_OPT_PROT_KM_HAL_HEAP_EXEC))
    {
        // Remove the hook if it was excepted. If we don't do this we will have an exit for every instruction in this
        // chunk and we will have to except it every time.
        IntHookRemoveChain(Hook);
        *Action = introGuestRetry;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinHalHandleDispatchTableWrite(
    _Inout_ PINTEGRITY_REGION IntegrityRegion
    )
///
/// @brief          Handles modifications done to the HAL dispatch table.
///
/// This is the integrity callback set by #IntWinHalProtectHalDispatchTable.
///
/// @param[in, out] IntegrityRegion The integrity region used to protect the HAL dispatch table.
///
/// @returns        #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BYTE const *pOriginal = NULL;
    PBYTE pPage = NULL;
    BOOLEAN bOnePage = FALSE;
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    BOOLEAN isBeta = IntPolicyCoreIsOptionBeta(INTRO_OPT_PROT_KM_HAL_DISP_TABLE);

    pOriginal = IntegrityRegion->OriginalContent;
    action = introGuestNotAllowed;
    reason = introReasonUnknown;

    bOnePage =
        (((IntegrityRegion->Gva + IntegrityRegion->Length - 1) & PAGE_MASK) == (IntegrityRegion->Gva & PAGE_MASK));

    status = IntVirtMemMap(IntegrityRegion->Gva, IntegrityRegion->Length, gGuest.Mm.SystemCr3, 0, &pPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to map GVA 0x%016llx: 0x%x\n", IntegrityRegion->Gva, status);
        goto _cleanup_and_exit;
    }

    for (DWORD offset = 0; offset < IntegrityRegion->Length; offset += gGuest.WordSize)
    {
        EXCEPTION_VICTIM_ZONE victim;
        EXCEPTION_KM_ORIGINATOR originator;
        QWORD originalValue = 0;
        QWORD newValue = 0;

        if (gGuest.Guest64)
        {
            originalValue = *(QWORD *)((size_t)pOriginal + (size_t)offset);
            newValue = *(QWORD *)((size_t)pPage + (size_t)offset);
        }
        else
        {
            originalValue = *(DWORD *)((size_t)pOriginal + (size_t)offset);
            newValue = *(DWORD *)((size_t)pPage + (size_t)offset);
        }

        if (newValue != originalValue)
        {
            DWORD currentOffset = offset;

            memzero(&victim, sizeof(victim));

            memzero(&originator, sizeof(originator));

            status = IntExceptGetVictimIntegrity(IntegrityRegion, &currentOffset, &victim);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntExceptGetVictimIntegrity failed: 0x%08x\n", status);
            }

            status = IntExceptGetOriginatorFromModification(&victim, &originator);
            if (!INT_SUCCESS(status))
            {
                TRACE("[INFO] IntExceptGetOriginatorFromModification failed: 0x%08x\n", status);
                if (status == INT_STATUS_EXCEPTION_BLOCK)
                {
                    action = introGuestNotAllowed;
                    reason = introReasonNoException;
                }

                // don't propagate the error
                status = INT_STATUS_SUCCESS;
            }

            LOG("[INTEGRITY VIOLATION] HalDispatchTable modification at 0x%016llx : 0x%x "
                "(index %d). New Value = 0x%016llx, Old Value = 0x%016llx\n",
                IntegrityRegion->Gva, offset, offset / gGuest.WordSize, newValue, originalValue);

            if (isBeta)
            {
                LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (B) ROOTKIT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
            }
            else
            {
                LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ROOTKIT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
            }

            if (!isBeta)
            {
                // restore the contents atomically
                if (gGuest.Guest64)
                {
                    _InterlockedExchange64((INT64 *)(pPage + offset), originalValue);
                }
                else
                {
                    _InterlockedExchange((INT32 *)(pPage + offset), (INT32)originalValue);
                }

                // This is needed because on multiple pages, pPage is not really a map to guest memory, it is
                // memory copied from a GVA to an allocated HVA, so modifications on this will not reflect on
                // guest if we don't write it explicitly
                if (!bOnePage)
                {
                    IntKernVirtMemWrite(IntegrityRegion->Gva + offset, gGuest.WordSize, pPage + offset);
                }
            }
            else
            {
                action = introGuestAllowed;
                // The action will be BETA detected, it will be allowed by default, so there is no use of
                // specifying it in the reason while the BETA flag is specified in the alert.
                reason = introReasonAllowed;

                // We let the modifications happen if BETA alerts are enabled and we don't want to SPAM the same
                // alert every time.
                status = IntIntegrityRecalculate(IntegrityRegion);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIntegrityRecalculate failed: 0x%x\n", status);
                    status = INT_STATUS_SUCCESS;    // don't propagate this error
                }
            }

            // send one alert for every modified pointer
            {
                PEVENT_INTEGRITY_VIOLATION pIntViolation = &gAlert.Integrity;

                memzero(pIntViolation, sizeof(*pIntViolation));

                pIntViolation->Header.Action = action;
                pIntViolation->Header.Reason = reason;
                pIntViolation->Header.MitreID = idExploitPrivEsc;

                pIntViolation->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_HAL_DISP_TABLE, reason);
                pIntViolation->Header.Flags |= ALERT_FLAG_ASYNC;

                pIntViolation->Header.CpuContext.Valid = FALSE;

                IntAlertFillWinProcessCurrent(&pIntViolation->Header.CurrentProcess);

                pIntViolation->Victim.Type = introObjectTypeHalDispatchTable;

                IntAlertFillWinKmModule(originator.Original.Driver, &pIntViolation->Originator.Module);

                memcpy(pIntViolation->Victim.Name, VICTIM_HAL_DISPATCH_TABLE, sizeof(VICTIM_HAL_DISPATCH_TABLE));

                pIntViolation->WriteInfo.Size = gGuest.WordSize;
                pIntViolation->WriteInfo.OldValue[0] = originalValue;
                pIntViolation->WriteInfo.NewValue[0] = newValue;

                pIntViolation->Size = gGuest.WordSize;
                pIntViolation->BaseAddress = IntegrityRegion->Gva;
                pIntViolation->VirtualAddress = IntegrityRegion->Gva + offset;

                IntAlertFillVersionInfo(&pIntViolation->Header);

                IntNotifyIntroEvent(introEventIntegrityViolation, pIntViolation, sizeof(*pIntViolation));
            }
        }
    }

_cleanup_and_exit:
    if (NULL != pPage)
    {
        IntVirtMemUnmap(&pPage);
    }

    return status;
}


static void
IntWinHalSendPerfCntIntegrityAlert(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends an #introEventIntegrityViolation for detections of writes over HalPerformanceCounter.
///
/// @param[in]  Victim      Victim information.
/// @param[in]  Originator  Originator information.
/// @param[in]  Action      The action taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
{
    INTSTATUS status;
    PEVENT_INTEGRITY_VIOLATION pIntViol;

    pIntViol = &gAlert.Integrity;
    memzero(pIntViol, sizeof(*pIntViol));

    pIntViol->BaseAddress = Victim->Integrity.StartVirtualAddress;
    pIntViol->VirtualAddress = Victim->Integrity.StartVirtualAddress + Victim->Integrity.Offset;
    pIntViol->Victim.Type = Victim->Object.Type;
    pIntViol->Size = Victim->Integrity.TotalLength;

    pIntViol->Header.Flags |= IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_HAL_PERF_CNT, Reason);

    // Force de-activation of ALERT_FLAG_NOT_RING0. We're always in ring0.
    pIntViol->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

    if (gGuest.KernelBetaDetections)
    {
        pIntViol->Header.Flags |= ALERT_FLAG_BETA;
    }

    pIntViol->Header.Flags |= ALERT_FLAG_ASYNC;

    pIntViol->Header.Action = Action;
    pIntViol->Header.Reason = Reason;
    pIntViol->Header.MitreID = idRootkit;

    memcpy(pIntViol->Victim.Name, VICTIM_HAL_PERFORMANCE_COUNTER, sizeof(VICTIM_HAL_PERFORMANCE_COUNTER));

    IntAlertFillWriteInfo(Victim, &pIntViol->WriteInfo);

    IntAlertFillWinKmModule(Originator->Original.Driver, &pIntViol->Originator.Module);

    IntAlertFillCpuContext(FALSE, &pIntViol->Header.CpuContext);

    // We can't know from what CPU the write was, but we know where the integrity check failed
    pIntViol->Header.CpuContext.Valid = FALSE;

    IntAlertFillWinProcessByCr3(pIntViol->Header.CpuContext.Cr3, &pIntViol->Header.CurrentProcess);

    IntAlertFillVersionInfo(&pIntViol->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViol, sizeof(*pIntViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static INTSTATUS
IntWinHalHandlePerfCounterModification(
    _Inout_ INTEGRITY_REGION *IntegrityRegion
    )
///
/// @brief Integrity callback for detections of modifications over HalPerformanceCounter.
///
/// When a modification is detected over HalPerformanceCounter protected area (more specifically, over the
/// protected function which gets called on KeQueryPerformanceCounter) on the timer check, this function will 
/// get called. In this function, all the detection logic is made for the HalPerformanceCounter protection,
/// as well as the decision whether this modification is legitimate or not. If the modification is deemed as not
/// legitimate and the policy implies blocking of such attempts, the old value will be overwritten over the
/// modified zone.
///
/// @param[in, out] IntegrityRegion The #INTEGRITY_REGION describing the protected zone.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    INTSTATUS status;
    DWORD offset = 0;
    BOOLEAN exitAfterInformation = FALSE;
    INTRO_ACTION_REASON reason;
    INTRO_ACTION action;

    STATS_ENTER(statsExceptionsKern);

    action = introGuestNotAllowed;
    reason = introReasonUnknown;

    status = IntExceptGetVictimIntegrity(IntegrityRegion, &offset, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting integrity zone: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetOriginatorFromModification(&victim, &originator);
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

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_HAL_PERF_CNT, &action, &reason))
    {
        IntWinHalSendPerfCntIntegrityAlert(&victim, &originator, action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_HAL_PERF_CNT, &action);

    if (action == introGuestAllowed)
    {
        IntIntegrityRecalculate(IntegrityRegion);
    }
    else if (action == introGuestNotAllowed)
    {
        IntPauseVcpus();

        status = IntKernVirtMemWrite(gHalData.HalPerfCounterAddress + WIN_KM_FIELD(Ungrouped, HalPerfCntFunctionOffset),
                                     gGuest.WordSize,
                                     IntegrityRegion->OriginalContent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemPatchWordSize failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    return INT_STATUS_SUCCESS;

}


INTSTATUS
IntWinHalProtectHalHeapExecs(
    void
    )
///
/// @brief      Hooks the HAL heap against execution.
///
/// This will protect the first 16 pages from the HAL heap. Based on the Windows version, some of them already have
/// the NX bit set inside the guest page tables.
/// #IntWinHalHandleHalHeapExec will be set as the EPT hook handler.
/// Pages that translate to physical address 0 or that are not present are not hooked.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if the HAL heap is already protected.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the HAL heap is not yet initialized.
///
{
    INTSTATUS status;
    QWORD hookAddrStart, hookAddrEnd;

    if (gHalData.HalHeapExecHook != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    // The HalHeap is not initialized, no need to hook it.
    if (0 == gHalData.HalHeapAddress)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[HAL] Adding Hal Heap hook at %llx...\n", gHalData.HalHeapAddress);

    hookAddrStart = gHalData.HalHeapAddress;
    hookAddrEnd = hookAddrStart + gHalData.HalHeapSize;

    status = IntHookObjectCreate(introObjectTypeHalHeap, 0, &gHalData.HalHeapExecHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        return status;
    }

    for (QWORD gva = hookAddrStart; gva < hookAddrEnd; gva += PAGE_SIZE)
    {
        BYTE r, w, x;
        QWORD gpa = 0;

        status = IntTranslateVirtualAddress(gva, gGuest.Mm.SystemCr3, &gpa);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Cannot protect hal heap page 0x%016llx\n", gva);
            continue;
        }

        status = IntGetEPTPageProtection(gGuest.UntrustedEptIndex, gpa, &r, &w, &x);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Cannot protect hal heap page 0x%016llx (GPA 0x%016llx)\n", gva, gpa);
            continue;
        }

        if (gpa < PAGE_SIZE)
        {
            WARNING("[WARNING] Will not protect hal heap page 0x%016llx because it translates to physical page 0\n",
                    gva);
            continue;
        }

        status = IntHookObjectHookRegion(gHalData.HalHeapExecHook,
                                         0,
                                         gva,
                                         PAGE_SIZE,
                                         IG_EPT_HOOK_EXECUTE,
                                         IntWinHalHandleHalHeapExec,
                                         NULL,
                                         0,
                                         NULL);

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: %08x Region (0x%016llx, 0x%016llx)\n",
                  status, gva, gva + PAGE_SIZE);
        }
        else
        {
            TRACE("[HAL] Hooking region (0x%016llx, 0x%016llx) against executions\n", gva, gva + PAGE_SIZE);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinHalUnprotectHalHeapExecs(
    void
    )
///
/// @brief      Deactivates the HAL heap execution protection.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gHalData.HalHeapExecHook == NULL)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    TRACE("[HAL] Removing Hal Heap hook...\n");

    status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gHalData.HalHeapExecHook, 0);

    return status;
}


INTSTATUS
IntWinHalProtectHalIntCtrl(
    void
    )
///
/// @brief      Protects the HAL interrupt controller against writes.
///
/// Will set #IntWinHalHandleHalIntCtrlWrite as the EPT hook callback.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gHalData.HalIntCtrlWriteHook != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (0 == gHalData.HalIntCtrlAddress)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[HAL] Adding Hal Interrupt Controller hook at %llx...\n", gHalData.HalIntCtrlAddress);

    status = IntHookObjectCreate(introObjectTypeHalIntController, 0, &gHalData.HalIntCtrlWriteHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        return status;
    }

    status = IntHookObjectHookRegion(gHalData.HalIntCtrlWriteHook,
                                     0,
                                     gHalData.HalIntCtrlAddress,
                                     WIN_KM_FIELD(Ungrouped, HalIntCtrlType),
                                     IG_EPT_HOOK_WRITE,
                                     IntWinHalHandleHalIntCtrlWrite,
                                     gHalData.OwnerHalModule,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
        return status;
    }

    return status;
}


INTSTATUS
IntWinHalUnprotectHalIntCtrl(
    void
    )
///
/// @brief      Deactivates the HAL interrupt controller write protection.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gHalData.HalIntCtrlWriteHook == NULL)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    TRACE("[HAL] Removing Hal Interrupt Controller hook...\n");

    status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gHalData.HalIntCtrlWriteHook, 0);

    return status;
}


INTSTATUS
IntWinHalProtectHalDispatchTable(
    void
    )
///
/// @brief      Activates the HAL dispatch table protection.
///
/// Will set #IntWinHalHandleDispatchTableWrite as the EPT hook handler.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gHalData.HalDispatchIntegrityHook != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (0 == gHalData.HalDispatchTableAddress)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    TRACE("[HAL] Adding HalDispatchTable hook at %llx...\n", gHalData.HalDispatchTableAddress);

    status = IntIntegrityAddRegion(gHalData.HalDispatchTableAddress,
                                   gHalData.HalDispatchTableSize,
                                   introObjectTypeHalDispatchTable,
                                   NULL,
                                   IntWinHalHandleDispatchTableWrite,
                                   TRUE,
                                   &gHalData.HalDispatchIntegrityHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinHalUnprotectHalDispatchTable(
    void
    )
///
/// @brief      Deactivates the HAL dispatch table protection.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gHalData.HalDispatchIntegrityHook == NULL)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    TRACE("[HAL] Removing Hal Dispatch Table hook...\n");

    status = IntIntegrityRemoveRegion(gHalData.HalDispatchIntegrityHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityRemoveRegion failed with status: 0x%08X\n", status);
        return status;
    }

    gHalData.HalDispatchIntegrityHook = NULL;

    return status;
}


INTSTATUS
IntWinHalProtectHalPerfCounter(
    void
    )
///
/// @brief Enables protection on HalPerformanceCounter function pointer.
///
/// The protected region contains the function which is called when KeQueryPerformanceCounter gets
/// called inside the guest OS.
///
/// @retval #INT_STATUS_SUCCESS                     On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT    If the protection is already initialized.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT        If the HalPerformanceCounter has not yet been found.
/// 
{
    INTSTATUS status;

    if (gHalData.HalPerfIntegrityObj != NULL)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (0 == gHalData.HalPerfCounterAddress)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    TRACE("[HAL] Adding HalPerformanceCounter hook at %llx...\n", gHalData.HalPerfCounterAddress);

    status = IntIntegrityAddRegion(gHalData.HalPerfCounterAddress + WIN_KM_FIELD(Ungrouped, HalPerfCntFunctionOffset),
                                   gGuest.WordSize,
                                   introObjectTypeHalPerfCounter,
                                   NULL,
                                   IntWinHalHandlePerfCounterModification,
                                   TRUE,
                                   &gHalData.HalPerfIntegrityObj);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityAddRegion failed: 0x%x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinHalUnprotectHalPerfCounter(
    void
    )
///
/// @brief Removes the protection on HalPerformanceCounter.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT    If the protection was not enabled beforehand.
///
{
    INTSTATUS status;

    if (gHalData.HalPerfIntegrityObj == NULL)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    TRACE("[HAL] Removing HalPerformanceCounter hook...\n");

    status = IntIntegrityRemoveRegion(gHalData.HalPerfIntegrityObj);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIntegrityRemoveRegion failed: 0x%08X\n", status);
        return status;
    }

    gHalData.HalPerfIntegrityObj = NULL;

    return status;
}


static BOOLEAN
IntWinHalIsIntController(
    _In_ QWORD CheckedAddress,
    _In_ QWORD HalHeap
    )
///
/// @brief      Checks if a guest memory range is the HAL interrupt controller.
///
/// The check is done based on invariants:
///     - the area starts with a list, with the next element pointing in the HAL heap as well
///     - starting with the 4th guest pointer, all the following pointers are either NULL, or point inside the
///     HAL heap
///     - the type must be 2
///
/// @param[in]  CheckedAddress  The guest virtual address to check.
/// @param[in]  HalHeap         The Hal Heap address.
///
/// @returns    True if CheckedAddress points to the HAL interrupt controller; False if it does not.
///
{
#define MAX_INT_CTRL_COUNT          20

    INTSTATUS status;
    QWORD functionPointer;
    QWORD functionOffset;

    QWORD initialInterruptController = 0;
    QWORD halFunction = 0;
    QWORD entriesOutsideTheHalHeap = 0;

    QWORD maxInterruptControllerCount = MAX_INT_CTRL_COUNT;
    BOOLEAN isListEntry = FALSE;

    // 1. First structure is a LIST_ENTRY structure.
    // All checked systems have at least 2 available controllers - we now have to validate that we actually
    // have a list.
    initialInterruptController = CheckedAddress;
    while (maxInterruptControllerCount)
    {
        status = IntKernVirtMemRead(initialInterruptController, gGuest.WordSize, &initialInterruptController, NULL);
        if (!INT_SUCCESS(status))
        {
            return FALSE;
        }

        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, initialInterruptController))
        {
            return FALSE;
        }

        if (initialInterruptController < HalHeap)
        {
            // Sometimes the ListHead is not situated on the HalHeap itself - we are only going to allow 1 entry
            // outside the Hal Heap.
            entriesOutsideTheHalHeap++;
        }

        if (CheckedAddress == initialInterruptController && entriesOutsideTheHalHeap <= 1)
        {
            isListEntry = TRUE;
            break;
        }

        maxInterruptControllerCount--;
    }

    if (!isListEntry)
    {
        return FALSE;
    }

    // 2. At offset WordSize * 4 starts an area of pointers to functions in hal.dll or nt, mixed with 0's
    // The list of functions spans until the type (2).
    BOOLEAN foundFunctions = FALSE;
    for (functionPointer = CheckedAddress + 4ull * gGuest.WordSize;
         functionPointer <= CheckedAddress + WIN_KM_FIELD(Ungrouped, HalIntCtrlTypeMaxOffset);
         functionPointer += gGuest.WordSize)
    {
        status = IntKernVirtMemRead(functionPointer, gGuest.WordSize, &halFunction, NULL);
        if (!INT_SUCCESS(status))
        {
            return FALSE;
        }

        if (0 == halFunction)
        {
            foundFunctions = TRUE;
            continue;
        }

        // 3. The type must be 2
        if (foundFunctions && (2 == (DWORD)halFunction))
        {
            break;
        }

        if (((halFunction < gHalData.OwnerHalModule->BaseVa) ||
             (halFunction > gHalData.OwnerHalModule->BaseVa + gHalData.OwnerHalModule->Size)) &&
            ((halFunction < gGuest.KernelVa) || (halFunction > gGuest.KernelVa + gGuest.KernelSize)))
        {
            return FALSE;
        }

        foundFunctions = TRUE;
    }

    if (!foundFunctions || 2 != (DWORD)halFunction)
    {
        return FALSE;
    }

    functionOffset = functionPointer - CheckedAddress;
    if (functionOffset < WIN_KM_FIELD(Ungrouped, HalIntCtrlTypeMinOffset) ||
        functionOffset > WIN_KM_FIELD(Ungrouped, HalIntCtrlTypeMaxOffset))
    {
        return FALSE;
    }

    WIN_KM_FIELD(Ungrouped, HalIntCtrlType) = (DWORD)functionOffset;

    return TRUE;

#undef MAX_INT_CTRL_COUNT  
#undef MAX_INT_CTRL_TYPE_OFFSET
#undef MIN_INT_CTRL_TYPE_OFFSET
}


BOOLEAN
IntWinHalIsHalPerf(
    _In_ QWORD HalPerfCandidate
    )
///
/// @brief  Verifies if the given pointer is the HalPerformanceCounter
///
/// The checks done on the given pointer are:
///     1. The pointer must be inside the Hal Heap.
///     2. Verify if there is a LIST_ENTRY at the beginning of the structure. The list must
///     contain the current pointer and should have all the pointers inside the Hal Heap, but
///     only one in the owner Hal module - which should be HalpRegisteredTimers.
///     3. At the protected zone offset - that is the offset from where KeQueryPerformanceCounter
///     gets the function address before calling it - there should be a pointer inside the Hal
///     owner driver.
///
/// @returns    TRUE if the given candidate passes all the checks, FALSE otherwise.
///
{
#define MAX_LIST_ITERATIONS_HAL_PERF    20
    QWORD nextList;
    DWORD numberOfOutsideHalHeap = 0;
    QWORD halPerfFunctionPtr = 0;
    BOOLEAN foundList = FALSE;
    INTSTATUS status;

    if (HalPerfCandidate < gHalData.HalHeapAddress ||
        HalPerfCandidate >= gHalData.HalHeapAddress + gHalData.HalHeapSize)
    {
        return FALSE;
    }

    nextList = HalPerfCandidate;

    for (DWORD i = 0; i < MAX_LIST_ITERATIONS_HAL_PERF; i++)
    {
        status = IntKernVirtMemFetchWordSize(nextList, &nextList);
        if (!INT_SUCCESS(status))
        {
            return FALSE;
        }

        if (nextList < gHalData.HalHeapAddress ||
            nextList >= gHalData.HalHeapAddress + gHalData.HalHeapSize)
        {
            numberOfOutsideHalHeap++;
        }

        if (numberOfOutsideHalHeap > 1)
        {
            return FALSE;
        }

        if (nextList == HalPerfCandidate)
        {
            foundList = TRUE;
            break;
        }
    }

    if (!foundList)
    {
        return FALSE;
    }

    status = IntKernVirtMemFetchWordSize(HalPerfCandidate + WIN_KM_FIELD(Ungrouped, HalPerfCntFunctionOffset),
                                         &halPerfFunctionPtr);
    if (!INT_SUCCESS(status))
    {
        return FALSE;
    }

    if (halPerfFunctionPtr < gHalData.OwnerHalModule->BaseVa ||
        halPerfFunctionPtr >= gHalData.OwnerHalModule->BaseVa + gHalData.OwnerHalModule->Size)
    {
        return FALSE;
    }

    return TRUE;
    
#undef MAX_LIST_ITERATIONS_HAL_PERF
}


static INTSTATUS
IntWinHalFindPerformanceCounterInternal(
    void
    )
///
/// @brief  Finds and protects if needed the HalPerformanceCounter structure.
///
/// This function will search the HalPerformanceCounter by the following heuristic:
/// Firstly, fetch the KeQueryPerformanceCounter address and decode the first instructions.
/// Among these instructions there should be an instructions of the form "mov reg, [mem]",
/// where the memory should represent either the rip relative address of HalpPerformanceCounter
/// variable on x64, either the absolute address on x86. For the pointer found at that address
/// we call #IntWinHalIsHalPerf in order to make additional checks.
/// Note that this function should only be called when all the needed data was already fetched.
/// This means that the Hal module should already be read in HalBuffer from #gHalData. For OSes
/// where the NT represent the Hal owner (such as 20h1), reading HalBuffer a priori is not needed.
///
/// @returns    #INT_STATUS_SUCCESS on success, #INT_STATUS_NOT_FOUND if HalPerformanceCounter
///             was not found or other appropriate statuses for other errors.
///
{
#define MAX_INSTRUCTIONS_SEARCH     10
    DWORD rva;
    INTSTATUS status;
    INSTRUX instrux = { 0 };
    DWORD csType = gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B;
    QWORD halPerfPtr = 0;
    BYTE *buff;
    DWORD buffSize;
    QWORD currentRip = 0;
    QWORD instruxOffset = 0;

    if (gGuest.KernelVa == gHalData.OwnerHalModule->BaseVa)
    {
        buff = gWinGuest->KernelBuffer;
        buffSize = gWinGuest->KernelBufferSize;
    }
    else
    {
        buff = gHalData.HalBuffer;
        buffSize = gHalData.HalBufferSize;
    }

    status = IntPeFindExportByNameInBuffer(gHalData.OwnerHalModule->BaseVa,
                                           buff,
                                           buffSize,
                                           "KeQueryPerformanceCounter",
                                           &rva);
                                   
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindExportByName failed: 0x%08x\n", status);
        return status;
    }

    currentRip = gHalData.OwnerHalModule->BaseVa + rva;
    instruxOffset = rva;

    for (size_t i = 0; i < MAX_INSTRUCTIONS_SEARCH; i++)
    {
        if (instruxOffset + ND_MAX_INSTRUCTION_LENGTH >= buffSize)
        {
            ERROR("[ERROR] The instruction at 0x%016llx resides outside the buffer!", currentRip);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        status = IntDecDecodeInstructionFromBuffer(buff + instruxOffset,
                                                   buffSize - instruxOffset,
                                                   csType,
                                                   &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionFromBuffer failed: 0x%08x\n", status);
            return status;
        }

        currentRip += instrux.Length;
        instruxOffset += instrux.Length;

        if (instrux.Instruction == ND_INS_MOV &&
            instrux.ExpOperandsCount == 2 &&
            instrux.Operands[1].Type == ND_OP_MEM)
        {
            QWORD possibleHalPerf = 0;

            // On x64 instruction is of the form mov reg, [rip relative address]
            if (gGuest.Guest64 && !instrux.Operands[1].Info.Memory.IsRipRel)
            {
                continue;
            }

            // On x86 instruction is of the form mov reg, [address]. Note that address is the displacement
            // and the instruction is not considered to use absolute addresses, so IsDirect is not set.
            if (!gGuest.Guest64 &&
                (instrux.Operands[1].Info.Memory.HasBase ||
                instrux.Operands[1].Info.Memory.HasIndex ||
                !instrux.Operands[1].Info.Memory.HasDisp))
            {
                continue;
            }

            if (instrux.Operands[1].Info.Memory.IsRipRel)
            {
                halPerfPtr = currentRip + instrux.Operands[1].Info.Memory.Disp;
            }
            else
            {
                halPerfPtr = instrux.Operands[1].Info.Memory.Disp;
            }

            status = IntKernVirtMemFetchWordSize(halPerfPtr, &possibleHalPerf);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
                continue;
            }

            if (!IntWinHalIsHalPerf(possibleHalPerf))
            {
                continue;
            }

            TRACE("[INFO] Found HalPerformanceCounter at 0x%016llx!\n", possibleHalPerf);

            gHalData.HalPerfCounterAddress = possibleHalPerf;

            break;
        }
    }

    if (0 == gHalData.HalPerfCounterAddress)
    {
        return INT_STATUS_NOT_FOUND;
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_PERF_CNT)
    {
        status = IntWinHalProtectHalPerfCounter();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalProtectHalPerfCounter failed: 0x%08x\n", status);
        }
    }

    return status;
#undef MAX_INSTRUCTIONS_SEARCH
}


static INTSTATUS
IntWinHalFinishRead(
    void
    )
///
/// @brief  This is the function called when the Hal is completely read.
///
/// Here should be initializations of protections which are dependent on the Hal driver contents.
/// For example, on HalPerformanceCounter protection, we need to fetch the KeQueryPerformanceCounter
/// export from the EAT, and then decode it, thus the whole Hal is needed in order to initialize this
/// protection.
///
/// @returns    #INT_STATUS_SUCCESS on success, or other appropriate error statuses if the function fails.
{
    INTSTATUS status;

    status = IntWinHalFindPerformanceCounterInternal();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinHalFindPerformanceCounterInternal failed: 0x%08x\n", status);
    }

    return status;
}


static void
IntWinHalCancelRead(
    void
    )
///
/// @brief  Cancels the Hal module read.
///
/// This function cancels all the pending page faults that were scheduled in order to read the
/// #WIN_HAL_DATA.HalBuffer.
///
{
    INTSTATUS status;
    LIST_ENTRY *initEntry;

    if (NULL == gHalData.HalBuffer)
    {
        return;
    }

    initEntry = gHalData.InitSwapHandles.Flink;
    while (initEntry != &gHalData.InitSwapHandles)
    {
        PWIN_INIT_SWAP pInitSwap = CONTAINING_RECORD(initEntry, WIN_INIT_SWAP, Link);
        initEntry = initEntry->Flink;

        status = IntSwapMemRemoveTransaction(pInitSwap->SwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed for %llx:%x: 0x%08x\n",
                  pInitSwap->VirtualAddress, pInitSwap->Size, status);
        }

        RemoveEntryList(&pInitSwap->Link);

        HpFreeAndNullWithTag(&pInitSwap, IC_TAG_WSWP);
    }
}


static INTSTATUS
IntWinHalSectionInMemory(
    _Inout_ WIN_INIT_SWAP *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      Handles the swap in of a Hal section done while the #WIN_HAL_DATA.HalBuffer is read
///
/// This is the IntSwapMemRead handler set by #IntWinHalReadHal that will read a Hal section into the
/// Hal buffer. It will set the appropriate part of the #WIN_HAL_DATA.HalBuffer with the data obtained from the
/// guest and will decrement the #WIN_HAL_DATA.RemainingSections counter. It will also remove Context from the
/// #WIN_HAL_DATA.InitSwapHandles list and will free it.
///
/// @param[in]  Context         The init swap handle used for this section
/// @param[in]  Cr3             Ignored
/// @param[in]  VirtualAddress  Ignored
/// @param[in]  PhysicalAddress Ignored
/// @param[in]  Data            The data read from the Hal
/// @param[in]  DataSize        The size of the Data buffer
/// @param[in]  Flags           A combination of flags describing the way in which the data was read. This function
///                             checks only for the #SWAPMEM_FLAG_ASYNC_CALL flag. If it is present, it means that it
///                             was invoked asynchronously, in which case it will pause the VCPUs in order to ensure
///                             consistency of the data. If the #WIN_HAL_DATA.RemainingSections is set to 0 by this
///                             callback while #SWAPMEM_FLAG_ASYNC_CALL is set, it will also initialize the protections
///                             that rely on the Hal module, by calling #IntWinHalFinishRead.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    PWIN_INIT_SWAP pSwp;
    QWORD va;
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);

    if (Flags & SWAPMEM_FLAG_ASYNC_CALL)
    {
        IntPauseVcpus();
    }

    status = INT_STATUS_SUCCESS;

    pSwp = Context;
    va = pSwp->VirtualAddress;

    // Remove the context. The caller knows this may happen & won't use it after IntSwapMemReadData
    RemoveEntryList(&pSwp->Link);
    HpFreeAndNullWithTag(&pSwp, IC_TAG_WSWP);

    if (0 == gHalData.RemainingSections)
    {
        ERROR("[ERROR] Callback came after we have no more sections to read...\n");
        status = INT_STATUS_INVALID_INTERNAL_STATE;
        goto resume_and_exit;
    }

    memcpy(gHalData.HalBuffer + va, Data, DataSize);

    gHalData.RemainingSections--;

    if ((0 == gHalData.RemainingSections) && (Flags & SWAPMEM_FLAG_ASYNC_CALL))
    {
        TRACE("[HAL] All sections from hal were read into buffer\n");

        status = IntWinHalFinishRead();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalFinishRead failed: 0x%08x\n", status);
        }
    }

resume_and_exit:
    if (Flags & SWAPMEM_FLAG_ASYNC_CALL)
    {
        IntResumeVcpus();
    }

    return status;
}


static INTSTATUS
IntWinHalReadHal(
    void
    )
///
/// @brief      Reads the whole Hal image in memory, including swapped-out sections
///
/// This will allocate and fill #WIN_HAL_DATA.HalBuffer. For the swapped-out sections, IntSwapMemRead will be used
/// with #IntWinHalSectionInMemory as the swap-in handler. Discardable sections will be filled with 0, as those
/// can not be brought back into memory. If all the sections are already present in memory, this function will try
/// to initialize the protections which rely on the Hal module, by calling #IntWinHalFinishRead. If not, this step
/// is left to the last invocation of the #IntWinHalSectionInMemory callback. Once #IntWinHalFinishRead is called
/// the Hal buffer can be safely used.
///
///
/// @retval     #INT_STATUS_SUCCESS in case of success. Note that even if this function exits with a success status,
///             the hal buffer is not necessarily valid yet, as parts of it may be read in an asynchronous manner.
/// @retval     #INT_STATUS_INVALID_OBJECT_TYPE if the MZPE validation of the headers fails.
/// @retval     #INT_STATUS_NOT_SUPPORTED if a section header can not be parsed.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if an internal error is encountered.
///
{
    INTSTATUS status;
    INTRO_PE_INFO peInfo = { 0 };
    DWORD secCount, secStartOffset;
    IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)gHalData.OwnerHalModule->Win.MzPeHeaders;

    InitializeListHead(&gHalData.InitSwapHandles);

    status = IntPeValidateHeader(gHalData.OwnerHalModule->BaseVa,
                                 (BYTE *)pDosHeader,
                                 PAGE_SIZE,
                                 &peInfo,
                                 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        return status;
    }

    if (gGuest.Guest64 != peInfo.Image64Bit)
    {
        ERROR("[ERROR] Inconsistent MZPE image!\n");
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if (peInfo.Image64Bit)
    {
        PIMAGE_NT_HEADERS64 pNth64;
        BOOLEAN unmapNtHeaders = FALSE;

        if ((QWORD)(DWORD)pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) < PAGE_SIZE)
        {
            // We are in the same page, so it's safe to use this
            pNth64 = (PIMAGE_NT_HEADERS64)((size_t)pDosHeader + pDosHeader->e_lfanew);
        }
        else
        {
            status = IntVirtMemMap(gHalData.OwnerHalModule->BaseVa + pDosHeader->e_lfanew, sizeof(*pNth64),
                                   gGuest.Mm.SystemCr3, 0, &pNth64);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n",
                      gHalData.OwnerHalModule->BaseVa + pDosHeader->e_lfanew, status);
                return status;
            }

            unmapNtHeaders = TRUE;
        }

        secCount = 0xffff & pNth64->FileHeader.NumberOfSections;
        secStartOffset = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
            pNth64->FileHeader.SizeOfOptionalHeader;

        if (unmapNtHeaders)
        {
            IntVirtMemUnmap(&pNth64);
        }
    }
    else
    {
        PIMAGE_NT_HEADERS32 pNth32;
        BOOLEAN unmapNtHeaders = FALSE;

        if ((QWORD)(DWORD)pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) < PAGE_SIZE)
        {
            // We are in the same page, so it's safe to use this
            pNth32 = (PIMAGE_NT_HEADERS32)((size_t)pDosHeader + pDosHeader->e_lfanew);
        }
        else
        {
            status = IntVirtMemMap(gHalData.OwnerHalModule->BaseVa + pDosHeader->e_lfanew, sizeof(*pNth32),
                                   gGuest.Mm.SystemCr3, 0, &pNth32);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n",
                      gGuest.KernelVa + pDosHeader->e_lfanew, status);
                return status;
            }

            unmapNtHeaders = TRUE;
        }

        secCount = 0xffff & pNth32->FileHeader.NumberOfSections;
        secStartOffset = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
            pNth32->FileHeader.SizeOfOptionalHeader;

        if (unmapNtHeaders)
        {
            IntVirtMemUnmap(&pNth32);
        }
    }

    if (secStartOffset >= PAGE_SIZE)
    {
        ERROR("[ERROR] Sections get outside the first page. We don't support this yet!\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (secStartOffset + secCount * sizeof(IMAGE_SECTION_HEADER) > PAGE_SIZE)
    {
        ERROR("[ERROR] Sections get outside the first page. We don't support this yet!\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (peInfo.SizeOfImage < PAGE_SIZE)
    {
        ERROR("[ERROR] SizeOfImage too small: %d!\n", peInfo.SizeOfImage);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    gHalData.HalBufferSize = peInfo.SizeOfImage;
    gHalData.HalBuffer = HpAllocWithTag(peInfo.SizeOfImage, IC_TAG_HALB);
    if (NULL == gHalData.HalBuffer)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(gHalData.HalBuffer, gHalData.OwnerHalModule->Win.MzPeHeaders, PAGE_SIZE);

    gHalData.RemainingSections = secCount;

    for (DWORD i = 0; i < secCount; i++)
    {
        DWORD secActualSize;

        PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)(gHalData.HalBuffer + secStartOffset +
                                                             i * sizeof(IMAGE_SECTION_HEADER));

        secActualSize = ROUND_UP(pSec->Misc.VirtualSize, PAGE_SIZE);

        if (0 == pSec->VirtualAddress)
        {
            ERROR("[ERROR] We cannot have a section starting at 0!\n");

            return INT_STATUS_NOT_SUPPORTED;
        }

        if (0 == pSec->Misc.VirtualSize)
        {
            ERROR("[ERROR] We cannot have a section starting at 0!\n");

            return INT_STATUS_NOT_SUPPORTED;
        }

        // Make sure the section fits within the allocated buffer. We must avoid cases where the SizeOfImage or
        // section headers are maliciously altered.
        if ((pSec->VirtualAddress >= peInfo.SizeOfImage) ||
            (secActualSize > peInfo.SizeOfImage) ||
            (pSec->VirtualAddress + secActualSize > peInfo.SizeOfImage))
        {
            ERROR("[ERROR] Section %d seems corrupted: sizeOfImage = 0x%x, secstart = 0x%x, secsize = 0x%x\n",
                  i, peInfo.SizeOfImage, pSec->VirtualAddress, pSec->Misc.VirtualSize);

            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if (pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        {
            memset(gHalData.HalBuffer + pSec->VirtualAddress, 0, secActualSize);

            gHalData.RemainingSections--;
        }
        else if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
        {
            // The section will be present, so read it now
            status = IntKernVirtMemRead(gHalData.OwnerHalModule->BaseVa + pSec->VirtualAddress,
                                        secActualSize,
                                        gHalData.HalBuffer + pSec->VirtualAddress,
                                        NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx -> 0x%016llx %s: 0x%08x\n",
                      gHalData.OwnerHalModule->BaseVa + pSec->VirtualAddress,
                      gHalData.OwnerHalModule->BaseVa + pSec->VirtualAddress + secActualSize,
                      pSec->Name, status);

                return status;
            }

            gHalData.RemainingSections--;
        }
        else
        {
            DWORD retSize = 0;

            // Use the swap mechanism only if we can't directly read the memory; this avoids unnecessary
            // recursive function calls.
            status = IntKernVirtMemRead(gHalData.OwnerHalModule->BaseVa + pSec->VirtualAddress,
                                        secActualSize,
                                        gHalData.HalBuffer + pSec->VirtualAddress,
                                        &retSize);
            if (!INT_SUCCESS(status))
            {
                PWIN_INIT_SWAP pSwp = NULL;
                void *swapHandle = NULL;

                pSwp = HpAllocWithTag(sizeof(*pSwp), IC_TAG_WSWP);
                if (NULL == pSwp)
                {
                    return INT_STATUS_INSUFFICIENT_RESOURCES;
                }

                pSwp->VirtualAddress = pSec->VirtualAddress;
                pSwp->Size = secActualSize;

                InsertTailList(&gHalData.InitSwapHandles, &pSwp->Link);

                WARNING("Section %d / %d is not in memory, will do a swap mem read\n", i, secCount);

                status = IntSwapMemReadData(0,
                                            gHalData.OwnerHalModule->BaseVa + pSec->VirtualAddress,
                                            secActualSize,
                                            SWAPMEM_OPT_BP_FAULT,
                                            pSwp,
                                            0,
                                            IntWinHalSectionInMemory,
                                            NULL,
                                            &swapHandle);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                    return status;
                }

                // The callback will be called async, save the handle in case an uninit will come
                if (NULL != swapHandle)
                {
                    pSwp->SwapHandle = swapHandle;
                }
            }
            else
            {
                if (retSize != secActualSize)
                {
                    ERROR("We requested %08x bytes, but got %08x!\n", secActualSize, retSize);
                    return INT_STATUS_INVALID_INTERNAL_STATE;
                }

                gHalData.RemainingSections--;
            }
        }
    }

    // We managed to read everything here, so continue the initialization
    if (0 == gHalData.RemainingSections)
    {
        TRACE("[HAL] All sections were present in memory!\n");

        status = IntWinHalFinishRead();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalFinishRead failed: 0x%08x\n", status);
        }
    }

    return status;

}


static INTSTATUS
IntWinHalFindPerformanceCounter(
    void
    )
///
/// @brief Starts the process of finding the HalPerformanceCounter.
///
/// On OSes for which the kernel is also the Hal owner, such as 20h1, this function will find synchronously
/// the HalPerformanceCounter structure, as the Hal buffer is equivalent with the already read Kernel Buffer.
/// Otherwise, the searching of HalPerformanceCounter might be asynchronous, as some sections in the Hal module
/// might be swapped out. A call to #IntWinHalReadHal will be made in order to read the present sections and
/// inject page faults on the swapped out ones. If no sections are swapped out, then
/// #IntWinHalFindPerformanceCounterInternal will be called synchronously in this case too. Otherwise, the
/// protection on HalPerformanceCounter will be initialized only when the paged-out sections are swapped in.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value if there was an error.
///
{
    if (gHalData.OwnerHalModule->BaseVa == gGuest.KernelVa)
    {
        return IntWinHalFindPerformanceCounterInternal();
    }
    else
    {
        return IntWinHalReadHal();
    }
}


static INTSTATUS
IntWinHalFindInterruptController(
    _In_ QWORD HalHeap,
    _In_ QWORD HalHeapSize,
    _Out_ QWORD *HalInterruptController
    )
///
/// @brief      Attempts to find the Hal Interrupt Controller address within the .data section of Hal.
///
/// This functions reads the .data section of the Hal module in order to find the RVA of the Hal Interrupt Controller.
/// Candidate RVAs are verified using #IntWinHalIsIntController in order to find the correct address.
///
/// @param[in]      HalHeap                 The Hal Heap address.
/// @param[in]      HalHeapSize             The Hal Heap size (may not be the entire Hal Heap).
/// @param[out]     HalInterruptController  The Hal Interrupt Controller address.
///
/// @returns    #INT_STATUS_SUCCESS     On success
/// @returns    #INT_STATUS_NOT_FOUND   If the Hal Interrupt Controller was not found
///
{
    INTSTATUS status;
    IMAGE_SECTION_HEADER dataSec = { 0 };
    DWORD nrSec = 0;
    QWORD halIntCtrlGva = 0;
    void *dataSectionMem = NULL;

    status = IntPeGetSectionHeadersByName(gHalData.OwnerHalModule->BaseVa, gHalData.OwnerHalModule->Win.MzPeHeaders,
                                          ".data", 1, gGuest.Mm.SystemCr3, &dataSec, &nrSec);
    if (!INT_SUCCESS(status) || nrSec == 0)
    {
        ERROR("[ERROR] IntPeGetSectionHeadersByName failed: 0x%08x, number of sections: %d\n", status, nrSec);
        // status may be a successful one, but if no sections were found we return an error status to signal that
        // HalInterruptController is not valid
        status = INT_STATUS_NOT_FOUND;
        goto exit;
    }

    if (dataSec.Misc.VirtualSize < gGuest.WordSize || dataSec.Misc.VirtualSize > ONE_MEGABYTE)
    {
        ERROR("[ERROR] Invalid data section size:%x\n", dataSec.Misc.VirtualSize);
        status = INT_STATUS_NOT_FOUND;
        goto exit;
    }

    status = IntVirtMemMap(gHalData.OwnerHalModule->BaseVa + dataSec.VirtualAddress, dataSec.Misc.VirtualSize,
                           gGuest.Mm.SystemCr3, 0, &dataSectionMem);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);

        status = INT_STATUS_NOT_FOUND;
        goto exit;
    }

    for (DWORD offset = 0; offset <= dataSec.Misc.VirtualSize - gGuest.WordSize; offset += gGuest.WordSize)
    {
        halIntCtrlGva = gGuest.Guest64 ? *(QWORD*)((QWORD)dataSectionMem + offset) :
                                         *(DWORD*)((QWORD)dataSectionMem + offset);

        if (halIntCtrlGva < HalHeap || halIntCtrlGva >= HalHeap + HalHeapSize)
        {
            continue;
        }

        if (IntWinHalIsIntController(halIntCtrlGva, HalHeap))
        {
            *HalInterruptController = halIntCtrlGva;
            status = INT_STATUS_SUCCESS;
            goto exit;
        }
    }

    status = INT_STATUS_NOT_FOUND;

exit:
    if (dataSectionMem)
    {
        IntVirtMemUnmap(&dataSectionMem);
    }

    return status;
}


static INTSTATUS
IntWinHalFindHalHeapAndInterruptController(
    _Out_ QWORD *HalHeapBaseAddress,
    _Out_ QWORD *HalInterruptController
    )
///
/// @brief      Attempts to find the Hal Heap and the Hal Interrupt Controller address within the .data section of Hal.
///
/// On Windows versions newer than RS2 the Hal Hep is randomized using KASLR. Within the .data section of Hal
/// there are 2 variables (HalpHeapStart and HalpOriginalHeapStart) that seem to point to the Hal Heap. This function
/// aims to find the Hal Heap using the following mechanism:
///     - Find kernel addresses within the .data section of Hal
///     - Translate the addresses and analyze the other entries from the same PT
///     - If other entries from the same PT point to physical devices, we have a candidate address
///     - In order to make sure our candidate address is actually the Hal Heap start, try to find the
///             Hal Interrupt Controller using that address
///
/// @param[out]     HalHeapBaseAddress      The Hal Heap address.
/// @param[out]     HalInterruptController  The Hal Interrupt Controller address.
///
/// @returns    #INT_STATUS_SUCCESS     On success
/// @returns    #INT_STATUS_NOT_FOUND   If the Hal Heap was not found
///
{
    INTSTATUS status;
    DWORD nrSec = 0;
    DWORD pteTableIndex = 0;
    QWORD ptePhysicalAddress = 0;
    QWORD ptPhysicalAddress = 0;
    QWORD halHeapStart = 0;
    QWORD deviceAddressCount = 0;
    VA_TRANSLATION halHeapStartTranslation = { 0 };
    IMAGE_SECTION_HEADER dataSec = { 0 };
    QWORD fallbackHalHeapVA = 0;
    QWORD halInterruptController = 0;
    QWORD *pt = NULL;
    void *dataSectionMem = NULL;

#define HAL_HEAP_ORIGINAL 0xFFFFFFFFF0000000
#define MASK_DEVICE_ADDRESS_FEC 0x00000000fec00000
#define MASK_DEVICE_ADDRESS_FED 0x00000000fed00000
#define MASK_DEVICE_ADDRESS_FEE 0x00000000fee00000
#define HAL_HEAP_PHYSICAL_ADDRESS 0x1000

    status = IntPeGetSectionHeadersByName(gHalData.OwnerHalModule->BaseVa, gHalData.OwnerHalModule->Win.MzPeHeaders,
                                          ".data", 1, gGuest.Mm.SystemCr3, &dataSec, &nrSec);
    if (!INT_SUCCESS(status) || nrSec == 0)
    {
        ERROR("[ERROR] IntPeGetSectionHeadersByName failed: 0x%08x, number of sections: %d\n", status, nrSec);
        goto exit;
    }

    if (dataSec.Misc.VirtualSize < gGuest.WordSize || dataSec.Misc.VirtualSize > ONE_MEGABYTE)
    {
        ERROR("[ERROR] Invalid data section size:%x\n", dataSec.Misc.VirtualSize);
        status = INT_STATUS_UNSUCCESSFUL;
        goto exit;
    }

    status = IntVirtMemMap(gHalData.OwnerHalModule->BaseVa + dataSec.VirtualAddress, dataSec.Misc.VirtualSize,
                           gGuest.Mm.SystemCr3, 0, &dataSectionMem);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);
        goto exit;
    }

    for (DWORD offset = 0; offset <= dataSec.Misc.VirtualSize - gGuest.WordSize; offset += gGuest.WordSize)
    {
        halHeapStart = gGuest.Guest64 ? *(QWORD*)((QWORD)dataSectionMem + offset) :
                                        *(DWORD*)((QWORD)dataSectionMem + offset);

        halHeapStart = halHeapStart & HAL_HEAP_ORIGINAL;

        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, halHeapStart))
        {
            continue;
        }

        status = IntTranslateVirtualAddressEx(halHeapStart, gGuest.Mm.SystemCr3, 0, &halHeapStartTranslation);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        if (0 == halHeapStartTranslation.MappingsCount)
        {
            continue;
        }

        // Here we obtain the physical address of the PT (PT[0])
        pteTableIndex = halHeapStartTranslation.MappingsCount - 1;
        ptePhysicalAddress = halHeapStartTranslation.MappingsTrace[pteTableIndex];
        ptPhysicalAddress = ptePhysicalAddress & PHYS_PAGE_MASK;

        // From what I`ve seen, even on KASLR Hal Heap OSes (newer than RS2) the Hal Heap is always mapped to PA 0x1000.
        // In theory we could use this to find the Hal Heap but it`s safer to look for mapped devices and keep
        // this as a fallback mechanism only.
        if (HAL_HEAP_PHYSICAL_ADDRESS == halHeapStartTranslation.PhysicalAddress)
        {
            fallbackHalHeapVA = halHeapStartTranslation.VirtualAddress;
        }

        status = IntPhysMemMap(ptPhysicalAddress, PAGE_SIZE, 0, &pt);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        // Now we are going to look for mapped devices. The PT used to translate the HalHeap VA has other PTEs that map
        // physical devices (0xfee00XXX, 0xfec00XXX, 0xfed00XXX, etc.), so we are going to look for them. Below there
        // are some PTEs dumped from WinDbg (they illustrate the PTEs that map physical devices).
        //
        // ffffd07b`d92000a0  80000000`00016863 80000000`fee0087b <- Physicall device
        // ffffd07b`d92000b0  80000000`00018863 80000000`fec0081b <- Physicall device
        // ffffd07b`d92000c0  80000000`00019863 80000000`0001c863
        // ffffd07b`d92000d0  80000000`0001d863 80000000`fed0081b <- Physicall device
        deviceAddressCount = 0;
        for (DWORD i = 0; i < 512; i++)
        {
            if (!pt[i])
            {
                continue;
            }

            if ((pt[i] & PHYS_PAGE_MASK) == MASK_DEVICE_ADDRESS_FEE)
            {
                deviceAddressCount++;
            }

            if ((pt[i] & PHYS_PAGE_MASK) == MASK_DEVICE_ADDRESS_FEC)
            {
                deviceAddressCount++;
            }

            if ((pt[i] & PHYS_PAGE_MASK) == MASK_DEVICE_ADDRESS_FED)
            {
                deviceAddressCount++;
            }
        }

        status = IntPhysMemUnmap(&pt);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        // If there are at least 2 mapped physical devices, try to find the interrupt controller to validate
        // our candidate address.
        if (deviceAddressCount >= 2)
        {
            status = IntWinHalFindInterruptController(halHeapStartTranslation.VirtualAddress,
                                                      PAGE_SIZE * HAL_HEAP_PROT_PAGES_EXEC,
                                                      &halInterruptController);
            if (!INT_SUCCESS(status))
            {
                continue;
            }

            TRACE("[HAL] Found HalInterruptController at 0x%016llx\n", halInterruptController);

            *HalHeapBaseAddress = halHeapStartTranslation.VirtualAddress;
            *HalInterruptController = halInterruptController;

            goto exit;
        }
    }

    if (fallbackHalHeapVA)
    {
        WARNING("[WARNING] We could not find the Hal Heap using the mapped devices - fallback using PA:0x1000 "
                "VA:%llx\n", fallbackHalHeapVA);

        status = IntWinHalFindInterruptController(fallbackHalHeapVA, PAGE_SIZE * HAL_HEAP_PROT_PAGES_EXEC,
                                                  &halInterruptController);
        if (INT_SUCCESS(status))
        {
            TRACE("[HAL] Found HalInterruptController at 0x%016llx\n", halInterruptController);

            *HalHeapBaseAddress = fallbackHalHeapVA;
            *HalInterruptController = halInterruptController;

            goto exit;
        }
        else
        {
            ERROR("[ERROR] We could not find the Hal Heap using the fallback VA\n");
        }
    }
    else
    {
        ERROR("[ERROR] We could not find the Hal Heap using the mapped devices and there is no fallback address\n");
    }

    status = INT_STATUS_NOT_FOUND;

exit:
    if (dataSectionMem)
    {
        IntVirtMemUnmap(&dataSectionMem);
    }

#undef HAL_HEAP_ORIGINAL
#undef MASK_DEVICE_ADDRESS_FEC
#undef MASK_DEVICE_ADDRESS_FED
#undef MASK_DEVICE_ADDRESS_FEE
#undef HAL_HEAP_PHYSICAL_ADDRESS

    return status;
}


INTSTATUS
IntWinHalCreateHalData(
    void
    )
///
/// @brief      Initializes #gHalData.
///
/// Will collect the relevant information from the guest and if any of the #INTRO_OPT_PROT_KM_HAL_DISP_TABLE,
/// #INTRO_OPT_PROT_KM_HAL_HEAP_EXEC, or #INTRO_OPT_PROT_KM_HAL_INT_CTRL option is active, will activate the
/// needed protections.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    status = IntPeFindKernelExport("HalDispatchTable", &gHalData.HalDispatchTableAddress);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindKernelExport failed for 'HalDispatchTable': 0x%x\n", status);
        return status;
    }

    // Starting from 20H1, the Hal Heap and Hal Interrupt controller have been moved to the nt itself on x64 versions
    // of Windows.
    if (gGuest.OSVersion >= WIN_BUILD_10_20H1 && gGuest.Guest64)
    {
        gHalData.OwnerHalModule = gGuest.KernelDriver;
    }
    else
    {
        gHalData.OwnerHalModule = IntDriverFindByName(u"hal.dll");
    }

    if (NULL == gHalData.OwnerHalModule)
    {
        ERROR("[ERROR] Could not find the module containing the Hal\n");
        return INT_STATUS_NOT_FOUND;
    }
    
    gHalData.HalDispatchTableSize = HAL_DISPATCH_TABLE_PTR_COUNT * gGuest.WordSize;

    TRACE("[HAL] Found HalDispatchTable at %llx, size %d\n",
          gHalData.HalDispatchTableAddress, gHalData.HalDispatchTableSize);

    // RS2 x64 made the hal heap ASLR compatible
    // RS2 x86 still maps the hal heap at the same Virtual Address.
    if (gGuest.OSVersion >= WIN_BUILD_10_RS2 && gGuest.Guest64)
    {
        QWORD halHeap = 0;
        QWORD halInterruptController = 0;
        status = IntWinHalFindHalHeapAndInterruptController(&halHeap, &halInterruptController);
        if (!INT_SUCCESS(status))
        {
            LOG("[HAL] Unable to find the HAL heap\n");
            goto _skip_hal_heap;
        }

        gHalData.HalHeapAddress = halHeap;
        gHalData.HalIntCtrlAddress = halInterruptController;
    }
    else
    {
        gHalData.HalHeapAddress = gGuest.Guest64 ? WIN_HAL_HEAP_BASE_64 : WIN_HAL_HEAP_BASE_32;
    }

    gHalData.HalHeapSize = PAGE_SIZE * HAL_HEAP_PROT_PAGES_EXEC;

    TRACE("[HAL] Found HalHeap at %llx, size %d\n", gHalData.HalHeapAddress, gHalData.HalHeapSize);

    if (gGuest.OSVersion < WIN_BUILD_8)
    {
        TRACE("[HAL] Hal Interrupt Controller/Performance Counter does not exist on Windows version %d!\n",
              gGuest.OSVersion);
        goto _skip_hal_heap;
    }

    if (!gHalData.HalIntCtrlAddress)
    {
        QWORD halInterruptController = 0;
        status = IntWinHalFindInterruptController(gHalData.HalHeapAddress, gHalData.HalHeapSize,
                                                  &halInterruptController);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Could not find Hal Interrupt Controller!\n");
            goto _skip_hal_heap;
        }

        gHalData.HalIntCtrlAddress = halInterruptController;
        TRACE("[HAL] Found HalInterruptController at 0x%016llx\n", gHalData.HalIntCtrlAddress);
    }

    status = IntWinHalFindPerformanceCounter();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinHalFindPerformanceCounter failed: 0x%08x\n", status);
        goto _skip_hal_heap;
    }

_skip_hal_heap:
    // Enable protections, if needed.
    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_DISP_TABLE)
    {
        status = IntWinHalProtectHalDispatchTable();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalHookHalDispatchTable failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_HEAP_EXEC)
    {
        status = IntWinHalProtectHalHeapExecs();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalHookHalHeapExecs failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_INT_CTRL)
    {
        status = IntWinHalProtectHalIntCtrl();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalHookHalIntCtrl failed: 0x%08x\n", status);
            return status;
        }
    }

    return status;
}


INTSTATUS
IntWinHalUpdateProtection(
    void
    )
///
/// @brief      Updates any of the HAL protections.
///
/// If any of the #INTRO_OPT_PROT_KM_HAL_DISP_TABLE, #INTRO_OPT_PROT_KM_HAL_HEAP_EXEC, or
/// #INTRO_OPT_PROT_KM_HAL_INT_CTRL option is changed, the protection is enabled, or disabled, based on the new value.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_DISP_TABLE)
    {
        status = IntWinHalProtectHalDispatchTable();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalHookHalDispatchTable failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        IntWinHalUnprotectHalDispatchTable();
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_HEAP_EXEC)
    {
        status = IntWinHalProtectHalHeapExecs();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalHookHalHeapExecs failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        IntWinHalUnprotectHalHeapExecs();
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_INT_CTRL)
    {
        status = IntWinHalProtectHalIntCtrl();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalHookHalIntCtrl failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        IntWinHalUnprotectHalIntCtrl();
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_HAL_PERF_CNT)
    {
        status = IntWinHalProtectHalPerfCounter();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinHalProtectHalPerfCounter failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        IntWinHalUnprotectHalPerfCounter();
    }

    return INT_STATUS_SUCCESS;
}

void
IntWinHalUninit(
    void
    )
///
/// @brief      Frees any resources held by #gHalData and removes all the HAL protections.
///
{
    IntWinHalUnprotectHalDispatchTable();

    IntWinHalUnprotectHalHeapExecs();

    IntWinHalUnprotectHalIntCtrl();

    IntWinHalUnprotectHalPerfCounter();

    IntWinHalCancelRead();

    if (NULL != gHalData.HalBuffer)
    {
        HpFreeAndNullWithTag(&gHalData.HalBuffer, IC_TAG_HALB);
    }
}
