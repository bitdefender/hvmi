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

        pEptViol->Violation = INTRO_EPT_EXECUTE;
        pEptViol->HookStartPhysical = Hook->GpaPage;
        pEptViol->HookStartVirtual = gva & PAGE_MASK;
        pEptViol->VirtualPage = gva & PAGE_MASK;
        pEptViol->Offset = Address & PAGE_OFFSET;
        pEptViol->Victim.Type = introObjectTypeHalHeap;
        pEptViol->ZoneTypes = ZONE_EXECUTE;

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

                // we let the modifications happen if BETA alerts are enabled and we don't want to SPAM the same
                // alert every time
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
#define MAX_INT_CTRL_TYPE_OFFSET    (gGuest.Guest64 ? 0xf0 : 0x6c)
#define MIN_INT_CTRL_TYPE_OFFSET    (gGuest.Guest64 ? 0xc0 : 0x60)
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
         functionPointer <= CheckedAddress + MAX_INT_CTRL_TYPE_OFFSET;
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
    if (functionOffset < MIN_INT_CTRL_TYPE_OFFSET || functionOffset > MAX_INT_CTRL_TYPE_OFFSET)
    {
        return FALSE;
    }

    WIN_KM_FIELD(Ungrouped, HalIntCtrlType) = (DWORD)functionOffset;

    return TRUE;

#undef MAX_INT_CTRL_COUNT  
#undef MAX_INT_CTRL_TYPE_OFFSET
#undef MIN_INT_CTRL_TYPE_OFFSET
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
        // status may be a succesful one, but if no sections were found we return an error status to signal that
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
        TRACE("[HAL] Hal Intterrupt Controller does not exist on Windows version %d!\n", gGuest.OSVersion);
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
}
