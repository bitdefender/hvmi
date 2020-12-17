/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winselfmap.h"
#include "alerts.h"
#include "hook.h"

extern LIST_HEAD gWinProcesses;


__forceinline static void
IntWinSelfMapSelfMapUpdate(
    _In_ QWORD ModifiedCr3,
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD NewValue
    )
///
/// @brief  Updates the self map entry value for a process
///
/// @param[in]      ModifiedCr3 Used to signal which Cr3 is changed. If KPTI is enabled, this can either be the kernel
///                             (is it is equal to WIN_PROCESS_OBJECT.Cr3), or the user (if it is not) Cr3.
/// @param[in, out] Process     The process which will be updated. If ModifiedCr3 is equal to WIN_PROCESS_OBJECT.Cr3,
///                             the WIN_PROCESS_OBJECT.SelfMapEntryValue field will be updated; otherwise, the
///                             WIN_PROCESS_OBJECT.UserSelfMapEntryValue field will be updated
/// @param[in]      NewValue    The new value to be used
///
{
    if (Process->Cr3 == ModifiedCr3)
    {
        Process->SelfMapEntryValue = NewValue;
    }
    else
    {
        Process->UserSelfMapEntryValue = NewValue;
    }
}


static INTSTATUS
IntWinSelfMapHandleCr3SelfMapModification(
    _In_ QWORD NewValue,
    _In_ QWORD OldValue,
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD Cr3
    )
///
/// @brief      Handles self map entry modifications for a process
///
/// @param[in]      NewValue    The new self map entry value
/// @param[in]      OldValue    The old self map entry value
/// @param[in, out] Process     The process for which the change was done
/// @param[in]      Cr3         The Cr3 for which the change was done
///
/// @retval         #INT_STATUS_SUCCESS always
///
{
    INTSTATUS status;
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    EVENT_TRANSLATION_VIOLATION *pTr = &gAlert.Translation;

    action = introGuestNotAllowed;
    reason = introReasonNoException;

    memzero(pTr, sizeof(*pTr));

    WARNING("[WARNING] Self-mapping entry modified for process '%s' with CR3 %llx (%s), addr %llx, "
            "from 0x%016llx to 0x%016llx\n", Process->Name, Cr3, Cr3 == Process->Cr3 ? "kernel" : "user",
            SELF_MAP_ENTRY(Cr3), OldValue, NewValue);

    if (IntPolicyCoreIsOptionBeta(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY))
    {
        LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ (B) ROOTKIT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");
    }
    else
    {
        LOG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ROOTKIT ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\n");

        QWORD *pPage = NULL;

        status = IntPhysMemMap(SELF_MAP_ENTRY(Cr3), sizeof(QWORD), 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            goto _just_send_alert;
        }

        // restore only the US bit in case of modification
        pPage[0] = NewValue & (~PT_US);

        IntPhysMemUnmap(&pPage);
    }

    // We always update the selfmap with the new value
    IntWinSelfMapSelfMapUpdate(Cr3, Process, NewValue);

_just_send_alert:
    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY, &action, &reason))
    {
        pTr->Header.Action = action;
        pTr->Header.Reason = reason;
        pTr->Header.MitreID = idRootkit;

        pTr->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY, reason) | ALERT_FLAG_ASYNC;

        if (Process->SystemProcess)
        {
            pTr->Header.Flags |= ALERT_FLAG_SYSPROC;
        }

        IntAlertFillCpuContext(FALSE, &pTr->Header.CpuContext);

        IntAlertFillWinProcessByCr3(Process->Cr3, &pTr->Header.CurrentProcess);

        IntAlertFillVersionInfo(&pTr->Header);

        pTr->WriteInfo.NewValue[0] = NewValue;
        pTr->WriteInfo.OldValue[0] = OldValue;
        pTr->WriteInfo.Size = sizeof(QWORD);

        pTr->Originator.Module.Valid = FALSE;
        pTr->Header.CpuContext.Valid = FALSE;
        pTr->Header.CurrentProcess.Valid = FALSE;

        pTr->Victim.VirtualAddress = SELF_MAP_ENTRY_VA;
        pTr->ViolationType = transViolationSelfMap;

        status = IntNotifyIntroEvent(introEventTranslationViolation, pTr, sizeof(*pTr));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinSelfMapCheckSelfMapEntry(
    _Inout_ WIN_PROCESS_OBJECT *Process,
    _In_opt_ const QWORD *CurrentKernelValue,
    _In_opt_ const QWORD *CurrentUserValue
    )
///
/// @brief  Checks the self map entry for a given process
///
/// This function verifies if any relevant bits have changed in the self map entry inside the Process page table. If
/// it detects any changes, it lets #IntWinSelfMapHandleCr3SelfMapModification handle those.
/// The relevant changes are defined by #SELF_MAP_ENTRY_IS_DETECTION.
///
/// If the process is swapped-out, the function does nothing.
///
/// @param[in, out] Process             The process for which the checks are done
/// @param[in]      CurrentKernelValue  The current value of the kernel Cr3. If this is NULL, the value will be read
///                                     from the guest
/// @param[in]      CurrentUserValue    The current value of the user Cr3. If KPTI is not enabled this should be NULL.
///                                     If KPTI is enabled and this process has different Cr3 values for user and kernel
///                                     mode, the value will be read from the guest
///
/// @returns        #INT_STATUS_SUCCESS         If successful, or an appropriate INTSTATUS error value.
/// @returns        #INT_STATUS_NOT_NEEDED_HINT If the process is swapped-out.
///
{
    QWORD currentKern, currentUser;
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (Process->Outswapped)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL == CurrentKernelValue)
    {
        status = IntPhysicalMemRead(SELF_MAP_ENTRY(Process->Cr3), sizeof(QWORD), &currentKern, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysicalMemRead failed: 0x%08x\n", status);
            goto _exit;
        }
    }
    else
    {
        currentKern = *CurrentKernelValue;
    }

    if (NULL == CurrentUserValue && Process->Cr3 != Process->UserCr3)
    {
        status = IntPhysicalMemRead(SELF_MAP_ENTRY(Process->UserCr3), sizeof(QWORD), &currentUser, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysicalMemRead failed: 0x%08x\n", status);
            goto _exit;
        }
    }
    else if (Process->Cr3 != Process->UserCr3)
    {
        currentUser = *CurrentUserValue;
    }
    else
    {
        goto _only_kern_check;
    }

    // When in beta, we should also verify that our stored value didn't have the U/S bit as on kernel beta detections
    // we only want to give an alert when this bit was modified vs. what we have stored instead of sending an alert
    // every time we check, but if KernelBetaDetections was changed on the fly we should also consider a detection
    // even if our previously stored value had U/S bit activated.
    if (Process->Cr3 != Process->UserCr3)
    {
        if (SELF_MAP_ENTRY_IS_DETECTION(currentUser) &&
            ((Process->UserSelfMapEntryValue & PT_US) != (currentUser & PT_US) || !gGuest.KernelBetaDetections))
        {
            status = IntWinSelfMapHandleCr3SelfMapModification(currentUser, Process->UserSelfMapEntryValue, Process,
                                                               Process->UserCr3);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinSelfMapCr3SelfMapModification failed: 0x%x\n", status);
            }
        }
        else if (Process->UserSelfMapEntryValue != currentUser)
        {
            Process->UserSelfMapEntryValue = currentUser;
        }
    }

_only_kern_check:
    if (SELF_MAP_ENTRY_IS_DETECTION(currentKern) &&
        ((Process->SelfMapEntryValue & PT_US) != (currentKern & PT_US) || !gGuest.KernelBetaDetections))
    {
        status = IntWinSelfMapHandleCr3SelfMapModification(currentKern,
                                                           Process->SelfMapEntryValue,
                                                           Process,
                                                           Process->Cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSelfMapCr3SelfMapModification failed: 0x%x\n", status);
        }
    }
    else if (Process->SelfMapEntryValue != currentKern)
    {
        Process->SelfMapEntryValue = currentKern;
    }

_exit:
    return status;
}


static INTSTATUS
IntWinSelfMapHandleCr3SelfMapWrite(
    _Inout_ WIN_PROCESS_OBJECT *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Handles writes done to the self map entry inside a process page tables
///
/// This is the handler of the EPT hook set by #IntWinSelfMapProtectSelfMapIndex, which will be done for processes
/// that are already protected. For processes that are not protected, the self map checks are done using the integrity
/// mechanism by the #IntWinSelfMapValidateSelfMapEntries function.
/// In cases in which the present bit is removed, the hook on the page table entry is removed. This happens for
/// privileged processes that do not keep their user Cr3 value.
/// If the old value is 0, the action is allowed even if it would normally justify a detection, as we have to let
/// the operating system load a Cr3 value if there is nothing loaded at the moment.
///
/// @param[in, out] Context     The process for which the change was made
/// @param[in]      Hook        The #HOOK_GPA for which this callback was invoked
/// @param[in]      Address     The accessed guest physical address
/// @param[out]     Action      The action that must be taken
///
/// @returns        #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    WIN_PROCESS_OBJECT *pProc = Context;
    INTSTATUS status;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    IG_ARCH_REGS *regs;
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    QWORD gva;
    QWORD cr3Modified;
    BOOLEAN isBeta;

    regs = &gVcpu->Regs;
    action = introGuestNotAllowed;
    reason = introReasonNoException;
    isBeta = IntPolicyCoreIsOptionBeta(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY);

    cr3Modified = CLEAN_PHYS_ADDRESS64(pProc->Cr3) == CLEAN_PHYS_ADDRESS64(Address) ? pProc->Cr3 : pProc->UserCr3;

    if (!gVcpu->PtEmuBuffer.Valid)
    {
        action = introGuestAllowed;
        reason = introReasonAllowed;
        goto cleanup_and_exit;
    }

    // KPTI is enabled and relevant only for non-privileged processes. Processes which are already privileged
    // (running as system/admin/etc.), do start with both the kernel and user CR3 allocated & initialized, but soon
    // after the process is created, the user CR3 will be freed. The self-map mechanism will keep the protection on
    // that user CR3. Eliminate the self-map protection on user CR3 once they are removed; we can figure out that a
    // user CR3 is deleted when the self-map entry for tit is made invalid (present bit == 0).
    if (!!(gVcpu->PtEmuBuffer.Old & PT_P) &&
        !(gVcpu->PtEmuBuffer.New & PT_P))
    {
        action = introGuestAllowed;
        reason = introReasonAllowed;

        if (Hook == pProc->SelfMapHook)
        {
            pProc->SelfMapHook = NULL;
        }
        else if (Hook == pProc->UserSelfMapHook)
        {
            pProc->UserSelfMapHook = NULL;
        }

        status = IntHookGpaRemoveHook((HOOK_GPA **)&Hook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }

        return INT_STATUS_SUCCESS;
    }

    if (gVcpu->PtEmuBuffer.Old == 0 ||
        (!SELF_MAP_ENTRY_IS_DETECTION(gVcpu->PtEmuBuffer.New)))
    {
        action = introGuestAllowed;
        reason = introReasonAllowed;

        IntWinSelfMapSelfMapUpdate(cr3Modified, pProc, gVcpu->PtEmuBuffer.New);

        goto cleanup_and_exit;
    }

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntExceptKernelGetOriginator failed: 0x%08x\n", status);
    }

    gva = SELF_MAP_ENTRY_VA;

    status = IntExceptGetVictimEpt(Context, Address, gva, introObjectTypeSelfMapEntry, ZONE_WRITE, &victim);

    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        goto _exit_exceptions;
    }

    // overwrite with these values
    victim.WriteInfo.NewValue[0] = gVcpu->PtEmuBuffer.New;
    victim.WriteInfo.OldValue[0] = gVcpu->PtEmuBuffer.Old;
    victim.WriteInfo.AccessSize = sizeof(QWORD);

    IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventEptViolation);

_exit_exceptions:
    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY, &action, &reason))
    {
        EVENT_EPT_VIOLATION *pEpt = &gAlert.Ept;

        memzero(pEpt, sizeof(*pEpt));

        WARNING("[WARNING] Self-mapping entry modified for process '%s' with CR3 %llx (%s), "
                "addr %llx, from 0x%016llx to 0x%016llx from RIP 0x%016llx\n",
                pProc->Name,
                cr3Modified,
                cr3Modified == pProc->Cr3 ? "kernel" : "user",
                Address,
                gVcpu->PtEmuBuffer.Old,
                gVcpu->PtEmuBuffer.New,
                regs->Rip);

        if (!isBeta)
        {
            QWORD *pPage = NULL;

            status = IntPhysMemMap(Address, sizeof(QWORD), 0, &pPage);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
                goto just_send_alert;
            }

            gVcpu->PtEmuBuffer.New &= (~PT_US);

            pPage[0] = gVcpu->PtEmuBuffer.New;

            IntPhysMemUnmap(&pPage);

            IntWinSelfMapSelfMapUpdate(cr3Modified, pProc, gVcpu->PtEmuBuffer.New);
        }

just_send_alert:
        pEpt->Header.Action = action;
        pEpt->Header.Reason = reason;
        pEpt->Header.MitreID = idRootkit;

        IntAlertFillCpuContext(TRUE, &pEpt->Header.CpuContext);

        IntAlertEptFillFromKmOriginator(&originator, pEpt);
        IntAlertEptFillFromVictimZone(&victim, pEpt);

        pEpt->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY, reason);

        if (pProc->SystemProcess)
        {
            pEpt->Header.Flags |= ALERT_FLAG_SYSPROC;
        }

        IntAlertFillWinProcessByCr3(regs->Cr3, &pEpt->Header.CurrentProcess);

        IntAlertFillCodeBlocks(originator.Original.Rip, regs->Cr3, FALSE, &pEpt->CodeBlocks);
        IntAlertFillExecContext(regs->Cr3, &pEpt->ExecContext);

        IntAlertFillVersionInfo(&pEpt->Header);

        status = IntNotifyIntroEvent(introEventEptViolation, pEpt, sizeof(*pEpt));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

cleanup_and_exit:
    if (isBeta || action == introGuestAllowed)
    {
        IntWinSelfMapSelfMapUpdate(cr3Modified, pProc, gVcpu->PtEmuBuffer.New);
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_SELF_MAP_ENTRY, &action);

    *Action = action;

    return INT_STATUS_SUCCESS;
}


TIMER_FRIENDLY INTSTATUS
IntWinSelfMapValidateSelfMapEntries(
    void
    )
///
/// @brief  Validates the self map entries for every process in the system
///
/// This function is used by the integrity mechanism in order to perform self map entry validations. Due to performance
/// reasons, we can't hook the self map entry for every process in the system. For processes that are already protected
/// this is not a problem, as we already have hooks placed inside their page tables. For the other processes we
/// delegate the check to the periodic integrity callback.
/// It uses the #IntWinSelfMapCheckSelfMapEntry function to check the self map entry for every process on the system.
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT if the guest is not initialized or the protection is not active
/// @retval #INT_STATUS_NOT_NEEDED_HINT if the guest is not Windows, not using 4- or 5-level paging (the other paging
///         modes do not use the self map mechanism), or if the #INTRO_OPT_PROT_KM_SELF_MAP_ENTRY activation option
///         was not provided
///
{
    LIST_ENTRY *pList = NULL;

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) ||
        (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SELF_MAP_ENTRY) == 0 ||
        (gGuest.Mm.Mode != PAGING_4_LEVEL_MODE &&
         gGuest.Mm.Mode != PAGING_5_LEVEL_MODE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    STATS_ENTER(statsSelfMapEntryProtection);

    pList = gWinProcesses.Flink;
    while (pList != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProcess = CONTAINING_RECORD(pList, WIN_PROCESS_OBJECT, Link);
        INTSTATUS status;

        pList = pList->Flink;

        status = IntWinSelfMapCheckSelfMapEntry(pProcess, NULL, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinCheckSelfMapEntry failed: 0x%08x\n", status);
        }
    }

    STATS_EXIT(statsSelfMapEntryProtection);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinSelfMapEnableSelfMapEntryProtection(
    void
    )
///
/// @brief  Enables the self map protection mechanism for the entire system
///
/// It will first check the self map index of every process using #IntWinSelfMapCheckSelfMapEntry, then the actual
/// protection will be activated using #IntWinSelfMapProtectSelfMapIndex.
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT if the guest is not initialized or the protection is not active
/// @retval #INT_STATUS_NOT_NEEDED_HINT if the guest is not Windows, not using 4- or 5-level paging (the other paging
///         modes do not use the self map mechanism)
///
{
    PLIST_ENTRY pList = NULL;

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) ||
        (gGuest.Mm.Mode != PAGING_4_LEVEL_MODE &&
         gGuest.Mm.Mode != PAGING_5_LEVEL_MODE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pList = gWinProcesses.Flink;
    while (pList != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProcess = CONTAINING_RECORD(pList, WIN_PROCESS_OBJECT, Link);
        INTSTATUS status;

        pList = pList->Flink;

        status = IntWinSelfMapCheckSelfMapEntry(pProcess, NULL, NULL);

        // no point in protecting the process if it already has a hook on it...
        if (pProcess->SelfMapHook != NULL && pProcess->UserSelfMapHook != NULL)
        {
            continue;
        }

        status = IntWinSelfMapProtectSelfMapIndex(pProcess);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProtectSelfMapIndex failed: 0x%08x\n", status);
            continue;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinSelfMapGetAndCheckSelfMapEntry(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Sets and validates the self map entry values for a process
///
/// If KPTI enabled for Process, this will read and validate both the kernel and the user Cr3. If not, only the kernel
/// Cr3 will be considered, as the user Cr3 will be 0. The values are obtained from the _KPROCESS kernel structure.
/// If the #INTRO_OPT_PROT_KM_SELF_MAP_ENTRY option was used, and a malicious change of the self map value is detected,
/// an alert will eventually be sent.
/// If the process is swapped-out, the function does nothing.
///
/// @param[in, out] Process     The process for which the values are read and validated
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_INVALID_PARAMETER_1 if Process is NULL
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT if the guest is not initialized or the protection is not active
/// @retval #INT_STATUS_NOT_NEEDED_HINT if the guest is not Windows, not using 4- or 5-level paging (the other paging
///         modes do not use the self map mechanism) or the process is swapped-out.
///
{
    INTSTATUS status;
    QWORD currentKern, currentUser;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) ||
        (gGuest.Mm.Mode != PAGING_4_LEVEL_MODE &&
         gGuest.Mm.Mode != PAGING_5_LEVEL_MODE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntPhysicalMemRead(SELF_MAP_ENTRY(Process->Cr3), sizeof(QWORD), &currentKern, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysicalMemRead failed: 0x%08x\n", status);
        goto _exit;
    }

    // assume current self map entry value has U/S bit deactivated, as we should give a detection on integrity checking
    Process->SelfMapEntryValue = (currentKern & (~PT_US));

    status = IntPhysicalMemRead(SELF_MAP_ENTRY(Process->UserCr3), sizeof(QWORD), &currentUser, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysicalMemRead failed: 0x%08x\n", status);
        goto _exit;
    }

    // assume current self map entry value has U/S bit deactivated, as we should give a detection on integrity checking
    Process->UserSelfMapEntryValue = (currentUser & (~PT_US));

    if (0 != (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SELF_MAP_ENTRY))
    {
        status = IntWinSelfMapCheckSelfMapEntry(Process, &currentKern, &currentUser);
    }

_exit:
    return status;
}


INTSTATUS
IntWinSelfMapDisableSelfMapEntryProtection(
    void
    )
///
/// @brief  Disables the self map entry protection for all the processes on the system
///
/// This will deactivate protection and will remove any hooks set by #IntWinSelfMapProtectSelfMapIndex
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT if the guest is not initialized or the protection is not active
/// @retval #INT_STATUS_NOT_NEEDED_HINT if the guest is not Windows, not using 4- or 5-level paging (the other paging
///         modes do not use the self map mechanism)
///
{
    LIST_ENTRY *pList = NULL;

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) ||
        (gGuest.Mm.Mode != PAGING_4_LEVEL_MODE &&
         gGuest.Mm.Mode != PAGING_5_LEVEL_MODE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pList = gWinProcesses.Flink;
    while (pList != &gWinProcesses)
    {
        WIN_PROCESS_OBJECT *pProcess = CONTAINING_RECORD(pList, WIN_PROCESS_OBJECT, Link);
        INTSTATUS status;

        pList = pList->Flink;

        status = IntWinSelfMapUnprotectSelfMapIndex(pProcess);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSelfMapUnprotectSelfMapIndex failed: 0x%08x\n", status);
            continue;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinSelfMapProtectSelfMapIndex(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Protects the self map index of a process by placing an EPT write hook on it
///
/// Essentially, this will protect the user/supervisor bit, in order to make sure that user mode code can not
/// access the page tables.
/// Currently, this is enabled only for the system process, as other processes may swap out their Cr3 contents.
/// Processes that have their self map entry protected in this way will have an EPT hook set on the page of their
/// kernel and user Cr3 (if KPTI is enabled). Because of this, care should be taken when activating this for processes,
/// as it may have a negative impact on performance because the kernel may do a lot of writes on those pages. This is
/// manageable for processes that are already protected, as we have other hooks placed on their page tables already.
/// The EPT hook handler used is #IntWinSelfMapHandleCr3SelfMapWrite.
///
/// @param[in]  Process     The process for which the protection is activated
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Process is NULL
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the guest is not Windows, not using 4- or 5-level paging (the other
///             paging modes do not use the self map mechanism)
///
{

    INTSTATUS status = INT_STATUS_SUCCESS;
    BOOLEAN bShouldProtect = FALSE;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if ((introGuestWindows != gGuest.OSType) ||
        (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SELF_MAP_ENTRY) == 0 ||
        (gGuest.Mm.Mode != PAGING_4_LEVEL_MODE &&
         gGuest.Mm.Mode != PAGING_5_LEVEL_MODE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Force only integrity mechanism to kick-in: as we have seen, processes might be "swapped-out"
    // (see MmSwapOutProcess) - when a process is then swapped in (see MmSwapInProcess), it verifies OutSwapped
    // flag in EPROCESS.Flags, and if it is set, it copies the whole upper entries (>0x800) from the current process
    // kernel PML4 into the upper entries of the swapped in process PML4, using memmove, case in which some MOVDQA
    // instructions come on kernel page tables (because this is the only hook we put on kernel page tables on
    // protected processes). So, until we find a better solution, keep only the integrity check.
    bShouldProtect = Process->Pid == 4;

    TRACE("[INFO] Protecting self-mapping entry for process %s, pid %d with CR3: %llx, UserCR3: %llx with %s\n",
          Process->Name, Process->Pid, Process->Cr3, Process->UserCr3, bShouldProtect ? "EPT" : "INTEGRITY");

    if (bShouldProtect)
    {
        if (Process->SelfMapHook == NULL)
        {
            status = IntHookGpaSetHook(SELF_MAP_ENTRY(Process->Cr3),
                                       sizeof(QWORD),
                                       IG_EPT_HOOK_WRITE,
                                       IntWinSelfMapHandleCr3SelfMapWrite,
                                       Process,
                                       NULL,
                                       HOOK_FLG_PAGING_STRUCTURE | HOOK_FLG_HIGH_PRIORITY,
                                       (PHOOK_GPA *)&Process->SelfMapHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaSetHook failed: 0x%08x\n", status);
            }
        }

        // Avoid double hooking
        if (Process->Cr3 != Process->UserCr3 && Process->UserSelfMapHook == NULL)
        {
            status = IntHookGpaSetHook(SELF_MAP_ENTRY(Process->UserCr3),
                                       sizeof(QWORD),
                                       IG_EPT_HOOK_WRITE,
                                       IntWinSelfMapHandleCr3SelfMapWrite,
                                       Process,
                                       NULL,
                                       HOOK_FLG_PAGING_STRUCTURE | HOOK_FLG_HIGH_PRIORITY,
                                       (PHOOK_GPA *)&Process->UserSelfMapHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaSetHook failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}


INTSTATUS
IntWinSelfMapUnprotectSelfMapIndex(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief  Removes the EPT protection for the self map entry index of a process
///
/// This removes the EPT hooks set by #IntWinSelfMapProtectSelfMapIndex.
///
/// @param[in]  Process     The process for which the protection is removed.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Process is NULL
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (Process == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    TRACE("[INFO] Deactivating self-map index protection for %s (pid %d, cr3: kernel %016llx, user: %016llx)\n",
          Process->Name, Process->Pid, Process->Cr3, Process->UserCr3);

    if (Process->SelfMapHook != NULL)
    {
        status = IntHookGpaRemoveHook((HOOK_GPA **)&Process->SelfMapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }
    }

    if (Process->UserSelfMapHook != NULL)
    {
        status = IntHookGpaRemoveHook((HOOK_GPA **)&Process->UserSelfMapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }
    }

    return status;
}
