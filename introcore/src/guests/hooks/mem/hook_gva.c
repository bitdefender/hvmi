/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook.h"
#include "hook_gva.h"
#include "alerts.h"
#include "memcloak.h"


static INTSTATUS
IntHookGvaDisableHooks(
    _In_ HOOK_GVA *Hook
    )
///
/// @brief Deactivates a GVA hook.
///
/// The GVA hook will be disabled, by completely removing the GPA hook placed on the physical page that the GVA
/// translates to. Before removing the GPA hook, a hash will be computed on the entire page, if integrity check is on.
///
/// @param[in]  Hook    The GVA hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If no GPA hook is set for this GVA hook.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == Hook->GpaHook)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    Hook->Hash = 0;

    if (Hook->IsIntegrityOn)
    {
        status = IntMemClkHashRegion(Hook->GvaPage + Hook->Offset,
                                     Hook->GpaHook->GpaPage + Hook->Offset,
                                     Hook->Length,
                                     &Hook->Hash);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkHashPage failed: 0x%08x\n", status);
        }
    }

    status = IntHookGpaRemoveHook(&Hook->GpaHook, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntHookGvaEnableHooks(
    _In_ HOOK_GVA *Hook,
    _In_ QWORD NewGpaPage
    )
///
/// @brief Enable a GVA hook.
///
/// The GPA hook for the physical page this GVA translates to will be hooked. In addition, if integrity check
/// is enabled, a hash will be computed on the newly mapped page. If this hash is not the same as the one
/// computed when the hook was disabled, an integrity check alert is generated.
///
/// @param[in]  Hook        The GVA hook.
/// @param[in]  NewGpaPage  The new guest physical page the hooked GVA translates to.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD crc;

    status = IntHookGpaSetHook(NewGpaPage + Hook->Offset,
                               Hook->Length,
                               Hook->Header.EptHookType,
                               Hook->Callback.Access,
                               Hook->Header.Context,
                               Hook,
                               0,
                               &Hook->GpaHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaSetHook failed: 0x%08x\n", status);
    }

    // Compute the hash on the given entity, to make sure it hasn't changed.
    if (Hook->IsIntegrityOn)
    {
        crc = 0;

        status = IntMemClkHashRegion(Hook->GvaPage + Hook->Offset,
                                     NewGpaPage + Hook->Offset,
                                     Hook->Length,
                                     &crc);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkHashPage failed: 0x%08x\n", status);
            return status;
        }

        if (0 == Hook->Hash)
        {
            Hook->Hash = crc;
        }
        else if (crc != Hook->Hash)
        {
            EVENT_TRANSLATION_VIOLATION *pTrViol = &gAlert.Translation;

            WARNING("[WARNING] Integrity validation failed on page 0x%016llx/0x%016llx (length: %x, offset: %x), "
                    "computed hash is 0x%08x, stored hash is 0x%08x!\n",
                    NewGpaPage,
                    Hook->GvaPage,
                    Hook->Length,
                    Hook->Offset,
                    crc,
                    Hook->Hash);

            memzero(pTrViol, sizeof(*pTrViol));

            pTrViol->Header.Action = introGuestAllowed;
            pTrViol->Header.Reason = introReasonNoException;
            pTrViol->Header.MitreID = idRootkit;

            pTrViol->WriteInfo.NewValue[0] = NewGpaPage + Hook->Offset;
            pTrViol->WriteInfo.OldValue[0] = 0;
            pTrViol->WriteInfo.Size = sizeof(QWORD);

            pTrViol->Victim.VirtualAddress = Hook->GvaPage + Hook->Offset;
            pTrViol->ViolationType = transViolationPageHash;

            IntAlertFillCpuContext(TRUE, &pTrViol->Header.CpuContext);

            pTrViol->Header.Flags = IntAlertCoreGetFlags(0, introReasonUnknown);

            if (gGuest.KernelBetaDetections)
            {
                pTrViol->Header.Flags |= ALERT_FLAG_BETA;
            }

            if (introGuestWindows == gGuest.OSType)
            {
                EXCEPTION_KM_ORIGINATOR originator;

                memzero(&originator, sizeof(originator));

                IntAlertFillWinProcessCurrent(&pTrViol->Header.CurrentProcess);

                status = IntExceptKernelGetOriginator(&originator, 0);
                if (!INT_SUCCESS(status))
                {
                    WARNING("[WARNING] Failed to get originator on translation violation, RIP: %llx\n",
                            pTrViol->Header.CpuContext.Rip);
                }

                IntAlertFillWinKmModule(originator.Original.Driver, &pTrViol->Originator.Module);
                IntAlertFillWinKmModule(originator.Return.Driver, &pTrViol->Originator.ReturnModule);
            }
            else
            {
                pTrViol->Header.CurrentProcess.Valid = FALSE;
            }

            IntAlertFillVersionInfo(&pTrViol->Header);

            status = IntNotifyIntroEvent(introEventTranslationViolation, pTrViol, sizeof(*pTrViol));
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}


static INTSTATUS
IntHookGvaRemoveHookInternal(
    _In_ HOOK_GVA *Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a GVA hook.
///
/// The GVA hook will be marked for removal. This function also removes the GPA hook established on the physical
/// page and the PTS hook establishes on the page-tales used to translate the hooked GVA. The hook will be marked
/// for removal, and it will either be deleted during the commit phase, or it will be deleted by a higher level
/// hook manager.
///
/// @param[in]  Hook    The GVA hook.
/// @param[in]  Flags   The removal flags. Can be #HOOK_FLG_CHAIN_DELETE for a chained delete.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the hook has already been removed.
///
{
    INTSTATUS status;

    if (0 != (Hook->Header.Flags & HOOK_FLG_REMOVE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL != Hook->GpaHook)
    {
        status = IntHookGpaRemoveHook(&Hook->GpaHook, HOOK_FLG_CHAIN_DELETE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }
    }

    // Remove the PT hook, if any. There may be cases when the PT entry is not hooked; this happens
    // when the PT is not present (the PD entry is invalid).
    if (NULL != Hook->PtsHook)
    {
        status = IntHookPtsRemoveHook((HOOK_PTS **)&Hook->PtsHook, HOOK_FLG_CHAIN_DELETE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsRemoveHook failed: 0x%08x\n", status);
        }
    }

    Hook->Header.Flags |= (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE);

    if (0 != (Flags & HOOK_FLG_CHAIN_DELETE))
    {
        Hook->Header.Flags |= HOOK_FLG_CHAIN_DELETE;
    }

    RemoveEntryList(&Hook->Link);

    InsertTailList(&gHooks->GvaHooks.RemovedHooksList, &Hook->Link);

    gHooks->GvaHooks.HooksRemoved = TRUE;

    gHooks->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookGvaHandleSwap(
    _In_ HOOK_GVA *Hook,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief Handle a swap event on a hooked guest virtual page.
///
/// This function will be called whenever a hooked virtual page is swapped in and out of the physical memory.
/// When the page is swapped out, this function will disable the hook on it. When the page is swapped in,
/// the hook will be re-enabled. If the physical page address is changed, the hook will be moved to the new page.
///
/// @param[in]  Hook            The GVA hook.
/// @param[in]  VirtualAddress  Swapped guest virtual address.
/// @param[in]  OldEntry        Old page table entry.
/// @param[in]  NewEntry        New page table entry.
/// @param[in]  OldPageSize     Old page size.
/// @param[in]  NewPageSize     New page size.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD newValue, oldValue, newGpaPage;
    BOOLEAN disableHook, enableHook;

    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(OldPageSize);
    UNREFERENCED_PARAMETER(Hook);

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = INT_STATUS_SUCCESS;
    newValue = NewEntry;
    oldValue = OldEntry;
    newGpaPage = 0;
    disableHook = enableHook = FALSE;

    // And actually handle the swap operation.
    if ((((oldValue & 1) == 1)) && (((newValue & 1) == 0)))
    {
        // Transition from present to non-present -> disable GVA hooks on this page.
        // The page was just swapped out.
        disableHook = TRUE;
    }
    else if ((((oldValue & 1) == 0)) && (((newValue & 1) == 1)))
    {
        // Transition from non-present to present -> enable GVA hooks on this page.
        // The page was just swapped in.
        enableHook = TRUE;
    }
    else if (((oldValue & 1) == 1) && ((newValue & 1) == 1) &&
             (CLEAN_PHYS_ADDRESS64(oldValue) != CLEAN_PHYS_ADDRESS64(newValue)))
    {
        // Transition from present to present, but with different GPA -> disable & re-enable the GVA hooks on this page.
        // This usually happens on COW (Copy On Write) inside user space, but may also happen with other reasons,
        // depending on the OSs mm policies.
        disableHook = enableHook = TRUE;
    }

    if (disableHook)
    {
        status = IntHookGvaDisableHooks(Hook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaDisableHooks failed: 0x%08x\n", status);
        }
    }

    if (!!(newValue & PT_P))
    {
        newGpaPage = (CLEAN_PHYS_ADDRESS64(newValue) & (~(NewPageSize - 1))) + (Hook->GvaPage & (NewPageSize - 1));
        Hook->IsPageWritable = !!(newValue & PT_RW);
    }

    if (enableHook)
    {
        status = IntHookGvaEnableHooks(Hook, newGpaPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaEnableHooks failed: 0x%08x\n", status);
        }
    }

    return status;
}


INTSTATUS
IntHookGvaSetHook(
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_ BYTE Type,
    _In_ void *Callback,
    _In_opt_ void *Context,
    _In_opt_ void *ParentHook,
    _In_opt_ DWORD Flags,
    _Out_opt_ HOOK_GVA **GvaHook
    )
///
/// @brief Set a read, write, execute or swap hook on a guest virtual address.
///
/// This function establishes an EPT hook on the indicates guest virtual (linear) address. A guest virtual address
/// hook usually consists of two children hooks:
/// 1. PTS hook - this hook covers all page-table entries the provided Gva translates through; any change in any level
///    of the page-tables will lead to the guest physical hook being updated, thus maintaining a consistent association
///    between the hooked guest virtual address and the guest physical address it translates to.
/// 2. GPA hook - this is the actual EPT hook; since EPT works with guest physical pages, all hooks end up being a
///    guest physical hook. This hook will be removed whenever the guest virtual page is swapped out, and it will be
///    restored each time it is swapped in.
/// This function can be used to set read, write or execute hook on the memory interval given by
/// [Gva, Gva + Length - 1].
/// This interval cannot exceed a page boundary. Gva needs not be page aligned. In this case, a PTS hook and a GPA hook
/// will be established. In this case, Callback must be a #PFUNC_EptViolationCallback.
/// This function can also be used to establish a swap hook on the given virtual page. In this case, low 12 bits from
/// Gva are ignored, as is the Length argument. In this case, Callback must be #PFUNC_SwapCallback and the Type must be
/// #IG_EPT_HOOK_NONE.
/// NOTE: Since EPT hooks can only be placed on guest physical pages, this function takes care of translating the
/// virtual address to a physical address in order to hook that page using EPT. It also takes care internally of swap
/// operations, so the guest physical hook will be updated whenever a translation change is made to this virtual
/// address.
///
/// @param[in]  Cr3         The virtual address space the hook is placed in. If this parameter is 0, the current
///                         System Cr3 will be used, meaning that a global hook will be placed (usually for kernel
///                         pages).
/// @param[in]  Gva         The guest virtual address to be hooked.
/// @param[in]  Length      The memory area size to be hooked. Ignored if Type is #IG_EPT_HOOK_NONE.
/// @param[in]  Type        Hook type. Can be #IG_EPT_HOOK_READ, #IG_EPT_HOOK_WRITE, #IG_EPT_HOOK_EXECUTE for regular
///                         EPT hooks, or #IG_EPT_HOOK_NONE for a swap hook.
/// @param[in]  Callback    The callback to be called on [Gva, Gva + Length - 1] accesses. If type is #IG_EPT_HOOK_NONE,
///                         the callback type must be #PFUNC_SwapCallback, otherwise it must be
///                         #PFUNC_EptViolationCallback.
/// @param[in]  Context     Optional context to be passes as a parameter to the callback.
/// @param[in]  ParentHook  Optional parent hook.
/// @param[in]  Flags       Hook flags. Check our HOOK_FLG* for more info.
/// @param[out] GvaHook     Optional output handle for the established hook. Can later be used to remove the hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the hooked memory area spans outside the page.
///
{
    INTSTATUS status, status2;
    PHOOK_GVA pGvaHook;

    pGvaHook = NULL;

    if ((Gva & PAGE_MASK) != ((Gva + Length - 1) & PAGE_MASK))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    Flags &= HOOK_FLG_GLOBAL_MASK;

    if (0 == Cr3)
    {
        Cr3 = gGuest.Mm.SystemCr3;
    }

    pGvaHook = HpAllocWithTag(sizeof(*pGvaHook), IC_TAG_GVAH);
    if (NULL == pGvaHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pGvaHook->Header.Flags = Flags;
    pGvaHook->Header.Context = Context;
    pGvaHook->Header.ParentHook = ParentHook;
    pGvaHook->Header.HookType = hookTypeGva;
    pGvaHook->Header.EptHookType = Type;

    if (Type == IG_EPT_HOOK_NONE)
    {
        pGvaHook->Callback.Swap = Callback;
    }
    else
    {
        pGvaHook->Callback.Access = Callback;
    }

    pGvaHook->GvaPage = Gva & PAGE_MASK;
    pGvaHook->Offset = Gva & PAGE_OFFSET;
    pGvaHook->Length = (WORD)Length;    // Safe cast, Length is never > PAGE_SIZE
    pGvaHook->IsIntegrityOn = (Type == IG_EPT_HOOK_WRITE) && (gGuest.Mm.SystemCr3 == Cr3);
    pGvaHook->IsPageWritable = FALSE;

    InsertTailList(&gHooks->GvaHooks.GvaHooks, &pGvaHook->Link);

    if (IG_EPT_HOOK_NONE != Type)
    {
        status = IntHookPtsSetHook(Cr3, Gva, IntHookGvaHandleSwap, pGvaHook, pGvaHook, Flags, &pGvaHook->PtsHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsSetHook failed: 0x%08x\n", status);
            pGvaHook->PtsHook = NULL;
            goto cleanup_and_exit;
        }

        // If the page is present and the type is not none, we set the actual GPA hook on the page.
        if (!!(pGvaHook->PtsHook->CurEntry & PT_P))
        {
            status = IntHookGvaHandleSwap(pGvaHook,
                                          pGvaHook->GvaPage,
                                          0,
                                          pGvaHook->PtsHook->CurEntry,
                                          0,
                                          pGvaHook->PtsHook->CurPageSize);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaHandleSwap failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }
        }
    }
    else
    {
        // If EPT_HOOK_NONE is used as a type, then this is a swap-in callback. Note that for these hooks, a
        // higher priority will be used.
        status = IntHookPtsSetHook(Cr3, Gva, Callback, Context, pGvaHook, Flags, &pGvaHook->PtsHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsSetHook failed: 0x%08x\n", status);
            pGvaHook->PtsHook = NULL;
            goto cleanup_and_exit;
        }
    }

    if (NULL != GvaHook)
    {
        *GvaHook = pGvaHook;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        status2 = IntHookGvaRemoveHookInternal(pGvaHook, 0);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntHookGvaRemoveHookInternal failed: 0x%08x\n", status2);
        }
    }

    gHooks->Dirty = TRUE;

    return status;
}


INTSTATUS
IntHookGvaRemoveHook(
    _Inout_ HOOK_GVA **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a GVA hook.
///
/// Removes the indicated GVA hook, together with any PTS or GPA hooks established through it. This function
/// will not delete the hook - the actual deletion will be made either during the commit phase, or when
/// the caller of this function (if it is a higher level hook system) decides so.
///
/// @param[in, out] Hook    The GVA hook to be removed.
/// @param[in]      Flags   Flags. See HOOK_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == *Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Flags &= HOOK_FLG_GLOBAL_MASK;

    status = IntHookGvaRemoveHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaRemoveHookInternal failed: 0x%08x\n", status);
    }

    if (!(Flags & HOOK_FLG_CHAIN_DELETE))
    {
        *Hook = NULL;
    }

    return status;
}


static INTSTATUS
IntHookGvaDeleteHookInternal(
    _In_ HOOK_GVA *Hook,
    _In_ DWORD Flags
    )
///
/// @brief Completely delete a GVA hook.
///
/// Delete the indicated GVA hook, together with the PTS or GPA hooks established through it.
///
/// @param[in]  Hook    The GVA hook to be deleted.
/// @param[in]  Flags   Flags. See HOOK_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If the hook was not previously marked as removed.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    if (0 == (Hook->Header.Flags & HOOK_FLG_REMOVE))
    {
        ERROR("[ERROR] Trying to delete a non-removed hook!\n");
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    STATS_ENTER(statsDeleteGva);

    if (NULL != Hook->GpaHook)
    {
        status = IntHookGpaDeleteHook(&Hook->GpaHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaDeleteHook failed: 0x%08x\n", status);
        }
    }

    if (NULL != Hook->PtsHook)
    {
        status = IntHookPtsDeleteHook((HOOK_PTS **)&Hook->PtsHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsDeleteHook failed: 0x%08x\n", status);
        }
    }

    RemoveEntryList(&Hook->Link);

    HpFreeAndNullWithTag(&Hook, IC_TAG_GVAH);

    STATS_EXIT(statsDeleteGva);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGvaDeleteHook(
    _Inout_ HOOK_GVA **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Completely delete a GVA hook.
///
/// Delete the indicated GVA hook, together with the PTS or GPA hooks established through it.
///
/// @param[in, out] Hook    The GVA hook to be deleted. Will be set to NULL on return.
/// @param[in]      Flags   Flags. See HOOK_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is used.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == *Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Flags &= HOOK_FLG_GLOBAL_MASK;

    status = IntHookGvaDeleteHookInternal(*Hook, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaDeleteHookInternal failed: 0x%08x\n", status);
    }

    *Hook = NULL;

    return status;
}


INTSTATUS
IntHookGvaCommitHooks(
    void
    )
///
/// @brief Commit all the modified GVA hooks.
///
/// This function will delete all GVA hooks which were previously marked as removed. Hooks marked with the
/// #HOOK_FLG_CHAIN_DELETE flag will not be deleted now, as it is expected that a higher level hook manager
/// will do so.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    LIST_ENTRY *list;

    if (!gHooks->GvaHooks.HooksRemoved)
    {
        return INT_STATUS_SUCCESS;
    }

    list = gHooks->GvaHooks.RemovedHooksList.Flink;
    while (list != &gHooks->GvaHooks.RemovedHooksList)
    {
        HOOK_GVA *pGvaHook = CONTAINING_RECORD(list, HOOK_GVA, Link);

        list = list->Flink;

        // Chain-delete means that the hook will be remove by its parent, directly. We don't have to do anything
        // with it.
        if (0 != (pGvaHook->Header.Flags & HOOK_FLG_CHAIN_DELETE))
        {
            continue;
        }

        if (pGvaHook->Header.Flags & HOOK_FLG_REMOVE)
        {
            INTSTATUS status = IntHookGvaDeleteHookInternal(pGvaHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaDeleteHookInternal failed: 0x%08x\n", status);
            }
        }
        else
        {
            ERROR("[ERROR] Invalid hook state: %x for hook at GVA 0x%016llx\n",
                  pGvaHook->Header.Flags, pGvaHook->GvaPage);
            IntEnterDebugger();
        }
    }

    gHooks->GvaHooks.HooksRemoved = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGvaInit(
    void
    )
///
/// @brief Initialize the GVA hooks system.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    InitializeListHead(&gHooks->GvaHooks.GvaHooks);

    InitializeListHead(&gHooks->GvaHooks.RemovedHooksList);

    return INT_STATUS_SUCCESS;
}
