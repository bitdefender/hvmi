/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook.h"
#include "hook_ptm.h"
#include "vecore.h"


///
/// Local invocation context, so we don't cause deadlocks while calling the modification callback.
///
typedef struct _INVOCATION_CONTEXT
{
    LIST_ENTRY          Link;               ///< List element entry.
    void                *Context;           ///< Context to be passed to the Callback.
    PFUNC_EptViolationCallback Callback;    ///< Write callback to be called for the modification.
} INVOCATION_CONTEXT, *PINVOCATION_CONTEXT;



static INTSTATUS
IntHookPtmWriteCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Called whenever a monitored page-table is written.
///
/// This callback is called whenever a write takes place inside a monitored page-table. Note that page-table
/// monitoring is optimized - we will have a single such callback for each hooked page-table, no matter how
/// many actual swap hooks are established on virtual addresses which translate through that page-table.
/// Inside this callback, each #HOOK_PTS_ENTRY hook callback will be called for handling.
///
/// @param[in]  Context     User supplied context, a #PHOOK_PTM_TABLE on this case.
/// @param[in]  Hook        The GPA hook handle.
/// @param[in]  Address     The written physical address.
/// @param[out] Action      Action to be taken.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PHOOK_PTM_TABLE pPt;
    DWORD i, offset;
    LIST_HEAD localCallbacksList;
    LIST_ENTRY *list;
#define LOCAL_BUF_SIZE 4
    INVOCATION_CONTEXT lc[LOCAL_BUF_SIZE] = { 0 }; // First 4 callbacks won't need heap allocations.

    UNREFERENCED_PARAMETER(Hook);


    if (Context == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Action == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    status = INT_STATUS_SUCCESS;
    i = 0;
    InitializeListHead(&localCallbacksList);

    *Action = introGuestAllowed;

    pPt = (PHOOK_PTM_TABLE)Context;

    STATS_ENTER(statsPtWriteTotal);

    offset = gGuest.PaeEnabled ? (Address & 0xFFF) >> 3 : (Address & 0xFFF) >> 2;

    // If this entry is not monitored, update the #VE cache.
    if ((gGuest.Mm.Mode == PAGING_4_LEVEL_MODE) && IsListEmpty(&pPt->Entries[offset]))
    {
        // No hooks on this entry, add it in the cache. Also, add the next 7 entries, if needed,
        // for spatial & time locality. It seems that experimentally, at least on a RS5 x64, there's no improvement
        // from 8 to 16 entries cached at once.
        for (DWORD k = 0; k < 8 && k + offset < pPt->EntriesCount; k++)
        {
            if (IsListEmpty(&pPt->Entries[offset + k]))
            {
                status = IntVeUpdateCacheEntry(Address + k * 8ull, FALSE);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntVeUpdateCacheEntry failed: 0x%08x\n", status);
                }
            }
        }

        status = INT_STATUS_SUCCESS;
        goto _stop_stats_and_exit;
    }

    /// IMPORTANT NOTE: We do not support writes that spill to the next entry. This will be caught by the PTS callback.

    list = pPt->Entries[offset].Flink;
    while (list != &pPt->Entries[offset])
    {
        PINVOCATION_CONTEXT pIc = NULL;
        PHOOK_PTM pPtm = CONTAINING_RECORD(list, HOOK_PTM, Link);

        list = list->Flink;

        if (i < LOCAL_BUF_SIZE)
        {
            pIc = &lc[i];
        }
        else
        {
            pIc = HpAllocWithTag(sizeof(*pIc), IC_TAG_INVC);
            if (NULL == pIc)
            {
                status = INT_STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
        }

        pIc->Callback = pPtm->Callback;
        pIc->Context = pPtm->Header.Context;

        InsertTailList(&localCallbacksList, &pIc->Link);

        i++;
    }

    i = 0;
    list = localCallbacksList.Flink;
    while (list != &localCallbacksList)
    {
        INTSTATUS status2;
        PINVOCATION_CONTEXT pIc = CONTAINING_RECORD(list, INVOCATION_CONTEXT, Link);

        list = list->Flink;

        status2 = pIc->Callback(pIc->Context, Hook, Address, Action);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] Callback failed: 0x%08x\n", status2);

            if (INT_STATUS_ACCESS_DENIED == status2)
            {
                status = status2;
            }
        }

        RemoveEntryList(&pIc->Link);

        if (i >= LOCAL_BUF_SIZE)
        {
            HpFreeAndNullWithTag(&pIc, IC_TAG_INVC);
        }

        i++;
    }

    // If any of the swap-in callbacks returned INT_STATUS_ACCESS_DENIED, than we will block this write.
    if (INT_STATUS_ACCESS_DENIED == status)
    {
        TRACE("[PTM] Callback returned INT_STATUS_ACCESS_DENIED, will block the PT write.\n");
        *Action = introGuestNotAllowed;
    }

_stop_stats_and_exit:
    STATS_EXIT(statsPtWriteTotal);

    if ((gGuest.KernelBetaDetections) && (*Action == introGuestNotAllowed))
    {
        *Action = introGuestAllowed;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtmAddTable(
    _In_ QWORD Gpa,
    _In_ DWORD Flags,
    _Out_ PHOOK_PTM_TABLE *PtHook
    )
///
/// @brief Add a new page-table to the monitored list.
///
/// Either return the #PHOOK_PTM_TABLE entry of an already monitored page-table, or allocate a new one, if the
/// page-table is not already monitored.
///
/// @param[in]  Gpa         The guest physical address of the page-table.
/// @param[in]  Flags       Flags. Use #HOOK_FLG_PAE_ROOT to indicate a PAE root entry.
/// @param[out] PtHook      The found or newly allocated page-table hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation function fails.
///
{
    INTSTATUS status;
    PHOOK_PTM_TABLE pPtHook;
    DWORD hid, i, size;
    LIST_ENTRY *list;

    if (NULL == PtHook)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pPtHook = NULL;

    if (!!(Flags & HOOK_FLG_PAE_ROOT))
    {
        hid = PTM_PAE_ROOT_HOOK_ID(Gpa);
        Gpa &= 0xFFFFFFE0;
    }
    else
    {
        hid = PTM_HOOK_ID(Gpa);
        Gpa &= PHYS_PAGE_MASK;
    }

    list = gHooks->PtmHooks.PtmHooks[hid].Flink;
    while (list != &gHooks->PtmHooks.PtmHooks[hid])
    {
        pPtHook = CONTAINING_RECORD(list, HOOK_PTM_TABLE, Link);

        list = list->Flink;

        if (pPtHook->Gpa == Gpa)
        {
            break;
        }

        pPtHook = NULL;
    }

    if (NULL == pPtHook)
    {
        pPtHook = HpAllocWithTag(sizeof(*pPtHook), IC_TAG_PTPP);
        if (NULL == pPtHook)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_and_exit;
        }

        pPtHook->Header.ParentHook = NULL;
        pPtHook->Header.Flags = Flags;
        pPtHook->Header.HookType = hookTypePtmPt;
        pPtHook->Header.Context = NULL;

        pPtHook->EntriesCount = (gGuest.PaeEnabled ? 512 : 1024);
        pPtHook->RefCount = 0;
        pPtHook->DelCount = 0;
        pPtHook->Gpa = Gpa;

        pPtHook->Entries = HpAllocWithTag(sizeof(*pPtHook->Entries) * pPtHook->EntriesCount, IC_TAG_PTPA);
        if (NULL == pPtHook->Entries)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_and_exit;
        }

        for (i = 0; i < pPtHook->EntriesCount; i++)
        {
            InitializeListHead(&pPtHook->Entries[i]);
        }

        size = !!(Flags & HOOK_FLG_PAE_ROOT) ? 0x20 : !!(Flags & HOOK_FLG_PT_UM_ROOT) ? PAGE_SIZE / 2 : PAGE_SIZE;

        status = IntHookGpaSetHook(Gpa, size, IG_EPT_HOOK_WRITE, IntHookPtmWriteCallback, pPtHook,
                                   pPtHook, Flags, &pPtHook->GpaHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaSetHook failed for gpa %llx: 0x%08x\n", Gpa, status);
            goto cleanup_and_exit;
        }

        // We must ensure that the page table is indeed hooked by the time this function returns. We do this by
        // flushing EPT permissions (which may be cached by the integrator). Once IntFlushEPTPermissions returns,
        // all EPT modifications are committed and the TLBs are invalidated.
        status = IntFlushEPTPermissions();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntFlushEPTPermissions failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        pPtHook->GpaHookSet = TRUE;

        InsertTailList(&gHooks->PtmHooks.PtmHooks[hid], &pPtHook->Link);

        status = INT_STATUS_SUCCESS;

cleanup_and_exit:
        if (!INT_SUCCESS(status) && (NULL != pPtHook))
        {
            if (NULL != pPtHook->GpaHook)
            {
                IntHookGpaRemoveHook(&pPtHook->GpaHook, 0);
            }

            if (NULL != pPtHook->Entries)
            {
                HpFreeAndNullWithTag(&pPtHook->Entries, IC_TAG_PTPA);
            }

            HpFreeAndNullWithTag(&pPtHook, IC_TAG_PTPP);
        }
    }
    else
    {
        status = INT_STATUS_SUCCESS;
    }

    *PtHook = pPtHook;

    return status;
}


INTSTATUS
IntHookPtmSetHook(
    _In_ QWORD Address,
    _In_ PFUNC_EptViolationCallback Callback,
    _In_ void *Context,
    _In_ void *ParentHook,
    _In_ DWORD Flags,
    _Out_opt_ PHOOK_PTM *Hook
    )
///
/// @brief Set a hook on a page-table.
///
/// Establishes a hook on the given page-table. The provided callback will be called whenever any entry inside
/// the page-table is modified.
///
/// @param[in]  Address         The guest physical address of the page-table.
/// @param[in]  Callback        The page-table modification callback.
/// @param[in]  Context         User-defined context to be passed to the Callback.
/// @param[in]  ParentHook      Higher level hook, if any.
/// @param[in]  Flags           Hook flags. Check the HOOK_FLG* definitions.
/// @param[out] Hook            Optional output parameter that will contain a handle to the newly placed hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is used.
///
{
    INTSTATUS status;
    PHOOK_PTM pPtmHook;
    PHOOK_PTM_TABLE pPtHook;
    DWORD offset;

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pPtHook = NULL;

    Flags &= HOOK_FLG_GLOBAL_MASK;
    gHooks->Dirty = TRUE;

    // Get the master page-table hook/manager.
    status = IntHookPtmAddTable(Address, Flags, &pPtHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtmAddTable failed: 0x%08x\n", status);
        return status;
    }

    pPtmHook = HpAllocWithTag(sizeof(*pPtmHook), IC_TAG_PTPM);
    if (NULL == pPtmHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pPtmHook->Header.Context = Context;
    pPtmHook->Header.ParentHook = ParentHook;
    pPtmHook->Header.Flags = Flags;
    pPtmHook->Header.HookType = hookTypePtm;

    pPtmHook->Callback = Callback;
    pPtmHook->Address = Address;
    pPtmHook->PtHook = pPtHook;

    // Add the Page Table Entry hook inside the Page Table hook.
    offset = gGuest.PaeEnabled ? ((Address & 0xFFF) >> 3) : ((Address & 0xFFF) >> 2);

    if ((gGuest.Mm.Mode == PAGING_4_LEVEL_MODE) && IsListEmpty(&pPtHook->Entries[offset]))
    {
        // First hook established on Address, make sure we evict it from the cache.
        status = IntVeUpdateCacheEntry(Address, TRUE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeUpdateCacheEntry failed: 0x%08x\n", status);
        }
    }

    InsertTailList(&pPtHook->Entries[offset], &pPtmHook->Link);

    pPtHook->RefCount++;

    if (NULL != Hook)
    {
        *Hook = pPtmHook;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtmRemoveTableHook(
    _In_ PHOOK_PTM_TABLE Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a page-table hook.
///
/// @param[in]  Hook    The hook to be removed.
/// @param[in]  Flags   Hook flags. If #HOOK_FLG_CHAIN_DELETE, the hook will be deleted by a higher level
///                     hook manager, instead of the commit function.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (Hook->GpaHookSet)
    {
        status = IntHookGpaRemoveHook(&Hook->GpaHook, HOOK_FLG_CHAIN_DELETE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }

        Hook->GpaHookSet = FALSE;
    }

    // We now mark the PT hook for removal.
    Hook->Header.Flags |= (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE);

    if (Flags & HOOK_FLG_CHAIN_DELETE)
    {
        Hook->Header.Flags |= HOOK_FLG_CHAIN_DELETE;
    }

    RemoveEntryList(&Hook->Link);

    InsertTailList(&gHooks->PtmHooks.RemovedPtHooks, &Hook->Link);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtmRemoveHookInternal(
    _In_ PHOOK_PTM Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a page-table hook handle.
///
/// Unlike #IntHookPtmRemoveTableHook which removes a page-table hook, this function removes a user set
/// page-table hook. If multiple hooks are established on the same page-table, this function will just
/// decrement the reference count of the #PHOOK_PTM_TABLE entry. Otherwise, it will remove the
/// #PHOOK_PTM_TABLE using the #IntHookPtmRemoveTableHook.
///
/// @param[in]  Hook    The hook to be removed.
/// @param[in]  Flags   Hook flags. If #HOOK_FLG_CHAIN_DELETE, the hook will be deleted by a higher level
///                     hook manager, instead of the commit function.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (0 != (Hook->Header.Flags & HOOK_FLG_REMOVE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Flags &= HOOK_FLG_GLOBAL_MASK;

    Hook->Header.Flags |= (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE);

    if (Flags & HOOK_FLG_CHAIN_DELETE)
    {
        Hook->Header.Flags |= HOOK_FLG_CHAIN_DELETE;
    }

    RemoveEntryList(&Hook->Link);

    InsertTailList(&gHooks->PtmHooks.RemovedPtmHooks, &Hook->Link);

    // Decrement the ref count on the table hook.
    Hook->PtHook->RefCount--;
    Hook->PtHook->DelCount++;

    if (0 == Hook->PtHook->RefCount)
    {
        status = IntHookPtmRemoveTableHook(Hook->PtHook, HOOK_FLG_CHAIN_DELETE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtmRemoveTableHook failed: 0x%08x\n", status);
        }
    }

    gHooks->PtmHooks.HooksRemoved = TRUE;

    gHooks->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookPtmRemoveHook(
    _Inout_ HOOK_PTM **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a page-table hook handle.
///
/// Unlike #IntHookPtmRemoveTableHook which removes a page-table hook, this function removes a user set
/// page-table hook. If multiple hooks are established on the same page-table, this function will just
/// decrement the reference count of the #PHOOK_PTM_TABLE entry. Otherwise, it will remove the
/// #PHOOK_PTM_TABLE using the #IntHookPtmRemoveTableHook.
///
/// @param[in, out] Hook    The hook to be removed.
/// @param[in]      Flags   Hook flags. If #HOOK_FLG_CHAIN_DELETE, the hook will be deleted by a higher level
///                         hook manager, instead of the commit function.
///
/// @retval #INT_STATUS_SUCCESS On success.
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

    status = IntHookPtmRemoveHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtmRemoveHookInternal failed: 0x%08x\n", status);
    }

    if (!(Flags & HOOK_FLG_CHAIN_DELETE))
    {
        *Hook = NULL;
    }

    return status;
}


static INTSTATUS
IntHookPtmDeleteTableHook(
    _In_ PHOOK_PTM_TABLE Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently delete a page-table hook.
///
/// @param[in]  Hook    The page-table hook.
/// @param[in]  Flags   Hook flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    RemoveEntryList(&Hook->Link);

    status = IntHookGpaDeleteHook(&Hook->GpaHook, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaDeleteHook failed: 0x%08x\n", status);
    }

    HpFreeAndNullWithTag(&Hook->Entries, IC_TAG_PTPA);

    HpFreeAndNullWithTag(&Hook, IC_TAG_PTPP);

    return status;
}


static INTSTATUS
IntHookPtmDeleteHookInternal(
    _In_ PHOOK_PTM Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently delete a page-table hook handle.
///
/// Unlike #IntHookPtmDeleteTableHook, this function only deletes the handle to a #PHOOK_PTM_TABLE. The
/// #PHOOK_PTM_TABLE entry will actually be deleted only when its reference count reaches 0.
///
/// @param[in]  Hook    The page-table hook.
/// @param[in]  Flags   Hook flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    status = INT_STATUS_SUCCESS;

    // Decrement the delete count. When it reaches zero, we'll actually gonna erase the entry.
    Hook->PtHook->DelCount--;
    if ((0 == Hook->PtHook->DelCount) && (0 == Hook->PtHook->RefCount))
    {
        status = IntHookPtmDeleteTableHook(Hook->PtHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtmDeleteTableHook failed: 0x%08x\n", status);
        }
    }

    RemoveEntryList(&Hook->Link);

    HpFreeAndNullWithTag(&Hook, IC_TAG_PTPM);

    return status;
}


INTSTATUS
IntHookPtmDeleteHook(
    _In_ HOOK_PTM **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently delete a page-table hook handle.
///
/// Unlike #IntHookPtmDeleteTableHook, this function only deletes the handle to a #PHOOK_PTM_TABLE. The
/// #PHOOK_PTM_TABLE entry will actually be deleted only when its reference count reaches 0.
///
/// @param[in]  Hook    The page-table hook.
/// @param[in]  Flags   Hook flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
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

    status = IntHookPtmDeleteHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtmDeleteHookInternal failed: 0x%08x\n", status);
    }

    *Hook = NULL;

    return status;
}


INTSTATUS
IntHookPtmCommitHooks(
    void
    )
///
/// @brief Commit the page-table hooks.
///
/// This function deletes all the hooks that have been removed. Only the hooks which were flagged with
/// the #HOOK_FLG_CHAIN_DELETE are spared, as it is expected that a higher level hook manager will delete
/// them.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    if (!gHooks->PtmHooks.HooksRemoved)
    {
        return INT_STATUS_SUCCESS;
    }

    list = gHooks->PtmHooks.RemovedPtmHooks.Flink;
    while (list != &gHooks->PtmHooks.RemovedPtmHooks)
    {
        PHOOK_PTM p = CONTAINING_RECORD(list, HOOK_PTM, Link);
        list = list->Flink;

        if (0 != (p->Header.Flags & HOOK_FLG_CHAIN_DELETE))
        {
            // Chain delete requested - we won't commit this hook, we'll let it's parent decide its faith.
            continue;
        }

        if (0 != (p->Header.Flags & HOOK_FLG_REMOVE))
        {
            status = IntHookPtmDeleteHookInternal(p, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtmDeleteHookInternal failed: 0x%08x\n", status);
            }
        }
        else
        {
            ERROR("[ERROR] Invalid hook state: %x for hook at PTA 0x%016llx\n", p->Header.Flags, p->Address);
            IntEnterDebugger();
        }
    }

    // Handle table hooks.
    list = gHooks->PtmHooks.RemovedPtHooks.Flink;
    while (list != &gHooks->PtmHooks.RemovedPtHooks)
    {
        PHOOK_PTM_TABLE p = CONTAINING_RECORD(list, HOOK_PTM_TABLE, Link);
        list = list->Flink;

        if (0 != (p->Header.Flags & HOOK_FLG_CHAIN_DELETE))
        {
            // Chain delete requested - we won't commit this hook, we'll let it's parent decide its faith.
            continue;
        }

        if (0 != (p->Header.Flags & HOOK_FLG_REMOVE))
        {
            status = IntHookPtmDeleteTableHook(p, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaDeleteHook failed: 0x%08x\n", status);
            }
        }
        else
        {
            ERROR("[ERROR] Invalid hook state: %x for hook at GPA 0x%016llx\n", p->Header.Flags, p->Gpa);
            IntEnterDebugger();
        }
    }

    gHooks->PtmHooks.HooksRemoved = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookPtmInit(
    void
    )
///
/// @brief Initialize the page-table hook system.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    for (DWORD i = 0; i < PTM_HOOK_TABLE_SIZE; i++)
    {
        InitializeListHead(&gHooks->PtmHooks.PtmHooks[i]);
    }

    InitializeListHead(&gHooks->PtmHooks.RemovedPtmHooks);
    InitializeListHead(&gHooks->PtmHooks.RemovedPtHooks);

    return INT_STATUS_SUCCESS;
}
