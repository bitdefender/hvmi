/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook.h"
#include "hook_pts.h"
#include "alerts.h"
#include "gpacache.h"
#include "kernvm.h"


///
/// Some important notes regarding the PTS hooks:
/// - "Page Table" is being often referred to as being a generic, arbitrary level page table. It might be a PML5E,
///   PML4E, PDPE, PDE or PTE.
/// - #HOOK_PTS_ENTRY structures are internal to this module - they shouldn't be used externally; the interface
///   structure is the #HOOK_PTS, which contains the bare-minimum info needed to invoke the VA modification callback.
/// - The VA modification callback will be called for every modification of any PTE; this means that a modification
///   of the A (Accessed) bit inside the PML4E that is part of the VA translation _will_ lead to the invocation of
///   the VA modification callback (although the "OldValue" and "NewValue" will be identical - this is needed due to
///   the possibility that PTE hooks be added dynamically or pages being split from a single large page to multiple
///   smaller pages).
/// - Modifications of the root translation entity (CR3) are not supported in any way. It is up to the caller to make
///   sure that either the root translation doesn't modify or the hooks or moved to the new translation root.
/// - The VA modification callback will be called for ignored bits modification as well as control bits modification
///   (for example, XD or W bit). Any change in the PTE on any translation level will lead to callback invocation!
/// - If global VA are to be hooked (for example, kernel pages), normally any CR3 may be used, since these VA all
///   translate to the same PA; however, the top level PT (PML5, PML4, PDP or PD) will be different in every VA space;
///   Therefore, it is advisable that these hooks be placed using the System CR3, and not any arbitrary CR3.
/// - Internally, the HOOK_PTS contexts can and will be moved up and down on the translation hierarchy as pages become
///   swapped in and out or as pages are split/merged. DO NOT make any assumption with regard to what the
///   HOOK_PTS->Parent points to. If needed, however, fields may be accessed from this structure (such as the address
///   of the PTE), but if you need this, you're probably doing something wrong.
/// - The swap callbacks must and will always be invoked in the exact same order in which they were placed!
/// - The swap callbacks will be invoked without holding any locks - this leads to possible race-conditions when a
///   hook may be removed before calling the callback, but we don't care about this situation, since the callback
///   would be called anyway.
///
/// It is important to understand the different types of hooks which exist for page-tables:
/// - HOOK_PTS - this is a hook handle associated with a monitored virtual address. One such hook will contain
///   multiple #HOOK_PTS_ENTRY structures, one for each page table entry monitored.
/// - #HOOK_PTS_ENTRY - this is a hook established on one page-table entry; a #HOOK_PTS can consist of multiple
///   #HOOK_PTS_ENTRY hooks, depending on how many paging levels are needed to translate that particular address.
/// - HOOK_PTM - this is the page-table manager; this system aggregates all the hooks for a single page-table;
///   this system is needed in order to make sure a single GPA hook exists for any monitored page-table; if this
///   would not be used, than for every virtual address that translates through a given page table, we would have
///   a distinct GPA hook, which would be a waste of memory.
/// In order to better understand this, let's consider we are monitoring 3 guest virtual addresses: V1, V2, V3.
/// These virtual addresses have the following translations:
///     V1: PML4_1[0], PDP_1[17], PD_1[511], PT_1[0]   => P1
///     V2: PML4_1[0], PDP_1[20], PD_2[511], PT_2[60]  => P2
///     V3: PML4_1[8], PDP_2[100], PD_3[88], PT_3[120] => P3
/// Monitoring each address will  require the following resources:
/// - 3 HOOK_PTS handles, one for each address
///     * HOOK_PTS_1, for V1
///     * HOOK_PTS_2, for V2
///     * HOOK_PTS_3, for V3
/// - 11 HOOK_PTS_ENTRY, because there are 11 distinct page-table entries monitored:
///     * HOOK_PTS_ENTRY_1, for PML4_1[0], for V1 and V2
///     * HOOK_PTS_ENTRY_2, for PDP_1[17], for V1
///     * HOOK_PTS_ENTRY_3, for PD_1[511], for V1
///     * HOOK_PTS_ENTRY_4, for PT_1[0], for V1
///     * HOOK_PTS_ENTRY_5, for PDP_1[20], for V2
///     * HOOK_PTS_ENTRY_6, for PD_2[511], for V2
///     * HOOK_PTS_ENTRY_7, for PT_2[60], for V2
///     * HOOK_PTS_ENTRY_8, for PML4_1[8], for V3
///     * HOOK_PTS_ENTRY_9, for PDP_2[100], for V3
///     * HOOK_PTS_ENTRY_10, for PD_3[88], for V3
///     * HOOK_PTS_ENTRY_11, for PT_3[120], for V3
/// - 9 HOOK_PTM, because there are 9 distinct page-tables monitored:
///     * HOOK_PTM_1, for PML4_1
///     * HOOK_PTM_2, for PDP_1
///     * HOOK_PTM_3, for PDP_2
///     * HOOK_PTM_4, for PD_1
///     * HOOK_PTM_5, for PD_2
///     * HOOK_PTM_6, for PD_3
///     * HOOK_PTM_7, for PT_1
///     * HOOK_PTM_8, for PT_2
///     * HOOK_PTM_9, for PT_3
/// Usually, these hooks tend to be very grouped, so monitoring several virtual addresses inside the same
/// process will lead to a very small number of HOOK_PTM and #HOOK_PTS_ENTRY hooks.
///


///
/// Used to temporarily store data used to invoke the swap callbacks.
///
typedef struct _INVOCATION_CONTEXT
{
    LIST_ENTRY          Link;           ///< List element entry.
    PHOOK_PTS           Hook;           ///< The PTS hook associated with the modified address.
    PFUNC_SwapCallback  Callback;       ///< The swap callback.
    void               *Context;        ///< Optional context, supplied by the caller who set the hook.
    QWORD               VirtualAddress; ///< Virtual address whose translation is being modified.
    QWORD               OldEntry;       ///< Old PT entry.
    QWORD               NewEntry;       ///< New PT entry.
    QWORD               OldPageSize;    ///< Old page size.
    QWORD               NewPageSize;    ///< New page size.
    DWORD               Flags;          ///< Flags.
    /// @brief  True if this entry was not dynamically allocated (it doesn't have to be freed).
    BOOLEAN             Static;
} INVOCATION_CONTEXT, *PINVOCATION_CONTEXT;


/// We keep up to 8 entries statically allocated, in order to avoid the cost of dynamically allocating memory each time
/// we have a translation modification.
#define INVK_CTX_CACHE_SIZE     8
static INVOCATION_CONTEXT gInvkCtxStatic[INVK_CTX_CACHE_SIZE];
static DWORD gInvkCtxIndex;

// Defines the internal PTS level constants.
#define PTS_LEVEL_ROOT          6
#define PTS_LEVEL_PML5          5
#define PTS_LEVEL_PML4          4
#define PTS_LEVEL_PDP           3
#define PTS_LEVEL_PD            2
#define PTS_LEVEL_PT            1


static PHOOK_PTS_ENTRY
IntHookPtsFindEntry(
    _In_ LIST_HEAD *ListHead,
    _In_ QWORD PhysicalAddress
    );

static INTSTATUS
IntHookPtsCreateEntry(
    _In_ QWORD PtPaAddress,
    _In_ WORD EntrySizeAndLevel,
    _In_opt_ PHOOK_PTS_ENTRY Parent,
    _Out_ PHOOK_PTS_ENTRY *Entry
    );

static INTSTATUS
IntHookPtsHandleModification(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue
    );


static __forceinline QWORD
IntHookPtsGetPageSize(
    _In_ PHOOK_PTS_ENTRY Entry
    )
///
/// @brief Computes the page size of a PTS entry.
///
/// Using the entry size and the level of a given translation, compute the page size associated to it.
///
/// @param[in]  Entry   The entry whose size is to be computed.
///
/// @retval The page size associated with this entry.
///
{
    const QWORD pageSizeL[4] = { PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G, 0 };
    const QWORD pageSizeS[2] = { PAGE_SIZE_4K, PAGE_SIZE_4M };

    return (4 == Entry->EntrySize) ? pageSizeS[Entry->Level - 1] : pageSizeL[Entry->Level - 1];
}


static void
IntHookAddCallbackToList(
    _In_ PLIST_HEAD List,
    _In_ PHOOK_PTS Context
    )
///
/// @brief Adds a callback to the provided list.
///
/// Adds the provided PTS context to the provided list, maintaining the priority order. Some contexts/hook entries
/// may have a higher priority than others.
///
/// @param[in]  List    The list where the context must be inserted.
/// @param[in]  Context The context/hook entry to be inserted.
///
{
    if (0 == (Context->Header.Flags & HOOK_FLG_HIGH_PRIORITY))
    {
        InsertTailList(List, &Context->Link);
    }
    else
    {
        // High priority - it goes at the end of the high-priority callbacks.
        LIST_ENTRY *pivot;

        pivot = List->Flink;
        while (pivot != List)
        {
            PHOOK_PTS pPts = CONTAINING_RECORD(pivot, HOOK_PTS, Link);

            if (0 == (pPts->Header.Flags & HOOK_FLG_HIGH_PRIORITY))
            {
                pivot = pivot->Blink;
                break;
            }

            pivot = pivot->Flink;
        }

        InsertAfterList(pivot, &Context->Link);
    }
}


static void
IntHookPtsCloneCallbacks(
    _In_ PHOOK_PTS_ENTRY Entry
    )
///
/// @brief Clone a list of callbacks locally, so they can be safely invoked.
///
/// This function will simply alloc the callbacks invocation list. The callbacks will be called when we're done
/// processing everything and any locks are released. This also allows each callback to safely remove its own
/// hook, if it desires so.
///
/// @param[in]  Entry   The entry whose callbacks are to be invoked.
///
{
    LIST_ENTRY *list = Entry->ContextEntries.Flink;
    while (list != &Entry->ContextEntries)
    {
        PHOOK_PTS pPts = CONTAINING_RECORD(list, HOOK_PTS, Link);

        list = list->Flink;

        pPts->OldEntry = pPts->CurEntry;
        pPts->OldPageSize = pPts->CurPageSize;
        pPts->CurEntry = pPts->Parent->WriteState.CurEntry;
        pPts->CurPageSize = IntHookPtsGetPageSize(pPts->Parent);

        // Callbacks will be invoked in the exact same order they are present inside the list.
        if (NULL != pPts->Callback)
        {
            INVOCATION_CONTEXT *pInvk;

            if (gInvkCtxIndex < INVK_CTX_CACHE_SIZE)
            {
                pInvk = &gInvkCtxStatic[gInvkCtxIndex];
                gInvkCtxIndex++;

                pInvk->Static = TRUE;
            }
            else
            {
                pInvk = HpAllocWithTag(sizeof(*pInvk), IC_TAG_INVC);
                if (NULL == pInvk)
                {
                    continue;
                }

                pInvk->Static = FALSE;
            }

            pInvk->Callback = pPts->Callback;
            pInvk->Context = pPts->Header.Context;
            pInvk->Flags = pPts->Header.Flags;
            pInvk->OldEntry = pPts->OldEntry;
            pInvk->NewEntry = pPts->CurEntry;
            pInvk->OldPageSize = pPts->OldPageSize;
            pInvk->NewPageSize = pPts->CurPageSize;
            pInvk->VirtualAddress = pPts->VirtualAddress;
            pInvk->Hook = pPts;

            InsertTailList(gHooks->PtsHooks.CallbacksList, &pInvk->Link);
        }
    }
}


static INTSTATUS
IntHookPtsInvokeCallbacks(
    _In_ LIST_HEAD *Callbacks
    )
///
/// @brief Invoke all the callbacks from a given list.
///
/// This function calls all the PTS (swap) callbacks for a given virtual address that has just had its translation
/// modified. The provided argument is a list of #INVOCATION_CONTEXT structures.
///
/// @param[in]  Callbacks   List of #INVOCATION_CONTEXT structures, one for each distinct callback.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ACCESS_DENIED If the PT modification seems malicious. Note that even if access denied is
///                                  returned, the PT entry write may have already been emulated.
///
{
    // We can now safely invoke the callbacks. If we would invoke the swap-in callbacks while holding the
    // PTS lock, then placing or removing paged hooks would become impossible.
    INTSTATUS status;
    LIST_ENTRY *list;
    BOOLEAN deny, pause;
    PINVOCATION_CONTEXT pInvk;

    deny = pause = FALSE;

    pInvk = CONTAINING_RECORD(Callbacks->Flink, INVOCATION_CONTEXT, Link);
    if (!!(pInvk->Flags & HOOK_FLG_HIGH_PRIORITY))
    {
        pause = TRUE;
        IntPauseVcpus();
    }

    list = Callbacks->Flink;
    while (list != Callbacks)
    {
        pInvk = CONTAINING_RECORD(list, INVOCATION_CONTEXT, Link);

        list = list->Flink;

        // VERY IMPORTANT: If this PTS hook has been flagged for removal, we mustn't call the callback, as it most
        // likely doesn't expect to be called, and resources may have already been freed, leading to use-after-free.
        // Concrete example: we have 2 swapmem callbacks on the same page. The page gets swapped in, and the first
        // callback is called; this callback decides to remove the transaction for the second callback, which will
        // free both the SWAPMEM_TRANSACTION and the SWAPMEM_PAGE structure. However, if we are not careful to NOT call
        // the second swap-in callback when the PTS hook has been removed, we will trigger the use-after-free, in that
        // the second callback will access the SWAPMEM_PAGE or the SWAPMEM_TRANSACTION structures, even though they
        // were freed by the first callback. The fix is trivial - simply avoid calling a PTS callback if the PTS hook
        // is flagged for removal.
        if (!!(pInvk->Hook->Header.Flags & (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE)))
        {
            LOG("[PTS] Skipping calling the PTS callback for VA 0x%016llx\n", pInvk->VirtualAddress);
            goto _skip_call;
        }

        status = pInvk->Callback(pInvk->Context,
                                 pInvk->VirtualAddress,
                                 pInvk->OldEntry,
                                 pInvk->NewEntry,
                                 pInvk->OldPageSize,
                                 pInvk->NewPageSize);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Callback failed: 0x%08x\n", status);

            if (INT_STATUS_ACCESS_DENIED == status)
            {
                deny = TRUE;
            }
        }
        else if (INT_STATUS_REMOVE_HOOK_ON_RET == status)
        {
            status = IntHookPtsRemoveHook((HOOK_PTS **)&pInvk->Hook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsRemoveHook failed: 0x%08x\n", status);
            }
        }

_skip_call:
        RemoveEntryList(&pInvk->Link);

        if (!pInvk->Static)
        {
            HpFreeAndNullWithTag(&pInvk, IC_TAG_INVC);
        }
    }

    if (pause)
    {
        IntResumeVcpus();
    }

    if (deny)
    {
        return INT_STATUS_ACCESS_DENIED;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsWriteCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Page-table modification handler.
///
/// This function is called by the PTM hook manager, whenever a page-table entry is written. This is called
/// for each written entry, and for each effective write. This function will call the PT write handler,
/// #IntHookPtwProcessWrite, and if we are dealing with a partial write, it will bail out.
/// In essence, it just processes the page-table entry write, and calls the main #IntHookPtsHandleModification
/// handler.
///
/// @param[in]  Context     The written PTS entry (#PHOOK_PTS_ENTRY).
/// @param[in]  Hook        The GPA hook handle.
/// @param[in]  Address     Written guest physical address.
/// @param[out] Action      Desired action for the memory write.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PHOOK_PTS_ENTRY pPt;
    QWORD newValue, oldValue;
    LIST_HEAD localCallbacksList;
    BOOLEAN exitfn;

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
    newValue = oldValue = 0;
    exitfn = FALSE;
    InitializeListHead(&localCallbacksList);
    gInvkCtxIndex = 0;

    *Action = introGuestAllowed;

    pPt = (PHOOK_PTS_ENTRY)Context;

    STATS_ENTER(statsPtWriteHits);

    // If the entry was removed in the meantime, bail out.
    if (0 != (pPt->Header.Flags & (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE)))
    {
        goto cleanup_and_exit;
    }

    status = IntHookPtwProcessWrite(&pPt->WriteState, Address, pPt->EntrySize, &oldValue, &newValue);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        *Action = introGuestAllowed;
        status = INT_STATUS_SUCCESS;
        exitfn = TRUE;
        goto cleanup_and_exit;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtwProcessWrite failed at %llx: 0x%08x\n", Address, status);
        IntDbgEnterDebugger();
        goto cleanup_and_exit;
    }
    else if ((INT_STATUS_PARTIAL_WRITE == status) || (INT_STATUS_NOT_NEEDED_HINT == status))
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    // Either no interesting bits were modified (P, PSE or GPA) or both the old and new values are invalid.
    if (((oldValue & HOOK_PTS_MONITORED_BITS) == (newValue & HOOK_PTS_MONITORED_BITS)) ||
        (0 == ((oldValue & PT_P) + (newValue & PT_P))))
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    gHooks->PtsHooks.CallbacksList = &localCallbacksList;

    status = IntHookPtsHandleModification(pPt, oldValue, newValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsHandleModification failed: 0x%08x\n", status);
    }

    gHooks->PtsHooks.CallbacksList = NULL;

cleanup_and_exit:

    if (exitfn)
    {
        goto exit_fn;
    }

    // We can now safely invoke the callbacks. If we would invoke the swap-in callbacks while holding the
    // PTS lock, then placing or removing paged hooks would become impossible.
    status = IntHookPtsInvokeCallbacks(&localCallbacksList);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsInvokeCallbacks failed: 0x%08x\n", status);
    }

    // If any of the swap-in callbacks returned INT_STATUS_ACCESS_DENIED, than we will block this write.
    if (INT_STATUS_ACCESS_DENIED == status)
    {
        TRACE("[PTS] Callback returned INT_STATUS_ACCESS_DENIED, will block the PT write.\n");
        *Action = introGuestNotAllowed;
    }

    STATS_EXIT(statsPtWriteHits);

    status = INT_STATUS_SUCCESS;

exit_fn:

    if ((gGuest.KernelBetaDetections) && (*Action == introGuestNotAllowed))
    {
        *Action = introGuestAllowed;
    }

    return status;
}


static INTSTATUS
IntHookPtsRemovePteHook(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ DWORD Flags
    )
///
/// @brief Remove a page table entry hook.
///
/// @param[in]  Entry   The page table entry hook to be removed.
/// @param[in]  Flags   Removal flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    // Clear the delete PT hook flag for now.
    Entry->Header.Flags &= ~HOOK_PTS_FLG_DELETE_PT_HOOK;

    if ((NULL != Entry->PtPaHook) && Entry->PtPaHookSet)
    {
        // Remove the hook established on the page table entry.
        status = IntHookPtmRemoveHook((HOOK_PTM **)&Entry->PtPaHook, HOOK_FLG_CHAIN_DELETE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtmRemoveHook failed: 0x%08x\n", status);
        }

        // Mark the fact that the PT entry is not hooked anymore.
        Entry->PtPaHookSet = FALSE;

        // Mark that we have to delete this PT hook.
        Entry->Header.Flags |= HOOK_PTS_FLG_DELETE_PT_HOOK;
    }

    RemoveEntryList(&Entry->Link);

    switch (Entry->Level)
    {
    case 1:
        InsertTailList(&gHooks->PtsHooks.RemovedHooksPtList, &Entry->Link);
        break;
    case 2:
        InsertTailList(&gHooks->PtsHooks.RemovedHooksPdList, &Entry->Link);
        break;
    case 3:
        InsertTailList(&gHooks->PtsHooks.RemovedHooksPdpList, &Entry->Link);
        break;
    case 4:
        InsertTailList(&gHooks->PtsHooks.RemovedHooksPml4List, &Entry->Link);
        break;
    case 5:
        InsertTailList(&gHooks->PtsHooks.RemovedHooksPml5List, &Entry->Link);
        break;
    case 6:
        InsertTailList(&gHooks->PtsHooks.RemovedHooksRootList, &Entry->Link);
        break;
    default:
        break;
    }

    // Update the flags.
    Entry->Header.Flags |= (HOOK_FLG_REMOVE);

    if (Flags & HOOK_FLG_CHAIN_DELETE)
    {
        Entry->Header.Flags |= HOOK_FLG_CHAIN_DELETE;
    }

    // Flag the state as being dirty.
    gHooks->PtsHooks.HooksRemoved = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsRemoveHookInternal(
    _In_ PHOOK_PTS Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a PTS hook.
///
/// This function will remove a PTS hook. This means that the callback will not be called anymore on translation
/// modifications. #HOOK_PTS_ENTRY and HOOK_PTM entries may still remain valid, if there are other #HOOK_PTS entries
/// pointing to them (they are reference counted).
///
/// @param[in]  Hook    The PTS hook to be removed.
/// @param[in]  Flags   The removal flags. Check out HOOK_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PHOOK_PTS_ENTRY pPt;
    PHOOK_HEADER pChild;
    BOOLEAN decRefCount;

    if (0 != (Hook->Header.Flags & HOOK_FLG_REMOVE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = INT_STATUS_SUCCESS;

    // We have to iterate through all the parents on this current branch, and decrement ref-counts where needed.
    pPt = Hook->Parent;     // We start from the Context entry.
    decRefCount = TRUE;     // And we have to decrement the ref count for now.
    pChild = &Hook->Header; // The child is the current PTS structure.

    // While we have more parents and the ref-count decreased...
    while ((NULL != pPt) && (decRefCount))
    {
        // Decrement the current ref count.
        pPt->RefCount--;

        if (0 == pPt->RefCount)
        {
            status = IntHookPtsRemovePteHook(pPt, HOOK_FLG_CHAIN_DELETE);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsRemovePteHook failed: 0x%08x\n", status);
            }

            // We need to mark this child in order to delete the PT hook. Since he's the last child being removed,
            // it's going to be its responsibility to remove the PT hook.
            pChild->Flags |= HOOK_PTS_FLG_DELETE_PD_HOOK;

            decRefCount = TRUE;
        }
        else
        {
            decRefCount = FALSE;
        }

        // Advance the child.
        pChild = &pPt->Header;

        // And go up one level to the next PD.
        pPt = pPt->Header.ParentHook;
    }

    // We now mark the PTS hook for removal.
    Hook->Header.Flags |= (HOOK_FLG_REMOVE);

    if (Flags & HOOK_FLG_CHAIN_DELETE)
    {
        Hook->Header.Flags |= HOOK_FLG_CHAIN_DELETE;
    }

    RemoveEntryList(&Hook->Link);
    RemoveEntryList(&Hook->PtsLink);

    // And insert it inside the removed PF hooks list.
    InsertTailList(&gHooks->PtsHooks.RemovedHooksPtsList, &Hook->Link);

    // Flag the state as being dirty.
    gHooks->PtsHooks.HooksRemoved = TRUE;

    return status;
}


static INTSTATUS
IntHookPtsDeletePdHook(
    _In_ PHOOK_PTS_ENTRY Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently deletes a page-table entry hook.
///
/// This function will delete the PTM hook of a given page table entry hook.
///
/// @param[in]  Hook    The hook to be removed.
/// @param[in]  Flags   Removal flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if ((NULL != Hook->PtPaHook) && (0 != (Hook->Header.Flags & HOOK_PTS_FLG_DELETE_PT_HOOK)))
    {
        status = IntHookPtmDeleteHook(&Hook->PtPaHook, Flags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtmDeleteHook failed: 0x%08x\n", status);
        }
    }

    RemoveEntryList(&Hook->Link);

    // Delete the current PD hook. All the upper level hooks have already been removed.
    HpFreeAndNullWithTag(&Hook, IC_TAG_PTPT);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsDeleteParents(
    _In_ PHOOK_PTS_ENTRY Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently deletes all PTM hooks of a page-table entry hook.
///
/// This function will delete all the PTM hook of a given page table entry hook.
///
/// @param[in]  Hook    The hook to be removed.
/// @param[in]  Flags   Removal flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // We must have a valid parent & we must have the delete PD hook flag set, which basically means that we must
    // delete the parent.
    if ((NULL != Hook->Header.ParentHook) && (0 != (Hook->Header.Flags & HOOK_PTS_FLG_DELETE_PD_HOOK)))
    {
        status = IntHookPtsDeleteParents(Hook->Header.ParentHook, Flags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtDeleteParents failed for level %d: 0x%08x\n", Hook->Level + 1, status);
        }

        Hook->Header.ParentHook = NULL;
    }

    // actually delete this entry.
    status = IntHookPtsDeletePdHook(Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtDeletePdHook failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsDeleteHookInternal(
    _In_ PHOOK_PTS Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently deletes a PTS hook.
///
/// This function will delete a PTS hook, together with all of its page-table entry and PTM hooks, if required.
///
/// @param[in]  Hook    The hook to be removed.
/// @param[in]  Flags   Removal flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = INT_STATUS_SUCCESS;

    // Remove all the parents, if needed.
    if ((NULL != Hook->Parent) && (0 != (Hook->Header.Flags & HOOK_PTS_FLG_DELETE_PD_HOOK)))
    {
        status = IntHookPtsDeleteParents(Hook->Parent, Flags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsDeleteParents failed: 0x%08x\n", status);
        }

        Hook->Parent = NULL;
    }

    RemoveEntryList(&Hook->Link);

    HpFreeAndNullWithTag(&Hook, IC_TAG_PTPS);

    return status;
}


static PHOOK_PTS_ENTRY
IntHookPtsFindEntry(
    _In_ LIST_HEAD *ListHead,
    _In_ QWORD PhysicalAddress
    )
///
/// @brief Finds an already existing page-table entry hook on a given physical address.
///
/// @param[in]  ListHead        The list to search for a matching PTS entry hook.
/// @param[in]  PhysicalAddress The address for which we are searching an already existing PTS entry hook.
///
/// @retval The found PTS entry hook or NULL if none is found.
///
{
    LIST_ENTRY *list;
    LIST_HEAD *listHead;

    listHead = ListHead;

    list = listHead->Flink;
    while (list != listHead)
    {
        PHOOK_PTS_ENTRY pPt = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);
        list = list->Flink;

        if (pPt->PtPaAddress == PhysicalAddress)
        {
            return pPt;
        }
    }

    return NULL;
}


static INTSTATUS
IntHookPtsDisableEntry(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD NewPtPaAddress,
    _In_ QWORD NewPteValue
    )
///
/// @brief Disable a page-table entry hook.
///
/// This function handles PTEs that have just become absent. Basically, the PTE that points to this entry has become
/// invalid, and therefore we have to disable this entry.
///
/// @param[in]  Entry           The PTS entry which is to be disabled.
/// @param[in]  NewPtPaAddress  Reserved for future use.
/// @param[in]  NewPteValue     Reserved for future use.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    // They are not needed here.
    UNREFERENCED_PARAMETER(NewPtPaAddress);
    UNREFERENCED_PARAMETER(NewPteValue);

    // If the GPA hook is set on this entry PTE, then remove it.
    if (Entry->PtPaHookSet && (NULL != Entry->PtPaHook))
    {
        status = IntHookPtmRemoveHook((HOOK_PTM **)&Entry->PtPaHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtmRemoveHook failed: 0x%08x\n", status);
        }
    }

    Entry->PtPaHookSet = FALSE;
    Entry->PtPaAddress = 0;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsEnableEntry(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD NewPtPaAddress
    )
///
/// @brief Enable a page-table entry hook.
///
/// The PT entry that points to this entry has just become valid. We can re-enable this entry and place a new hook on
/// the PTE of this entry, since the upper level PTE just become valid.
///
/// @param[in]  Entry           The page-table entry hook that will be enabled.
/// @param[in]  NewPtPaAddress  The new page-table physical address.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    // Remove the old hook, if there's one.
    if (Entry->PtPaHookSet && (NULL != Entry->PtPaHook))
    {
        if (Entry->PtPaAddress != NewPtPaAddress)
        {
            status = IntHookPtmRemoveHook((HOOK_PTM **)&Entry->PtPaHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtmRemoveHook failed: 0x%08x\n", status);
            }
        }
        else
        {
            return INT_STATUS_SUCCESS;
        }
    }

    // Establish a new hook on this PTE.
    status = IntHookPtmSetHook(NewPtPaAddress,
                               IntHookPtsWriteCallback,
                               Entry,
                               Entry,
                               HOOK_FLG_PAGING_STRUCTURE,
                               &Entry->PtPaHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtmSetHook failed: 0x%08x\n", status);
        return status;
    }

    // Update the internal flags.
    Entry->PtPaHookSet = TRUE;

    Entry->PtPaAddress = NewPtPaAddress;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsRemapEntry(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD NewPtPaAddress
    )
///
/// @brief Remap a page-table entry to a new value.
///
/// The PT entry that points to this entry has just been remapped. It remained valid, but the physical address of the
/// pointed table modified.
///
/// @param[in]  Entry           The page-table entry that has just changed translations.
/// @param[in]  NewPtPaAddress  The new page-table physical address.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntHookPtsDisableEntry(Entry, 0, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtDisableEntry failed: 0x%08x\n", status);
        return status;
    }

    status = IntHookPtsEnableEntry(Entry, NewPtPaAddress);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsEnableEntry failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsMergeEntry(
    _In_ PHOOK_PTS_ENTRY MergeRoot,
    _In_ PHOOK_PTS_ENTRY Entry
    )
///
/// @brief Merge multiple entries into a single one.
///
/// The PTE that points to this entry has just become PSE - Page Size Extended. This means that now it points to
/// a single 2M/4M/1G page instead of another PT. We have to iterate the lower levels and "Adopt" all the contexts
/// from the lower level entries, which will be destroyed.
///
/// @param[in]  MergeRoot   The new root page-table entry hook.
/// @param[in]  Entry       The page-table entry hook that is being migrated to the larger page.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE If an invalid internal state is encountered.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    // First of all, do the recursive calls.
    list = Entry->ChildrenEntries.Flink;
    while (list != &Entry->ChildrenEntries)
    {
        PHOOK_PTS_ENTRY pPt = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);

        list = list->Flink;

        // Go deeper & parse the lower level tables.
        status = IntHookPtsMergeEntry(MergeRoot, pPt);
        if (!INT_SUCCESS(status))
        {
            // We can safely continue in case of failure. Any error generated inside IntHookPtsMergeEntry is fatal
            // and would normally lead to a BugCheck.
            ERROR("[ERROR] IntHookPtsMergeEntry failed: 0x%08x\n", status);
        }

        // We know for sure that pPt PTE, which is a child of Entry, was removed; therefore, we can safely decrement
        // the ref count.
        if (Entry->RefCount > 0)
        {
            Entry->RefCount--;
        }
        else
        {
            ERROR("[ERROR] Entry %p has refcount 0!\n", Entry);
            IntDbgEnterDebugger();
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }
    }

    // If the root is the same with the entry then we're done.
    if (MergeRoot == Entry)
    {
        goto done;
    }

    list = Entry->ContextEntries.Flink;
    while (list != &Entry->ContextEntries)
    {
        PHOOK_PTS pPts = CONTAINING_RECORD(list, HOOK_PTS, Link);

        list = list->Flink;

        // Remove this context entry from the current leaf.
        RemoveEntryList(&pPts->Link);

        // Insert this context entry inside the new leaf (the new large page)
        IntHookAddCallbackToList(&MergeRoot->ContextEntries, pPts);
        ///InsertTailList(&MergeRoot->ContextEntries, &pPts->Link);

        // Update the ref count of the current entry.
        Entry->RefCount--;

        // Update the ref count of the new leaf (the large page)
        MergeRoot->RefCount++;

        // And update the context parent pointer.
        pPts->Parent = MergeRoot;
    }

    // Right here, the current Entry refCount _must_ be zero. If it isn't, something went wrong.
    if (0 != Entry->RefCount)
    {
        ERROR("[ERROR] Entry %p refCount is %d after entry merging!\n", Entry, Entry->RefCount);
        IntDbgEnterDebugger();
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    // We can flag this entry for removal
    status = IntHookPtsRemovePteHook(Entry, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtRemovePteHook failed: 0x%08x\n", status);
        IntDbgEnterDebugger();
        return status;
    }

done:
    // Done!
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsControlEntry(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD NewPtPaAddress,
    _In_ QWORD NewPteValue
    )
///
/// @brief Handle control bits modifications inside a page-table entry.
///
/// @param[in]  Entry           The entry being modified.
/// @param[in]  NewPtPaAddress  The page-table physical address.
/// @param[in]  NewPteValue     The page-table entry value.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(Entry);
    UNREFERENCED_PARAMETER(NewPtPaAddress);
    UNREFERENCED_PARAMETER(NewPteValue);

    // There is nothing to do here.

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsHandleModification(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue
    )
///
/// @brief Handle a modification inside a page-table entry.
///
/// This function handles all types of modifications inside page-table entries, at any level. The cases it needs
/// to handle are:
/// 1. Simply modify the page-table entry of a monitored address
/// 2. Modify the translation of a high-level paging structure - for example, change the address of a page-directory
///    inside the PML4.
/// 3. Split a large page (for example, 2M) into small (4K) pages.
/// 4. Merge small pages (for example, 4K) into a large (2M) page.
/// Some modifications will lead to the swap callback being invoked, while others may not (for example, if the final
/// physical address of the translation is the same).
///
/// @param[in]  Entry       The page-table entry that is being modified.
/// @param[in]  OldValue    Old page-table entry value.
/// @param[in]  NewValue    New page-table entry value.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If both the old and the new values are invalid.
///
{
    INTSTATUS status;
    QWORD curValue, newValue;
    BOOLEAN curValid, newValid, curPse, newPse, pseChanged;
    LIST_ENTRY *list;

    // Now handle the actual modification. Update the current entry.
    curValue = OldValue;
    newValue = NewValue;

    curValid = (0 != (curValue & 1));
    newValid = (0 != (newValue & 1));

    // Both the old & the new values are invalid. Bail out.
    if (!curValid && !newValid)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    STATS_ENTER(statsPtWriteRelevant);

    if (newValid)
    {
        if (Entry->Level != 1)
        {
            curPse = (0 != (Entry->IsPs));
            newPse = (0 != (newValue & PD_PS));
        }
        else
        {
            curPse = newPse = FALSE;
        }
    }
    else
    {
        // The entry is not valid, we don't care about the PSE.
        curPse = newPse = FALSE;
    }

    pseChanged = (newValid && (curPse != newPse));

    // Handle PSE changes and non-leaf modifications.
    if (newValid && ((!Entry->IsLeaf && !pseChanged) || (Entry->IsLeaf && curPse && !newPse)))
    {
        // This happens in two cases:
        // 1. non-leaf entry is modified (no PSE change)
        // 2. a large page is remapped as smaller pages
        //
        // Two important things must be handled here:
        // 1. Contexts that have been added while this entry was invalid - lower level page tables will be allocated and
        //    the contexts will be propagated downwards
        // 2. A PTE that previously pointed to a large page now points to smaller pages - we basically have to do the
        //    exact same thing.

        DWORD offsetsCount, index;
        QWORD offsets[8] = { 0 };
        PHOOK_PTS_ENTRY pPt;
        static PHOOK_PTS_ENTRY cache[1024]; // Used for fast lookup to already allocated entries.
        BOOLEAN useCache = FALSE;

        memzero(cache, sizeof(cache));

        offsetsCount = 0;

        // If there are no children entries, we can use the cache for faster lookup for entries which have just
        // been allocated.
        useCache = IsListEmpty(&Entry->ChildrenEntries);

        list = Entry->ContextEntries.Flink;
        while (list != &Entry->ContextEntries)
        {
            BYTE level;
            QWORD childPtPaAddress, offset;
            PHOOK_PTS pPts = CONTAINING_RECORD(list, HOOK_PTS, Link);

            list = list->Flink;

            // Split the address.
            IntSplitVirtualAddress(pPts->VirtualAddress, &offsetsCount, offsets);

            // Get this new entry PtPaAddress.
            level = (BYTE)(offsetsCount - Entry->Level + 1);

            offset = offsets[level];
            index = (DWORD)(offset / Entry->EntrySize);

            childPtPaAddress = CLEAN_PHYS_ADDRESS64(newValue) + offset;

            if (useCache)
            {
                pPt = cache[index];
            }
            else
            {
                pPt = IntHookPtsFindEntry(&Entry->ChildrenEntries, childPtPaAddress);
            }
            if (NULL == pPt)
            {
                // The child PT entry does not yet exist; We have to alloc it. Hook it if the PS changed, otherwise
                // it will be hooked when parsing all the children entries.
                status = IntHookPtsCreateEntry(childPtPaAddress,
                                               Entry->EntrySize | ((Entry->Level - 1) << 8), Entry, &pPt);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookPtCreateEntry failed for %llx: 0x%08x\n", childPtPaAddress, status);
                    continue;
                }

                cache[index] = pPt;
            }

            // For each moved context we have to decrement the Entry refCount.
            if (Entry->RefCount > 0)
            {
                Entry->RefCount--;
            }
            else
            {
                ERROR("[ERROR] Entry %p refCount is zero!\n", Entry);
                IntDbgEnterDebugger();
            }

            // Remove the context from this Entry, and insert it inside the child contexts entries.
            RemoveEntryList(&pPts->Link);

            IntHookAddCallbackToList(&pPt->ContextEntries, pPts);

            // Update the PTS hook parent.
            pPts->Parent = pPt;

            // Update the pPt ref count.
            pPt->RefCount++;
        }
    }
    else if (newValid && !curPse && newPse)
    {
        // This happens in one case:
        // 1. small pages are remapped as a large page
        // Note that if the entry is non-leaf and it was valid but now it becomes invalid, the children will simply
        // be marked invalid. There's no need to merge all the lower-level entries, because we don't destroy the
        // lower-level tree. The only cases where the tree has to be re-arranged are: small pages maps as large page,
        // large page mapped as small pages or non-leaf entry being mapped for the first time.

        status = IntHookPtsMergeEntry(Entry, Entry);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtMergeEntry failed: 0x%08x\n", status);
        }

        // If we get here, the ChildrenEntries should already be empty.
        if (!IsListEmpty(&Entry->ChildrenEntries))
        {
            ERROR("[ERROR] Just merged entry %108p, but the ChildrenList is not empty!\n", Entry);
            IntDbgEnterDebugger();
        }
    }

    // Parse the existing children.
    list = Entry->ChildrenEntries.Flink;
    while (list != &Entry->ChildrenEntries)
    {
        PHOOK_PTS_ENTRY pPt = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);
        QWORD oldChildValue, newChildValue, newPtPaAddress;

        newChildValue = 0;

        // Fetch the new value that lies inside the new children PTE
        newPtPaAddress = CLEAN_PHYS_ADDRESS64(newValue) + pPt->EntryOffset;

        // Parse the current entry.
        if (!newValid)
        {
            // The entry is not valid. We must remove the hook.
            status = IntHookPtsDisableEntry(pPt, 0, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsDisableEntry failed: 0x%08x\n", status);
            }
        }
        else
        {
            // The entry is now valid. Handle each separate case.

            if (pseChanged)
            {
                // curPse && !newPse
                // One 1G/4M/2M page re-mapped as smaller pages.
                // This is handled when collapsing contexts into new, lower-level page table entries.
                // Handled above

                // !curPse && newPse
                // Smaller pages re-mapped as larger pages.
                // Handled above
            }
            else if (!curValid)
            {
                // The entry was not valid, now it is and the PSE is the same.
                status = IntHookPtsEnableEntry(pPt, newPtPaAddress);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookPtsEnableEntry failed: 0x%08x\n", status);
                }
            }
            else if (CLEAN_PHYS_ADDRESS64(curValue) != CLEAN_PHYS_ADDRESS64(newValue))
            {
                // The entry was valid, but the physical address changed.
                status = IntHookPtsRemapEntry(pPt, newPtPaAddress);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookPtsRemapEntry failed: 0x%08x\n", status);
                }
            }
            else
            {
                // Control bits were modified. Ignored for now.
            }
        }

        // Fetch the new child value after placing the PT hooks, in order to avoid PT modifications made between
        // the moment where we read the value and the moment where the EPT hook is actually placed.
        if (newValid && !newPse)
        {
            status = IntGpaCacheFetchAndAdd(gGuest.GpaCache, newPtPaAddress, pPt->EntrySize, (PBYTE)&newChildValue);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGpaCacheFetchAndAdd failed: 0x%08x\n", status);
                newChildValue = 0;
            }
        }

        oldChildValue = pPt->WriteState.CurEntry;

        // Simulate a write inside the child.
        pPt->WriteState.CurEntry = newChildValue;

        // Recursive call.
        status = IntHookPtsHandleModification(pPt, oldChildValue, newChildValue);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsHandleModification failed: 0x%08x\n", status);
        }

        list = list->Flink;
    }


    Entry->IsValid = newValid;

    if (newValid)
    {
        Entry->IsPs = newPse;

        Entry->IsLeaf = (Entry->IsPs) || (1 == Entry->Level);
    }


    // If this is a leaf entry and we have any kind of modification between the old value and the new one, we can
    // invoke the registered callbacks.
    if (Entry->IsLeaf)
    {
        IntHookPtsCloneCallbacks(Entry);
    }

    STATS_EXIT(statsPtWriteRelevant);

    return INT_STATUS_SUCCESS;
}


static __inline INTSTATUS
IntHookPtsCreateEntry(
    _In_ QWORD PtPaAddress,
    _In_ WORD EntrySizeAndLevel,
    _In_opt_ PHOOK_PTS_ENTRY Parent,
    _Out_ PHOOK_PTS_ENTRY *Entry
    )
///
/// @brief Creates a new page-table entry hook structure.
///
/// This function will allocate a new #HOOK_PTS_ENTRY structure for a page-table entry that is not monitored yet.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation fails.
///
{
    INTSTATUS status;
    HOOK_PTS_ENTRY *pPt;
    DWORD flags;

    status = INT_STATUS_SUCCESS;
    *Entry = NULL;

    pPt = HpAllocWithTag(sizeof(*pPt), IC_TAG_PTPT);
    if (NULL == pPt)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize and fill the entry.
    InitializeListHead(&pPt->ChildrenEntries);
    InitializeListHead(&pPt->ContextEntries);

    // Initialize the header.
    pPt->Header.Flags = 0;
    pPt->Header.Context = NULL;
    pPt->Header.ParentHook = Parent;
    pPt->Header.HookType = hookTypePtsPt;

    pPt->EntrySize = EntrySizeAndLevel & 0xFF;
    pPt->Level = EntrySizeAndLevel >> 8;
    pPt->IsLeaf = pPt->Level == 1;
    pPt->PtPaHookSet = FALSE;
    pPt->IsValid = FALSE;
    pPt->IsPs = FALSE;
    pPt->WriteState.IntEntry = 0;
    pPt->WriteState.CurEntry = 0;
    pPt->WriteState.WrittenMask = 0;
    pPt->PtPaAddress = PtPaAddress;
    pPt->RefCount = 0;
    pPt->PtPaHook = NULL;
    pPt->EntryOffset = (DWORD)(PtPaAddress & PAGE_OFFSET);

    if (pPt->Level < PTS_LEVEL_ROOT)
    {
        if ((pPt->Level == 3) && (gGuest.Mm.Mode == PAGING_PAE_MODE))
        {
            // Top level mapping structure (PDPTE) on PAE paging - we only need to hook 0x20 bytes (4 entries).
            flags = HOOK_FLG_PAE_ROOT;
        }
        else if (((CLEAN_PHYS_ADDRESS64(PtPaAddress) != CLEAN_PHYS_ADDRESS64(gGuest.Mm.SystemCr3))) &&
                 (((pPt->Level == 5) && (gGuest.Mm.Mode == PAGING_5_LEVEL_MODE)) ||
                  ((pPt->Level == 4) && (gGuest.Mm.Mode == PAGING_4_LEVEL_MODE)) ||
                  ((pPt->Level == 2) && (gGuest.Mm.Mode == PAGING_NORMAL_MODE))))
        {
            // Top level mapping inside a user process CR3 - we only need to hook the low half of the entries.
            flags = HOOK_FLG_PT_UM_ROOT;
        }
        else
        {
            // Generic paging structure, otherwise.
            flags = HOOK_FLG_PAGING_STRUCTURE;
        }

        // Place the write hook, only if it is not the root.
        status = IntHookPtmSetHook(pPt->PtPaAddress,
                                   IntHookPtsWriteCallback,
                                   pPt,
                                   pPt,
                                   flags,
                                   &pPt->PtPaHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtmSetHook failed: 0x%08x\n", status);

            // And leave!
            goto cleanup_and_exit;
        }

        // IMPORTANT: Fetch data from the page-table page only after the hook has been set on it. Otherwise, we may
        // race with the guest: the page-table entries may be modified since the entry has been read and until the
        // table has been hooked, leading to inconsistencies.

        // Also, if this is not the root, fetch the current entry inside the PT.
        status = IntGpaCacheFetchAndAdd(gGuest.GpaCache,
                                        pPt->PtPaAddress,
                                        pPt->EntrySize,
                                        (PBYTE)&pPt->WriteState.CurEntry);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGpaCacheFetchAndAdd failed for 0x%016llx: 0x%08x\n", pPt->PtPaAddress, status);

            // And leave!
            goto cleanup_and_exit;
        }

        // Save the valid flag.
        pPt->IsValid = (0 != (pPt->WriteState.CurEntry & 1));

        // Save the PS flag.
        pPt->IsPs = (pPt->IsValid) && (pPt->Level != 1) && (0 != (pPt->WriteState.CurEntry & PD_PS));

        // Determine whether this is a leaf or not.
        pPt->IsLeaf = (pPt->Level == 1) || (pPt->IsPs);

        pPt->PtPaHookSet = TRUE;
    }

    if (NULL != Parent)
    {
        InsertTailList(&Parent->ChildrenEntries, &pPt->Link);

        Parent->RefCount++;
    }

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pPt)
        {
            HpFreeAndNullWithTag(&pPt, IC_TAG_PTPT);
        }
    }

    *Entry = pPt;

    return status;
}


INTSTATUS
IntHookPtsSetHook(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PFUNC_SwapCallback Callback,
    _In_opt_ void *Context,
    _In_opt_ void *Parent,
    _In_ DWORD Flags,
    _Out_ PHOOK_PTS *Hook
    )
///
/// @brief Start monitoring translation modifications for the given VirtualAddress.
///
/// Establishes a hook inside the page-tables of the given VirtualAddress inside the Cr3 virtual address space.
/// Whenever there is a translation modification for the given VirtualAddress, the Callback will be invoked. The
/// Context can be a user-supplied value which is passed to the invoked callback.
/// This function will either add a new page-table entry hook (PTS entry hook) on each page-table entry used to
/// translate the provided virtualAddress, or it will simply increment the reference count of an existing such
/// entry.
///
/// @param[in]  Cr3             The monitored virtual address space.
/// @param[in]  VirtualAddress  The virtual address to be monitored.
/// @param[in]  Callback        The #PFUNC_SwapCallback to be called when the translation is modified.
/// @param[in]  Context         Optional context that will be passed to the Callback.
/// @param[in]  Parent          Optional parent hook.
/// @param[in]  Flags           Hook flags. Check HOOK_FLG* for more info.
/// @param[out] Hook            The hook handle which can later be used to remove this hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If a kernel-mode address is to be monitored outside the kernel Cr3.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation fails.
///
{
    INTSTATUS status;
    PHOOK_PTS pPts;
    QWORD pml5eAddress, pml4eAddress, pdpeAddress, pdeAddress, pteAddress;
    PHOOK_PTS_ENTRY root, pml5, pml4, pdp, pd, pt, pf;
    DWORD hid;
    LIST_ENTRY *list;
    BYTE entrySize;
    BOOLEAN doCleanup;
    PHOOK_PTS_STATE pPtsState;

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_7;
    }

    pPts = NULL;
    pml5eAddress = pml4eAddress = pdpeAddress = pdeAddress = pteAddress = 0;
    root = pml4 = pdp = pd = pt = pf = NULL;
    doCleanup = FALSE;
    pPtsState = &gHooks->PtsHooks;

    Flags &= HOOK_FLG_GLOBAL_MASK;

    if (0 == Cr3)
    {
        Cr3 = gGuest.Mm.SystemCr3;
    }

    if ((Cr3 != gGuest.Mm.SystemCr3) && (( gGuest.Guest64 && !!(VirtualAddress & BIT(63))) ||
                                         (!gGuest.Guest64 && !!(VirtualAddress & BIT(31)))))
    {
        ERROR("[ERROR] Kernel mapping 0x%016llx hook set inside non-system CR3 0x%016llx!\n", VirtualAddress, Cr3);
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = INT_STATUS_SUCCESS;

    // Entries may be 4 bytes or 8 bytes in length. They are 4 bytes in legacy paging mode only.
    entrySize = (gGuest.Mm.Mode == PAGING_NORMAL_MODE ? 4 : 8);

    pPts = HpAllocWithTag(sizeof(*pPts), IC_TAG_PTPS);
    if (NULL == pPts)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pPts->Header.Flags = Flags;
    pPts->Header.ParentHook = Parent;
    pPts->Header.Context = Context;
    pPts->Header.HookType = hookTypePts;

    pPts->Callback = Callback;
    pPts->VirtualAddress = VirtualAddress;

    pPts->Cr3 = Cr3;

    // Search the root. The key is the Cr3.
    if (PAGING_PAE_MODE == gGuest.Mm.Mode)
    {
        hid = HOOK_PT_PAE_ROOT_HASH_ID(Cr3);
    }
    else
    {
        hid = HOOK_PT_HASH_ID(Cr3);
    }

    list = gHooks->PtsHooks.HooksRootList[hid].Flink;
    while (list != &gHooks->PtsHooks.HooksRootList[hid])
    {
        root = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);

        list = list->Flink;

        if (root->PtPaAddress == Cr3)
        {
            break;
        }

        root = NULL;
    }

    // If we didn't find a root yet, create one.
    if (NULL == root)
    {
        // Level 6 is just a magic that indicates the root of translation.
        status = IntHookPtsCreateEntry(Cr3,
                                       entrySize | (PTS_LEVEL_ROOT << 8),
                                       NULL,
                                       &root);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsCreateEntry failed: 0x%08x\n", status);
            doCleanup = TRUE;
            goto cleanup_and_exit;
        }

        // Insert the root inside the roots hash table.
        InsertTailList(&gHooks->PtsHooks.HooksRootList[hid], &root->Link);
    }

    // Force the PF to root for now.
    pf = root;

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode)
    {
        pml5eAddress = (CLEAN_PHYS_ADDRESS64(Cr3)) + PML5_INDEX(VirtualAddress) * 8ull;
    }

    // Parse and hook the PML5 entry.
    if (0 != pml5eAddress)
    {
        // PML5 entry present, hook it if not already hooked.
        pml5 = IntHookPtsFindEntry(&root->ChildrenEntries, pml5eAddress);
        if (NULL == pml5)
        {
            status = IntHookPtsCreateEntry(pml5eAddress, entrySize | (PTS_LEVEL_PML5 << 8), root, &pml5);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsCreateEntry failed: 0x%08x\n", status);
                doCleanup = TRUE;
                goto cleanup_and_exit;
            }
        }

        pf = pml5;
    }
    else
    {
        pml5 = root;
    }

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode)
    {
        if (!!(pml5->WriteState.CurEntry & PT_P))
        {
            pml4eAddress = (CLEAN_PHYS_ADDRESS64(pml5->WriteState.CurEntry)) + PML4_INDEX(VirtualAddress) * 8ull;
        }
    }
    else if (PAGING_4_LEVEL_MODE == gGuest.Mm.Mode)
    {
        pml4eAddress = (CLEAN_PHYS_ADDRESS64(Cr3)) + PML4_INDEX(VirtualAddress) * 8ull;
    }


    // Parse and hook the PML4 entry.
    if (0 != pml4eAddress)
    {
        // PML4 entry present, hook it if not already hooked.
        pml4 = IntHookPtsFindEntry(&pml5->ChildrenEntries, pml4eAddress);
        if (NULL == pml4)
        {
            status = IntHookPtsCreateEntry(pml4eAddress, entrySize | (PTS_LEVEL_PML4 << 8), pml5, &pml4);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsCreateEntry failed: 0x%08x\n", status);
                doCleanup = TRUE;
                goto cleanup_and_exit;
            }
        }

        pf = pml4;
    }
    else
    {
        pml4 = root;
    }

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode ||
        PAGING_4_LEVEL_MODE == gGuest.Mm.Mode)
    {
        if (!!(pml4->WriteState.CurEntry & PT_P))
        {
            pdpeAddress = (CLEAN_PHYS_ADDRESS64(pml4->WriteState.CurEntry)) + PDP_INDEX(VirtualAddress) * 8ull;
        }
    }
    else if (PAGING_PAE_MODE == gGuest.Mm.Mode)
    {
        pdpeAddress = (CLEAN_PHYS_ADDRESS32PAE_ROOT(Cr3)) + PDPPAE_INDEX(VirtualAddress) * 8ull;
    }


    // PDP entry now.
    if (0 != pdpeAddress)
    {
        QWORD pdpeValue;

        // PDP entry present, hook it if not already hooked.
        pdp = IntHookPtsFindEntry(&pml4->ChildrenEntries, pdpeAddress);
        if (NULL == pdp)
        {
            status = IntHookPtsCreateEntry(pdpeAddress, entrySize | (PTS_LEVEL_PDP << 8), pml4, &pdp);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsCreateEntry failed: 0x%08x\n", status);
                doCleanup = TRUE;
                goto cleanup_and_exit;
            }
        }

        pf = pdp;

        pdpeValue = pdp->WriteState.CurEntry;

        // Check for 1G page.
        if ((0 != (pdpeValue & PDP_PS)) && (0 != (pdpeValue & PDP_P)))
        {
            pf->IsLeaf = TRUE;
            goto parse_done;
        }
    }
    else
    {
        pdp = root;
    }

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode ||
        PAGING_4_LEVEL_MODE == gGuest.Mm.Mode ||
        PAGING_PAE_MODE == gGuest.Mm.Mode)
    {
        if (!!(pdp->WriteState.CurEntry & PT_P))
        {
            pdeAddress = (CLEAN_PHYS_ADDRESS64(pdp->WriteState.CurEntry)) + PD_INDEX(VirtualAddress) * 8ull;
        }
    }
    else if (PAGING_NORMAL_MODE == gGuest.Mm.Mode)
    {
        pdeAddress = (CLEAN_PHYS_ADDRESS32(Cr3)) + PD32_INDEX(VirtualAddress) * 4ull;
    }


    // PD entry now.
    if (0 != pdeAddress)
    {
        QWORD pdeValue;

        // PDP entry present, hook it if not already hooked.
        pd = IntHookPtsFindEntry(&pdp->ChildrenEntries, pdeAddress);
        if (NULL == pd)
        {
            status = IntHookPtsCreateEntry(pdeAddress, entrySize | (PTS_LEVEL_PD << 8), pdp, &pd);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsCreateEntry failed: 0x%08x\n", status);
                doCleanup = TRUE;
                goto cleanup_and_exit;
            }
        }

        pf = pd;

        pdeValue = pd->WriteState.CurEntry;

        // Check for 2M/4M large page.
        if ((0 != (pdeValue & PDP_PS)) && (0 != (pdeValue & PDP_P)))
        {
            pf->IsLeaf = TRUE;
            goto parse_done;
        }
    }
    else
    {
        pd = root;
    }

    if (PAGING_5_LEVEL_MODE == gGuest.Mm.Mode ||
        PAGING_4_LEVEL_MODE == gGuest.Mm.Mode ||
        PAGING_PAE_MODE == gGuest.Mm.Mode)
    {
        if (!!(pd->WriteState.CurEntry & PT_P))
        {
            pteAddress = (CLEAN_PHYS_ADDRESS64(pd->WriteState.CurEntry)) + PT_INDEX(VirtualAddress) * 8ull;
        }
    }
    else if (PAGING_NORMAL_MODE == gGuest.Mm.Mode)
    {
        if (!!(pd->WriteState.CurEntry & PT_P))
        {
            pteAddress = (CLEAN_PHYS_ADDRESS32(pd->WriteState.CurEntry)) + PT32_INDEX(VirtualAddress) * 4ull;
        }
    }


    // PT entry now.
    if (0 != pteAddress)
    {
        // PDP entry present, hook it if not already hooked.
        pt = IntHookPtsFindEntry(&pd->ChildrenEntries, pteAddress);
        if (NULL == pt)
        {
            status = IntHookPtsCreateEntry(pteAddress, entrySize | (PTS_LEVEL_PT << 8), pd, &pt);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsCreateEntry failed: 0x%08x\n", status);
                doCleanup = TRUE;
                goto cleanup_and_exit;
            }
        }

        pf = pt;

        pf->IsLeaf = TRUE;
        goto parse_done;
    }
    else
    {
        pt = root;
    }

parse_done:
cleanup_and_exit:

    // We will now insert the current PTS hook inside the contexts list of the PF. Note that right now, we don't know
    // and we don't care who pf is; it might be the pml4 or it might be the pt (the structures may be incomplete).
    // The PTS hook will be moved up and down on the hierarchy whenever the translations are modified.
    if (NULL != pf)
    {
        // Add the PTS entry to the list.
        IntHookAddCallbackToList(&pf->ContextEntries, pPts);

        // Update the refcount.
        pf->RefCount++;

        // Mark the reference to the parent.
        pPts->Parent = pf;
    }

    // Insert the entry in the global PTS list (this needs to be done even in the case of a failure, because
    // IntHookPtsRemoveHookInternal will try to remove it from that list and will crash)
    InsertTailList(&pPtsState->HooksPtsList, &pPts->PtsLink);

    // Something went wrong; We need to free what we managed to allocate.
    if (doCleanup)
    {
        INTSTATUS status2;

        if (NULL != pf)
        {
            // The pf is initialized, we can remove the PTS.
            status2 = IntHookPtsRemoveHookInternal(pPts, 0);
            if (!INT_SUCCESS(status2))
            {
                ERROR("[ERROR] IntHookPtsRemoveHookInternal failed: 0x%08x\n", status2);
            }
        }
        else
        {
            // pf is NULL, we don't even have a root, so we just have to free the PTS descriptor.
            HpFreeAndNullWithTag(&pPts, IC_TAG_PTPS);
        }

        pPts = NULL;
    }
    else if (NULL != pf)
    {
        // Store the current physical addresses and page size
        pPts->OldEntry = 0;
        pPts->OldPageSize = 0;
        pPts->CurEntry = pf->WriteState.CurEntry;
        pPts->CurPageSize = IntHookPtsGetPageSize(pf);
    }

    if (INT_SUCCESS(status))
    {
        *Hook = pPts;
    }

    return status;
}


INTSTATUS
IntHookPtsRemoveHook(
    _Inout_ HOOK_PTS **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a PTS hook.
///
/// Remove a PTS hook. Modifications to the subsequent virtual address translations will not be reported anymore.
/// The hook is not deleted until either the commit phase, or when a higher level hook manager decides so.
///
/// @param[in, out] Hook    The hook to be removed.
/// @param[in]      Flags   Hook flags. Check out HOOK_FLG* for more info.
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

    status = IntHookPtsRemoveHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsRemoveHookInternal failed: 0x%08x\n", status);
    }

    // NOTE: If chain delete is requested, the caller will make sure to explicitly call delete on this hook. In this
    // case, don't NULL out the hook, as it's still needed, and it's not removed yet.
    if (!(Flags & HOOK_FLG_CHAIN_DELETE))
    {
        *Hook = NULL;
    }

    return status;
}


INTSTATUS
IntHookPtsDeleteHook(
    _Inout_ HOOK_PTS **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently delete the PTS hook.
///
/// This function will permanently delete an existing PTS hook. This function must be called only if the
/// hook has already been removed.
///
/// @param[in, out] Hook    The hook to be deleted.
/// @param[in]      Flags   Hook flags. Check out HOOK_FLG* for more info.
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

    status = IntHookPtsDeleteHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsDeleteHookInternal failed: 0x%08x\n", status);
    }

    *Hook = NULL;

    return status;
}


static __inline INTSTATUS
IntHookPtsCleanupList(
    _In_ LIST_HEAD *ListHead
    )
///
/// @brief Commits a list of page-table entry hooks.
///
/// @param[in]  ListHead    The list of page-table entry hooks to be committed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    // Hooks have been removed, make sure we free them all.
    list = ListHead->Flink;
    while (list != ListHead)
    {
        PHOOK_PTS_ENTRY pPt = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);

        list = list->Flink;

        if (0 != (pPt->Header.Flags & HOOK_FLG_CHAIN_DELETE))
        {
            continue;
        }

        if (0 != (pPt->Header.Flags & HOOK_FLG_REMOVE))
        {
            status = IntHookPtsDeletePdHook(pPt, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsDeletePdHook failed: 0x%08x\n", status);
            }
        }
        else
        {
            WARNING("[WARNING] Unknown state for the hook at %p, flags %08x!\n", pPt, pPt->Header.Flags);
            IntEnterDebugger();
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookPtsCommitHooks(
    void
    )
///
/// @brief Commit all PTS hook modifications.
///
/// This function will effectively delete all the removed PTS hooks. Hooks which are flagged with the
/// #HOOK_FLG_CHAIN_DELETE delete will be spared, as it is expected that they will be deleted by a higher-level
/// hook manager.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    if (!gHooks->PtsHooks.HooksRemoved)
    {
        return INT_STATUS_SUCCESS;
    }

    // Cleanup the PTS list of hooks.
    list = gHooks->PtsHooks.RemovedHooksPtsList.Flink;
    while (list != &gHooks->PtsHooks.RemovedHooksPtsList)
    {
        PHOOK_PTS pPts = CONTAINING_RECORD(list, HOOK_PTS, Link);
        list = list->Flink;

        // Chain delete requested - the parent of this hook will decide when to delete it.
        if (0 != (pPts->Header.Flags & HOOK_FLG_CHAIN_DELETE))
        {
            continue;
        }

        // Hook is removed, we can delete it.
        if (0 != (pPts->Header.Flags & HOOK_FLG_REMOVE))
        {
            status = IntHookPtsDeleteHookInternal(pPts, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsDeleteHookInternal failed: 0x%08x\n", status);
            }
        }
        else
        {
            ERROR("[ERROR] Unknown hook state for hook %p, flags %08x\n", pPts, pPts->Header.Flags);
            IntEnterDebugger();
        }
    }

    // We can try to clean-up the PTE hooks.
    status = IntHookPtsCleanupList(&gHooks->PtsHooks.RemovedHooksPtList);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtCleanupList failed: 0x%08x\n", status);
    }

    // We can try to clean-up the PDE hooks.
    status = IntHookPtsCleanupList(&gHooks->PtsHooks.RemovedHooksPdList);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtCleanupList failed: 0x%08x\n", status);
    }

    // We can try to clean-up the PDPE hooks.
    status = IntHookPtsCleanupList(&gHooks->PtsHooks.RemovedHooksPdpList);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtCleanupList failed: 0x%08x\n", status);
    }

    // We can try to clean-up the PML4E hooks.
    status = IntHookPtsCleanupList(&gHooks->PtsHooks.RemovedHooksPml4List);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtCleanupList failed: 0x%08x\n", status);
    }

    // We can try to clean-up the PML5E hooks.
    status = IntHookPtsCleanupList(&gHooks->PtsHooks.RemovedHooksPml5List);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtCleanupList failed: 0x%08x\n", status);
    }

    // We can try to clean-up the Root hooks.
    status = IntHookPtsCleanupList(&gHooks->PtsHooks.RemovedHooksRootList);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtCleanupList failed: 0x%08x\n", status);
    }

    gHooks->PtsHooks.HooksRemoved = FALSE;

    return status;
}


INTSTATUS
IntHookPtsInit(
    void
    )
///
/// @brief Initializes the PTS hooks system.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    InitializeListHead(&gHooks->PtsHooks.HooksPtsList);

    for (DWORD i = 0; i < HOOK_PT_HASH_SIZE; i++)
    {
        InitializeListHead(&gHooks->PtsHooks.HooksRootList[i]);
    }

    InitializeListHead(&gHooks->PtsHooks.RemovedHooksRootList);
    InitializeListHead(&gHooks->PtsHooks.RemovedHooksPtsList);
    InitializeListHead(&gHooks->PtsHooks.RemovedHooksPtList);
    InitializeListHead(&gHooks->PtsHooks.RemovedHooksPdList);
    InitializeListHead(&gHooks->PtsHooks.RemovedHooksPdpList);
    InitializeListHead(&gHooks->PtsHooks.RemovedHooksPml4List);
    InitializeListHead(&gHooks->PtsHooks.RemovedHooksPml5List);

    gHooks->PtsHooks.HooksRemoved = FALSE;

    gHooks->PtsHooks.CallbacksList = NULL;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookPtsWriteEntry(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue
    )
///
/// @brief Tests the translation modification handler.
///
/// @param[in]  Entry       The entry to be "modified".
/// @param[in]  OldValue    Old page-table entry value.
/// @param[in]  NewValue    New page-table entry value.
///
{
    Entry->WriteState.CurEntry = OldValue;

    return IntHookPtsHandleModification(Entry, OldValue, NewValue);
}


INTSTATUS
IntHookPtsCheckIntegrity(
    void
    )
///
/// @brief Checks the integrity of the existing page-table hooks. Used for debugging the PT filter.
///
/// This function will iterate through all the monitored virtual addresses and check if the actual translation
/// present inside the guest is the same as the last value saved by Introcore. Basically, this function ensures
/// that these hook structures are up to date with the actual memory contents. Used for debugging the PT filter.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If PT filtering is not enabled.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the hooks system is not initialized.
///
{
    if (!gGuest.PtFilterEnabled)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL == gHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    STATS_ENTER(statsPtsIntegrity);

    for (LIST_ENTRY *entry = gHooks->PtsHooks.HooksPtsList.Flink;
         entry != &gHooks->PtsHooks.HooksPtsList; entry = entry->Flink)
    {
        PHOOK_PTS pHook = CONTAINING_RECORD(entry, HOOK_PTS, PtsLink);
        VA_TRANSLATION tr = { 0 };
        QWORD changedBits;
        INTSTATUS status;

        if (0 != ((HOOK_FLG_DISABLED | HOOK_FLG_REMOVE) & pHook->Header.Flags))
        {
            // Skip disabled/removed hooks
            continue;
        }

        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, pHook->VirtualAddress))
        {
            // Don't check user mode translations
            // If someone has the power of changing these we already have big problems
            continue;
        }

        if (pHook->IntegrityCheckFailed)
        {
            // No point in checking this VA again if the integrity check already failed for it
            continue;
        }

        status = IntTranslateVirtualAddressEx(pHook->VirtualAddress, pHook->Cr3, 0, &tr);
        if (!INT_SUCCESS(status) || 0 == tr.MappingsCount)
        {
            TRACE("[ERROR] IntTranslateVirtualAddressEx failed for 0x%016llx with Cr3 0x%016llx: 0x%08x\n",
                  pHook->VirtualAddress, pHook->Cr3, status);
            continue;
        }

        if ((0 == (pHook->CurEntry & PT_P)) && (0 == (tr.MappingsEntries[tr.MappingsCount - 1] & PT_P)))
        {
            // Don't check the translation if both the old and the new entry are not present
            continue;
        }

        changedBits = pHook->CurEntry ^ tr.MappingsEntries[tr.MappingsCount - 1];
        if ((0 != (HOOK_PTS_MONITORED_BITS & changedBits)) ||
            (pHook->CurPageSize != tr.PageSize))
        {
            PEVENT_TRANSLATION_VIOLATION pTr = &gAlert.Translation;
            EXCEPTION_KM_ORIGINATOR originator = { 0 };
            BOOLEAN inAgent = FALSE;

            // This might be a fake violation. Basically, we have a race condition: while the timer runs another
            // CPU might be in the filtering agent waiting for a PT write to be acknowledged by introcore.

            IntPauseVcpus();

            status = IntThrSafeCheckThreads(THS_CHECK_ONLY | THS_CHECK_PTFILTER);
            if (INT_STATUS_CANNOT_UNLOAD == status)
            {
                inAgent = TRUE;
            }

            IntResumeVcpus();

            if (inAgent)
            {
                goto stop_and_exit;
            }

            LOG("[PTS INTEGRITY] Translation modification for VA 0x%016llx in CR3 0x%016llx: old = 0x%016llx "
                "new = 0x%016llx old size = 0x%016llx new size = 0x%016llx\n",
                pHook->VirtualAddress, pHook->Cr3,
                pHook->CurEntry, tr.MappingsEntries[tr.MappingsCount - 1],
                pHook->CurPageSize, tr.PageSize);

            memset(pTr, 0, sizeof(EVENT_TRANSLATION_VIOLATION));

            pTr->Header.Action = introGuestAllowed;
            pTr->Header.Reason = introReasonAllowed;
            pTr->Header.MitreID = idRootkit;

            pTr->WriteInfo.NewValue[0] = tr.MappingsEntries[tr.MappingsCount - 1];
            pTr->WriteInfo.OldValue[0] = pHook->CurEntry;
            pTr->WriteInfo.Size = 8;

            pTr->Victim.VirtualAddress = pHook->VirtualAddress;
            pTr->ViolationType = transViolationWatchdog;

            IntAlertFillCpuContext(FALSE, &pTr->Header.CpuContext);

            pTr->Header.Flags = IntAlertCoreGetFlags(0, introReasonUnknown);
            pTr->Header.Flags |= ALERT_FLAG_FEEDBACK_ONLY;
            pTr->Header.Flags |= (gGuest.KernelBetaDetections ? ALERT_FLAG_BETA : 0);

            IntAlertFillWinProcessCurrent(&pTr->Header.CurrentProcess);

            status = IntExceptKernelGetOriginator(&originator, 0);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] Failed to get originator on translation violation, RIP: %llx\n",
                        pTr->Header.CpuContext.Rip);
            }
            else
            {
                IntAlertFillWinKmModule(originator.Original.Driver, &pTr->Originator.Module);
            }

            IntAlertFillVersionInfo(&pTr->Header);

            status = IntNotifyIntroEvent(introEventTranslationViolation, pTr, sizeof(*pTr));
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
            }

            pHook->IntegrityCheckFailed = TRUE;
        }
    }

stop_and_exit:
    STATS_EXIT(statsPtsIntegrity);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookPtsDumpPtsEntry(
    _In_ HOOK_PTS_ENTRY const *Entry
    )
///
/// @brief      Prints a #HOOK_PTS_ENTRY structure.
///
/// @param[in]  Entry   Structure to print.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Entry is NULL.
///
{
    LIST_ENTRY *list;
    QWORD x;
    DWORD i;

    if (NULL == Entry)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    for (i = 0; i < (DWORD)(5 - Entry->Level); i++)
    {
        NLOG("    ");
    }

    IntPhysicalMemRead(Entry->PtPaAddress, Entry->EntrySize, &x, NULL);

    NLOG("Level %d, Entry %p, PTE at 0x%016llx, refcount %d, Cur 0x%016llx, Int 0x%016llx, "
         "Real 0x%016llx, IsValid %d, IsPs %d, IsLeaf %d\n",
         Entry->Level, Entry, Entry->PtPaAddress, Entry->RefCount, Entry->WriteState.CurEntry,
         Entry->WriteState.IntEntry, x, Entry->IsValid, Entry->IsPs, Entry->IsLeaf);

    list = Entry->ContextEntries.Flink;
    while (list != &Entry->ContextEntries)
    {
        PHOOK_PTS pPts = CONTAINING_RECORD(list, HOOK_PTS, Link);

        list = list->Flink;

        for (i = 0; i < (DWORD)(5 - Entry->Level); i++)
        {
            NLOG("    ");
        }

        NLOG("    -> Context %p, Flags 0x%08x, Context callback %p, callback context %p, VA 0x%016llx\n",
             pPts, pPts->Header.Flags, pPts->Callback, pPts->Header.Context, pPts->VirtualAddress);
    }

    list = Entry->ChildrenEntries.Flink;
    while (list != &Entry->ChildrenEntries)
    {
        PHOOK_PTS_ENTRY pPt = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);

        list = list->Flink;

        IntHookPtsDumpPtsEntry(pPt);
    }

    return INT_STATUS_SUCCESS;
}


void
IntHookPtsDump(
    void
    )
///
/// @brief      Prints all the page table hooks.
///
/// This prints all the page table hooks from #gHooks.
///
{
    LIST_ENTRY *list;
    DWORD i;

    for (i = 0; i < HOOK_PT_HASH_SIZE; i++)
    {
        list = gHooks->PtsHooks.HooksRootList[i].Flink;
        while (list != &gHooks->PtsHooks.HooksRootList[i])
        {
            PHOOK_PTS_ENTRY pPt = CONTAINING_RECORD(list, HOOK_PTS_ENTRY, Link);

            list = list->Flink;

            NLOG("-------------------------------------------------------------\n");
            NLOG("Root 0x%016llx, with refcount %d\n", pPt->PtPaAddress, pPt->RefCount);
            IntHookPtsDumpPtsEntry(pPt);
        }
    }
}
