/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook.h"
#include "hook_gpa.h"
#include "callbacks.h"
#include "introcpu.h"
#include "ptfilter.h"

#ifdef INT_COMPILER_MSVC
#pragma warning(push)
#pragma warning(disable: 4204)  // nonstandard extension used: non-constant aggregate initializer
#endif // INT_COMPILER_MSVC


PHOOK_EPT_ENTRY
IntHookGpaGetEptEntry(
    _In_ QWORD GpaPage
    )
///
/// @brief Get the EPT entry associated with a physical page.
///
/// This function will search for an existing EPT entry, and return it. If none is found, it will allocate one,
/// insert it in the EPT entry list, and return it.
///
/// @param[in] GpaPage  Guest physical page whose EPT entry is to be returned. Low 12 bits are ignored.
///
/// @returns The EPT entry associated with the provided guest physical page, or NULL if none is found and a memory
///          alloc fails.
///
{
    HOOK_EPT_ENTRY *pEptEntry;
    const DWORD id = GPA_EPT_ID(GpaPage);

    GpaPage &= PHYS_PAGE_MASK;

    pEptEntry = IntHookGpaGetExistingEptEntry(GpaPage);
    if (NULL != pEptEntry)
    {
        return pEptEntry;
    }

    //
    // No entry found for this GPA, allocate a new one.
    // NOTE: If we see a page for the first time (it is not hooked), we can safely assume it is RWX.
    //
    pEptEntry = HpAllocWithTag(sizeof(*pEptEntry), IC_TAG_EPTE);
    if (NULL == pEptEntry)
    {
        return NULL;
    }

    pEptEntry->GpaPage = GpaPage;

    InsertTailList(&gHooks->GpaHooks.EptEntries[id], &pEptEntry->Link);

    return pEptEntry;
}


static INTSTATUS
IntHookGpaGetSppEntry(
    _Inout_ HOOK_EPT_ENTRY *Entry
    )
///
/// @brief Allocates a SPP entry for the given EPT hook.
///
/// Allocates a SPP entry for the provided EPT entry. SPP entries are used to describe 128 bytes granularity hooks
/// on capable Intel CPUs. If no write hooks exist inside the given page, the SPP entry will be initialized to
/// the default value indicating that sub-page writes are allowed. If at least a hook is present on this page, the
/// SPP entry will be initialized assuming that the entire page is hooked. This function must be called whenever
/// placing the first write hook that does not cover the entire page (less than 4K).
///
/// @param[in, out] Entry   The EPT entry whose SPP entry is to be allocated.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation function fails.
/// @retval #INT_STATUS_ALREADY_INITIALIZED If the SPP entry has already been allocated for this EPT entry.
///
{
    if (NULL != Entry->Spp)
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    Entry->Spp = HpAllocWithTag(sizeof(*Entry->Spp), IC_TAG_SPPE);
    if (NULL == Entry->Spp)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initially, the SPP entry is considered non-writable.
    Entry->Spp->OldSpp = 0;

    // If this isn't the first write hook on this page, make sure we reflect it inside the current SPP permissions
    // and inside the 128B non-write areas.
    if (Entry->WriteCount == 0)
    {
        Entry->Spp->CurSpp = 0x5555555555555555;
    }
    else
    {
        // This isn't the first write-hook on this page, but it is the first sub-page hook - this means that a previous
        // write hook covers the entire page.
        Entry->Spp->CurSpp = 0;

        for (DWORD i = 0; i < 32; i++)
        {
            Entry->Spp->SppCount[i] += Entry->WriteCount;
        }
    }

    return INT_STATUS_SUCCESS;
}


static void
IntHookGpaInsertHookInList(
    _Inout_ LIST_ENTRY *List,
    _In_ HOOK_GPA *Hook
    )
///
/// @brief Insert the hook in the given list of hooks.
///
/// Inserts the provided hook inside the given hooks list. This function must be used whenever inserting
/// hooks inside a list, as it takes into account high-priority hooks - hooks that must be called before
/// the regular ones.
///
/// @param[in, out] List    The list where the hook must be inserted.
/// @param[in]      Hook    The hook that must be inserted in the list.
///
{
    if (0 == (Hook->Header.Flags & HOOK_FLG_HIGH_PRIORITY))
    {
        InsertTailList(List, &Hook->Link);
    }
    else
    {
        LIST_ENTRY *pivot = List->Flink;

        while (pivot != List)
        {
            HOOK_GPA *pHook = CONTAINING_RECORD(pivot, HOOK_GPA, Link);

            if (0 == (pHook->Header.Flags & HOOK_FLG_HIGH_PRIORITY))
            {
                pivot = pivot->Blink;
                break;
            }

            pivot = pivot->Flink;
        }

        InsertAfterList(pivot, &Hook->Link);
    }
}


PHOOK_EPT_ENTRY
IntHookGpaGetExistingEptEntry(
    _In_ QWORD GpaPage
    )
///
/// @brief Get the EPT entry associated with the provided guest physical page.
///
/// @param[in] GpaPage  The guest physical page for which the EPT entry must be retrieved. Low 12 bits are ignored.
///
/// @return The EPT entry associated with the provided guest physical page, or NULL if none is found.
///
{
    const DWORD id = GPA_EPT_ID(GpaPage);
    LIST_ENTRY *list = gHooks->GpaHooks.EptEntries[id].Flink;

    GpaPage &= PHYS_PAGE_MASK;

    while (list != &gHooks->GpaHooks.EptEntries[id])
    {
        HOOK_EPT_ENTRY *pEptEntry = CONTAINING_RECORD(list, HOOK_EPT_ENTRY, Link);
        list = list->Flink;

        if (pEptEntry->GpaPage == GpaPage)
        {
            return pEptEntry;
        }
    }

    return NULL;
}


INTSTATUS
IntHookGpaSetHook(
    _In_ QWORD Gpa,
    _In_ DWORD Length,
    _In_ BYTE Type,
    _In_ PFUNC_EptViolationCallback Callback,
    _In_opt_ void *Context,
    _In_opt_ void *ParentHook,
    _In_opt_ DWORD Flags,
    _Out_opt_ HOOK_GPA **Hook
    )
///
/// @brief Places an EPT hook on the indicated memory range.
///
/// Establishes a memory hook, using the EPT/NPT, on the provided guest physical address. The provided guest physical
/// address needs not be page aligned, but the memory area for which the hook is placed must not exceed the page
/// boundary. Whenever the indicated access (read, write, execute) takes place inside the hooked range, the provided
/// callback will be called (see #PFUNC_EptViolationCallback for more info). Note that the CPU may trigger events for
/// accesses outside the hooked range - these will not cause the callback to be called, but they will induce a
/// significant performance penalty, so care must be taken when placing memory hooks. The minimum granularity of a
/// hook is given by the hardware page size, and it usually is 4K - this means that placing a hook on a range of 4 bytes
/// will still trigger events for the entire page, but the provided callback will be called if and only if at least on
/// byte inside the hooked range is accessed. If a write hook is placed on a CPU & HV which supports sub-page
/// permissions (SPP), the hook granularity is reduced to 128 bytes. Please refer to the Intel docs for more
/// information, and take into consideration that even if a SPP hook is placed on a 128 bytes region, events may still
/// be generated for accesses outside that region.
/// Accepted hook types are:
/// - #IG_EPT_HOOK_READ - read hook, call the callback on each read access.
/// - #IG_EPT_HOOK_WRITE - write hook, call the callback on each write access.
/// - #IG_EPT_HOOK_EXECUTE - execute hook, call the callback on each instruction fetch.
/// NOTE: Placing a read-only hook is not supported by Intel hardware (a page cannot be writable without having read
/// permissions). Therefore, if you wish to establish a read hook on a page, make sure you first set a write hook, in
/// order to avoid an EPT misconfiguration.
/// NOTE: Placing a write hook on a page table (as indicated by #HOOK_FLG_PAGING_STRUCTURE, #HOOK_FLG_PAE_ROOT,
/// and #HOOK_FLG_PT_UM_ROOT flags) may be treated differently than placing a hook on a regular page:
/// - If the PT filter is enabled, the page will not actually be hooked in EPT, meaning that it will remain writable;
///   however, accesses will be instrumented directly inside the guest, and relevant modifications will be reported
///   to introspection;
/// - If VE and VMFUNC are supported by the CPU and the HV, the page will be marked non-writable inside the EPT,
///   and it will also be marked convertible, meaning that instead of EPT violations, VEs will be generated inside
///   the guest. Inside the guest, a filtering agent exists which analyzes page-table writes, and raises a VMCALL to
///   introspection only if the access is deemed relevant (for example, simply modifying the A/D bits will not lead
///   to a VM exit).
/// Also note that when hooking page-tables against writes, the Intel CPUs will generate an EPT violation on every
/// page walk, if it has to set the A/D bits; Due to performance concerns, these EPT violations are handled directly
/// inside the HV, and they are never sent to introspection; therefore, the callback will never be called for page-walk
/// induced EPT violations.
/// NOTE: Some Intel CPUs do not support execute-only EPT hooks.
/// NOTE: There is a limit on how many hooks of a given type can be placed on a given page - this limit is
/// #MAX_HOOK_COUNT - #MAX_HOOK_COUNT read, write and execute hooks can be placed on the same page.
/// NOTE: This function will invoke the integrator/HV in order to alter the EPT access rights for the provided guest
/// physical page. However, these requests may be cached and/or TLB shoot-down may take place only when the current
/// VCPU enters back in guest mode. This means that placing a hook does not guarantee that events will take place
/// immediately. If the caller needs this guarantee, it has to pause the VCPUs, set the hook, and then immediately
/// resume the VCPUs, as on each VCPU resume, all EPT access rights are committed immediately.
/// NOTE: The callback will be called whenever an instruction does the indicated access inside the hooked region;
/// however, it may be called in cases where the instruction does not appear to directly access the area - this may
/// happen when implicit memory accesses are made by the CPU to that area; for example, delivering an interrupt
/// or on exception will trigger writes on the stack, in order to save the interrupt frame; if that area of the
/// stack is write-hooked, the callback will be invoked, even if the current instruction does no memory access at all.
/// NOTE: #IG_EPT_HOOK_READ, #IG_EPT_HOOK_WRITE, #IG_EPT_HOOK_EXECUTE cannot be combined. Only one hook type can be set
/// with one call to this function. If one want to place multiple hook types (for example, both a read and a write
/// hook), this function must be called twice - one for the write hook, and once for the read hook.
///
/// @param[in]  Gpa         Guest physical address to be hooked.
/// @param[in]  Length      The length of the region to be hooked: [Gpa, Gpa + Length - 1].
/// @param[in]  Type        EPT hook type: #IG_EPT_HOOK_READ, #IG_EPT_HOOK_WRITE or #IG_EPT_HOOK_EXECUTE.
/// @param[in]  Callback    Function to be called whenever the indicated access is made inside [Gpa, Gpa + Length - 1].
/// @param[in]  Context     Optional context that will be passed to the Callback function when an access is made.
/// @param[in]  ParentHook  Hooks can be chained, so if an upper-level hook system places a GPA hook, it should use
///                         this argument to indicate the higher level hook structure.
/// @param[in]  Flags       Hook flags. Please see HOOK_FLG_* for more info.
/// @param[out] Hook        A pointer to a hook handle. Upon successful return, this will contain the hook handle
///                         which can be later used to remove the hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If the hooked area spans outside the given page.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation fails.
/// @retval #INT_STATUS_ARITHMETIC_OVERFLOW If too many hooks have been placed on the page.
///
{
    INTSTATUS status;
    HOOK_GPA *pGpaHook;
    HOOK_EPT_ENTRY *eptEntry;
    DWORD hid;
    BOOLEAN setr, setc, sets;

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if ((Gpa & PAGE_MASK) != ((Gpa + Length - 1) & PAGE_MASK))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Length > PAGE_SIZE)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if ((Type != IG_EPT_HOOK_READ) && (Type != IG_EPT_HOOK_WRITE) && (Type != IG_EPT_HOOK_EXECUTE))
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pGpaHook = NULL;
    hid = GPA_HOOK_ID(Gpa);
    Flags &= HOOK_FLG_GLOBAL_MASK;
    setr = setc = sets = FALSE;

    pGpaHook = HpAllocWithTag(sizeof(*pGpaHook), IC_TAG_GPAH);
    if (NULL == pGpaHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pGpaHook->Header.Context = Context;
    pGpaHook->Header.ParentHook = ParentHook;
    pGpaHook->Header.Flags = Flags;
    pGpaHook->Header.HookType = hookTypeGpa;
    pGpaHook->Header.EptHookType = Type;

    pGpaHook->Callback = Callback;
    pGpaHook->GpaPage = Gpa & PAGE_MASK;
    pGpaHook->Length = (WORD)Length;
    pGpaHook->Offset = Gpa & PAGE_OFFSET;

    // Get the EPT entry, in order to update the restrictions.
    eptEntry = IntHookGpaGetEptEntry(Gpa);
    if (NULL == eptEntry)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    // Handle Sub-Page Protection. Note that by default, we won't allocate a SPP entry until a sub-page hook is placed.
    if (gHooks->GpaHooks.SppEnabled && (IG_EPT_HOOK_WRITE == Type))
    {
        if ((Length < PAGE_SIZE_4K) && (NULL == eptEntry->Spp))
        {
            status = IntHookGpaGetSppEntry(eptEntry);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaGetSppEntry failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }
        }

        if (NULL != eptEntry->Spp)
        {
            DWORD i, low, high;

            // The low 128B chunk that is being hooked.
            low = ROUND_DOWN((DWORD)pGpaHook->Offset, 128) >> 7;

            // The high 128B chunk that is being hooked (exclusive).
            high = ROUND_UP((DWORD)(pGpaHook->Offset + pGpaHook->Length), 128) >> 7;

            for (i = low; i < high; i++)
            {
                if (0 == eptEntry->Spp->SppCount[i]++)
                {
                    eptEntry->Spp->CurSpp &= ~(1ULL << (2 * i));
                    sets = TRUE;
                }
            }
        }
    }

    switch (Type)
    {
    case IG_EPT_HOOK_READ:
        if (MAX_HOOK_COUNT == eptEntry->ReadCount)
        {
            CRITICAL("[ERROR] Read hook count exceeds the limit for page 0x%016llx!\n", eptEntry->GpaPage);
            status = INT_STATUS_ARITHMETIC_OVERFLOW;
            goto cleanup_and_exit;
        }

        setr = 0 == eptEntry->ReadCount++;
        break;
    case IG_EPT_HOOK_WRITE:
        if (MAX_HOOK_COUNT == eptEntry->WriteCount)
        {
            CRITICAL("[ERROR] Write hook count exceeds the limit for page 0x%016llx!\n", eptEntry->GpaPage);
            status = INT_STATUS_ARITHMETIC_OVERFLOW;
            goto cleanup_and_exit;
        }

        setr = 0 == eptEntry->WriteCount++;
        break;
    case IG_EPT_HOOK_EXECUTE:
        if (MAX_HOOK_COUNT == eptEntry->ExecuteCount)
        {
            CRITICAL("[ERROR] Execute hook count exceeds the limit for page 0x%016llx!\n", eptEntry->GpaPage);
            status = INT_STATUS_ARITHMETIC_OVERFLOW;
            goto cleanup_and_exit;
        }

        setr = 0 == eptEntry->ExecuteCount++;
        break;
    default:
        break;
    }

    // Paging structure hooks will be convertible - they will be delivered as #VE in the guest.
    if (0 != (Flags & HOOK_PAGE_TABLE_FLAGS))
    {
        if (MAX_HOOK_COUNT == eptEntry->PtCount)
        {
            CRITICAL("[ERROR] Page table hook count exceeds the limit for page 0x%016llx!\n", eptEntry->GpaPage);
            status = INT_STATUS_ARITHMETIC_OVERFLOW;
            goto cleanup_and_exit;
        }

        eptEntry->PtCount++;

        if (gHooks->GpaHooks.VeEnabled)
        {
            if (MAX_HOOK_COUNT == eptEntry->ConvCount)
            {
                CRITICAL("[ERROR] Convertible hook count exceeds the limit for page 0x%016llx!\n", eptEntry->GpaPage);
                status = INT_STATUS_ARITHMETIC_OVERFLOW;
                goto cleanup_and_exit;
            }

            setc = 0 == eptEntry->ConvCount++;
        }
        else if (gHooks->GpaHooks.PtCacheEnabled)
        {
            status = IntPtiCacheRemove(Gpa);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPtsInt3CacheRemove failed for 0x%016llx and this sucks\n", Gpa);
                IntEnterDebugger();
            }

            if (IG_EPT_HOOK_WRITE == Type)
            {
                // Don't make the entry non-writable. Also, don't touch the SPP permissions.
                setr = sets = FALSE;
            }
        }
    }

    // Set the appropriate access rights.
    if (setr)
    {
        status = IntSetEPTPageProtection(gGuest.UntrustedEptIndex,
                                         pGpaHook->GpaPage,
                                         0 == eptEntry->ReadCount,
                                         0 == eptEntry->WriteCount,
                                         0 == eptEntry->ExecuteCount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageProtection failed for GPA 0x%016llx: 0x%08x\n", pGpaHook->GpaPage, status);
            goto cleanup_and_exit;
        }
    }

    if (setc)
    {
        status = IntSetEPTPageConvertible(gGuest.UntrustedEptIndex, pGpaHook->GpaPage, 0 != eptEntry->ConvCount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTConvertible failed for GPA 0x%016llx: 0x%08x\n", pGpaHook->GpaPage, status);
            goto cleanup_and_exit;
        }
    }

    // Modify the SPP entry, if needed.
    if (sets)
    {
        status = IntSetSPPPageProtection(pGpaHook->GpaPage, eptEntry->Spp->CurSpp);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetSPPPageProtection failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    if (0 == gHooks->GpaHooks.HooksCount++)
    {
        status = IntEnableEptNotifications();
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }
    }

    // Insert the hook in the uncommitted hooks list.
    if (IG_EPT_HOOK_READ == Type)
    {
        IntHookGpaInsertHookInList(&gHooks->GpaHooks.GpaHooksRead[hid], pGpaHook);
    }
    else if (IG_EPT_HOOK_WRITE == Type)
    {
        IntHookGpaInsertHookInList(&gHooks->GpaHooks.GpaHooksWrite[hid], pGpaHook);
    }
    else
    {
        IntHookGpaInsertHookInList(&gHooks->GpaHooks.GpaHooksExecute[hid], pGpaHook);
    }

    if (NULL != Hook)
    {
        *Hook = pGpaHook;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pGpaHook)
        {
            HpFreeAndNullWithTag(&pGpaHook, IC_TAG_GPAH);
        }
    }

    return status;
}


static INTSTATUS
IntHookGpaSetNewPageProtection(
    _In_ HOOK_GPA *Hook
    )
///
/// @brief Update EPT protection for a removed hook.
///
/// Given a GPA hook entry that is being removed, this function will update the EPT access rights according to
/// the hook entry.
/// NOTE: This function will trigger a bug-check if a hook with a 0 reference count is being removed.
///
/// @param[in]  Hook    The GPA hook entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation fails.
///
{
    INTSTATUS status;
    HOOK_EPT_ENTRY *eptEntry;
    BOOLEAN setr, setc, sets;

    eptEntry = NULL;
    setr = setc = sets = FALSE;

    eptEntry = IntHookGpaGetEptEntry(Hook->GpaPage);
    if (NULL == eptEntry)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Removing hook - restore the correct access bits.
    switch (Hook->Header.EptHookType)
    {
    case IG_EPT_HOOK_READ:
        BUG_ON(0 == eptEntry->ReadCount);

        setr = 0 == --eptEntry->ReadCount;
        break;
    case IG_EPT_HOOK_WRITE:
        BUG_ON(0 == eptEntry->WriteCount);

        setr = 0 == --eptEntry->WriteCount;
        break;
    case IG_EPT_HOOK_EXECUTE:
        BUG_ON(0 == eptEntry->ExecuteCount);

        setr = 0 == --eptEntry->ExecuteCount;
        break;
    default:
        break;
    }

    if (0 != (Hook->Header.Flags & HOOK_PAGE_TABLE_FLAGS))
    {
        BUG_ON(0 == eptEntry->PtCount);

        eptEntry->PtCount--;

        if (gHooks->GpaHooks.VeEnabled)
        {
            BUG_ON(0 == eptEntry->ConvCount);

            setc = 0 == --eptEntry->ConvCount;
        }
        else if (gHooks->GpaHooks.PtCacheEnabled)
        {
            if (IG_EPT_HOOK_WRITE == Hook->Header.EptHookType)
            {
                // No need to modify EPT, as we left the entry writable.
                setr = sets = FALSE;
            }
        }
    }

    if (gHooks->GpaHooks.SppEnabled && (IG_EPT_HOOK_WRITE == Hook->Header.EptHookType))
    {
        if (NULL != eptEntry->Spp)
        {
            DWORD low, high;

            // The low 128B chunk that is being hooked.
            low = ROUND_DOWN((DWORD)Hook->Offset, 128) >> 7;

            // The high 128B chunk that is being hooked (exclusive).
            high = ROUND_UP((DWORD)(Hook->Offset + Hook->Length), 128) >> 7;

            for (DWORD i = low; i < high; i++)
            {
                if (0 == --eptEntry->Spp->SppCount[i])
                {
                    eptEntry->Spp->CurSpp |= (1ULL << (2 * i));
                    sets = TRUE;
                }
            }
        }
    }

    if (setr)
    {
        // If no hooks are set for a particular EPT permission, it means that the page has that permission.
        const BYTE r = eptEntry->ReadCount == 0;
        const BYTE w = eptEntry->WriteCount == 0;
        const BYTE x = eptEntry->ExecuteCount == 0;

        // Modify the rights.
        status = IntSetEPTPageProtection(gGuest.UntrustedEptIndex,
                                         Hook->GpaPage,
                                         r,
                                         w,
                                         x);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageProtection failed for GPA 0x%016llx: 0x%08x\n", Hook->GpaPage, status);
            return status;
        }
    }

    if (setc)
    {
        // Modify the convertible flag.
        status = IntSetEPTPageConvertible(gGuest.UntrustedEptIndex, Hook->GpaPage, 0 != eptEntry->ConvCount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetEPTPageConvertible failed for GPA 0x%016llx: 0x%08x\n", Hook->GpaPage, status);
            return status;
        }
    }

    if (sets)
    {
        status = IntSetSPPPageProtection(Hook->GpaPage, eptEntry->Spp->CurSpp);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetSPPPageProtection failed for GPA 0x%016llx: 0x%08x\n", Hook->GpaPage, status);
            return status;
        }
    }

    if ((0 == eptEntry->WriteCount) && (NULL != eptEntry->Spp))
    {
        // The last write hook was removed, we can free the SPP entry as well.
        HpFreeAndNullWithTag(&eptEntry->Spp, IC_TAG_SPPE);
    }

    if (0 == GPA_REF_COUNT(eptEntry))
    {
        // All hooks were removed, there's no point in keeping this entry anymore
        RemoveEntryList(&eptEntry->Link);
        HpFreeAndNullWithTag(&eptEntry, IC_TAG_EPTE);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookGpaRemoveHookInternal(
    _In_ HOOK_GPA *Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a GPA hook.
///
/// This function will only flag the current hook for removal. No other action will be taken. The hook
/// will then be removed during the commit phase. Once this function is called, the hook callback will
/// not be called anymore.
///
/// @param[in]  Hook    The GPA hook to be removed.
/// @param[in]  Flags   Flags. If #HOOK_FLG_CHAIN_DELETE is set, the function will just mark the hook as being
///                     removed; the actual deletion will be done by calling the #IntHookGpaDeleteHook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the hook has already been marked for removal.
///
{
    if (0 != (Hook->Header.Flags & HOOK_FLG_REMOVE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Hook->Header.Flags |= HOOK_FLG_DISABLED | HOOK_FLG_REMOVE;

    if (Flags & HOOK_FLG_CHAIN_DELETE)
    {
        Hook->Header.Flags |= HOOK_FLG_CHAIN_DELETE;

        // No point inserting it into the removed queue, since it will ignore chain deleted hooks
        gHooks->Dirty = TRUE;

        return INT_STATUS_SUCCESS;
    }

    if (IG_EPT_HOOK_READ == Hook->Header.EptHookType)
    {
        QueueInsert(&gHooks->GpaHooks.RemovedHooksRead, &Hook->LinkRemoved);
    }
    else if (IG_EPT_HOOK_WRITE == Hook->Header.EptHookType)
    {
        QueueInsert(&gHooks->GpaHooks.RemovedHooksWrite, &Hook->LinkRemoved);
    }
    else if (IG_EPT_HOOK_EXECUTE == Hook->Header.EptHookType)
    {
        QueueInsert(&gHooks->GpaHooks.RemovedHooksExecute, &Hook->LinkRemoved);
    }
    else
    {
        ERROR("[ERROR] Invalid hook type %d for hook %p\n", Hook->Header.EptHookType, Hook);
        IntDbgEnterDebugger();
    }

    gHooks->GpaHooks.HooksRemoved = TRUE;

    gHooks->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGpaRemoveHook(
    _Inout_ HOOK_GPA **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Remove a GPA hook.
///
/// This function will only flag the current hook for removal. No other action will be taken. The hook
/// will then be removed during the commit phase. Once this function is called, the hook callback will
/// not be called anymore.
///
/// @param[in, out]     Hook    The GPA hook to be removed.
/// @param[in]          Flags   Flags. If #HOOK_FLG_CHAIN_DELETE is set, the function will just mark the hook as being
///                             removed; the actual deletion will be done by calling the #IntHookGpaDeleteHook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the hook has already been marked for removal.
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

    status = IntHookGpaRemoveHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaRemoveHookInternal failed: 0x%08x\n", status);
    }

    if (!(Flags & HOOK_FLG_CHAIN_DELETE))
    {
        *Hook = NULL;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookGpaDeleteHookInternal(
    _In_ HOOK_GPA *Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently delete a GPA hook.
///
/// @param[in, out] Hook    The hook to be deleted.
/// @param[in]      Flags   Flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Flags);

    // Restore old access rights on the page.
    status = IntHookGpaSetNewPageProtection(Hook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaSetNewPageProtection failed: 0x%08x\n", status);
    }

    if (0 >= --gHooks->GpaHooks.HooksCount)
    {
        status = IntDisableEptNotifications();
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    RemoveEntryList(&Hook->Link);

    HpFreeAndNullWithTag(&Hook, IC_TAG_GPAH);

    return status;
}


INTSTATUS
IntHookGpaDeleteHook(
    _In_ HOOK_GPA **Hook,
    _In_ DWORD Flags
    )
///
/// @brief Permanently delete a GPA hook.
///
/// This function will permanently delete the hook, restoring the original EPT access rights. This function
/// must be called only if IntHookGpaRemoveHook with the #HOOK_FLG_CHAIN_DELETE has been called before.
///
/// @param[in, out] Hook    The hook to be deleted.
/// @param[in]      Flags   Flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
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

    status = IntHookGpaDeleteHookInternal(*Hook, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaDeleteHookInternal failed: 0x%08x\n", status);
    }

    *Hook = NULL;

    return status;
}


INTSTATUS
IntHookGpaCommitHooks(
    void
    )
///
/// @brief Commit existing modified hooks.
///
/// This function will iterate the list of removed hooks, and it will actually delete them. Hooks which are
/// flagged with #HOOK_FLG_CHAIN_DELETE will not be deleted, as it is expected that someone else will delete
/// them (this happens when a higher-level hook system wants to delete an entire chain of hooks).
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    // The order in which we remove hooks must be the following:
    // 1. Read hooks
    // 2. Write hooks
    // 3. Execute hooks
    // If we'd commit read hooks first, we may end up with inconsistent EPT rights -> Write & Execute,
    // which may trigger EPT misconfiguration.
    QUEUE_HEAD *hooksQueues[] =
    {
        &gHooks->GpaHooks.RemovedHooksRead,
        &gHooks->GpaHooks.RemovedHooksWrite,
        &gHooks->GpaHooks.RemovedHooksExecute
    };

    INTSTATUS status;

    if (!gHooks->GpaHooks.HooksRemoved)
    {
        return INT_STATUS_SUCCESS;
    }

    // Iterate the list of removed hooks and actually delete the designated hooks.
    for (DWORD i = 0; i < ARRAYSIZE(hooksQueues); i++)
    {
        QUEUE_HEAD *hooksQueue = hooksQueues[i];
        QUEUE_ENTRY *queue;

        while ((queue = QueueRemove(hooksQueue)) != hooksQueue)
        {
            PHOOK_GPA pGpaHook = CONTAINING_RECORD(queue, HOOK_GPA, LinkRemoved);

            if (0 != (pGpaHook->Header.Flags & HOOK_FLG_CHAIN_DELETE))
            {
                // Chain delete requested - we won't commit this hook, we'll let it's parent decide its faith.
                ERROR("[ERROR] Invalid hook state: %x (chain delete) for hook at GPA 0x%016llx\n",
                      pGpaHook->Header.Flags, pGpaHook->GpaPage);
                continue;
            }

            if (0 == (pGpaHook->Header.Flags & HOOK_FLG_REMOVE))
            {
                ERROR("[ERROR] Invalid hook state: %x for hook at GPA 0x%016llx\n",
                      pGpaHook->Header.Flags,
                      pGpaHook->GpaPage);

                IntEnterDebugger();
            }

            status = IntHookGpaDeleteHookInternal(pGpaHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaDeleteHookInternal failed: 0x%08x\n", status);
            }
        }
    }

    gHooks->GpaHooks.HooksRemoved = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGpaDisableHook(
    _In_ HOOK_GPA *Hook
    )
///
/// @brief Disable a GPA hook.
///
/// Disables the indicated hook. The hook will not be removed, but the callback will not be called anymore.
///
/// @param[in]  Hook    The hook to be disabled.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Hook->Header.Flags |= HOOK_FLG_DISABLED;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGpaEnableHook(
    _In_ HOOK_GPA *Hook
    )
///
/// @brief Enable a GPA hook.
///
/// Enables a hook. Once a hook is enabled, the callback will be called again for accesses inside the hooked
/// region.
/// NOTE: When setting a GPA hook, it is enabled by default. This function must be called only if one wishes
/// to re-enable a hook previously disabled using #IntHookGpaDisableHook.
///
/// @param[in]  Hook    The GPA hook to be enabled.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Hook->Header.Flags &= ~HOOK_FLG_DISABLED;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGpaIsPageHooked(
    _In_ QWORD Gpa,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    )
///
/// @brief Get the read, write and execute access for the given guest physical page.
///
/// @param[in]  Gpa     The guest physical page for which read, write & execute access is queried.
/// @param[out] Read    Will contain, upon successful return, 1 if the page is readable, 0 if it is read-hooked.
/// @param[out] Write   Will contain, upon successful return, 1 if the page is writable, 0 if it is write-hooked.
/// @param[out] Execute Will contain, upon successful return, 1 if the page is executable, 0 if it is execute-hooked.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    LIST_ENTRY *list;
    DWORD i, hid;

    LIST_HEAD *hooksLists[] =
    {
        gHooks->GpaHooks.GpaHooksWrite,
        gHooks->GpaHooks.GpaHooksRead,
        gHooks->GpaHooks.GpaHooksExecute
    };

    if (NULL == Read)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Write)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Execute)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    hid = GPA_HOOK_ID(Gpa);

    // Assume full rights.
    *Read = *Write = *Execute = 1;

    for (i = 0; i < ARRAYSIZE(hooksLists); i++)
    {
        LIST_HEAD *hooksList = &hooksLists[i][hid];

        list = hooksList->Flink;

        while (list != hooksList)
        {
            PHOOK_GPA p = CONTAINING_RECORD(list, HOOK_GPA, Link);
            list = list->Flink;

            // Skip/ignore removed hooks.
            if (0 != (p->Header.Flags & (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE)))
            {
                continue;
            }

            if ((Gpa & PAGE_MASK) == p->GpaPage)
            {
                switch (i)
                {
                case 0:
                    *Write = 0;
                    break;
                case 1:
                    *Read = 0;
                    break;
                case 2:
                    *Execute = 0;
                default:
                    break;
                }

                break;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGpaInit(
    void
    )
///
/// @brief Initialize the GPA hook system. This function should be called only once, during introspection init.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    for (DWORD i = 0; i < GPA_HOOK_TABLE_SIZE; i++)
    {
        InitializeListHead(&gHooks->GpaHooks.GpaHooksExecute[i]);
        InitializeListHead(&gHooks->GpaHooks.GpaHooksRead[i]);
        InitializeListHead(&gHooks->GpaHooks.GpaHooksWrite[i]);
    }

    QueueInitialize(&gHooks->GpaHooks.RemovedHooksRead);
    QueueInitialize(&gHooks->GpaHooks.RemovedHooksWrite);
    QueueInitialize(&gHooks->GpaHooks.RemovedHooksExecute);

    for (DWORD i = 0; i < GPA_EPT_TABLE_SIZE; i++)
    {
        InitializeListHead(&gHooks->GpaHooks.EptEntries[i]);
    }

    // Get the untrusted EPT index.
    status = IntGetCurrentEptIndex(IG_CURRENT_VCPU, &gGuest.UntrustedEptIndex);
    if (!INT_SUCCESS(status))
    {
#ifdef USER_MODE
        gGuest.UntrustedEptIndex = 1;
#else
        gGuest.UntrustedEptIndex = 0;
#endif // INT_COMPILER_MSVC

        ERROR("[ERROR] IntGetCurrentEptIndex failed: 0x%08x. Will assume untrusted EPT index %d.\n",
              status, gGuest.UntrustedEptIndex);
    }

    // By default, assume the protected EPT index is an invalid one.
    gGuest.ProtectedEptIndex = INVALID_EPTP_INDEX;

    gHooks->GpaHooks.SppEnabled = FALSE;

    // Check SPP support. We use the SPP feature if two conditions are met:
    // 1. The Get/Set SPP protection APIs are initialized inside the interface;
    // 2. The SPP feature is present & enabled for this guest.
    if (GlueIsSppApiAvailable())
    {
        gHooks->GpaHooks.SppEnabled = gGuest.SupportSPP;
    }

    return INT_STATUS_SUCCESS;
}


void
IntHookGpaDump(
    void
    )
///
/// @brief Dump the entire contents of the GPA hook system, listing each hook.
///
{
    DWORD i, j, count, count2;
    LIST_ENTRY *list, *table;
    BYTE r, w, x;
    const char *msg[3] = { "read", "write", "execute" };

    if (NULL == gHooks)
    {
        return;
    }

    for (j = 0; j < 3; j++)
    {
        NLOG("GPA %s hooks:\n", msg[j]);

        if (0 == j)
        {
            table = gHooks->GpaHooks.GpaHooksRead;
        }
        else if (1 == j)
        {
            table = gHooks->GpaHooks.GpaHooksWrite;
        }
        else
        {
            table = gHooks->GpaHooks.GpaHooksExecute;
        }

        count = 0;

        for (i = 0; i < GPA_HOOK_TABLE_SIZE; i++)
        {
            list = table[i].Flink;

            count2 = 0;

            while (list != &table[i])
            {
                PHOOK_GPA pHook = CONTAINING_RECORD(list, HOOK_GPA, Link);

                IntGetEPTPageProtection(gGuest.UntrustedEptIndex, pHook->GpaPage, &r, &w, &x);

                NLOG("%04d: %p GPA: 0x%016llx, Offset: %04x, Length: %04x, Type: %d, Flags: %08x, Parent: %p,"
                     "Callback: %p, Context: %p, EPT: %c%c%c\n", count++,
                     pHook, pHook->GpaPage, pHook->Offset, pHook->Length, pHook->Header.EptHookType,
                     pHook->Header.Flags, pHook->Header.ParentHook, pHook->Callback, pHook->Header.Context,
                     r ? 'R' : '-', w ? 'W' : '-', x ? 'X' : '-');

                list = list->Flink;

                count2++;
            }

            NLOG("===> Load of list %04d: %d\n", i, count2);
        }
    }

    count = 0;

    for (i = 0; i < 3; i++)
    {
        QUEUE_HEAD *hooksQueue;
        QUEUE_ENTRY *queue;

        if (0 == i)
        {
            hooksQueue = &gHooks->GpaHooks.RemovedHooksRead;
        }
        else if (1 == i)
        {
            hooksQueue = &gHooks->GpaHooks.RemovedHooksWrite;
        }
        else
        {
            hooksQueue = &gHooks->GpaHooks.RemovedHooksExecute;
        }

        queue = hooksQueue->Next;

        NLOG("Removed hooks list for '%s':\n", 0 == i ? "read" : 1 == i ? "write" : "execute");

        while (queue != hooksQueue)
        {
            PHOOK_GPA pHook = CONTAINING_RECORD(queue, HOOK_GPA, LinkRemoved);

            NLOG("%04d: %p GPA: 0x%016llx, Offset: %04x, Length: %04x, Flags: %08x, Parent: %p,"
                 "Callback: %p, Context: %p\n", count++,
                 pHook, pHook->GpaPage, pHook->Offset, pHook->Length, pHook->Header.Flags,
                 pHook->Header.ParentHook, pHook->Callback, pHook->Header.Context);

            queue = queue->Next;
        }
    }
}


static INTSTATUS
IntHookGpaEnableDisableVe(
    _In_ BOOLEAN Enable
    )
///
/// @brief Enable or disable the VE filtering mechanism.
///
/// When enabling VE filtering, the function will mark all page-tables as being convertible inside the EPT.
/// When disabling VE filtering, it will remove the convertible flag from all page-table pages.
///
/// @param[in]  Enable  True if the VE filtering is to be enabled, false otherwise.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If Enable is true and VE filtering is already enabled, or if Enable is false
///                                     and VE filtering is already disabled.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (gHooks->GpaHooks.VeEnabled && Enable)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (!(gHooks->GpaHooks.VeEnabled || Enable))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Iterate all the pages and mark the PT hooks as convertible.
    for (DWORD i = 0; i < GPA_EPT_TABLE_SIZE; i++)
    {
        LIST_ENTRY *list = gHooks->GpaHooks.EptEntries[i].Flink;
        while (list != &gHooks->GpaHooks.EptEntries[i])
        {
            HOOK_EPT_ENTRY *p = CONTAINING_RECORD(list, HOOK_EPT_ENTRY, Link);

            list = list->Flink;

            if (0 != p->PtCount)
            {
                BOOLEAN setc = FALSE;
                const QWORD gpa = p->GpaPage;
                TRACE("[HOOK] Marking GPA %llx as being %s (%c%c%c)\n", gpa, Enable ? "conv" : "non-conv",
                      !p->ReadCount ? 'R' : '-', !p->WriteCount ? 'W' : '-', !p->ExecuteCount ? 'X' : '-');

                if (Enable)
                {
                    if (MAX_HOOK_COUNT < (QWORD)p->ConvCount + (QWORD)p->PtCount)
                    {
                        CRITICAL("[ERROR] Convertible hook count exceeds the limit for page 0x%016llx!\n", p->GpaPage);
                        return INT_STATUS_ARITHMETIC_OVERFLOW;
                    }

                    setc = 0 == p->ConvCount;

                    p->ConvCount += p->PtCount;
                }
                else
                {
                    BUG_ON(p->ConvCount < p->PtCount);

                    p->ConvCount -= p->PtCount;

                    setc = 0 == p->ConvCount;
                }

                if (setc)
                {
                    status = IntSetEPTPageConvertible(gGuest.UntrustedEptIndex, gpa, Enable);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntSetEPTPageConvertible failed: 0x%08x\n", status);
                    }
                }
            }
        }
    }

    gHooks->GpaHooks.VeEnabled = Enable;

    return status;
}


static INTSTATUS
IntHookGpaEnableDisablePtCache(
    _In_ BOOLEAN Enable
    )
///
/// @brief Enable or disable the in guest PT filtering mechanism.
///
/// When enabling PT filtering, the function will mark all page-tables as being writable inside the EPT.
/// When disabling PT filtering, it will mark all page-table pages non-writable inside EPT.
///
/// @param[in]  Enable  True if the PT filtering is to be enabled, false otherwise.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If Enable is true and PT filtering is already enabled, or if Enable is false
///                                     and PT filtering is already disabled.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (gHooks->GpaHooks.PtCacheEnabled && Enable)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if (!(gHooks->GpaHooks.PtCacheEnabled || Enable))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Iterate all the pages and mark the PT hooks as convertible.
    for (DWORD i = 0; i < GPA_EPT_TABLE_SIZE; i++)
    {
        LIST_ENTRY *list = gHooks->GpaHooks.EptEntries[i].Flink;
        while (list != &gHooks->GpaHooks.EptEntries[i])
        {
            HOOK_EPT_ENTRY *p = CONTAINING_RECORD(list, HOOK_EPT_ENTRY, Link);

            list = list->Flink;

            if (0 != p->PtCount)
            {
                const QWORD gpa = p->GpaPage;
                TRACE("[HOOK] Marking GPA %llx as being %s (%c%c%c)\n", gpa, Enable ? "PT filtered" : "EPT hooked",
                      !p->ReadCount ? 'R' : '-', Enable ? 'W' : '-', !p->ExecuteCount ? 'X' : '-');

                status = IntSetEPTPageProtection(gGuest.UntrustedEptIndex,
                                                 gpa, 0 == p->ReadCount, !!Enable, 0 == p->ExecuteCount);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSetEPTPageProtection failed: 0x%08x\n", status);
                }
            }
        }
    }

    // Safe to be here, since we don't return if IntSetEPTPageProtection returns errors.
    gHooks->GpaHooks.PtCacheEnabled = Enable;

    return status;
}


INTSTATUS
IntHookGpaEnableVe(
    void
    )
///
/// @brief Enable VE filtering.
///
{
    return IntHookGpaEnableDisableVe(TRUE);
}


INTSTATUS
IntHookGpaEnablePtCache(
    void
    )
///
/// @brief Enable PT filtering.
///
{
    return IntHookGpaEnableDisablePtCache(TRUE);
}


INTSTATUS
IntHookGpaDisableVe(
    void
    )
///
/// @brief Disable VE filtering.
///
{
    return IntHookGpaEnableDisableVe(FALSE);
}


INTSTATUS
IntHookGpaDisablePtCache(
    void
    )
///
/// @brief Disable PT filtering.
///
{
    return IntHookGpaEnableDisablePtCache(FALSE);
}


INTSTATUS
IntHookGpaGetEPTPageProtection(
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    )
///
/// @brief Get the EPT page protection for the indicated guest physical address.
///
/// @param[in]  EptIndex    The EPT for which the rights are taken. Must be the UntrustedEptIndex.
/// @param[in]  Address     Guest physical address whose access rights are queried.
/// @param[out] Read        Will be 1 if the page is readable, 0 otherwise.
/// @param[out] Write       Will be 1 if the page is writable, 0 otherwise.
/// @param[out] Execute     Will be 1 if the page is executable, 0 otherwise.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    const HOOK_EPT_ENTRY *pEpt;

    if (EptIndex != gGuest.UntrustedEptIndex)
    {
        ERROR("[ERROR] Only the Untrusted EPT is supported!\n");
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pEpt = IntHookGpaGetExistingEptEntry(Address & PAGE_MASK);
    if (NULL != pEpt)
    {
        *Read = 0 == pEpt->ReadCount;
        *Write = 0 == pEpt->WriteCount;
        *Execute = 0 == pEpt->ExecuteCount;
    }
    else
    {
        *Read = *Write = *Execute = 1;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookGpaFindConvertible(
    void
    )
///
/// @brief Displays all convertible pages.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    // Iterate all the pages and mark the PT hooks as convertible.
    for (DWORD i = 0; i < GPA_EPT_TABLE_SIZE; i++)
    {
        LIST_ENTRY *list = gHooks->GpaHooks.EptEntries[i].Flink;
        while (list != &gHooks->GpaHooks.EptEntries[i])
        {
            BOOLEAN c;
            PHOOK_EPT_ENTRY p = CONTAINING_RECORD(list, HOOK_EPT_ENTRY, Link);

            list = list->Flink;

            IntGetEPTPageConvertible(gGuest.UntrustedEptIndex, p->GpaPage, &c);
            if (c)
            {
                LOG("!!!! Page 0x%016llx is convertible!\n", p->GpaPage);
            }
            else if (p->PtCount)
            {
                LOG("**** Page 0x%016llx is page table, but it is NOT convertible!\n", p->GpaPage);
            }
        }
    }

    return status;
}
#ifdef INT_COMPILER_MSVC
#pragma warning(pop)
#endif // INT_COMPILER_MSVC
