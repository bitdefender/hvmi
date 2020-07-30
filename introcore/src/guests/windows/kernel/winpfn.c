/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winpfn.h"
#include "hook.h"


/// @brief  The list of locked PFNs.
static LIST_HEAD gWinPfns = LIST_HEAD_INIT(gWinPfns);

/// @brief  Iterates the linked list in #gWinPfns.
///
/// Can be used to safely iterate the PFN list. The current PFN pointed to by _var_name can safely be removed
/// from the list, but note that removing other detours while iterating the list using this macro is not a valid
/// operation and can corrupt the list.
///
/// @param[in]  _var_name   The name of the variable in which the #WIN_PFN_LOCK pointer will be placed. This variable
///                         will be declared by the macro an available only in the context created by the macro.
#define for_each_pfn_lock(_var_name) list_for_each (gWinPfns, WIN_PFN_LOCK, _var_name)


INTSTATUS
IntWinPfnIsMmPfnDatabase(
    _In_ QWORD MmPfnDatabase
    )
///
/// @brief      Checks if a a guest virtual address points to MmPfnDatabase.
///
/// @param[in]  MmPfnDatabase   Guest virtual address to check.
///
/// @retval     #INT_STATUS_SUCCESS if the provided address is indeed the MmPfnDataBase.
/// @retval     #INT_STATUS_INVALID_OBJECT_TYPE if it is not.
///
{
    INTSTATUS status;
    VA_TRANSLATION pfnTranslation = {0};
    VA_TRANSLATION kernTrans = {0};
    QWORD pteAddress, pfnAddress;
    BYTE pPfn[0x60]; // there is no way the _MM_PFN will be bigger than this, ever!
    DWORD pfnSize;

    if (MmPfnDatabase % (2 * ONE_MEGABYTE) != 0)
    {
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    if (gGuest.Guest64)
    {
        status = IntTranslateVirtualAddressEx(gGuest.KernelVa, gGuest.Mm.SystemCr3, TRFLG_NONE, &kernTrans);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddressEx: 0x%08x\n", status);
            return status;
        }

        pfnAddress = WIN_PFN_GET_STRUCT_VA(MmPfnDatabase, kernTrans.PhysicalAddress);
        pfnAddress += WIN_KM_FIELD(Mmpfn, Pte);

        // Read the pfn entry corresponding to  the kernel and analyze it
        status = IntKernVirtMemFetchQword(pfnAddress, &pteAddress);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        status = IntTranslateVirtualAddressEx(pteAddress, gGuest.Mm.SystemCr3, TRFLG_NONE, &pfnTranslation);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        for (DWORD l = 0; l < kernTrans.MappingsCount - 1; l++)
        {
            // The translations must be the same (the second to the first, third to second, etc)
            if (pfnTranslation.MappingsTrace[l + 1] != kernTrans.MappingsTrace[l])
            {
                return INT_STATUS_INVALID_OBJECT_TYPE;
            }
        }

        pfnSize = WIN_KM_FIELD(Mmpfn, Size);
        if (pfnSize > sizeof(pPfn))
        {
            ERROR("[ERROR] The PFN size is too large: %d bytes!", pfnSize);
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }

        // The read is OK, we make sure that pfnSize <= sizeof(pPfn).
        status = IntKernVirtMemRead(MmPfnDatabase, pfnSize, pPfn, NULL);
        if (!INT_SUCCESS(status))
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = INT_STATUS_SUCCESS;
    }
    else
    {
        // Check the pfn of the first 100 pages in the
        // .text section. This works because we have the guarantee that the
        // section is not paged and present at this point.
        QWORD kVa = gGuest.KernelVa;

        if (gGuest.PaeEnabled)
        {
            pfnSize = WIN_KM_FIELD(Mmpfn, PaeSize);
        }
        else
        {
            pfnSize = WIN_KM_FIELD(Mmpfn, Size);
        }
        if (pfnSize > sizeof(pPfn))
        {
            ERROR("[ERROR] The PFN size is too large: %d bytes!", pfnSize);
            return INT_STATUS_INVALID_INTERNAL_STATE;
        }

        for (DWORD page = 0; page < 100; page++)
        {
            VA_TRANSLATION translation = {0};
            WORD refCount, pageLocation;

            status = IntTranslateVirtualAddressEx(kVa, gGuest.Mm.SystemCr3, TRFLG_NONE, &translation);
            if (!INT_SUCCESS(status) || (translation.Flags & PT_P) == 0)
            {
                ERROR("[ERROR] IntTranslateVirtualAddressEx failed for 0x%016llx (kernel at 0x%016llx): 0x%08x\n",
                      kVa, gGuest.KernelVa, status);
                return status;
            }

            pfnAddress = WIN_PFN_GET_STRUCT_VA(MmPfnDatabase, translation.PhysicalAddress);

            // XEN stuff: we can't map two pages, so read the memory
            // The read is OK, we make sure that pfnSize <= sizeof(pPfn).
            status = IntKernVirtMemRead(pfnAddress, pfnSize, pPfn, NULL);
            if (!INT_SUCCESS(status))
            {
                return status;
            }

            if (gGuest.PaeEnabled)
            {
                pteAddress = *(DWORD *)(pPfn + WIN_KM_FIELD(Mmpfn, PaePte));
                refCount = *(WORD *)(pPfn + WIN_KM_FIELD(Mmpfn, PaeRefCount));
                pageLocation = *(WORD *)(pPfn + WIN_KM_FIELD(Mmpfn, PaeFlags)) & 7;
            }
            else
            {
                pteAddress = *(DWORD *)(pPfn + WIN_KM_FIELD(Mmpfn, Pte));
                refCount = *(WORD *)(pPfn + WIN_KM_FIELD(Mmpfn, RefCount));
                pageLocation = *(WORD *)(pPfn + WIN_KM_FIELD(Mmpfn, Flags)) & 7;
            }

            if (!IS_KERNEL_POINTER_WIN(FALSE, pteAddress) ||
                pteAddress == 0xffffffff ||
                pteAddress < gGuest.KernelVa)
            {
                return INT_STATUS_INVALID_OBJECT_TYPE;
            }

            if (refCount > 0xff || refCount == 0 ||
                (pageLocation != WinPfnActivePage &&
                 pageLocation != WinPfnModifiedPage))
            {
                return INT_STATUS_INVALID_OBJECT_TYPE;
            }

            kVa += PAGE_SIZE;
        }

        // The read is OK, we make sure that pfnSize <= sizeof(pPfn).
        status = IntKernVirtMemRead(MmPfnDatabase, pfnSize, pPfn, NULL);
        if (!INT_SUCCESS(status))
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // NULL page pfn should be NULL
        for (DWORD j = 8; j < pfnSize; j++)
        {
            if (pPfn[j] != 0)
            {
                ERROR("[ERROR] NULL page pfn 0x%016llx should be NULL!\n", MmPfnDatabase);
                return INT_STATUS_INVALID_OBJECT_TYPE;
            }
        }

        status = INT_STATUS_SUCCESS;
    }

    return status;
}


static INTSTATUS
IntWinPfnModifyRefCount(
    _In_ QWORD PhysicalAddress,
    _In_ BOOLEAN Increment
    )
///
/// @brief      Modifies the in-guest reference count of a physical page.
///
/// The counter is incremented or decremented with #WIN_PFN_INC_VALUE.
///
/// When incrementing the counter, if the page is not in the #WinPfnModifiedPage, #WinPfnActivePage,
/// #WinPfnModifiedNowritePage, or #WinPfnStandbyPage states the operation is refused.
///
/// We do not increment the counter if it the new value would be larger than #WIN_PFN_REF_MAX.
///
/// When decrementing the counter, we do nothing if the value is already less than #WIN_PFN_INC_VALUE. 
///
/// @param[in]  PhysicalAddress Physical address for which to modify the reference counter.
/// @param[in]  Increment       True to increment the counter, False to decrement it.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the change is not needed.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the page is not in a state that supports the reference counter change.
/// @retval     #INT_STATUS_NOT_INITIALIZED if the PFN entry for this page is not initialized.
///
{
    BYTE *pPfnMap;
    QWORD pfnGva = 0;
    WORD pageLocation, initialFlags, initialRefCount;
    DWORD refCount;
    INTSTATUS status;
    BOOLEAN save = FALSE;

    // Get the address of PFN entry for the given physical address
    pfnGva = WIN_PFN_GET_STRUCT_VA(gWinGuest->MmPfnDatabase, PhysicalAddress);

    if (gGuest.Guest64 || !gGuest.PaeEnabled)
    {
        pfnGva += WIN_KM_FIELD(Mmpfn, RefCount);
    }
    else
    {
        pfnGva += WIN_KM_FIELD(Mmpfn, PaeRefCount);
    }

    pfnGva = FIX_GUEST_POINTER(gGuest.Guest64, pfnGva);

    status = IntVirtMemMap(pfnGva, 4, gGuest.Mm.SystemCr3, 0, &pPfnMap);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to get _MMPFN.u3 from address 0x%016llx for GPA 0x%016llx: 0x%08x\n",
              pfnGva, PhysicalAddress, status);
        return status;
    }

    pageLocation = ((0xFFFF0000 & *(DWORD *)pPfnMap) >> 16) & 7; // the first 3 bits represents the page location
    initialFlags = (0xffff0000 & *(DWORD *)pPfnMap) >> 16;
    initialRefCount = 0x0000ffff & *(DWORD *)pPfnMap;
    refCount = initialRefCount;

    if (Increment)
    {
        // Make sure the page is good (when coming from hibernate/standby pages can be in modified state)
        if (pageLocation != WinPfnModifiedPage &&
            pageLocation != WinPfnActivePage &&
            pageLocation != WinPfnModifiedNowritePage &&
            pageLocation != WinPfnStandbyPage)
        {
            WARNING("[WARNING] Cannot lock a page that isn't active. u3=0x%08x, pageLocation=%d\n",
                    *(DWORD *)pPfnMap, pageLocation);
            status = INT_STATUS_NOT_SUPPORTED;
            goto leave;
        }

        // Sometimes, even if the page is present and the driver that uses it loaded, the page has
        // the reference count 0, so mark this page uninitialized and will be locked after the windows initializes it
        if (refCount == 0)
        {
            ERROR("[ERROR] The page is not initialized!\n");
            status = INT_STATUS_NOT_INITIALIZED;
            goto leave;
        }

        if (refCount + WIN_PFN_INC_VALUE > WIN_PFN_REF_MAX)
        {
            CRITICAL("[ERROR] Reference counter is higher than expected: 0x%08x\n", refCount);
            goto leave;
        }

        save = TRUE;
        refCount += WIN_PFN_INC_VALUE;
    }
    else // Decrement the reference count
    {
        if (refCount < WIN_PFN_INC_VALUE)
        {
            ERROR("[ERROR] Ref counter underflow! rc = 0x%08x\n", refCount);
            status = INT_STATUS_NOT_NEEDED_HINT;
            goto leave;
        }

        refCount -= WIN_PFN_INC_VALUE;
        save = TRUE;
    }

    if (!save)
    {
        goto leave;
    }

    // Write the modifications back, but only the ref count. If the page was change from Active to Modified since
    // the mapping, leave it as it is, since who may know what can happen
    refCount = (WORD)_InterlockedCompareExchange16((INT16 *)pPfnMap, (INT16)refCount, (INT16)initialRefCount);
    if (initialRefCount != refCount)
    {
        ERROR("[ERROR] The ref count was change since we started locking it "
              "until now... Initial: 0x%04x, Now: 0x%04x\n", initialRefCount, *(WORD *)pPfnMap);

        // if somehow the page was released in the meantime, return with error...
        if (refCount == 0)
        {
            ERROR("[ERROR] The page was released in the meantime! rc = 0x%08x\n", refCount);
            status = INT_STATUS_NOT_SUPPORTED;
        }
    }

    // Just a check so we know if there are race conditions (maybe some other processor starts unloading this page
    // and the flags for RemovalRequested/InPageError are set)... If we ever see this, we will treat it.
    if (initialFlags != (WORD)_InterlockedCompareExchange16((INT16 *)(pPfnMap + 2), (INT16)initialFlags,
                                                            (INT16)initialFlags))
    {
        ERROR("[ERROR] Initial flags changed: Initial: 0x%04x, Now: 0x%04x\n", initialFlags, *(WORD *)(pPfnMap + 2));
    }

leave:
    IntVirtMemUnmap(&pPfnMap);

    return status;
}


static PWIN_PFN_LOCK
IntWinPfnFindByGpa(
    _In_ QWORD GpaPage
    )
///
/// @brief      Finds a PFN lock by a guest physical address.
///
/// @param[in]  GpaPage The page to search by.
///
/// @returns    A pointer to the lock for the given page; NULL if no lock exists.
///
{
    GpaPage &= PHYS_PAGE_MASK;

    for_each_pfn_lock(pLock)
    {
        if (GpaPage == pLock->GpaPage)
        {
            return pLock;
        }
    }

    return NULL;
}


static PWIN_PFN_LOCK
IntWinPfnFindByGva(
    _In_ QWORD GvaPage
    )
///
/// @brief      Finds a PFN lock by a guest virtual address.
///
/// @param[in]  GvaPage The page to search by.
///
/// @returns    A pointer to the lock for the given page; NULL if no lock exists.
///
{
    GvaPage &= PAGE_MASK;

    for_each_pfn_lock(pLock)
    {
        if (GvaPage == pLock->Page)
        {
            return pLock;
        }
    }

    return NULL;
}


static INTSTATUS
IntWinPfnMoveLock(
    _Inout_ WIN_PFN_LOCK *PfnLock,
    _In_ QWORD NewGpa
    )
///
/// @brief          Moves a lock set for a guest virtual address when the page to which it translates to changes.
///
/// Since locks on virtual pages are in fact locks on the physical pages to which they translate to, when the
/// translation changes we need to move the lock to the new page. This means that we must unlock the old page and
/// lock the new one.
///
/// If the old physical address of the lock is 0 it means that the page is swapped in and we only have to set the
/// lock on the new page.
///
/// If the new physical address is 0 it means that the page is swapped out and we only have to remove the lock
/// from the old page.
///
/// @param[in, out] PfnLock The lock that must be moved.
/// @param[in]      NewGpa  The new guest physical address that will receive the lock.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    // Decrement the reference count of the old page
    if (0 != PfnLock->GpaPage)
    {
        status = IntWinPfnModifyRefCount(PfnLock->GpaPage, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnModifyRefCount failed for GVA %llx GPA %llx: 0x%08x\n",
                  PfnLock->Page, PfnLock->GpaPage, status);
        }
    }

    PfnLock->GpaPage = NewGpa & PAGE_MASK;

    if (0 != PfnLock->GpaPage)
    {
        // Increment the reference count of the new page
        status = IntWinPfnModifyRefCount(PfnLock->GpaPage, TRUE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnModifyRefCount failed for 0x%016llx 0x%016llx: 0x%08x\n",
                  PfnLock->Page, PfnLock->GpaPage, status);

            PfnLock->GpaPage = 0;
        }
    }

    return status;
}


static INTSTATUS
IntWinPfnUnlockAddress(
    _In_ QWORD Address,
    _In_ BOOLEAN IsPhysical
    )
///
/// @brief      Unlocks a guest page.
///
/// Every #IntWinPfnLockAddress call for an address must match a call to this function. If the Introcore reference
/// counter reaches 0, it means that we also have to remove the lock from the guest, but only if it is a physical, not
/// large, page.
/// Also, any resources held by the lock are freed: the swap hook (if it exists) and the lock itself. It will
/// also be removed from the #gWinPfns list.
///
/// @param[in]  Address     Address to unlock.
/// @param[in]  IsPhysical  True if Address is a guest physical address; False if it is a guest virtual address.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Address is a guest virtual address and it does not point
///             inside the kernel.
/// @retval     #INT_STATUS_NOT_FOUND if no lock is found for Address.
///
{
    INTSTATUS status;
    WIN_PFN_LOCK *pLock;

    if (!IsPhysical && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, Address))
    {
        WARNING("[WARNING] Cannot unlock user-mode pages for now: 0x%016llx!\n", Address);
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    Address &= PAGE_MASK;

    // When we release by GVA, it should already be present in memory, and if it isn't (was
    // transitioned to big page), we just ignore it (we check all these below)
    if (!IsPhysical)
    {
        pLock = IntWinPfnFindByGva(Address);
    }
    else
    {
        pLock = IntWinPfnFindByGpa(Address);
    }

    if (NULL == pLock)
    {
        return INT_STATUS_NOT_FOUND;
    }

    if (0 != --pLock->RefCount)
    {
        return INT_STATUS_SUCCESS;
    }

    if (pLock->Present && !pLock->LargePage && pLock->GpaPage)
    {
        status = IntWinPfnModifyRefCount(pLock->GpaPage, FALSE);
        if (INT_STATUS_NOT_NEEDED_HINT == status)
        {
            LOG("[INFO] Page at 0x%016llx it's not locked by us...\n", Address);
        }
        else if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    if (NULL != pLock->SwapHook)
    {
        status = IntHookPtsRemoveHook((HOOK_PTS **)&pLock->SwapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsRemoveHook failed for 0x%016llx: 0x%08x\n", Address, status);
        }
    }

    RemoveEntryList(&pLock->Link);

    HpFreeAndNullWithTag(&pLock, IC_TAG_WPFN);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinPfnHandleTranslationChange(
    _In_ WIN_PFN_LOCK *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief      Handles translation changes for locked guest virtual pages.
///
/// This is the EPT swap hook set by #IntWinPfnLockAddress. Since locks on virtual pages are in fact locks on the
/// physical pages to which they translate to, when the translation changes, we also have to move the lock to the
/// new page.
/// If the new page is a large page, or if the page is swapped out, the in-guest reference counter is decremented. For
/// large pages the swap hook will also be removed, as large pages are not swappable.
/// If the page size remains 4KB, the lock is moved using #IntWinPfnMoveLock.
///
/// @param[in]  Context         The context set by #IntWinPfnLockAddress. This will be the #WIN_PFN_LOCK structure
///                             for which the hook was placed.
/// @param[in]  VirtualAddress  The guest virtual address for which the translation changed.
/// @param[in]  OldEntry        The old page table entry for VirtualAddress.
/// @param[in]  NewEntry        The new page table entry for VirtualAddress.
/// @param[in]  OldPageSize     The old page size. Ignored.
/// @param[in]  NewPageSize     The new page size.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    WIN_PFN_LOCK *pLock = Context;
    INTSTATUS status;
    QWORD newGpa;

    UNREFERENCED_PARAMETER(OldPageSize);

    if (pLock->RefCount == 0)
    {
        LOG("[PFN] Page at 0x%016llx is already released, will leave now...\n", VirtualAddress);
        return INT_STATUS_SUCCESS;
    }

    if (gGuest.Guest64)
    {
        newGpa = CLEAN_PHYS_ADDRESS64(NewEntry);
    }
    else if (gGuest.PaeEnabled)
    {
        newGpa = CLEAN_PHYS_ADDRESS32PAE(NewEntry);
    }
    else
    {
        newGpa = CLEAN_PHYS_ADDRESS32(NewEntry);
    }

    if ((NewPageSize != PAGE_SIZE_4K) ||                // Transition to a large page, or
        (0 == (NewEntry & PT_P) && pLock->Present))     // The page is swapped out
    {
        TRACE("[PFN] Removing lock for 0x%016llx : 0x%016llx transitions from 0x%016llx to 0x%016llx (large: %d)\n",
              pLock->Page, pLock->GpaPage, OldEntry, NewEntry, PAGE_SIZE_4K != NewPageSize);

        // Don't actually remove the lock (there may be pointers to it in other structures),
        // so just remove the refcount
        if (0 != pLock->GpaPage)
        {
            status = IntWinPfnModifyRefCount(pLock->GpaPage, FALSE);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinPfnModifyRefCount failed: 0x%08x\n", status);
            }
        }

        pLock->GpaPage = 0;

        pLock->Present = 0 != (NewEntry & PT_P);
        pLock->LargePage = PAGE_SIZE_4K != NewPageSize;

        if (pLock->LargePage)
        {
            status = IntHookPtsRemoveHook((HOOK_PTS **)&pLock->SwapHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsRemoveHook failed for 0x%016llx: 0x%08x\n", pLock->Page, status);
            }
        }
    }
    else if (newGpa != pLock->GpaPage)
    {
        TRACE("[PFN] Moving lock for 0x%016llx from 0x%016llx -> 0x%016llx\n", pLock->Page, pLock->GpaPage, newGpa);

        pLock->Present = TRUE;
        pLock->LargePage = FALSE;

        status = IntWinPfnMoveLock(pLock, newGpa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnMoveLock failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinPfnLockAddress(
    _In_ QWORD Address,
    _In_ BOOLEAN IsPhysical,
    _Out_opt_ PWIN_PFN_LOCK *PfnLock
    )
///
/// @brief      Locks a guest page.
///
/// Every #IntWinPfnLockAddress call for an address must match a call to this function. If the Introcore reference
/// counter reaches 0, it means that we also have to remove the lock from the guest, but only if it is a physical, not
/// large, page.
/// Also, any resources held by the lock are freed: the swap hook (if it exists) and the lock itself. It will
/// also be removed from the #gWinPfns list.
///
/// @param[in]  Address     Address to unlock.
/// @param[in]  IsPhysical  True if Address is a guest physical address; False if it is a guest virtual address.
/// @param[out] PfnLock     On success, will contain a pointer to the lock. May be NULL.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Address is a guest virtual address and it does not point
///             inside the kernel.
/// @retval     #INT_STATUS_NOT_FOUND if no lock is found for Address.
///
{
    INTSTATUS status;
    WIN_PFN_LOCK *pLock;
    BOOLEAN isPresent;
    QWORD gpa, size;

    if (!IsPhysical && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, Address))
    {
        WARNING("[WARNING] Cannot lock user-mode pages for now: 0x%016llx!\n", Address);
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    Address &= PAGE_MASK;

    if (!IsPhysical)
    {
        VA_TRANSLATION translation = {0};

        status = IntTranslateVirtualAddressEx(Address, gGuest.Mm.SystemCr3, TRFLG_NONE, &translation);
        if (!INT_SUCCESS(status) && (INT_STATUS_PAGE_NOT_PRESENT != status) &&
            (INT_STATUS_NO_MAPPING_STRUCTURES != status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddressEx failed for GVA 0x%016llx: 0x%08x\n", Address, status);
            return status;
        }

        if (INT_SUCCESS(status) && (0 != (translation.Flags & PT_P)))
        {
            isPresent = TRUE;
            gpa = translation.PhysicalAddress;
            size = translation.PageSize;
        }
        else
        {
            isPresent = FALSE;
            gpa = 0;
            size = PAGE_SIZE_4K;
        }
    }
    else
    {
        isPresent = TRUE;
        gpa = Address;
        size = PAGE_SIZE_4K;
    }

    if (size != PAGE_SIZE_4K)
    {
        // We don't lock big pages anymore
        if (PfnLock != NULL)
        {
            *PfnLock = NULL;
        }
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!IsPhysical)
    {
        pLock = IntWinPfnFindByGva(Address);
    }
    else
    {
        pLock = IntWinPfnFindByGpa(gpa);
    }

    if (NULL == pLock)
    {
        pLock = HpAllocWithTag(sizeof(*pLock), IC_TAG_WPFN);
        if (NULL == pLock)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else // the page is already locked. Increase RefCount and exit
    {
        pLock->RefCount++;

        if (NULL != PfnLock)
        {
            *PfnLock = pLock;
        }

        return INT_STATUS_SUCCESS;
    }

    pLock->Page = Address;
    pLock->GpaPage = gpa;
    pLock->RefCount = 1;
    pLock->Present = isPresent;
    pLock->LargePage = size != PAGE_SIZE_4K;

    if (pLock->Present && !pLock->LargePage)
    {
        status = IntWinPfnModifyRefCount(pLock->GpaPage, TRUE);
    }
    else
    {
        // Wait for modification
        status = INT_STATUS_SUCCESS;
    }

    if (INT_STATUS_NOT_INITIALIZED == status)
    {
        LOG("[INFO] Page at gva 0x%016llx and gpa 0x%016llx it's not initialized. Will hook the page!\n",
            Address, gpa);
    }
    else if (!INT_SUCCESS(status))
    {
        HpFreeAndNullWithTag(&pLock, IC_TAG_WPFN);

        return status;
    }

    if (!IsPhysical)
    {
        status = IntHookPtsSetHook(0,
                                   Address,
                                   IntWinPfnHandleTranslationChange,
                                   pLock,
                                   NULL,
                                   0,
                                   (PHOOK_PTS *)&pLock->SwapHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsSetHook failed: 0x%08x\n", status);
        }
    }

    InsertTailList(&gWinPfns, &pLock->Link);

    if (NULL != PfnLock)
    {
        *PfnLock = pLock;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinPfnLockGva(
    _In_ QWORD Gva,
    _Out_opt_ WIN_PFN_LOCK **PfnLock
    )
///
/// @brief      Locks a guest virtual address.
///
/// This will actually lock the guest physical address to which Gva translates to, and place a swap hook on Gva
/// page tables. If the page is not currently present, it will be locked when it will be made present.
///
/// @param[in]  Gva     Guest virtual address to lock.
/// @param[out] PfnLock On success, will contain a pointer to the lock. May be NULL.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    return IntWinPfnLockAddress(Gva, FALSE, PfnLock);
}


INTSTATUS
IntWinPfnLockGpa(
    _In_ QWORD Gpa,
    _Out_opt_ WIN_PFN_LOCK **PfnLock
    )
///
/// @brief      Locks a guest physical address.
///
/// @param[in]  Gpa     Guest physical address to lock.
/// @param[out] PfnLock On success, will contain a pointer to the lock. May be NULL.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    return IntWinPfnLockAddress(Gpa, TRUE, PfnLock);
}


INTSTATUS
IntWinPfnRemoveLock(
    _Inout_ WIN_PFN_LOCK *PfnLock,
    _In_ BOOLEAN Force
    )
///
/// @brief          Removes a PFN lock.
///
/// This will decrement the Introcore reference counter and only remove the lock when it reaches 0, unless a forced
/// removal is requested.
///
/// @param[in, out] PfnLock Lock to remove. The pointer will no longer be valid after this function returns.
/// @param[in]      Force   True to remove the lock even if the reference counter is not 0.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_NOT_NEEDED_HINT if the reference counter has not reached 0 and Force is False.
/// @retval         #INT_STATUS_INVALID_PARAMETER_1 if PfnLock is NULL.
///
{
    INTSTATUS status;

    if (NULL == PfnLock)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    //
    // If there still are references to this pfn lock then exit... If we force
    // it, then down below we set the refcount to 0, and the next time we call
    // this the refcount will be negative and != 0
    //
    if (!Force && (--PfnLock->RefCount) != 0)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!gGuest.ShutDown && PfnLock->GpaPage != 0)
    {
        status = IntWinPfnModifyRefCount(PfnLock->GpaPage, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnModifyRefCount failed: 0x%08x\n", status);
        }
    }

    if (NULL != PfnLock->SwapHook)
    {
        status = IntHookPtsRemoveHook((HOOK_PTS **)&PfnLock->SwapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsRemoveHook failed for gva 0x%016llx, gpa 0x%016llx: 0x%08x\n",
                  PfnLock->Page, PfnLock->GpaPage, status);
        }
    }

    RemoveEntryList(&PfnLock->Link);

    HpFreeAndNullWithTag(&PfnLock, IC_TAG_WPFN);

    return INT_STATUS_SUCCESS;
}


void
IntWinPfnDump(
    void
    )
///
/// @brief      Prints all the PFN locks.
///
{
    DWORD index = 0;

    LOG("[DBGINTRO] Pfn locks:\n");

    for_each_pfn_lock(pLock)
    {
        LOG(" ## %04d @ %p -> VA: 0x%016llx, GPA: 0x%016llx, SwapHook: %p, RefCount: %x, Present: %d, LargePage: %d\n",
            index++, pLock, pLock->Page, pLock->GpaPage, pLock->SwapHook, pLock->RefCount,
            pLock->Present, pLock->LargePage);
    }
}


void
IntWinPfnUnInit(
    void
    )
///
/// @brief      Uninits the PFN locks.
///
/// If any locks are still active when this function is called, they will be forcibly removed using
/// #IntWinPfnRemoveLock.
///
{
    INTSTATUS status;

    for_each_pfn_lock(pLock)
    {
        ERROR("[ERROR] There should be no pfn locks remaining... Got one on %llx, %llx!\n",
              pLock->GpaPage, pLock->Page);

        status = IntWinPfnRemoveLock(pLock, TRUE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinPfnRemoveLock failed: 0x%08x\n", status);
            continue;
        }
    }
}
