/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "swapmem.h"
#include "winagent.h"
#include "hook.h"
#include "introcpu.h"


///
/// @file swapmem.c
///
/// @brief This module is responsibility for reading guest memory that may be swapped out.
///
/// This module handles reading guest virtual memory. Usually, a required range of guest memory will not be present
/// entirely inside the guest physical memory. The missing pages may be swapped in at some time in the future, but
/// there's no guarantee. In order to ensure that we will gain access to the swapped out data, this module will
/// schedule page-fault injections for missing pages. The doesn't have to deal with low-level aspects of paging,
/// all it has to do is call IntSwapMemReadData, and wait for the data read callback to be called. Internally,
/// this module will read all the data already available, and, for the missing pages, it will inject PFs inside
/// the guest.
/// NOTE: We can inject only a single PF at any given moment, even if more than 1 VCPU are present. This greatly
/// simplifies the scheduler and any PF tracking logic, by also avoiding too many PFs to be injected at the
/// same time (for example, on a guest with multiple VCPUs, we may cause a significant performance overhead if
/// we were to inject a PF on each VCPU).
/// NOTE: When reading kernel memory, the PF will be injected in the context of a SYSCALL, where interrupt are
/// enabled, no locks are being held and we are in paged context.
/// NOTE: The caller may wish to avoid injecting a PF. If it desires to, it can use the #SWAPMEM_OPT_NO_FAULT
/// option, which will tell this module to not inject any PF in order to read the indicated region of memory. Instead,
/// it will simply wait for the required pages to be naturally swapped in as a result of guest access.
/// NOTE: When we inject a PF, there is no guarantee that the PF will indeed reach the guest; sometimes, the HV
/// may decide to inject something else (for example, an IPI, or another exception), and, as a result, the PF
/// that we tried to inject will be lost. However, in order to address this, there is the event injection callback
/// (#IntHandleEventInjection in callbacks.c) which gets called immediately after injecting an event inside the
/// guest, if we had a pending PF (or another pending exception). This callback will receive as arguments the
/// injected vector, the CR2 and the error code; using these arguments, we can check if the PF which we wanted
/// got injected, and if it wasn't, we can simply retry injecting it later. This allows the scheduler to know exactly
/// if a swapmem PF was injected or not.
///


///
/// This context is used only internally. It represents a swapmem transaction. A transaction is a request to read
/// a contiguous portion of guest virtual memory, parts of which may not be present in physical memory.
///
typedef struct _SWAPMEM_TRANSACTION
{
    LIST_ENTRY              Link;               ///< List entry element.
    QWORD                   Cr3;                ///< Virtual address space from where we read memory.
    QWORD                   VirtualAddress;     ///< Guest virtual address to be read.
    QWORD                   PhysicalAddress;    ///< Guest physical address, once we get a translation.
    PBYTE                   Data;               ///< Pointer to a region of Introcore memory where the guest memory
    ///< memory will be read.
    DWORD                   DataMaxSize;        ///< Maximum data size to be read.
    DWORD                   DataCurrentSize;    ///< How much we've read so far.
    DWORD                   Flags;              ///< Transaction flags. Take a look at SWAPMEM_FLAG* for more info.
    DWORD                   Options;            ///< Transaction options. Take a look at SWAPMEM_OPT* for more info.
    DWORD                   ContextTag;         ///< If tag is not zero, on transactions cleanup, the context will be
    ///< freed.
    void                   *Context;            ///< Options context to be passed to the callbacks.
    BOOLEAN                 IsEnqueued;         ///< True if the transaction has been inserted in the global
    ///< transactions list.
    BOOLEAN                 IsCanceled;         ///< True if the transaction has been canceled.
    LIST_HEAD               Pages;              ///< List of pages to be read (list of #SWAPMEM_PAGE).
    PFUNC_PagesReadCallback Callback;           ///< Callback called as soon as all the requested data is available.
    PFUNC_PreInjectCallback PreInject;          ///< Callback called before injecting a PF inside the guest. If this
    ///< returns #INT_STATUS_NOT_NEEDED_HINT, the PF will be canceled.
} SWAPMEM_TRANSACTION, *PSWAPMEM_TRANSACTION;


///
/// Describes one page that will be read. A transaction contains a page entry for each page of virtual memory it needs
/// to read from guest space.
///
typedef struct _SWAPMEM_PAGE
{
    LIST_ENTRY              Link;               ///< List entry link.
    QWORD                   VirtualAddress;     ///< Guest virtual address of the page.
    PHOOK_PTS               Hook;               ///< Swap in hook handle set on this page.
    PSWAPMEM_TRANSACTION    Transaction;        ///< Parent transaction.
    QWORD                   TimeStamp;          ///< When was the last time we injected a PF for this page.
    BOOLEAN                 IsReady;            ///< True if the page is ready to be read.
    BOOLEAN                 IsPending;          ///< True if we injected a PF for the page, and we are waiting for it.
    BOOLEAN                 IsDone;             ///< True if the page has been read.
    BOOLEAN                 IsEnqueued;         ///< True if the page has been inserted inside the list of pages.
} SWAPMEM_PAGE, *PSWAPMEM_PAGE;


///
/// Global swapmem state.
///
typedef struct _SWAPMEM_STATE
{
    BOOLEAN         Initialized;                ///< True if the state has been initialized.
    LIST_HEAD       SwapTranzactionsList;       ///< List of transactions.
    PSWAPMEM_PAGE   PendingPage;                ///< Currently pending page. There can be only one pending page.
} SWAPMEM_STATE, *PSWAPMEM_STATE;


static SWAPMEM_STATE gSwapState = { 0 };


static INTSTATUS
IntSwapMemCleanupCallback(
    _In_ void *DataAddress,
    _In_ QWORD DataInfo
    )
///
/// @brief Cleans up a transaction, by freeing the data buffer, the context and the transaction itself.
///
/// @param[in]  DataAddress     Transaction address.
/// @param[in]  DataInfo        Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    PSWAPMEM_TRANSACTION pCtx;

    UNREFERENCED_PARAMETER(DataInfo);

    pCtx = (PSWAPMEM_TRANSACTION)DataAddress;

    if (NULL != pCtx->Data)
    {
        HpFreeAndNullWithTag(&pCtx->Data, IC_TAG_SWPP);
    }

    if ((0 != pCtx->ContextTag) && (NULL != pCtx->Context))
    {
        HpFreeAndNullWithTag(&pCtx->Context, pCtx->ContextTag);
    }

    HpFreeAndNullWithTag(&pCtx, IC_TAG_SWCX);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntSwapMemCancelTransaction(
    _In_ PSWAPMEM_TRANSACTION Transaction
    )
///
/// @brief Cancels a transaction.
//
/// @param[in]  Transaction The transaction to be canceled.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    list = Transaction->Pages.Flink;
    while (list != &Transaction->Pages)
    {
        PSWAPMEM_PAGE pPage = CONTAINING_RECORD(list, SWAPMEM_PAGE, Link);

        list = list->Flink;

        RemoveEntryList(&pPage->Link);

        pPage->IsEnqueued = FALSE;
        pPage->IsReady = pPage->IsPending = pPage->IsDone = FALSE;

        if (NULL != pPage->Hook)
        {
            status = IntHookPtsRemoveHook((HOOK_PTS **)&pPage->Hook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsRemoveHook failed: 0x%08x\n", status);
            }
        }

        if (pPage == gSwapState.PendingPage)
        {
            gSwapState.PendingPage = NULL;
        }

        HpFreeAndNullWithTag(&pPage, IC_TAG_SWPG);
    }

    status = IntSwapMemCleanupCallback(Transaction, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemCleanupCallback failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntSwapMemHandleBreakpointAgent(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD AgentTag,
    _In_opt_ void *Context
    )
///
/// @brief Handles a breakpoint agent.
///
/// This callback is called as soon as a breakpoint agent gets triggered inside the guest. Inside this function, we
/// will simply inject a PF, which is usually for a kernel address. The PF is injected on the SYSCALL flow, where
/// interrupts are enabled, and no locks are held, making it safe.
///
/// @param[in]  GuestVirtualAddress     Unused.
/// @param[in]  AgentTag                Unused.
/// @param[in]  Context                 The kernel guest virtual address we inject the PF for.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(GuestVirtualAddress);
    UNREFERENCED_PARAMETER(AgentTag);

    TRACE("[SWAPMEM] Injecting a #PF from #BP handler at %p on cpu %d\n", Context, gVcpu->Index);

    status = IntInjectExceptionInGuest(VECTOR_PF, (QWORD)Context, 0, gVcpu->Index);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntInjectExceptionInGuest failed for 0x%016llx: 0x%08x\n", (QWORD)Context, status);

        // Injection failed, we will retry injecting this #PF later.
        IntSwapMemCancelPendingPF((QWORD)Context);
    }

    return status;
}


static INTSTATUS
IntSwapMemInjectMiniSwapper(
    _In_ QWORD VirtualAddress
    )
///
/// @brief Injects the mini swapper, which is basically just a breakpoint agent.
///
/// @param[in]  VirtualAddress  The kernel virtual address to be swapped in.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_OPERATION_NOT_IMPLEMENTED If the OS is not Windows.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinAgentInjectBreakpoint(IntSwapMemHandleBreakpointAgent, (void *)VirtualAddress, NULL);
    }
    else
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }
}


static INTSTATUS
IntSwapMemPageSwappedIn(
    _In_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief Handle a page swap-in event.
///
/// This function is called when the translation of a page we wish to read is modified. We will check if the page
/// has been swapped in, and if it has, we will read its contents. Once the entire memory region is read (which
/// may include more than one page), the swap-in callback will be called, sending along a pointer to the read data.
/// After a page has been swapped in and read, the page-table hooks set for that page translation is removed.
///
/// @param[in]  Context         Optional context, points to the swapped in page structure, #SWAPMEM_PAGE.
/// @param[in]  VirtualAddress  The guest virtual address whose translation has just been modified.
/// @param[in]  OldEntry        Old page table entry.
/// @param[in]  NewEntry        New page table entry.
/// @param[in]  OldPageSize     Old page size.
/// @param[in]  NewPageSize     New page size.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    PSWAPMEM_TRANSACTION pCtx;
    PSWAPMEM_PAGE pPage;
    DWORD readSize, offset;

    UNREFERENCED_PARAMETER(OldEntry);
    UNREFERENCED_PARAMETER(OldPageSize);

    // Make sure the entry is present.
    if (0 == (NewEntry & PT_P))
    {
        return INT_STATUS_SUCCESS;
    }

    pPage = (PSWAPMEM_PAGE)Context;
    if (NULL == pPage)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pCtx = pPage->Transaction;
    if (NULL == pCtx->Data)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (pPage->IsDone || pCtx->IsCanceled)
    {
        return INT_STATUS_SUCCESS;
    }

    // Indicate that the current VCPU is not busy waiting for this swap anymore. We do this only if the page is
    // pending. If the page is not pending, this means we didn't inject a #PF for it but it was swapped in anyway.
    if (pPage == gSwapState.PendingPage)
    {
        gSwapState.PendingPage = NULL;
    }

    // If we get here, this will be an async callback call.
    pCtx->Flags |= SWAPMEM_FLAG_ASYNC_CALL;

    if (0 != (NewEntry & PT_XD))
    {
        pCtx->Flags |= SWAPMEM_FLAG_ENTRY_XD;
    }

    // Copy the newly mapped physical page.
    NewEntry = NewEntry & PHYS_PAGE_MASK & ~(NewPageSize - 1);

    if (VirtualAddress == pCtx->VirtualAddress)
    {
        pCtx->PhysicalAddress = NewEntry + (pCtx->VirtualAddress & (NewPageSize - 1));
    }

    offset = (DWORD)(pPage->VirtualAddress - pCtx->VirtualAddress);

    readSize = MIN((DWORD)(NewPageSize - (pPage->VirtualAddress & (NewPageSize - 1))), pCtx->DataMaxSize - offset);

    TRACE("[SWAPMEM] Page %llx was swapped in at %llx, will read 0x%x bytes at offset 0x%x\n",
          VirtualAddress, NewEntry, readSize, offset);

    status = IntPhysicalMemReadAnySize(NewEntry + (pPage->VirtualAddress & (NewPageSize - 1)),
                                       readSize,
                                       pCtx->Data + offset,
                                       NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysicalMemReadAnySize failed for 0x%016llx : %08x (%08x) : 0x%08x\n",
              NewEntry, (DWORD)NewPageSize, readSize, status);
    }

    pCtx->DataCurrentSize += readSize;

    pPage->IsReady = FALSE;
    pPage->IsPending = FALSE;
    pPage->IsDone = TRUE;

    if (NULL != pPage->Hook)
    {
        status = IntHookPtsRemoveHook((HOOK_PTS **)&pPage->Hook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsRemoveHook failed: 0x%08x\n", status);
        }
    }

    // Remove the current page, as we read its content.
    if (pPage->IsEnqueued)
    {
        RemoveEntryList(&pPage->Link);
        pPage->IsEnqueued = FALSE;

        HpFreeAndNullWithTag(&pPage, IC_TAG_SWPG);
    }

    // Check if we've read everything.
    if (pCtx->DataCurrentSize == pCtx->DataMaxSize)
    {
        // Invoke the callback, if set.
        if (NULL != pCtx->Callback)
        {
            status = pCtx->Callback(pCtx->Context, pCtx->Cr3, pCtx->VirtualAddress, pCtx->PhysicalAddress,
                                    pCtx->Data, pCtx->DataMaxSize, pCtx->Flags);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Callback failed: 0x%08x\n", status);
            }
        }

        // Successfully called callback, invalidate the context & the tag.
        pCtx->Context = NULL;
        pCtx->ContextTag = 0;

        if (pCtx->IsEnqueued)
        {
            RemoveEntryList(&pCtx->Link);
            pCtx->IsEnqueued = FALSE;

            status = IntSwapMemCleanupCallback(pCtx, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntSwapMemCleanupCallback failed: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSwapMemReadData(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_ DWORD Options,
    _In_opt_ void *Context,
    _In_opt_ DWORD ContextTag,
    _In_opt_ PFUNC_PagesReadCallback Callback,
    _In_opt_ PFUNC_PreInjectCallback PreInject,
    _Out_opt_ void **SwapHandle
    )
///
/// @brief Reads a region of guest virtual memory, and calls the indicated callback when all the data is available.
///
/// The function will read Length bytes from VirtualAddress inside Cr3 address space. The function may either read
/// the data directly, if it is present inside the physical memory, or it may inject a page fault in order to force
/// a swap-in of the pages containing the data. Callback will be invoked when all the data has been read. The
/// callback may be invoked synchronously or asynchronously: if a page fault is needed to read parts of the data,
/// it will invoked asynchronously. Otherwise, it will be invoked synchronously. The flag #SWAPMEM_FLAG_ASYNC_CALL
/// will be set in the Flags argument of the callback for asynchronously calls. The function can be used to read
/// data of arbitrary length (including data spanning multiple pages). Some pages may be swapped in as a result of
/// us injecting a PF for them, others may be swapped in naturally due to the normal guest activity, and other
/// pages may already be present when calling this function.
/// The PreInject callback will be called before actually injecting a PF inside the guest. This callback is optional,
/// but if it present and it returns #INT_STATUS_NOT_NEEDED_HINT, the PF will be inhibited, and therefore, it will
/// not be injected.
///
/// @param[in]  Cr3             Virtual address space where we wish to read data from.
/// @param[in]  VirtualAddress  Guest virtual address we wish to read from.
/// @param[in]  Length          Length, in bytes. Can span multiple pages.
/// @param[in]  Options         Options. Check out SWAPMEM_OPT* for more info.
/// @param[in]  Context         Optional context to be passed to the callbacks.
/// @param[in]  ContextTag      If Context is provided and ContextTag is not 0, the Context will be freed when removing
///                             the transaction.
/// @param[in]  Callback        Called once all the data is available.
/// @param[in]  PreInject       Callback invoked BEFORE injecting the PF. If this returns INT_STATUS_NOT_NEEDED_HINT,
///                             the PF will not be injected.
/// @param[out] SwapHandle      Contains, upon return, a handle to the swap object. If #SWAPMEM_OPT_NO_DUPS is used
///                             and a transaction is already present, SwapHandle will be set to NULL. Since the
///                             transactions are not reference counted, it would be problematic to return a handle, as
///                             it can then get freed more than once.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    PSWAPMEM_TRANSACTION pCtx;
    PSWAPMEM_PAGE pPage;
    VA_TRANSLATION tr = {0};
    QWORD tCr3, page = 0;
    BOOLEAN bInvoke = FALSE;

    pCtx = NULL;
    pPage = NULL;
    tCr3 = Cr3;

    if (0 == tCr3)
    {
        tCr3 = gGuest.Mm.SystemCr3;
    }

    // If no duplicate transactions are allowed, make sure this one is unique.
    if (0 != (Options & SWAPMEM_OPT_NO_DUPS))
    {
        LIST_ENTRY *list;

        list = gSwapState.SwapTranzactionsList.Flink;
        while (list != &gSwapState.SwapTranzactionsList)
        {
            PSWAPMEM_TRANSACTION p = CONTAINING_RECORD(list, SWAPMEM_TRANSACTION, Link);

            list = list->Flink;

            // The transaction is already present, bail out.
            if ((p->Cr3 == Cr3) && (p->VirtualAddress == VirtualAddress) &&
                (p->DataMaxSize == Length) && (p->Options == Options))
            {
                if (NULL != SwapHandle)
                {
                    *SwapHandle = NULL;
                }
                return INT_STATUS_SUCCESS;
            }
        }
    }

    pCtx = HpAllocWithTag(sizeof(*pCtx), IC_TAG_SWCX);
    if (NULL == pCtx)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    pCtx->Cr3 = Cr3;
    pCtx->Callback = Callback;
    pCtx->PreInject = PreInject;
    pCtx->Context = Context;
    pCtx->ContextTag = ContextTag;
    pCtx->DataCurrentSize = 0;
    pCtx->DataMaxSize = Length;
    pCtx->VirtualAddress = VirtualAddress;
    pCtx->Options = Options;
    pCtx->Flags = 0;
    InitializeListHead(&pCtx->Pages);

    pCtx->Data = HpAllocWithTag(Length, IC_TAG_SWPP);
    if (NULL == pCtx->Data)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    for (page = VirtualAddress; page < VirtualAddress + Length; page = (page & PAGE_MASK) + PAGE_SIZE_4K)
    {
        status = IntTranslateVirtualAddressEx(page, tCr3, TRFLG_NONE, &tr);
        if ((INT_STATUS_NO_MAPPING_STRUCTURES == status) ||
            (INT_STATUS_PAGE_NOT_PRESENT == status) ||
            (0 == (tr.Flags & PT_P)) ||
            ((0 != (Options & SWAPMEM_OPT_RW_FAULT)) && (!tr.IsWritable)))
        {
            TRACE("[SWAPMEM] Page %llx is at %llx with flags %llx and opts %x, "
                  "scheduling #PF injection to read %d bytes...\n",
                  page, tr.PhysicalAddress, tr.Flags, Options, Length);

            // The current page is not present. Allocate a SWAPMEM_PAGE structure and insert it inside the pending
            // pages list.
            pPage = HpAllocWithTag(sizeof(*pPage), IC_TAG_SWPG);
            if (NULL == pPage)
            {
                status = INT_STATUS_INSUFFICIENT_RESOURCES;
                goto cleanup_and_exit;
            }

            pPage->Transaction = pCtx;
            pPage->VirtualAddress = page;
            pPage->Hook = NULL;
            pPage->IsReady = TRUE;
            pPage->IsPending = FALSE;
            pPage->IsDone = FALSE;
            pPage->IsEnqueued = TRUE;

            // All set, this page is ready to be swapped in.
            InsertTailList(&pCtx->Pages, &pPage->Link);

            // Place the hook after we insert to page in the list, so in case of failure, the page gets cleaned up.
            status = IntHookPtsSetHook(Cr3, page, IntSwapMemPageSwappedIn, pPage, NULL, 0, &pPage->Hook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookPtsSetHook failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
        else
        {
            // We purposely use PAGE_SIZE, since we iterate in 4K chunks.
            DWORD toRead = (DWORD)MIN(PAGE_REMAINING(page), Length - (page - VirtualAddress));

            // The page is already present. We can read it right now!
            status = IntPhysicalMemReadAnySize(tr.PhysicalAddress,
                                               toRead,
                                               pCtx->Data + (page - VirtualAddress),
                                               NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPhysicalMemReadAnySize failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }

            pCtx->Flags |= (tr.Flags & PT_XD) ? SWAPMEM_FLAG_ENTRY_XD : 0;

            if (page == VirtualAddress)
            {
                pCtx->PhysicalAddress = tr.PhysicalAddress;
            }

            pCtx->DataCurrentSize += toRead;
        }
    }

    if (pCtx->DataCurrentSize == pCtx->DataMaxSize)
    {
        bInvoke = TRUE;
    }
    else
    {
        InsertTailList(&gSwapState.SwapTranzactionsList, &pCtx->Link);
        pCtx->IsEnqueued = TRUE;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    // pCtx can be safely used outside the locked region, since it will be freed via a post-commit callback.
    // In addition, if we get here, pCtx was not enqueued to the transactions list, so we're all good.
    if (bInvoke)
    {
        if (NULL != pCtx->Callback)
        {
            // Everything was present, we can invoke the callback right now.
            status = pCtx->Callback(pCtx->Context, pCtx->Cr3, pCtx->VirtualAddress, pCtx->PhysicalAddress,
                                    pCtx->Data, pCtx->DataMaxSize, pCtx->Flags);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Callback failed: 0x%08x\n", status);
            }
        }

        // Successfully called callback, invalidate the context & the tag.
        pCtx->Context = NULL;
        pCtx->ContextTag = 0;

        status = INT_STATUS_SUCCESS;
    }

    if (!INT_SUCCESS(status) || bInvoke)
    {
        if (NULL != pCtx)
        {
            INTSTATUS status2;

            status2 = IntSwapMemCancelTransaction(pCtx);
            if (!INT_SUCCESS(status2))
            {
                ERROR("[ERROR] IntSwapMemCancelTransaction failed: 0x%08x\n", status2);
            }

            pCtx = NULL;
        }
    }

    if (NULL != SwapHandle)
    {
        *SwapHandle = pCtx;
    }

    return status;
}


static PSWAPMEM_PAGE
IntSwapMemFindPendingPage(
    _In_ QWORD VirtualAddress,
    _In_ QWORD Cr3
    )
///
/// @brief Finds a pending page, given the guest virtual address and the Cr3.
///
/// @param[in]  VirtualAddress  The virtual address.
/// @param[in]  Cr3             The Cr3.
///
/// @returns The pending page, or NULL if none is found.
///
{
    for (LIST_ENTRY *list = gSwapState.SwapTranzactionsList.Flink; list != &gSwapState.SwapTranzactionsList;
         list = list->Flink)
    {
        PSWAPMEM_TRANSACTION tr = CONTAINING_RECORD(list, SWAPMEM_TRANSACTION, Link);

        for (LIST_ENTRY *pages = tr->Pages.Flink; pages != &tr->Pages; pages = pages->Flink)
        {
            PSWAPMEM_PAGE pPage = CONTAINING_RECORD(pages, SWAPMEM_PAGE, Link);

            if ((pPage->VirtualAddress == VirtualAddress) && (pPage->Transaction->Cr3 == Cr3))
            {
                return pPage;
            }
        }
    }

    return NULL;
}


INTSTATUS
IntSwapMemInjectPendingPF(
    void
    )
///
/// @brief Inject a PF for a pending page.
///
/// This is the main PF scheduling algorithm. This is called before returning from every callback, and
/// it checks the list of existing transactions & pages, in order to inject a PF inside the guest. Note
/// that only a single PF can be injected at any given time (even if we have multiple VCPUs), as this
/// makes the scheduler much simpler, and it avoids spamming the guest kernel with unexpected PFs.
/// Before injecting a PF, it makes sure the context is right (user/kernel, CR3), and it calls the
/// PreInjectCallback; of the PreInject callback does not return #INT_STATUS_SUCCESS, the PF for that
/// page will not be injected, and another page will be selected.
/// PFs can be either injected directly (user-mode PFs, when the context is right) or indirectly
/// (kernel-mode PFs) via the breakpoint agent. No other PFs will be injected until the pending one
/// has been handled (the page has been swapped in).
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *listCtx, *listPage;
    VA_TRANSLATION tr;
    QWORD cr3;
    DWORD ring;
    BOOLEAN bInjected;

    cr3 = 0;
    ring = 0;
    bInjected = FALSE;

    // Fast check - if the list of transactions is empty, bail out.
    if (IsListEmpty(&gSwapState.SwapTranzactionsList))
    {
        return INT_STATUS_SUCCESS;
    }

    // A pending exception exists, bail out now.
    if (gVcpu->Exception.Valid)
    {
        return INT_STATUS_SUCCESS;
    }

    // A pending #PF is being processed, wait for it.
    if (NULL != gSwapState.PendingPage)
    {
        return INT_STATUS_SUCCESS;
    }

    status = IntCr3Read(IG_CURRENT_VCPU, &cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
        return status;
    }

    status = IntGetCurrentRing(IG_CURRENT_VCPU, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    // Pick a good #PF to inject.
    listCtx = gSwapState.SwapTranzactionsList.Flink;
    while (listCtx != &gSwapState.SwapTranzactionsList)
    {
        PSWAPMEM_TRANSACTION pCtx = CONTAINING_RECORD(listCtx, SWAPMEM_TRANSACTION, Link);

        listCtx = listCtx->Flink;

        // If a #PF should not be injected, bail out now; we'll wait for the page to be swapped in when it may...
        if (0 != (pCtx->Options & SWAPMEM_OPT_NO_FAULT))
        {
            continue;
        }

        // If the VA spaces don't match, bail out.
        if ((cr3 != pCtx->Cr3) && (0 != pCtx->Cr3))
        {
            continue;
        }

        // If we requested user fault and we're in kernel mode or kernel fault and we're in user mode, bail out.
        if (((IG_CS_RING_0 != ring) && (0 != (pCtx->Options & SWAPMEM_OPT_KM_FAULT))) ||
            ((IG_CS_RING_3 != ring) && (0 != (pCtx->Options & SWAPMEM_OPT_UM_FAULT))))
        {
            continue;
        }

        // Now check for pending pages.
        listPage = pCtx->Pages.Flink;
        while (listPage != &pCtx->Pages)
        {
            PSWAPMEM_PAGE pPage = CONTAINING_RECORD(listPage, SWAPMEM_PAGE, Link);
            DWORD pfec = 0;

            listPage = listPage->Flink;

            if (!pPage->IsReady)
            {
                continue;
            }

            // No need to bail out in case of error, we'll just assume the page is not present.
            status = IntTranslateVirtualAddressEx(pPage->VirtualAddress, cr3, TRFLG_NONE, &tr);
            if (INT_SUCCESS(status))
            {
                // The page is already present.
                pfec |= ((0 != (tr.Flags & PT_P)) ? PFEC_P : 0);
            }

            // Check for user or kernel access.
            pfec |= ((ring == IG_CS_RING_3) ? PFEC_US : 0);

            // If we force a write fault, set the write flag.
            pfec |= ((0 != (pCtx->Options & SWAPMEM_OPT_RW_FAULT)) ? PFEC_RW : 0);

            TRACE("[SWAPMEM] [VCPU %d] Translated page 0x%016llx to 0x%016llx, entry 0x%016llx\n", gVcpu->Index,
                  pPage->VirtualAddress, tr.PhysicalAddress, tr.Flags);

            // Call the pre-inject callback, which has the last word in deciding whether the #PF should be injected.
            if (NULL != pCtx->PreInject)
            {
                status = pCtx->PreInject(pCtx->Context, cr3, pPage->VirtualAddress);
                if (!INT_SUCCESS(status) || (INT_STATUS_NOT_NEEDED_HINT == status))
                {
                    TRACE("[SWAPMEM] The pre-injection callback decided we cannot inject a #PF yet for 0x%016llx!\n",
                          pPage->VirtualAddress);
                    continue;
                }
            }

            // If a #PF must be generated only inside user mode, do so. Also, more checks should be done, to make sure
            // the #PF won't crash the guest, but as of now, we only use this to inject faults in user-mode,
            // which is safe.
            if (0 != (pCtx->Options & (SWAPMEM_OPT_BP_FAULT)))
            {
                TRACE("[SWAPMEM] Injecting AG/BP #PF for %llx/%llx!\n", cr3, pPage->VirtualAddress);

                status = IntSwapMemInjectMiniSwapper(pPage->VirtualAddress);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemInjectMiniSwapper failed: 0x%08x\n", status);
                }
            }
            else
            {
                TRACE("[SWAPMEM] Injecting UM/KM/direct #PF for %llx/%llx!\n", cr3, pPage->VirtualAddress);

                status = IntInjectExceptionInGuest(VECTOR_PF, pPage->VirtualAddress, pfec, gVcpu->Index);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntInjectExceptionInGuest failed: 0x%08x\n", status);
                }
            }

            if (INT_SUCCESS(status))
            {
                pPage->IsReady = FALSE;
                pPage->IsPending = TRUE;
                pPage->IsDone = FALSE;
                pPage->TimeStamp = gGuest.TimerCalls;
                gSwapState.PendingPage = pPage;
                bInjected = TRUE;
            }

            break;
        }

        if (bInjected || !INT_SUCCESS(status))
        {
            break;
        }
    }

    return status;
}


void
IntSwapMemCancelPendingPF(
    _In_ QWORD VirtualAddress
    )
///
/// @brief Cancel a pending PF.
///
/// Cancel the pending PF on the provided VirtualAddress. This can happen if we requested a PF injection, but
/// the HV had to inject something else. In this case, we cancel the injection, and we mark the page Ready,
/// allowing it to be re-injected later.
///
/// @param[in]  VirtualAddress  The virtual address the PF was requested for.
///
{
    // There can be only one pending #PF injection from swapmem at any given time, no matter how many CPUs we have.
    // However, make sure that the pending page is the same as the page for which an injection was requested, in order
    // to not cancel a valid transaction due to an injection error from an unrelated exception.
    if (NULL != gSwapState.PendingPage &&
        (gSwapState.PendingPage->VirtualAddress & PAGE_MASK) == (VirtualAddress & PAGE_MASK))
    {
        TRACE("[SWAPMEM] Canceling pending #PF for 0x%016llx, CR3 0x%016llx, CPU %d...\n",
              gSwapState.PendingPage->VirtualAddress, gSwapState.PendingPage->Transaction->Cr3, gVcpu->Index);

        // All other faults need to wait.
        gSwapState.PendingPage->IsReady = TRUE;
        gSwapState.PendingPage->IsPending = FALSE;
        gSwapState.PendingPage->IsDone = FALSE;
        gSwapState.PendingPage->TimeStamp = 0;

        gSwapState.PendingPage = NULL;
    }
}


void
IntSwapMemReinjectFailedPF(
    void
    )
///
/// @brief Reinject timed-out PFs.
///
/// Sometimes, injected PFs may get lost, mainly due to the HV, or may be dropped unexpectedly inside the guest.
/// We detect this by maintaining a time-stamp for each pending PF, and retrying the injection after aprox. 1s.
/// Note that reinjecting a PF more than once is not an issue, as the OS can handle this kind of spurious PFs.
///
{
    if (NULL != gSwapState.PendingPage)
    {
        if (gSwapState.PendingPage->TimeStamp + 1 < gGuest.TimerCalls)
        {
            LOG("[SWAPMEM] Page 0x%016llx with CR3 0x%016llx exceeds the age limit, will retry injection...\n",
                gSwapState.PendingPage->VirtualAddress, gSwapState.PendingPage->Transaction->Cr3);

            gSwapState.PendingPage->IsPending = FALSE;
            gSwapState.PendingPage->IsReady = TRUE;
            gSwapState.PendingPage->TimeStamp = 0;

            gSwapState.PendingPage = NULL;
        }
    }
}


INTSTATUS
IntSwapMemRemoveTransaction(
    _In_ void *Transaction
    )
///
/// @brief Remove a transaction.
///
/// Once a transaction is removed, the callback will no longer be called, and the swap hooks will be removed.
/// The data will no longer be available. This should be called, for example, when there is a pending read for
/// a process that is just terminating.
///
/// @param[in]  Transaction The transaction to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    PSWAPMEM_TRANSACTION pCtx;

    if (NULL == Transaction)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pCtx = (PSWAPMEM_TRANSACTION)Transaction;

    RemoveEntryList(&pCtx->Link);
    pCtx->IsEnqueued = FALSE;

    status = IntSwapMemCancelTransaction(pCtx);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemCancelTransaction failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntSwapMemRemoveTransactionsForVaSpace(
    _In_ QWORD Cr3
    )
///
/// @brief Remove all transactions initiated for a virtual address space.
///
/// Will remove all active transactions for the given VA space. The read-data callback will not be called for any of
/// the aborted transactions. Useful when a process is terminating.
///
/// @param[in]  Cr3 The virtual address space.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    list = gSwapState.SwapTranzactionsList.Flink;
    while (list != &gSwapState.SwapTranzactionsList)
    {
        PSWAPMEM_TRANSACTION pCtx = CONTAINING_RECORD(list, SWAPMEM_TRANSACTION, Link);
        list = list->Flink;

        if (pCtx->Cr3 == Cr3)
        {
            TRACE("[SWAPMEM] Removing transaction request at 0x%016llx for VA space 0x%016llx.\n",
                  pCtx->VirtualAddress, pCtx->Cr3);

            RemoveEntryList(&pCtx->Link);
            pCtx->IsEnqueued = FALSE;

            status = IntSwapMemCancelTransaction(pCtx);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntSwapMemCancelTransaction failed: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSwapMemInit(
    void
    )
///
/// @brief Init the swapmem system.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    InitializeListHead(&gSwapState.SwapTranzactionsList);

    gSwapState.Initialized = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntSwapMemUnInit(
    void
    )
///
/// @brief Uninit the swapmem system.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the system has not been initialized.
///
{
    if (!gSwapState.Initialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    memzero(&gSwapState, sizeof(gSwapState));

    return INT_STATUS_SUCCESS;
}


void
IntSwapMemDump(
    void
    )
///
/// @brief Dump all active transactions & pages.
///
{
    LIST_ENTRY *list1, *list2;

    list1 = gSwapState.SwapTranzactionsList.Flink;
    while (list1 != &gSwapState.SwapTranzactionsList)
    {
        PSWAPMEM_TRANSACTION pCtx = CONTAINING_RECORD(list1, SWAPMEM_TRANSACTION, Link);

        list1 = list1->Flink;

        LOG("Transaction %p: CR3 = 0x%016llx, GVA = 0x%016llx, max len = %d, cur len = %d, options = %d\n",
            pCtx, pCtx->Cr3, pCtx->VirtualAddress, pCtx->DataMaxSize, pCtx->DataCurrentSize, pCtx->Options);

        list2 = pCtx->Pages.Flink;
        while (list2 != &pCtx->Pages)
        {
            PSWAPMEM_PAGE pPage = CONTAINING_RECORD(list2, SWAPMEM_PAGE, Link);

            list2 = list2->Flink;

            LOG("    Page %p: GVA = 0x%016llx, state: %d %d %d\n",
                pPage, pPage->VirtualAddress, pPage->IsReady, pPage->IsPending, pPage->IsDone);
        }
    }
}
