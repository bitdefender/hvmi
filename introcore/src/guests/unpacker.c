/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "unpacker.h"
#include "decoder.h"
#include "hook.h"


///
/// @file unpacker.c
///
/// @brief This module monitors pages against unpack.
///
/// This module monitors pages against unpack. Note that this is legacy code, and it *should* be rewritten in a more
/// efficient manner (for example, the unpack monitor should be enabled for an entire module, not on a single page
/// at a time). It should also return a handle to the monitored page/module.
/// NOTE: All pages are kept in a single linked list; this can cause serious performance penalty if many such pages
/// are monitored. If performance is of concern, this module must be optimized.
/// NOTE: Since the monitor functions work directly with a Cr3 and a virtual address, no handles are returned. Make
/// sure that each page is monitored only once, otherwise, when trying to remove a page, only the first match will
/// be removed. Alternatively, rewrite this mechanism to return a handle for each monitored page.
///


#define UNPACK_STATE_NONE           0x00  ///< Initial state.
#define UNPACK_STATE_DIRTY          0x01  ///< The page was written.
#define UNPACK_STATE_EXEC           0x02  ///< The page contains code that has been fetched for execution.


///
/// One page monitored against unpack.
///
typedef struct _UNPACK_PAGE
{
    LIST_ENTRY      Link;               ///< List entry link.
    QWORD           Cr3;                ///< Virtual address space this page belongs to.
    QWORD           VirtualAddress;     ///< Page virtual address.
    WORD            WriteCount;         ///< Number of times the page has been written.
    BYTE            State;              ///< Page state - check UNPACK_STATE*.
    PFUNC_PageUnpackedCallback UnpackCallback;  ///< Unpack callback, called as soon as the page has been unpacked.
    PFUNC_PageIsWriteValid WriteCheckCallback;   ///< Write callback, called when the page is written.
    void           *CallbackContext;    ///< Optional context, passed to the callbacks.
    void           *WriteHook;          ///< Write hook handle.
    void           *ExecHook;           ///< Exec hook handle.
} UNPACK_PAGE, *PUNPACK_PAGE;


static LIST_HEAD gUnpckPages = LIST_HEAD_INIT(gUnpckPages);



static PUNPACK_PAGE
IntUnpFindPage(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    )
///
/// @brief Finds a monitored page.
///
/// @param[in]  Cr3             Virtual address space of the monitored page.
/// @param[in]  VirtualAddress  Address to be found.
///
/// @returns The found page structure, or NULL, if none is found.
///
{
    LIST_ENTRY *list;

    list = gUnpckPages.Flink;
    while (list != &gUnpckPages)
    {
        PUNPACK_PAGE pPage = CONTAINING_RECORD(list, UNPACK_PAGE, Link);
        list = list->Flink;

        if ((pPage->VirtualAddress == VirtualAddress) && (pPage->Cr3 == Cr3))
        {
            return pPage;
        }
    }

    return NULL;
}


static INTSTATUS
IntUnpUnWatchPageInternal(
    _In_ PUNPACK_PAGE Page
    )
///
/// @brief Remove monitor from the indicated page.
///
/// @param[in]  Page    The monitored page.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;

    if (NULL == Page)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL != Page->WriteHook)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&Page->WriteHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        }
    }

    if (NULL != Page->ExecHook)
    {
        status = IntHookGvaRemoveHook((HOOK_GVA **)&Page->ExecHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
        }
    }

    RemoveEntryList(&Page->Link);

    HpFreeAndNullWithTag(&Page, IC_TAG_UNPG);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUnpPageExecuteCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle executions from a monitored page.
///
/// If the page is dirty, this function will decode the current instruction and it will invoke the unpack callback.
///
/// @param[in]  Context     The context - a monitored page.
/// @param[in]  Hook        GPA hook handle.
/// @param[in]  Address     Guest physical address that has just been executed.
/// @param[out] Action      Desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PUNPACK_PAGE pPage;
    PFUNC_PageUnpackedCallback cbk;
    QWORD cr3, va;
    void *cbkCtxt;
    INSTRUX instrux;

    UNREFERENCED_PARAMETER(Hook);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    cbk = NULL;
    cbkCtxt = NULL;
    va = 0;
    cr3 = 0;

    pPage = (PUNPACK_PAGE)Context;

    pPage->State |= UNPACK_STATE_EXEC;

    if (pPage->State & UNPACK_STATE_DIRTY)
    {
        // Decode the designated instruction.
        status = IntDecDecodeInstructionAtRip(gVcpu->Index, &gVcpu->Regs, NULL, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionAtRip failed: 0x%08x\n", status);

            memset(&instrux, 0, sizeof(instrux));
        }

        if (NULL != pPage->UnpackCallback)
        {
            cbk = pPage->UnpackCallback;
            cr3 = pPage->Cr3;
            va = pPage->VirtualAddress + (Address & PAGE_OFFSET);
            cbkCtxt = pPage->CallbackContext;
        }
    }

    // Done, remove the hook from this page.
    IntUnpUnWatchPageInternal(pPage);

    if (NULL != cbk)
    {
        status = cbk(cr3, va, &instrux, cbkCtxt);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Unpacker callback failed: 0x%08x\n", status);
        }
    }

    *Action = introGuestAllowed;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntUnpPageWriteCallback(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle writes inside a monitored page.
///
/// When the page is written, the write callback will be called, in order to check the write. If the callback
/// returns false, it means that the write is not legitimate, the page will be marked as being dirty, and the
/// execute hook will be set on it. If it returns true, the write callback will be kept, and no execute callback
/// will be set.
///
/// @param[in]  Context     The context - a monitored page.
/// @param[in]  Hook        GPA hook handle.
/// @param[in]  Address     Guest physical address that has just been executed.
/// @param[out] Action      Desired action.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PUNPACK_PAGE pPage;
    BOOLEAN bValid;

    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Hook);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }


    pPage = (PUNPACK_PAGE)Context;

    // Check if the write is valid (example, it is an IAT).
    if (NULL != pPage->WriteCheckCallback)
    {
        bValid = pPage->WriteCheckCallback(pPage->Cr3,
                                           pPage->VirtualAddress + (Address & 0xFFF),
                                           pPage->CallbackContext);
    }
    else
    {
        bValid = FALSE;
    }

    if (!bValid)
    {
        pPage->State |= UNPACK_STATE_DIRTY;
        pPage->WriteCount++;
    }

    if (pPage->WriteCount >= 32)
    {
        if (NULL != pPage->WriteHook)
        {
            status = IntHookGvaRemoveHook((HOOK_GVA **)&pPage->WriteHook, 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }

        status = IntHookGvaSetHook(pPage->Cr3,
                                   pPage->VirtualAddress,
                                   PAGE_SIZE,
                                   IG_EPT_HOOK_EXECUTE,
                                   IntUnpPageExecuteCallback,
                                   pPage,
                                   NULL,
                                   0,
                                   (PHOOK_GVA *)&pPage->ExecHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
            pPage->ExecHook = NULL;
            goto cleanup_and_exit;
        }
    }

cleanup_and_exit:

    // We will always allow the actions, but we won't send any notifications.
    *Action = introGuestAllowed;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntUnpWatchPage(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PFUNC_PageUnpackedCallback UnpackCallback,
    _In_ PFUNC_PageIsWriteValid WriteCheckCallback,
    _In_opt_ void *CallbackContext
    )
///
/// @brief Monitor a page against unpacking.
///
/// This function starts to monitor the indicated page against unpacking. The algorithm is fairly simple:
/// 1. Place a write hook on the indicated page;
/// 2. On each write inside the page, call the write check callback; if the write check callback returns
///    true (valid write), do nothing; otherwise, mark the page dirty and increment the write count;
/// 3. Once the write count reaches a threshold (32), remove the write hook and place an execute hook on
///    the page;
/// 4. When the page is executed, call the unpack callback, to indicate that the page has been unpacked.
///
/// @param[in]  Cr3                 Virtual address space.
/// @param[in]  VirtualAddress      The virtual address of the page to be monitored.
/// @param[in]  UnpackCallback      Called when the page is deemed to be "unpacked".
/// @param[in]  WriteCheckCallback  Called on each write, to validate it. Some writes may be valid (for example,
///                                 the writes made by the loader inside the IAT).
/// @param[in]  CallbackContext     Optional context to be passed to the unpack & write callbacks.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;

    UNPACK_PAGE *pPage = HpAllocWithTag(sizeof(*pPage), IC_TAG_UNPG);
    if (NULL == pPage)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pPage->Cr3 = Cr3;
    pPage->VirtualAddress = VirtualAddress;
    pPage->State = UNPACK_STATE_NONE;
    pPage->UnpackCallback = UnpackCallback;
    pPage->WriteCheckCallback = WriteCheckCallback;
    pPage->CallbackContext = CallbackContext;
    pPage->WriteHook = NULL;
    pPage->ExecHook = NULL;

    InsertTailList(&gUnpckPages, &pPage->Link);

    status = IntHookGvaSetHook(Cr3,
                               VirtualAddress,
                               PAGE_SIZE,
                               IG_EPT_HOOK_WRITE,
                               IntUnpPageWriteCallback,
                               pPage,
                               NULL,
                               0,
                               (PHOOK_GVA *)&pPage->WriteHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaSetHook failed: 0x%08x\n", status);
        pPage->WriteHook = NULL;
        goto cleanup_and_exit;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pPage)
        {
            IntUnpUnWatchPageInternal(pPage);
        }
    }

    return status;
}


INTSTATUS
IntUnpUnWatchPage(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    )
///
/// @brief Stop monitoring the indicated page.
///
/// @param[in]  Cr3             The virtual address space.
/// @param[in]  VirtualAddress  The address to stop monitoring against unpack.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    list = gUnpckPages.Flink;
    while (list != &gUnpckPages)
    {
        PUNPACK_PAGE pPage = CONTAINING_RECORD(list, UNPACK_PAGE, Link);
        list = list->Flink;

        if ((pPage->VirtualAddress == VirtualAddress) && (pPage->Cr3 == Cr3))
        {
            status = IntUnpUnWatchPageInternal(pPage);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntUnpUnWatchPageInternal failed: 0x%08x, page 0x%016llx/0x%016llx\n",
                      status,
                      pPage->VirtualAddress,
                      pPage->Cr3);
            }

            break;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntUnpUnWatchVaSpacePages(
    _In_ QWORD Cr3
    )
///
/// @brief Stop monitoring all pages belonging to a virtual address space.
///
/// @param[in]  Cr3     The virtual address space to stop monitoring against unpack.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    list = gUnpckPages.Flink;
    while (list != &gUnpckPages)
    {
        PUNPACK_PAGE pPage = CONTAINING_RECORD(list, UNPACK_PAGE, Link);
        list = list->Flink;

        if (pPage->Cr3 == Cr3)
        {
            status = IntUnpUnWatchPageInternal(pPage);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntUnpUnWatchPageInternal failed: 0x%08x, page 0x%016llx/0x%016llx\n",
                      status, pPage->VirtualAddress, pPage->Cr3);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntUnpRemovePages(
    void
    )
///
/// @brief Stop monitoring all pages.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    list = gUnpckPages.Flink;
    while (list != &gUnpckPages)
    {
        PUNPACK_PAGE pPage = CONTAINING_RECORD(list, UNPACK_PAGE, Link);
        list = list->Flink;

        status = IntUnpUnWatchPageInternal(pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntUnpUnWatchPageInternal failed: 0x%08x, page 0x%016llx/0x%016llx\n",
                  status, pPage->VirtualAddress, pPage->Cr3);
        }
    }

    return INT_STATUS_SUCCESS;
}


void
IntUnpUninit(
    void
    )
///
/// @brief Uninit the unpacker. This will stop the monitor on all pages.
///
{
    IntUnpRemovePages();
}
