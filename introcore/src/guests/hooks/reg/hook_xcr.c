/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook_xcr.h"
#include "callbacks.h"
#include "guests.h"


INTSTATUS
IntHookXcrSetHook(
    _In_ DWORD Xcr,
    _In_ DWORD Flags,
    _In_ PFUNC_XcrWriteHookCallback Callback,
    _In_opt_ void *Context,
    _Out_opt_ HOOK_XCR **Hook
    )
///
/// @brief Set an extended control register write hook.
///
/// This function will place an XCR write hook. Currently, only XCR0 is defined by Intel.
/// When the first XCR hook is set, the notification callback will be registered to the integrator.
///
/// @param[in]  Xcr         The intercepted XCR.
/// @param[in]  Flags       Flags. Can be used by the caller.
/// @param[in]  Callback    The callback to be called when the indicated XCR is written.
/// @param[in]  Context     Optional context.
/// @param[out] Hook        A handle to the newly placed hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc failed.
///
{
    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL != Hook)
    {
        *Hook = NULL;
    }

    HOOK_XCR *pHook = HpAllocWithTag(sizeof(*pHook), IC_TAG_XCRH);
    if (NULL == pHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pHook->Callback = Callback;
    pHook->Context = Context;
    pHook->Disabled = FALSE;
    pHook->Flags = Flags;
    pHook->Xcr = Xcr;

    if (0 == gGuest.XcrHooks->HooksCount++)
    {
        INTSTATUS status = IntEnableXcrNotifications();
        if (!INT_SUCCESS(status))
        {
            HpFreeAndNullWithTag(&pHook, IC_TAG_XCRH);
            return status;
        }
    }

    InsertTailList(&gGuest.XcrHooks->XcrHooksList, &pHook->Link);

    if (NULL != Hook)
    {
        *Hook = pHook;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookXcrDeleteHook(
    _In_ HOOK_XCR *Hook
    )
///
/// @brief Permanently delete an extended control register hook.
///
/// NOTE: When the last XCR hook is removed, the XCR notifications callback will be unregistered from the integrator.
///
/// @param[in]  Hook    The XCR hook to be deleted.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    if (!Hook->Disabled)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    HpFreeAndNullWithTag(&Hook, IC_TAG_XCRH);

    if (0 >= --gGuest.XcrHooks->HooksCount)
    {
        return IntDisableXcrNotifications();
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookXcrRemoveHook(
    _In_ HOOK_XCR *Hook
    )
///
/// @brief Remove an extended control register hook.
///
/// Removes an XCR write hook. First of all, this function will mark the hook as being disabled (the callback will never
/// be called again). If we are currently in the context of a XCR violation, we will wait for the commit phase to
/// permanently delete the hook. Otherwise, the hook will be deleted immediately.
///
/// @param[in]  Hook    The hook to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Hook->Disabled = TRUE;

    // If we're not handling an XCR violation right now than we can safely delete the XCR hook.
    if (CPU_STATE_XCR_WRITE != gVcpu->State)
    {
        RemoveEntryList(&Hook->Link);

        INTSTATUS status = IntHookXcrDeleteHook(Hook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookXcrDeleteHook failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


static void
IntHookXcrRemoveAllHooks(
    void
    )
///
/// @brief Remove all extended control register write hooks.
///
{
    list_for_each(gGuest.XcrHooks->XcrHooksList, HOOK_XCR, pHook)
    {
        INTSTATUS status = IntHookXcrRemoveHook(pHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookXcrRemoveHook failed: 0x%08x\n", status);
        }
    }
}


INTSTATUS
IntHookXcrCommit(
    void
    )
///
/// @brief Commit the extended control register hooks.
///
/// This function will iterate the list of XCR hooks, and it will delete all the hooks that were flagged for removal.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the XCR hooks state is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == gGuest.XcrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    list_for_each(gGuest.XcrHooks->XcrHooksList, HOOK_XCR, pHook)
    {
        if (pHook->Disabled)
        {
            RemoveEntryList(&pHook->Link);

            status = IntHookXcrDeleteHook(pHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookXcrDeleteHook failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}


INTSTATUS
IntHookXcrInit(
    void
    )
///
/// @brief Initialize the extended control registers hook state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    gGuest.XcrHooks = HpAllocWithTag(sizeof(*gGuest.XcrHooks), IC_TAG_XCRS);
    if (NULL == gGuest.XcrHooks)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeListHead(&gGuest.XcrHooks->XcrHooksList);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookXcrUninit(
    void
    )
///
/// @brief Uninit the extended control register hooks state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the XCR hooks state is not initialized.
///
{
    if (NULL == gGuest.XcrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    IntHookXcrRemoveAllHooks();

    HpFreeAndNullWithTag(&gGuest.XcrHooks, IC_TAG_XCRS);

    return INT_STATUS_SUCCESS;
}
