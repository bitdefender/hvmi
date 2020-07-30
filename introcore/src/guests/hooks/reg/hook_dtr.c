/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook_dtr.h"
#include "callbacks.h"
#include "guests.h"


INTSTATUS
IntHookDtrSetHook(
    _In_ DWORD Flags,
    _In_ PFUNC_DtrReadWriteHookCallback Callback,
    _Out_opt_ void **Hook
    )
///
/// @brief Places a descriptor table register hook.
///
/// Establishes a hook on a descriptor table register. The Flags argument indicates which register is hooked
/// and for what access. On each load or store on the hooked register, the callback will be called.
/// NOTE: Make sure that the Flags contains only one of:
/// - #IG_DESC_ACCESS_IDTR, #IG_DESC_ACCESS_GDTR, #IG_DESC_ACCESS_LDTR & #IG_DESC_ACCESS_TR
/// and only one of:
/// - #IG_DESC_ACCESS_READ, #IG_DESC_ACCESS_WRITE
/// Any other combination of flags will prevent the callback from being called for any kind of access.
/// NOTE: Intel has a single VMCS control which enabled/disables VM exits for all descriptor registers. Hooking any one
/// of them will trigger VM exits for all of them.
/// NOTE: Descriptor table exiting is normally disabled; it will be enabled when the first hook is set.
///
/// @param[in]  Flags       A combination of IG_DESC_ACCESS indicating what register & for what access the hook is set.
/// @param[in]  Callback    The callback to be called when the indicated register is loaded/stored.
/// @param[out] Hook        The handle to the newly placed hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    if (Callback == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    HOOK_DTR *pHook = HpAllocWithTag(sizeof(*pHook), IC_TAG_DTRH);
    if (NULL == pHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pHook->Flags = Flags;
    pHook->Callback = Callback;

    if (0 == gGuest.DtrHooks->HooksCount++)
    {
        INTSTATUS status = IntEnableDtrNotifications();
        if (!INT_SUCCESS(status))
        {
            HpFreeAndNullWithTag(&pHook, IC_TAG_DTRH);
            return status;
        }
    }

    InsertTailList(&gGuest.DtrHooks->DtrHooksList, &pHook->Link);

    if (NULL != Hook)
    {
        *Hook = pHook;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntHookDtrDeleteHook(
    _In_ HOOK_DTR *Hook
    )
///
/// @brief Permanently delete a descriptor register hook.
///
/// NOTE: If this is the last descriptor register hook that is removed, Introcore will ask the HV to disable
/// descriptor table access notifications.
///
/// @param[in]  Hook    The DTR hook to be deleted.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    if (!Hook->Disabled)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    HpFreeAndNullWithTag(&Hook, IC_TAG_DTRH);

    if (0 >= --gGuest.DtrHooks->HooksCount)
    {
        return IntDisableDtrNotifications();
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookDtrRemoveHook(
    _In_ HOOK_DTR *Hook
    )
///
/// @brief Remove a descriptor register hook.
///
/// Removes a DTR hook. First of all, this function will mark the hook as being disabled (the callback will never
/// be called again). If we are currently in the context of a DTR violation, we will wait for the commit phase to
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

    // If we're not handling an DTR violation right now than we can safely delete the DTR hook.
    if (CPU_STATE_DTR_LOAD != gVcpu->State)
    {
        RemoveEntryList(&Hook->Link);

        INTSTATUS status = IntHookDtrDeleteHook(Hook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookDtrDeleteHook failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


static void
IntHookDtrRemoveAllHooks(
    void
    )
///
/// @brief Remove all descriptor register hooks.
///
{
    list_for_each(gGuest.DtrHooks->DtrHooksList, HOOK_DTR, pHook)
    {
        INTSTATUS status = IntHookDtrRemoveHook(pHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookDtrRemoveHook failed: 0x%08x\n", status);
        }
    }
}


INTSTATUS
IntHookDtrCommit(
    void
    )
///
/// @brief Commit the descriptor registers hooks.
///
/// This function will iterate the list of DTR hooks, and it will delete all the hooks that were flagged for removal.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the DTR hooks state is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == gGuest.DtrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    list_for_each(gGuest.DtrHooks->DtrHooksList, HOOK_DTR, pHook)
    {
        if (pHook->Disabled)
        {
            RemoveEntryList(&pHook->Link);

            status = IntHookDtrDeleteHook(pHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookDtrDeleteHook failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}


INTSTATUS
IntHookDtrInit(
    void
    )
///
/// @brief Initialize the descriptor registers hook state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    gGuest.DtrHooks = HpAllocWithTag(sizeof(*gGuest.DtrHooks), IC_TAG_DTRS);
    if (NULL == gGuest.DtrHooks)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeListHead(&gGuest.DtrHooks->DtrHooksList);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookDtrUninit(
    void
    )
///
/// @brief Uninit the descriptor registers hooks state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the DTR hooks state is not initialized.
///
{
    if (NULL == gGuest.DtrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    IntHookDtrRemoveAllHooks();

    HpFreeAndNullWithTag(&gGuest.DtrHooks, IC_TAG_DTRS);

    return INT_STATUS_SUCCESS;
}
