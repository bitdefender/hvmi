/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook_msr.h"
#include "callbacks.h"
#include "guests.h"


INTSTATUS
IntHookMsrSetHook(
    _In_ DWORD Msr,
    _In_ DWORD Flags,
    _In_ PFUNC_MsrReadWriteHookCallback Callback,
    _In_opt_ void *Context,
    _Out_opt_ void **Hook
    )
///
/// @brief Set a model-specific register write hook.
///
/// Establishes a hook on the given MSR (Model Specific Register). Flags may indicate whether it is a read, write
/// or both hook. When the first hook is set on a MSR, VM exits are enabled for it. When the first MSR hook is
/// set, the MSR access callback is registered to the HV.
///
/// @param[in]  Msr         The MSR to be intercepted.
/// @param[in]  Flags       #IG_MSR_HOOK_WRITE for write access, #IG_MSR_HOOK_READ for read access.
/// @param[in]  Callback    The callback to be called when Msr is accessed.
/// @param[in]  Context     Optional context, will be passed to the callback on calls.
/// @param[in]  Hook        Handle to the newly placed MSR hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BOOLEAN bWasEnabled = FALSE, bOldValue = FALSE, bFound = FALSE;

    if (Callback == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    list_for_each(gGuest.MsrHooks->MsrHooksList, HOOK_MSR, pListHook)
    {
        // We must skip disabled MSRs. MSR exit for this MSR may have been disabled already of the MSR hook is disabled.
        if ((pListHook->Msr == Msr) && (!pListHook->Disabled))
        {
            bWasEnabled = pListHook->WasEnabled;

            bFound = TRUE;

            break;
        }
    }

    HOOK_MSR *pHook = HpAllocWithTag(sizeof(*pHook), IC_TAG_MSRHK);
    if (NULL == pHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pHook->Context = Context;
    pHook->Msr = Msr;
    pHook->Flags = Flags;
    pHook->Callback = Callback;

    if (!bFound)
    {
        status = IntEnableMsrExit(Msr, &bOldValue);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntEnableMsrExit failed: 0x%08x\n", status);
        }
    }

    if (bFound)
    {
        pHook->WasEnabled = bWasEnabled;
    }
    else
    {
        pHook->WasEnabled = bOldValue;
    }

    if (0 == gGuest.MsrHooks->HooksCount++)
    {
        status = IntEnableMsrNotifications();
        if (!INT_SUCCESS(status))
        {
            HpFreeAndNullWithTag(&pHook, IC_TAG_MSRHK);
            return status;
        }
    }

    InsertTailList(&gGuest.MsrHooks->MsrHooksList, &pHook->Link);

    if (NULL != Hook)
    {
        *Hook = pHook;
    }

    return status;
}


static INTSTATUS
IntHookMsrDeleteHook(
    _In_ HOOK_MSR *Hook
    )
///
/// @brief Permanently delete a model specific register hook.
///
/// NOTE: When the last MSR hook is removed, the MSR notifications callback will be unregistered from the integrator.
///
/// @param[in]  Hook    The MSR hook to be deleted.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    if (!Hook->Disabled)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    HpFreeAndNullWithTag(&Hook, IC_TAG_MSRHK);

    if (0 >= --gGuest.MsrHooks->HooksCount)
    {
        return IntDisableMsrNotifications();
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookMsrRemoveHook(
    _In_ HOOK_MSR *Hook
    )
///
/// @brief Remove a model specific register hook.
///
/// Removes a MSR write hook. First of all, this function will mark the hook as being disabled (the callback will never
/// be called again). If we are currently in the context of a MSR violation, we will wait for the commit phase to
/// permanently delete the hook. Otherwise, the hook will be deleted immediately.
/// NOTE: If this is the last hook set on this particular MSR, VM exits will be disabled on it.
///
/// @param[in]  Hook    The hook to be removed.
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

    Hook->Disabled = TRUE;

    BOOLEAN bDisable = TRUE;
    list_for_each(gGuest.MsrHooks->MsrHooksList, HOOK_MSR, pHook)
    {
        if ((Hook->Msr == pHook->Msr) && (pHook != Hook) && (!pHook->Disabled))
        {
            bDisable = FALSE;
        }
    }

    if (bDisable)
    {
        bDisable = !Hook->WasEnabled;
    }

    if (bDisable)
    {
        // We deactivate MSR exiting for this MSR only if it was deactivated before we activated it.
        status = IntDisableMsrExit(Hook->Msr, &bDisable);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDisableMsrExit failed: 0x%08x\n", status);
        }
    }

    // If we're not handling a MSR violation right now then we can safely delete the MSR hook.
    if (CPU_STATE_MSR_VIOLATION != gVcpu->State)
    {
        RemoveEntryList(&Hook->Link);

        status = IntHookMsrDeleteHook(Hook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookMsrDeleteHook failed: 0x%08x\n", status);
        }
    }

    return INT_STATUS_SUCCESS;
}


static void
IntHookMsrRemoveAllHooks(
    void
    )
///
/// @brief Remove all model specific register write hooks.
///
{
    list_for_each(gGuest.MsrHooks->MsrHooksList, HOOK_MSR, pHook)
    {
        INTSTATUS status = IntHookMsrRemoveHook(pHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookMsrRemoveHook failed: 0x%08x\n", status);
        }
    }
}


INTSTATUS
IntHookMsrCommit(
    void
    )
///
/// @brief Commit the model specific register hooks.
///
/// This function will iterate the list of MSR hooks, and it will delete all the hooks that were flagged for removal.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the MSR hooks state is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == gGuest.MsrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    list_for_each(gGuest.MsrHooks->MsrHooksList, HOOK_MSR, pHook)
    {
        if (pHook->Disabled)
        {
            RemoveEntryList(&pHook->Link);

            status = IntHookMsrDeleteHook(pHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookMsrDeleteHook failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}


INTSTATUS
IntHookMsrInit(
    void
    )
///
/// @brief Initialize the model specific registers hook state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    gGuest.MsrHooks = HpAllocWithTag(sizeof(*gGuest.MsrHooks), IC_TAG_MSRS);
    if (NULL == gGuest.MsrHooks)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeListHead(&gGuest.MsrHooks->MsrHooksList);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookMsrUninit(
    void
    )
///
/// @brief Uninit the model specific register hooks state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the MSR hooks state is not initialized.
///
{
    if (NULL == gGuest.MsrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    IntHookMsrRemoveAllHooks();

    HpFreeAndNullWithTag(&gGuest.MsrHooks, IC_TAG_MSRS);

    return INT_STATUS_SUCCESS;
}
