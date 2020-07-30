/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook_cr.h"
#include "callbacks.h"
#include "guests.h"


INTSTATUS
IntHookCrSetHook(
    _In_ DWORD Cr,
    _In_ DWORD Flags,
    _In_ PFUNC_CrWriteHookCallback Callback,
    _In_opt_ void *Context,
    _Out_opt_ HOOK_CR **Hook
    )
///
/// @brief Set a control register write hook.
///
/// This function will place a write hook on the indicated control register. Whenever the register is written,
/// the indicated callback will be called.
/// NOTE: On some hypervisors, modifying certain bits inside CR4 (for example CR4.PGE[7]) will not trigger an event
/// to be sent to Introcore.
/// NOTE: When placing a write hook on a CR for the first time, Introcore will ask the HV to enable VM exits on
/// that particular register. This may lead to a significant performance impact (for example, when monitoring
/// CR3 for writes, a VM exit will be triggered on each context switch). When removing the last write hook on a
/// particular CR, Introcore will ask the HV to disable VM exits on that CR.
/// NOTE: VM exits on some registers will always be enabled (for example, CR0 or CR4), but the CPU may trigger a
/// VM exit only when certain bits are modified (for example, CR0.PE or CR0.PG).
///
/// @param[in]  Cr          The control register to be monitored.
/// @param[in]  Flags       Generic flags, caller defined.
/// @param[in]  Callback    The callback to be called when the CR is modified.
/// @param[in]  Context     Optional context, will be passed as an argument to the Callback.
/// @param[out] Hook        Optional hook handle. Can be later used to remove the hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    HOOK_CR *pHook = HpAllocWithTag(sizeof(*pHook), IC_TAG_CRH);
    if (NULL == pHook)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pHook->Callback = Callback;
    pHook->Context = Context;
    pHook->Disabled = FALSE;
    pHook->Flags = Flags;
    pHook->Cr = Cr;

    // Check if we already have a hook on this CR, in which case, we don't have to activate exits on it.
    BOOLEAN bCrAlreadyHooked = FALSE;

    list_for_each(gGuest.CrHooks->CrHooksList, HOOK_CR, pListHook)
    {
        if (Cr == pListHook->Cr)
        {
            bCrAlreadyHooked = TRUE;
            break;
        }
    }

    if (!bCrAlreadyHooked)
    {
        status = IntEnableCrWriteExit(Cr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntEnableCrWriteExit failed: 0x%08x\n", status);
        }
    }

    if (0 == gGuest.CrHooks->HooksCount++)
    {
        status = IntEnableCrNotifications();
        if (!INT_SUCCESS(status))
        {
            HpFreeAndNullWithTag(&pHook, IC_TAG_CRH);
            return status;
        }
    }

    InsertTailList(&gGuest.CrHooks->CrHooksList, &pHook->Link);

    if (NULL != Hook)
    {
        *Hook = pHook;
    }

    return status;
}


static INTSTATUS
IntHookCrDeleteHook(
    _In_ HOOK_CR *Hook
    )
///
/// @brief Permanently delete a control register hook.
///
/// NOTE: When the last CR hook is removed, the CR notifications callback will be unregistered from the integrator.
///
/// @param[in]  Hook    The CR hook to be deleted.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    if (!Hook->Disabled)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    HpFreeAndNullWithTag(&Hook, IC_TAG_CRH);

    if (0 >= --gGuest.CrHooks->HooksCount)
    {
        return IntDisableCrNotifications();
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookCrRemoveHook(
    _In_ HOOK_CR *Hook
    )
///
/// @brief Remove a control register hook.
///
/// Removes a CR write hook. First of all, this function will mark the hook as being disabled (the callback will never
/// be called again). If we are currently in the context of a CR violation, we will wait for the commit phase to
/// permanently delete the hook. Otherwise, the hook will be deleted immediately.
///
/// @param[in]  Hook    The hook to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_INITIALIZED If the CR hooks state is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    CR_HOOK_STATE *pCrHooksState = gGuest.CrHooks;
    if (NULL == pCrHooksState)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    Hook->Disabled = TRUE;

    BOOLEAN bCrStillHooked = FALSE;
    list_for_each(pCrHooksState->CrHooksList, HOOK_CR, pHook)
    {
        if ((pHook != Hook) && (pHook->Cr == Hook->Cr))
        {
            bCrStillHooked = TRUE;
            break;
        }
    }

    if (!bCrStillHooked)
    {
        status = IntDisableCrWriteExit(Hook->Cr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDisableCrWriteExit failed: 0x%08x\n", status);
        }
    }

    if (CPU_STATE_CR_WRITE != gVcpu->State)
    {
        RemoveEntryList(&Hook->Link);

        status = IntHookCrDeleteHook(Hook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookCrDeleteHook failed: 0x%08x\n", status);
        }
    }

    return status;
}


static INTSTATUS
IntHookCrRemoveAllHooks(
    void
    )
///
/// @brief Remove all control register write hooks.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the hooks state is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    CR_HOOK_STATE *pCrHookState = gGuest.CrHooks;
    if (NULL == pCrHookState)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    list_for_each(pCrHookState->CrHooksList, HOOK_CR, pHook)
    {
        status = IntHookCrRemoveHook(pHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookCrRemoveHook failed: 0x%08x\n", status);
        }
    }

    return status;
}


INTSTATUS
IntHookCrCommit(
    void
    )
///
/// @brief Commit the control register hooks.
///
/// This function will iterate the list of CR hooks, and it will delete all the hooks that were flagged for removal.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED If the CR hooks state is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == gGuest.CrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    list_for_each(gGuest.CrHooks->CrHooksList, HOOK_CR, pHook)
    {
        if (pHook->Disabled)
        {
            RemoveEntryList(&pHook->Link);

            status = IntHookCrDeleteHook(pHook);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookCrDeleteHook failed: 0x%08x\n", status);
            }
        }
    }

    return status;
}


INTSTATUS
IntHookCrInit(
    void
    )
///
/// @brief Initialize the control registers hook state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    gGuest.CrHooks = HpAllocWithTag(sizeof(*gGuest.CrHooks), IC_TAG_CRS);
    if (NULL == gGuest.CrHooks)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeListHead(&gGuest.CrHooks->CrHooksList);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookCrUninit(
    void
    )
///
/// @brief Uninit the control register hooks state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the CR hooks state is not initialized.
///
{
    if (NULL == gGuest.CrHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    IntHookCrRemoveAllHooks();

    HpFreeAndNullWithTag(&gGuest.CrHooks, IC_TAG_CRS);

    return INT_STATUS_SUCCESS;
}
