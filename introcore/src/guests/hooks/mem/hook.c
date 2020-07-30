/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook.h"


HOOK_STATE *gHooks = NULL; ///< Global hooks state.


INTSTATUS
IntHookCommitAllHooks(
    void
    )
///
/// @brief Commits all the hooks.
///
/// This function will call the commit function for each existing hook system. The commit functions have the role
/// of actually deleting each removed hook. The reason this has to be done is because we want to allow a callback
/// to remove its own hook. Therefore, whenever a hook is removed, we cannot free it right away, since it may be
/// removed from its own callback. Instead, each removed hook is placed in a removed hooks list, and they are deleted
/// all at once when every callback was handled.
/// If a new hook system is to be added, a commit function should normally be created for it as well, and that commit
/// function should be called here.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the hook system has not been initialized.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If no hooks were removed.
///
{
    INTSTATUS status;

    if (NULL == gHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gHooks->Dirty)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    STATS_ENTER(statsHookCommit);

    status = IntHookObjectCommit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCommit failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntHookGvaCommitHooks();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGvaCommitHooks failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntHookPtsCommitHooks();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtsCommitHooks failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntHookPtmCommitHooks();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookPtmCommitHooks failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntHookGpaCommitHooks();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookGpaCommitHooks failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

#ifdef DEBUG_CHECK_HOOKS
    IntDbgCheckHooks();
#endif


cleanup_and_exit:
    if (gHooks->GpaHooks.HooksRemoved || gHooks->GvaHooks.HooksRemoved ||
        gHooks->PtsHooks.HooksRemoved || gHooks->Objects.ObjectsRemoved ||
        gHooks->PtmHooks.HooksRemoved)
    {
        // There are hooks uncommitted. We don't want to reset the dirt marker,
        // so we have a chance to commit them on next run.
    }
    else
    {
        gHooks->Dirty = FALSE;
    }

    STATS_EXIT(statsHookCommit);

    return status;
}


INTSTATUS
IntHookRemoveChain(
    _In_ PHOOK_GPA HookGpa
    )
///
/// @brief Removes a hook chain, starting with the given GPA hook.
///
/// In Introcore, the hooks may be chained. For example, an object (or region hook) may contain multiple GVA
/// hooks, which in turn contain multiple PTS or GPA hooks. Whenever a callback returns the status
/// #INT_STATUS_REMOVE_HOOK_ON_RET, we must remove the top-most hook structure. This is done by starting with
/// the current GPA hook, and iterating, upwards, each parent hook until we end up finding a NULL parent.
/// Once we encounter such a hook, we may call the appropriate remove function on it, which in turn will take
/// care of removing all the children hooks, up until and including the current HookGpa.
///
/// @param[in] HookGpa  The GPA hook, which usually is the bottom most hook.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If an unknown top-most hook is encountered.
///
{
    PHOOK_HEADER pHook;

    if (NULL == HookGpa)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // Find the most upper level hook.
    pHook = &HookGpa->Header;
    while (pHook->ParentHook)
    {
        pHook = (PHOOK_HEADER)pHook->ParentHook;
    }

    // Remove the most upper level hook.
    switch (pHook->HookType)
    {
    case hookTypeGpa:
        return IntHookGpaRemoveHook((HOOK_GPA **)&pHook, 0);

    case hookTypeGva:
        return IntHookGvaRemoveHook((HOOK_GVA **)&pHook, 0);

    case hookTypePts:
        return IntHookPtsRemoveHook((HOOK_PTS **)&pHook, 0);

    case hookTypePtm:
        return IntHookPtmRemoveHook((HOOK_PTM **)&pHook, 0);

    case hookTypeRegion:
        return IntHookObjectRemoveRegion((PHOOK_REGION_DESCRIPTOR *)&pHook, 0);

    default:
        ERROR("[ERROR] Unknown hook type %d!\n", pHook->HookType);
        return INT_STATUS_NOT_SUPPORTED;
    }
}


INTSTATUS
IntHookInit(
    void
    )
///
/// @brief Initialize the global hook system.
///
/// This function will initialize all the hook systems. Creating a new hook subsystem requires that it be initialized
/// here, by calling its Init function.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED If the hook system has already been initialized.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation function failed.
///
{
    INTSTATUS status;

    if (NULL != gHooks)
    {
        ERROR("[ERROR] Trying to do IntHookInit multiple times!\n");
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    gHooks = HpAllocWithTag(sizeof(*gHooks), IC_TAG_HOOKS);
    if (NULL == gHooks)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntHookGpaInit();
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    status = IntHookPtmInit();
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    status = IntHookPtsInit();
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    status = IntHookGvaInit();
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    status = IntHookObjectInit();
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    return  INT_STATUS_SUCCESS;

cleanup_and_exit:
    IntHookObjectUninit();

    if (NULL != gHooks)
    {
        HpFreeAndNullWithTag(&gHooks, IC_TAG_HOOKS);
    }

    return status;
}


INTSTATUS
IntHookUninit(
    void
    )
///
/// @brief Uninit the global hooks system.
///
/// This function will call the uninit function of each hook system. Creating a new hook system will require to add
/// a call to its uninit function here.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the hooks system is not initialized.
///
{
    INTSTATUS status;

    if (NULL == gHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    status = IntHookCommitAllHooks();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookCommitAllHooks failed: 0x%08x\n", status);
    }

    status = IntHookObjectUninit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectUninit: 0x%08x\n", status);
    }

    HpFreeAndNullWithTag(&gHooks, IC_TAG_HOOKS);

    gHooks = NULL;

    return INT_STATUS_SUCCESS;
}


QWORD
IntHookGetGlaFromGpaHook(
    _In_ HOOK_GPA const *Hook,
    _In_ QWORD Address
    )
///
/// @brief Gets the GLA from a GPA hook.
///
/// Since GVA and GPA hooks are distinct, and logic hooks will be placed on guest virtual pages, but the EPT
/// works with guest physical pages, the only relation between a GPA hook and a virtual address is given by
/// the parent-child relationship between the hooks. This function will return the linear address associated
/// with a given guest physical hook.
/// NOTE: If we have multiple guest virtual pages pointing to the same guest physical page, we should also
/// have multiple guest physical page hooks, as Introcore does not take into consideration shared memory.
/// Multiple hooks set on the same guest physical range will lead to multiple hook structures being allocated.
/// The only aliasing issue that could potentially appear is if that the same callback, with the same context
/// is used for different virtual pages which translate to the same physical page; in this scenario, the caller
/// must be aware of shared memory implications, and should use the context to properly identify the virtual
/// pages involved in the hook.
///
/// @param[in]  Hook    The GPA hook.
/// @param[in]  Address The guest physical address accessed, used only to extract the low 12 bit (page offset).
///
/// @returns The guest linear address accessed for a given guest physical hook.
///
{
    HOOK_GVA const *pGva = Hook->Header.ParentHook;

    if ((NULL == pGva) || (pGva->Header.HookType != hookTypeGva))
    {
        ERROR("[ERROR] The GPA hook for address 0x%016llx does not point to a valid GVA hook: %p, type %d",
              Hook->GpaPage, pGva, pGva ? pGva->Header.HookType : 0);
        IntBugCheck();
    }

    return pGva->GvaPage + (Address & 0xFFF);
}
