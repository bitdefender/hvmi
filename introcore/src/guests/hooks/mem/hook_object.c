/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hook.h"
#include "hook_object.h"


static INTSTATUS
IntHookObjectRemoveRegionInternal(
    _In_ HOOK_REGION_DESCRIPTOR *Region,
    _In_ DWORD Flags
    )
///
/// @brief Remove a hooked region of memory.
///
/// This function will remove a region of hooked memory. It will call the remove function for each child hook
/// (with the #HOOK_FLG_CHAIN_DELETE flag set, in order to allow us to delete the hooks), and it will remove
/// the hook from the list of active hooks. The region will not actually be removed until the commit phase.
/// However, it will be marked as removed, and no callback for any of the lower-level hooks will be called
/// again.
///
/// @param[in]  Region  The hook region to be removed.
/// @param[in]  Flags   Flags. Reserved for future use.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the region has already been removed.
///
{
    UNREFERENCED_PARAMETER(Flags);

    if (Region->Header.Flags & (HOOK_FLG_REMOVE))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    for (DWORD i = 0; i < Region->HooksCount; i++)
    {
        if (NULL != Region->Hooks[i])
        {
            INTSTATUS status;

            status = IntHookGvaRemoveHook((HOOK_GVA **)&Region->Hooks[i], HOOK_FLG_CHAIN_DELETE);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook failed: 0x%08x\n", status);
            }
        }
    }

    Region->Header.Flags |= (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE);

    RemoveEntryList(&Region->Link);

    // IMPORTANT: Write hooks must be inserted at the end of the remove list. The reason is that the EPT does not allow
    // certain combinations of RWX flags; for example, one cannot have a W page which is not R. Therefore, if we have
    // two regions - one which contains R hooks and one which contains W hooks, we must make sure we remove the W hook
    // last, in order to have the R flag restored by the time we also restore the W flag - otherwise, we'll restore
    // the W flag first, which is invalid (as the entry is not yet R, because we didn't remove the R hook), and we will
    // either get an error from the HV (best case scenario) or trigger EPT misconfiguration (worst case scenario).
    if (Region->Header.EptHookType == IG_EPT_HOOK_WRITE)
    {
        InsertTailList(&Region->Object->RemovedRegions, &Region->Link);
    }
    else
    {
        InsertHeadList(&Region->Object->RemovedRegions, &Region->Link);
    }

    Region->Object->RegionsRemoved = TRUE;

    gHooks->Objects.ObjectsRemoved = TRUE;

    gHooks->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookObjectCreate(
    _In_ DWORD ObjectType,
    _In_ QWORD Cr3,
    _Out_ void **Object
    )
///
/// @brief Create a new hook object.
///
/// This function will create a new hook object, which can be used as a container for multiple hooked regions.
/// For example, one might wish to create a hook object for a loaded module, or for an entire process.
///
/// @param[in]  ObjectType  The type of the object. User defined.
/// @param[in]  Cr3         The address space the object resides in. Use 0 for global (kernel) objects.
/// @param[out] Object      Will contain, upon successfully return, the newly created object. The object can then
///                         be used as a parameter for other hook related functions.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation function fails.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    HOOK_OBJECT_DESCRIPTOR *pObj;

    if (NULL == Object)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pObj = HpAllocWithTag(sizeof(*pObj), IC_TAG_HKOBJ);
    if (NULL == pObj)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pObj->ObjectType = ObjectType;
    pObj->Cr3 = Cr3;
    pObj->RegionsRemoved = FALSE;

    InitializeListHead(&pObj->Regions);

    InitializeListHead(&pObj->RemovedRegions);

    InsertTailList(&gHooks->Objects.Objects, &pObj->Link);

    *Object = pObj;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookObjectHookRegion(
    _In_ void *Object,
    _In_ QWORD Cr3,
    _In_ QWORD Gla,
    _In_ SIZE_T Length,
    _In_ BYTE Type,
    _In_ void *Callback,
    _In_opt_ void *Context,
    _In_opt_ DWORD Flags,
    _Out_opt_ HOOK_REGION_DESCRIPTOR **Region
    )
///
/// @brief Hook a contiguous region of virtual memory inside the provided virtual address space.
///
/// This function hooks a contiguous region of memory inside the provided virtual address space. The entire region
/// will be hooked using the same hook type. Both access hooks (read, write or execute) and swap hooks can be set.
/// The region will later be removed by either explicitly calling #IntHookObjectRemoveRegion on the handle returned
/// bu this function (the Region parameter) or when the hook object this region belongs to is destroyed.
///
/// @param[in]  Object      A previously created hook object, using IntHookObjectCreate function.
/// @param[in]  Cr3         The target virtual address space.
/// @param[in]  Gla         Guest linear address where the hook starts.
/// @param[in]  Length      The length of the hooked region. Can span multiple pages.
/// @param[in]  Type        Hook type. Can be #IG_EPT_HOOK_READ, #IG_EPT_HOOK_WRITE, #IG_EPT_HOOK_EXECUTE or
///                         #IG_EPT_HOOK_NONE, for swap in hooks.
/// @param[in]  Callback    The callback to be called whenever the region is accessed or swapped.
/// @param[in]  Context     Optional context to be passed to the provided callback on events.
/// @param[in]  Flags       Hook flags.
/// @param[out] Region      Optional pointer to a region handle, which can later be used to unhook the memory area.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation fails.
///
{
    INTSTATUS status;
    HOOK_OBJECT_DESCRIPTOR *pObj;
    HOOK_REGION_DESCRIPTOR *pReg;

    if (NULL == Object)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_7;
    }

    if (Length > ONE_GIGABYTE)
    {
        ERROR("[ERROR] Trying to hook (%d) [%llx - %llx] with callback %p\n",
              Type, Gla, Gla + Length, Callback);
    }

    pObj = Object;

    Flags &= HOOK_FLG_GLOBAL_MASK;

    pReg = HpAllocWithTag(sizeof(*pReg), IC_TAG_REGD);
    if (NULL == pReg)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pReg->Header.Context = Context;
    pReg->Header.Flags = Flags;
    pReg->Header.ParentHook = NULL;
    pReg->Header.HookType = hookTypeRegion;
    pReg->Header.EptHookType = Type;

    pReg->HookLength = Length;
    pReg->HookStart = Gla;
    pReg->Object = pObj;

    InsertTailList(&pObj->Regions, &pReg->Link);

    pReg->Hooks = HpAllocWithTag(sizeof(void *) * ((Length / PAGE_SIZE) + 2), IC_TAG_HKAR);
    if (NULL == pReg->Hooks)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    for (QWORD gva = Gla; gva < Gla + Length; )
    {
        QWORD left = Gla + Length - gva;
        DWORD length = (DWORD)MIN(PAGE_SIZE, PAGE_REMAINING(gva));
        length = (DWORD)MIN(left, length);

        status = IntHookGvaSetHook(Cr3,
                                   gva,
                                   length,
                                   Type,
                                   Callback,
                                   Context,
                                   pReg,
                                   Flags,
                                   (HOOK_GVA **)&pReg->Hooks[pReg->HooksCount]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed for GVA 0x%016llx: 0x%08x\n", gva, status);
            goto cleanup_and_exit;
        }

        pReg->HooksCount++;
        gva += PAGE_REMAINING(gva);
    }

    if (NULL != Region)
    {
        *Region = pReg;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status) && (NULL != pReg))
    {
        INTSTATUS status2 = IntHookObjectRemoveRegionInternal(pReg, 0);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntHookObjectRemoveRegionInternal failed: 0x%08x\n", status2);
        }
    }

    gHooks->Dirty = TRUE;

    return status;
}


static INTSTATUS
IntHookObjectDeleteRegion(
    _In_ HOOK_REGION_DESCRIPTOR *Region,
    _In_ DWORD Flags
    )
///
/// @brief Permanently deletes the indicated region.
///
/// This function deletes a region of hooked memory. This should be called only from the commit function, or by a
/// higher level hook manager.
///
/// @param[in]  Region  The hook region.
/// @param[in]  Flags   Flags. Reserved for future use.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Flags);

    for (DWORD i = 0; i < Region->HooksCount; i++)
    {
        if (NULL != Region->Hooks[i])
        {
            INTSTATUS failStatus = IntHookGvaDeleteHook((HOOK_GVA **)&Region->Hooks[i], 0);
            if (!INT_SUCCESS(failStatus))
            {
                ERROR("[ERROR] IntHookGvaDeleteHook failed: 0x%08x\n", failStatus);
                status = failStatus;
            }
        }
    }

    RemoveEntryList(&Region->Link);

    HpFreeAndNullWithTag((void **)&Region->Hooks, IC_TAG_HKAR);

    HpFreeAndNullWithTag(&Region, IC_TAG_REGD);

    return status;
}


INTSTATUS
IntHookObjectRemoveRegion(
    _Inout_ HOOK_REGION_DESCRIPTOR **Region,
    _In_ DWORD Flags
    )
///
/// @brief Remove a hooked region of memory.
///
/// This function will remove a region of hooked memory. It will call the remove function for each child hook
/// (with the #HOOK_FLG_CHAIN_DELETE flag set, in order to allow us to delete the hooks), and it will remove
/// the hook from the list of active hooks. The region will not actually be removed until the commit phase.
/// However, it will be marked as removed, and no callback for any of the lower-level hooks will be called
/// again.
///
/// @param[in, out] Region  The hook region to be removed.
/// @param[in]      Flags   Flags. Reserved for future use.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the region has already been removed.
///
{
    INTSTATUS status;

    if (NULL == Region)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == *Region)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Flags &= HOOK_FLG_GLOBAL_MASK;

    status = IntHookObjectRemoveRegionInternal(*Region, Flags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectRemoveRegionInternal failed: 0x%08x\n", status);
    }

    *Region = NULL;

    return status;

}


INTSTATUS
IntHookObjectDestroy(
    _Inout_ HOOK_OBJECT_DESCRIPTOR **Object,
    _In_ DWORD Flags
    )
///
/// @brief Destroy an entire hook object. All regions belonging to this object will be removed.
///
/// This function will destroy an entire hook object, and all its belonging regions. This function will not delete
/// the hooked regions on the spot - instead, it will remove them: all hooks will be disabled (no callbacks will
/// be called from this point on), but the regions will be deleted during the commit phase.
///
/// @param[in, out] Object  The hook object to be destroyed.
/// @param[in]      Flags   The hook flags. Will usually be 0.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    if (NULL == Object)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == *Object)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Flags &= HOOK_FLG_GLOBAL_MASK;

    if ((*Object)->Flags & HOOK_FLG_REMOVE)
    {
        return INT_STATUS_SUCCESS;
    }

    list = (*Object)->Regions.Flink;
    while (list != &(*Object)->Regions)
    {
        HOOK_REGION_DESCRIPTOR *pReg = CONTAINING_RECORD(list, HOOK_REGION_DESCRIPTOR, Link);

        list = list->Flink;

        status = IntHookObjectRemoveRegionInternal(pReg, Flags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectRemoveRegionInternal failed: 0x%08x\n", status);
        }
    }

    (*Object)->Flags |= (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE);

    (*Object)->RegionsRemoved = TRUE;

    *Object = NULL;

    gHooks->Objects.ObjectsRemoved = TRUE;

    gHooks->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


void *
IntHookObjectFindRegion(
    _In_ QWORD Gva,
    _In_ void *HookObject,
    _In_ BYTE HookType
    )
///
/// @brief Searches for a region of hooked memory inside the provided hook object.
///
/// @param[in]  Gva         The region guest virtual address to be searched.
/// @param[in]  HookObject  The target hook object.
/// @param[in]  HookType    The searched hook type.
///
/// @returns The identified hook region or NULL, if none is found.
///
{
    LIST_ENTRY *list = NULL;
    HOOK_OBJECT_DESCRIPTOR *pObject = NULL;

    if (HookObject == NULL)
    {
        return NULL;
    }

    pObject = (HOOK_OBJECT_DESCRIPTOR *)(HookObject);

    list = pObject->Regions.Flink;
    while (list != &pObject->Regions)
    {
        HOOK_REGION_DESCRIPTOR *pRegion = CONTAINING_RECORD(list, HOOK_REGION_DESCRIPTOR, Link);

        list = list->Flink;
        if (IN_RANGE_LEN(Gva, pRegion->HookStart, pRegion->HookLength) &&
            ((pRegion->Header.EptHookType & HookType) == pRegion->Header.EptHookType))
        {
            return pRegion;
        }
    }

    return NULL;
}


static INTSTATUS
IntHookObjectDestroyAll(
    _In_ DWORD Flags
    )
///
/// @brief Destroy all existing hook objects.
///
/// @param[in]  Flags   Hook flags.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    Flags &= HOOK_FLG_GLOBAL_MASK;

    list = gHooks->Objects.Objects.Flink;
    while (list != &gHooks->Objects.Objects)
    {
        HOOK_OBJECT_DESCRIPTOR *pObj = CONTAINING_RECORD(list, HOOK_OBJECT_DESCRIPTOR, Link);

        list = list->Flink;

        if (0 == (pObj->Flags & HOOK_FLG_REMOVE))
        {
            LIST_ENTRY *list2 = pObj->Regions.Flink;

            LOG("[ERROR] There should be no hook objects remaining... Got one: (%llx, %d)!\n",
                pObj->Cr3, pObj->ObjectType);

            while (list2 != &pObj->Regions)
            {
                HOOK_REGION_DESCRIPTOR *pReg = CONTAINING_RECORD(list2, HOOK_REGION_DESCRIPTOR, Link);

                list2 = list2->Flink;

                status = IntHookObjectRemoveRegionInternal(pReg, Flags);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntHookObjectRemoveRegionInternal failed: 0x%08x\n", status);
                }
            }

            pObj->Flags |= (HOOK_FLG_DISABLED | HOOK_FLG_REMOVE);

            pObj->RegionsRemoved = TRUE;
        }
    }

    gHooks->Objects.ObjectsRemoved = TRUE;

    gHooks->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookObjectCommit(
    void
    )
///
/// @brief Commit removed hook objects and regions.
///
/// This function deletes all removed objects and regions. At this point they will be permanently deleted.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    // Check if any objects have been actually removed.
    if (!gHooks->Objects.ObjectsRemoved)
    {
        return INT_STATUS_SUCCESS;
    }

    list = gHooks->Objects.Objects.Flink;
    while (list != &gHooks->Objects.Objects)
    {
        HOOK_OBJECT_DESCRIPTOR *pObj = CONTAINING_RECORD(list, HOOK_OBJECT_DESCRIPTOR, Link);

        list = list->Flink;

        if ((pObj->RegionsRemoved) || (0 != (pObj->Flags & (HOOK_FLG_REMOVE))))
        {
            LIST_ENTRY *list2 = pObj->RemovedRegions.Flink;
            while (list2 != &pObj->RemovedRegions)
            {
                HOOK_REGION_DESCRIPTOR *pReg = CONTAINING_RECORD(list2, HOOK_REGION_DESCRIPTOR, Link);

                list2 = list2->Flink;

                if (0 != (pReg->Header.Flags & (HOOK_FLG_REMOVE)))
                {
                    STATS_ENTER(statsDeleteRegion);

                    status = IntHookObjectDeleteRegion(pReg, 0);

                    STATS_EXIT(statsDeleteRegion);

                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntHookObjectDeleteRegion failed: 0x%08x\n", status);
                    }
                }
            }
        }

        // Reset the regions-removal indicator.
        pObj->RegionsRemoved = FALSE;


        // Remove the master object structure now. There is no HookObjectDelete function, because we don't
        // need one; this is the only place where objects can be deleted.
        if (0 != (pObj->Flags & (HOOK_FLG_REMOVE)))
        {
            RemoveEntryList(&pObj->Link);

            HpFreeAndNullWithTag(&pObj, IC_TAG_HKOBJ);
        }
    }

    gHooks->Objects.ObjectsRemoved = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookObjectInit(
    void
    )
///
/// @brief Initialize the hook object system.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    InitializeListHead(&gHooks->Objects.Objects);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntHookObjectUninit(
    void
    )
///
/// @brief Uninit the hook object system.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the hook system has not been initialized yet.
///
{
    if (NULL == gHooks)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    INTSTATUS status = IntHookObjectDestroyAll(0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectDestroyAll failed: 0x%08x\n", status);
    }

    return status;
}
