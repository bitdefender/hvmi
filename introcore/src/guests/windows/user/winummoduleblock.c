/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winummoduleblock.h"
#include "hook.h"
#include "swapmem.h"
#include "introcpu.h"
#include "winummodule.h"

///
/// @file winummoduleblock.c
///
/// @brief This file contains the logic that blocks Windows module loads in case of a double agent attack.
///
/// The introspection provides a mechanism to block double agent attacks (controlled by #PROC_OPT_PROT_DOUBLE_AGENT).
/// This file implements the logic used to block a module load if deemed malicious by the internal heuristic.
///


///
/// @brief      Windows module block object.
///
typedef struct _WIN_MOD_BLOCK_OBJECT
{
    /// The Windows process module to be blocked.
    WIN_PROCESS_MODULE                  *Module;

    /// The flags that will determine the action the be taken in case a malicious module is detected.
    WIN_MOD_BLOCK_FLAG                  Flags;

    /// The callback that will provided the detection logic.
    PFUNC_IntWinModBlockCallback        Callback;

    /// This callback is invoked when the module headers have been successfully read.
    PFUNC_IntWinModBlockHeadersCallback HeadersCallback;

    ///  This callback is invoked before destroying the #WIN_MOD_BLOCK_OBJECT associated with this module.
    PFUNC_IntWinModBlockCleanup         CleanupCallback;

    /// A list of callbacks that will be invoked for different dllMain reasons.
    LIST_ENTRY                          ReasonCallbacksList;

    /// The swap handle used for reading the module headers.
    void                                *HeadersSwapHandle;
    /// The hook object placed on the executable sections.
    void        *ExecHookObject;
    /// The entry point of the module.
    DWORD       EntryPoint;
} WIN_MOD_BLOCK_OBJECT, *PWIN_MOD_BLOCK_OBJECT;


///
/// @brief      A reason callback structure (this can contain multiple callbacks to be invoked for a certain dllMain
/// reason).
///
typedef struct _REASON_CALLBACK_LIST_OBJECT
{
    LIST_ENTRY  Link;       ///<  Entry within #WIN_MOD_BLOCK_OBJECT::ReasonCallbacksList.
    DWORD       Reason;     ///<  The dllMain reason.
    LIST_ENTRY  Callbacks;  ///<  A list of callbacks to be invoked for the given dllMain reason.
} REASON_CALLBACK_LIST_OBJECT, *PREASON_CALLBACK_LIST_OBJECT;


///
/// @brief      A reason callback context (invoked for a given dllMain reason).
///
typedef struct _REASON_CALLBACK_OBJECT
{
    LIST_ENTRY Link;                                ///<  Entry within #REASON_CALLBACK_LIST_OBJECT::Callbacks.
    PFUNC_IntWinModBlockCallback ReasonCallback;    ///<  The callback to be invoked.
} REASON_CALLBACK_OBJECT, *PREASON_CALLBACK_OBJECT;



static INTSTATUS
IntWinModBlockHandleExecution(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief      This function is invoked when a hooked section belonging to the analyzed module starts executing.
///
/// After obtaining information such as dllHandle, reason, etc. this functions invokes #WIN_MOD_BLOCK_OBJECT::Callback
/// which uses some heuristics in order to determine if this is a double agent case or not. If the execution is deemed
/// unsafe, the WIN_MOD_BLOCK_OBJECT::ReasonCallbacksList will be iterated invoking the callbacks. If the final
/// required action is not #introGuestAllowed, depending on the provided flags (#winModBlockFlagUnloadAfterExec,
/// #winModBlockFlagDoNotUnload and #winModBlockFlagKillOnError), the module load could be blocked or the entire
/// process could be terminated in case of an error.
///
/// @param[in]          Context     The #WIN_MOD_BLOCK_OBJECT structure of the module in question.
/// @param[in]          Hook        The GPA hook handle.
/// @param[in]          Address     The accessed address.
/// @param[in, out]     Action      Desired action.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    WIN_MOD_BLOCK_OBJECT *pBlockObj = Context;
    WIN_PROCESS_MODULE *pMod = pBlockObj->Module;
    INTSTATUS status, status2;
    IG_ARCH_REGS *regs = &gVcpu->Regs;
    QWORD retAddr = 0, dllHandle, reserved;
    DWORD addrSize, reason;
    INTRO_ACTION action = introGuestAllowed;
    BOOLEAN bEntryPoint = TRUE;

    UNREFERENCED_PARAMETER(Hook);
    UNREFERENCED_PARAMETER(Address);

    if (regs->Cr3 != pMod->Subsystem->Process->Cr3)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsModuleLoadViolation);

    addrSize = pMod->Subsystem->SubsystemType == winSubsys64Bit ? 8 : 4;

    // get the return address from stack
    status = IntVirtMemRead(regs->Rsp, addrSize, pMod->Subsystem->Process->Cr3, &retAddr, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        goto _continue;
    }

    if ((DWORD)(regs->Rip - pMod->VirtualBase) != pBlockObj->EntryPoint)
    {
        WARNING("[WARNING] Something which is not the entry point was called for %s (Rip %llx rva %x Entry point %x)\n",
                utf16_for_log(pMod->Path->Name), regs->Rip,
                (DWORD)(regs->Rip - pMod->VirtualBase), pBlockObj->EntryPoint);
        bEntryPoint = FALSE;
    }

    // get the parameters of DllMain; from regs for x64 and from stack for x86
    if (pMod->Subsystem->SubsystemType == winSubsys64Bit && bEntryPoint)
    {
        dllHandle = regs->Rcx;
        reason = (DWORD)regs->Rdx;
        reserved = regs->R8;
    }
    else if (bEntryPoint)
    {
        DWORD stackArr[3];

        status = IntVirtMemRead(regs->Rsp + addrSize, 3 * addrSize, pMod->Subsystem->Process->Cr3, stackArr, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
            goto _exit;
        }

        dllHandle = stackArr[0];
        reason = stackArr[1];
        reserved = stackArr[2];
    }
    else
    {
        dllHandle = WINMODBLOCK_INVALID_VALUE;
        reason = WINMODBLOCK_INVALID_VALUE;
        reserved = WINMODBLOCK_INVALID_VALUE;
    }

    status = pBlockObj->Callback(pMod, pBlockObj, dllHandle, reason, reserved, retAddr, &action);

    *Action = MAX(action, *Action);

    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Block object callback returned: 0x%08x\n", status);
        goto _exit;
    }

    if (*Action == introGuestAllowed)
    {
        goto _exit;
    }

    list_for_each(pBlockObj->ReasonCallbacksList, REASON_CALLBACK_LIST_OBJECT, pCbList)
    {
        if (pCbList->Reason != reason)
        {
            continue;
        }

        list_for_each(pCbList->Callbacks, REASON_CALLBACK_OBJECT, pCbObj)
        {
            status = pCbObj->ReasonCallback(pMod, pBlockObj, dllHandle, reason, reserved, retAddr, &action);

            *Action = MAX(action, *Action);

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Callback for reason %u returned: 0x%08x\n", reason, status);
                goto _exit;
            }

        }
    }

_exit:
    if (*Action == introGuestAllowed)
    {
        status = IntWinModBlockRemoveBlockObject(pBlockObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinModBlockRemoveBlockObject failed: 0x%08x\n", status);
        }

        // If we allowed the execution, ignore the WINMODBLOCK_FLAG_KILL_ON_ERROR flag
        status = INT_STATUS_SUCCESS;
        goto _continue;
    }
    else if (*Action != introGuestNotAllowed)
    {
        goto _continue;
    }

    if (bEntryPoint && !!(pBlockObj->Flags & winModBlockFlagUnloadAfterExec))
    {
        TRACE("[INFO] Forcing unload by returning FALSE for module %s\n", utf16_for_log(pMod->Path->Name));

        regs->Rax = FALSE;
    }
    else if (bEntryPoint && !!(pBlockObj->Flags & winModBlockFlagDoNotUnload))
    {
        regs->Rax = TRUE;
    }

    regs->Rip = retAddr;

    // On x86 need to emulate RET 0xC for DllMain - when we are not sure if
    // it is entrypoint or not, we will not clean stack.
    regs->Rsp += pMod->Subsystem->SubsystemType == winSubsys64Bit || !bEntryPoint ? addrSize : 4 * addrSize;

    // We changed the RIP so we'll tell the integrator we did everything (otherwise on KVM some emulation
    // will take place from the old RIP).
    *Action = introGuestAllowedVirtual;

    // We shall propagate the status from Callback for the WINMODBLOCK_FLAG_KILL_ON_ERROR to take place.
    status2 = IntSetGprs(gVcpu->Index, regs);
    if (!INT_SUCCESS(status2))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status2);
    }

_continue:
    STATS_EXIT(statsModuleLoadViolation);

    // We can't really rely on introGuestRetry. It is not guaranteed that no emulation will take place etc.
    // IntroGuestRetry should be used only when the page with Rip is swapped out or when we are removing the hook...
    // but, since it's the maximum action we'll use it and overwrite here
    if (*Action == introGuestRetry)
    {
        *Action = introGuestAllowedVirtual;
    }

    if (!INT_SUCCESS(status))
    {
        if (!!(pBlockObj->Flags & winModBlockFlagKillOnError))
        {
            WARNING("[WARNING] Status is %x and flag KILL_ON_ERROR given, will try to kill process...\n", status);
            IntInjectExceptionInGuest(VECTOR_PF, 0, PFEC_US, gVcpu->Index);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntModBlockHandlePreInjection(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    )
///
/// @brief      This function is invoked before injecting the \#PF used to read the module headers.
///
/// We have to make sure that the VAD corresponding to this module is already inserted in the RB tree inside the guest.
/// If we inject a \#PF but the VAD is not queued yet, we will end up crashing the process, because it would receive
/// a \#PF for an address which is still invalid (because the VAD is not inserted in the tree yet).
///
/// @param[in]  Context             The #WIN_MOD_BLOCK_OBJECT structure of the module in question.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The guest GVA
///
/// @retval     #INT_STATUS_SUCCESS             The VAD is inside the tree so we can safely inject the \#PF.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     The VAD is NOT inside the tree, bail out (do not inject the \#PF).
///
{
    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);

    PWIN_MOD_BLOCK_OBJECT pModBlock = (PWIN_MOD_BLOCK_OBJECT)Context;
    if (NULL == pModBlock)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    PWIN_PROCESS_MODULE pMod = pModBlock->Module;
    if (NULL == pMod)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!IntWinVadIsInTree(pMod->Vad))
    {
        LOG("[WINMODULE] The VAD 0x%016llx belonging to module %s seems to not be inside the tree yet, "
            "will postpone #PF...\n",
            pMod->Vad->VadGva, utf16_for_log(pMod->Path->Path));

        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntModBlockHandleBlockModHeadersInMemory(
    _In_ WIN_MOD_BLOCK_OBJECT *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) BYTE *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      This function is invoked when the module headers have been successfully read.
///
/// After the module headers have been successfully read, this function will iterate trough all the sections and
/// and place an execute hook (invoking #IntWinModBlockHandleExecution for all the sections that are executable and
/// non-discardable). Also, this function will invoke the #WIN_MOD_BLOCK_OBJECT::HeadersCallback callback,
/// provided as context.
///
/// @param[in]  Context             The #WIN_MOD_BLOCK_OBJECT structure of the module in question.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    WIN_MOD_BLOCK_OBJECT *pBlockObj = Context;
    WIN_PROCESS_MODULE *pMod = pBlockObj->Module;
    INTSTATUS status;
    IMAGE_SECTION_HEADER *pSec;
    INTRO_PE_INFO peInfo = { 0 };

    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(DataSize);
    UNREFERENCED_PARAMETER(Flags);

    TRACE("[INFO] Headers for suspicious dll %s in memory!\n", utf16_for_log(pMod->Path->Path));

    pBlockObj->HeadersSwapHandle = NULL;

    status = IntHookObjectCreate(introObjectTypeExecSuspiciousDll,
                                 Cr3,
                                 &pBlockObj->ExecHookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntPeValidateHeader(pMod->VirtualBase, Data, DataSize, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    pBlockObj->EntryPoint = peInfo.EntryPoint;

    TRACE("[INFO] Hooking for execute for Virtual Base (0x%016llx)\n", pMod->VirtualBase);

    pSec = (IMAGE_SECTION_HEADER *)(Data + peInfo.SectionOffset);
    for (DWORD iSec = 0; iSec < peInfo.NumberOfSections; iSec++, pSec++)
    {
        char name[9] = { 0 };

        memcpy(name, pSec->Name, 8);

        if ((QWORD)pSec->VirtualAddress + pSec->Misc.VirtualSize > pMod->Vad->PageCount * PAGE_SIZE)
        {
            INFO("[INFO] Skipping section from VA 0x%08x, size 0x%08x, which is larger than VadSize 0x%016llx\n",
                 pSec->VirtualAddress, pSec->Misc.VirtualSize, pMod->Vad->PageCount * PAGE_SIZE);
            continue;
        }

        if (!!(pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            TRACE("[INFO] Hooking for execute section %s (0x%08x, 0x%08x)\n",
                  name, pSec->VirtualAddress, pSec->Misc.VirtualSize);
            status = IntHookObjectHookRegion(pBlockObj->ExecHookObject,
                                             Cr3,
                                             pMod->VirtualBase + pSec->VirtualAddress,
                                             ROUND_UP((SIZE_T)pSec->Misc.VirtualSize, PAGE_SIZE),
                                             IG_EPT_HOOK_EXECUTE,
                                             IntWinModBlockHandleExecution,
                                             pBlockObj,
                                             0,
                                             NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }
        }
        else
        {

            LOG("[INFO] Skipping for execute section %s (0x%08x, 0x%08x)\n",
                name, pSec->VirtualAddress, pSec->Misc.VirtualSize);
        }
    }

    if (NULL != pBlockObj->HeadersCallback)
    {
        status = pBlockObj->HeadersCallback(pMod, Data);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Section callback returned: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (pBlockObj->ExecHookObject)
        {
            IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&pBlockObj->ExecHookObject, 0);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinModBlockBlockModuleLoad(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ WIN_MOD_BLOCK_FLAG Flags,
    _In_ PFUNC_IntWinModBlockCallback Callback,
    _In_opt_ PFUNC_IntWinModBlockHeadersCallback HeadersCallback,
    _In_opt_ PFUNC_IntWinModBlockCleanup CleanupCallback,
    _Inout_ void **BlockObject
    )
///
/// @brief      This function is invoked when a suspicious dll is loaded in order to analyze and block the dll load
/// if required.
///
/// This function reads the module headers, hooks the executable sections and invokes the provided Callback in order
/// to obtain a required action. Depending on the provided Flags, this function could block the module load or
/// kill the process if an error occurred while blocking the load.
///
/// @param[in]      Module              The #WIN_PROCESS_MODULE structure of the module in question.
/// @param[in]      Flags               The flags that will indicate what kind of action should be taken if the module
///                                     is deemed unsafe.
///
/// @param[in]      Callback            The callback that will provided the detection logic.
/// @param[in]      HeadersCallback     This callback is invoked when the module headers have been successfully read.
/// @param[in]      CleanupCallback     This callback is invoked before destroying the #WIN_MOD_BLOCK_OBJECT associated
///                                     with this module.
///
/// @param[in, out] BlockObject         The #WIN_MOD_BLOCK_OBJECT associated with the given module.
///
/// @retval     #INT_STATUS_SUCCESS                     On success.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE      WIN_PROCESS_MODULE::StaticScan must NOT be TRUE.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES      A memory allocation failed.
///
{
    WIN_MOD_BLOCK_OBJECT *pBlockObject;
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL == Module)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Flags)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == BlockObject)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (Module->StaticScan)
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    pBlockObject = HpAllocWithTag(sizeof(*pBlockObject), IC_TAG_WINMOD_BLOCK);
    if (NULL == pBlockObject)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pBlockObject->Callback = Callback;
    pBlockObject->HeadersCallback = HeadersCallback;
    pBlockObject->CleanupCallback = CleanupCallback;
    pBlockObject->Flags = Flags;
    pBlockObject->Module = Module;
    InitializeListHead(&pBlockObject->ReasonCallbacksList);

    status = IntSwapMemReadData(Module->Subsystem->Process->Cr3,
                                Module->VirtualBase,
                                PAGE_SIZE,
                                SWAPMEM_OPT_UM_FAULT,
                                pBlockObject,
                                0,
                                IntModBlockHandleBlockModHeadersInMemory,
                                IntModBlockHandlePreInjection,
                                &pBlockObject->HeadersSwapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    *BlockObject = pBlockObject;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pBlockObject)
        {
            HpFreeAndNullWithTag(&pBlockObject, IC_TAG_WINMOD_BLOCK);
        }
    }

    return status;
}


INTSTATUS
IntWinModBlockRegisterCallbackForReason(
    _In_ void *BlockObject,
    _In_ DWORD Reason,
    _In_ PFUNC_IntWinModBlockCallback Callback
    )
///
/// @brief  Registers a callback that is invoked when the blocked module's DllMain function is called with a given
/// reason parameter.
///
/// There can be any number of callbacks for any reason. Take into account that the reason equal to 0xFFFFFFFF
/// (#WINMODBLOCK_INVALID_VALUE) is reserved and an error will be returned if one tries to call this function for
/// that specific reason.
///
/// @param[in]      BlockObject         The #WIN_MOD_BLOCK_OBJECT associated with the given module.
/// @param[in]      Reason              The DllMain provided reason.
/// @param[in]      Callback            A callback which is invoked at every execution inside the suspicious DLL of
///                                     DllMain when the reason parameter in DllMain equals to the given Reason
///                                     parameter. See #PFUNC_IntWinModBlockCallback in callbacks section for more
///                                     details.
///                                     If the returned Action by the registered callback is introGuestAllowed, the
///                                     block object will be removed. Please note that even if the maximum priority of
///                                     action is taken (e.g. introGuestRetry has more priority), if the main callback
///                                     (registered through #IntWinModBlockBlockModuleLoad) returns introGuestAllowed,
///                                     then no other callback registered through
///                                     #IntWinModBlockRegisterCallbackForReason gets called and the block
///                                     object is removed!
///
/// @retval     #INT_STATUS_SUCCESS                     On success.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES      A memory allocation failed.
///
{
    WIN_MOD_BLOCK_OBJECT *pObj = BlockObject;
    BOOLEAN found = FALSE;
    INTSTATUS status = INT_STATUS_SUCCESS;
    REASON_CALLBACK_LIST_OBJECT *pFinalCbList = NULL;
    REASON_CALLBACK_OBJECT *pCbObj = NULL;

    if (NULL == BlockObject)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (WINMODBLOCK_INVALID_VALUE == Reason)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pCbObj = HpAllocWithTag(sizeof(*pCbObj), IC_TAG_WINMOD_CB_OBJ);
    if (NULL == pCbObj)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    list_for_each(pObj->ReasonCallbacksList, REASON_CALLBACK_LIST_OBJECT, pCbList)
    {
        if (pCbList->Reason == Reason)
        {
            pFinalCbList = pCbList;
            found = TRUE;
            break;
        }
    }

    if (!found)
    {
        pFinalCbList = HpAllocWithTag(sizeof(*pFinalCbList), IC_TAG_WINMOD_CB_LIST);
        if (NULL == pFinalCbList)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_and_exit;
        }

        pFinalCbList->Reason = Reason;
        InitializeListHead(&pFinalCbList->Callbacks);

        InsertTailList(&pObj->ReasonCallbacksList, &pFinalCbList->Link);
    }

    pCbObj->ReasonCallback = Callback;

    InsertTailList(&pFinalCbList->Callbacks, &pCbObj->Link);

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pCbObj)
        {
            HpFreeAndNullWithTag(&pCbObj, IC_TAG_WINMOD_CB_OBJ);
        }

        if (NULL != pFinalCbList)
        {
            HpFreeAndNullWithTag(&pFinalCbList, IC_TAG_WINMOD_CB_LIST);
        }
    }

    return status;
}


INTSTATUS
IntWinModBlockRemoveBlockObject(
    _Inout_ void *BlockObject
    )
///
/// @brief      This function is used in order to destroy a #WIN_MOD_BLOCK_OBJECT structure.
///
/// This functions invokes the cleanup callback provided when to #IntWinModBlockBlockModuleLoad after which all the
/// structures used by the the #WIN_MOD_BLOCK_OBJECT are safely destroyed.
///
/// @param[in]      BlockObject         The #WIN_MOD_BLOCK_OBJECT structure to be destroyed.
///
/// @retval     #INT_STATUS_SUCCESS                     On success.
///
{
    WIN_MOD_BLOCK_OBJECT *pObj = BlockObject;
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIST_ENTRY *list, *list2;

    if (NULL == BlockObject)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL != pObj->CleanupCallback)
    {
        status = pObj->CleanupCallback(pObj->Module, pObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Cleanup callback returned: 0x%08x\n", status);
            // Continue cleaning up, even if this failed.
        }
    }

    if (NULL != pObj->ExecHookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&pObj->ExecHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
        }
    }

    if (NULL != pObj->HeadersSwapHandle)
    {
        status = IntSwapMemRemoveTransaction(pObj->HeadersSwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed: 0x%08x\n", status);
        }
    }

    list = pObj->ReasonCallbacksList.Flink;

    while (list != &pObj->ReasonCallbacksList)
    {
        REASON_CALLBACK_LIST_OBJECT *pCbList = CONTAINING_RECORD(list, REASON_CALLBACK_LIST_OBJECT, Link);
        list = list->Flink;

        list2 = pCbList->Callbacks.Flink;

        while (list2 != &pCbList->Callbacks)
        {
            REASON_CALLBACK_OBJECT *pCbObj = CONTAINING_RECORD(list2, REASON_CALLBACK_OBJECT, Link);
            list2 = list2->Flink;

            RemoveEntryList(&pCbObj->Link);
            HpFreeAndNullWithTag(&pCbObj, IC_TAG_WINMOD_CB_OBJ);
        }

        RemoveEntryList(&pCbList->Link);
        HpFreeAndNullWithTag(&pCbList, IC_TAG_WINMOD_CB_LIST);
    }

    HpFreeAndNullWithTag(&pObj, IC_TAG_WINMOD_BLOCK);

    return status;
}
