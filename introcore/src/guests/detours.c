/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       detours.c
/// @ingroup    group_detours
/// @brief      The guest detour API implementation
///

#include "detours.h"
#include "decoder.h"
#include "guests.h"
#include "introcpu.h"
#include "memcloak.h"
#include "slack.h"
#include "lixmodule.h"
#include "kernvm.h"
#include "alerts.h"
#include "introcrt.h"


/// @brief  The maximum size of the original function code we will replace.
#define DETOUR_MAX_FUNCTION_SIZE 24

///
/// @brief  Holds information about the currently set detours.
///
typedef struct _DETOURS_STATE
{
    LIST_HEAD               DetoursList;    ///< List of detours. Each entry is a #DETOUR structure.
    union
    {
        PDETOUR             DetoursTable[detTagMax];        ///< Table of detours, indexed by #DETOUR_TAG.
        PDETOUR             LixDetourTable[det_max_id];     ///< Table of detours, indexed by #DETOUR_TAG (linux).
    };
} DETOURS_STATE, *PDETOURS_STATE;

/// @brief  The global detour state.
static DETOURS_STATE gDetours =
{

    .DetoursList = LIST_HEAD_INIT(gDetours.DetoursList)
};

/// @brief  Iterates the linked list in #gDetours.
///
/// Can be used to safely iterate the detour list. The current detour pointed to by _var_name can safely be removed
/// from the list, but note that removing other detours while iterating the list using this macro is not a valid
/// operation and can corrupt the list.
///
/// @param[in]  _var_name   The name of the variable in which the #DETOUR pointer will be placed. This variable
///                         will be declared by the macro an available only in the context created by the macro.
#define for_each_detour(_var_name)      list_for_each (gDetours.DetoursList, DETOUR, _var_name)


static INTSTATUS
IntDetDisableLixHypercall(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Disables a Linux detour hypercall.
///
/// This is done by overwriting the #LIX_GUEST_DETOUR.EnableOptions field with 0.
//
/// After this function exists, the #DETOUR.Disabled field will be set to True.
///
/// @param[in, out] Detour  The detour for which the hypercall is disabled.
///
/// @retval         #INT_STATUS_SUCCESS         On success.
/// @retval         #INT_STATUS_NOT_NEEDED_HINT If the LixGuestDetour address not valid.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (!Detour->LixFnDetour)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DETOUR] Disabling detour - Function name : %s, Hijack function name: %s\n", Detour->LixFnDetour->FunctionName,
            Detour->LixFnDetour->HijackFunctionName != NULL ? Detour->LixFnDetour->HijackFunctionName : "none");

    Detour->Disabled = TRUE;

    status = IntKernVirtMemPatchQword(Detour->LixGuestDetour + OFFSET_OF(LIX_GUEST_DETOUR, EnableOptions), 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed for GVA 0x%016llx with status: 0x%08x\n", Detour->LixGuestDetour, status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDetDisableWinHypercall(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Disables a Windows detour hypercall.
///
/// This is done by replacing the hypercall instruction with NOPs. If the hypercall type is #hypercallTypeInt3, a
/// single NOP (0x90) is used to replace the INT3 instruction. If hypercall type is #hypercallTypeVmcall, a "long"
/// NOP is used (0x66 0x66 0x90). This is done because replacing an instruction with an instruction of the same size
/// is safer.
/// After this function exists, the #DETOUR.Disabled field will be set to True.
///
/// @param[in, out] Detour  The detour for which the hypercall is disabled.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_NOT_NEEDED_HINT if the detour those not have a memory cloak handle or if the detour
///                 does not have a hypercall instruction.
///
{
    BYTE nop = 0x90;
    BYTE atomic_nop_3[3] = {0x66, 0x66, 0x90};

    if (NULL == Detour->HandlerCloakHandle)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Detour->Disabled = TRUE;

    if (Detour->HypercallOffset == DETOUR_INVALID_HYPERCALL)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    switch (Detour->HypercallType)
    {
    case hypercallTypeInt3:
        return IntMemClkModifyPatchedData(Detour->HandlerCloakHandle,
                                          Detour->HypercallOffset,
                                          sizeof(nop),
                                          &nop);

    case hypercallTypeVmcall:
        return IntMemClkModifyPatchedData(Detour->HandlerCloakHandle,
                                          Detour->HypercallOffset,
                                          sizeof(atomic_nop_3),
                                          atomic_nop_3);

    case hypercallTypeNone:
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return INT_STATUS_NOT_NEEDED_HINT;
}


static INTSTATUS
IntDetEnableHypercall(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Enables a detour hypercall.
///
/// This is done by replacing the NOPs at the hypercall offset with the proper hypercall instruction.
/// If the hypercall type is #hypercallTypeInt3 this will be a INT3 (0xCC) instruction. If the hypercall type is
/// #hypercallTypeVmcall this will be a VMCALL (0x0F 0x01 0xC1) instruction. For other hypercall types no change is
/// done.
/// After this function exists, the #DETOUR.Disabled field will be set to False.
///
/// @param[in, out] Detour  The detour for which the hypercall is disabled.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_NOT_NEEDED_HINT if the detour those not have a memory cloak handle or if the detour
///                 does not have a hypercall instruction.
///
{
    BYTE int3 = 0xCC;
    BYTE vmcall[3] = {0x0F, 0x01, 0xC1};

    if (NULL == Detour->HandlerCloakHandle)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    Detour->Disabled = FALSE;

    if (Detour->HypercallOffset == DETOUR_INVALID_HYPERCALL)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    switch (Detour->HypercallType)
    {
    case hypercallTypeInt3:
        return IntMemClkModifyPatchedData(Detour->HandlerCloakHandle,
                                          Detour->HypercallOffset,
                                          sizeof(int3),
                                          &int3);

    case hypercallTypeVmcall:
        return IntMemClkModifyPatchedData(Detour->HandlerCloakHandle,
                                          Detour->HypercallOffset,
                                          sizeof(vmcall),
                                          vmcall);

    case hypercallTypeNone:
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return INT_STATUS_NOT_NEEDED_HINT;
}


static void
IntDetRemoveBranch(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Restores the original instructions of a hooked function.
///
/// This will restore the bytes we replaced with the jump to our detour handler. It does not remove the detour
/// handler itself, but the handler will no longer be executed by the guest (unless a guest thread is currently
/// executing it).
/// It does nothing if the detour does not have a memory cloak handle for the original function.
///
/// @param[in, out] Detour  The detour for which to restore the original function. After this function returns, the
///                         FunctionCloakHandle will be set to NULL.
{
    if (NULL == Detour->FunctionCloakHandle)
    {
        return;
    }

    IntMemClkUncloakRegion(Detour->FunctionCloakHandle, MEMCLOAK_OPT_APPLY_PATCH);

    Detour->FunctionCloakHandle = NULL;
}


static void
IntDetRemoveHandler(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Removes a detour handler from the guest.
///
/// If a memory cloak handle exists for the detour handler, the original contents of that memory region will be
/// restored. Any slack space allocated for this detour will also be freed.
/// Note that the jump to the detour handler present at the beginning of the hooked function will not be removed.
/// #IntDetRemoveBranch should be called before calling this function.
/// No safeness checks are done. If a guest thread is currently running inside the detour handler or returns to it
/// the guest will be left in an unstable state.
///
/// @param[in, out] Detour  The detour for which the handler is removed. After this function returns, the fields
///                         HandlerCloakHandle and HandlerAddress will be set to NULL.
{
    if (NULL != Detour->HandlerCloakHandle)
    {
        IntMemClkUncloakRegion(Detour->HandlerCloakHandle, MEMCLOAK_OPT_APPLY_PATCH);
    }

    Detour->HandlerCloakHandle = NULL;

    if (0 != Detour->HandlerAddress)
    {
        IntSlackFree(Detour->HandlerAddress);
    }

    Detour->HandlerAddress = 0;
}


static void
IntDetRemoveDetour(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Removes and frees a detour.
///
/// This will restore the original contents of the hooked function, will remove the detour handler, and will free
/// any resources associated with this detour, including the detour itself.
/// No safeness checks are done. If a guest thread is currently running inside the detour handler or returns to it
/// the guest will be left in an unstable state.
///
/// @param[in, out] Detour  The detour to be removed. After this function returns this pointer is no longer valid.
///
/// @post           Detour is NULL.
///
{
    IntDetRemoveBranch(Detour);

    IntDetRemoveHandler(Detour);

    HpFreeAndNullWithTag(&Detour, IC_TAG_DETG);
}


static void
IntDetPermanentlyDisableDetour(
    _Inout_ DETOUR *Detour
    )
///
/// @brief          Removes a detour from the guest.
///
/// This will restore the original contents of the hooked function, will remove the detour handler, and will free
/// any resources associated with this detour, except the detour itself.
/// No safeness checks are done. If a guest thread is currently running inside the detour handler or returns to it
/// the guest will be left in an unstable state.
///
/// @param[in, out] Detour      The detour to be removed.
///
{
    IntDetRemoveBranch(Detour);

    if (gGuest.OSType == introGuestLinux)
    {
        IntDetDisableLixHypercall(Detour);
    }
    else if (gGuest.OSType == introGuestWindows)
    {
        IntDetDisableWinHypercall(Detour);
    }
}


INTSTATUS
IntDetDisableDetour(
    _In_ DETOUR_TAG Tag
    )
///
/// @brief      Disables a detour based on its tag.
///
/// After the detour is disabled, its handler will no longer issue hypercalls, but it will still be present inside
/// the guest and the guest will still execute it. If it has any side effects, those will still be visible inside
/// the guest.
///
/// @param[in]  Tag     The tag of the detour which will be disabled.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Tag is not less than #detTagMax.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if no detour exists for the given tag.
///
{
    if (gGuest.OSType == introGuestLinux)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (Tag >= detTagMax)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == gDetours.DetoursTable[Tag])
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return IntDetDisableWinHypercall(gDetours.DetoursTable[Tag]);
}


INTSTATUS
IntDetEnableDetour(
    _In_ DETOUR_TAG Tag
    )
///
/// @brief      Enables a detour based on its tag.
///
/// After the detour is enabled, its handler will start to issue hypercalls.
///
/// @param[in]  Tag     The tag of the detour which will be enabled.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Tag is not less than #detTagMax.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if no detour exists for the given tag.
///
{
    DETOUR *pDetour;

    if (Tag >= detTagMax)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pDetour = gDetours.DetoursTable[Tag];
    if (NULL == pDetour)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return IntDetEnableHypercall(pDetour);
}


static INTSTATUS
IntDetCreateObjectLix(
    _In_ QWORD FunctionAddress,
    _In_ const LIX_FN_DETOUR *FnDetour,
    _Out_ LIX_GUEST_DETOUR *DetourStruct,
    _Out_ DETOUR **Detour
    )
///
/// @brief Create a #DETOUR structure using the information from #LIX_FN_DETOUR.
///
/// @param[in]      FunctionAddress     The guest virtual address of the function to be hooked
/// @param[in]      FnDetour            Pointer to a structure that describes the hook.
/// @param[out]     DetourStruct        On success, a structure that describes the detour that is injected in guest.
/// @param[out]     Detour              On success, the #DETOUR structure used by detour-mechanism.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INSUFFICIENT_RESOURCES   If HpAllocWithTag fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DETOUR *pDetour = NULL;
    QWORD detourStructGva = gLixGuest->MmAlloc.Detour.Data.Address +  OFFSET_OF(LIX_HYPERCALL_PAGE,
                                                                    Detours) + sizeof(LIX_GUEST_DETOUR) * FnDetour->Id;

    // This reads a LIX_GUEST_DETOUR structure from the guest memory, but the region that contains the structure,
    // gLixGuest->MmAlloc.Detour.Data.Address, is protected against writes (and writes are blocked
    // even if beta is enabled).
    status = IntKernVirtMemRead(detourStructGva,
                                sizeof(LIX_GUEST_DETOUR),
                                DetourStruct,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed with status: 0x%08x\n", status);
        return status;
    }

    pDetour = HpAllocWithTag(sizeof(*pDetour), IC_TAG_DETG);
    if (NULL == pDetour)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pDetour->Callback = FnDetour->Callback;
    pDetour->FunctionAddress = FunctionAddress;
    pDetour->HypercallType = hypercallTypeVmcall;
    pDetour->HandlerAddress = gLixGuest->MmAlloc.Detour.Data.Address + DetourStruct->Address;
    pDetour->RelocatedCodeOffset = (BYTE)(DetourStruct->RelocatedCode - DetourStruct->Address);
    pDetour->RelocatedCodeLength = 0;
    pDetour->LixGuestDetour = detourStructGva;
    pDetour->LixFnDetour = FnDetour;

    *Detour = pDetour;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDetRelocate(
    _In_ DETOUR *Detour,
    _In_ BYTE *FunctionCode,
    _In_ DWORD FunctionSize,
    _Out_opt_ DWORD *InstrCount
    )
///
/// @brief Relocate the over-written instruction from detoured function.
///
/// This function relocate at least 5 bytes from the provided FunctionCode; the length of the relocated code may be
/// larger only if the first instructions of the function has a length grater than 5 bytes.
/// If the decoded instruction is rip-relative, the supported instructions are 'CALL', 'JMP', 'MOV', 'CMP' and 'JMP';
/// for these instruction the relative address is computed to our handler-address. If the decoded instruction is not
/// rip-relative, every byte of it is copied to the out handler-address.
///
/// @param[in]      Detour          The structure that describes a detour.
/// @param[in]      FunctionCode    A buffer that contains the first FunctionSize bytes of detoured function.
/// @param[in]      FunctionSize    The size of the FunctionCode buffer.
/// @param[in, out] InstrCount      The number of the relocated instructions.
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_SUPPORTED    If an instruction of the function is nut supported.
///
{
    INTSTATUS status;
    INSTRUX instrux;
    BYTE handler[DETOUR_MAX_HANDLER_SIZE] = {0};
    BYTE prologueSize = 0;

    QWORD handlerAddress = Detour->HandlerAddress;
    DWORD handlerSize = DETOUR_MAX_HANDLER_SIZE;

    if (InstrCount)
    {
        *InstrCount = 0;
    }

    status = IntKernVirtMemRead(handlerAddress, handlerSize, handler, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed with status: 0x%08x\n", status);
        return status;
    }

    while (prologueSize < 5)
    {
        BOOLEAN relInstr = FALSE;

        status = IntDecDecodeInstructionFromBuffer(FunctionCode + prologueSize,
                                                   FunctionSize - prologueSize,
                                                   gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B,
                                                   &instrux);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        if (InstrCount)
        {
            *InstrCount += 1;
        }

        relInstr = NdIsInstruxRipRelative(&instrux);

        if (relInstr)
        {
            if ((instrux.PrimaryOpCode != 0xe8) &&      // CALL
                (instrux.PrimaryOpCode != 0xe9) &&      // JMP
                (instrux.PrimaryOpCode != 0x89) &&      // MOV
                (instrux.PrimaryOpCode != 0x8b) &&      // MOV
                (instrux.PrimaryOpCode != 0x80) &&      // CMP
                (instrux.Instruction != ND_INS_Jcc || instrux.Length != 6))
            {
                WARNING("[WARNING] RIP relative found at GVA 0x%016llx, can't continue!\n",
                        Detour->FunctionAddress + prologueSize);
                IntDumpInstruction(&instrux, Detour->FunctionAddress + prologueSize);

                return INT_STATUS_NOT_SUPPORTED;
            }
        }

        if (instrux.PrimaryOpCode == 0xe8 || instrux.PrimaryOpCode == 0xe9)
        {
            QWORD calledFunc;
            DWORD patched;

            calledFunc = Detour->FunctionAddress + prologueSize +
                SIGN_EX(instrux.RelOffsLength, instrux.RelativeOffset);

            patched = (DWORD)(calledFunc - (handlerAddress + Detour->RelocatedCodeOffset + prologueSize));
            handler[Detour->RelocatedCodeOffset + prologueSize] = instrux.PrimaryOpCode;

            memcpy(handler + Detour->RelocatedCodeOffset + prologueSize + 1, &patched, 4);
        }
        else if (relInstr && (instrux.PrimaryOpCode == 0x8b || instrux.PrimaryOpCode == 0x89))
        {
            DWORD relOp = (instrux.Operands[0].Type == ND_OP_MEM) ? 0 : 1;

            QWORD movGva = Detour->FunctionAddress + prologueSize +
                SIGN_EX(4, instrux.Operands[relOp].Info.Memory.Disp);

            DWORD patched = (DWORD)(movGva - (handlerAddress + Detour->RelocatedCodeOffset + prologueSize));

            if (instrux.Rex.Rex != 0)
            {
                handler[Detour->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
                handler[Detour->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];
                handler[Detour->RelocatedCodeOffset + prologueSize + 2] = instrux.InstructionBytes[2];

                memcpy(handler + Detour->RelocatedCodeOffset + prologueSize + 3, &patched, 4);
            }
            else
            {
                handler[Detour->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
                handler[Detour->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];

                memcpy(handler + Detour->RelocatedCodeOffset + prologueSize + 2, &patched, 4);
            }
        }
        else if (relInstr && instrux.PrimaryOpCode == 0x80)
        {
            DWORD relOp = (instrux.Operands[0].Type == ND_OP_MEM) ? 0 : 1;

            QWORD cmpGva = Detour->FunctionAddress + prologueSize +
                SIGN_EX(4, instrux.Operands[relOp].Info.Memory.Disp);

            DWORD patched = (DWORD)(cmpGva - (handlerAddress + Detour->RelocatedCodeOffset + prologueSize));

            handler[Detour->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
            handler[Detour->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];

            memcpy(handler + Detour->RelocatedCodeOffset + prologueSize + 2, &patched, 4);

            handler[Detour->RelocatedCodeOffset + prologueSize + 6] = instrux.InstructionBytes[6];
        }
        else if (relInstr && instrux.Instruction == ND_INS_Jcc)
        {
            QWORD target = Detour->FunctionAddress + instrux.Operands[0].Info.RelativeOffset.Rel;
            DWORD newRel = (DWORD)(target - (handlerAddress + Detour->RelocatedCodeOffset));

            // Translate the old JMP into the new JMP. We make it long and we modify the relative offset so that it
            // points to the same address. Important note: we must make sure that the target is NOT inside the
            // relocated code, otherwise we need to do some more black magic.
            handler[Detour->RelocatedCodeOffset + prologueSize] = 0x0F;
            handler[Detour->RelocatedCodeOffset + prologueSize + 1] = 0x80 | instrux.Predicate;

            memcpy(handler + Detour->RelocatedCodeOffset + prologueSize + 2, &newRel, 4);
        }
        else
        {
            // Copy the current instruction inside the detour handler
            memcpy(handler + Detour->RelocatedCodeOffset + prologueSize, FunctionCode + prologueSize, instrux.Length);
        }

        prologueSize += instrux.Length;
    }

    status = IntVirtMemWrite(handlerAddress, handlerSize, gGuest.Mm.SystemCr3, handler);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemWrite failed with status: 0x%x.", status);
        return status;
    }

    Detour->RelocatedCodeLength = prologueSize;

    return INT_STATUS_SUCCESS;
}


static DETOUR *
IntDetFindByTag(
    _In_ DETOUR_TAG Tag
    )
///
/// @brief  Searches a detour by its tag.
///
/// @param[in]  Tag     The tag of the detour.
///
/// @returns    A pointer to a #DETOUR structure for the given tag, if it exists.
///
{
    if (Tag >= detTagMax)
    {
        return NULL;
    }

    return gDetours.DetoursTable[Tag];
}


static INTSTATUS
IntDetHandleWrite(
    _In_ void *Hook,
    _In_ QWORD PhysicalAddress,
    _In_ QWORD RegionVirtualAddress,
    _In_ void *CloakHandle,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handle the writes over bytes modified from detoured function.
///
/// Allow the write only if the originator is an active patch (ftrace or text_poke).
///
/// If the write is allowed the content of the active patch is relocated inside our detour-handler
///
/// @param[in]      Hook                    The hook object for which this callback was invoked.
/// @param[in]      PhysicalAddress         The modified guest physical address.
/// @param[in]      RegionVirtualAddress    The modified guest virtual address.
/// @param[in]      CloakHandle             The memcloak object for which this callback was invoked.
/// @param[out]     Action                  The taken action.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If Hook is invalid.
/// @retval     INT_STATUS_INVALID_PARAMETER_4      If CloakHandle is invalid.
/// @retval     INT_STATUS_INVALID_PARAMETER_6      If Action is invalid.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD regionOffset;
    BOOLEAN relocateAfter;
    INTRO_ACTION action = introGuestNotAllowed;
    BYTE *memcloakData = NULL;
    DWORD memcloakDataSize;
    LIX_ACTIVE_PATCH *pActivePatch = NULL;

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == CloakHandle)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    // We will handle and emulate the write instead of allowing it. Even if we fail, the guest still shouldn't
    // be allowed to perform any writes inside our detours.
    *Action = introGuestNotAllowed;

    if (gGuest.OSType != introGuestLinux)
    {
        ERROR("[ERROR] Detour writes are not being handled on this OS!");
        return INT_STATUS_NOT_SUPPORTED;
    }

    for (DWORD index = 0; index < ARRAYSIZE(gLixGuest->ActivePatch); index++)
    {
        status = IntLixDrvIsLegitimateTextPoke(Hook, PhysicalAddress, &gLixGuest->ActivePatch[index], &action);
        if (INT_SUCCESS(status))
        {
            pActivePatch = &gLixGuest->ActivePatch[index];
            break;
        }
    }

    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntLixDrvIsLegitimateTextPoke failed for address 0x%llx. Status: 0x%08x\n",
                PhysicalAddress, status);
        return status;
    }

    if (action != introGuestAllowed)
    {
        ERROR("[ERROR] The guest attempted to perform a write inside detour %d with a non-legitimate "
              "text poke. Will deny!", pActivePatch->DetourTag);
        return INT_STATUS_SUCCESS;
    }

    if (!pActivePatch->IsDetour)
    {
        ERROR("[ERROR] Detour write handler called, but the ActivePatch is not inside a detour! 0x%llx (+%d)\n",
              pActivePatch->Gva, pActivePatch->Length);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // At this point the patch is legitimate and we should handle it.

    status = IntMemClkGetOriginalData(CloakHandle, &memcloakData, &memcloakDataSize);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkGetOriginalData failed: 0x%08x\n", status);
        return status;
    }

    regionOffset = (DWORD)(pActivePatch->Gva - RegionVirtualAddress);

    WARNING("[WARNING] The guest is applying a patch with size %d at 0x%llx (+ %d).\n",
            pActivePatch->Length, RegionVirtualAddress, regionOffset);

    // Basically, we are checking if this write tries to overwrite the 0xCC, which means that
    // the poke is completed and we should attempt to update the relocated code inside our detour handler.
    relocateAfter = (pActivePatch->Length == 1);
    relocateAfter = relocateAfter && (RegionVirtualAddress == pActivePatch->Gva);
    relocateAfter = relocateAfter && (memcloakData[regionOffset] == 0xCC);

    // This is just a safety measure in case this function will be called twice for the same write.
    // 99% this is happening on KVM or if the write is at a page boundary.
    relocateAfter = relocateAfter && (pActivePatch->Data[0] != 0xCC);

    // This way we are tricking the guest into thinking that the write was actually performed.
    status = IntMemClkModifyOriginalData(CloakHandle,
                                         regionOffset,
                                         pActivePatch->Length,
                                         pActivePatch->Data);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkModifyPatchedData failed with status 0x%08x\n", status);
        return status;
    }

    TRACE("[INFO] Updated memcloak original buffer at 0x%llx. Size: %d\n. ",
          pActivePatch->Gva, pActivePatch->Length);

    if (relocateAfter)
    {
        DETOUR *pDet = IntDetFindByTag(pActivePatch->DetourTag);

        // Here we should call this again because the memcloak buffer may have been changed since the last  call
        status = IntMemClkGetOriginalData(CloakHandle, &memcloakData, &memcloakDataSize);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkGetOriginalData failed: 0x%08x\n", status);
            return INT_STATUS_SUCCESS;
        }

        if (memcloakDataSize < pDet->RelocatedCodeLength)
        {
            // This should never ever happen.
            BUG_ON(TRUE);

            ERROR("[ERROR] Cloaked region size for detour %d is smaller than the relocated code length (%d vs %d)!\n",
                  pDet->Tag, memcloakDataSize, pDet->RelocatedCodeLength);

            return INT_STATUS_SUCCESS;
        }

        IntPauseVcpus();

        status = IntDetRelocate(pDet, memcloakData, pDet->RelocatedCodeLength, NULL);
        if (!INT_SUCCESS(status))
        {
            // Not that big of a problem, the relocated code inside our detour handler will not be updated.
            ERROR("[ERROR] Failed to relocate patch for detour %d. Status: 0x%08x\n\n",
                  pActivePatch->DetourTag, status);
        }

        IntResumeVcpus();

        IntDisasmGva(pDet->HandlerAddress, pDet->HandlerSize);
        IntDisasmBuffer(memcloakData, pDet->RelocatedCodeLength, pDet->FunctionAddress);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDetPatchFunction(
    _In_ DETOUR *Detour,
    _In_ BYTE *FunctionCode,
    _In_ DWORD FunctionSize
    )
///
/// @brief Patch the first instruction of the function with a 'JMP' to our handler.
///
/// This function over-write the first 5 bytes from the function with a rip-relative 'JMP' instruction to our handler
/// and if the relocated code is larger than 5 bytes, the function over-writes (Detour->RelocatedCodeLength - 5) bytes
/// with 'NOP' instructions.
///
/// Memory cloaking (see @ref group_memclk) will be used to hide the pieces of code modified during this
/// process.
///
/// @param[in]      Detour          The structure that describes a detour.
/// @param[in]      FunctionCode    A buffer that contains the first FunctionSize bytes of detoured function.
/// @param[in]      FunctionSize    The size of the FunctionCode buffer.
///
/// @retval     INT_STATUS_SUCCESS          On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BYTE functionDetour[DETOUR_MAX_FUNCTION_SIZE] = {0};
    QWORD handlerAddress = 0;

    UNREFERENCED_PARAMETER(FunctionSize);

    handlerAddress = Detour->HandlerAddress;

    functionDetour[0] = 0xE9;
    *(DWORD *)(functionDetour + 1) = (DWORD)(handlerAddress - (Detour->FunctionAddress + 5));

    for (DWORD i = 5; i < Detour->RelocatedCodeLength; i++)
    {
        functionDetour[i] = 0x90;
    }

    status = IntMemClkCloakRegion(Detour->FunctionAddress,
                                  0,
                                  Detour->RelocatedCodeLength,
                                  MEMCLOAK_OPT_APPLY_PATCH,
                                  FunctionCode,
                                  functionDetour,
                                  IntDetHandleWrite,
                                  &Detour->FunctionCloakHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloackRegion failed: 0x%08x\n", status);
        goto _exit;
    }

    return INT_STATUS_SUCCESS;

_exit:
    return status;
}


static INTSTATUS
IntDetSendIntegrityAlert(
    _In_ char *FunctionName,
    _In_ QWORD FunctionAddress,
    _In_ QWORD DetourAddress
    )
///
/// @brief Sends an integrity alert if the provieded function is already hooked.
///
/// @param[in]  FunctionName    The name of the hooked function.
/// @param[in]  FunctionAddress The guest virtual address of the function.
/// @param[in]  DetourAddress   The guest virtual address to which the function is detoured.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_INTEGRITY_VIOLATION *pEvent = &gAlert.Integrity;
    KERNEL_DRIVER *pDriver = NULL;

    memzero(pEvent, sizeof(*pEvent));

    pEvent->Header.Action = introGuestAllowed;
    pEvent->Header.Reason = introReasonAllowed;
    pEvent->Header.MitreID = idHooking;

    pEvent->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

    IntAlertFillVersionInfo(&pEvent->Header);
    IntAlertFillCpuContext(FALSE, &pEvent->Header.CpuContext);

    pDriver = IntDriverFindByAddress(DetourAddress);
    if (pDriver)
    {
        if (gGuest.OSType == introGuestWindows)
        {
            IntAlertFillWinKmModule(pDriver, &pEvent->Originator.Module);
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            IntAlertFillLixKmModule(pDriver, &pEvent->Originator.Module);
        }
    }

    pEvent->Header.CpuContext.Valid = FALSE;
    pEvent->Victim.Type = introObjectTypeHookedFunction;

    utf8toutf16(pEvent->Victim.Name, FunctionName, MIN(sizeof(pEvent->Victim.Name), (DWORD)strlen(FunctionName)));

    pEvent->BaseAddress = FunctionAddress;
    pEvent->VirtualAddress = FunctionAddress;
    pEvent->Size = gGuest.WordSize;

    pEvent->WriteInfo.Size = gGuest.WordSize;
    pEvent->WriteInfo.NewValue[0] = DetourAddress;

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDetSetLixHook(
    _In_ QWORD FunctionAddress,
    _In_ const LIX_FN_DETOUR *FnDetour,
    _Out_ BOOLEAN *MultipleInstructions
    )
///
/// @brief Detours a function from guest.
///
/// The detours content are injected in guest by the 'init' agent (see #IntLixGuestAllocateDeploy).
/// Each detour has one structure of type #LIX_GUEST_DETOUR assigned; #LIX_GUEST_DETOUR structures is ordered  by the
/// #DETOUR_ID enum.
///
/// The function fetches the #LIX_GUEST_DETOUR structure (index-based) and fill the FunctionAddress field with the
/// original function address plus the length of the relocated code.
///
/// The EnableFlags is used by each detour (in guest) to check if the hypercall is enabled.
///
/// The over-written code from original function is relocated by calling the #IntDetRelocate function and the 'JMP'
/// instruction that detours the function is set calling the #IntDetPatchFunction function.
///
/// @param[in]      FunctionAddress         The guest virtual address of the function to be hooked
/// @param[in]      FnDetour                Pointer to a structure that describes the hook.
/// @param[out]     MultipleInstructions    On success, true if multiple instruction is over-written, otherwise false.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If FunctionAddress is invalid.
/// @retval     INT_STATUS_INVALID_PARAMETER_2      If FnDetour is invalid.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DETOUR *pDetour = NULL;
    LIX_GUEST_DETOUR detourStruct = { 0 };
    DWORD relInstrCount = 0;
    BYTE functionCode[DETOUR_MAX_FUNCTION_SIZE] = {0};

    if (FunctionAddress == 0)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (FnDetour == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntKernVirtMemRead(FunctionAddress, sizeof(functionCode), functionCode, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed with status: 0x%08x\n", status);
        return status;
    }

    if (functionCode[0] == 0xE9 || functionCode[0] == 0xE8)
    {
        QWORD addr = FunctionAddress + SIGN_EX_32(*(DWORD *)&functionCode[1]) + 5;

        IntDetSendIntegrityAlert(FnDetour->FunctionName, FunctionAddress, addr);

        WARNING("[WARNING] API function already detoured (0x%016llx) by kprobe/live-patch!\n", addr);
    }

    status = IntDetCreateObjectLix(FunctionAddress, FnDetour, &detourStruct, &pDetour);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetCreateObjectLix failed with status: 0x%08x.", status);
        return status;
    }

    status = IntDetRelocate(pDetour, functionCode, sizeof(functionCode), &relInstrCount);
    if (!INT_SUCCESS(status))
    {
        ERROR("[WARNING] IntDetRelocate failed with status: 0x%08x.", status);
        goto _exit;
    }

    *MultipleInstructions = FALSE;
    if (relInstrCount > 1)
    {
        *MultipleInstructions = TRUE;
    }

    status = IntDetPatchFunction(pDetour, functionCode, sizeof(functionCode));
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetPatchFunction failed with status: 0x%08x.", status);
        goto _exit;
    }

    detourStruct.EnableOptions = FnDetour->EnableFlags;
    detourStruct.JumpBack = FunctionAddress + pDetour->RelocatedCodeLength;

    // The written area is protected, so no need to use IntVirtMemSafeWrite.
    status = IntKernVirtMemWrite(pDetour->LixGuestDetour, sizeof(detourStruct), &detourStruct);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed with status: 0x%08x\n", status);
        goto _exit;
    }

    InsertTailList(&gDetours.DetoursList, &pDetour->Link);

    gDetours.LixDetourTable[FnDetour->Id] = pDetour;

    LOG("[DETOUR] %llx: handler @ %llx (%s)\n",
        pDetour->FunctionAddress, pDetour->HandlerAddress, FnDetour->FunctionName);

    status = INT_STATUS_SUCCESS;

_exit:
    if (!INT_SUCCESS(status) && (NULL != pDetour))
    {
        IntDetRemoveDetour(pDetour);
    }

    return status;
}


INTSTATUS
IntDetSetHook(
    _In_ QWORD FunctionAddress,
    _In_ QWORD ModuleBase,
    _Inout_ API_HOOK_DESCRIPTOR *Descriptor,
    _Inout_ API_HOOK_HANDLER *Handler
    )
///
/// @brief      Will inject code inside the guest.
///
/// This function will inject a piece of code (the detour handler) inside the guest virtual address space.
/// This can be used to hook a function, but it is not mandatory for this to be a classic function hook.
/// When hooking a function, it will replace at least the first 5 bytes from FunctionAddress with a jump to the
/// hook handler. At least 5 bytes are replaced because that is the size of the injected jump, but more bytes may
/// be replaced if the instructions over-written inside the guest have a larger total length. The original instructions
/// will be relocated after the detour handler and will be followed by a jump back to the remaining function body. If
/// the original instructions are RIP-relative the function will fail.
///
/// In order to find a place for the detour handler inside the module in which the hook function resides, the
/// slack.c functionality is used. If no specific API is hooked, the detour will be placed inside the core guest
/// kernel module.
///
/// Memory cloaking (see @ref group_memclk) will be used to hide the pieces of code modified and injected during this
/// process.
///
/// Errors encountered for Descriptors that have the NotCritical field set to False are treated as fatal errors and
/// introcore will be stopped.
///
/// If a pre- or post-hook callback exists in the Descriptor it is called. The pre-hook callback is called before
/// the hook is written inside the guest. If it returns #INT_STATUS_NOT_NEEDED_HINT, the hook is no longer set, even
/// if it is a critical hook and this is not treated as an error. If an error is returned, the hook will no longer be
/// set, but if the hook is critical this will be treated as an error to set the hook. The post-hook callback return
/// value is ignored.
///
/// A detour successfully set can be found in the #gDetours list of detours.
///
/// @param[in]  FunctionAddress     The guest virtual address of the function to be hooked. Can be 0, in which case
///                                 no function will be hooked, but the detour will still be injected inside the
///                                 guest.
/// @param[in]  ModuleBase          The guest virtual address of the module in which the detour should be placed. If
///                                 a function is hooked this should be the module that owns that function. If 0
///                                 the kernel module will be used.
/// @param[in]  Descriptor          Pointer to a structure that describes the hook and the detour handler.
/// @param[in]  Handler             The descriptor of the detour handler to be injected inside the guest.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Descriptor is NULL or if its tag is not less than #detTagMax.
/// @retval     #INT_STATUS_BUFFER_OVERFLOW if the function hooked is inside the Windows kernel, but its address
///             points outside the kernel buffer.
/// @retval     #INT_STATUS_NOT_SUPPORTED if the function is already hooked. This is detected by checking if the
///             function starts with a 0xE9 (a JMP instruction). This means that we already hooked this function, and
///             hooking it again is an error, or a driver inside the guest hooked it, in which case the kernel can
///             not be trusted and it may be already compromised. The same status value is returned if the total
///             size of the handler (including the relocated instructions) is larger than #DETOUR_MAX_HANDLER_SIZE.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available.
///
{
    INTSTATUS status;
    DETOUR *pDetour;
    INSTRUX instrux;
    BYTE origFn[DETOUR_MAX_FUNCTION_SIZE], newFn[DETOUR_MAX_FUNCTION_SIZE];
    BYTE origHnd[DETOUR_MAX_HANDLER_SIZE], newHnd[DETOUR_MAX_HANDLER_SIZE];
    DWORD prologueSize, newJumpBackOffset, totalHandlerSize, i;

    prologueSize = 0;

    if (NULL == Descriptor)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Descriptor->Tag >= detTagMax)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Handler)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (0 == ModuleBase)
    {
        ModuleBase = gGuest.KernelVa;
    }

    if (FunctionAddress)
    {
        //
        // Get the original function code (from the kernel buffer if we have that)
        //
        if ((gGuest.OSType == introGuestWindows) && (ModuleBase == gGuest.KernelVa))
        {
            DWORD funOffset = (DWORD)(FunctionAddress - ModuleBase);

            if (funOffset + sizeof(origFn) > gWinGuest->KernelBufferSize)
            {
                ERROR("[ERROR] Function not inside kernel buffer. Offset: 0x%08x, size: 0x%08zx, buffer size: 0x%08x\n",
                      funOffset, sizeof(origFn), gWinGuest->KernelBufferSize);
                return INT_STATUS_BUFFER_OVERFLOW;
            }

            memcpy(origFn, gWinGuest->KernelBuffer + funOffset, sizeof(origFn));
        }
        else
        {
            status = IntKernVirtMemRead(FunctionAddress, sizeof(origFn), origFn, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
                return status;
            }
        }

        // If the function is already hooked, leave.
        if (origFn[0] == 0xE9)
        {
            QWORD addr = FunctionAddress + SIGN_EX_32(*(DWORD *)&origFn[1]) + 5;

            IntDetSendIntegrityAlert(Descriptor->FunctionName, FunctionAddress, addr);

            WARNING("[INFO] API function already detoured (0x%016llx), don't know by who! Aborting!\n", addr);
            return INT_STATUS_NOT_SUPPORTED;
        }

        // Compute the size of the prologue. We need this before actually parsing the prologue in order to know how
        // much slack to allocate.
        while (prologueSize < 5)
        {
            status = IntDecDecodeInstructionFromBuffer(origFn + prologueSize,
                                                       sizeof(origFn) - prologueSize,
                                                       gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B,
                                                       &instrux);
            if (!INT_SUCCESS(status))
            {
                return status;
            }

            prologueSize += instrux.Length;
        }
    }

    totalHandlerSize = Handler->CodeLength + prologueSize;

    if (sizeof(newHnd) < totalHandlerSize)
    {
        ERROR("[ERROR] The size of the handler exceeds %zu bytes: %d!\n", sizeof(newHnd), totalHandlerSize);
        return INT_STATUS_NOT_SUPPORTED;
    }

    pDetour = HpAllocWithTag(sizeof(*pDetour), IC_TAG_DETG);
    if (NULL == pDetour)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntSlackAlloc(ModuleBase, FALSE, totalHandlerSize, &pDetour->HandlerAddress, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSlackAlloc failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (NULL != Descriptor->PreCallback)
    {
        status = Descriptor->PreCallback(FunctionAddress, Handler, Descriptor);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] PreCallback for hook %d (`%s!%s`) failed: 0x%08x\n",
                  Descriptor->Tag, utf16_for_log(Descriptor->ModuleName), Descriptor->FunctionName, status);
            goto cleanup_and_exit;
        }
        else if (INT_STATUS_NOT_NEEDED_HINT == status)
        {
            LOG("[INFO] PreCallback for hook %d (`%s!%s`) returned NOT NEEDED. Will skip the hook (critical: %d)\n",
                Descriptor->Tag,
                utf16_for_log(Descriptor->ModuleName),
                Descriptor->FunctionName,
                !Descriptor->NotCritical);

            goto cleanup_and_exit;
        }
    }

    status = IntKernVirtMemRead(pDetour->HandlerAddress, totalHandlerSize, origHnd, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    memcpy(newHnd, Handler->Code, totalHandlerSize - prologueSize);

    if (0 == FunctionAddress)
    {
        goto _no_function;
    }

    // Clone the modified bytes inside the handler code. We need to relocate minimum 5 bytes
    prologueSize = 0;
    while (prologueSize < 5)
    {
        BOOLEAN relInstr = FALSE;

        status = IntDecDecodeInstructionFromBuffer(origFn + prologueSize,
                                                   sizeof(origFn) - prologueSize,
                                                   gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B,
                                                   &instrux);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        relInstr = NdIsInstruxRipRelative(&instrux);

        if (relInstr)
        {
            if ((instrux.PrimaryOpCode != 0xe8) &&      // CALL
                (instrux.PrimaryOpCode != 0x89) &&      // MOV
                (instrux.PrimaryOpCode != 0x8b) &&      // MOV
                (instrux.PrimaryOpCode != 0x80) &&      // CMP
                (instrux.PrimaryOpCode != 0x63) &&      // MOVSXD
                (instrux.Instruction != ND_INS_Jcc || instrux.Length != 6))
            {
                CHAR insText[ND_MIN_BUF_SIZE] = {0};

                NdToText(&instrux, FunctionAddress + prologueSize, sizeof(insText), insText);

                WARNING("[WARNING] RIP relative instruction '%s' found at GVA 0x%016llx, can't continue!\n",
                        insText, FunctionAddress + prologueSize);
                IntDumpInstruction(&instrux, FunctionAddress + prologueSize);

                status = INT_STATUS_NOT_SUPPORTED;
                goto cleanup_and_exit;
            }
        }

        if (instrux.PrimaryOpCode == 0xe8)
        {
            QWORD calledFunc = FunctionAddress + prologueSize + SIGN_EX(instrux.RelOffsLength, instrux.RelativeOffset);

            DWORD patched = (DWORD)(calledFunc -
                (pDetour->HandlerAddress + Handler->RelocatedCodeOffset + prologueSize));

            newHnd[Handler->RelocatedCodeOffset + prologueSize] = 0xe8;
            memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 1, &patched, 4);
        }
        else if (relInstr && (instrux.PrimaryOpCode == 0x8b || instrux.PrimaryOpCode == 0x89))
        {
            DWORD relOp = (instrux.Operands[0].Type == ND_OP_MEM) ? 0 : 1;

            QWORD movGva = FunctionAddress + prologueSize + SIGN_EX(4, instrux.Operands[relOp].Info.Memory.Disp);
            DWORD patched = (DWORD)(movGva - (pDetour->HandlerAddress + Handler->RelocatedCodeOffset + prologueSize));

            if (instrux.Rex.Rex != 0)
            {
                newHnd[Handler->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
                newHnd[Handler->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];
                newHnd[Handler->RelocatedCodeOffset + prologueSize + 2] = instrux.InstructionBytes[2];

                memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 3, &patched, 4);
            }
            else
            {
                newHnd[Handler->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
                newHnd[Handler->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];

                memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 2, &patched, 4);
            }
        }
        else if (relInstr && instrux.PrimaryOpCode == 0x80)
        {
            DWORD relOp = (instrux.Operands[0].Type == ND_OP_MEM) ? 0 : 1;

            QWORD cmpGva = FunctionAddress + prologueSize + SIGN_EX(4, instrux.Operands[relOp].Info.Memory.Disp);
            DWORD patched = (DWORD)(cmpGva - (pDetour->HandlerAddress + Handler->RelocatedCodeOffset + prologueSize));

            newHnd[Handler->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
            newHnd[Handler->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];

            memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 2, &patched, 4);

            newHnd[Handler->RelocatedCodeOffset + prologueSize + 6] = instrux.InstructionBytes[6];
        }
        else if (relInstr && instrux.Instruction == ND_INS_Jcc)
        {
            QWORD target = FunctionAddress + instrux.Operands[0].Info.RelativeOffset.Rel;
            DWORD newRel = (DWORD)(target - (pDetour->HandlerAddress + Handler->RelocatedCodeOffset));

            // Translate the old JMP into the new JMP. We make it long and we modify the relative offset so that it
            // points to the same address. Important note: we must make sure that the target is NOT inside the
            // relocated code, otherwise we need to do some more black magic.
            newHnd[Handler->RelocatedCodeOffset + prologueSize] = 0x0F;
            newHnd[Handler->RelocatedCodeOffset + prologueSize + 1] = 0x80 | instrux.Predicate;

            memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 2, &newRel, 4);
        }
        else if (relInstr && instrux.PrimaryOpCode == 0x63)
        {
            DWORD relOp = (instrux.Operands[0].Type == ND_OP_MEM) ? 0 : 1;
            QWORD crtInstruxGva = FunctionAddress + prologueSize + SIGN_EX(4, instrux.Operands[relOp].Info.Memory.Disp);
            DWORD crtInstruxPatch = (DWORD)(crtInstruxGva - (pDetour->HandlerAddress + Handler->RelocatedCodeOffset +
                                                             prologueSize));

            if (instrux.Rex.Rex != 0)
            {
                newHnd[Handler->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
                newHnd[Handler->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];
                newHnd[Handler->RelocatedCodeOffset + prologueSize + 2] = instrux.InstructionBytes[2];


                memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 3, &crtInstruxPatch, 4);
            }
            else
            {
                newHnd[Handler->RelocatedCodeOffset + prologueSize] = instrux.InstructionBytes[0];
                newHnd[Handler->RelocatedCodeOffset + prologueSize + 1] = instrux.InstructionBytes[1];

                memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize + 2, &crtInstruxPatch, 4);
            }
        }
        else
        {
            // Copy the current instruction inside the detour handler
            memcpy(newHnd + Handler->RelocatedCodeOffset + prologueSize, origFn + prologueSize, instrux.Length);
        }

        prologueSize += instrux.Length;
    }

    // Patch the jump from the handler code. Note that the jump address inside the handler code is
    // variable. The fact that the MAX_PROLOGUE_SIZE is defined to 8 bytes is just a template. The
    // actual layout of the handler code once injected inside the guest is variable. The JMP back
    // will be located immediately after the prologue, be it 5 or 20 bytes in length.
    newJumpBackOffset = Handler->RelocatedCodeOffset + prologueSize;

    // Set the JMP opcode.
    *(newHnd + newJumpBackOffset) = 0xE9;

    *(DWORD *)(newHnd + newJumpBackOffset + 1) = (DWORD)((FunctionAddress + 5) - (pDetour->HandlerAddress +
                                                                                  newJumpBackOffset + 5));

    // Now re-patch the jump from handler code to jump after the whole prologue (and don't execute the NOP)
    *(DWORD *)(newHnd + newJumpBackOffset + 1) += prologueSize - 5;

    // Set a jmp handler
    newFn[0] = 0xE9;
    *(DWORD *)(newFn + 1) = (DWORD)(pDetour->HandlerAddress - (FunctionAddress + 5));

    for (i = 5; i < prologueSize; i++)
    {
        newFn[i] = 0x90;
    }

_no_function:

    pDetour->Tag = Descriptor->Tag;
    // This can be NULL! We can have dummy handlers/handlers that don't issue hypercalls.
    pDetour->Callback = Descriptor->Callback;
    pDetour->HandlerSize = totalHandlerSize;
    pDetour->FunctionAddress = FunctionAddress;
    // The hypercall can be missing from the handler, in which case the HypercallAddress will be 0.
    pDetour->HypercallAddress = (Handler->HypercallOffset == DETOUR_INVALID_HYPERCALL) ? 0 : pDetour->HandlerAddress +
                                Handler->HypercallOffset;
    pDetour->HypercallOffset = Handler->HypercallOffset;
    pDetour->ModuleBase = ModuleBase;
    pDetour->HypercallType = Handler->HypercallType;
    pDetour->JumpBackOffset = Handler->RelocatedCodeOffset + (BYTE)prologueSize;
    pDetour->RelocatedCodeOffset = Handler->RelocatedCodeOffset;
    pDetour->RelocatedCodeLength = (BYTE)prologueSize;

    memcpy(pDetour->PublicDataOffsets, Handler->PublicDataOffsets,
           sizeof(API_HOOK_PUBLIC_DATA) * Handler->NrPublicDataOffsets);
    pDetour->NrPublicDataOffsets = Handler->NrPublicDataOffsets;

    pDetour->Descriptor = Descriptor;

    status = IntMemClkCloakRegion(pDetour->HandlerAddress,
                                  0,
                                  pDetour->HandlerSize,
                                  MEMCLOAK_OPT_APPLY_PATCH,
                                  origHnd,
                                  newHnd,
                                  NULL,
                                  &pDetour->HandlerCloakHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloackRegion failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (FunctionAddress)
    {
        status = IntMemClkCloakRegion(pDetour->FunctionAddress,
                                      0,
                                      pDetour->RelocatedCodeLength,
                                      MEMCLOAK_OPT_APPLY_PATCH,
                                      origFn,
                                      newFn,
                                      NULL,
                                      &pDetour->FunctionCloakHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkCloackRegion failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    // Add thew new detour to the list.
    InsertTailList(&gDetours.DetoursList, &pDetour->Link);

    gDetours.DetoursTable[pDetour->Tag] = pDetour;

    TRACE("[DETOUR] Hooked function @ 0x%016llx, handler @ 0x%016llx, hypercall @ 0x%016llx\n",
          pDetour->FunctionAddress, pDetour->HandlerAddress, pDetour->HypercallAddress);

    // This just checks if the current detour overlaps with the SSDT somehow...
    if ((gGuest.OSType == introGuestWindows) && gWinGuest->Ssdt && gWinGuest->NumberOfServices)
    {
        QWORD start = gWinGuest->Ssdt & PAGE_MASK;
        // Multiply the number of services by 4 because on 32-bit kernels the SSDT contains pointers, while on
        // 64-bit kernels it contains offsets inside the kernel image.
        QWORD end = start + gWinGuest->NumberOfServices * 4ull;

        end = ALIGN_UP(end, PAGE_SIZE);

        TRACE("[INFO] Will ensure that SSDT isn't in our detours!\n");

        if (IN_RANGE(pDetour->FunctionAddress, start, end) ||
            IN_RANGE(pDetour->FunctionAddress + pDetour->RelocatedCodeLength, start, end))
        {
            WARNING("[WARNING] SSDT 0x%016llx (%d services) is in the same page (function) as detour %d \n",
                    gWinGuest->Ssdt, gWinGuest->NumberOfServices, pDetour->Tag);
        }

        if (IN_RANGE(pDetour->HandlerAddress, start, end) ||
            IN_RANGE(pDetour->HandlerAddress + pDetour->HandlerSize, start, end))
        {
            WARNING("[WARNING] SSDT 0x%016llx (%d services) is in the same page (handler) as detour %d \n",
                    gWinGuest->Ssdt, gWinGuest->NumberOfServices, pDetour->Tag);
        }
    }

cleanup_and_exit:
    if (!INT_SUCCESS(status) && (NULL != pDetour))
    {
        IntDetRemoveDetour(pDetour);
    }
    else
    {
        if (NULL != Descriptor->PostCallback)
        {
            status = Descriptor->PostCallback(Handler);
            if (!INT_SUCCESS(status))
            {
                WARNING("[ERROR] PostCallback for hook %d (`%s!%s`) failed: 0x%08x\n",
                        Descriptor->Tag, utf16_for_log(Descriptor->ModuleName), Descriptor->FunctionName, status);
            }

            status = INT_STATUS_SUCCESS;
        }
    }

    return status;
}


INTSTATUS
IntDetSetReturnValue(
    _In_ DETOUR const *Detour,
    _Inout_opt_ IG_ARCH_REGS *Registers,
    _In_ QWORD ReturnValue
    )
///
/// @brief          Sets the return value for a hooked guest function.
///
/// This allows introcore to set a specific return value for a hooked guest function. Note that the in-guest handler
/// must be aware of this and must be able to properly handle this, usually by returning early from the hooked guest
/// function.
///
/// @param[in]      Detour      The detour for which the return value is changed.
/// @param[in, out] Registers   The register state to be used. If NULL, the current register state from the current
///                             VCPU will be used.
/// @param[in]      ReturnValue The return value. If the detour hypercall type is #hypercallTypeInt3 this will be set
///                             in the RAX register. If the hypercall type is #hypercallTypeVmcall this will be set
///                             in the RSI register. Other hypercall types are not supported. For 32-bit guests, the
///                             upper 32-bits of the return value are ignored.
///
/// @retval         #INT_STATUS_SUCCESS in case of success.
/// @retval         #INT_STATUS_NOT_SUPPORTED if the hypercall type is not #hypercallTypeInt3 or #hypercallTypeVmcall.
///
{
    INTSTATUS status;
    IG_ARCH_REGS regs;

    if (NULL == Registers)
    {
        status = IntGetGprs(gVcpu->Index, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        Registers = &regs;
    }

    switch (Detour->HypercallType)
    {
    case hypercallTypeInt3:
        Registers->Rax = ReturnValue;
        break;

    case hypercallTypeVmcall:
        Registers->Rsi = ReturnValue;
        break;

    default:
    {
        ERROR("[DETOUR] Invalid hypercall type %d ...", Detour->HypercallType);
        return INT_STATUS_NOT_SUPPORTED;
    }
    }

    status = IntSetGprs(gVcpu->Index, Registers);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDetCallCallback(
    void
    )
///
/// @brief      Calls the appropriate detour handler for hypercall.
///
/// This will iterate the list of detours and will call the first one that matches the hypercall. In order to match
/// a detour must have the same hypercall type as the hypercall that was issued, must have the HypercallAddress equal
/// to the RIP from which the hypercall was issued, and must have a valid callback. If it is not disabled, it is
/// called. Even if it is disabled the search stops after the first match.
///
/// If the detour is enabled, its HitCount is incremented. If the callback returns #INT_STATUS_DISABLE_DETOUR_ON_RET
/// the hypercall is disabled, but the detour is not removed from the guest memory and it will still be executed by
/// the guest. If it returns #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP the detour is removed from the guest (this is
/// available only for detours with a #hypercallTypeInt3 hypercall type). Other return values are ignored and are
/// not even logged.
///
/// @retval     #INT_STATUS_SUCCESS in case of success. This does not take into account error encountered by the
///             detour callback.
/// @retval     #INT_STATUS_NOT_FOUND if no matching detour was found. This means that the hypercall was not issued
///             by a detour.
/// @retval     #INT_STATUS_NO_DETOUR_EMU if no emulation is needed. This means that the detour callback returned
///             #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP and the detour was removed and the guest RIP was moved to
///             point back to the original function address, meaning that the guest should be let to execute the
///             original function, and emulation is not needed, because there is nothing to emulate.
///
{
    INTSTATUS status = INT_STATUS_NOT_FOUND;
    DETOUR *pDetour = NULL;
    BOOLEAN bCalled = FALSE;

    if (gGuest.OSType == introGuestLinux &&
        IN_RANGE_LEN(gVcpu->Regs.Rip, gLixGuest->MmAlloc.Detour.Code.Address, gLixGuest->MmAlloc.Detour.Code.Length))
    {
        DETOUR *pDet = NULL;
        if (gVcpu->Regs.Rbx >= det_max_id)
        {
            return INT_STATUS_NOT_FOUND;
        }

        pDet = gDetours.LixDetourTable[gVcpu->Regs.Rbx];

        if (!pDet->Disabled)
        {
            pDet->HitCount++;
            status = gLixHookHandlersx64[gVcpu->Regs.Rbx].Callback(pDet);
        }
        else
        {
            status = INT_STATUS_SUCCESS;
        }

        pDetour = pDet;
    }
    else
    {
        for_each_detour(pDet)
        {
            // We match a detour using the RIP that generated the VMEXIT. Also, ignore detours with missing handlers.
            if (pDet->HypercallAddress != gVcpu->Regs.Rip ||
                pDet->HypercallAddress == 0 ||
                pDet->HypercallOffset == DETOUR_INVALID_HYPERCALL ||
                pDet->Callback == NULL)
            {
                continue;
            }

            if (!pDet->Disabled)
            {
                // Note: detours can be safely added from other detour handlers.
                // However, we can only remove the current detour, as removing other detours will possibly
                // corrupt the detours list.
                status = pDet->Callback(pDet);

                bCalled = TRUE;

                pDet->HitCount++;
            }
            else
            {
                status = INT_STATUS_SUCCESS;
            }

            pDetour = pDet;

            break;
        }
    }

    if (INT_STATUS_DISABLE_DETOUR_ON_RET == status)
    {
        LOG("[DETOUR] Removing detour with tag %d\n", pDetour->Tag);
        IntDetPermanentlyDisableDetour(pDetour);
    }
    else if (INT_STATUS_REMOVE_DETOUR_AND_SET_RIP == status)
    {
        if (pDetour->HypercallType == hypercallTypeVmcall)
        {
            if (gGuest.OSType == introGuestWindows)
            {
                WARNING("[WARNING] The detour uses vmcall as a hypercall. Cannot remove and set RIP ...");
                return INT_STATUS_SUCCESS;
            }
            else if (gGuest.OSType == introGuestLinux)
            {
                QWORD addrRegs = gLixGuest->MmAlloc.PerCpuData.PerCpuAddress + (gVcpu->Index * PAGE_SIZE);

                LOG("[DETOUR] Removing detour with tag %d and setting RIP[%d] to 0x%016llx\n",
                        pDetour->Tag, gVcpu->Index, pDetour->FunctionAddress);

                IntDetPermanentlyDisableDetour(pDetour);

                status = IntKernVirtMemRead(addrRegs, 16 * 8, &gVcpu->Regs, NULL);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n",
                          addrRegs, status);
                    return status;
                }

                // The intergator adds the length of VMCALL instruction (3 bytes) to RIP
                gVcpu->Regs.Rip = pDetour->FunctionAddress - 3;

                IntSetGprs(gVcpu->Index, &gVcpu->Regs);

                return INT_STATUS_NO_DETOUR_EMU;
            }
        }

        if (pDetour->HypercallType == hypercallTypeInt3)
        {
            LOG("[DETOUR] Removing detour with tag %d and setting RIP[%d] to 0x%016llx\n",
                pDetour->Tag, gVcpu->Index, pDetour->FunctionAddress);

            IntDetPermanentlyDisableDetour(pDetour);

            gVcpu->Regs.Rip = pDetour->FunctionAddress;

            IntSetGprs(gVcpu->Index, &gVcpu->Regs);

            return INT_STATUS_NO_DETOUR_EMU;
        }
    }
    else if (bCalled)
    {
        // Force success if any callback was called, in case that some unknown statuses are returned, such as
        // INT_STATUS_NOT_FOUND, which can generate guest crashes by re-injecting the int3.
        return INT_STATUS_SUCCESS;
    }

    return status;
}


INTSTATUS
IntDetModifyPublicData(
    _In_ DETOUR_TAG Tag,
    _In_ void const *Data,
    _In_ DWORD DataSize,
    _In_ char const *PublicDataName
    )
///
/// @brief      Modifies public parts of a detour handler.
///
/// A detour that allows for external changes exposes the parts of its handler that can be changed as public data
/// by describing them inside the #API_HOOK_HANDLER.PublicDataOffsets array.
/// An external caller only needs the detour tag and the name of the data region that it wants to change.
/// The data is modified using the memory cloaking mechanism, see @ref group_memclk.
///
/// @param[in]  Tag             The tag of the detour.
/// @param[in]  Data            Buffer with the new contents of the detour handler.
/// @param[in]  DataSize        The size of the Data buffer. Must not be larger than the size of the public data region.
/// @param[in]  PublicDataName  NULL-terminated string of the public data name. This is case sensitive.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Tag is not less than #detTagMax.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Data is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if DataSize is 0.
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 if PublicDataName is NULL.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT if no detour is found for Tag.
/// @retval     #INT_STATUS_NOT_FOUND if no public data region is found for PublicDataName.
/// @retval     #INT_STATUS_INVALID_DATA_SIZE if DataSize is larger than the size of the public data region.
///
{
    INTSTATUS status;
    DETOUR *pDet;
    API_HOOK_PUBLIC_DATA *pPublicData = NULL;

    if (Tag >= detTagMax)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Data)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == DataSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == PublicDataName)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    pDet = gDetours.DetoursTable[Tag];
    if (NULL == pDet)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (NULL == pDet->HandlerCloakHandle)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    for (DWORD i = 0; i < pDet->NrPublicDataOffsets; i++)
    {
        if (!strcmp(PublicDataName, pDet->PublicDataOffsets[i].PublicDataName))
        {
            pPublicData = &pDet->PublicDataOffsets[i];
            break;
        }
    }

    if (NULL == pPublicData)
    {
        return INT_STATUS_NOT_FOUND;
    }

    if (DataSize > pPublicData->PublicDataSize)
    {
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    LOG("[DETOUR] Will modify patched data for public data %s at offset %d with size %u\n",
        pPublicData->PublicDataName, pPublicData->PublicDataOffset, DataSize);

    status = IntMemClkModifyPatchedData(pDet->HandlerCloakHandle, pPublicData->PublicDataOffset, DataSize, Data);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkModifyPatchedData failed: 0x%08x\n", status);
    }

    return status;
}


void
IntDetDisableAllHooks(
    void
    )
///
/// @brief  Removes all detours from the guest.
///
/// This will restore the original contents of the hooked functions, will remove the detour handlers, and will free
/// any resources associated with the detours, except the detour structures.
/// No safeness checks are done. If a guest thread is currently running inside a detour handler or returns to it
/// the guest will be left in an unstable state.
///
{
    for_each_detour(pDet)
    {
        IntDetPermanentlyDisableDetour(pDet);
    }
}


void
IntDetUninit(
    void
    )
///
/// @brief  Uninitializes the detour module.
///
/// Will iterate over the global detour list in #gDetours and will call #IntDetRemoveDetour for each detour. After
/// this function returns, #gDetours will be completely reset and no active detours will be remaining.
/// No safeness checks are done. If a guest thread is currently running inside a detour handler or returns to it
/// the guest will be left in an unstable state.
///
{
    for_each_detour(pDet)
    {
        RemoveEntryList(&pDet->Link);

        gDetours.DetoursTable[pDet->Tag] = NULL;

        IntDetRemoveDetour(pDet);
    }

    memzero(&gDetours, sizeof(gDetours));
    InitializeListHead(&gDetours.DetoursList);
}


void
IntDetDumpDetours(
    void
    )
///
/// @brief  Prints all the detours in the #gDetours list of detours.
///
{
    LOG("[DBGINTRO] Introspection detours:\n");

    for_each_detour(pDetour)
    {
        char *pFnName = NULL;
        if (gGuest.OSType == introGuestLinux)
        {
            if (pDetour->LixFnDetour != NULL)
            {
                pFnName = pDetour->LixFnDetour->FunctionName;
            }
            else if (pDetour->Descriptor != NULL)
            {
                pFnName = pDetour->Descriptor->FunctionName;
            }
        }
        else if (gGuest.OSType == introGuestWindows)
        {
            pFnName = pDetour->Descriptor != NULL ? pDetour->Descriptor->FunctionName : NULL;
        }

        LOG(" ## %-32s Hits: %12llu, RIP: %llx, Tag: %02d, Handler RIP: %llx (+ %02x), Hooked RIP: %llx\n",
            pFnName != NULL ? pFnName : "unknown",
            pDetour->HitCount,
            pDetour->HypercallAddress,
            pDetour->Tag,
            pDetour->HandlerAddress,
            pDetour->HandlerSize,
            pDetour->FunctionAddress);

        if (gGuest.OSType == introGuestWindows && pDetour->ModuleBase != gGuest.KernelVa)
        {
            LOG("        Module: %llx\n",
                pDetour->ModuleBase);
        }
    }
}


BOOLEAN
IntDetIsPtrInRelocatedCode(
    _In_ QWORD Ptr,
    _Out_opt_ DETOUR_TAG *Tag
    )
///
/// @brief  Checks if a guest pointer is inside the modified prologue of a function.
///
/// @param[in]  Ptr     The guest virtual address to check.
/// @param[out] Tag     If Ptr is inside a modified function prologue, will contain the tag of the detour set for it.
///                     May be NULL.
///
/// @returns    True if Ptr is inside a modified function prologue, False if it is not.
///
{
    for_each_detour(pDet)
    {
        if (Ptr >= pDet->FunctionAddress &&
            Ptr < pDet->FunctionAddress + pDet->RelocatedCodeLength)
        {
            if (NULL != Tag)
            {
                *Tag = pDet->Tag;
            }

            return TRUE;
        }
    }

    if (NULL != Tag)
    {
        *Tag = detTagMax;
    }

    return FALSE;
}


BOOLEAN
IntDetIsPtrInHandler(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type,
    _Out_opt_ DETOUR_TAG *Tag
    )
///
/// @brief  Checks if a guest pointer is inside a detour handler.
///
/// @param[in]  Ptr     The guest virtual address to check.
/// @param[in]  Type    The type of pointer Ptr is. This is used only for logging purposes.
/// @param[out] Tag     If Ptr is inside a detour handler, will contain the tag of the detour set for it. May be NULL.
///
/// @returns    True if Ptr is inside a detour handler prologue, False if it is not.
///
{

    if (gGuest.OSType == introGuestLinux)
    {
        if (Tag)
        {
            *Tag = 0;
        }

        if (IN_RANGE_LEN(Ptr, gLixGuest->MmAlloc.Detour.Code.Address, gLixGuest->MmAlloc.Detour.Code.Length))
        {
            return TRUE;
        }
    }

    for_each_detour(pDet)
    {
        if ((Ptr >= pDet->HandlerAddress) && (Ptr < pDet->HandlerAddress + pDet->HandlerSize))
        {
            WARNING("[WARNING] Found %s ptr 0x%016llx in detours: handler RIP 0x%016llx, hook RIP 0x%016llx\n",
                    Type == ptrLiveRip ? "live RIP" : "stack value", Ptr, pDet->HandlerAddress, pDet->FunctionAddress);

            // This is ugly, but we want to avoid modifying the RtlpVirtualUnwind handler while a RIP
            // is pointing inside of it, since we can't atomically modify 2 instructions if the first
            // one has already executed...
            if (pDet->Tag >= detTagRtlVirtualUnwind1 && pDet->Tag < detTagRtlVirtualUnwindMax)
            {
                extern BOOLEAN gRipInsideRtlpVirtualUnwindReloc;

                if (Ptr < pDet->HandlerAddress + pDet->RelocatedCodeOffset)
                {
                    gRipInsideRtlpVirtualUnwindReloc = TRUE;
                }
            }

            if (NULL != Tag)
            {
                *Tag = pDet->Tag;
            }

            return TRUE;
        }
    }

    if (NULL != Tag)
    {
        *Tag = detTagMax;
    }

    return FALSE;
}


QWORD
IntDetRelocatePtrIfNeeded(
    _In_ QWORD Ptr
    )
///
/// @brief      Returns the new value Ptr should have if it is currently pointing inside a relocated prologue.
///
/// @param[in]  Ptr     Guest virtual address to check.
///
/// @returns    The new Ptr value.
///
{
    for_each_detour(pDetour)
    {
        if ((Ptr > pDetour->FunctionAddress) &&
            (Ptr < pDetour->FunctionAddress + pDetour->RelocatedCodeLength))
        {
            return pDetour->HandlerAddress + pDetour->RelocatedCodeOffset + (Ptr - pDetour->FunctionAddress);
        }
    }

    // No modification, return it as it is.
    return Ptr;
}


INTSTATUS
IntDetGetAddrAndTag(
    _In_ QWORD Ptr,
    _Out_ QWORD *Address,
    _Out_ DWORD *Size,
    _Out_ DETOUR_TAG *Tag
    )
///
/// @brief  Checks if Ptr is inside a detour handler and returns the detour's handler address, size and tag.
///
/// @param[in]  Ptr     Guest virtual address to check.
/// @param[out] Address If Ptr is inside a detour handler, will contain the start of the handler. May be NULL.
/// @param[out] Size    If Ptr is inside a detour handler, will contain the size of the handler. May be NULL.
/// @param[out] Tag     If Ptr is inside a detour handler, will contain the tag of the detour. May be NULL.
///
/// @retval     #INT_STATUS_SUCCESS if Ptr is inside a detour handler.
/// @retval     #INT_STATUS_NOT_FOUND if Ptr is not inside a detour handler.
///
{
    for_each_detour(pDetour)
    {
        if ((Ptr > pDetour->HandlerAddress) &&
            (Ptr < pDetour->HandlerAddress + pDetour->HandlerSize))
        {
            *Address = pDetour->HandlerAddress;
            *Size = pDetour->HandlerSize;
            *Tag = pDetour->Tag;

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntDetGetByTag(
    _In_ DETOUR_TAG Tag,
    _Out_ QWORD *Address,
    _Out_opt_ DWORD *Size
    )
///
/// @brief  Get a detour handler address and size by its tag.
///
/// @param[in]  Tag     Detour tag.
/// @param[out] Address On success, the address of the detour handler.
/// @param[out] Size    On success, the size of the detour handler. May be NULL.
///
/// @retval     #INT_STATUS_SUCCESS if there is a detour for the given tag.
/// @retval     #INT_STATUS_NOT_FOUND if there is no detour for the given tag.
///
{
    DETOUR *pDet = IntDetFindByTag(Tag);
    if (pDet)
    {
        *Address = pDet->HandlerAddress;

        if (NULL != Size)
        {
            *Size = pDet->HandlerSize;
        }

        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntDetGetFunctionAddressByTag(
    _In_ DETOUR_TAG Tag,
    _Out_ QWORD *FunctionAddress
    )
///
/// @brief  Get a detour function address by its tag.
///
/// @param[in]  Tag             Detour tag.
/// @param[out] FunctionAddress On success, the address of the function which was detoured.
///
/// @retval     #INT_STATUS_SUCCESS if there is a detour for the given tag.
/// @retval     #INT_STATUS_NOT_FOUND if there is no detour for the given tag.
///
{
    DETOUR *pDet = IntDetFindByTag(Tag);
    if (pDet)
    {
        *FunctionAddress = pDet->FunctionAddress;
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntDetGetArgumentInternal(
    _In_ DWORD Arg,
    _In_opt_ BYTE const *StackBuffer,
    _In_ DWORD StackBufferSize,
    _Out_ QWORD *Value
    )
///
/// @brief      Reads the value of an argument passed from a detour.
///
/// @param[in]  Arg             Argument encoding as taken from a #DETOUR_ARGS structure.
/// @param[in]  StackBuffer     Optional buffer containing the guest stack. If the argument is on the stack, will use
///                             this buffer instead of reading it directly from the guest.
/// @param[in]  StackBufferSize The size of the StackBuffer. If the argument is outside the size of the stack buffer,
///                             it will be taken directly from the guest memory.
/// @param[out] Value           On success, will contain the argument value.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if the argument encoding is corrupted.
///
{
    IG_ARCH_REGS const *pRegs = &gVcpu->Regs;
    BOOLEAN haveStackBuffer = StackBuffer && StackBufferSize;

    *Value = 0;

    if (DET_ARG_ON_STACK(Arg)) // Read argument from the stack
    {
        DWORD stackOffset = DET_ARG_STACK_OFFSET(Arg);

        if (haveStackBuffer && stackOffset + gGuest.WordSize <= StackBufferSize)
        {
            if (gGuest.WordSize == 4)
            {
                *Value = *(DWORD const *)(StackBuffer + stackOffset);
            }
            else
            {
                *Value = *(QWORD const *)(StackBuffer + stackOffset);
            }
        }
        else
        {
            INTSTATUS status;

            status = IntKernVirtMemRead(pRegs->Rsp + stackOffset, gGuest.WordSize, Value, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed for %llx: 0x%08x\n", pRegs->Rsp + stackOffset, status);
                return status;
            }
        }
    }
    else if (DET_ARG_REGS(Arg)) // Simply get from registers
    {
        *Value = ((QWORD const *)pRegs)[Arg];
    }
    else
    {
        ERROR("[ERROR] Invalid argument type: 0x%08x\n", Arg);
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDetGetArgument(
    _In_ void const *Detour,
    _In_ DWORD Index,
    _In_opt_ BYTE const *StackBuffer,
    _In_ DWORD StackBufferSize,
    _Out_ QWORD *Value
    )
///
/// @brief      Reads the specified argument for a detour.
///
/// @param[in]  Detour          The detour for which to read the argument.
/// @param[in]  Index           The number of the argument to read.
/// @param[in]  StackBuffer     If the argument is on the stack and this is not NULL, it will be used instead of
///                             reading the argument from the guest memory. If multiple calls are made for the same
///                             detour, it is worth it to read the guest stack once and passing it as a buffer to all
///                             calls made to this function.
/// @param[in]  StackBufferSize The size of the stack buffer. If the argument is outside the size of the stack buffer,
///                             it will be taken directly from the guest memory.
/// @param[out] Value           On success, the value of the argument.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Detour is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Index is equal or grater than #DET_ARGS_MAX.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Value is NULL.
/// @retval     #INT_STATUS_NOT_INITIALIZED if the Detour is not properly uninitialized.
///
{
    API_HOOK_DESCRIPTOR const *pApi;
    DETOUR const *pDetour;
    DWORD const *pArgs;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Index >= DET_ARGS_MAX)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Value)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pDetour = Detour;
    pApi = pDetour->Descriptor;
    if (NULL == pApi)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    pArgs = pApi->Arguments.Argv;
    return IntDetGetArgumentInternal(pArgs[Index], StackBuffer, StackBufferSize, Value);
}


INTSTATUS
IntDetGetArguments(
    _In_ void const *Detour,
    _In_ DWORD Argc,
    _Out_writes_(Argc) QWORD *Argv
    )
///
/// @brief      Reads multiple arguments from a detour.
///
/// Iterates over the arguments in Detour and calls #IntDetGetArgumentInternal for each one.
/// If one or more arguments are on the stack, the function will calculate the size of the stack that must be
/// read in order to have access on all of them, and map it a single time, before calling it.
///
/// @param[in]  Detour      The detour for which to read the arguments.
/// @param[in]  Argc        The number of arguments to read.
/// @param[out] Argv        On success, will contain the first Argc arguments from this detour. If the detour has less
///                         than Argc arguments, the function stops reading when it reaches the last argument. This
///                         buffer should be large enough to contain Argc 64-bit integers, even for 32-bit guests.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Detour is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Argc is 0 or not less than #DET_ARGS_MAX.
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if Argv is NULL.
/// @retval     #INT_STATUS_NOT_INITIALIZED if Detour is not fully initialized yet.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if the caller requested more arguments than there are available.
///
{
    BYTE stackBuffer[256];
    DETOUR const *detour;
    API_HOOK_DESCRIPTOR const *api;
    DWORD const *args;
    DWORD stackBufferSize = 0;
    BYTE const *pStackBuffer = NULL;
    DWORD argc;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Argc || DET_ARGS_MAX <= Argc)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Argv)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    detour = Detour;
    api = detour->Descriptor;
    if (NULL == api)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    args = api->Arguments.Argv;
    argc = Argc;
    if (argc > api->Arguments.Argc)
    {
        ERROR("[ERROR] Requested to read %u arguments for for detour %d, but only %u exist.\n",
                argc, detour->Tag, api->Arguments.Argc);
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    for (DWORD i = 0; i < argc; i++)
    {
        if (DET_ARG_ON_STACK(args[i]))
        {
            stackBufferSize = MAX(stackBufferSize, DET_ARG_STACK_OFFSET(args[i]));
        }
    }

    if (stackBufferSize)
    {
        INTSTATUS status;
        QWORD rsp = gVcpu->Regs.Rsp;

        // Add the size of the last parameter
        stackBufferSize += gGuest.WordSize;
        // Just in case we have something so far up the stack
        stackBufferSize = MIN(stackBufferSize, sizeof(stackBuffer));

        status = IntKernVirtMemRead(rsp, stackBufferSize, &stackBuffer, NULL);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntKernVirtMemRead failed for [0x%016llx, 0x%016llx]: 0x%08x\n",
                    rsp, rsp + stackBufferSize, status);
            stackBufferSize = 0;
            // We could still try to read them one at a time
        }
        else
        {
            pStackBuffer = stackBuffer;
        }
    }

    for (DWORD i = 0; i < argc; i++)
    {
        // pStackBuffer will be NULL if we get here and we could not read the stack
        // or there are no arguments on the stack; IntDetGetArgumentInternal will handle that
        INTSTATUS status = IntDetGetArgumentInternal(args[i], pStackBuffer, stackBufferSize, &Argv[i]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDetGetArgument failed for %u: 0x%08x\n", i, status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDetPatchArgument(
    _In_ void const *Detour,
    _In_ DWORD Index,
    _In_ QWORD Value
    )
///
/// @brief      Modifies the value of a detour argument.
///
/// @param[in]  Detour      The detour for which to modify the value of an argument.
/// @param[in]  Index       The index of the argument.
/// @param[in]  Value       The value of the argument. For 32-bit guests, the upper 32-bits of the value are ignored.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Detour is NULL.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Index is not less than the argument count of the detour.
/// @retval     #INT_STATUS_NOT_INITIALIZED if the Detour is not fully initialized yet.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if the argument encoding is corrupted.
///
{
    INTSTATUS status;
    API_HOOK_DESCRIPTOR const *pApi;
    DETOUR const *pDetour;
    PIG_ARCH_REGS pRegs;
    QWORD arg;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pDetour = Detour;
    pApi = pDetour->Descriptor;
    if (NULL == pApi)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (Index >= pApi->Arguments.Argc)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pRegs = &gVcpu->Regs;
    arg = pApi->Arguments.Argv[Index];

    if (DET_ARG_ON_STACK(arg))
    {
        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                     pRegs->Rsp + DET_ARG_STACK_OFFSET(arg),
                                     gGuest.WordSize,
                                     &Value,
                                     IG_CS_RING_0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
            return status;
        }
    }
    else if (DET_ARG_REGS(arg))
    {
        ((QWORD *)pRegs)[arg] = Value;

        status = IntSetGprs(gVcpu->Index, pRegs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        ERROR("[ERROR] Invalid argument type: 0x%016llx\n", arg);
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    return INT_STATUS_SUCCESS;
}
