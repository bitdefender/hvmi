/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winapi.h"
#include "decoder.h"
#include "drivers.h"
#include "guests.h"
#include "introcpu.h"
#include "memcloak.h"
#include "winhkhnd.h"
#include "winpe.h"
#include "crc32.h"


static INTSTATUS
IntWinApiFindFunctionRva(
    _In_ WIN_UNEXPORTED_FUNCTION *Patterns,
    _In_ QWORD ModuleBase,
    _In_ BOOLEAN IgnoreSectionHint,
    _Out_ DWORD *FunctionRva,
    _Out_opt_ DETOUR_ARGS **Arguments
    )
///
/// @brief  Searches for a function in a module, based on the given patterns.
///
/// Will search in the module represented by ModuleBase a function which matches at least one
/// of the given #WIN_UNEXPORTED_FUNCTION patterns. If IgnoreSectionHint is set to TRUE, then
/// it will search through all the sections, otherwise just on the section hint present in the
/// descriptor, if any.
///
/// @param[in]  Patterns            Contains information about the patterns which describe the
///                                 searched function.
/// @param[in]  ModuleBase          The module base where the patterns are searched for.
/// @param[in]  IgnoreSectionHint   If this parameter is set to TRUE, all the sections in the given
///                                 module are scanned for the given patterns.
/// @param[out] FunctionRva         The relative address to the module base where the function
///                                 was found.
/// @param[in]  Arguments           The arguments assigned for the found pattern, if any.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If the given patterns could not be found.
///
{
    INTSTATUS status = INT_STATUS_NOT_FOUND;

    for (DWORD i = 0; i < Patterns->PatternsCount; ++i)
    {
        WIN_UNEXPORTED_FUNCTION_PATTERN *pPattern = &Patterns->Patterns[i];

        if (ModuleBase == gGuest.KernelVa)
        {
            status = IntPeFindFunctionByPatternInBuffer(gWinGuest->KernelBuffer,
                                                        gWinGuest->KernelBufferSize,
                                                        pPattern,
                                                        IgnoreSectionHint,
                                                        FunctionRva);
        }
        else
        {
            status = IntPeFindFunctionByPattern(ModuleBase,
                                                pPattern,
                                                IgnoreSectionHint,
                                                FunctionRva);
        }

        if (INT_SUCCESS(status) && Arguments != NULL)
        {
            if (pPattern->Arguments.Argc != 0)
            {
                *Arguments = &pPattern->Arguments;
            }
            else
            {
                *Arguments = NULL;
            }

            break;
        }
    }

    return status;
}


static INTSTATUS
IntWinApiHook(
    _In_ API_HOOK_DESCRIPTOR *HookDescriptor
    )
///
/// @brief Will hook one function from a module as described by the HookDescriptor.
///
/// Will place a detour on HookDescriptor->FunctionName from HookDescriptor->ModuleName.
/// If HookDescriptor->Exported is TRUE, will search for said export and hook it.
/// Otherwise, it will search for the pattern signatures in HookDescriptor->Patterns to find
/// the function's address.
///
/// @param[in] HookDescriptor Describes the way a function will be hooked.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no good handler / matching signature is found.
///
{
    INTSTATUS status = INT_STATUS_UNSUCCESSFUL;
    PAPI_HOOK_HANDLER pHandler = NULL;
    DETOUR_ARGS *pArgs = NULL;
    DWORD functionRva = 0;
    QWORD functionRip = 0;
    QWORD moduleBase = 0;
    DWORD i = 0;

    if (NULL == HookDescriptor)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == wstrcasecmp(u"ntoskrnl.exe", HookDescriptor->ModuleName))
    {
        moduleBase = gGuest.KernelVa;
    }
    else
    {
        KERNEL_DRIVER *pDriver = IntDriverFindByName(HookDescriptor->ModuleName);
        if (NULL == pDriver)
        {
            ERROR("[ERROR] IntDriverFindByName failed for %s: 0x%x\n",
                  utf16_for_log(HookDescriptor->ModuleName), status);
            return status;
        }

        moduleBase = pDriver->BaseVa;
    }

    if (HookDescriptor->Exported)
    {
        // Function exported, parse the exports and get the RVA.
        if (moduleBase == gGuest.KernelVa)
        {
            QWORD functionGva;

            status = IntPeFindKernelExport(HookDescriptor->FunctionName, &functionGva);

            functionRva = (DWORD)(functionGva - gGuest.KernelVa);
        }
        else
        {
            status = IntPeFindExportByName(moduleBase, NULL, HookDescriptor->FunctionName, &functionRva);
        }
    }
    else
    {
        if (NULL == HookDescriptor->Patterns)
        {
            TRACE("[INFO] No patterns given for %s, we won't hook\n", HookDescriptor->FunctionName);
            return INT_STATUS_NOT_NEEDED_HINT;
        }

        status = IntWinApiFindFunctionRva(HookDescriptor->Patterns,
                                          moduleBase,
                                          FALSE,
                                          &functionRva,
                                          &pArgs);

        // If we failed to find any pattern for the given routine, retry the search ignoring
        // OS version or section hint restrictions.
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Failed to find '%s', will try again, ignoring section hint\n",
                    HookDescriptor->FunctionName);
            status = IntWinApiFindFunctionRva(HookDescriptor->Patterns,
                                              moduleBase,
                                              TRUE,
                                              &functionRva,
                                              &pArgs);
        }
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Function '%s' not found inside module '%s': 0x%08x\n",
              HookDescriptor->FunctionName, utf16_for_log(HookDescriptor->ModuleName), status);
        return status;
    }

    if (pArgs != NULL)
    {
        HookDescriptor->Arguments.Argc = pArgs->Argc;
        memcpy(HookDescriptor->Arguments.Argv, pArgs->Argv, sizeof(HookDescriptor->Arguments.Argv[0]) * HookDescriptor->Arguments.Argc);
    }

    functionRip = functionRva + moduleBase;

    TRACE("[DETOUR] Found function '%s' @ 0x%016llx inside module '%s'\n",
          HookDescriptor->FunctionName, functionRip, utf16_for_log(HookDescriptor->ModuleName));

    // Find a proper handler for this function.
    pHandler = NULL;

    for (i = 0; i < HookDescriptor->HandlersCount; i++)
    {
        pHandler = &HookDescriptor->Handlers[i];

        if ((gGuest.OSVersion >= pHandler->MinVersion) && (gGuest.OSVersion <= pHandler->MaxVersion))
        {
            break;
        }

        pHandler = NULL;
    }

    if (NULL != pHandler)
    {
        status = IntDetSetHook(functionRip, moduleBase, HookDescriptor, pHandler);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDetSetHook failed: 0x%08x\n", status);
        }
    }
    else
    {
        ERROR("[DETOUR] Valid handler not found for %s!\n", HookDescriptor->FunctionName);
        status = INT_STATUS_NOT_FOUND;
    }

    return status;
}


INTSTATUS
IntWinApiHookAll(
    void
    )
///
/// @brief Iterates through all hookable APIs and sets requested hooks.
///
/// @returns #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS, failStatus;
    API_HOOK_DESCRIPTOR *pDescrs = NULL;
    size_t count = 0;
    BOOLEAN shouldFail;

    if (gGuest.Guest64)
    {
        pDescrs = gHookableApisX64;
        count = gHookableApisX64Size;
    }
    else
    {
        pDescrs = gHookableApisX86;
        count = gHookableApisX86Size;
    }

    TRACE("[DETOUR] Establishing API hooks...\n");

    shouldFail = FALSE;
    failStatus = INT_STATUS_NOT_FOUND;

    for (size_t i = 0; i < count; i++)
    {
        if ((gGuest.OSVersion < pDescrs[i].MinVersion) || (gGuest.OSVersion > pDescrs[i].MaxVersion))
        {
            LOG("[DETOUR] API function hook on %s is not enabled for this OS: %d - %d/%d\n",
                pDescrs[i].FunctionName, pDescrs[i].MinVersion, pDescrs[i].MaxVersion, gGuest.OSVersion);
            continue;
        }

        status = IntWinApiHook(&pDescrs[i]);
        if (!INT_SUCCESS(status))
        {
            if (!pDescrs[i].NotCritical)
            {
                ERROR("[ERROR] Failed to hook Critical API %s, will search the others and abort!\n",
                      pDescrs[i].FunctionName);
                shouldFail = TRUE;
                failStatus = status;
            }
            else
            {
                WARNING("[WARNING] Failed to hook non Critical API %s, will ignore\n", pDescrs[i].FunctionName);
            }
        }

        if (NULL != pDescrs[i].Patterns)
        {
            HpFreeAndNullWithTag(&pDescrs[i].Patterns, IC_TAG_CAMI);
        }
    }

    if (shouldFail)
    {
        if ((failStatus == INT_STATUS_PAGE_NOT_PRESENT) || (failStatus == INT_STATUS_NO_MAPPING_STRUCTURES))
        {
            // This allows us to retry initialization.
            IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        }
        else
        {
            // No way we can init, we didn't find all the functions.
            IntGuestSetIntroErrorState(intErrGuestApiNotFound, NULL);

            gGuest.DisableOnReturn = TRUE;
        }

        return failStatus;
    }

    TRACE("[DETOUR] Done establishing API hooks!\n");

    IntWinApiUpdateHooks();

    return INT_STATUS_SUCCESS;
}


void
IntWinApiUpdateHooks(
    void
    )
///
/// @brief Iterate through all hookable APIs and enable or disable them according to
/// the current Introcore options.
///
{
    const API_HOOK_DESCRIPTOR *pDescrs = NULL;
    size_t count = 0;

    if (gGuest.Guest64)
    {
        pDescrs = gHookableApisX64;
        count = gHookableApisX64Size;
    }
    else
    {
        pDescrs = gHookableApisX86;
        count = gHookableApisX86Size;
    }

    for (size_t i = 0; i < count; i++)
    {
        // Most of the detours can't be disabled, ever, because we'd lose quite a bit of the guest's state.
        if (pDescrs[i].EnableFlags == DETOUR_ENABLE_ALWAYS)
        {
            continue;
        }

        if ((0 == (pDescrs[i].EnableFlags  & gGuest.CoreOptions.Current)) ||
            (0 != (pDescrs[i].DisableFlags & gGuest.CoreOptions.Current)))
        {
            TRACE("[DETOUR] Disabling detour on function '%s' according to new options: %llx!\n",
                  pDescrs[i].FunctionName, gGuest.CoreOptions.Current);

            IntDetDisableDetour(pDescrs[i].Tag);
        }
        else
        {
            TRACE("[DETOUR] Enabling detour on function '%s' according to new options: %llx!\n",
                  pDescrs[i].FunctionName, gGuest.CoreOptions.Current);

            IntDetEnableDetour(pDescrs[i].Tag);
        }
    }
}


INTSTATUS
IntWinApiHookVeHandler(
    _In_ QWORD NewHandler,
    _Out_ void **Cloak,
    _Out_opt_ QWORD *OldHandler,
    _Out_opt_ DWORD *ReplacedCodeLen,
    _Out_writes_to_(38, *ReplacedCodeLen) BYTE *ReplacedCode
    )
///
/// @brief Hooks the \#VE handler.
///
/// Hook the original \#VE handler and make it point to our handler.
/// The code sequence is:
/// @code
///     CALL $+4
///     LFENCE
///     MOV dword [rsp], NewHandle low
///     MOV dword [rsp + 4], NewHandle high
///     ret
/// @endcode
///
/// Guests older than RS3 are not aware of the VirtualizationException, and the first
/// instruction is a "PUSH 0x14". On these, there are two cases:
/// @code
/// KPTI on  - "PUSH 0x14/JMP KiIsrThunkShadow"
/// KPTI off - "PUSH 0x14/PUSH rbp/JMP KiUnexpectedInterrupt"
/// @endcode
/// We search for the JMP, which directs us to the effective handler.
///
/// If the guest has the KPTI patches, the IDT points to the shadow, so we search
/// for the real one.
///
/// @param[in]  NewHandler      Address of our handler.
/// @param[out] Cloak           Will receive the memory cloak used to hide the hook.
/// @param[out] OldHandler      Will receive the address of the old handler.
/// @param[out] ReplacedCodeLen Will receive the size of the code replaced by this function.
/// @param[out] ReplacedCode    Will receive the code replaced by this function.
///
/// @returns    #INT_STATUS_SUCCESS if successfully, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    QWORD vehnd;
    DWORD codelen, iidx;
    INSTRUX ix;

/// Minimum Code length in bytes to be replaced by our int20 hook.
#define MIN_CODE_LEN    24
    BYTE newcode[64], oldcode[64];

    vehnd = 0;

    // Note: interrupt 20 should not be called in any way, so it's safe to hook it like this, without employing
    // thread safeness and without using single instructions.

    // Get the INT 20 entry.
    status = IntIdtGetEntry(IG_CURRENT_VCPU, 20, &vehnd);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIdtGetEntry failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    LOG("[VECORE] Original #VE handler at %llx...\n", vehnd);

    // Special handling for older Windows versions, where the #VE handler was considered an unexpected exception.
    status = IntDecDecodeInstruction(IG_CS_TYPE_64B, vehnd, &ix);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecDecodeInstruction failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // If the first instruction of the IDT handler is a "PUSH 0x14", this means we have an older Windows version on
    // out hand, a version which is not aware of the VirtualizationException.
    // These versions are: 7, 8, 8.1, TH1, TH2, RS1 and RS2
    // On these, there are 2 cases:
    // KPTI on  - "PUSH 0x14/JMP KiIsrThunkShadow"
    // KPTI off - "PUSH 0x14/PUSH rbp/JMP KiUnexpectedInterrupt"
    // We search the JMP, which directs us to the effective handler.
    if (ix.Instruction == ND_INS_PUSH && ix.Operands[0].Type == ND_OP_IMM && ix.Operands[0].Info.Immediate.Imm == 0x14)
    {
        for (iidx = 0; iidx < 4; iidx++)
        {
            vehnd += ix.Length;

            status = IntDecDecodeInstruction(IG_CS_TYPE_64B, vehnd, &ix);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecDecodeInstruction failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }

            if (ix.Instruction == ND_INS_JMPNR)
            {
                vehnd = vehnd + ix.Length + ix.Operands[0].Info.RelativeOffset.Rel;
                LOG("[VECORE] KiIsrThunkShadow identified, the handler is at 0x%016llx\n", vehnd);
                break;
            }
        }

        if (iidx == 4)
        {
            ERROR("[ERROR] JMP to the main ISR handler not found!\n");
            status = INT_STATUS_NOT_FOUND;
            goto cleanup_and_exit;
        }

        iidx = 0;
    }

    // If this is with KPTI, search for the real handler, as the IDT entry points to the shadow.
    if (gGuest.KptiActive)
    {
        DWORD i = 0;
        BOOLEAN bMovcr3 = FALSE;

        LOG("[VECORE] KPTI enabled, %llx is the shadow handler, searching for the original handler...\n", vehnd);

        while (i < 128)
        {
            // We only work on 64 bit.
            status = IntDecDecodeInstruction(IG_CS_TYPE_64B, vehnd + i, &ix);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecDecodeInstruction failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }

            if ((ix.Instruction == ND_INS_MOV_CR) && ND_IS_OP_REG(&ix.Operands[0], ND_REG_CR, 8, NDR_CR3))
            {
                bMovcr3 = TRUE;
            }

            if ((ix.Instruction == ND_INS_JMPNR) && (bMovcr3))
            {
                vehnd = vehnd + i + ix.Length + ix.Operands[0].Info.RelativeOffset.Rel;
                break;
            }

            i += ix.Length;
        }
    }

    LOG("[VECORE] Found the real #VE handler at %llx...\n", vehnd);

    LOG("[VECORE] The new #VE handler will be at %llx...\n", NewHandler);

    // Read the old code.
    status = IntKernVirtMemRead(vehnd, sizeof(oldcode), oldcode, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    codelen = 0;
    while (codelen < MIN_CODE_LEN)
    {
        INSTRUX instrux;
        NDSTATUS ndstat;

        ndstat = NdDecodeEx(&instrux, oldcode + codelen, sizeof(oldcode) - codelen, ND_CODE_64, ND_DATA_64);
        if (!ND_SUCCESS(ndstat))
        {
            ERROR("[ERROR] NdDecodeEx failed: 0x%08x\n", ndstat);
            return INT_STATUS_NOT_SUPPORTED;
        }

        codelen += instrux.Length;
    }

    // Hook the original #VE handler and make it point to our handler.
    // The sequence is: PUSH 2 byte chunks from the new VE handler, than ret to it.
    iidx = 0;

    // IMPORTANT: In order to mitigate RSB Spectre, we will first do a relative CALL, in order to make sure the RET
    // misprediction goes to some code controlled by us. This is basically a retpoline of sorts.

    // CALL $+4
    newcode[iidx++] = 0xE8;
    newcode[iidx++] = 0x03;
    newcode[iidx++] = 0x00;
    newcode[iidx++] = 0x00;
    newcode[iidx++] = 0x00;

    // LFENCE
    newcode[iidx++] = 0x0F;
    newcode[iidx++] = 0xAE;
    newcode[iidx++] = 0xE8;

    // MOV dword [rsp], NewHandle low
    newcode[iidx++] = 0xC7;
    newcode[iidx++] = 0x04;
    newcode[iidx++] = 0x24;
    newcode[iidx++] = (NewHandler >> 0) & 0xFF;
    newcode[iidx++] = (NewHandler >> 8) & 0xFF;
    newcode[iidx++] = (NewHandler >> 16) & 0xFF;
    newcode[iidx++] = (NewHandler >> 24) & 0xFF;

    // MOV dword [rsp + 4], NewHandle high
    newcode[iidx++] = 0xC7;
    newcode[iidx++] = 0x44;
    newcode[iidx++] = 0x24;
    newcode[iidx++] = 0x04;
    newcode[iidx++] = (NewHandler >> 32) & 0xFF;
    newcode[iidx++] = (NewHandler >> 40) & 0xFF;
    newcode[iidx++] = (NewHandler >> 48) & 0xFF;
    newcode[iidx++] = (NewHandler >> 56) & 0xFF;

    newcode[iidx++] = 0xC3;

    // Fill in the gap with NOPs.
    for (DWORD i = iidx; i < codelen; i++)
    {
        newcode[i] = 0x90;
    }

    status = IntMemClkCloakRegion(vehnd, 0, codelen, MEMCLOAK_OPT_APPLY_PATCH, oldcode, newcode, NULL, Cloak);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (NULL != OldHandler)
    {
        *OldHandler = vehnd;
    }

    if (NULL != ReplacedCodeLen)
    {
        *ReplacedCodeLen = codelen;
    }

    if (NULL != ReplacedCode)
    {
        memcpy(ReplacedCode, oldcode, codelen);
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    return status;
}


INTSTATUS
IntWinApiUpdateHookDescriptor(
    _In_ WIN_UNEXPORTED_FUNCTION *Function,
    _In_ DWORD ArgumentsCount,
    _In_ const DWORD *Arguments
    )
///
/// @brief Update a hook descriptor with corresponding function patterns
/// and argument list from CAMI.
///
/// @param[in] Function Patterns given from CAMI, also contains the name hash.
/// @param[in] ArgumentsCount Number of elements in Arguments.
/// @param[in] Arguments List of arguments from CAMI.
///
/// @returns #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    API_HOOK_DESCRIPTOR *pDescrs;
    size_t count;

    if (NULL == Function)
    {
        return INT_STATUS_INVALID_PARAMETER;
    }

    if (gGuest.Guest64)
    {
        pDescrs = gHookableApisX64;
        count = gHookableApisX64Size;
    }
    else
    {
        pDescrs = gHookableApisX86;
        count = gHookableApisX86Size;
    }

    for (size_t i = 0; i < count; i++)
    {
        DWORD crc32 = Crc32String(pDescrs[i].FunctionName, INITIAL_CRC_VALUE);
        if ((crc32 == Function->NameHash) &&
            (gGuest.OSVersion >= pDescrs[i].MinVersion) && (gGuest.OSVersion <= pDescrs[i].MaxVersion))
        {
            pDescrs[i].Patterns = Function;
            if (0 != ArgumentsCount)    // If no arguments are given, leave the default ones.
            {
                pDescrs[i].Arguments.Argc = MIN(ArgumentsCount, ARRAYSIZE(pDescrs[i].Arguments.Argv));
                memcpy(pDescrs[i].Arguments.Argv, Arguments,
                       sizeof(pDescrs[i].Arguments.Argv[0]) * pDescrs[i].Arguments.Argc);
            }

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}

