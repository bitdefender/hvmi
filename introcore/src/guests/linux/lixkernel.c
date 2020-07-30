/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixkernel.h"
#include "decoder.h"
#include "hook.h"
#include "lixvdso.h"
#include "alerts.h"
#include "lixksym.h"

///
/// @file lixkernel.c
///
/// This file contains the protection logic against malicious kernel reads and writes, as well as the
/// mitigation logic for CVE-2019-1125 vulnerability on Linux operating systems.. For an in-depth explanation of
/// this mechanism, see swapgs.c.

///
/// @brief native_swapgs gadgets patched by Introspection.
///
static struct
{
    QWORD LfenceRip;        ///< The RIP where the lfence instruction was injected.
    BYTE  OriginalBytes[3]; ///< The bytes that were modified with the lfence instruction.
} gPatchedSwapgs[128] = {0};

///
/// @brief The total number of patched swapgs gadgets.
///
static DWORD gTotalPatchedSwapgs = 0;

///
/// @brief The guest virtual address of the "native_swapgs" function.
///
static QWORD gNativeSwapgs = 0;

///
/// @brief The original first 10 bytes of the "native_swapgs" function.
///
static BYTE gOriginalNativeSwapgs[0x10] = {0};

///
/// @brief Variable marking whether the "native_swapgs" function was detoured or not.
static BOOLEAN gNativeSwapgsHooked = FALSE;


///
/// @brief Hook descriptor for "native_swapgs" detour.
///
API_HOOK_DESCRIPTOR gSwapgsDetour
__section(".detours") =
{
    .FunctionName = "native_swapgs",
    .MinVersion   = DETOUR_MIN_VERSION_ANY,
    .MaxVersion   = DETOUR_MAX_VERSION_ANY,
    .Callback     = NULL,
    .Tag          = detTagSwapgs,
    .EnableFlags  = DETOUR_ENABLE_ALWAYS,

    .HandlersCount = 1,
    .Handlers =
    {
        {
            .MinVersion    = DETOUR_MIN_VERSION_ANY,
            .MaxVersion    = DETOUR_MAX_VERSION_ANY,
            .HypercallType = hypercallTypeNone,
            .CodeLength    = 5,                         // prologue + jmp back

            .Code = { 0 },

            .HypercallOffset     = DETOUR_INVALID_HYPERCALL,
            .RelocatedCodeOffset = 0x00,
        },
    },
};


static void
IntLixPatchSwapgs(
    void
    )
///
/// @brief Finds vulnerable SWAPGS instruction inside the kernel and applies mitigations.
///
{
    INTSTATUS status;
    QWORD symEnd;
    static BYTE lfence[3] = {0x0f, 0xae, 0xe8};

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SWAPGS))
    {
        return;
    }

    if (gNativeSwapgsHooked)
    {
        return;
    }

    gNativeSwapgs = IntKsymFindByName("native_swapgs", &symEnd);
    if (!gNativeSwapgs)
    {
        ERROR("[ERROR] IntKsymFindByName could not find native_swapgs\n");
    }
    else if (symEnd - gNativeSwapgs != ARRAYSIZE(gOriginalNativeSwapgs))
    {
        WARNING("[WARNING] 'native_swapgs' size is 0x%llx, which we don't support!\n", symEnd - gNativeSwapgs);

        IntDisasmGva(gNativeSwapgs, (DWORD)(symEnd - gNativeSwapgs));
    }
    else
    {
        status = IntKernVirtMemRead(gNativeSwapgs, sizeof(gOriginalNativeSwapgs), gOriginalNativeSwapgs, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for %llx: %08x\n", gNativeSwapgs, status);
            goto _instrument_kernel;
        }

        if (gOriginalNativeSwapgs[0] == 0x0f &&
            gOriginalNativeSwapgs[1] == 0x01 &&
            gOriginalNativeSwapgs[2] == 0xf8 &&
            gOriginalNativeSwapgs[3] == 0xc3)
        {
            BYTE newSwapgs[] =
            {
                0x0f, 0x01, 0xf8,           // swapgs
                0x0f, 0xae, 0xe8,           // lfence
                0xc3,                       // retn
            };

            LOG("[SWAPGS] Overwriting native_swapgs...\n");

            status = IntKernVirtMemWrite(gNativeSwapgs, sizeof(newSwapgs), newSwapgs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemWrite failed for rip %llx: %08x\n", gNativeSwapgs, status);
                goto _instrument_kernel;
            }

            gNativeSwapgsHooked = TRUE;
        }
        else if (gOriginalNativeSwapgs[0] == 0x55 &&
                 gOriginalNativeSwapgs[1] == 0x48 &&
                 gOriginalNativeSwapgs[2] == 0x89 &&
                 gOriginalNativeSwapgs[3] == 0xe5)
        {
            QWORD addr = 0;

            status = IntDetGetByTag(detTagSwapgs, &addr, NULL);
            if (!INT_SUCCESS(status))
            {
                LOG("[SWAPGS] Detouring native_swapgs...\n");

                status = IntDetSetHook(gNativeSwapgs, 0, &gSwapgsDetour, &gSwapgsDetour.Handlers[0]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntDetSetHook failed for 'native_swapgs': %08x\n", status);
                    goto _instrument_kernel;
                }

                status = IntDetGetByTag(detTagSwapgs, &addr, NULL);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntDetGetByTag failed after just setting it: %08x\n", status);
                    goto _instrument_kernel;
                }

                //
                // Instead of `MOV rbp, rsp`, do a `lfence`,
                // since the function doesn't actually use any stack
                //
                status = IntKernVirtMemWrite(addr + 1, sizeof(lfence), lfence);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Failed writing 'lfence' to the detour handler: %08x\n", status);
                    goto _instrument_kernel;
                }

                gNativeSwapgsHooked = TRUE;
            }
            else
            {
                LOG("[SWAPGS] 'native_swapgs' already detoured!");
            }
        }
        else
        {
            WARNING("[WARNING] Unknown native_swapgs...\n");

            IntDisasmGva(gNativeSwapgs, sizeof(gOriginalNativeSwapgs));
        }
    }

_instrument_kernel:
    for (QWORD page = gLixGuest->Layout.CodeStart;
         page < gLixGuest->Layout.CodeEnd;
         page += PAGE_SIZE)
    {
        BYTE *buf;

        status = IntVirtMemMap(page, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &buf);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR]IntVirtMemMap failed for 0x%llx : %08x\n", page, status);
            continue;
        }

        for (QWORD rip = 0; rip < PAGE_SIZE;)
        {
            QWORD symStart;
            char symName[LIX_SYMBOL_NAME_LEN];

            if (0x0F != buf[rip])
            {
                rip++;
                continue;
            }

            if (PAGE_REMAINING(rip) > 2 && (0x01 != buf[rip + 1] || 0xF8 != buf[rip + 2]))
            {
                rip++;
                continue;
            }
            else if (PAGE_REMAINING(rip) <= 2)
            {
                BYTE rest[2] = { 0 };

                status = IntKernVirtMemRead(rip + 1, sizeof(rest), rest, NULL);
                if (!INT_SUCCESS(status) || 0x01 != rest[0] || 0xF8 != rest[1])
                {
                    rip++;
                    continue;
                }
            }

            status = IntKsymFindByAddress(page + rip, LIX_SYMBOL_NAME_LEN, symName, &symStart, &symEnd);
            if (!INT_SUCCESS(status))
            {
                rip++;
                continue;
            }

            for (QWORD fRip = symStart; fRip < symEnd;)
            {
                INSTRUX instrux;

                status = IntDecDecodeInstruction(IG_CS_TYPE_64B, fRip, &instrux);
                if (!INT_SUCCESS(status))
                {
                    // The instruction is 'invalid' because the code-segment can be 16/32/64
                    TRACE("[SWAPGS] Function starts at %llx but it's instr at %llx is invalid (the code-segment type is not 64): %08x\n",
                          symStart, fRip, status);

                    fRip++;
                    continue;
                }

                if (instrux.Instruction != ND_INS_SWAPGS)
                {
                    goto _next_instr;
                }

                fRip += instrux.Length;
                status = IntDecDecodeInstruction(IG_CS_TYPE_64B, fRip, &instrux);
                if (!INT_SUCCESS(status))
                {
                    fRip++;
                    continue;
                }

                if (instrux.Length == 3 && instrux.Instruction == ND_INS_NOP)
                {
                    LOG("[SWAPGS] RIP %llx in function %s\n", fRip - instrux.Length, symName);

                    status = IntKernVirtMemRead(fRip,
                                                sizeof(gPatchedSwapgs[gTotalPatchedSwapgs].OriginalBytes),
                                                gPatchedSwapgs[gTotalPatchedSwapgs].OriginalBytes,
                                                NULL);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntKernVirtMemRead failed for rip %llx: %08x\n", fRip, status);
                        goto _next_instr;
                    }

                    status = IntKernVirtMemWrite(fRip, sizeof(lfence), lfence);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntKernVirtMemWrite failed for rip %llx: %08x\n", fRip, status);
                        goto _next_instr;
                    }

                    gPatchedSwapgs[gTotalPatchedSwapgs++].LfenceRip = fRip;
                }
                else
                {
                    char nd[ND_MIN_BUF_SIZE];

                    NdToText(&instrux, fRip, sizeof(nd), nd);
                    LOG("[SWAPGS] Ignoring at RIP %llx (%s) in function %s\n",
                        fRip - instrux.Length, nd, symName);
                }

                if (gTotalPatchedSwapgs >= ARRAYSIZE(gPatchedSwapgs))
                {
                    ERROR("[ERROR] More than %d 'swapgs; nop[3]', bail out...\n", gTotalPatchedSwapgs);
                    break;
                }

_next_instr:
                fRip += instrux.Length;
            }

            rip = symEnd - page;
        }

        IntVirtMemUnmap(&buf);
    }
}


static void
IntLixUnpatchSwapgs(
    void
    )
///
/// @brief Deactivates swapgs mitigations set by #IntLixPatchSwapgs.
///
{
    INTSTATUS status;

    if (gNativeSwapgsHooked)
    {
        // Let's hope it's not interrupted in this function
        for (DWORD cpu = 0; cpu < gGuest.CpuCount; cpu++)
        {
            IG_ARCH_REGS regs;

            status = IntGetGprs(cpu, &regs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGetGprs failed on cpu %d: %08x\n", cpu, status);
                continue;
            }

            if (regs.Rip >= gNativeSwapgs && regs.Rip < sizeof(gOriginalNativeSwapgs))
            {
                size_t offset = regs.Rip - gNativeSwapgs;

                switch (offset)
                {
                case 0:
                    LOG("[SWAPGS] RIP is at the start of patched native_swapgs, do nothing...\n");
                    break;

                case 6: // FALLTHROUGH
                case 3:
                    LOG("[SWAPGS] RIP is %llx ('%s'), move it to %llx ('retn')...\n",
                        regs.Rip, offset == 3 ? "lfence" : "retn", gNativeSwapgs + 3);

                    regs.Rip = gNativeSwapgs + 3;

                    status = IntSetGprs(cpu, &regs);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntSetGprs failed: %08x\n", status);
                    }

                    break;

                default:
                    LOG("[SWAPGS] Invalid RIP (%llx) position: %ld\n", regs.Rip, offset);
                    goto _restore_patched;
                }
            }
        }

        LOG("[SWAPGS] Restore original 'native_swapgs' at RIP %llx\n", gNativeSwapgs);

        status = IntKernVirtMemWrite(gNativeSwapgs, sizeof(gOriginalNativeSwapgs), gOriginalNativeSwapgs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed for 'native_swapgs': %08x\n", status);
        }

        gNativeSwapgsHooked = FALSE;
    }

_restore_patched:
    for (DWORD i = 0; i < gTotalPatchedSwapgs; i++)
    {
        if (!IS_KERNEL_POINTER_LIX(gPatchedSwapgs[i].LfenceRip))
        {
            ERROR("[ERROR] lfence rip %llx is not valid!\n", gPatchedSwapgs[i].LfenceRip);
            continue;
        }

        LOG("[SWAPGS] Restore at RIP %llx\n", gPatchedSwapgs[i].LfenceRip);

        status = IntKernVirtMemWrite(gPatchedSwapgs[i].LfenceRip,
                                     sizeof(gPatchedSwapgs[i].OriginalBytes),
                                     gPatchedSwapgs[i].OriginalBytes);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed for rip %llx: %08x\n",
                  gPatchedSwapgs[i].LfenceRip, status);
        }

        memzero(&gPatchedSwapgs[i], sizeof(gPatchedSwapgs[i]));
    }

    gTotalPatchedSwapgs = 0;
}


static INTSTATUS
IntLixKernelHandleRead(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handles reads performed from a Kernel module's text section.
///
/// @param[in]  Context Context supplied to #IntHookGpaSetHook. This should be a
///                     pointer to a #KERNEL_DRIVER object.
/// @param[in]  Hook    The #HOOK_GPA object which triggered this event.
/// @param[in]  Address The accessed guest physical address.
/// @param[out] Action  The action that has to be taken.
///
/// @return #INT_STATUS_SUCCESS            On success.
/// @return #INT_STATUS_REMOVE_HOOK_ON_RET If the hook placed on the page containing the address should be removed.
///
{
    INTSTATUS status;
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    CHAR ksymRead[LIX_SYMBOL_NAME_LEN] = { 0 };
    INTRO_ACTION_REASON reason = introReasonUnknown;
    KERNEL_DRIVER *pDriver = Context;
    HOOK_GVA *pGvaHook = NULL;
    QWORD rip = gVcpu->Regs.Rip;
    QWORD size = gVcpu->AccessSize;
    QWORD gva = 0;
    QWORD ksymStart = 0;
    BOOLEAN exitAfterInformation = FALSE;

    *Action = introGuestNotAllowed;

    pGvaHook = (HOOK_GVA *)(((HOOK_GPA *)Hook)->Header.ParentHook);
    gva = pGvaHook->GvaPage + (Address & PAGE_OFFSET);

    for (int p = 0; p < lixActivePatchCount; p++)
    {
        LIX_ACTIVE_PATCH *pActivePatch = &gLixGuest->ActivePatch[p];

        if (IN_RANGE_LEN(gva, pActivePatch->Gva, pActivePatch->Length))
        {
            *Action = introGuestAllowed;

            return INT_STATUS_SUCCESS;
        }
    }

    if ((gVcpu->Instruction.Instruction == ND_INS_VERW || gVcpu->Instruction.Instruction == ND_INS_VERR) &&
        (PAGE_FRAME_NUMBER(gva) == PAGE_FRAME_NUMBER(rip)) && gVcpu->Instruction.Operands[0].Info.Memory.IsRipRel)
    {
        // VERW instruction is used to to cause the processor to overwrite buffer values that are affected by MDS
        // The VERW operand is a valid writable data segment near the rip (e.g. RIP - 2)
        // RIP:0xffffffff84d75ed6       'VERW      word ptr [rel 0xffffffff84d75ed4]'

        *Action = introGuestAllowed;

        return INT_STATUS_REMOVE_HOOK_ON_RET;
    }

    status = IntKsymFindByAddress(gva, sizeof(ksymRead), ksymRead, &ksymStart, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKsymFindByAddress failed for %llx: 0x%08x\n", gva, status);

        *Action = introGuestNotAllowed;
        reason = introReasonInternalError;
    }
    else
    {
        if (gva + size - ksymStart <= 5)
        {
            *Action = introGuestAllowed;

            return INT_STATUS_SUCCESS;
        }
    }

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptKernelGetOriginator failed with status: 0x%08x\n", status);

        *Action = introGuestNotAllowed;
        reason = introReasonInternalError;

        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(pDriver,
                                   Address,
                                   gva,
                                   introObjectTypeKmModule,
                                   ZONE_READ,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed with status: 0x%08x\n", status);

        *Action = introGuestNotAllowed;
        reason = introReasonInternalError;

        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(pDriver->ProtectionFlag, Action, &reason))
    {
        EVENT_EPT_VIOLATION *pEptViol = &gAlert.Ept;
        CHAR ksym[LIX_SYMBOL_NAME_LEN];

        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = reason;
        pEptViol->Header.MitreID = idExploitRemote;

        pEptViol->Header.Flags = IntAlertCoreGetFlags(pDriver->ProtectionFlag, reason);

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        IntAlertFillLixKmModule(originator.Original.Driver, &pEptViol->Originator.Module);
        IntAlertFillLixKmModule(originator.Return.Driver, &pEptViol->Originator.ReturnModule);

        IntAlertFillLixKmModule(victim.Object.Module.Module, &pEptViol->Victim.Module);

        IntAlertFillLixCurrentProcess(&pEptViol->Header.CurrentProcess);

        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        status = IntKsymFindByAddress(gva, sizeof(ksym), ksym, NULL, NULL);
        if (INT_SUCCESS(status))
        {
            memcpy(pEptViol->FunctionName, ksym, sizeof(pEptViol->FunctionName) - 1);
        }

        IntLixDrvGetSecName(pDriver, gva, pEptViol->ModifiedSectionName);

        IntLixDrvGetSecName(originator.Original.Driver, originator.Original.Rip, pEptViol->RipSectionName);

        IntAlertFillVersionInfo(&pEptViol->Header);

        IntAlertFillCodeBlocks(originator.Original.Rip, gGuest.Mm.SystemCr3, FALSE, &pEptViol->CodeBlocks);

        IntAlertFillExecContext(gGuest.Mm.SystemCr3, &pEptViol->ExecContext);

        IntAlertEptFillFromVictimZone(&victim, pEptViol);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    IntPolicyCoreForceBetaIfNeeded(pDriver->ProtectionFlag, Action);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixHookKernelRead(
    void
    )
///
/// @brief Establishes read hooks for Kernel code.
///
/// @return #INT_STATUS_SUCCESS         On success.
/// @return #INT_STATUS_NOT_NEEDED_HINT If the hooks are already established.
///
{
    INTSTATUS status;
    KERNEL_DRIVER *pDriver;

    pDriver = gGuest.KernelDriver;
    if (NULL == pDriver)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (pDriver->Protected && (pDriver->ProtectionFlag & INTRO_OPT_PROT_KM_LX_TEXT_READS))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL == pDriver->Lix.HookObjectRead)
    {
        status = IntHookObjectCreate(introObjectTypeKmModule, 0, &pDriver->Lix.HookObjectRead);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }
    }

    for (QWORD crtGva = gLixGuest->Layout.CodeStart; crtGva < gLixGuest->Layout.CodeEnd; crtGva += PAGE_SIZE)
    {
        if ((gLixGuest->Layout.CodeEnd - crtGva < PAGE_SIZE) &&
            IN_RANGE(gLixGuest->Layout.ExTableStart, crtGva, crtGva + PAGE_SIZE))
        {
            continue;
        }

        DWORD size = (DWORD)(gLixGuest->Layout.CodeEnd - crtGva < PAGE_SIZE ? gLixGuest->Layout.CodeEnd - crtGva : PAGE_SIZE);
        status = IntHookObjectHookRegion(pDriver->Lix.HookObjectRead,
                                         0,
                                         crtGva,
                                         size,
                                         IG_EPT_HOOK_READ,
                                         IntLixKernelHandleRead,
                                         gGuest.KernelDriver,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed for region 0x%016llx - 0x%016llx: 0x%08x\n",
                  crtGva, crtGva + PAGE_SIZE, status);
        }
    }

    pDriver->ProtectionFlag |= INTRO_OPT_PROT_KM_LX_TEXT_READS;
    pDriver->Protected = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixHookKernelWrite(
    void
    )
///
/// @brief Establishes read and write hooks for Kernel code.
///
/// @return #INT_STATUS_SUCCESS         On success.
/// @return #INT_STATUS_NOT_NEEDED_HINT If the hooks are already established.
///
{
    INTSTATUS status;
    KERNEL_DRIVER *pDriver;

    pDriver = gGuest.KernelDriver;
    if (NULL == pDriver)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (pDriver->Protected && (pDriver->ProtectionFlag & INTRO_OPT_PROT_KM_LX))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (NULL == pDriver->HookObject)
    {
        status = IntHookObjectCreate(introObjectTypeKmModule, 0, &pDriver->HookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }
    }

    status = IntHookObjectHookRegion(pDriver->HookObject,
                                     0,
                                     gLixGuest->Layout.CodeStart,
                                     (DWORD)(gLixGuest->Layout.CodeEnd - gLixGuest->Layout.CodeStart),
                                     IG_EPT_HOOK_WRITE,
                                     IntLixDrvHandleWrite,
                                     gGuest.KernelDriver,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed for region 0x%016llx - 0x%016llx: 0x%08x\n",
              gLixGuest->Layout.CodeStart, gLixGuest->Layout.CodeEnd, status);
    }

    status = IntHookObjectHookRegion(pDriver->HookObject,
                                     0,
                                     gLixGuest->Layout.RoDataStart,
                                     (DWORD)(gLixGuest->Layout.RoDataEnd - gLixGuest->Layout.RoDataStart),
                                     IG_EPT_HOOK_WRITE,
                                     IntLixDrvHandleWrite,
                                     gGuest.KernelDriver,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed for region 0x%016llx - 0x%016llx: 0x%08x\n",
              gLixGuest->Layout.RoDataStart, gLixGuest->Layout.RoDataEnd, status);
    }

    if (gLixGuest->Layout.ExTableStart)
    {
        status = IntHookObjectHookRegion(pDriver->HookObject,
                                         0,
                                         gLixGuest->Layout.ExTableStart,
                                         (DWORD)(gLixGuest->Layout.ExTableEnd - gLixGuest->Layout.ExTableStart),
                                         IG_EPT_HOOK_WRITE,
                                         IntLixDrvHandleWrite,
                                         gGuest.KernelDriver,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed for region 0x%016llx - 0x%016llx : 0x%08x\n",
                  gLixGuest->Layout.ExTableStart, gLixGuest->Layout.ExTableEnd, status);
        }
    }
    else
    {
        WARNING("[WARNING] ExTable is not available. Will skip protection.\n");
    }

    pDriver->Protected = TRUE;
    pDriver->ProtectionFlag |= INTRO_OPT_PROT_KM_LX;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixKernelWriteProtect(
    void
    )
///
/// @brief Activates kernel protection.
///
/// This function will protect kernel code against malicious writes.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntLixHookKernelWrite();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixHookKernel failed: 0x%08x\n", status);
        return status;
    }

    IntLixPatchSwapgs();

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixKernelReadProtect(
    void
    )
///
/// @brief Activates kernel protection.
///
/// This function will protect kernel code against malicious reads.
///
/// @returns #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntLixHookKernelRead();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixHookKernel failed: 0x%08x\n", status);
        return status;
    }

    IntLixPatchSwapgs();

    return INT_STATUS_SUCCESS;
}


static void
IntLixUnhookKernelWrite(
    void
    )
///
/// @brief Removes write hooks from the kernel code section.
///
{
    KERNEL_DRIVER *pDriver;

    pDriver = gGuest.KernelDriver;
    if (NULL == pDriver)
    {
        return;
    }

    IntLixUnpatchSwapgs();

    pDriver->Protected = FALSE;
    pDriver->ProtectionFlag = 0;

    if (NULL == pDriver->HookObject)
    {
        return;
    }

    IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&pDriver->HookObject, 0);
}


static void
IntLixUnhookKernelRead(
    void
    )
///
/// @brief Removes write hooks from the kernel code section.
///
{
    KERNEL_DRIVER *pDriver;

    pDriver = gGuest.KernelDriver;
    if (NULL == pDriver)
    {
        return;
    }

    pDriver->Protected = FALSE;
    pDriver->ProtectionFlag = 0;

    if (NULL == pDriver->Lix.HookObjectRead)
    {
        return;
    }

    IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&pDriver->Lix.HookObjectRead, 0);
}


void
IntLixKernelWriteUnprotect(
    void
    )
///
/// @brief Deactivates the kernel protection against write.
///
{
    if (!(gGuest.CoreOptions.Current & (INTRO_OPT_PROT_KM_LX_TEXT_READS | INTRO_OPT_PROT_KM_LX)))
    {
        IntLixUnpatchSwapgs();
    }

    IntLixUnhookKernelWrite();
}


void
IntLixKernelReadUnprotect(
    void
    )
///
/// @brief Deactivates the kernel protection against read.
///
{
    if (!(gGuest.CoreOptions.Current & (INTRO_OPT_PROT_KM_LX_TEXT_READS | INTRO_OPT_PROT_KM_LX)))
    {
        IntLixUnpatchSwapgs();
    }

    IntLixUnhookKernelRead();
}
