/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixvdso.h"
#include "alerts.h"
#include "decoder.h"
#include "hook.h"
#include "lixstack.h"
#include "lixksym.h"


#define LIX_VDSO_GPA_HOOK_PAGE_COUNT    3

static void *gVdsoHook = NULL;
static void *gVdsoGpaHook[LIX_VDSO_GPA_HOOK_PAGE_COUNT];


static LIX_SYMBOL gInitVdsoSym = { 0 };
static LIX_SYMBOL gAddNopsSym = { 0 };
static LIX_SYMBOL gTextPokeEarlySym = { 0 };



static void
IntLixVdsoHandleKernelModeWrite(
    _In_ QWORD Address,
    _In_ INTRO_OBJECT_TYPE Type,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief Handles vDSO modification (from kernel-mode) detected by the EPT mechanism.
///
/// If a write from kernel-mode occurs the exceptions mechanism is used to decide if the write should be allowed.
///
/// @param[in]   Address     The modified guest physical address.
/// @param[in]   Type        The type of the modified zone.
/// @param[out]  Action      The action that will be taken.
/// @param[out]  Reason      The reason for which Action is taken.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    BOOLEAN except = TRUE;

    *Reason = introReasonUnknown;
    *Action = introGuestNotAllowed;

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        *Reason = introReasonNoException;
        except = FALSE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptKernelGetOriginator failed with status: 0x%08x\n", status);
        *Reason = introReasonInternalError;
        except = FALSE;
    }

    status = IntExceptGetVictimEpt(NULL, Address, gVcpu->Gla, Type, ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        *Reason = introReasonInternalError;
        ERROR("[ERROR] IntExceptGetVictimEpt failed with status: 0x%08x\n", status);
        except = FALSE;
    }

    if (except)
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, Reason, introEventEptViolation);
    }
    else
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, *Reason);
    }

    STATS_EXIT(statsExceptionsKern);
}


static void
IntLixVdsoHandleUserModeWrite(
    _In_ QWORD Address,
    _In_ INTRO_OBJECT_TYPE Type,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief Handles vDSO modification (from user-mode) detected by the EPT mechanism.
///
/// If a write from user-mode occurs the exceptions mechanism is used to decide if the write should be allowed.
///
/// @param[in]   Address     The modified guest physical address.
/// @param[in]   Type        The type of the modified zone.
/// @param[out]  Action      The action that will be taken.
/// @param[out]  Reason      The reason for which Action is taken.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_TASK_OBJECT *pTask = NULL;
    INSTRUX *pInstrux = &gVcpu->Instruction;
    EXCEPTION_UM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    BOOLEAN except = TRUE;

    *Reason = introReasonUnknown;
    *Action = introGuestNotAllowed;

    pTask = IntLixTaskGetCurrent(gVcpu->Index);
    if (NULL == pTask)
    {
        ERROR("[ERROR] No current task on CPU %d\n", gVcpu->Index);
        except = FALSE;
    }

    STATS_ENTER(statsExceptionsUser);

    if (pTask != NULL)
    {
        status = IntExceptUserGetOriginator(pTask, TRUE, gVcpu->Regs.Rip, pInstrux, &originator);
        if (status == INT_STATUS_EXCEPTION_BLOCK)
        {
            *Reason = introReasonNoException;
            except = FALSE;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptUserGetOriginator failed with status: 0x%08x\n", status);
            *Reason = introReasonInternalError;
            except = FALSE;
        }
    }

    status = IntExceptGetVictimEpt(NULL, Address, gVcpu->Gla, Type, ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        *Reason = introReasonInternalError;
        ERROR("[ERROR] IntExceptGetVictimEpt failed with status: 0x%08x\n", status);
        except = FALSE;
    }

    victim.Object.NameHash = victim.Object.Type == introObjectTypeVdso ? umExcNameVdso : umExcNameVsyscall;

    if (except)
    {
        IntExcept(&victim, &originator, exceptionTypeUm, Action, Reason, introEventEptViolation);
    }
    else
    {
        IntExceptUserLogInformation(&victim, &originator, *Action, *Reason);
    }

    STATS_EXIT(statsExceptionsUser);
}


static INTSTATUS
IntLixVdsoHandleWriteCommon(
    _In_opt_ void *Context,
    _In_ HOOK_GPA *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handles vDSO modification detected by the EPT mechanism.
///
/// This function calls the #IntLixVdsoHandleKernelModeWrite or #IntLixVdsoHandleUserModeWrite according to the RIP to
/// handle the vDSO write. If the write is not allowed or feedback-only reason is set, the event is reported to the
/// integrator.
///
/// @param[in]       Context     The type of the modified zone.
/// @param[in]       Hook        The #HOOK_GPA for which this callback was invoked.
/// @param[in]       Address     The modified guest physical address.
/// @param[out]      Action      The action that will be taken.
///
/// @retval          #INT_STATUS_SUCCESS     Always.
///
{
    INTSTATUS status;
    INTRO_OBJECT_TYPE type = (INTRO_OBJECT_TYPE)(QWORD)(Context);
    INTRO_ACTION_REASON reason = introReasonUnknown;

    *Action = introGuestNotAllowed;

    if (IS_KERNEL_POINTER_LIX(gVcpu->Regs.Rip))
    {
        IntLixVdsoHandleKernelModeWrite(Address, type, Action, &reason);
    }
    else
    {
        IntLixVdsoHandleUserModeWrite(Address, type, Action, &reason);
    }

    if (IntPolicyCoreTakeAction(INTRO_OPT_PROT_KM_VDSO, Action, &reason))
    {
        EVENT_EPT_VIOLATION *pEptViol = &gAlert.Ept;
        memzero(pEptViol, sizeof(*pEptViol));

        pEptViol->Header.Action = *Action;
        pEptViol->Header.Reason = introReasonNoException;
        pEptViol->Header.MitreID = idHooking;

        pEptViol->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_VDSO, reason);

        pEptViol->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

        IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

        if (IS_KERNEL_POINTER_LIX(gVcpu->Regs.Rip))
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByAddress(gVcpu->Regs.Rip);
            if (pDriver)
            {
                IntAlertFillLixKmModule(pDriver, &pEptViol->Originator.Module);
            }
        }

        pEptViol->Victim.Type = type;

        IntAlertFillLixCurrentProcess(&pEptViol->Header.CurrentProcess);

        pEptViol->Offset = gVcpu->Gla & PAGE_OFFSET;
        pEptViol->VirtualPage = gVcpu->Gla & PAGE_MASK;
        pEptViol->PhysicalPage = Hook->GpaPage;

        pEptViol->HookStartVirtual = gVcpu->Gla & PAGE_MASK;
        pEptViol->HookStartPhysical = Hook->GpaPage;

        pEptViol->Violation = IG_EPT_HOOK_WRITE;
        pEptViol->ZoneTypes = ZONE_LIB_CODE;

        IntAlertFillVersionInfo(&pEptViol->Header);

        IntAlertFillCodeBlocks(gVcpu->Regs.Rip, gVcpu->Regs.Cr3, FALSE, &pEptViol->CodeBlocks);
        IntAlertFillExecContext(0, &pEptViol->ExecContext);

        status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
        }
    }

    IntPolicyCoreForceBetaIfNeeded(INTRO_OPT_PROT_KM_VDSO, Action);

    return INT_STATUS_SUCCESS;
}


static __forceinline BOOLEAN
IntLixVdsoIsInitWrite(
    _In_ QWORD Rip
    )
///
/// @brief Checks if the write is over the vDSO on the initialization phase.
///
/// This function verify if the provided RIP:
///     - is in range [text_poke_early_start, text_poke_early_end];
///     - is in range [add_nops_start, add_nops_end];
///     - is in range [init_vdso_start, init_vdso_end];
///
/// @param[in]  Rip     The originator RIP of the write.
///
/// @retval             True if at least one condition is met, otherwise false.
{
    return (IN_RANGE(Rip, gTextPokeEarlySym.Start, gTextPokeEarlySym.End) ||
            IN_RANGE(Rip, gAddNopsSym.Start, gAddNopsSym.End) ||
            IN_RANGE(Rip, gInitVdsoSym.Start, gInitVdsoSym.End));
}


static INTSTATUS
IntLixVdsoHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Handles vDSO modification detected by the EPT mechanism.
///
/// This function checks if the modification is an initialization write; if the 'init' write is detected, the write is
/// allowed, otherwise #IntLixVdsoHandleWriteCommon is called.
/// The #IntLixVdsoIsInitWrite is called for the stack-trace too.
///
/// @param[in]       Context     The type of the modified zone.
/// @param[in]       Hook        The #HOOK_GPA for which this callback was invoked.
/// @param[in]       Address     The modified guest physical address.
/// @param[out]      Action      The action that will be taken.
///
/// @retval         #INT_STATUS_SUCCESS     Always.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    STACK_TRACE st = { 0 };
    STACK_ELEMENT stElements[8] = { 0 };

    st.Traces = stElements;

    if (IntLixVdsoIsInitWrite(pRegs->Rip))
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    status = IntLixStackTraceGetReg(0, pRegs, ARRAYSIZE(stElements), 0, &st);
    if (INT_SUCCESS(status) && st.NumberOfTraces > 0)
    {
        for (DWORD i = 0; i < st.NumberOfTraces; i++)
        {
            if (IntLixVdsoIsInitWrite(st.Traces[i].ReturnAddress))
            {
                *Action = introGuestAllowed;
                return INT_STATUS_SUCCESS;
            }
        }
    }

    return IntLixVdsoHandleWriteCommon(Context, Hook, Address, Action);
}


static INTSTATUS
IntLixVdsoResolveImageAddress(
    _In_ char *FunctionName,
    _Out_ QWORD *Address
    )
///
/// @brief Parse the provided function and search the 'vdso_image...' address.
///
/// The function decode the instructions of the provided function until the 'mov rdi, immediate; call/jmp map_vdso'
/// pattern is found.
/// This function is used for the Linux guests that don't export the 'vdso_image...' address.
///
/// @param[in]  FunctionName    The provided function name.
/// @param[out] Address         The address of the 'vdso_image...'.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If the address of the 'vdso_image...' is not found.
///
{
    INTSTATUS status;
    INSTRUX instrux;
    QWORD funcStart = 0;
    QWORD funcEnd = 0;
    QWORD mapVdsoAddr;
    QWORD address = 0;
    QWORD rdiValue = 0;

    mapVdsoAddr = IntKsymFindByName("map_vdso", NULL);
    if (!mapVdsoAddr)
    {
        ERROR("[ERROR] IntKsymFindByName could not find map_vdso\n");
        return INT_STATUS_NOT_FOUND;
    }

    funcStart = IntKsymFindByName(FunctionName, &funcEnd);
    if (!funcStart)
    {
        ERROR("[ERROR] Could not find %s in kallsyms\n", FunctionName);
        return INT_STATUS_NOT_FOUND;
    }

    rdiValue = 0;
    while (funcStart < funcEnd)
    {
        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, funcStart, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed: %08x\n", status);
            return status;
        }

        funcStart += instrux.Length;

        if (ND_INS_MOV == instrux.Instruction &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[0].Info.Register.Reg == NDR_RDI) // mov RDI, vdso_image_64;
        {
            if (instrux.Operands[1].Type == ND_OP_IMM)
            {
                rdiValue = SIGN_EX_32(instrux.Operands[1].Info.Immediate.Imm);
            }
            else if (instrux.Operands[1].Type == ND_OP_MEM)
            {
                QWORD tmp = funcStart + instrux.Operands[1].Info.Memory.Disp;
                status = IntKernVirtMemFetchQword(tmp, &tmp);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntKernVirtMemFetchQword failed for 0x016%llx: 0x%08x\n", tmp, status);
                }
                else
                {
                    rdiValue = tmp;
                }
            }
            else
            {
                ERROR("[ERROR] Unsupported operand type for <mov rdi, ...> instruction: %d\n",
                      instrux.Operands[1].Type);
            }

            continue;
        }

        if ((instrux.Instruction == ND_INS_CALLNR || instrux.Instruction == ND_INS_JMPNR) &&
            instrux.Operands[0].Type == ND_OP_OFFS &&
            mapVdsoAddr == (funcStart + instrux.Operands[0].Info.RelativeOffset.Rel))
        {
            address = rdiValue;
            break;
        }
    }

    if (address)
    {
        *Address = address;
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixVdsoResolveDynamicOffset(
    void
    )
///
/// @brief Fetch the address of the 'vdso_image_64', 'vdso_image_x32' ksyms or the address of the 'vdso_start',
/// 'vdso_end', 'vdsox32_start', 'vdsox32_end' ksyms.
///
/// If the guest has vDSO image struct this function fetch the addresses of the 'vdso_image_64', 'vdso_image_x32'
/// ksyms. If these symbols are exported, this function call the IntKsymFindByName , otherwise
/// #IntLixVdsoResolveImageAddress is called.
/// If the guest hasn't vDSO image struct the function fetch the addresses of the 'vdso_start', 'vdso_end',
/// 'vdsox32_start', 'vdsox32_end' ksyms by calling the IntKsymFindByName.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_NOT_FOUND   If the addresses are not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (LIX_FIELD(Info, HasVdsoImageStruct))
    {
        QWORD vdsoImage = 0;
        QWORD vdsoSize = 0;

        vdsoImage = IntKsymFindByName("vdso_image_64", NULL);
        if (!vdsoImage)
        {
            status = IntLixVdsoResolveImageAddress("arch_setup_additional_pages", &vdsoImage);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] vdso_image_64 not found: 0x%08x\n", status);
                return status;
            }
        }

        status = IntKernVirtMemFetchQword(vdsoImage, &gLixGuest->Vdso.VdsoStart);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed fetching from vdso_image %llx: 0x%08x\n", vdsoImage, status);
            return status;
        }

        status = IntKernVirtMemFetchQword(vdsoImage + sizeof(QWORD), &vdsoSize);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed fetching from vdso_image %llx: 0x%08x\n", vdsoImage, status);
            return status;
        }

        if (vdsoSize > 2 * PAGE_SIZE)
        {
            WARNING("[WARNING] vdso size is too large: %llu!\n", vdsoSize);
            vdsoSize = 2 * PAGE_SIZE;
        }

        gLixGuest->Vdso.VdsoEnd = gLixGuest->Vdso.VdsoStart + vdsoSize;

        vdsoImage = IntKsymFindByName("vdso_image_x32", NULL);
        if (!vdsoImage)
        {
            status = IntLixVdsoResolveImageAddress("compat_arch_setup_additional_pages", &vdsoImage);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] vdso_image_x32 not found: 0x%08x\n", status);
                goto _exit;
            }
        }

        status = IntKernVirtMemFetchQword(vdsoImage, &gLixGuest->Vdso.Vdso32Start);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed fetching from vdso_image_x32 %llx: 0x%08x\n", vdsoImage, status);
            return status;
        }

        status = IntKernVirtMemFetchQword(vdsoImage + sizeof(QWORD), &vdsoSize);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed fetching from vdso_image_x32 %llx: 0x%08x\n", vdsoImage, status);
            return status;
        }

        if (vdsoSize > 2 * PAGE_SIZE)
        {
            WARNING("[WARNING] vdso size is too large: %llu!\n", vdsoSize);
            vdsoSize = 2 * PAGE_SIZE;
        }

        gLixGuest->Vdso.Vdso32End = gLixGuest->Vdso.Vdso32Start + vdsoSize;
    }
    else
    {
        gLixGuest->Vdso.VdsoStart = IntKsymFindByName("vdso_start", NULL);
        if (!gLixGuest->Vdso.VdsoStart)
        {
            WARNING("[WARNING] 'vdso_start' not found\n");
            return INT_STATUS_NOT_FOUND;
        }

        gLixGuest->Vdso.VdsoEnd = IntKsymFindByName("vdso_end", NULL);
        if (!gLixGuest->Vdso.VdsoEnd)
        {
            WARNING("[WARNING] 'vdso_end' not found\n");
            return INT_STATUS_NOT_FOUND;
        }

        gLixGuest->Vdso.Vdso32Start = IntKsymFindByName("vdsox32_start", NULL);
        if (!gLixGuest->Vdso.Vdso32Start)
        {
            LOG("[INFO] Guest has been built without x32 ABI support!\n");
            status = INT_STATUS_SUCCESS;
            goto _exit;
        }

        gLixGuest->Vdso.Vdso32End = IntKsymFindByName("vdsox32_end", NULL);
        if (!gLixGuest->Vdso.Vdso32End)
        {
            WARNING("[WARNING] 'vdso_end_x32' not found\n");
            status = INT_STATUS_SUCCESS;
            goto _exit;
        }
    }

    status = INT_STATUS_SUCCESS;

_exit:
    return status;
}


static INTSTATUS
IntLixVdsoDynamicProtectRelocate(
    void
    )
///
/// @brief Protect the vDSO using GPA hooks.
///
/// This function is used if the vDSO image is relocated; the kernel 2.6 discards the initial vDSO image and move it to
/// another guest virtual address.
/// In order to find the guest physical address of the vDSO image, the function fetch the
/// task_struct->mm->context->vdso of the 'init' task that is a guest virtual address of the mapped vDSO image in that
/// task. The address of the vDSO image is translated to the guest physical address and then the function set a GPA hook.
///
/// @retval     #INT_STATUS_SUCCESS                  On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT     If the vDSO is not initialized yet.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD vdsoStart = 0;
    QWORD vdsoEnd = 0;
    DWORD index;
    LIX_TASK_OBJECT *pTask;

    for (DWORD i = 0; i < ARRAYSIZE(gVdsoGpaHook); i++)
    {
        if (gVdsoGpaHook[i] != NULL)
        {
            return INT_STATUS_NOT_NEEDED_HINT;
        }
    }

    pTask = IntLixTaskFindByPid(1);
    if (pTask == NULL)
    {
        LOG("[LIX-VDSO] Will protect the vdso later...\n");
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    status = IntLixVdsoFetchAddress(pTask, &vdsoStart);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVdsoFetchAddress failed with status: 0x%08x.\n", status);
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    vdsoEnd = vdsoStart + (gLixGuest->Vdso.VdsoEnd - gLixGuest->Vdso.VdsoStart);

    index = 0;
    for (QWORD current = vdsoStart & PAGE_MASK; (current < vdsoEnd) &&
         (index < ARRAYSIZE(gVdsoGpaHook)); current += PAGE_SIZE)
    {
        QWORD physAddr;
        status =  IntTranslateVirtualAddress(current, pTask->Cr3, &physAddr);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntTranslateVirtualAddress failed with status: 0x%08x. Will retry later...\n", status);
            return INT_STATUS_NOT_INITIALIZED_HINT;
        }

        status = IntHookGpaSetHook(physAddr,
                                   PAGE_SIZE,
                                   IG_EPT_HOOK_WRITE,
                                   IntLixVdsoHandleWrite,
                                   (void *)(introObjectTypeVdso),
                                   0,
                                   0,
                                   (HOOK_GPA **)(&gVdsoGpaHook[index]));

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaSetHook failed: 0x%08x\n", status);
            return status;
        }
        index++;

        TRACE("[LIX-VDSO] Protecting VDSO physical page: 0x%llx.\n", physAddr);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixVdsoDynamicProtectNonRelocate(
    void
    )
///
/// @brief Protect the vDSO using GVA hooks.
///
/// This function is used if the vDSO image that is not relocated (see #IntLixVdsoDynamicProtectRelocate).
/// This function hooks the [vdso_start, vdso_end] range and the [vdso32_start, vdso32_end] range, if any.
///
/// @retval     #INT_STATUS_SUCCESS                  On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD hookSize = 0;

    if (NULL == gVdsoHook)
    {
        status = IntHookObjectCreate(introObjectTypeVdso, 0, &gVdsoHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            return status;
        }
    }

    hookSize = ALIGN_UP(gLixGuest->Vdso.VdsoEnd - gLixGuest->Vdso.VdsoStart, PAGE_SIZE);

    if (IntHookObjectFindRegion(gLixGuest->Vdso.VdsoStart, gVdsoHook, IG_EPT_HOOK_WRITE) != NULL)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntHookObjectHookRegion(gVdsoHook,
                                     0,
                                     gLixGuest->Vdso.VdsoStart,
                                     hookSize,
                                     IG_EPT_HOOK_WRITE,
                                     IntLixVdsoHandleWrite,
                                     (void *)(introObjectTypeVdso),
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed setting hook on vdso: 0x%08x!\n", status);
        gVdsoHook = NULL;

        return status;
    }

    TRACE("[INFO] Protected vdso %llx -> %llx\n", gLixGuest->Vdso.VdsoStart, gLixGuest->Vdso.VdsoEnd);

    if (gLixGuest->Vdso.Vdso32Start && gLixGuest->Vdso.Vdso32End)
    {
        hookSize = ALIGN_UP(gLixGuest->Vdso.Vdso32End - gLixGuest->Vdso.Vdso32Start, PAGE_SIZE);

        status = IntHookObjectHookRegion(gVdsoHook,
                                         0,
                                         gLixGuest->Vdso.Vdso32Start,
                                         hookSize,
                                         IG_EPT_HOOK_WRITE,
                                         IntLixVdsoHandleWrite,
                                         (void *)(introObjectTypeVdso),
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed setting hook on vdso: 0x%08x!\n", status);
            gVdsoHook = NULL;

            return status;
        }

        TRACE("[INFO] Protected vdso_32 %llx -> %llx\n", gLixGuest->Vdso.Vdso32Start, gLixGuest->Vdso.Vdso32End);
    }

    return status;
}


INTSTATUS
IntLixVdsoDynamicProtect(
    void
    )
///
/// @brief This function activates the protection for the vDSO image.
///
/// The function checks if the vDSO image is relocated and calls the proper function to activate the protection.
/// The 'init_vdso', 'text_poke_early', 'add_nops' ksyms are fetched in order to except the init writes
/// (see #IntLixVdsoIsInitWrite).
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (gLixGuest->Vdso.VdsoStart >= MAX(gLixGuest->Layout.RoDataEnd, gLixGuest->Layout.DataEnd))
    {
        status = IntLixVdsoDynamicProtectRelocate();
    }
    else
    {
        status = IntLixVdsoDynamicProtectNonRelocate();
    }

    if (status == INT_STATUS_NOT_NEEDED_HINT || status == INT_STATUS_NOT_INITIALIZED_HINT)
    {
        return INT_STATUS_SUCCESS;
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to protect the vdso...\n");
        return status;
    }

    gInitVdsoSym.Start = IntKsymFindByName("init_vdso", &gInitVdsoSym.End);
    if (!gInitVdsoSym.Start)
    {
        WARNING("[WARNING] Failed finding 'init_vdso'. Some FPs may follow\n");
        gInitVdsoSym.Start = gInitVdsoSym.End = 0;
    }

    gTextPokeEarlySym.Start = IntKsymFindByName("text_poke_early", &gTextPokeEarlySym.End);
    if (!gTextPokeEarlySym.Start)
    {
        WARNING("[WARNING] Failed finding 'text_poke_early'. Some FPs may follow\n");
        gTextPokeEarlySym.Start = gTextPokeEarlySym.End = 0;
    }

    gAddNopsSym.Start = IntKsymFindByName("add_nops", &gAddNopsSym.End);
    if (!gAddNopsSym.Start)
    {
        WARNING("[WARNING] Failed finding 'add_nops'. Some FPs may follow\n");
        gAddNopsSym.Start = gAddNopsSym.End = 0;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixVdsoFixedProtect(
    void
    )
///
/// @brief This function activates the protection for the VSYSCALL.
///
/// A GVA hook is set for the VSYSCALL page.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If the kernel is build without VSYSCALL support.
///
{
    INTSTATUS status;
    QWORD vdsoPhys;

    if (!LIX_FIELD(Info, HasVdsoFixed))
    {
        TRACE("[INFO] This kernel is built without VSYSCALL support!");
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntTranslateVirtualAddress(LIX_VDSO_FIXED, gGuest.Mm.SystemCr3, &vdsoPhys);
    if (!INT_SUCCESS(status))
    {
        LOG("[INFO] Fixed VDSO is not present @ 0x%016llx (0x%08x)\n", LIX_VDSO_FIXED, status);
        return status;
    }

    if (NULL == gVdsoHook)
    {
        status = IntHookObjectCreate(introObjectTypeVdso, 0, &gVdsoHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed with status: 0x%08x\n", status);
            return status;
        }
    }

    gLixGuest->Vdso.Vsyscall = LIX_VDSO_FIXED;

    status = IntHookObjectHookRegion(gVdsoHook,
                                     0,
                                     gLixGuest->Vdso.Vsyscall,
                                     PAGE_SIZE,
                                     IG_EPT_HOOK_WRITE,
                                     IntLixVdsoHandleWriteCommon,
                                     (void *)(introObjectTypeVsyscall),
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed setting hook on vsyscall with status: 0x%08x\n", status);
    }
    else
    {
        TRACE("[INFO] Protected VSYSCALL @ 0x%016llx\n", LIX_VDSO_FIXED);
    }

    return status;
}


INTSTATUS
IntLixVdsoFetchAddress(
    _In_ LIX_TASK_OBJECT *Task,
    _Out_ QWORD *Address
    )
///
/// @brief Fetch the guest virtual address of the vDSO mapped on the provided task.
///
/// @param[in]  Task        The task from which the vDSO address is fetched.
/// @param[out] Address     The address of the vDSO image.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the provided task is invalid.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (Task == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntKernVirtMemFetchQword(Task->MmGva + LIX_FIELD(MmStruct, VdsoAddress), Address);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed with status: 0x%08x.\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixVdsoProtect(
    void
    )
///
/// @brief Activates protection for the vDSO image and VSYSCALL.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (NULL != gVdsoHook)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    status = IntLixVdsoFixedProtect();
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntLixVdsoFixedProtect failed: 0x%08x\n", status);
    }

    status = IntLixVdsoResolveDynamicOffset();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVdsoResolveDynamicOffset failed with status: 0x%08x.\n", status);
        return status;
    }

    status = IntLixVdsoDynamicProtect();
    if (INT_STATUS_NOT_FOUND == status)
    {
        WARNING("[WARNING] Dynamic VDSO cannot be protected for this guest\n");
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixVdsoDynamicProtect failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


void
IntLixVdsoUnprotect(
    void
    )
///
/// @brief Remove protection for the vDSO image and VSYSCALL.
///
{
    if (NULL != gVdsoHook)
    {
        IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gVdsoHook, 0);
    }

    for (DWORD index = 0; index < ARRAYSIZE(gVdsoGpaHook); index++)
    {
        if (gVdsoGpaHook[index] != NULL)
        {
            INTSTATUS status = IntHookGpaDeleteHook((HOOK_GPA **)(&gVdsoGpaHook[index]), 0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaDeleteHook failed with status: 0x%08x\n", status);
            }
        }
    }
}
