/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "thread_safeness.h"
#include "guests.h"
#include "introcpu.h"
#include "lixprocess.h"
#include "memtables.h"
#include "ptfilter.h"
#include "utils.h"
#include "vecore.h"
#include "winprocesshp.h"
#include "winthread.h"
#include "swapgs.h"


#define KSTACK_PAGE_COUNT_X86       8   ///< Stack page count to check on 32-bit systems
#define KSTACK_PAGE_COUNT_X64       16  ///< Stack page count to check on 64-bit systems

static BOOLEAN gSafeToUnload = FALSE;


static __forceinline DWORD
IntThrGetStackSize(
    _In_opt_ QWORD Rsp
    )
{
    if (gGuest.OSType == introGuestWindows)
    {
        return (gGuest.Guest64 ? KSTACK_PAGE_COUNT_X64 : KSTACK_PAGE_COUNT_X86) * PAGE_SIZE;
    }

    QWORD stackBase = Rsp & (~((QWORD)LIX_FIELD(Info, ThreadSize) - 1));

    return MIN((DWORD)(LIX_FIELD(Info, ThreadSize)), (DWORD)(LIX_FIELD(Info, ThreadSize) - (Rsp - stackBase)));
}


static BOOLEAN
IntThrSafeIsStackPtrInIntro(
    _In_ QWORD StackFrameStart,
    _In_opt_ QWORD StackFrameEnd,
    _In_ QWORD Options,
    _In_ QWORD ProcessGva
    )
///
/// @brief  Checks if a pointer from the stack points to a section of code injected or modified
/// by Introcore inside the guest.
///
/// @param[in]  StackFrameStart     The start of the stack frame to be checked.
/// @param[in]  StackFrameEnd       The end of the stack frame to be checked.
/// @param[in]  Options             Options that control the checks that will be made. Can be
///                                 a combination of @ref group_thread_safeness_options values.
/// @param[in]  ProcessGva          The guest virtual address at which the task is found. Ignored for Windows guests.
///
/// @returns    True if a pointer on the stack is inside an Introcore code or data region, False if it is not
///
{
    INTSTATUS status;
    QWORD stackPtr = StackFrameStart;
    BYTE *pStack = NULL;

    if (StackFrameStart % gGuest.WordSize != 0)
    {
        return FALSE;
    }

    if ((gGuest.OSType == introGuestWindows && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, StackFrameStart)) ||
        (gGuest.OSType == introGuestLinux && !IS_KERNEL_POINTER_LIX(StackFrameStart)))
    {
        return FALSE;
    }

    if (StackFrameEnd == 0)
    {
        StackFrameEnd = StackFrameStart + IntThrGetStackSize(StackFrameStart);
    }

    if (StackFrameStart > StackFrameEnd)
    {
        WARNING("[WARNING] Found a start stack pointer value (0x%llx) greater than the end value (0x%llx).",
                StackFrameStart, StackFrameEnd);
        return FALSE;
    }

    if (gGuest.OSType == introGuestLinux)
    {
        for (DWORD index = 0; index < gGuest.CpuCount; index++)
        {
            if (ProcessGva == gVcpu->LixProcessGva)
            {
                TRACE("[SAFENESS] Ignore running task 0x%llx ... \n", gVcpu->LixProcessGva);
                return FALSE;
            }
        }
    }

    while (StackFrameStart < StackFrameEnd)
    {
        DWORD toCheck = (DWORD)(MIN(PAGE_REMAINING(stackPtr), StackFrameEnd - StackFrameStart));

        // For the first page, stackPtr might not be page aligned, so align it before mapping it
        status = IntVirtMemMap(stackPtr, toCheck, gGuest.Mm.SystemCr3, 0, &pStack);
        if (!INT_SUCCESS(status))
        {
            if (gGuest.OSType == introGuestLinux)
            {
                WARNING("[WARNING] Failed to map the stack page %llx : %08x\n",
                        stackPtr & PAGE_MASK, status);
            }

            break;
        }

        for (DWORD i = 0; i < toCheck; i += gGuest.WordSize)
        {
            QWORD stackValue;
            DETOUR_TAG detTag;
            QWORD tableGva, gadget;

            if (gGuest.Guest64)
            {
                stackValue = *(QWORD *)(pStack + i);
            }
            else
            {
                stackValue = *(DWORD *)(pStack + i);
            }

            if (!!(Options & THS_CHECK_DETOURS) && IntDetIsPtrInHandler(stackValue, ptrStackValue, &detTag))
            {
                WARNING("[SAFENESS] Stack value @ %016llx (= %016llx) points inside detour %d\n",
                        stackPtr + i, stackValue, detTag);
                IntVirtMemUnmap(&pStack);
                return TRUE;
            }

            if (!!(Options & THS_CHECK_MEMTABLES) && IntMtblIsPtrInReloc(stackValue, ptrStackValue, &tableGva))
            {
                WARNING("[SAFENESS] Stack value @ %016llx (= %016llx) points inside mem table for %016llx\n",
                        stackPtr + i, stackValue, tableGva);
                IntVirtMemUnmap(&pStack);
                return TRUE;
            }

            if (!!(Options & THS_CHECK_TRAMPOLINE) && IntAgentIsPtrInTrampoline(stackValue, ptrStackValue))
            {
                WARNING("[SAFENESS] Stack value @ %016llx (= %016llx) points inside agent trampoline\n",
                        stackPtr + i, stackValue);
                IntVirtMemUnmap(&pStack);
                return TRUE;
            }

            if (!!(Options & THS_CHECK_PTFILTER) && IntPtiIsPtrInAgent(stackValue, ptrStackValue))
            {
                WARNING("[SAFENESS] Stack value @ %016llx (= %016llx) points inside PT Filter\n",
                        stackPtr + i, stackValue);
                IntVirtMemUnmap(&pStack);
                return TRUE;
            }

            if (!!(Options & THS_CHECK_VEFILTER) && IntVeIsPtrInAgent(stackValue, ptrStackValue))
            {
                WARNING("[SAFENESS] Stack value @ %016llx (= %016llx) points inside the #VE Agent\n",
                        stackPtr + i, stackValue);
                IntVirtMemUnmap(&pStack);
                return TRUE;
            }

            if (!!(Options & THS_CHECK_SWAPGS) && IntSwapgsIsPtrInHandler(stackValue, ptrStackValue, &gadget))
            {
                WARNING("[SAFENESS] Stack value @ %016llx (= %016llx) points inside a SWAPGS gadget at 0x%016llx\n",
                        stackPtr + i, stackValue, gadget);
                IntVirtMemUnmap(&pStack);
                return TRUE;
            }
        }

        IntVirtMemUnmap(&pStack);
        stackPtr += toCheck;    // skip all that we checked
        StackFrameStart += toCheck;
    }

    return FALSE;
}


static BOOLEAN
IntThrSafeIsLiveRIPInIntro(
    _In_ const IG_ARCH_REGS *Registers,
    _In_ QWORD Options
    )
///
/// @brief  Checks if the RIP on one of the guests VCPU points inside an Introcore owned code section
///
/// @param[in]  Registers   Register state to be checked
/// @param[in]  Options     Options that control the checks that will be made. Can be
///                         a combination of @ref group_thread_safeness_options values
///
/// @returns    True if the RIP is inside an Introcore code region, false if it is not
///
{
    DETOUR_TAG detTag;
    QWORD tableGva, gadget;

    if (!!(Options & THS_CHECK_DETOURS) && IntDetIsPtrInHandler(Registers->Rip, ptrLiveRip, &detTag))
    {
        WARNING("[SAFENESS] Live RIP %016llx points inside detour %d\n", Registers->Rip, detTag);
        return TRUE;
    }

    if (!!(Options & THS_CHECK_MEMTABLES) && IntMtblIsPtrInReloc(Registers->Rip, ptrLiveRip, &tableGva))
    {
        WARNING("[SAFENESS] Live RIP %016llx points inside mem table for %016llx\n", Registers->Rip, tableGva);
        return TRUE;
    }

    if (!!(Options & THS_CHECK_TRAMPOLINE) && IntAgentIsPtrInTrampoline(Registers->Rip, ptrLiveRip))
    {
        WARNING("[SAFENESS] Live RIP %016llx points inside agent trampoline\n", Registers->Rip);
        return TRUE;
    }

    if (!!(Options & THS_CHECK_PTFILTER) && IntPtiIsPtrInAgent(Registers->Rip, ptrLiveRip))
    {
        WARNING("[SAFENESS] Live RIP %016llx points inside PT Filter\n", Registers->Rip);

        IntDumpGva(Registers->Rip, 16, Registers->Cr3);
        return TRUE;
    }

    if (!!(Options & THS_CHECK_VEFILTER) && IntVeIsPtrInAgent(Registers->Rip, ptrLiveRip))
    {
        WARNING("[SAFENESS] Live RIP %016llx points inside the #VE Agent\n", Registers->Rip);
        return TRUE;
    }

    if (!!(Options & THS_CHECK_SWAPGS) && IntSwapgsIsPtrInHandler(Registers->Rip, ptrLiveRip, &gadget))
    {
        WARNING("[SAFENESS] Live RIP 0x%016llx points inside SWAPGS gadget at 0x%016llx\n", Registers->Rip, gadget);
        return TRUE;
    }

    return FALSE;
}


static INTSTATUS
IntThrSafeMoveReturn(
    _In_ QWORD StackFrameStart,
    _In_opt_ QWORD StackFrameEnd
    )
///
/// @brief  Will check if it is safe for Introcore to move the return value on the stack
///
/// @param[in]  StackFrameStart     The start of the stack frame to be checked
/// @param[in]  StackFrameEnd       The end of the stack frame to be checked
///
/// @returns    True if operation can be done safely, False if it can not be done safely
///
{
    BYTE *pStack = NULL;
    QWORD stackPtr = StackFrameStart;

    if (StackFrameStart % gGuest.WordSize != 0)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if ((gGuest.OSType == introGuestWindows && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, StackFrameStart)) ||
        (gGuest.OSType == introGuestLinux && !IS_KERNEL_POINTER_LIX(StackFrameStart)))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (StackFrameEnd == 0)
    {
        StackFrameEnd = StackFrameStart + IntThrGetStackSize(StackFrameStart);
    }

    if (StackFrameStart > StackFrameEnd)
    {
        WARNING("[WARNING] Found a start stack pointer value (0x%llx) greater than the end value (0x%llx).",
                StackFrameStart, StackFrameEnd);
        return FALSE;
    }

    while (StackFrameStart < StackFrameEnd)
    {
        DWORD toCheck = (DWORD)(MIN(PAGE_REMAINING(stackPtr), StackFrameEnd - StackFrameStart));
        INTSTATUS status;

        status = IntVirtMemMap(stackPtr, toCheck, gGuest.Mm.SystemCr3, 0, &pStack);
        if (!INT_SUCCESS(status))
        {
            break;
        }

        for (DWORD i = 0; i < toCheck; i += gGuest.WordSize)
        {
            QWORD stackValue, newValue;

            if (gGuest.Guest64)
            {
                stackValue = *(QWORD *)(pStack + i);
            }
            else
            {
                stackValue = *(DWORD *)(pStack + i);
            }

            newValue = IntDetRelocatePtrIfNeeded(stackValue);
            if (newValue == stackValue)
            {
                newValue = IntSwapgsRelocatePtrIfNeeded(stackValue);
            }

            if (newValue != stackValue)
            {
                // IMPORTANT: If the return is at the beginning of a function, we can leave it there, and it will just
                // go through VMCALL.
                WARNING("[WARNING] Moving stack value (@ 0x%016llx) from 0x%016llx to 0x%016llx\n",
                        (stackPtr & PAGE_MASK) + i, stackValue, newValue);

                if (((QWORD)(pStack + i - gGuest.WordSize) & PAGE_MASK) == ((QWORD)pStack & PAGE_MASK))
                {
                    LOG("[SAFENESS] @ 0x%016llx we have: 0x%016llx\n", (stackPtr & PAGE_MASK) + i - gGuest.WordSize,
                        gGuest.Guest64 ? * (QWORD *)(pStack + i - 8) : * (DWORD *)(pStack + i - 4));
                }

                if (((QWORD)(pStack + i + gGuest.WordSize) & PAGE_MASK) == ((QWORD)pStack & PAGE_MASK))
                {
                    LOG("[SAFENESS] @ 0x%016llx we have: 0x%016llx\n", (stackPtr & PAGE_MASK) + i + gGuest.WordSize,
                        gGuest.Guest64 ? * (QWORD *)(pStack + i + 8) : * (DWORD *)(pStack + i + 4));
                }

                if (gGuest.Guest64)
                {
                    *(QWORD *)(pStack + i) = newValue;
                }
                else
                {
                    *(DWORD *)(pStack + i) = newValue & 0xffffffff;
                }
            }
        }

        IntVirtMemUnmap(&pStack);
        stackPtr += toCheck;    // skip all that we checked
        StackFrameStart += toCheck;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeMoveRip(
    _In_ IG_ARCH_REGS *Registers,
    _In_ DWORD CpuNumber
    )
///
/// @brief  Will check if it is safe for Introcore to modify the RIP value
///
/// @param[in]  Registers   Register state to be checked
/// @param[in]  CpuNumber   The VCPU for which the check is done. Can be #IG_CURRENT_VCPU
///
/// @returns    True if operation can be done safely, False if it can not be done safely
///
{
    INTSTATUS status;
    QWORD newRip;

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    newRip = IntDetRelocatePtrIfNeeded(Registers->Rip);
    if (newRip == Registers->Rip)
    {
        newRip = IntSwapgsRelocatePtrIfNeeded(Registers->Rip);
    }
    if (newRip != Registers->Rip)
    {
        WARNING("[WARNING] Moving live RIP from 0x%016llx 0x%016llx\n", Registers->Rip, newRip);

        Registers->Rip = FIX_GUEST_POINTER(gGuest.Guest64, newRip);

        status = IntSetGprs(CpuNumber, Registers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed moving the RIP of the running CPU %d to the new address: 0x%08x\n",
                  CpuNumber, status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeWinInspectWaitingThread(
    _In_ QWORD Ethread,
    _In_ QWORD Options
    )
///
/// @brief  Inspects a waiting thread from a Windows guest
///
/// The check is skipped for threads that are in the KTHREAD_STATE.Running and KTHREAD_STATE.Terminated
/// states, as those are either checked when checking the live state of a CPU (for running threads), or
/// don't need to be checked (as they are terminated). The check is also skipped if the wait reason of
/// a thread is not KWAIT_REASON.WrDispatchInt or KWAIT_REASON.WrQuantumEnd.
///
/// @param[in]  Ethread     The guest virtual address at which the thread to be inspected is found
/// @param[in]  Options     Options that control the checks that will be made. Can be
///                         a combination of @ref group_thread_safeness_options values
///
/// @retval     #INT_STATUS_SUCCESS in case of success; this means that none of the
///             active threads are using Introcore code or data
/// @retval     #INT_STATUS_CANNOT_UNLOAD if it is not safe to unload given the current guest state
///
{
    BYTE *pThread;
    UCHAR state, waitReason;
    QWORD currentStack;
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, Ethread))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if ((Ethread & PAGE_OFFSET) + WIN_KM_FIELD(Thread, WaitReason) > PAGE_SIZE)
    {
        WARNING("[WARNING] Ethread 0x%016llx is too high in page!\n", Ethread);
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = IntVirtMemMap(Ethread, PAGE_REMAINING(Ethread), gGuest.Mm.SystemCr3, 0, &pThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for VA 0x%016llx: 0x%08x\n", Ethread, status);
        return status;
    }

    state = *(pThread + WIN_KM_FIELD(Thread, State));
    waitReason = *(pThread + WIN_KM_FIELD(Thread, WaitReason));
    if (gGuest.Guest64)
    {
        currentStack = *(QWORD *)(pThread + WIN_KM_FIELD(Thread, KernelStack));
    }
    else
    {
        currentStack = *(DWORD *)(pThread + WIN_KM_FIELD(Thread, KernelStack));
    }

    IntVirtMemUnmap(&pThread);

    if (state == Running)
    {
        LOG("[SAFENESS] Thread 0x%016llx is running, will examine it later\n", Ethread);
        return INT_STATUS_NOT_NEEDED_HINT;
    }
    else if (state == Terminated)
    {
        LOG("[SAFENESS] Terminated thread 0x%016llx\n", Ethread);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (WrDispatchInt != waitReason && WrQuantumEnd != waitReason)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    LOG("[SAFENESS] We have a WAITING thread to examine at 0x%016llx! Reason: %d, State: %d\n",
        Ethread, waitReason, state);

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, currentStack) || // the stack is in kernel
        0 != (currentStack % gGuest.WordSize))                  // the stack is aligned
    {
        WARNING("[WARNING] Thread %016llx has stack at %016llx. Thread was TERMINATED!\n",
                Ethread, currentStack);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!!(Options & THS_CHECK_ONLY))
    {
        if (IntThrSafeIsStackPtrInIntro(currentStack, 0, Options, 0))
        {
            gSafeToUnload = FALSE;
            status = INT_STATUS_BREAK_ITERATION;
        }
    }
    else
    {
        status = IntThrSafeMoveReturn(currentStack, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntThrSafeMoveReturn failed for stack %016llx: %08x\n", currentStack, status);
        }
    }

    return status;
}


static INTSTATUS
IntThrSafeLixInspectWaitingThread(
    _In_ QWORD TaskStruct,
    _In_ QWORD Options
    )
///
/// @brief  Inspects a waiting thread from a Linux guest.
///
/// @param[in]  TaskStruct  The guest virtual address at which the task to be inspected is found.
/// @param[in]  Options     Options that control the checks that will be made. Can be
///                         a combination of @ref group_thread_safeness_options values.
///
/// @retval     #INT_STATUS_SUCCESS in case of success; this means that none of the.
///             active threads are using Introcore code or data.
/// @retval     #INT_STATUS_CANNOT_UNLOAD if it is not safe to unload given the current guest state.
///
{
    INTSTATUS status;
    DWORD taskFlags;
    QWORD currentStack;

    status = IntKernVirtMemFetchDword(TaskStruct + LIX_FIELD(TaskStruct, Flags), &taskFlags);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the task's flags from %llx: 0x%08x.\n",
              TaskStruct + LIX_FIELD(TaskStruct, Flags), status);
        return status;
    }

    if (taskFlags & (PF_EXITPIDONE | PF_EXITING))
    {
        LOG("[SAFENESS] Ignoring task %llx which is dying: %08x\n", TaskStruct, taskFlags);
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // task->thread_struct.sp
    currentStack = TaskStruct + gLixGuest->OsSpecificFields.ThreadStructOffset + LIX_FIELD(TaskStruct, ThreadStructSp);

    status = IntKernVirtMemFetchQword(currentStack, &currentStack);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx with status: 0x%08x\n", currentStack, status);

        status = IntKernVirtMemFetchQword(TaskStruct + LIX_FIELD(TaskStruct, Stack), &currentStack);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the task's stack from %llx: 0x%08x\n",
                  TaskStruct + LIX_FIELD(TaskStruct, Stack), status);
            return status;
        }
    }

    if (!IS_KERNEL_POINTER_LIX(currentStack))
    {
        WARNING("[WARNING] Task %llx has current stack %llx, with flags %08x\n",
                TaskStruct, currentStack, taskFlags);

        return INT_STATUS_NOT_NEEDED_HINT;
    }

    currentStack = ALIGN_UP(currentStack, 8);

    if (!!(Options & THS_CHECK_ONLY))
    {
        if (IntThrSafeIsStackPtrInIntro(currentStack, 0, Options, TaskStruct))
        {
            gSafeToUnload = FALSE;
            status = INT_STATUS_BREAK_ITERATION;
        }
    }
    else
    {
        status = IntThrSafeMoveReturn(currentStack, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntThrSafeMoveReturn failed for stack 0x%016llx: 0x%08x\n", currentStack, status);
        }
    }

    return status;
}


static INTSTATUS
IntThrSafeLixGetCurrentStack(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *Stack
    )
///
/// @brief  Get the current stack value for a VCPU for a Linux guest
///
/// This is done by reading the stack information saved in the kernel's task structure
///
/// @param[in]  CpuNumber   The VCPU for which the query is done
/// @param[out] Stack       The stack, as saved by the kernel
///
/// @returns    #INT_STATUS_SUCCESS in case of success, or other INTSTATUS values in case of error
///
{
    DWORD stackOffset;
    INTSTATUS status;

    LIX_TASK_OBJECT *pTask = IntLixTaskGetCurrent(CpuNumber);
    if (NULL == pTask)
    {
        return INT_STATUS_NOT_FOUND;
    }

    stackOffset = LIX_FIELD(TaskStruct, Stack);

    status = IntKernVirtMemFetchQword(pTask->Gva + stackOffset, Stack);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeWinGetCurrentStack(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *CurrentStack,
    _Out_ QWORD *StackBase,
    _Out_ QWORD *StackLimit
    )
///
/// @brief  Get the current stack values for a VCPU for a Windows guest
///
/// This is done by reading the stack information saved in the kernel's _KTHREAD structure
///
/// @param[in]  CpuNumber       The VCPU for which the query is done
/// @param[out] CurrentStack    The current stack pointer, as saved by the kernel
/// @param[out] StackBase       The base of the stack, as saved by the kernel
/// @param[out] StackLimit      The limit of the stack, as saved by the kernel
///
/// @returns    #INT_STATUS_SUCCESS in case of success, or other INTSTATUS values in case of error
///
{
    QWORD currentThread;
    INTSTATUS status;

    status = IntWinThrGetCurrentThread(CpuNumber, &currentThread);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemRead(currentThread + WIN_KM_FIELD(Thread, KernelStack),
                                gGuest.WordSize,
                                CurrentStack,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        LOG("[ERROR] IntKernVirtMemRead failed for (Ethread: %016llx, KernelStack: 0x%x): 0x%08x\n",
            currentThread, WIN_KM_FIELD(Thread, KernelStack), status);
        return status;
    }

    status = IntKernVirtMemRead(currentThread + WIN_KM_FIELD(Thread, StackBase),
                                gGuest.WordSize,
                                StackBase,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        LOG("[ERROR] IntKernVirtMemRead failed for (Ethread: %016llx, StackBase: 0x%x): 0x%08x\n",
            currentThread, WIN_KM_FIELD(Thread, StackBase), status);
        return status;
    }

    status = IntKernVirtMemRead(currentThread + WIN_KM_FIELD(Thread, StackLimit),
                                gGuest.WordSize,
                                StackLimit,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        LOG("[ERROR] IntKernVirtMemRead failed for (Ethread: %016llx, StackLimit: 0x%x): 0x%08x\n",
            currentThread, WIN_KM_FIELD(Thread, StackLimit), status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeLixInspectRunningThreadOnCpu(
    _In_ DWORD Cpu,
    _In_ const IG_ARCH_REGS *Regs,
    _In_ QWORD Options
    )
///
/// @brief  Inspects the running threads of a VCPU
///
/// @param[in]  Cpu     The VCPU for which the checks are done
/// @param[in]  Regs    Register state
/// @param[in]  Options Options that control the checks that will be made. Can be
///                     a combination of @ref group_thread_safeness_options values
///
/// @retval   #INT_STATUS_SUCCESS in case of success; this means that none of the
///             active threads are using Introcore code or data
/// @retval   #INT_STATUS_CANNOT_UNLOAD if it is not safe to unload given the current guest state
///
{
    INTSTATUS status;
    QWORD toCheck[2];
    QWORD currentStack;
    const QWORD maxSize = IntThrGetStackSize(0);

    status = IntThrSafeLixGetCurrentStack(Cpu, &currentStack);
    if (!INT_SUCCESS(status))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    LOG("[SAFENESS] CPU %u has current stack = 0x%016llx and RSP = 0x%016llx\n", Cpu, currentStack, Regs->Rsp);

    if (Regs->Rsp < currentStack)
    {
        toCheck[0] = Regs->Rsp;
        toCheck[1] = currentStack;
    }
    else
    {
        toCheck[0] = currentStack;
        toCheck[1] = Regs->Rsp;
    }

    // Skip close values
    if (toCheck[1] - toCheck[0] < maxSize)
    {
        // Keep the lowest one
        toCheck[1] = 0;
    }

    for (DWORD p = 0; p < ARRAYSIZE(toCheck); p++)
    {
        const QWORD ptr = toCheck[p];
        const DWORD size = IntThrGetStackSize(ptr);

        if (!IS_KERNEL_POINTER_LIX(ptr))
        {
            continue;
        }

        LOG("[SAFENESS] Will check stack %016llx with RIP %016llx on CPU %u\n", ptr, Regs->Rip, Cpu);

        if (!!(Options & THS_CHECK_ONLY))
        {
            if (IntThrSafeIsStackPtrInIntro(ptr, ptr + size, Options, 0))
            {
                return INT_STATUS_CANNOT_UNLOAD;
            }
        }
        else
        {
            status = IntThrSafeMoveReturn(ptr, ptr + size);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntThrSafeMoveReturn failed for stack %016llx for CPU %u: 0x%08x\n", ptr, Cpu, status);
                return status;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeWinInspectRunningThreadOnCpu(
    _In_ DWORD Cpu,
    _In_ const IG_ARCH_REGS *Regs,
    _In_ QWORD Options
    )
///
/// @brief  Inspects the running threads of a VCPU
///
/// @param[in]  Cpu     The VCPU for which the checks are done
/// @param[in]  Regs    Register state
/// @param[in]  Options Options that control the checks that will be made. Can be
///                     a combination of @ref group_thread_safeness_options values
///
/// @retval   #INT_STATUS_SUCCESS in case of success; this means that none of the
///             active threads are using Introcore code or data
/// @retval   #INT_STATUS_CANNOT_UNLOAD if it is not safe to unload given the current guest state
///
{
    INTSTATUS status;
    QWORD stackBase, stackLimit, stackSavedInEthread, low, high;
    BOOLEAN lowestPtrChecked = FALSE;
    QWORD toCheck[3];

    // Make them 0 because on 32 bits we'll end up with garbage in the high-part.
    stackSavedInEthread = stackLimit = stackBase = 0;

    status = IntThrSafeWinGetCurrentStack(Cpu, &stackSavedInEthread, &stackBase, &stackLimit);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntThrSafeWinGetCurrentStack failed on CPU %u: 0x%08x\n", Cpu, status);
        return status;
    }

    LOG("[SAFENESS] Active thread on CPU %u has stack @ 0x%016llx with base = 0x%016llx "
        "limit = 0x%016llx RSP = 0x%016llx and RBP = 0x%016llx\n",
        Cpu, stackSavedInEthread, stackBase, stackLimit, Regs->Rsp, Regs->Rbp);

    toCheck[0] = Regs->Rsp;
    toCheck[1] = stackSavedInEthread;
    toCheck[2] = gGuest.Guest64 ? 0 : Regs->Rbp;

    UtilSortQwords(toCheck, ARRAYSIZE(toCheck));

    // Is there even a chance for the stack base and limit to be reversed?
    if (stackBase > stackLimit)
    {
        low = stackLimit;
        high = stackBase;
    }
    else
    {
        low = stackBase;
        high = stackLimit;
    }

    for (DWORD p = 0; p < ARRAYSIZE(toCheck); p++)
    {
        DWORD size;
        const QWORD ptr = toCheck[p];
        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, ptr))
        {
            continue;
        }

        if (!lowestPtrChecked && IN_RANGE(ptr, low, high))
        {
            // ptr is the lowest, non-zero, stack location that is on the known ETHREAD stack, so check everything
            // between ptr and stack base
            size = (DWORD)((high & PAGE_MASK) - (ptr & PAGE_MASK));
            lowestPtrChecked = TRUE;
        }
        else if (IN_RANGE(ptr, low, high))
        {
            // ptr is on the known ETHREAD stack, but was already checked at a previous step, skip it
            continue;
        }
        else
        {
            // ptr is not on the known ETHREAD stack (most likely an interrupt changed the stack), so check it
            // using a "close enough" page count approximation
            LOG("[SAFENESS] Stack pointer 0x%016llx is not on the known Ethread stack [0x%016llx, 0x%016llx)!\n",
                ptr, low, high);
            size = IntThrGetStackSize(ptr);
        }

        if (!!(Options & THS_CHECK_ONLY))
        {
            if (IntThrSafeIsStackPtrInIntro(ptr, ptr + size, Options, 0))
            {
                return INT_STATUS_CANNOT_UNLOAD;
            }
        }
        else
        {
            status = IntThrSafeMoveReturn(ptr, ptr + size);
            if (!INT_SUCCESS(status) && ptr != Regs->Rbp)
            {
                ERROR("[ERROR] IntThrSafeMoveReturn failed for stack %016llx for CPU %u: 0x%08x\n", ptr, Cpu, status);
                return status;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeInspectRunningThreads(
    _In_ QWORD Options
    )
///
/// @brief  Inspects the currently running threads.
///
/// @param[in]  Options     Options that control the checks that will be made. Can be a combination of
///                         @ref group_thread_safeness_options values.
///
/// @retval     #INT_STATUS_SUCCESS in case of success; this means that none of the active threads are using introcore
///             code or data.
/// @retval     #INT_STATUS_CANNOT_UNLOAD if it is not safe to unload given the current guest state.
///
{
    INTSTATUS status;

    for (DWORD c = 0; c < gGuest.CpuCount; c++)
    {
        IG_ARCH_REGS regs;

        status = IntGetGprs(c, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed for CPU %u: 0x%08x\n", c, status);
            continue;
        }

        if (0 == regs.Cr3)
        {
            LOG("[CPU %u] Is inactive, will not check anything!\n", c);
            continue;
        }

        if ((gGuest.OSType == introGuestWindows && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, regs.Rip)) ||
            (gGuest.OSType == introGuestLinux && !IS_KERNEL_POINTER_LIX(regs.Rip)))
        {
            TRACE("[INFO] CPU %u, RIP 0x%016llx is in user-mode... We can safely ignore it\n", c, regs.Rip);
            continue;
        }

        TRACE("[INFO] Cpu %u, RIP 0x%016llx, will continue checking\n", c, regs.Rip);

        if (!!(Options & THS_CHECK_ONLY))
        {
            if (IntThrSafeIsLiveRIPInIntro(&regs, Options))
            {
                WARNING("[SAFENESS] IntThrSafeIsLiveRIPInIntro failed for CPU %u\n", c);
                return INT_STATUS_CANNOT_UNLOAD;
            }
        }
        else
        {
            status = IntThrSafeMoveRip(&regs, c);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed moving RIP %016llx on CPU %u: 0x%08x\n", regs.Rip, c, status);
            }
        }

        if (introGuestWindows == gGuest.OSType)
        {
            status = IntThrSafeWinInspectRunningThreadOnCpu(c, &regs, Options);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntThrSafeWinInspectRunningThreadOnCpu failed for CPU %u: 0x%08x\n", c, status);
                return status;
            }
        }
        else if (introGuestLinux == gGuest.OSType)
        {
            IntLixTaskGetCurrentTaskStruct(c, &gVcpu->LixProcessGva);

            status = IntThrSafeLixInspectRunningThreadOnCpu(c, &regs, Options);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntThrSafeLixInspectRunningThreadOnCpu failed for CPU %u: 0x%08x\n", c, status);
                return status;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntThrSafeWinInspectWaitingFromGuestList(
    _In_ QWORD Eprocess,
    _In_ QWORD Options
    )
{
    return IntWinThrIterateThreads(Eprocess, IntThrSafeWinInspectWaitingThread, Options);
}


INTSTATUS
IntThrSafeCheckThreads(
    _In_ QWORD Options
    )
///
/// @brief  Checks if any of the guest threads have their RIP or have any stack pointers pointing to
/// regions of code owned by Introcore.
///
/// This is done by iterating the in-guest thread lists. This function assumes that all the VCPUs are paused.
///
/// @param[in]  Options     Options that control the checks that will be made. Can be
///                         a combination of @ref group_thread_safeness_options values
///
/// @retval     #INT_STATUS_SUCCESS in case of success; this means that no guest state points to code or data owned by
///             Introcore
/// @retval     #INT_STATUS_NOT_SUPPORTED if the type of the guest OS is not known or supported
/// @retval     #INT_STATUS_CANNOT_UNLOAD if it is not safe to unload given the current guest state
///
{
    INTSTATUS status;

    // Assume, for now, that we can unload
    gSafeToUnload = TRUE;

    if (!gGuest.GuestInitialized)
    {
        // Introspection was still initializing, so it's safe to unload.
        return INT_STATUS_SUCCESS;
    }

    status = IntThrSafeInspectRunningThreads(Options);
    if (!!(Options & THS_CHECK_ONLY) && status == INT_STATUS_CANNOT_UNLOAD)
    {
        gSafeToUnload = FALSE;
        return status;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntThrSafeInspectRunningThreads failed: 0x%08x\n", status);
        return status;
    }

    // Will iterate all threads in the guest and will set #gSafeToUnload to TRUE if
    // a thread returns to our detours
    if (gGuest.OSType == introGuestWindows)
    {
        // We won't have any hooks in guest or other stuff until we didn't read the kernel, so it's safe to
        // unload.
        if (0 != gWinGuest->RemainingSections)
        {
            return INT_STATUS_SUCCESS;
        }

        status = IntWinProcIterateGuestProcesses(IntThrSafeWinInspectWaitingFromGuestList, Options);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        status = IntLixTaskIterateGuestTasks(IntThrSafeLixInspectWaitingThread, Options);
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (status == INT_STATUS_NOT_INITIALIZED)
    {
        gSafeToUnload = FALSE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed iterating processes and threads: 0x%08x\n", status);
        return status;
    }

    if (!!(Options & THS_CHECK_ONLY) && !gSafeToUnload)
    {
        return INT_STATUS_CANNOT_UNLOAD;
    }

    return status;
}
