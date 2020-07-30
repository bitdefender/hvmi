/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixstack.h"
#include "drivers.h"
#include "guests.h"
#include "lixmm.h"
#include "lixfiles.h"
#include "lixksym.h"


INTSTATUS
IntLixStackTraceGet(
    _In_opt_ QWORD Cr3,
    _In_ QWORD Stack,
    _In_ QWORD Rip,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Retrieves a Kernel stack trace.
///
/// This function will attempt to parse stackframes starting from the value of the Stack parameter. When a
/// valid return address if found, information about the code residing at that address(such as kernel driver,
/// next stack frame, return address, instruction pointer) are fetched.
///
/// Note: This function will fail for Kernels compiled with "-fomit-frame-pointer". Sigh!
///
/// @param[in]    Cr3               The CR3 that will be used to map virtual memory. If not set then
///                                 the system CR3 will be used.
/// @param[in]    Stack             The current stack pointer.
/// @param[in]    Rip               The current instruction pointer.
/// @param[in]    MaxNumberOfTraces The maximum number of traces this function should retrieve.
/// @param[in]    Flags             Flags controlling this function's behaviour. The only flag acknowledged
///                                 by this function is #STACK_FLG_FAST_GET.
/// @param[inout] StackTrace        Will contain upon successful return the backtrace.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER_2 If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    BOOLEAN remap;
    QWORD stackFrame;
    PBYTE pOriginalStackMap, pStack;
    QWORD currentRip;
    QWORD interationsTry;
    QWORD cr3;
    DWORD searchLimit;

    UNREFERENCED_PARAMETER(Flags);

    if (!IS_KERNEL_POINTER_WIN(TRUE, Stack) || Stack % 8 != 0)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == StackTrace || NULL == StackTrace->Traces)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    memzero(StackTrace->Traces, MaxNumberOfTraces * sizeof(STACK_ELEMENT));

    StackTrace->NumberOfTraces = 0;
    pStack = pOriginalStackMap = NULL;
    StackTrace->StartRip = Rip;
    stackFrame = Stack;
    currentRip = Rip;
    interationsTry = MaxNumberOfTraces * 2ull;
    remap = TRUE;
    status = INT_STATUS_NOT_FOUND;
    cr3 = Cr3 != 0 ? Cr3 : gGuest.Mm.SystemCr3;

    while (StackTrace->NumberOfTraces < MaxNumberOfTraces && interationsTry-- > 0)
    {
        QWORD nextStackFrame, currentStackFrame, retAddress;
        KERNEL_DRIVER *pRetMod = NULL;

        if (remap)
        {
            status = IntVirtMemMap(stackFrame & PAGE_MASK, PAGE_SIZE, cr3, 0, &pOriginalStackMap);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", stackFrame, status);
                goto leave;
            }

            pStack = pOriginalStackMap + (stackFrame & PAGE_OFFSET);
            remap = FALSE;
        }

        //
        // If we are at offset 0xff8 (the return address is at 8),
        // then we don't need to map this page but the next one
        //
        if (((stackFrame + 8) & PAGE_MASK) != (stackFrame & PAGE_MASK))
        {
            status = IntKernVirtMemFetchQword(stackFrame + 8, &retAddress);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting the return address for stack frame 0x%016llx: 0x%08x\n",
                      stackFrame, status);
                goto leave;
            }
        }
        else
        {
            retAddress = *(QWORD *)(pStack + 8);
        }

        // go to the next if this value is an address on the stack or not a kernel pointer
        if (!IS_KERNEL_POINTER_LIX(retAddress) || retAddress > 0xfffffffffffff000)
        {
            goto _next_stack_frame;
        }

        if (0 == (Flags & STACK_FLG_FAST_GET))
        {
            pRetMod = IntDriverFindByAddress(retAddress);
        }

        if (StackTrace->NumberOfTraces > 0)
        {
            if (StackTrace->Traces[StackTrace->NumberOfTraces - 1].ReturnAddress == retAddress)
            {
                // We remained in the same stack trace (will loop infinitely...)
                break;
            }
        }

        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnAddress = retAddress;
        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnModule = pRetMod;
        StackTrace->Traces[StackTrace->NumberOfTraces].RetAddrPointer = stackFrame + gGuest.WordSize;
        StackTrace->Traces[StackTrace->NumberOfTraces].CurrentRip = currentRip;
        StackTrace->NumberOfTraces++;

        currentRip = retAddress;

_next_stack_frame:
        // Get the previous stack frame @ rbp
        nextStackFrame = *(QWORD *)pStack;

        currentStackFrame = stackFrame;

        //
        // Stack limit is somewhere around 4KB. If this fails then we most probably have a function that doesn't
        // respect the RBP as frame-pointer convention so do a little back-search for a pointer on the stack (where
        // the original stack value was saved). Worst-case we get to the previous stack-frame and will get out after
        // this.
        //
        searchLimit = 256;
        while ((nextStackFrame - currentStackFrame >= 4 * PAGE_SIZE) ||
               !IS_KERNEL_POINTER_WIN(TRUE, nextStackFrame) ||
               (nextStackFrame % 8 != 0))
        {
            pStack -= 8;
            stackFrame -= 8;

            // If we got in the previous page, do the remapping
            if (((size_t)pStack & PAGE_MASK) != ((size_t)pOriginalStackMap & PAGE_MASK))
            {
                searchLimit--;
                if (0 == searchLimit)
                {
                    goto leave;
                }

                IntVirtMemUnmap(&pOriginalStackMap);

                status = IntVirtMemMap(stackFrame & PAGE_MASK, PAGE_SIZE, cr3, 0, &pOriginalStackMap);
                if (!INT_SUCCESS(status))
                {
                    if (StackTrace->NumberOfTraces > 0)
                    {
                        status = INT_STATUS_SUCCESS;
                    }
                    else
                    {
                        TRACE("[WARNING] Got to the beginning of stack and no frame was found. Status = 0x%08x\n",
                              status);
                    }

                    goto leave;
                }

                pStack = pOriginalStackMap + (stackFrame & PAGE_OFFSET);
            }

            nextStackFrame = *(QWORD *)pStack;
        }

        if (nextStackFrame == currentStackFrame || nextStackFrame % 8 != 0)
        {
            // if it's the same stack frame or an unaligned value we have nothing else to do
            goto leave;
        }

        if ((nextStackFrame & PAGE_MASK) != (stackFrame & PAGE_MASK))
        {
            remap = TRUE;
            IntVirtMemUnmap(&pOriginalStackMap);
        }

        // save the next pointer, and search again from there
        stackFrame = nextStackFrame;
        pStack = pOriginalStackMap + (stackFrame & PAGE_OFFSET);
    }

    status = INT_STATUS_SUCCESS; // if we get here we are successful

leave:
    if (NULL != pOriginalStackMap)
    {
        IntVirtMemUnmap(&pOriginalStackMap);
    }

    return status;
}


INTSTATUS
IntLixStackTraceGetReg(
    _In_opt_ QWORD Cr3,
    _In_ PIG_ARCH_REGS Registers,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Retrieves a Kernel stack backtrace based on the register values.
///
/// This function will extract a valid stack frame pointer and will supply it to
/// #IntLixStackTraceGet alongside the instruction pointer.
///
/// @param[in]    Cr3               The CR3 that will be used to map virtual memory. If not set then
///                                 the system CR3 will be used.
/// @param[in]    Registers         The registers values.
/// @param[in]    MaxNumberOfTraces The maximum number of traces this function should retrieve.
/// @param[in]    Flags             Flags controlling the behavior of this function.
/// @param[in, out] StackTrace      Will contain upon successful return the backtrace.
///
/// @return INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER_2 If an invalid parameter is supplied.
///
{
    QWORD stackFrame;

    stackFrame = Registers->Rbp;

    if (0 == Cr3)
    {
        Cr3 = gGuest.Mm.SystemCr3;
    }

    //
    // If RBP doesn't point to a valid stack, then we can only get one return address.
    // Let's hope it's enough!
    //
    if ((stackFrame > Registers->Rsp &&
         stackFrame - Registers->Rsp > 32 * PAGE_SIZE) ||
        (stackFrame < Registers->Rsp &&
         Registers->Rsp - stackFrame > 32 * PAGE_SIZE))
    {
        INTSTATUS status;

        memzero(StackTrace->Traces, MaxNumberOfTraces * sizeof(STACK_ELEMENT));

        stackFrame = Registers->Rsp;

        StackTrace->NumberOfTraces = 1;

        status = IntKernVirtMemFetchQword(stackFrame, &StackTrace->Traces[0].ReturnAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] RSP 0x%016llx is not present: %08x\n", stackFrame, status);
            return status;
        }

        StackTrace->Traces[0].ReturnModule = IntDriverFindByAddress(StackTrace->Traces[0].ReturnAddress);

        return INT_STATUS_SUCCESS;
    }

    return IntLixStackTraceGet(Cr3, stackFrame, Registers->Rip, MaxNumberOfTraces, Flags, StackTrace);
}


void
IntLixDumpStacktrace(
    _In_ DWORD MaxTraces
    )
///
/// @brief Logs a Kernel stack backtrace.
///
/// Unlike #IntLixStackTraceGet, this function will parse the stack and for each value that does look like a valid
/// kernel pointer will log it's symbol name (if available) as well as the module where it resides.
///
/// This function's behavior is somehow similar to the dump_stack() function from Linux Kernel.
///
/// @param[in] MaxTraces The maximum number of traces.
///
{
    INTSTATUS status;
    CHAR funcName[MAX_FUNC_NAME];
    DWORD trace = 0;
    QWORD rsp = gVcpu->Regs.Rsp;

    do
    {
        DWORD size = PAGE_REMAINING(rsp);
        QWORD *pStack;

        status = IntVirtMemMap(rsp, size, gGuest.Mm.SystemCr3, 0, &pStack);
        if (!INT_SUCCESS(status))
        {
            return;
        }

        for (DWORD i = 0; i < size / 8; i++)
        {
             KERNEL_DRIVER *pMod;

            if (!IS_KERNEL_POINTER_LIX(pStack[i]))
            {
                continue;
            }

            pMod = IntDriverFindByAddress(pStack[i]);
            if (NULL == pMod)
            {
                continue;
            }

            // if it is a kernel function, we can dump its name
            if (pMod == gGuest.KernelDriver)
            {
                if (!IN_RANGE(pStack[i], gLixGuest->Layout.CodeStart, gLixGuest->Layout.CodeEnd))
                {
                    continue;
                }

                status = IntKsymFindByAddress(pStack[i], sizeof(funcName), funcName, NULL, NULL);
                if (INT_SUCCESS(status))
                {
                    LOG("[STACK-TRACE] <0x%llx> %s\n", pStack[i], funcName);
                }
                else
                {
                    if ((pMod->Lix.Initialized ||
                         !IN_RANGE_LEN(pStack[i], pMod->Lix.InitLayout.Base, pMod->Lix.InitLayout.TextSize)) &&
                        !IN_RANGE_LEN(pStack[i], pMod->Lix.CoreLayout.Base, pMod->Lix.CoreLayout.TextSize))
                    {
                        continue;
                    }

                    LOG("[STACK-TRACE] <0x%llx> (symbol not found)\n", pStack[i]);
                }
            }
            else
            {
                LOG("[STACK-TRACE] <0x%llx> (symbol not found) in mod %s\n", pStack[i], (char *)pMod->Name);
            }

            if (++trace >= MaxTraces)
            {
                break;
            }
        }

        IntVirtMemUnmap(&pStack);

        rsp += size;
    } while (trace < MaxTraces);
}


void
IntLixStackDumpUmStackTrace(
    _In_ LIX_TASK_OBJECT *Task
    )
///
/// @brief Logs the libraries found in the user mode stacktrace.
///
/// This function will read the trap frame available in the kernel mode stack of the process and will
/// attempt to log the filenames of the VMAs that have pointers on the stack. Will also log
/// the trap frame as well as the code residing at the trap frame return address.
///
/// @param[in] Task The Linux process.
///
{
    INTSTATUS status;
    LIX_TRAP_FRAME trapFrame;
    LIX_VMA crtVma;
    LIX_VMA stackVma;
    CHAR *pFileName = NULL;

    status = IntLixTaskGetTrapFrame(Task, &trapFrame);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskGetUmTrapFrame failed: %08x\n", status);
        return;
    }

    status = IntLixMmFetchVma(Task, trapFrame.Rip, &crtVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmFetchVad failed for RIP %llx: %08x\n", trapFrame.Rip, status);
        return;
    }

    status = IntLixGetFileName(crtVma.File, &pFileName, NULL, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGetFileName failed with status: %x\n", status);
    }

    status = IntLixMmFetchVma(Task, trapFrame.Rsp, &stackVma);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixMmFetchVad failed for RIP %llx: %08x\n", trapFrame.Rsp, status);
        return;
    }

    TRACE("[UM STACK-TRACE] Task : '%s' (%d/%d) -> '%s' RIP: 0x%llx",
          Task->ProcName, Task->Pid, Task->Tgid, pFileName != NULL ? pFileName : "<no file>", trapFrame.Rip);
    TRACE("[UM STACK-TRACE] Stack [0x%llx - 0x%llx] - Stack pointer: 0x%llx\n", stackVma.Start, stackVma.End,
          trapFrame.Rsp);

    if (pFileName != NULL)
    {
        HpFreeAndNullWithTag(&pFileName, IC_TAG_NAME);
    }

    IntDisasmGva(trapFrame.Rip - 0x20, 0x40);

    IntDumpLixUmTrapFrame(&trapFrame);

    for (QWORD crtRsp = trapFrame.Rsp; crtRsp < stackVma.End; crtRsp += 8)
    {
        LIX_VMA tmpVma;
        CHAR *pTmpFile = NULL;
        QWORD value = 0;

        status = IntVirtMemFetchQword(crtRsp, Task->Cr3, &value);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        status = IntLixMmFetchVma(Task, value, &tmpVma);
        if (!INT_SUCCESS(status))
        {
            continue;
        }

        if (tmpVma.Flags & VM_EXEC)
        {
            IntLixGetFileName(tmpVma.File, &pTmpFile, NULL, NULL);

            LOG("[UM STACK-TRACE] Return = 0x%016llx : Stack = 0x%016llx, File '%s'",
                value, crtRsp, pTmpFile == NULL ? "<invalid file>" : pTmpFile);
        }

        if (pTmpFile != NULL)
        {
            HpFreeAndNullWithTag(&pTmpFile, IC_TAG_NAME);
        }
    }
}


