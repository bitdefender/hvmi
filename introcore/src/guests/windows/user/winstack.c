/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winstack.h"
#include "decoder.h"
#include "drivers.h"
#include "guests.h"
#include "introcpu.h"
#include "winpe.h"
#include "winummodule.h"
#include "winthread.h"
#include "swapmem.h"


#define TRAPFRAME_MAX_ITERATIONS         0x100


static INTSTATUS
IntStackAnalyzePointer(
    _In_ QWORD Gva,
    _Out_opt_ QWORD *CallAddress
    )
///
/// @brief Get the address of the kernel function that was called in order to push Gva on the
/// stack as a return address.
///
/// @param[in]  Gva             The return address.
/// @param[out] CallAddress     The address of the called function.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    NDSTATUS ndstatus;
    BYTE defCode, defData;
    BYTE code[0x20] = { 0 };
    INSTRUX instruction;
    QWORD calledFuncAddress, i;
    BOOLEAN isCall;

    status = IntKernVirtMemRead(Gva - 7, sizeof(code), code, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // init
    isCall = TRUE;
    calledFuncAddress = 0;

    defData = gGuest.Guest64 ? ND_DATA_64 : ND_DATA_32;
    defCode = gGuest.Guest64 ? ND_CODE_64 : ND_CODE_32;

    // We check from big instructions to small ones. This assures that the instructions will be
    // decoded with prefixes. Also 5-byte instructions (0xe8 calls) are the most frequent ones.
    // WARNING: Don't add the instruction length to the Gva. The Gva already points to the
    // instruction after the CALL.
    for (i = 0; i <= 5; i++)
    {
        // we must be sure if the instruction is really a CALL before jumping to cleanup and exit at the end of this
        // for loop.
        BOOLEAN bIsInstruxCall = FALSE;

        ndstatus = NdDecodeEx(&instruction, code + i, sizeof(code) - i, defCode, defData);
        if (!ND_SUCCESS(ndstatus))
        {
            continue;
        }

        // get the call address if that's possible
        switch (instruction.Instruction)
        {
        case ND_INS_CALLNR:
        {
            bIsInstruxCall = TRUE;

            calledFuncAddress = Gva + instruction.Operands[0].Info.RelativeOffset.Rel;
            break;
        }

        case ND_INS_CALLNI:
        {
            bIsInstruxCall = TRUE;

            if (ND_OP_IMM == instruction.Operands[0].Type)
            {
                calledFuncAddress = instruction.Operands[0].Info.Immediate.Imm;
            }
            else if (ND_OP_MEM == instruction.Operands[0].Type)
            {
                QWORD fetchAddress;

                if (instruction.Operands[0].Info.Memory.IsRipRel)
                {
                    // Disp is already sign extended
                    fetchAddress = Gva + instruction.Operands[0].Info.Memory.Disp;
                }
                else if (instruction.Operands[0].Info.Memory.HasDisp &&
                         !instruction.Operands[0].Info.Memory.HasBase &&
                         !instruction.Operands[0].Info.Memory.HasIndex)
                {
                    fetchAddress = instruction.Operands[0].Info.Memory.Disp;
                }
                else
                {
                    // So far so good, but it's using registers.
                    break;
                }

                // Get the actual called address
                status = IntKernVirtMemFetchQword(fetchAddress, &calledFuncAddress);
                if (!INT_SUCCESS(status))
                {
                    WARNING("[WARNING] Failed to get function address from 0x%016llx (Call RIP 0x%016llx): 0x%08x\n",
                            fetchAddress, Gva, status);
                    calledFuncAddress = 0;
                }
            }
            else if (ND_OP_OFFS == instruction.Operands[0].Type)
            {
                calledFuncAddress = Gva + instruction.Operands[0].Info.RelativeOffset.Rel;
            }

            break;
        }

        case ND_INS_CALLFI:
        case ND_INS_CALLFD:
            bIsInstruxCall = TRUE;

            if (ND_OP_OFFS == instruction.Operands[0].Type)
            {
                calledFuncAddress = Gva + instruction.Operands[0].Info.RelativeOffset.Rel;
            }
            else if (ND_OP_MEM == instruction.Operands[0].Type)
            {
                QWORD fetchAddress;

                if (instruction.Operands[0].Info.Memory.IsRipRel)
                {
                    // Disp is already sign extended
                    fetchAddress = Gva + instruction.Operands[0].Info.Memory.Disp;
                }
                else if (instruction.Operands[0].Info.Memory.HasDisp &&
                         !instruction.Operands[0].Info.Memory.HasBase &&
                         !instruction.Operands[0].Info.Memory.HasIndex)
                {
                    fetchAddress = instruction.Operands[0].Info.Memory.Disp;
                }
                else
                {
                    // So far so good, but it's using registers.
                    break;
                }

                // Get the actual called address
                status = IntKernVirtMemFetchQword(fetchAddress, &calledFuncAddress);
                if (!INT_SUCCESS(status))
                {
                    WARNING("[WARNING] Failed to get function address from 0x%016llx (Call RIP 0x%016llx): 0x%08x\n",
                          fetchAddress, Gva, status);
                    calledFuncAddress = 0;
                }
            }
            else if (ND_OP_REG == instruction.Operands[0].Type)
            {
                calledFuncAddress = 0;
            }
            else
            {
                ///TRACE("[STACK] Op type not supported: %d\n", instruction.Operands[0].Type);
            }
            break;

        default:
            break;
        }

        // Make sure that instruction length is good (it doesn't override return address & it hasn't slack space)
        // Also, we need to make sure that this instruction is REALLY a CALL instruction before jumping to cleanup
        // and leave
        if (Gva == Gva - (7 - i) + instruction.Length && bIsInstruxCall)
        {
            goto cleanup_and_leave;
        }
    }

    // If we get here and don't find a good instruction then it's no good
    isCall = FALSE;

cleanup_and_leave:
    if (!isCall || (calledFuncAddress != 0 && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, calledFuncAddress)))
    {
        status = INT_STATUS_NOT_FOUND;
    }

    if (NULL != CallAddress)
    {
        *CallAddress = FIX_GUEST_POINTER(gGuest.Guest64, calledFuncAddress);
    }

    return status;
}


static INTSTATUS
IntWinStackTraceGet64(
    _In_ QWORD Rsp,
    _In_ QWORD Rip,
    _In_ DWORD MaxTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Get a kernel stack trace starting from the current stack pointer for 64 bit systems.
///
/// This is the same method WinDbg uses. It parses the internal windows structures _RUNTIME_FUNCTION and _UNWIND_INFO
/// to see how may stack space each function needs (just the prologue which contains push registers and sub rsp, value).
/// A further check it's still needed because we don't know how many parameters each function has on the stack.
///
/// @param[in]      Rsp         Stack frame pointer from where to start searching.
/// @param[in]      Rip         Instruction pointer from where to start searching.
/// @param[in]      MaxTraces   Maximum number of stack traces to get.
/// @param[in]      Flags       Can be either #STACK_FLG_ONLY_DRIVER_ADDRS or #STACK_FLG_FAST_GET.
/// @param[in, out] StackTrace  A caller initialized #STACK_TRACE structure that will hold the stack trace.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    QWORD currentRip, currentRsp, newRsp, currentModBase;
    PBYTE pStack, pStackBase, pModBaseMap;
    BOOLEAN ripInsideSameModule;
    KERNEL_DRIVER *pDriver;
    INTSTATUS status;

    if (NULL == StackTrace || NULL == StackTrace->Traces)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    STATS_ENTER(statsStackTrace64);

    StackTrace->NumberOfTraces = 0;
    StackTrace->StartRip = Rip;
    StackTrace->Bits64 = TRUE;
    pStack = pModBaseMap = pStackBase = NULL;
    currentRip = Rip;
    currentRsp = Rsp & ~7; // Make sure the stack is 8-bytes aligned.
    currentModBase = 0;
    pDriver = NULL;

    ripInsideSameModule = FALSE;

    do
    {
        RUNTIME_FUNCTION runtimeFunction;
        DWORD prologueSize, tries, beginRva;
        QWORD retAddress, retModuleBase, calledAddress, retAddrPtr;
        BOOLEAN interrupt, exception, hasFramePointer, found, fErrorCode;

        memzero(&runtimeFunction, sizeof(runtimeFunction));
        prologueSize = tries = beginRva = 0;
        found = hasFramePointer = interrupt = exception = fErrorCode = FALSE;
        retModuleBase = retAddress = calledAddress = retAddrPtr = 0;
        status = INT_STATUS_SUCCESS;

        // If we are inside the same module then don't remap the module base
        if (!ripInsideSameModule)
        {
            // Unmap the module if it was previously mapped
            if (NULL != pModBaseMap)
            {
                IntVirtMemUnmap(&pModBaseMap);
            }

            // Get the image base of the RIP if we don't already have one. If this fails we get out with an error.
            if (0 == currentModBase)
            {
                pDriver = IntDriverFindByAddress(currentRip);
                if (NULL == pDriver)
                {
                    if ((Flags & STACK_FLG_ONLY_DRIVER_ADDRS) &&
                        StackTrace->NumberOfTraces > 0)
                    {
                        ERROR("[ERROR] Failed to find the module base of RIP 0x%016llx RSP 0x%016llx at try %d\n",
                              currentRip, currentRsp, StackTrace->NumberOfTraces);
                    }
                    else if (StackTrace->NumberOfTraces == 0)
                    {
                        // If we are on the first try, the the start RIP can be outside of the driver
                        goto _start_searching;
                    }
                }
                else
                {
                    currentModBase = pDriver->BaseVa;
                }

                if (0 == currentModBase)
                {
                    if (Flags & STACK_FLG_ONLY_DRIVER_ADDRS)
                    {
                        goto _cleanup_and_leave;
                    }
                    else
                    {
                        goto _start_searching;
                    }
                }
            }

            // As we always search in the kernel buffer in the case of NT, we don't need the headers to be mapped
            // again here, so we'll skip it.
            if (currentModBase != gGuest.KernelVa)
            {
                status = IntVirtMemMap(currentModBase, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pModBaseMap);
                if (!INT_SUCCESS(status))
                {
                    // Extra check for user-mode drivers, which are not present all the time
                    if (pDriver != NULL &&
                        (0 == wstrcasecmp(pDriver->Name, u"win32k.sys") ||
                         0 == wstrcasecmp(pDriver->Name, u"TSDDD.dll") ||
                         0 == wstrcasecmp(pDriver->Name, u"cdd.dll")))
                    {
                        // Even if the number of traces is 0, we don't care, since if this driver would have modified
                        // something it would be present.
                        status = INT_STATUS_SUCCESS;
                    }
                    else
                    {
                        ERROR("[ERROR] Failed mapping driver base 0x%016llx to host: 0x%08x\n",
                              currentModBase, status);
                    }

                    goto _cleanup_and_leave;
                }
            }
        }
        else if (currentModBase == 0)
        {
            if (Flags & STACK_FLG_ONLY_DRIVER_ADDRS)
            {
                goto _cleanup_and_leave;
            }
            else
            {
                goto _start_searching;
            }
        }

        if (currentModBase != gGuest.KernelVa)
        {
            status = IntPeGetRuntimeFunction(currentModBase,
                                             pModBaseMap,
                                             (DWORD)(currentRip - currentModBase),
                                             &runtimeFunction);
        }
        else
        {
            status = IntPeGetRuntimeFunctionInBuffer(currentModBase,
                                                     gWinGuest->KernelBuffer,
                                                     gWinGuest->KernelBufferSize,
                                                     (DWORD)(currentRip - currentModBase),
                                                     &runtimeFunction);
        }

        if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
        {
            ERROR("[ERROR] Failed getting runtime function for module 0x%016llx RIP 0x%016llx: 0x%08x\n",
                  currentModBase, currentRip, status);
            goto _cleanup_and_leave;
        }
        else if (status == INT_STATUS_NOT_FOUND)
        {
            // If an address is not found inside the table, it is supposed to be a leaf function and RSP points to
            // the functions return address (somewhere in documentations).
        }
        else
        {
            DWORD ripOffset = (DWORD)(currentRip - currentModBase);

            // We start with this RVA and see in IntPeParseUnwindData if we need to go back further
            beginRva = runtimeFunction.BeginAddress;

            // We have one of those functions that starts somewhere and jumps around. We must assume a
            // rip offset greater than the length of the prologue.
            if (ripOffset < runtimeFunction.BeginAddress || ripOffset > runtimeFunction.EndAddress)
            {
                ripOffset = runtimeFunction.EndAddress - beginRva; // Assume the prologue executed fully
            }
            else
            {
                ripOffset -= beginRva;
            }

            if (currentModBase != gGuest.KernelVa)
            {
                status = IntPeParseUnwindData(currentModBase,
                                              pModBaseMap,
                                              &runtimeFunction,
                                              ripOffset,
                                              &prologueSize,
                                              &beginRva,
                                              &interrupt,
                                              &exception,
                                              &hasFramePointer);
            }
            else
            {
                status = IntPeParseUnwindDataInBuffer(currentModBase,
                                                      gWinGuest->KernelBuffer,
                                                      gWinGuest->KernelBufferSize,
                                                      &runtimeFunction,
                                                      ripOffset,
                                                      &prologueSize,
                                                      &beginRva,
                                                      &interrupt,
                                                      &exception,
                                                      &hasFramePointer);
            }

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntPeParseUnwindData failed for driver 0x%016llx with RIP 0x%016llx and begining "
                      "RVA 0x%x: 0x%08x\n", currentModBase, currentRip, runtimeFunction.BeginAddress, status);
                goto _cleanup_and_leave;
            }
        }

_start_searching:
        // advance the stack pointer
        newRsp = currentRsp + prologueSize;

        // If the function has a frame pointer then inside the function the initial size can grow, and there is no
        // safe way to know that size (and if that code is actually executed). But if the function has no frame pointer
        // we can only search in 16 values for the return address
        if (hasFramePointer)
        {
            tries = 0x400;      // suppose it doesn't reserve more than 1KB on the stack (if it does, this fails)
        }
        else
        {
            tries = 16;
        }

        if (!hasFramePointer && (interrupt || exception))
        {
            // Trap frame is just where the stack is
            status = IntKernVirtMemFetchQword(newRsp + ((exception) ? 8 : 0), &retAddress);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting the return address form GVA 0x%016llx: 0x%08x",
                      newRsp + (exception ? 8 : 0), status);
                goto _cleanup_and_leave;
            }

            if (IS_KERNEL_POINTER_WIN(TRUE, retAddress))
            {
                pDriver = IntDriverFindByAddress(retAddress);

                retModuleBase = pDriver ? pDriver->BaseVa : 0;
            }
            else
            {
                retModuleBase = 0;
                pDriver = NULL;
            }

            LOG("[STACK] NONHEUR : Found trap frame at stack address 0x%016llx with ret address 0x%016llx \n",
                newRsp, retAddress);

            retAddrPtr = newRsp + ((exception) ? 8 : 0);
            newRsp += (exception) ? (6 * 8) : (5 * 8);
            found = TRUE;
            status = INT_STATUS_SUCCESS;
            goto _next_stack_frame;
        }

        // if we are in an exception assume we found the error code already
        fErrorCode = exception;

        // If we are in a normal function, without the .pdb files there is no way to know how many parameters the
        // function has. So analyze all the pointers from here up.
        while (tries > 0)
        {
            // Map the stack if we didn't previously mapped it or the new stack gets into another page
            if (((currentRsp & PAGE_MASK) != (newRsp & PAGE_MASK)) || NULL == pStackBase)
            {
                if (NULL != pStackBase)
                {
                    IntVirtMemUnmap(&pStackBase);
                }

                currentRsp = newRsp;

                status = IntVirtMemMap(currentRsp & PAGE_MASK, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pStackBase);
                if (!INT_SUCCESS(status))
                {
                    // the stack is guarded, so we got to the end of the current stackframe (probably)
                    status = INT_STATUS_SUCCESS;
                    goto _cleanup_and_leave;
                }
            }

            // get the value on the stack, but first go to the current offset
            pStack = pStackBase + (newRsp & PAGE_OFFSET);

            // Here we can return to a user-mode address and we must parse the stack manually for the trap frame
            // {[ExceptionErrorCode], RIP, CS, EFLAGS, Old RSP, SS}. We don't know where it is, since the function
            // uses a frame pointer and the RSP could point anywhere...
            if (hasFramePointer && (exception || interrupt))
            {
                PQWORD pTrapFrame = (PQWORD)pStack;
                BOOLEAN um, km, fRip, fCs, fSs, fRsp, fEflags;
                um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;

                if (!fErrorCode)
                {
                    // Error code must be a DWORD
                    if (*pTrapFrame > 0xffffffff)
                    {
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddress = 0;

                        goto _next_pointer;
                    }

                    fErrorCode = TRUE;
                    goto _next_pointer;
                }

                if (!fRip)
                {
                    // RIP can be both user and kernel mode
                    if (IS_KERNEL_POINTER_WIN(TRUE, *pTrapFrame) && *pTrapFrame != 0xffffffffffffffff)
                    {
                        km = TRUE;
                    }
                    else if (*pTrapFrame > 0xffffffff && *pTrapFrame != 0xffffffffffffffff)
                    {
                        um = TRUE;
                    }
                    else
                    {
                        newRsp -= interrupt ? 8 : 0;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddress = 0;

                        goto _next_pointer;
                    }

                    retAddrPtr = newRsp;
                    retAddress = *pTrapFrame;

                    fRip = TRUE;
                    goto _next_pointer;
                }

                if (!fCs)
                {
                    // CS cannot be greater than 0xff
                    if (*pTrapFrame > 0xff)
                    {
                        newRsp -= interrupt ? 8 * 2 : 8;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }

                    // in kernel mode CS is 8 byte aligned
                    if (km && (*pTrapFrame % 8 != 0))
                    {
                        newRsp -= interrupt ? 8 * 2 : 8;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }
                    // in user mode CS can have any alignment

                    fCs = TRUE;
                    goto _next_pointer;
                }

                if (!fEflags)
                {
                    if (*pTrapFrame == 0)
                    {
                        newRsp -= interrupt ? 8 * 3 : 8 * 2;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }

                    // EFLAGS must be something nice
                    // 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
                    // 0  0  0  0  0  0  0  0  0  0  ID VP IP IF AC VM RF 0  NT PL OF DF  IF TF SF ZF 0  AF 0  PF 1  CF
                    if ((*pTrapFrame > (1 << 22)) ||    // bits [31 - 22]
                        (*pTrapFrame & (1 << 14)) ||
                        (*pTrapFrame & (1 << 5)) ||
                        (*pTrapFrame & (1 << 3)) ||
                        (0 == (*pTrapFrame & (1 << 1)))) // bit 1 must be 1
                    {
                        newRsp -= interrupt ? 8 * 3 : 8 * 2;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }

                    fEflags = TRUE;
                    goto _next_pointer;
                }

                if (!fRsp)
                {
                    // RSP is 8 byte (16 ?!) aligned
                    if (0 != *pTrapFrame % 8)
                    {
                        newRsp -= interrupt ? 8 * 4 : 8 * 3;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }

                    // RSP must be in the same space as RIP
                    if (km && (!IS_KERNEL_POINTER_WIN(TRUE, *pTrapFrame)))
                    {
                        newRsp -= interrupt ? 8 * 4 : 8 * 3;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }
                    else if (um && (IS_KERNEL_POINTER_WIN(TRUE, *pTrapFrame)))
                    {
                        newRsp -= interrupt ? 8 * 4 : 8 * 3;
                        um = km = fRip = fCs = fSs = fRsp = fEflags = FALSE;
                        fErrorCode = exception;
                        retAddrPtr = retAddress = 0;
                        goto _next_pointer;
                    }

                    fRsp = TRUE;
                    goto _next_pointer;
                }

                fSs = TRUE;
                if (fErrorCode && fRip && fCs && fEflags && fRsp && fSs)
                {
                    newRsp -= interrupt ? 5 * 8 : 4 * 8;
                    if (um)
                    {
                        retModuleBase = 0;      // We could somehow search for it, but that's beyond our purpose
                        pDriver = NULL;
                    }

                    // The beginning of the function is the called address for interrupts. No need to search for it
                    calledAddress = currentModBase + beginRva;

                    goto _found_ret;
                }
            }
            else
            {
                QWORD crip;

                // We do a normal analysis here. It's enough to see that the return address is a CALL or a JMP->CALL
                // (for imported functions).
                retAddress = *(PQWORD)pStack;

                // If this isn't a kernel pointer or the address is some pointer on the stack
                if (!IS_KERNEL_POINTER_WIN(TRUE, retAddress) || retAddress == 0xffffffffffffffff)
                {
                    goto _next_pointer;
                }

                // For normal pointers we must search analyze the call since the rules must apply (JMP/CALL)
                status = IntStackAnalyzePointer(retAddress, &calledAddress);
                if (!INT_SUCCESS(status))
                {
                    goto _next_pointer;
                }

                // If there is a call but on a different address, the get the next pointer.
                // But if the call address is 0 (that means the call involved a register) then we have nothing else
                // to do
                if (calledAddress != 0 && currentModBase != 0 && beginRva != 0 &&
                    calledAddress != currentModBase + beginRva)
                {
                    // See if the difference between current function and the called one is greater then maximum
                    // function length
                    if (calledAddress < currentModBase + beginRva &&
                        ((currentModBase + beginRva) - calledAddress > MAX_FUNC_LENGTH))
                    {
                        goto _analyze_jmp_after_call_case;
                    }
                }
                else if (calledAddress != 0 &&
                         (calledAddress < currentRip - MAX_FUNC_LENGTH || calledAddress > currentRip))
                {
                    // if the call does not involve a register and is outside [rip - 0xaa0, rip],
                    // we can assume that this is another call to another function, not ours
                    goto _analyze_jmp_after_call_case;
                }

                // We didn't end up in a case in which "we have a CALL [something]" where something is not near the
                // current rip, so we can just consider this as a success.
                goto _stack_trace_ok;

_analyze_jmp_after_call_case:
                pDriver = IntDriverFindByAddress(calledAddress);
                if (NULL == pDriver)
                {
                    goto _next_pointer;
                }

                STATS_ENTER(statsStackTraceSpecialCase);

                crip = calledAddress;

                for (DWORD i = 0; i < 100; i++)
                {
                    INSTRUX instrux;
                    QWORD calledFuncAddress = 0;
                    BOOLEAN bIsJump = FALSE;

                    status = IntDecDecodeInstruction(IG_CS_TYPE_64B, crip, &instrux);
                    if (!INT_SUCCESS(status))
                    {
                        break;
                    }

                    switch (instrux.Instruction)
                    {
                        case ND_INS_JMPNI: // JMP [...]
                        {
                            bIsJump = TRUE;

                            if (ND_OP_MEM == instrux.Operands[0].Type)
                            {
                                QWORD fetchAddress;

                                if (instrux.Operands[0].Info.Memory.IsRipRel)
                                {
                                    // Disp is already sign extended
                                    fetchAddress = crip + instrux.Length + instrux.Operands[0].Info.Memory.Disp;
                                }
                                else if (instrux.Operands[0].Info.Memory.HasDisp &&
                                         !instrux.Operands[0].Info.Memory.HasBase &&
                                         !instrux.Operands[0].Info.Memory.HasIndex)
                                {
                                    fetchAddress = instrux.Operands[0].Info.Memory.Disp;
                                }
                                else
                                {
                                    // So far so good, but it's using registers.
                                    break;
                                }

                                // Get the actual called address
                                status = IntKernVirtMemFetchQword(fetchAddress, &calledFuncAddress);
                                if (!INT_SUCCESS(status))
                                {
                                    WARNING("[WARNING] Failed to get function address from 0x%016llx "
                                            "(Call RIP 0x%016llx): 0x%08x\n", fetchAddress, crip, status);
                                    calledFuncAddress = 0;
                                    break;
                                }
                            }
                            else if (ND_OP_REG == instrux.Operands[0].Type)
                            {
                                calledFuncAddress = 0;
                                break;
                            }
                            else
                            {
                                // Don't take into account for now other things than JMP REG, JMP [MEM]
                                bIsJump = FALSE;
                            }

                            break;
                        }
                        case ND_INS_JMPNR:
                        {
                            bIsJump = TRUE;
                            calledFuncAddress = crip + instrux.Length + instrux.Operands[0].Info.RelativeOffset.Rel;
                            break;
                        }
                        default:
                        {
                            break;
                        }
                    }

                    if (bIsJump)
                    {
                        if (calledFuncAddress == 0 ||
                            (calledFuncAddress >= currentRip - MAX_FUNC_LENGTH && calledFuncAddress <= currentRip))
                        {
                            STATS_EXIT(statsStackTraceSpecialCase);
                            calledAddress = calledFuncAddress;
                            goto _stack_trace_ok;
                        }
                        break;
                    }

                    crip += instrux.Length;
                }

                STATS_EXIT(statsStackTraceSpecialCase);

                // If we ended here then we didn't find a CALL addr, and at addr a JMP REG, so we just go to next
                // pointer
                goto _next_pointer;

_stack_trace_ok:
                retAddrPtr = newRsp;
            }

_found_ret:
            if (IS_KERNEL_POINTER_WIN(TRUE, retAddress))
            {
                BOOLEAN bIsCode = FALSE;

                pDriver = IntDriverFindByAddress(retAddress);

                if (pDriver)
                {
                    DWORD rva = (DWORD)(retAddress - pDriver->BaseVa);
                    IMAGE_SECTION_HEADER sec = { 0 };

                    status = IntPeGetSectionHeaderByRva(pDriver->BaseVa, pDriver->Win.MzPeHeaders, rva, &sec);
                    if (!INT_SUCCESS(status))
                    {
                        goto _finish_searching_data_sec;
                    }

                    if (!!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                    {
                        bIsCode = TRUE;
                    }
                }

_finish_searching_data_sec:
                // Ignore non-code sections on stack trace when the call address can't be calculated.
                // If the return address is a `call rax` we can't actually verify that is valid return, so if the RIP
                // is not in a CODE/EXEC section, the return address call instruction must actually point where it
                // should (0xe8 calls, memory calls, etc.)
                if (!bIsCode && pDriver && calledAddress == 0)
                {
                    goto _next_pointer;
                }

                retModuleBase = pDriver ? pDriver->BaseVa : 0;
            }
            else
            {
                retModuleBase = 0;
                pDriver = NULL;
            }

            found = TRUE;
            status = INT_STATUS_SUCCESS;
            goto _next_stack_frame;

_next_pointer:
            newRsp += 8;
            tries--;
            status = INT_STATUS_SUCCESS;
        }

_next_stack_frame:
        if (!found)
        {
            // Don't save and don't go further
            if (INT_SUCCESS(status) && 0 == StackTrace->NumberOfTraces)
            {
                status = INT_STATUS_NOT_FOUND;
            }

            goto _cleanup_and_leave;
        }

        StackTrace->Traces[StackTrace->NumberOfTraces].CurrentRip = currentRip;
        StackTrace->Traces[StackTrace->NumberOfTraces].RetAddrPointer = retAddrPtr;
        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnAddress = retAddress;
        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnModule = pDriver;

        // the new RIP is the address we return
        currentRip = retAddress;

        // Mark the address imprecise if we have different values
        if (calledAddress != currentModBase + beginRva)
        {
            StackTrace->Traces[StackTrace->NumberOfTraces].Flags |= STACK_CALL_ADDRESS_IMPRECISE;
        }

        if (exception)
        {
            StackTrace->Traces[StackTrace->NumberOfTraces].Flags |= STACK_EXCEPTION_ROUTINE;
        }
        else if (interrupt)
        {
            StackTrace->Traces[StackTrace->NumberOfTraces].Flags |= STACK_INTERRUPT_ROUTINE;
        }

        // If exists, save the address at the call instruction, not the current function
        if (calledAddress != 0)
        {
            StackTrace->Traces[StackTrace->NumberOfTraces].CalledAddress = calledAddress;
        }
        else if (beginRva > 0)
        {
            StackTrace->Traces[StackTrace->NumberOfTraces].CalledAddress = currentModBase + beginRva;
        }

        // Update the module base to the new driver we are in
        if (retModuleBase == currentModBase)
        {
            ripInsideSameModule = TRUE;
        }
        else
        {
            ripInsideSameModule = FALSE;
            currentModBase = retModuleBase;
        }

        // finally increment the count
        StackTrace->NumberOfTraces++;

        // the current RSP is where we left it (adding the trap frame if that's the case)
        currentRsp = newRsp + (interrupt ? 5 * 8 : exception ? 4 * 8 : 0);

        if (retAddrPtr == currentRsp && 0 == retModuleBase && !interrupt && !exception)
        {
            currentRsp += 8;
        }

        // Signal an error only if we found no traces (and no error occurred)
        if (retModuleBase == 0 && (Flags & STACK_FLG_ONLY_DRIVER_ADDRS))
        {
            if (StackTrace->NumberOfTraces == 0 && status == INT_STATUS_SUCCESS)
            {
                ERROR("[ERROR] Didn't found a trace on the stack. RIP at 0x%016llx in module 0x%016llx\n",
                      currentRip, currentModBase);
                status = INT_STATUS_NOT_FOUND;
            }

            goto _cleanup_and_leave;
        }

        if (!IS_KERNEL_POINTER_WIN(TRUE, retAddress))
        {
            // we return in user-mode, so we cannot go further
            break;
        }
    } while (StackTrace->NumberOfTraces < MaxTraces);

_cleanup_and_leave:
    if (NULL != pStack)
    {
        pStack = pStackBase;
        IntVirtMemUnmap(&pStack);
    }

    if (NULL != pModBaseMap)
    {
        IntVirtMemUnmap(&pModBaseMap);
    }

    STATS_EXIT(statsStackTrace64);

    return status;
}


static INTSTATUS
IntWinStackTraceGet32(
    _In_ DWORD Stack,
    _In_ DWORD Eip,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Get a kernel stack trace starting from the current stack pointer for 32 bit systems.
///
/// Simplest algorithm. EBP[0] = next stack frame, EBP[1] = return address, EBP[2..] = parameters
///
/// If the function doesn't use the x86 stack convention, will just skip it...
/// Either way, the old method failed too if the EBP wasn't used as a stack pointer. From what I saw, the
/// windows kernel drivers are respecting the stack convention. If it fails for a 3rd party driver, we will
/// have no way but to except it through exceptions.bin.
///
/// @param[in]      Stack               Stack frame pointer from where to start searching.
/// @param[in]      Eip                 Instruction pointer from where to start searching.
/// @param[in]      MaxNumberOfTraces   Maximum number of stack traces to get.
/// @param[in]      Flags               Can be either #STACK_FLG_ONLY_DRIVER_ADDRS or #STACK_FLG_FAST_GET.
/// @param[in, out] StackTrace          A caller initialized #STACK_TRACE structure that will hold the stack trace.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    QWORD ebp, cr3;
    BOOLEAN remap;
    PDWORD pStack, pOrigStack;
    DWORD currentRip = 0;
    QWORD calledAddr = 0;

    UNREFERENCED_PARAMETER(Flags);

    if (!IS_KERNEL_POINTER_WIN(FALSE, Stack) || Stack % 4 != 0)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == MaxNumberOfTraces)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == StackTrace || NULL == StackTrace->Traces)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    STATS_ENTER(statsStackTrace32);

    StackTrace->StartRip = Eip;
    StackTrace->NumberOfTraces = 0;
    StackTrace->Bits64 = FALSE;
    ebp = Stack;
    remap = TRUE;
    pStack = pOrigStack = NULL;
    cr3 = gGuest.Mm.SystemCr3;
    status = INT_STATUS_SUCCESS;
    currentRip = Eip;

    for (DWORD frame = 0; frame < MaxNumberOfTraces; frame++)
    {
        DWORD retAddress = 0;
        DWORD nextFrame = 0;
        DWORD remaining;
        KERNEL_DRIVER *pMod = NULL;

        remaining = PAGE_REMAINING(ebp);

        if (remap)
        {
            if (NULL != pOrigStack)
            {
                IntVirtMemUnmap(&pOrigStack);
            }

            status = IntVirtMemMap(ebp, remaining, cr3, 0, &pOrigStack);
            if (!INT_SUCCESS(status))
            {
                LOG("[ERROR] Got to the end of the stack at 0x%016llx: 0x%08x\n", ebp, status);
                goto _check_and_leave;
            }

            pStack = pOrigStack;
        }

        // Always possible since the ebp is DWORD-aligned...
        nextFrame = pStack[0];

        if (nextFrame % 4 != 0)
        {
            WARNING("[WARNING] Unaligned stack: %08x\n", nextFrame);
            goto _check_and_leave;
        }
        else if (!IS_KERNEL_POINTER_WIN(FALSE, nextFrame))
        {
            TRACE("[INFO] User-Mode stack: %08x\n", nextFrame);
            goto _check_and_leave;
        }

        if (remaining >= 8)
        {
            retAddress = pStack[1];
        }
        else
        {
            status = IntKernVirtMemFetchDword(ebp + 4, &retAddress);
            if (!INT_SUCCESS(status))
            {
                LOG("[ERROR] Got to the end of the stack at 0x%016llx: 0x%08x\n", ebp + 4, status);
                goto _check_and_leave;
            }
        }

        if (IS_KERNEL_POINTER_WIN(FALSE, retAddress) && 0xffffffff != retAddress)
        {
            pMod = IntDriverFindByAddress(retAddress);
        }

        status = IntStackAnalyzePointer(retAddress, &calledAddr);
        if (!INT_SUCCESS(status))
        {
            calledAddr = 0;
        }

        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnAddress = retAddress;
        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnModule = pMod;

        StackTrace->Traces[StackTrace->NumberOfTraces].RetAddrPointer = ebp + 4;
        StackTrace->Traces[StackTrace->NumberOfTraces].CalledAddress = calledAddr;
        StackTrace->Traces[StackTrace->NumberOfTraces].CurrentRip = currentRip;

        currentRip = retAddress;

        ++StackTrace->NumberOfTraces;

        if ((ebp & PAGE_MASK) != (nextFrame & PAGE_MASK))
        {
            // We remap since we are in a different page... No point in recalculating the pStack pointer.
            remap = TRUE;
        }
        else
        {
            DWORD diff = (ebp > nextFrame) ? (DWORD)(ebp - nextFrame) : (DWORD)(nextFrame - ebp);

            remap = FALSE;

            // Just recalculate the stack pointer, no need to do a whole remap.
            pStack = (PDWORD)((PBYTE)pOrigStack + diff);
        }

        ebp = nextFrame;
    }

_check_and_leave:
    if (NULL != pOrigStack)
    {
        IntVirtMemUnmap(&pOrigStack);
    }

    STATS_EXIT(statsStackTrace32);

    if (0 == StackTrace->NumberOfTraces)
    {
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinStackTraceGet(
    _In_ QWORD StackFrame,
    _In_ QWORD Rip,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Get a kernel stack trace starting from the current stack pointer for 64 bit systems.
///
/// @param[in]      StackFrame          The current stack frame (EBP on x86, RSP on x86_64).
/// @param[in]      Rip                 The current instruction pointer ( ignored on x86).
/// @param[in]      MaxNumberOfTraces   Maximum number of stack traces to get.
/// @param[in]      Flags               Can be either #STACK_FLG_ONLY_DRIVER_ADDRS or #STACK_FLG_FAST_GET.
/// @param[in, out] StackTrace          A caller initialized #STACK_TRACE structure that will hold the stack trace.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    if (gGuest.Guest64)
    {
        return IntWinStackTraceGet64(StackFrame, Rip, MaxNumberOfTraces, Flags, StackTrace);
    }
    else
    {
        return IntWinStackTraceGet32((DWORD)StackFrame, (DWORD)Rip, MaxNumberOfTraces, Flags, StackTrace);
    }
}


static INTSTATUS
IntWinStackTraceGetUser32(
    _In_ PIG_ARCH_REGS Registers,
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ DWORD MaxNumberOfTraces,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Get the user stack trace of a 32 bit windows process.
///
/// @param[in]      Registers           Pointer to a structure containing registers of the current CPU.
/// @param[in]      Process             Pointer to the process from which to get the stack trace.
/// @param[in]      MaxNumberOfTraces   Maximum number of stack traces to get.
/// @param[in,out]  StackTrace          A caller initialized #STACK_TRACE structure that will hold the stack trace.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    QWORD cr3, ebp;
    INTSTATUS status;
    PDWORD pStack, pOrigStack;
    BOOLEAN remap;

    remap = TRUE;
    cr3 = Registers->Cr3;
    ebp = Registers->Rbp;
    pStack = pOrigStack = NULL;
    status = INT_STATUS_UNSUCCESSFUL;

    for (DWORD frame = 0; frame < MaxNumberOfTraces; frame++)
    {
        DWORD retAddress = 0;
        DWORD nextFrame = 0;
        DWORD remaining;
        PWIN_PROCESS_MODULE pMod = NULL;

        remaining = PAGE_REMAINING(ebp);

        if (remap)
        {
            if (NULL != pOrigStack)
            {
                IntVirtMemUnmap(&pOrigStack);
            }

            status = IntVirtMemMap(ebp, remaining, cr3, 0, &pOrigStack);
            if (!INT_SUCCESS(status))
            {
                LOG("[ERROR] Got to the end of the stack at 0x%016llx: 0x%08x\n", ebp, status);
                goto _check_and_leave;
            }

            pStack = pOrigStack;
        }

        // Always possible since the ebp is DWORD-aligned...
        nextFrame = pStack[0];

        if (nextFrame % 4 != 0)
        {
            ERROR("[ERROR] Unaligned stack value %08x (current %08llx)\n", nextFrame, ebp);
            goto _check_and_leave;
        }
        else if (IS_KERNEL_POINTER_WIN(FALSE, nextFrame))
        {
            TRACE("[INFO] Kernel-Mode stack %08x (current %08llx)\n", nextFrame, ebp);
            goto _check_and_leave;
        }
        else if (0 == nextFrame)
        {
            // Nothing we can do about this
            goto _check_and_leave;
        }

        if (nextFrame < ebp)
        {
            ERROR("[ERROR] Return stack frame %x is smaller than current %llx\n", nextFrame, ebp);
            goto _check_and_leave;
        }

        if (remaining >= 8)
        {
            retAddress = pStack[1];
        }
        else
        {
            status = IntVirtMemRead(ebp + 4, 4, cr3, &retAddress, NULL);
            if (!INT_SUCCESS(status))
            {
                LOG("[ERROR] Got to the end of the stack at 0x%016llx: 0x%08x\n", ebp + 4, status);
                goto _check_and_leave;
            }
        }

        pMod = IntWinUmModFindByAddress(Process, retAddress);
        if (NULL == pMod)
        {
            WARNING("[WARNING] Failed getting the dll base for RIP %08x\n", retAddress);
            goto _check_and_leave;
        }

        if (pMod->Cache && pMod->Cache->Headers)
        {
            IMAGE_SECTION_HEADER sec;

            status = IntPeGetSectionHeaderByRva(pMod->VirtualBase,
                                                pMod->Cache->Headers,
                                                (DWORD)(retAddress - pMod->VirtualBase),
                                                &sec);
            if (!INT_SUCCESS(status) ||
                (!(sec.Characteristics & IMAGE_SCN_CNT_CODE) &&
                 !(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)))
            {
                goto _save_and_next;
            }
        }

_save_and_next:
        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnAddress = retAddress;
        StackTrace->Traces[StackTrace->NumberOfTraces].ReturnModule = pMod;

        StackTrace->Traces[StackTrace->NumberOfTraces].RetAddrPointer = ebp + 4;
        StackTrace->Traces[StackTrace->NumberOfTraces].CalledAddress = 0;
        StackTrace->Traces[StackTrace->NumberOfTraces].CurrentRip = 0;

        ++StackTrace->NumberOfTraces;

        if ((ebp & PAGE_MASK) != (nextFrame & PAGE_MASK))
        {
            // We remap since we are in a different page... No point in recalculating the pStack pointer.
            remap = TRUE;
        }
        else
        {
            // We know that nextFrame > ebp
            DWORD diff = (DWORD)(nextFrame - ebp);

            remap = FALSE;

            // Just recalculate the stack pointer, no need to do a whole remap.
            pStack = (PDWORD)((PBYTE)pStack + diff);
        }

        ebp = nextFrame;
    }

_check_and_leave:
    if (NULL != pStack)
    {
        IntVirtMemUnmap(&pStack);
    }

    if (0 == StackTrace->NumberOfTraces)
    {
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinStackTraceGetUser64(
    _In_ PIG_ARCH_REGS Registers,
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Remaining,
    _Inout_ STACK_TRACE *StackTrace
    )
///
/// @brief Get the user stack trace of a 64 bit windows process.
///
/// @param[in]      Registers           Pointer to a structure containing registers of the current CPU.
/// @param[in]      Process             Pointer to the process from which to get the stack trace.
/// @param[in]      MaxNumberOfTraces   Maximum number of stack traces to get.
/// @param[in]      Remaining           Number of bytes that can be accessed starting from the current RSP.
/// @param[in,out]  StackTrace          A caller initialized #STACK_TRACE structure that will hold the stack trace.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    QWORD stackFrame;
    INTSTATUS status;
    PBYTE pStack;
    DWORD pagesToParse = Remaining > PAGE_SIZE ? 2 : 1;

    stackFrame = Registers->Rsp;

    for (DWORD j = 0; j < pagesToParse; j++)
    {
        DWORD remaining = PAGE_REMAINING(stackFrame);

        status = IntVirtMemMap(stackFrame, remaining, Registers->Cr3, 0, &pStack);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Cannot get a stack at address %llx (start RSP %llx): 0x%08x\n",
                  stackFrame, Registers->Rsp, status);

            return status;
        }

        for (DWORD i = 0; i < remaining; i += 8)
        {
            PWIN_PROCESS_MODULE pMod;
            QWORD ret = 0;
            IMAGE_SECTION_HEADER sec;

            ret = *(QWORD *)(pStack + i);

            pMod = IntWinUmModFindByAddress(Process, ret);
            if (NULL == pMod)
            {
                continue;
            }

            if (pMod->Cache && pMod->Cache->Headers)
            {
                status = IntPeGetSectionHeaderByRva(pMod->VirtualBase,
                                                    pMod->Cache->Headers,
                                                    (DWORD)(ret - pMod->VirtualBase),
                                                    &sec);
                if (!INT_SUCCESS(status))
                {
                    continue;
                }

                if (!(sec.Characteristics & IMAGE_SCN_CNT_CODE) &&
                    !(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                {
                    continue;
                }
            }

            StackTrace->Traces[StackTrace->NumberOfTraces].ReturnAddress = ret;
            StackTrace->Traces[StackTrace->NumberOfTraces].ReturnModule = pMod;
            StackTrace->Traces[StackTrace->NumberOfTraces].RetAddrPointer = stackFrame + i;

            if (++StackTrace->NumberOfTraces >= MaxNumberOfTraces)
            {
                break;
            }
        }

        IntVirtMemUnmap(&pStack);

        if (StackTrace->NumberOfTraces >= MaxNumberOfTraces)
        {
            break;
        }

        stackFrame += remaining;
    }

    if (StackTrace->NumberOfTraces == 0)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinStackHandleUserStackPagedOut(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Out_ QWORD *Remaining
    )
///
/// @brief  Handles the case when the stack is needed but is swapped out.
///
/// When checking for the return modules in some certain cases, such as writes from memcpy-like functions,
/// we will need the return module in order to match the exceptions, as the caller should be excepted instead
/// of the memcpy function. But, in the case when the stack is swapped out, we would most probably raise some
/// false positives, as the return module cannot be fetched and the exceptions will not match on these violations.
/// For this purpose, when the exception mechanism returns #INT_STATUS_STACK_SWAPPED_OUT, this function should
/// be called. This function will check if the stack is inside the known limits (fetched from TIB), and will
/// inject a page-fault in order to force the OS to swap in the stack. The caller must retry the instruction
/// which caused the violation when this function succeeds, as, on retrying, the stack should be in memory.
/// Note that, sometimes we would need the next page as well in order to get a correct stack trace. For this purpose,
/// we will get the current VAD containing the stack and inject a page fault either up until the end of the VAD, or
/// up until the next page after the one containing the RSP. If there doesn't exist such a VAD then we will not
/// inject any page faults, so the presence of a VAD for the current stack is also a form of validation.
///
/// @param[in]  Process         The process in which the stack swapped out corner case took place.
/// @param[out] Remaining       If the function succeeds, will contain the number of bytes which are accessible
///                             starting from the current RSP.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_INVALID_DATA_VALUE  If the stack is a kernel pointer.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT     If we are in the context of another process, in the case of shared memory,
///                                             indicating that no action needs to be done for this process.
/// @retval     #INT_STATUS_STACK_SWAPPED_OUT   If a \#PF was injected, either for the TIB or the stack, signaling that
///                                             the current instruction must be retried.
///
{
    INTSTATUS status;
    QWORD tibBase, stackBase, stackLimit;
    QWORD vadRoot = 0;
    VAD stackVad = { 0 };
    BOOLEAN foundSwappedOut = FALSE;

    tibBase = stackBase = stackLimit = 0;

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, gVcpu->Regs.Rsp))
    {
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    // For shared memory we should analyze the possibility of stack swapped out only when we are in
    // the context of the process where the violation is triggered.
    if (gVcpu->Regs.Cr3 != Process->Cr3)
    {
        *Remaining = 0;
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntWinThrGetCurrentStackBaseAndLimit(&tibBase, &stackBase, &stackLimit);
    if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
    {
        LOG("TIB is not present! Will inject #PF for %llx!\n", tibBase);

        // It is safe to inject page faults now, as we are processing a write over a user-mode module from another
        // user-mode module inside the same process at this time.
        // NOTE: We do not save a handle for this swap event (this is the only one) since this page may be executed
        // in the context of multiple threads, which would mean multiple swap-in attempts; therefore, we don't use
        // a context or a callback for this swap, which will be removed when terminating the process, if needed.
        status = IntSwapMemReadData(gVcpu->Regs.Cr3, tibBase, 32, SWAPMEM_OPT_UM_FAULT | SWAPMEM_OPT_NO_DUPS,
                                    NULL, 0, NULL, NULL, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
            return status;
        }

        // We'll return this status to signal that a #PF was injected and the action should be retried.
        return INT_STATUS_STACK_SWAPPED_OUT;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentStackBaseAndLimit failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemFetchWordSize(Process->EprocessAddress + WIN_KM_FIELD(Process, VadRoot), &vadRoot);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchWordSize failed: 0x%08x\n", status);
        return status;
    }

    status = IntWinVadFetchByRange(vadRoot, gVcpu->Regs.Rsp & PAGE_MASK, gVcpu->Regs.Rsp & PAGE_MASK, &stackVad);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinVadFetchByRange failed: 0x%08x\n", status);
        return status;
    }

    *Remaining = stackVad.EndPage + PAGE_SIZE - gVcpu->Regs.Rsp;

    if ((gVcpu->Regs.Rsp < stackLimit) || (gVcpu->Regs.Rsp >= stackBase))
    {
        // If the stack is pivoted, don't inject anything, we can't assume that we'll succeed.
        return INT_STATUS_SUCCESS;
    }

    // Inject a page fault on every page starting from the current RSP, up until either the end of the VAD containing
    // the stack, or the next page, as it would be enough for our purposes of getting the stacktrace.
    // Note: if the first page is not swapped out, and the second is swapped out then this code will inject a #PF
    // only on the second page, as it will be swapped out when checking the translation in IntSwapMemReadData.
    for (QWORD page = gVcpu->Regs.Rsp & PAGE_MASK;
         page <= stackVad.EndPage && page <= (gVcpu->Regs.Rsp & PAGE_MASK) + PAGE_SIZE;
         page += PAGE_SIZE)
    {
        QWORD pa;

        status = IntTranslateVirtualAddress(page, gVcpu->Regs.Cr3, &pa);
        if (status == INT_STATUS_NO_MAPPING_STRUCTURES || status == INT_STATUS_PAGE_NOT_PRESENT)
        {
            status = IntSwapMemReadData(gVcpu->Regs.Cr3, page, gGuest.WordSize,
                                        SWAPMEM_OPT_UM_FAULT | SWAPMEM_OPT_NO_DUPS, NULL, 0, NULL, NULL, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                return status;
            }

            foundSwappedOut = TRUE;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddress failed: 0x%08x\n", status);
            return status;
        }
    }

    if (foundSwappedOut)
    {
        return INT_STATUS_STACK_SWAPPED_OUT;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinStackTraceGetUser(
    _In_ PIG_ARCH_REGS Registers,
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ DWORD MaxNumberOfTraces,
    _Out_ STACK_TRACE *StackTrace
    )
///
/// @brief Get the user stack trace of a windows process.
///
/// @param[in]      Registers           Pointer to a structure containing registers of the current CPU.
/// @param[in]      Process             Pointer to the process from which to get the stack trace.
/// @param[in]      MaxNumberOfTraces   Maximum number of stack traces to get.
/// @param[in,out]  StackTrace          A caller initialized #STACK_TRACE structure that will hold the stack trace.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    DWORD csType;
    QWORD remaining = 0;

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == MaxNumberOfTraces)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, Registers->Rip))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    memzero(StackTrace->Traces, MaxNumberOfTraces * sizeof(STACK_ELEMENT));
    StackTrace->StartRip = Registers->Rip;
    StackTrace->NumberOfTraces = 0;

    status = IntWinStackHandleUserStackPagedOut(Process, &remaining);
    if (!INT_SUCCESS(status))
    {
        TRACE("[INFO] IntWinStackHandleUserStackPagedOut failed: 0x%08x\n", status);
        return status;
    }

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    if ((csType != IG_CS_TYPE_32B) && (csType != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", csType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (csType == IG_CS_TYPE_32B)
    {
        QWORD stackFrame = Registers->Rbp;

        StackTrace->Bits64 = FALSE;

        if ((stackFrame > Registers->Rsp &&
             stackFrame - Registers->Rsp > 3 * PAGE_SIZE) ||
            (stackFrame < Registers->Rsp &&
             Registers->Rsp - stackFrame > 3 * PAGE_SIZE))
        {
            // We probably are not in a stackframe, so get the first address on the stack and consider it to be the
            // return address
            PWIN_PROCESS_MODULE pMod = NULL;
            DWORD retAddress = 0;
            BOOLEAN bFound = FALSE;

            stackFrame = Registers->Rsp;

            // Parse the first 8 DWORDs on the stack, because the function might have done some pushes
            // (e.g. memset does not do a stack frame, but performs a push edi, so we shouldn't take the edi value as
            // the return address)
            for (size_t stackIndex = 0; stackIndex < MIN(8u, remaining / 4); stackIndex++)
            {
                status = IntVirtMemRead(stackFrame + stackIndex * 4, 4, Registers->Cr3, &retAddress, NULL);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] RSP 0x%016llx is not present: %08x\n", stackFrame + stackIndex * 4, status);
                    return status;
                }

                pMod = IntWinUmModFindByAddress(Process, retAddress);
                if (NULL == pMod)
                {
                    continue;
                }

                bFound = TRUE;
                break;
            }

            if (!bFound)
            {
                ERROR("[ERROR] DLL base was not found on stack 0x%016llx\n", stackFrame);
                return INT_STATUS_NOT_FOUND;
            }

            StackTrace->NumberOfTraces = 1;

            StackTrace->Traces[0].ReturnAddress = retAddress;
            StackTrace->Traces[0].ReturnModule = pMod;
            StackTrace->Traces[0].RetAddrPointer = stackFrame;

            return INT_STATUS_SUCCESS;
        }

        status = IntWinStackTraceGetUser32(Registers, Process, MaxNumberOfTraces, StackTrace);
        if (INT_SUCCESS(status))
        {
            return INT_STATUS_SUCCESS;
        }

        return INT_STATUS_NOT_FOUND;
    }

    StackTrace->Bits64 = TRUE;

    return IntWinStackTraceGetUser64(Registers, Process, MaxNumberOfTraces, remaining, StackTrace);
}


INTSTATUS
IntWinStackUserCheckIsPivoted(
    _In_ QWORD UserRsp,
    _In_ DWORD SegCs,
    _In_ BOOLEAN IsWow64Stack,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo,
    _Out_ BOOLEAN *IsPivoted
    )
///
/// @brief Check whether the stack is pivoted by checking if it's in the bounds of the
/// stack base and limit from the TIB.
///
/// @param[in]     UserRsp      The current user stack pointer.
/// @param[in]     SegCs        The CS selector, can be any of the #CODE_SEG_UM_32_GUEST_64, #CODE_SEG_UM_64_GUEST_64,
///                             or #CODE_SEG_UM_32_GUEST_32.
/// @param[in]     IsWow64Stack True if this is a Wow64 stack.
/// @param[in,out] DpiExtraInfo Pointer to a caller allocated #DPI_EXTRA_INFO structure that will have the stack base
///                             and limit fields set upon success.
/// @param[out]    IsPivoted    Will be set to TRUE if the stack is pivoted, FALSE otherwise.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    QWORD tibBase;
    QWORD stackBase;
    QWORD stackLimit;
    DWORD csType;
    DWORD alignSize;
    INTSTATUS status;

    tibBase = 0;
    stackBase = 0;
    stackLimit = 0;
    csType = 0;
    status = INT_STATUS_SUCCESS;

    if (NULL == IsPivoted)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    *IsPivoted = FALSE;
    alignSize = gGuest.WordSize;

    if (gGuest.Guest64)
    {
        switch (SegCs)
        {
        case CODE_SEG_UM_32_GUEST_64:
            csType = IG_CS_TYPE_32B;
            alignSize = sizeof(DWORD);
            break;

        case CODE_SEG_UM_64_GUEST_64:
            csType = IG_CS_TYPE_64B;
            break;

        default:
            ERROR("[ERROR] Unrecognized CS value: 0x%08x\n", SegCs);
            return INT_STATUS_INVALID_PARAMETER_2;
        }
    }
    else
    {
        csType = IG_CS_TYPE_32B;
    }

    if (0 == UserRsp ||
        IS_KERNEL_POINTER_WIN(gGuest.Guest64, UserRsp) ||
        UserRsp % alignSize != 0)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }


    status = IntWinThrGetCurrentTib(IG_CS_RING_0, csType, &tibBase);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentTib failed: 0x%08x\n", status);
        return status;
    }

    // Teb field will be NULL for WSL threads
    if (0 == tibBase)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntWinThrGetUmStackBaseAndLimitFromTib(tibBase, csType, gVcpu->Regs.Cr3, &stackBase, &stackLimit);
    if (!INT_SUCCESS(status))
    {
        if ((INT_STATUS_PAGE_NOT_PRESENT == status) ||
            (INT_STATUS_NO_MAPPING_STRUCTURES == status))
        {
            WARNING("[WARNING] IntWinThrGetUmStackBaseAndLimitFromTib failed: 0x%08x\n", status);
            return INT_STATUS_NOT_NEEDED_HINT;
        }

        ERROR("[ERROR] IntWinThrGetUmStackBaseAndLimitFromTib failed: 0x%08x\n", status);
        return status;
    }

    if (IsWow64Stack)
    {
        DpiExtraInfo->DpiPivotedStackExtraInfo.Wow64StackBase = stackBase;
        DpiExtraInfo->DpiPivotedStackExtraInfo.Wow64StackLimit = stackLimit;
    }
    else
    {
        DpiExtraInfo->DpiPivotedStackExtraInfo.StackBase = stackBase;
        DpiExtraInfo->DpiPivotedStackExtraInfo.StackLimit = stackLimit;
    }

    if (UserRsp < stackLimit || UserRsp > stackBase)
    {
        WARNING("[WARNING] UM stack (0x%016llx) outside of the limit and base interval "
                "from the current TIB [0x%016llx, 0x%016llx].\n", UserRsp, stackLimit, stackBase);
        *IsPivoted = TRUE;
    }

    return status;
}


static INTSTATUS
IntWinStackUserTrapFrameGet64(
    _In_  QWORD KernelStack,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo,
    _Out_ KTRAP_FRAME64 *TrapFrame
    )
///
/// @brief Get a 64 bit trap frame from a kernel stack.
///
/// Will parse the current KM stack for the trap frame.
/// We will check some fields in TrapFrame to validate it.
///
/// @param[in]      KernelStack     The kernel stack from which to start searching for the trap frame.
/// @param[in,out]  DpiExtraInfo    Pointer to a caller allocated #DPI_EXTRA_INFO structure. It will
///                                 have the DpiPivotedStackExtraInfo.TrapFrameAddress set accordingly
///                                 upon success.
/// @param[out]     TrapFrame       Pointer to a caller allocated #KTRAP_FRAME64 structure that will hold
///                                 the trap frame.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    BYTE *stackPointer;
    QWORD stackPointerGVA;
    BOOLEAN bFound;

    stackPointer = NULL;
    stackPointerGVA = 0;
    bFound = FALSE;

    if (!IS_KERNEL_POINTER_WIN(TRUE, KernelStack) || KernelStack % 8 != 0)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == TrapFrame)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    stackPointerGVA = ALIGN_DOWN(KernelStack, PAGE_SIZE) - PAGE_SIZE;

    // Map the first page of the stack, the TrapFrame should be there
    status = IntVirtMemMap(stackPointerGVA, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &stackPointer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed from GVA 0x%016llx: 0x%08x\n", stackPointerGVA, status);
        return status;
    }

    for (QWORD i = 0; i < PAGE_SIZE - sizeof(KTRAP_FRAME64); i += sizeof(QWORD))
    {
        bFound = IntWinIsUmTrapFrame(stackPointer + i);

        if (bFound)
        {
            *TrapFrame = *(PKTRAP_FRAME64)(stackPointer + i);

            DpiExtraInfo->DpiPivotedStackExtraInfo.TrapFrameAddress = stackPointerGVA + i;

            TRACE("[INFO] TrapFrame found: 0x%016llx\n", stackPointerGVA + i);
            break;
        }
    }

    IntVirtMemUnmap(&stackPointer);

    if (!bFound)
    {
        status = INT_STATUS_NOT_FOUND;
    }

    return status;
}


static INTSTATUS
IntWinStackUserTrapFrameGet32(
    _In_  DWORD KernelStack,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo,
    _Out_ KTRAP_FRAME32 *TrapFrame
    )
///
/// @brief Get a 32 bit trap frame from a kernel stack.
///
/// Will parse the current KM stack for the trap frame.
/// We will check some fields in TrapFrame to validate it.
///
/// @param[in]      KernelStack     The kernel stack from which to start searching for the trap frame.
/// @param[in,out]  DpiExtraInfo    Pointer to a caller allocated #DPI_EXTRA_INFO structure. It will
///                                 have the DpiPivotedStackExtraInfo.TrapFrameAddress set accordingly
///                                 upon success.
/// @param[out]     TrapFrame       Pointer to a caller allocated #KTRAP_FRAME32 structure that will hold
///                                 the trap frame.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    BYTE *stackPointer;
    QWORD stackPointerGVA;
    BOOLEAN bFound;

    status = INT_STATUS_SUCCESS;
    stackPointer = NULL;
    stackPointerGVA = 0;
    bFound = FALSE;

    if (!IS_KERNEL_POINTER_WIN(FALSE, KernelStack) || KernelStack % 4 != 0)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == TrapFrame)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    stackPointerGVA = ALIGN_DOWN(KernelStack, PAGE_SIZE) - PAGE_SIZE;

    // Map the first page of the stack, the TrapFrame should be there
    status = IntVirtMemMap(stackPointerGVA, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &stackPointer);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed from GVA 0x%016llx: 0x%08x\n", stackPointerGVA, status);
        return status;
    }

    for (DWORD i = 0; i < PAGE_SIZE - sizeof(KTRAP_FRAME32); i += sizeof(DWORD))
    {
        bFound = IntWinIsUmTrapFrame(stackPointer + i);

        if (bFound)
        {
            *TrapFrame = *(PKTRAP_FRAME32)(stackPointer + i);

            DpiExtraInfo->DpiPivotedStackExtraInfo.TrapFrameAddress = stackPointerGVA + i;

            TRACE("[INFO] TrapFrame found: 0x%016llx\n", stackPointerGVA + i);
            break;
        }
    }

    IntVirtMemUnmap(&stackPointer);

    if (!bFound)
    {
        status = INT_STATUS_NOT_FOUND;
    }

    return status;
}


INTSTATUS
IntWinStackUserTrapFrameGetGeneric(
    _Out_ QWORD *UserRsp,
    _Out_ DWORD *SegCs,
    _In_ BOOLEAN Fallback,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo
    )
///
/// @brief Get a bit trap frame from a kernel stack.
///
/// Will also set the DpiExtraInfo DpiPivotedStackExtraInfo.TrapFrameAddress and DpiPivotedStackExtraInfo.CurrentStack
/// fields accordingly upon success.
///
/// @param[out]     UserRsp         Will hold the current user space stack pointer.
/// @param[out]     SegCs           Will be set to any of the #CODE_SEG_UM_32_GUEST_64, #CODE_SEG_UM_64_GUEST_64, or
///                                 #CODE_SEG_UM_32_GUEST_32 accordingly.
/// @param[in]      Fallback        If TRUE and we fail getting a valid trap frame, will search on the user stack.
/// @param[in,out]  DpiExtraInfo    Pointer to a caller allocated #DPI_EXTRA_INFO structure.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD currentThread = 0;

    if (NULL == UserRsp)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == SegCs)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *UserRsp = 0;
    *SegCs = 0;

    status = IntWinThrGetCurrentThread(IG_CURRENT_VCPU, &currentThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentThread failed: 0x%08x\n", status);
        return status;
    }

    if (gGuest.Guest64)
    {
        QWORD trapFrameAddress = 0;
        QWORD stackBase = 0;
        KTRAP_FRAME64 trapFrame = { 0 };

        status = IntKernVirtMemFetchQword(currentThread + WIN_KM_FIELD(Thread, TrapFrame), &trapFrameAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the TrapFrame from Ethread 0x%016llx: 0x%08x\n", currentThread, status);
            return status;
        }

        // TrapFrame field for WSL thread will be NULL, we can find the TrapFrame on stack
        if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, trapFrameAddress))
        {
            QWORD count = 0;

            status = IntKernVirtMemRead(trapFrameAddress, sizeof(KTRAP_FRAME64), &trapFrame, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting the trap frame from CurrentThread 0x%016llx: 0x%08x\n",
                      currentThread, status);
                return status;
            }

            DpiExtraInfo->DpiPivotedStackExtraInfo.TrapFrameAddress = trapFrameAddress;

            while ((IS_KERNEL_POINTER_WIN(gGuest.Guest64, trapFrame.TrapFrame)) &&
                   (count++ < TRAPFRAME_MAX_ITERATIONS))
            {
                trapFrameAddress = trapFrame.TrapFrame;

                status = IntKernVirtMemRead(trapFrameAddress, sizeof(KTRAP_FRAME64), &trapFrame, NULL);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Failed getting the TrapFrame from CurrentThread 0x%016llx: 0x%08x\n",
                          currentThread, status);
                    return status;
                }

                DpiExtraInfo->DpiPivotedStackExtraInfo.TrapFrameAddress = trapFrameAddress;
            }

            if (count == TRAPFRAME_MAX_ITERATIONS)
            {
                WARNING("[WARNING] Specially crafted TrapFrame somehow: 0x%016llx\n", trapFrameAddress);
                return INT_STATUS_NOT_SUPPORTED;
            }
        }

        // Check if the found TrapFrame is a valid user-mode one, fall back to stack searching if not
        if (!IntWinIsUmTrapFrame(&trapFrame) && Fallback)
        {
            status = IntKernVirtMemFetchQword(currentThread + WIN_KM_FIELD(Thread, StackBase), &stackBase);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting the StackBase from CurrentThread 0x%016llx: 0x%08x\n",
                      currentThread, status);
                return status;
            }

            status = IntWinStackUserTrapFrameGet64(stackBase, DpiExtraInfo, &trapFrame);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting a TrapFrame: 0x%08x.\n", status);
                return status;
            }
        }

        DpiExtraInfo->DpiPivotedStackExtraInfo.CurrentStack = trapFrame.Rsp;

        *UserRsp = trapFrame.Rsp;
        *SegCs = trapFrame.SegCs;
    }
    else
    {
        KTRAP_FRAME32 trapFrame = { 0 };
        DWORD trapFrameAddress = 0;
        DWORD stackBase = 0;

        status = IntKernVirtMemFetchDword(currentThread + WIN_KM_FIELD(Thread, TrapFrame), &trapFrameAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the TrapFrame from Ethread 0x%016llx: 0x%08x\n", currentThread, status);
            return status;
        }

        // TrapFrame field for WSL thread will be NULL, we can find the TrapFrame on stack
        if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, trapFrameAddress))
        {
            status = IntKernVirtMemRead(trapFrameAddress, sizeof(KTRAP_FRAME32), &trapFrame, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed reading the TrapFrame from CurrentThread 0x%016llx: 0x%08x\n",
                      currentThread, status);
                return status;
            }

            if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, trapFrame.Eip))
            {
                WARNING("[WARNING] Current TrapFrame 0x%08x has a kernel mode Eip: 0x%08x \n",
                        trapFrameAddress, trapFrame.Eip);

                return INT_STATUS_NOT_NEEDED_HINT;
            }

            DpiExtraInfo->DpiPivotedStackExtraInfo.TrapFrameAddress = trapFrameAddress;
        }

        // Check if the found TrapFrame is a valid user-mode one, fall back to stack searching if not
        if (!IntWinIsUmTrapFrame(&trapFrame) && Fallback)
        {
            status = IntKernVirtMemFetchDword(currentThread + WIN_KM_FIELD(Thread, StackBase), &stackBase);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting the StackBase from CurrentThread 0x%016llx: 0x%08x\n",
                      currentThread, status);
                return status;
            }

            status = IntWinStackUserTrapFrameGet32(stackBase, DpiExtraInfo, &trapFrame);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed getting a TrapFrame: 0x%08x.\n", status);
                return status;
            }
        }

        DpiExtraInfo->DpiPivotedStackExtraInfo.CurrentStack = trapFrame.HardwareEsp;

        *UserRsp = trapFrame.HardwareEsp;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinStackWow64CheckIsPivoted(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo
    )
///
/// @brief Check whether a wow64 process' stack is pivoted.
///
/// Will set the CreationInfo field of the Process accordingly upon success.
///
/// @param[in] Process          The process whose stack to be checked.
/// @param[in] RealParent       The process' parent.
/// @param[in,out] DpiExtraInfo Pointer to a caller allocated #DPI_EXTRA_INFO structure.
//                              It's DpiPivotedStackExtraInfo.CurrentWow64Stack will be set to the rsp upon success.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD tib = 0;
    QWORD wow64SaveArea = 0;
    QWORD userWow64Rsp = 0;

    // Here we know we are in ring 0 and we want to get the user gs value (TIB), so it's safe to put cs type 64 bits.
    status = IntWinThrGetCurrentTib(IG_CS_RING_0, IG_CS_TYPE_64B, &tib);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinThrGetCurrentTib failed: 0x%08x\n", status);
        return status;
    }

    // These all might be swapped as they reside in UM. We have to check it and bail out if it happens.
    status = IntVirtMemRead(tib + WIN_UM_FIELD(Teb, Wow64SaveArea),
                            gGuest.WordSize, RealParent->Cr3, &wow64SaveArea, NULL);
    if (status == INT_STATUS_NO_MAPPING_STRUCTURES || status == INT_STATUS_PAGE_NOT_PRESENT)
    {
        INFO("[INFO] IntVirtMemRead failed: 0x%08x, the page 0x%016llx seems to be swapped out...\n", status,
             tib + WIN_UM_FIELD(Teb, Wow64SaveArea));
        return INT_STATUS_SUCCESS;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    status = IntVirtMemRead(wow64SaveArea + WIN_UM_FIELD(Teb, Wow64StackInSaveArea), sizeof(DWORD), RealParent->Cr3,
                            &userWow64Rsp, NULL);
    if (status == INT_STATUS_NO_MAPPING_STRUCTURES || status == INT_STATUS_PAGE_NOT_PRESENT)
    {
        INFO("[INFO] IntVirtMemRead failed: 0x%08x, the page 0x%016llx seems to be swapped out...\n", status,
             wow64SaveArea + WIN_UM_FIELD(Teb, Wow64StackInSaveArea));
        return INT_STATUS_SUCCESS;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    DpiExtraInfo->DpiPivotedStackExtraInfo.CurrentWow64Stack = userWow64Rsp;

    // Here we should get from fs the stack base and stack limit so we put the dummy cs which we know is valid for wow64
    status = IntWinStackUserCheckIsPivoted(userWow64Rsp, CODE_SEG_UM_32_GUEST_64, TRUE, DpiExtraInfo,
                                           &Process->CreationInfo.ParentHasPivotedStack);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinStackUserCheckIsPivoted failed: 0x%08x.\n", status);
        return status;
    }
    else if (Process->CreationInfo.ParentHasPivotedStack)
    {
        WARNING("[WARNING] Process 0x%016llx created with WoW64 pivoted stack.\n", Process->EprocessAddress);
    }

    return status;
}


BOOLEAN
IntWinIsUmTrapFrame(
    _In_ void *TrapFrame
    )
///
/// @brief Checks whether a TrapFrame is valid or not.
///
/// @param[in] TrapFrame    Pointer to a trap frame to be checked.
///
/// @returns TRUE if the trap frame is valid, FALSE otherwise.
///
{
    if (gGuest.Guest64)
    {
        KTRAP_FRAME64 *trapFrame = (KTRAP_FRAME64 *)TrapFrame;

        // EFLAGS check reserved bits
        if ((trapFrame->EFlags >= (1 << 22)) ||
            (trapFrame->EFlags & (1 << 1)) == 0 ||
            (trapFrame->EFlags & (1 << 3)) != 0 ||
            (trapFrame->EFlags & (1 << 5)) != 0 ||
            (trapFrame->EFlags & (1 << 15)) != 0)
        {
            return FALSE;
        }

        // Guest 64 valid SegCs
        if (trapFrame->SegCs != CODE_SEG_UM_64_GUEST_64)
        {
            return FALSE;
        }

        // UM, aligned Rsp
        if (trapFrame->Rsp % 8 != 0 ||
            IS_KERNEL_POINTER_WIN(TRUE, trapFrame->Rsp) ||
            trapFrame->Rsp == 0 ||
            trapFrame->Rsp == QWORD_MAX)
        {
            return FALSE;
        }

        // UM Rip
        if (IS_KERNEL_POINTER_WIN(TRUE, trapFrame->Rip) ||
            trapFrame->Rip == 0 ||
            trapFrame->Rip == QWORD_MAX)
        {
            return FALSE;
        }
    }
    else
    {
        KTRAP_FRAME32 *trapFrame = (KTRAP_FRAME32 *)TrapFrame;

        // EFLAGS check reserved bits
        if ((trapFrame->EFlags >= (1 << 22)) ||
            (trapFrame->EFlags & (1 << 1)) == 0 ||
            (trapFrame->EFlags & (1 << 3)) != 0 ||
            (trapFrame->EFlags & (1 << 5)) != 0 ||
            (trapFrame->EFlags & (1 << 15)) != 0)
        {
            return FALSE;
        }

        // Guest 32 valid SegCs
        if (trapFrame->SegCs != CODE_SEG_UM_32_GUEST_32)
        {
            return FALSE;
        }

        // Valid Esp
        if (IS_KERNEL_POINTER_WIN(FALSE, trapFrame->HardwareEsp) ||
            trapFrame->HardwareEsp % 4 != 0 ||
            trapFrame->HardwareEsp == 0 ||
            trapFrame->HardwareEsp == DWORD_MAX)
        {
            return FALSE;
        }

        // Valid Eip
        if (IS_KERNEL_POINTER_WIN(FALSE, trapFrame->Eip) ||
            trapFrame->Eip == 0 ||
            trapFrame->Eip == DWORD_MAX)
        {
            return FALSE;
        }
    }

    return TRUE;
}
