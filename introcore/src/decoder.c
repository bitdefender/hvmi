/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "decoder.h"
#include "gpacache.h"
#include "guests.h"
#include "icache.h"
#include "introcpu.h"
#include "kernvm.h"
#include "lixprocess.h"
#include "winprocesshp.h"

/// @brief  Get the value of a register inside a register array.
///
/// This assumes that the registers are placed in the order documented by the Intel manual.
///
/// @param[in]  ctx     Structure containing the registers. #IG_ARCH_REGS can safely be used with this macro.
/// @param[in]  reg     The index of the register.
///
/// @returns    The value of the register.
#define REG_GPRV(ctx, reg) (*((&(ctx)->Rax) + (reg)))
/// @brief  Get the pointer to a register.
///
/// This assumes that the registers are placed in the order documented by the Intel manual.
///
/// @param[in]  ctx     Structure containing the registers. #IG_ARCH_REGS can safely be used with this macro.
/// @param[in]  reg     The index of the register.
///
/// @returns    A pointer to reg.
#define REG_GPRP(ctx, reg) ((&(ctx)->Rax) + (reg))

/// @brief  Checks if a memory access is done inside the Windows kernel virtual address space.
///
/// @param[in]  is64    True if this is a 64-bit kernel, False if it is a 32-bit kernel.
/// @param[in]  gla     Guest linear address at which the access starts.
/// @param[in]  size    The size of the access.
///
/// @retval     True if the entire access is done inside the kernel virtual address space.
/// @retval     False if it is not.
#define IS_ACCESS_IN_KERNEL_WIN(is64, gla, size)    IS_KERNEL_POINTER_WIN((is64), (gla)) && \
                                                    IS_KERNEL_POINTER_WIN((is64), (gla) + (size)-1)
/// @brief  Checks if a memory access is done inside the Linux kernel virtual address space.
///
/// @param[in]  gla     Guest linear address at which the access starts.
/// @param[in]  size    The size of the access.
///
/// @retval     True if the entire access is done inside the kernel virtual address space.
/// @retval     False if it is not.
#define IS_ACCESS_IN_KERNEL_LIX(gla, size)          IS_KERNEL_POINTER_LIX((gla)) && \
                                                    IS_KERNEL_POINTER_LIX((gla) + (size)-1)

/// Describes the flags affected by an instruction
enum
{
    FM_LOGIC, ///< Logic operation.
    FM_SUB,   ///< Subtraction.
    FM_ADD,   ///< Addition.
} INT_FLAGS_MODE;

/// @brief  Get the sign bit of a value.
///
/// @param[in]  sz  Size of the value.
/// @param[in]  x   Value.
///
/// @returns    The value of the sign bit.
#define GET_SIGN(sz, x) ((sz) == 1 ? ((x)&0x80) >> 7 : \
                         (sz) == 2 ? ((x)&0x8000) >> 15 : \
                         (sz) == 4 ? ((x)&0x80000000) >> 31 : (x) >> 63)


static void
IntDecSetFlags(
    _In_ QWORD Dst,
    _In_ QWORD Src1,
    _In_ QWORD Src2,
    _In_ DWORD Size,
    _In_ PIG_ARCH_REGS Regs,
    _In_ DWORD FlagsMode
    )
///
/// @brief Sets the flags according to the result of an operation.
///
/// @param[in]      Dst         The result of the operation.
/// @param[in]      Src1        The first source operand.
/// @param[in]      Src2        The second source operand.
/// @param[in]      Size        The size of the destination.
/// @param[in, out] Regs        The registers state.
/// @param[in]      FlagsMode   Flags mode. A combination of INT_FLAGS_MODE values
///
{
    BYTE pfArr[16] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4};

    // Mask the operands with their respective size.
    Dst = ND_TRIM(Size, Dst);
    Src1 = ND_TRIM(Size, Src1);
    Src2 = ND_TRIM(Size, Src2);

    // PF set if the first bytes has an even number of 1 bits.
    if ((pfArr[Dst & 0xF] + pfArr[(Dst >> 4) & 0xF]) % 2 == 0)
    {
        Regs->Flags |= CPU_EFLAGS_PF;
    }
    else
    {
        Regs->Flags &= ~CPU_EFLAGS_PF;
    }

    // ZF set if the result is zero.
    if (Dst == 0)
    {
        Regs->Flags |= CPU_EFLAGS_ZF;
    }
    else
    {
        Regs->Flags &= ~CPU_EFLAGS_ZF;
    }

    // SF is set if the sign flag is set.
    if (GET_SIGN(Size, Dst) != 0)
    {
        Regs->Flags |= CPU_EFLAGS_SF;
    }
    else
    {
        Regs->Flags &= ~CPU_EFLAGS_SF;
    }

    // OF and CF are handled differently for some instructions.
    if (FM_LOGIC == FlagsMode)
    {
        // OF and CF are cleared on logic instructions.
        Regs->Flags &= ~(CPU_EFLAGS_OF | CPU_EFLAGS_CF);
    }
    else
    {
        // Set CF.
        if ((FM_SUB == FlagsMode) && (Src1 < Src2))
        {
            Regs->Flags |= CPU_EFLAGS_CF;
        }
        else if ((FM_ADD == FlagsMode) && (Dst < Src1))
        {
            Regs->Flags |= CPU_EFLAGS_CF;
        }
        else
        {
            Regs->Flags &= ~CPU_EFLAGS_CF;
        }

        // Set OF.
        if (FM_SUB == FlagsMode)
        {
            if ((GET_SIGN(Size, Src1) && !GET_SIGN(Size, Src2) && !GET_SIGN(Size, Dst)) ||
                (!GET_SIGN(Size, Src1) && GET_SIGN(Size, Src2) && GET_SIGN(Size, Dst)))
            {
                Regs->Flags |= CPU_EFLAGS_OF;
            }
            else
            {
                Regs->Flags &= ~CPU_EFLAGS_OF;
            }
        }
        else if (FM_ADD == FlagsMode)
        {
            if ((GET_SIGN(Size, Src1) == GET_SIGN(Size, Src2) && GET_SIGN(Size, Src1) != GET_SIGN(Size, Dst)))
            {
                Regs->Flags |= CPU_EFLAGS_OF;
            }
            else
            {
                Regs->Flags &= ~CPU_EFLAGS_OF;
            }
        }
    }
}


INTSTATUS
IntDecDecodeInstruction(
    _In_ IG_CS_TYPE CsType,
    _In_ QWORD Gva,
    _Out_ void *Instrux
    )
///
/// @brief Decode an instruction from the provided guest linear address.
///
/// Will decode, in the context of the current CPU the instruction
/// located at address GuestVirtualAddress. The decoded instruction will be returned in the Instrux argument.
/// Note that this function does not use the instruction cache. It will map & decode the provided Gva on each call.
///
/// @param[in]  CsType  Operating mode/mode in which the instruction must be decoded.
/// @param[in]  Gva     The guest virtual address that contains the instruction to be decoded.
/// @param[out] Instrux Will contain, upon successful return, the decoded instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_PAGE_NOT_PRESENT If the page containing the instruction is not mapped.
/// @retval #INT_STATUS_DISASM_ERROR If the decoding failed.
///
{
    NDSTATUS ndstatus;
    INTSTATUS status;
    BYTE defData, defCode;
    BYTE code[16] = { 0 };
    BOOLEAN partialFetch;
    size_t fetchedBytes;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    partialFetch = FALSE;

    if (IG_CS_TYPE_64B == CsType)
    {
        defData = ND_DATA_64;
        defCode = ND_CODE_64;
    }
    else if (IG_CS_TYPE_32B == CsType)
    {
        defData = ND_DATA_32;
        defCode = ND_CODE_32;
    }
    else if (IG_CS_TYPE_16B == CsType)
    {
        defData = ND_DATA_16;
        defCode = ND_CODE_16;
    }
    else
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if ((Gva & PAGE_MASK) != ((Gva + ND_MAX_INSTRUCTION_LENGTH) & PAGE_MASK))
    {
        void *p;
        DWORD size;

        size = PAGE_REMAINING(Gva);

        status = IntVirtMemMap(Gva, size, 0, 0, &p);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_leave;
        }

        memcpy(code, p, size);
        fetchedBytes = size;

        IntVirtMemUnmap(&p);

        status = IntVirtMemMap(Gva + size, 16 - size, 0, 0, &p);
        if (!INT_SUCCESS(status))
        {
            partialFetch = TRUE;
            goto partial_fetch;
        }

        memcpy(&code[size], p, 16 - size);
        fetchedBytes += 16 - size;

        IntVirtMemUnmap(&p);
partial_fetch:
        ;
    }
    else
    {
        void *p;

        status = IntVirtMemMap(Gva, 16, 0, 0, &p);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_leave;
        }

        memcpy(code, p, 16);
        fetchedBytes = 16;

        IntVirtMemUnmap(&p);
    }

    ndstatus = NdDecodeEx(Instrux, code, fetchedBytes, defCode, defData);
    if ((ND_STATUS_BUFFER_TOO_SMALL == ndstatus) && (partialFetch))
    {
        status = INT_STATUS_PAGE_NOT_PRESENT;
        goto cleanup_and_leave;
    }
    else if (!ND_SUCCESS(ndstatus))
    {
        status = INT_STATUS_DISASM_ERROR;
        goto cleanup_and_leave;
    }
    else
    {
        // no error from disasm
        status = INT_STATUS_SUCCESS;
    }

cleanup_and_leave:

    return status;
}


INTSTATUS
IntDecDecodeInstructionFromBuffer(
    _In_reads_bytes_(BufferSize) PBYTE Buffer,
    _In_ size_t BufferSize,
    _In_ IG_CS_TYPE CsType,
    _Out_ void *Instrux
    )
///
/// @brief Decode an instruction from the provided buffer.
///
/// Decodes an instruction from the provided buffer. If the function fails, the Instrux parameter is undefined.
///
/// @param[in]  Buffer      The buffer containing the instruction.
/// @param[in]  BufferSize  The size of the input buffer.
/// @param[in]  CsType      Operating mode (16, 32 or 64 bit).
/// @param[out] Instrux     Will contain upon successful return the decoded instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_DISASM_ERROR If instruction decoding failed.
///
{
    NDSTATUS ndstatus;
    INTSTATUS status;
    BYTE defData, defCode;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == BufferSize)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (IG_CS_TYPE_64B == CsType)
    {
        defData = ND_DATA_64;
        defCode = ND_CODE_64;
    }
    else if (IG_CS_TYPE_32B == CsType)
    {
        defData = ND_DATA_32;
        defCode = ND_CODE_32;
    }
    else if (IG_CS_TYPE_16B == CsType)
    {
        defData = ND_DATA_16;
        defCode = ND_CODE_16;
    }
    else
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    ndstatus = NdDecodeEx(Instrux, Buffer, BufferSize, defCode, defData);
    if (!ND_SUCCESS(ndstatus))
    {
        status = INT_STATUS_DISASM_ERROR;
        goto cleanup_and_leave;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_leave:

    return status;
}


INTSTATUS
IntDecDecodeInstructionAtRip(
    _In_ DWORD CpuNumber,
    _In_ IG_ARCH_REGS *Registers,
    _In_opt_ IG_SEG_REGS *Segments,
    _Out_ INSTRUX *Instrux
    )
///
/// @brief Decode an instruction at current RIP on the provided VCPU.
///
/// Will decode the instruction pointed by the current RIP on the provided CPU. If CpuNumber is not the current VCPU,
/// make sure it is paused before doing any kind of query on it, since information from a running VCPU is undefined.
///
/// @param[in]  CpuNumber   The CPU number.
/// @param[in]  Registers   The general purpose register state.
/// @param[in]  Segments    Optional pointer to the segment register state. If NULL, the segment registers will be
///                         fetched internally.
/// @param[out] Instrux     Will contain, upon successful return, the decoded instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If the provided CPU is not in 16, 32 or 64 bit mode.
/// @retval INT_DISASM_ERROR If a decoding error occurs.
///
{
    INTSTATUS status;
    IG_SEG_REGS segs;
    DWORD csType = 0;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == Segments)
    {
        status = IntGetSegs(CpuNumber, &segs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetSegs failed: 0x%08x\n", status);
            return status;
        }

        Segments = &segs;
    }

    // Get the CS type for this cpu (we need it in order to see if it's in 16 bit, 32 bit or 64 bit).
    status = IntGetCurrentMode(CpuNumber, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    // Make sure the CPU is either in 32 bit or in 64 bit.
    if ((csType != IG_CS_TYPE_16B) && (csType != IG_CS_TYPE_32B) && (csType != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", csType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    return IntDecDecodeInstruction(csType, Segments->CsBase + Registers->Rip, Instrux);
}


INTSTATUS
IntDecDecodeInstructionAtRipWithCache(
    _In_ void *Cache,
    _In_ DWORD CpuNumber,
    _In_ PIG_ARCH_REGS Registers,
    _Out_ PINSTRUX Instrux,
    _In_ DWORD Options,
    _Out_opt_ BOOLEAN *CacheHit,
    _Out_opt_ BOOLEAN *Added
    )
///
/// @brief Decode an instruction using the cache.
///
/// Given the CPU CpuNumber, this function will decode the instruction located at RIP, using the cache. If the
/// instruction was already cached, it will be returned from there. Otherwise, it will be added to the cache,
/// if Options does not contain #DEC_OPT_NO_CACHE.
///
/// @param[in]  Cache       The instruction cache.
/// @param[in]  CpuNumber   The CPU number for which the instruction at RIP will be decoded.
/// @param[in]  Registers   The general purpose registers state.
/// @param[out] Instrux     Will contain, upon successful return, the decoded instruction.
/// @param[in]  Options     Decode options. Can be 0 or #DEC_OPT_NO_CACHE, which indicates that the instruction should
///                         not be cached.
/// @param[out] CacheHit    Optional, set to true if the cache was hit, or false otherwise.
/// @param[out] Added       Optional, set to true if the instruction has been added to the cache, false otherwise.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_PAGE_NOT_PRESENT If the page containing the instruction is swapped out.
/// @retval #INT_STATUS_NO_MAPPING_STRUCTURES If the page containing the instruction is swapped out.
/// @retval #INT_STATUS_NOT_SUPPORTED If the CR3 for the CPU CpuNumber does not point to a valid process.
///
{
    INTSTATUS status;
    DWORD ring, mode;
    QWORD cr3, rip;
    BOOLEAN global;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    mode = 0;
    global = FALSE;

    status = IntGetCurrentMode(CpuNumber, &mode);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    // Get the current CPL of the running VCPU. We use a common x64 invariant: user mode < 0xFFFF800000000000 -
    // this greatly improves performance on Xen.
    if (IG_CS_TYPE_64B == mode)
    {
        // 64 bit mode (not 32 bit or compatibility mode), RIP == linear RIP - CS has base 0 in 64 bits mode.
        rip = Registers->Rip;

        ring = (rip < 0xFFFF800000000000 ? IG_CS_RING_3 : IG_CS_RING_0);
    }
    else
    {
        IG_SEG_REGS segs;

        // 32 bit or compatibility mode. We have to get the segment registers to determine the linear RIP.
        status = IntGetSegs(CpuNumber, &segs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetSegs failed: 0x%08x\n", status);
            return status;
        }

        ring = (segs.SsAr >> 5) & 3;

        rip = segs.CsBase + Registers->Rip;
    }

    cr3 = Registers->Cr3;

    // Check if we're in user-mode or kernel-mode.
    if (IG_CS_RING_0 == ring)
    {
        // We're in kernel mode, we can make the entry global - match it in any VA space.
        global = TRUE;
        cr3 = 0;
    }

    // Lookup the instruction inside the icache.
    status = IntIcLookupInstruction(Cache, Instrux, rip, cr3);
    if (!INT_SUCCESS(status))
    {
        // Not found, decode it now.
        status = IntDecDecodeInstruction(mode, rip, Instrux);
        if ((INT_STATUS_PAGE_NOT_PRESENT == status) || (INT_STATUS_NO_MAPPING_STRUCTURES == status))
        {
            TRACE("[INFO] The page containing the RIP has been swapped out; will retry the instruction.\n");
            return status;
        }
        else if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstructionAt failed: 0x%08x\n", status);
            return status;
        }

        // Cache instructions if and only if we're not in real mode or unpaged and the caller requests it
        if ((0 != (Registers->Cr0 & CR0_PE)) &&
            (0 != (Registers->Cr0 & CR0_PG)) &&
            (0 == (Options & DEC_OPT_NO_CACHE)))
        {
            BOOLEAN goodCr3 = FALSE;

            // Make sure a process with this CR3 exists. The reason we have to do this is EFI; during BOOT, exits may
            // be triggered from the EFI runtime, with CR3s which do not belong to any process. Caching such entries
            // in the icache may lead to issues, since that CR3 will be freed without us knowing (since it doesn't
            // belong to any process, no process termination event will take place).
            if (0 != cr3)
            {
                // Non-null cr3, make sure this belongs to a valid process.
                void *pProc;

                if (gGuest.OSType == introGuestWindows)
                {
                    pProc = IntWinProcFindObjectByCr3(cr3);
                }
                else if (gGuest.OSType == introGuestLinux)
                {
                    pProc = IntLixTaskFindByCr3(cr3);
                }
                else
                {
                    pProc = NULL;
                }

                if (NULL != pProc)
                {
                    goodCr3 = TRUE;
                }
            }
            else
            {
                // cr3 is 0, we can cache this, since we will use the SystemCR3.
                goodCr3 = TRUE;
            }

            // Add it to the instruction cache.
            if (goodCr3)
            {
                status = IntIcAddInstruction(Cache, Instrux, rip, cr3, global);
                if (!INT_SUCCESS(status) && (INT_STATUS_PAGE_NOT_PRESENT != status) &&
                    (INT_STATUS_NO_MAPPING_STRUCTURES != status))
                {
                    // It's not an issue that we couldn't add the instruction to the cache.
                    WARNING("[WARNING] IntIcAddInstruction failed: 0x%08x\n", status);
                }
            }
            else
            {
                WARNING("[WARNING] Cannot cache %s, RIP 0x%016llx, CR3 0x%016llx, as no valid process exists!\n",
                        Instrux->Mnemonic, rip, cr3);
                status = INT_STATUS_NOT_SUPPORTED;
            }

            if (NULL != Added)
            {
                *Added = !!INT_SUCCESS(status);
            }
        }
        else if (NULL != Added)
        {
            *Added = FALSE;
        }

        if (NULL != CacheHit)
        {
            *CacheHit = FALSE;
        }
    }
    else
    {
        if (NULL != CacheHit)
        {
            *CacheHit = TRUE;
        }
        if (NULL != Added)
        {
            *Added = FALSE;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDecDecodeOperandSize(
    _In_ PINSTRUX Instrux,
    _In_ PND_OPERAND Operand,
    _In_ PIG_ARCH_REGS Registers,
    _Out_ DWORD *AccessSize
    )
///
/// @brief Decode the size of the given operand.
///
/// Given an instruction operand and the general purpose registers state, it will decode it's size. It assumes it will
/// be called for memory operands only. This function is required, as some instructions may contain operands who's size
/// is variable (for example, XSAVE/XRSTOR memory operand, which depends on the enabled extended state).
///
/// @param[in]  Instrux     The decoded instruction.
/// @param[in]  Operand     The instruction (memory) operand for which the size is to be computed.
/// @param[in]  Registers   The general purpose registers state.
/// @param[out] AccessSize  Will contain, upon successful return, the actual size of the provided operand.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    DWORD accessSize;

    UNREFERENCED_PARAMETER(Registers);

    accessSize = Operand->Size;

    if ((0 == accessSize) || (ND_SIZE_UNKNOWN == accessSize))
    {
        // We still don't know the accessed size. Check if this is XSAVE & friends. If it is, we need to compute
        // the actual accessed size.
        if ((ND_INS_XSAVE == Instrux->Instruction) || (ND_INS_XSAVEC == Instrux->Instruction) ||
            (ND_INS_XSAVEOPT == Instrux->Instruction) || (ND_INS_XSAVES == Instrux->Instruction) ||
            (ND_INS_XRSTOR == Instrux->Instruction) || (ND_INS_XRSTORS == Instrux->Instruction))
        {
            INTSTATUS status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_XSAVE_SIZE,
                                                 (void *)(size_t)IG_CURRENT_VCPU,
                                                 &accessSize,
                                                 sizeof(accessSize));
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntQueryGuestInfo failed: 0x%08x\n", status);
                return status;
            }
        }

        if ((ND_INS_FXSAVE == Instrux->Instruction) || (ND_INS_FXRSTOR == Instrux->Instruction))
        {
            // Size is always 512 bytes for FXSAVE/FXRSTOR. It includes FPU state, FPU control/tag/etc. words & SSE
            // state.
            accessSize = 512;
        }

        if ((ND_INS_BNDLDX == Instrux->Instruction) || (ND_INS_BNDSTX == Instrux->Instruction))
        {
            // BNDSTX/BNDLDX access the BND page tables. The accessed size, is therefore:
            // 4B (x86) or 8B (x64) of the access is inside the BND directory
            // 16B (x86) or 32B (x64) if the access is inside the BND table
            // For now, assume the worst (maximum size), but a full MPX walk should be done to deduce if the access
            // size is 4/8 bytes or 16/32 bytes.
            accessSize = (Instrux->DefCode == ND_CODE_64) ? 32 : 16;
        }
    }
    else if (ND_SIZE_CACHE_LINE == accessSize)
    {
        /// Cache-flushing instructions (CLFLUSH, CLFLUSHOPT, CLWB) should not be a problem, as the page walk
        /// and the EPT walk should be done when data is written in memory an cached.
        accessSize = 64;
    }

    *AccessSize = accessSize;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecDecodeAccessSize(
    _In_ PINSTRUX Instrux,
    _In_ PIG_ARCH_REGS Registers,
    _In_ QWORD Gla,
    _In_ BYTE AccessType,
    _Out_ DWORD *AccessSize
    )
///
/// @brief Decode the memory access size of a given instruction.
///
/// This function will decode the memory access size from the provided instruction.
/// Important note: this function assumes that the memory access as explicit (as part of an instruction execution).
/// However, there are several cases where the CPU may access memory implicitly:
/// - CPU page walk as part of VA translation or setting of an accessed/dirty bits (GPA access, read/write)
/// - Stack access as part of an interrupt or exception delivery (GLA access, write)
/// - IDT access as part of an interrupt or exception delivery (GLA access, read)
/// - GDT/LDT access as part of a descriptor load or setting of an accessed bit (GLA access, read/write)
/// - TSS access as part of a task switch or interrupt delivery - IST access (GLA access, read/write)
/// - BTS/BTM/PEBS access as part of performance monitoring/branch tracing (GLA access, read/write)
/// - PT (Processor Trace) accesses (GLA access, read/write)
/// - MPX BNDLDX/BNDSTX instructions
/// - SGX events? (read/write)
/// Note that except for the implicit CPU page walk accesses, we can't really tell whether an access is caused by
/// the instruction itself or by any other event, such as an interrupt/exception delivery that reads the IDT.
///
/// @param[in]  Instrux     The decoded instruction.
/// @param[in]  Registers   The general purpose registers state.
/// @param[in]  Gla         Reserved for future use.
/// @param[in]  AccessType  The operand who\`s access is equal to AccessType will be decoded (useful for MOVS
///                         instruction).
/// @param[out] AccessSize  Will contain, upon successful return, the size of the memory operand who`s access is
///                         AccessType.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If a memory operand with access AccessType is not found.
///
{
    DWORD i;

    UNREFERENCED_PARAMETER(Registers);
    UNREFERENCED_PARAMETER(Gla);

    // NOTE: We use the fact that there isn't a single instruction that has multiple memory operands, except for
    // MOVS/CMPS.
    for (i = 0; i < Instrux->OperandsCount; i++)
    {
        // Check if this is the memory operand.
        // We stop at the first operand that has at least some of the desired flags.
        if ((ND_OP_MEM == Instrux->Operands[i].Type) && !!(Instrux->Operands[i].Access.Access & AccessType))
        {
            return IntDecDecodeOperandSize(Instrux, &Instrux->Operands[i], Registers, AccessSize);
        }
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntDecComputeLinearAddress(
    _In_ PINSTRUX Instrux,
    _In_ PND_OPERAND Operand,
    _In_opt_ PIG_ARCH_REGS Registers,
    _Out_ QWORD *LinearAddress
    )
///
/// @brief Given an instruction and a memory operand, it will compute the guest linear address encoded by that operand.
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  Operand         The memory operand.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[out] LinearAddress   The computed linear address associated with the provided operand.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If VSIB is used by the instruction.
///
{
    INTSTATUS status;
    IG_ARCH_REGS gprRegs;
    IG_SEG_REGS segRegs;
    PND_OPERAND pOp;
    QWORD gla;

    if (NULL == Registers)
    {
        status = IntGetGprs(IG_CURRENT_VCPU, &gprRegs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        Registers = &gprRegs;
    }

    pOp = Operand;

    if (pOp->Type != ND_OP_MEM)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    // We can't handle VSIB and compressed displacement.
    if (pOp->Info.Memory.IsVsib)
    {
        ERROR("[ERROR] VSIB is not supported! Use IntDecComputeVsibLinearAddresses.\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    // We have the mem operand. Compute the linear address.
    status = IntGetSegs(IG_CURRENT_VCPU, &segRegs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetSegs failed with status: 0x%x\n", status);
        return status;
    }

    if (pOp->Info.Memory.HasSeg)
    {
        switch (pOp->Info.Memory.Seg)
        {
        case NDR_ES:
            gla = segRegs.EsBase;
            break;
        case NDR_CS:
            gla = segRegs.CsBase;
            break;
        case NDR_SS:
            gla = segRegs.SsBase;
            break;
        case NDR_DS:
            gla = segRegs.DsBase;
            break;
        case NDR_FS:
            gla = segRegs.FsBase;
            break;
        case NDR_GS:
            gla = segRegs.GsBase;
            break;
        default:
            gla = 0;
            break;
        }
    }
    else
    {
        gla = 0;
    }

    // Direct addressing. No RIP relative, base or SIB addressing can be present.
    if (pOp->Info.Memory.IsDirect)
    {
        gla += pOp->Info.Memory.Disp;

        goto done;
    }

    // Handle base.
    if (pOp->Info.Memory.HasBase)
    {
        // Seg.Base + Base
        QWORD base = ((PQWORD)&Registers->Rax)[pOp->Info.Memory.Base];

        base &= ND_SIZE_TO_MASK(pOp->Info.Memory.BaseSize);

        gla += base;
    }

    // Handle index.
    if (pOp->Info.Memory.HasIndex)
    {
        // Seg.Base [+ Base] + Index * Scale
        QWORD index = ((PQWORD)&Registers->Rax)[pOp->Info.Memory.Index];

        index &= ND_SIZE_TO_MASK(pOp->Info.Memory.IndexSize);

        gla += index * pOp->Info.Memory.Scale;
    }

    // Handle displacement.
    if (pOp->Info.Memory.HasDisp)
    {
        if (pOp->Info.Memory.HasCompDisp)
        {
            gla += pOp->Info.Memory.Disp * pOp->Info.Memory.CompDispSize;
        }
        else
        {
            gla += pOp->Info.Memory.Disp;
        }
    }

    // RIP relative addressing.
    if (pOp->Info.Memory.IsRipRel)
    {
        gla += Registers->Rip + Instrux->Length;
    }

    // Special handling for BT, BTR, BTS, BTC instructions with bitbase addressing.
    if (pOp->Info.Memory.IsBitbase)
    {
        QWORD bitbase, op1size, op2size;

        if ((Instrux->Operands[1].Type != ND_OP_REG) || (Instrux->Operands[1].Info.Register.Type != ND_REG_GPR))
        {
            return INT_STATUS_INVALID_PARAMETER_2;
        }

        op1size = Instrux->Operands[0].Size;
        op2size = Instrux->Operands[1].Size;

        bitbase = ND_SIGN_EX(op2size, ((QWORD *)&Registers->Rax)[Instrux->Operands[1].Info.Register.Reg]);

        if (bitbase & (1ULL << 63))
        {
            gla -= ((~bitbase >> 3) & ~(op1size - 1)) + op1size;
        }
        else
        {
            gla += (bitbase >> 3) & ~(op1size - 1);
        }
    }

    // Special handling for stack operations: if we have a PUSH, we have to subtract the accessed size, as, in fact,
    // RSP - size is accessed, not RSP.
    if (pOp->Info.Memory.IsStack)
    {
        if (pOp->Access.Write || pOp->Access.CondWrite)
        {
            gla -= pOp->Size;
        }
    }

done:
    *LinearAddress = gla;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDecComputeVsibLinearAddresses(
    _In_ PINSTRUX Instrux,
    _In_ PND_OPERAND Operand,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _Out_writes_to_(16, Operand->Info.Memory.Vsib.ElemCount) QWORD *LinearAddresses
    )
///
/// @brief Decode VSIB addresses from the given instruction.
///
/// This function will compute up to 16 indexes as used by VSIB addressing. Make sure the LinearAddresses param can
/// hold the maximum number of indexes. This function must be called when the memory operand of the given instruction
/// uses the VSIB addressing.
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  Operand         The VSIB memory operand.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[in]  XsaveArea       Optional pointer to the XSAVE area where the state is saved.
/// @param[out] LinearAddresses Up to 16 VSIB addresses accessed by the instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is provided.
///
{
    INTSTATUS status;
    IG_ARCH_REGS gprRegs;
    IG_SEG_REGS segRegs;
    PND_OPERAND pOp;
    QWORD baseseg;
    DWORD i;
    OPERAND_VALUE indexValue = { 0 };
    union
    {
        DWORD dindexes[16];
        QWORD qindexes[8];
    } vsibindex;

    if (NULL == Registers)
    {
        status = IntGetGprs(IG_CURRENT_VCPU, &gprRegs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        Registers = &gprRegs;
    }

    pOp = Operand;

    if ((pOp->Type != ND_OP_MEM) || !pOp->Info.Memory.IsVsib)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    // We have the mem operand. Compute the linear address.
    status = IntGetSegs(IG_CURRENT_VCPU, &segRegs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetSegs failed with status: 0x%x\n", status);
        return status;
    }

    // Fetch the SSE index register.
    status = IntDecGetSseRegValue(XsaveArea, pOp->Info.Memory.Index, pOp->Info.Memory.IndexSize, &indexValue);
    if (!INT_SUCCESS(status))
    {
        if (INT_STATUS_OPERATION_NOT_IMPLEMENTED != status)
        {
            ERROR("[ERROR] IntDecGetSseRegValue failed: 0x%08x\n", status);
        }

        return status;
    }

    if (indexValue.Size > sizeof(vsibindex))
    {
        ERROR("[ERROR] The index value is too large: %u bytes!\n", indexValue.Size);
        return INT_STATUS_NOT_SUPPORTED;
    }

    memcpy(&vsibindex, indexValue.Value.ByteValues, indexValue.Size);

    if (pOp->Info.Memory.HasSeg)
    {
        switch (pOp->Info.Memory.Seg)
        {
        case NDR_ES:
            baseseg = segRegs.EsBase;
            break;
        case NDR_CS:
            baseseg = segRegs.CsBase;
            break;
        case NDR_SS:
            baseseg = segRegs.SsBase;
            break;
        case NDR_DS:
            baseseg = segRegs.DsBase;
            break;
        case NDR_FS:
            baseseg = segRegs.FsBase;
            break;
        case NDR_GS:
            baseseg = segRegs.GsBase;
            break;
        default:
            baseseg = 0;
            break;
        }
    }
    else
    {
        baseseg = 0;
    }

    for (i = 0; i < Operand->Info.Memory.Vsib.ElemCount; i++)
    {
        QWORD gla = baseseg;

        // Handle base.
        if (pOp->Info.Memory.HasBase)
        {
            // Seg.Base + Base
            QWORD base = ((PQWORD)&Registers->Rax)[pOp->Info.Memory.Base];

            base &= ND_SIZE_TO_MASK(pOp->Info.Memory.BaseSize);

            gla += base;
        }

        // Handle index.
        if (pOp->Info.Memory.HasIndex)
        {
            QWORD index;

            // Seg.Base [+ Base] + Index * Scale
            if (pOp->Info.Memory.Vsib.IndexSize == 4)
            {
                index = vsibindex.dindexes[i];
            }
            else
            {
                index = vsibindex.qindexes[i];
            }

            gla += index * pOp->Info.Memory.Scale;
        }

        // Handle displacement.
        if (pOp->Info.Memory.HasDisp)
        {
            if (pOp->Info.Memory.HasCompDisp)
            {
                gla += pOp->Info.Memory.Disp * pOp->Info.Memory.CompDispSize;
            }
            else
            {
                gla += pOp->Info.Memory.Disp;
            }
        }

        // RIP relative addressing.
        if (pOp->Info.Memory.IsRipRel)
        {
            gla += Registers->Rip + Instrux->Length;
        }

        LinearAddresses[i] = gla;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecDecodeSourceLinearAddressFromInstruction(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _Out_ QWORD *LinearAddress
    )
///
/// @brief Decode the source memory linear address.
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[out] LinearAddress   Will contain, upon successful exit, the read linear address.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If a memory operand that is read is not found.
///
{
    DWORD i;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == LinearAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    i = 0;

    // Find the memory operand.
    while (i < Instrux->OperandsCount)
    {
        if ((Instrux->Operands[i].Type == ND_OP_MEM) && (Instrux->Operands[i].Access.Read ||
                                                         Instrux->Operands[i].Access.CondRead))
        {
            break;
        }

        i++;
    }

    if (i >= Instrux->OperandsCount)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return IntDecComputeLinearAddress(Instrux, &Instrux->Operands[i], Registers, LinearAddress);
}


INTSTATUS
IntDecDecodeDestinationLinearAddressFromInstruction(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _Out_ QWORD *LinearAddress
    )
///
/// @brief Decode the destination memory linear address.
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[out] LinearAddress   Will contain, upon successful exit, the written linear address.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If a memory operand that is written is not found.
///
{
    DWORD i;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == LinearAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    i = 0;

    // Find the memory operand.
    while (i < Instrux->OperandsCount)
    {
        if ((Instrux->Operands[i].Type == ND_OP_MEM) && (Instrux->Operands[i].Access.Write ||
                                                         Instrux->Operands[i].Access.CondWrite))
        {
            break;
        }

        i++;
    }

    if (i >= Instrux->OperandsCount)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return IntDecComputeLinearAddress(Instrux, &Instrux->Operands[i], Registers, LinearAddress);
}


static INTSTATUS
IntSetValueForOperand(
    _In_ PINSTRUX Instrux,
    _In_ DWORD OperandIndex,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_ OPERAND_VALUE *OpValue,
    _In_ BOOLEAN Commit
    )
///
/// @brief Set the value of an instruction operand.
///
/// This function will set the value for the provided instruction operand. If the operand is a general purpose register,
/// it will modify that register. If the operand is memory, it will do a memory store to that address.
/// This function only supports memory, general purpose & vector registers.
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  OperandIndex    The operand who`s value is to be modified.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[in]  OpValue         The new operand value to be set.
/// @param[in]  Commit          If true, the registers state will be committed to the visible state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If an unsupported operand type is used.
///
{
    INTSTATUS status;
    PND_OPERAND pOp;
    IG_ARCH_REGS regs;
    QWORD gla;
    BOOLEAN commitRegs;

    gla = 0;
    commitRegs = FALSE;

    if (NULL == Registers)
    {
        status = IntGetGprs(IG_CURRENT_VCPU, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        Registers = &regs;
    }

    pOp = &Instrux->Operands[OperandIndex];

    if (pOp->Type == ND_OP_MEM)
    {
        // Decode the linear address.
        status = IntDecComputeLinearAddress(Instrux, pOp, Registers, &gla);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecComputeLinearAddress failed: 0x%08x\n", status);
            return status;
        }

        // Write the data.
        status = IntVirtMemSafeWrite(Registers->Cr3, gla, OpValue->Size, OpValue->Value.ByteValues, IG_CS_RING_0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
            return status;
        }

        // Modify the stack pointer, if needed.
        if (pOp->Info.Memory.IsStack)
        {
            Registers->Rsp -= pOp->Size;
            commitRegs = TRUE;
        }
    }
    else if (pOp->Type == ND_OP_REG)
    {
        if (pOp->Info.Register.Type == ND_REG_GPR)
        {
            PBYTE dst = NULL;

            if ((pOp->Size == ND_SIZE_8BIT) && (ND_ENCM_LEGACY == Instrux->EncMode) && (!Instrux->HasRex) &&
                (pOp->Info.Register.Reg >= NDR_RSP))
            {
                dst = (PBYTE) & ((PQWORD)&Registers->Rax)[pOp->Info.Register.Reg - 4] + 1;
            }
            else
            {
                dst = (PBYTE) & ((PQWORD)&Registers->Rax)[pOp->Info.Register.Reg];
            }

            switch (OpValue->Size)
            {
            case ND_SIZE_8BIT:
                *dst = OpValue->Value.ByteValues[0];
                break;
            case ND_SIZE_16BIT:
                *((PWORD)dst) = OpValue->Value.WordValues[0];
                break;
            case ND_SIZE_32BIT:
                *((PDWORD)dst) = OpValue->Value.DwordValues[0];
                *((PDWORD)(dst + 4)) = 0;
                break;
            case ND_SIZE_64BIT:
                *((PQWORD)dst) = OpValue->Value.QwordValues[0];
                break;
            default:
                break;
            }

            commitRegs = TRUE;
        }
        else if (pOp->Info.Register.Type == ND_REG_SSE)
        {
            status = IntDecSetSseRegValue(NULL, pOp->Info.Register.Reg, OpValue->Size, OpValue, Commit);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecSetSseRegValue failed for register %d with size %d: 0x%08x\n",
                      pOp->Info.Register.Reg, OpValue->Size, status);
            }
            return status;
        }
        else
        {
            ERROR("[ERROR] Unsupported register type: %d\n", pOp->Info.Register.Type);
            return INT_STATUS_NOT_SUPPORTED;
        }
    }
    else
    {
        ERROR("[ERROR] Unsupported operand type: %d\n", pOp->Type);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (commitRegs && Commit)
    {
        status = IntSetGprs(IG_CURRENT_VCPU, Registers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntGetValueFromOperand(
    _In_ PINSTRUX Instrux,
    _In_ DWORD OperandIndex,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_opt_ PBYTE MemoryValue,
    _Out_ OPERAND_VALUE *WrittenValue
    )
///
/// @brief Get the value of an instruction operand.
///
/// Returns the value from the given operand. Supported operand types: GPRs, memory operands, immediate operands
/// OperandIndex is zero-based index of the desired operand. If provided, MemoryValue will be used to fetch the
/// memory operand, if the operand is located in memory. Otherwise, the linear address will be computed and the
/// operand will be fetched from within the guest memory.
/// Note: no checks are made on OperandValue size. The caller should allocate enough space for the maximum possible
/// operand size
///
/// @param[in]  Instrux         Decoded instruction.
/// @param[in]  OperandIndex    The index of the operand who`s value is to be fetched.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[in]  MemoryValue     Optional pointer to a memory region containing the memory operand.
/// @param[out] WrittenValue    Will contain, upon successful return, the operand value.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the given operand type is not supported
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    IG_ARCH_REGS regs;
    QWORD opValue[4] = {0xbdbdbad, 0xbdbdbad, 0xbdbdbad, 0xbdbdbad}; // in case we will ever want to read a YMM value
    BYTE opSize = 0;
    PND_OPERAND pOp;
    //QWORD operandValue;

    if (OperandIndex >= Instrux->OperandsCount)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pOp = &Instrux->Operands[OperandIndex];
    opSize = (BYTE)pOp->Size;

    if (opSize > sizeof(opValue) || 0 == opSize)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    // If the caller didn't pass any, then read from the current VCPU.
    if (NULL == Registers)
    {
        status = IntGetGprs(IG_CURRENT_VCPU, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        Registers = &regs;
    }

    if ((ND_OP_REG == pOp->Type) && (ND_REG_GPR == pOp->Info.Register.Type))
    {
        DWORD gprIndex = 0;

        // special check for ah, bh, ch, dh
        if ((ND_SIZE_8BIT == pOp->Size) && (pOp->Info.Register.Reg >= NDR_RSP) &&
            !Instrux->HasRex && (ND_ENCM_LEGACY == Instrux->EncMode))
        {
            gprIndex = pOp->Info.Register.Reg - 4;

            opValue[0] = ((PQWORD)&Registers->Rax)[gprIndex];
            opValue[0] = (opValue[0] >> 8) & 0xFF;
        }
        else
        {
            gprIndex = pOp->Info.Register.Reg;

            opValue[0] = ((PQWORD)&Registers->Rax)[gprIndex];
        }
    }
    else if (ND_OP_REG == pOp->Type && ND_REG_SSE == pOp->Info.Register.Type)
    {
        status = IntDecGetSseRegValue(NULL, pOp->Info.Register.Reg, pOp->Info.Register.Size, WrittenValue);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecGetSseRegValue failed for instruction %s with status: 0x%x\n",
                  Instrux->Mnemonic, status);
            return status;
        }
        WrittenValue->Size = (BYTE)Instrux->Operands[OperandIndex].Size;
        return INT_STATUS_SUCCESS;
    }
    else if (ND_OP_IMM == pOp->Type)
    {
        opValue[0] = pOp->Info.Immediate.Imm;
    }
    else if (ND_OP_MEM == pOp->Type)
    {
        if (NULL == MemoryValue)
        {
            QWORD guestVa = 0;
            DWORD retLength = 0;

            status = IntDecComputeLinearAddress(Instrux, pOp, Registers, &guestVa);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecComputeLinearAddress failed: 0x%08x\n", status);
                return status;
            }

            // Safe: We check if opSize is greater than sizeof(opValue).
            status = IntVirtMemRead(guestVa, opSize, Registers->Cr3, &opValue, &retLength);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntVirtMemRead failed for %llx: 0x%x\n", guestVa, status);
                return status;
            }
            if (retLength != (DWORD)opSize)
            {
                WARNING("[WARNING] IntVirtMemRead completed with no errors, but the returned size "
                        "(%d) is not the expected size (%d\n",
                        retLength, opSize);
            }
        }
        else
        {
            switch (opSize)
            {
            case 1:
                opValue[0] = *MemoryValue;
                break;
            case 2:
                opValue[0] = *(PWORD)MemoryValue;
                break;
            case 4:
                opValue[0] = *(PDWORD)MemoryValue;
                break;
            case 8:
                opValue[0] = *(PQWORD)MemoryValue;
                break;
            default:
                memcpy(opValue, MemoryValue, opSize);
                break;
            }
        }
    }
    else
    {
        // we don't know what to do with this
        ERROR("[ERROR] Unsupported operand type %d\n", pOp->Type);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (opSize > 8)
    {
        memcpy(WrittenValue->Value.QwordValues, opValue, opSize);
    }
    else
    {
        WrittenValue->Value.QwordValues[0] = ND_TRIM(opSize, opValue[0]);
    }

    WrittenValue->Size = opSize;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecEmulateRead(
    _In_ PINSTRUX Instrux,
    _In_opt_ BYTE *SrcValueBuffer
    )
///
/// @brief Emulate a read access.
///
/// This function assumes that it is called for emulating instructions that read data from memory.
/// If not NULL, SrcValueBuffer will be used instead of the real memory contents. Caller must ensure that
/// SrcValueBuffer has a minimum size of gVcpu->AccessSize.
/// Note that after calling this function some assumptions about the global state can't be made:
/// on successful emulation, gVcpu->Regs.Rip will no longer point to the instruction bytes from which
/// gVcpu->Instruction was decoded, but to the next instruction; as a result, calling IntDecEmulateRead
/// twice on the same exit might prove fatal.
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  SrcValueBuffer  Optional pointer to the source value buffer.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_SUPPORTED If the emulation is not supported (invalid OS, architecture, instruction).
///
{
    IG_ARCH_REGS *regs = &gVcpu->Regs;
    OPERAND_VALUE finalValue = { 0 };
    OPERAND_VALUE srcValue = { 0 };
    BOOLEAN hasSrc = FALSE;
    INTSTATUS status;
    DWORD ring;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (gVcpu->AccessSize > ND_MAX_REGISTER_SIZE)
    {
        ERROR("[ERROR] Unsupported access size: 0x%08x\n", gVcpu->AccessSize);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Instrux->EncMode != ND_ENCM_LEGACY && Instrux->EncMode != ND_ENCM_VEX)
    {
        ERROR("[ERROR] Unsupported encoding: %02d\n", Instrux->EncMode);
        IntDumpInstruction(Instrux, regs->Rip);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // The RIP must be in kernel
    if ((gGuest.OSType == introGuestWindows && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, regs->Rip)) ||
        (gGuest.OSType == introGuestLinux && !IS_KERNEL_POINTER_LIX(regs->Rip)))
    {
        ERROR("[ERROR] RIP is not in kernel: 0x%016llx\n", regs->Rip);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // The access must be done in kernel
    if ((gGuest.OSType == introGuestWindows &&
            !IS_ACCESS_IN_KERNEL_WIN(gGuest.Guest64, gVcpu->Gla, gVcpu->AccessSize)) ||
        (gGuest.OSType == introGuestLinux &&
            !IS_ACCESS_IN_KERNEL_LIX(gVcpu->Gla, gVcpu->AccessSize)))
    {
        ERROR("[ERROR] Access is not in kernel: [0x%016llx, 0x%016llx)\n", gVcpu->Gla, gVcpu->Gla + gVcpu->AccessSize);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // The access must be read
    if (ND_ACCESS_READ != (Instrux->MemoryAccess & ND_ACCESS_READ))
    {
        ERROR("[ERROR] Access is not read: 0x%02x\n", Instrux->MemoryAccess);
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = IntGetCurrentRing(IG_CURRENT_VCPU, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    // The current ring must be 0
    if (ring != IG_CS_RING_0)
    {
        ERROR("[ERROR] Ring is not 0: %d\n", ring);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (SrcValueBuffer != NULL)
    {
        memcpy(srcValue.Value.ByteValues, SrcValueBuffer, gVcpu->AccessSize);
        srcValue.Size = gVcpu->AccessSize;
        hasSrc = TRUE;
    }

    status = INT_STATUS_SUCCESS;

    switch (Instrux->Instruction)
    {
    case ND_INS_MOVZX:
    case ND_INS_MOV:
    {
        DWORD dstSize = Instrux->Operands[0].Size;

        if (!hasSrc)
        {
            status = IntGetValueFromOperand(Instrux, 1, regs, NULL, &srcValue);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
                return status;
            }
        }

        // Copy just the size of the destination operand (can't be more than a QWORD)
        finalValue.Value.QwordValues[0] = srcValue.Value.QwordValues[0];
        finalValue.Size = dstSize;
        break;
    }

    case ND_INS_AND:
    case ND_INS_OR:
    case ND_INS_XOR:
    {
        // Read the first operand and compute the new value
        OPERAND_VALUE val1 = { 0 };

        if (!hasSrc)
        {
            status = IntGetValueFromOperand(Instrux, 1, regs, NULL, &srcValue);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
                return status;
            }
        }

        status = IntGetValueFromOperand(Instrux, 0, regs, NULL, &val1);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            return status;
        }

        if (ND_INS_AND == Instrux->Instruction)
        {
            finalValue.Value.QwordValues[0] = val1.Value.QwordValues[0] & srcValue.Value.QwordValues[0];
        }
        else if (ND_INS_OR == Instrux->Instruction)
        {
            finalValue.Value.QwordValues[0] = val1.Value.QwordValues[0] | srcValue.Value.QwordValues[0];
        }
        else if (ND_INS_XOR == Instrux->Instruction)
        {
            finalValue.Value.QwordValues[0] = val1.Value.QwordValues[0] ^ srcValue.Value.QwordValues[0];
        }
        else
        {
            ERROR("[ERROR] Someone forgot to add a case here? Instruction: %s\n", Instrux->Mnemonic);
            return INT_STATUS_NOT_SUPPORTED;
        }

        finalValue.Size = val1.Size;

        // We have to set the flags
        IntDecSetFlags(finalValue.Value.QwordValues[0], val1.Value.QwordValues[0],
                       srcValue.Value.QwordValues[0], finalValue.Size, regs, FM_LOGIC);

        break;
    }

    case ND_INS_MOVDQA:
    case ND_INS_MOVDQU:
    case ND_INS_MOVAPS:
    {
        // Loads the first operand with the value from the second
        // Intel SDM specifies that when the MOVAPS source operand is a memory, it must be aligned on a 16- or 32- or
        // 64-byte boundary, or a #GP will be generated. But since we are treating an EPT violation caused by this
        // instruction we know that it could not generate a #GP, so there's no need to check for alignment here
        // and inject a #GP in guest
        DWORD dstSize = Instrux->Operands[0].Size;

        if (!hasSrc)
        {
            status = IntGetValueFromOperand(Instrux, 1, regs, NULL, &srcValue);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
                return status;
            }
        }

        // Nothing else to do, except set the operand value (which is done after the switch)
        memcpy(finalValue.Value.ByteValues, srcValue.Value.ByteValues, srcValue.Size);
        // The actual size we have to set is the size of the destination
        finalValue.Size = dstSize;

        break;
    }

    case ND_INS_VMOVDQU:
    {
        if (!hasSrc)
        {
            status = IntGetValueFromOperand(Instrux, 1, regs, NULL, &srcValue);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
                return status;
            }
        }

        if (ND_ENCM_VEX == Instrux->EncMode)
        {
            // DEST[255:0] <- SRC[255:0] or DEST[128:0] <- SRC[128:0]
            // DEST[MAXVL-1:256] <- 0    or DEST[MAXVL-1:128] <- 0
            ND_OPERAND_SIZE maxvl;
            status = IntDecGetMaxvl(&maxvl);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecGetMaxvl failed: 0x%08x\n", status);
                return status;
            }

            // finalValue is already zeroed

            memcpy(finalValue.Value.ByteValues, srcValue.Value.ByteValues, srcValue.Size);
            finalValue.Size = maxvl;
        }
        else
        {
            status = INT_STATUS_NOT_SUPPORTED;
        }

        break;
    }

    default:
        ERROR("[ERROR] Unsupported instruction: %s!\n", Instrux->Mnemonic);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (!INT_SUCCESS(status))
    {
        return status;
    }

    for (SIZE_T i = 0; i < PAGE_COUNT_4K(gVcpu->Gla, gVcpu->AccessSize); i++)
    {
        QWORD gla = gVcpu->Gla + (i * PAGE_SIZE_4K);
        status = IntDecEmulatePageWalk(gla, gVcpu->Regs.Cr3, PW_FLAGS_SET_A);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecEmulatePageWalk failed for 0x%016llx: 0x%08x\n", gla, status);
            return status;
        }
    }

    regs->Rip += Instrux->Length;
    status = IntSetGprs(IG_CURRENT_VCPU, regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        return status;
    }

    // Set the value
    status = IntSetValueForOperand(Instrux, 0, regs, &finalValue, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetValueForOperand failed: 0x%08x\n", status);

        // Restore RIP
        regs->Rip -= Instrux->Length;
        status = IntSetGprs(IG_CURRENT_VCPU, regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
            // This is bad. We can't really continue, as the guest is now in an unstable state: the instruction was not
            // emulated, but the RIP points to the next instruction. Even if we switch the order of operations:
            /// set the operand value, then update the RIP, we will still have the same problem, only in reverse:
            /// we may end up with the instruction being emulated, but the RIP still pointing to it
            IntBugCheck();
        }

        return status;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecGetWrittenValueFromInstruction(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_opt_ PBYTE MemoryValue,
    _Out_ OPERAND_VALUE *WrittenValue
    )
///
/// @brief Decode a written value from a memory write instruction.
///
/// Get the written value from an INSTRUX. It only supports a basic set of instructions (MOV, STOSB, MOVSB, XCHG, ADD,
/// XOR, etc.).
/// WrittenValue will always contain the value that will be written in the destination operand.
/// For instructions that write to more than one operand (XCHG, XADD, etc), the value written to the memory operand
/// will be returned.
/// For CMPXCHG, CMPXCHG8B and CMPXCHG16B the return value is computed based on the compare result.
/// No checks are made on WrittenValue size. The caller should allocate enough for the largest possible operand size.
/// For now, the only supported instruction for which more than a QWORD is needed is CMPXCHG16B (2 QWORDs)
///
/// @param[in]  Instrux         The decoded instruction.
/// @param[in]  Registers       Optional pointer to the general purpose registers state.
/// @param[in]  MemoryValue     Optional parameter to an already mapped memory region containing the memory operand.
/// @param[out] WrittenValue    Will contain, upon successful return, the written value to memory.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If an unsupported instruction is provided.
///
{
    INTSTATUS status = INT_STATUS_UNSUCCESSFUL;
    IG_ARCH_REGS regs;
    OPERAND_VALUE writtenValue = { 0 };
    QWORD value;
    BOOLEAN bComputeResult = FALSE;
    OPERAND_VALUE value1 = { 0 };
    OPERAND_VALUE value2 = { 0 };

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == WrittenValue)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    // If the caller didn't pass any, then read from the current VCPU.
    if (NULL == Registers)
    {
        status = IntGetGprs(IG_CURRENT_VCPU, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
            return status;
        }

        Registers = &regs;
    }

    // each instruction is unique and special
    switch (Instrux->Instruction)
    {
    // all we need is the second operand, simple
    case ND_INS_MOV:
    case ND_INS_STOS:
    case ND_INS_MOVS:
    case ND_INS_MOVNTI:
    case ND_INS_MOVZX:
        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        break;

    case ND_INS_MOVSX:
    case ND_INS_MOVSXD:
        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &value1);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        bComputeResult = TRUE;

        break;

    case ND_INS_XCHG:
        if (ND_OP_MEM == Instrux->Operands[1].Type)
        {
            // get the value from the first operand
            status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &writtenValue);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }
        }
        else
        {
            // get the value from the second operand
            status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &writtenValue);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }
        }

        break;

    case ND_INS_CMPXCHG:
        // Compares the value in the AL, AX, EAX, or RAX register with the first operand (destination operand).
        // If the two values are equal, the second operand (source operand) is loaded into the destination operand.
        // Otherwise, the destination operand is loaded into the AL, AX, EAX or RAX register.

        // get the value from the destination operand
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &value2);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for CMPXCHG (destination operand) with status: 0x%x\n",
                    status);
            return status;
        }

        value1.Value.QwordValues[0] = ND_TRIM(value2.Size, Registers->Rax);

        if (value1.Value.QwordValues[0] == value2.Value.QwordValues[0])
        {
            // get the value from the source operand
            status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &writtenValue);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for CMPXCHG (source operand) with status: 0x%x\n",
                        status);
                return status;
            }
        }
        else
        {
            // destination remains unchanged
            writtenValue = value2;
        }

        break;

    case ND_INS_CMPXCHG8B:
        // Compares the 64-bit value in EDX:EAX with the operand (destination operand). If the values are equal,
        // the 64-bit value in ECX:EBX is stored in the destination operand.
        // Otherwise, the value in the destination operand is loaded into EDX:EAX.
        // The destination operand is an 8-byte memory location.
        // For the EDX:EAX and ECX:EBX register pairs, EDX and ECX contain the high-order 32 bits and EAX and EBX
        // contain the low-order 32 bits of a 64-bit value.

        // get the value from EDX:EAX
        value1.Value.QwordValues[0] = ((Registers->Rdx & 0xFFFFFFFF) << 32) | (Registers->Rax & 0xFFFFFFFF);

        // get the operand value
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &value2);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for CMPXCHG8B with status: 0x%x\n", status);
            return status;
        }

        // compare them
        if (value1.Value.QwordValues[0] == value2.Value.QwordValues[0])
        {
            // return ECX:EBX
            writtenValue.Value.QwordValues[0] = ((Registers->Rcx & 0xFFFFFFFF) << 32) | (Registers->Rbx & 0xFFFFFFFF);
        }
        else
        {
            // destination remains unchanged
            writtenValue = value2;
        }

        writtenValue.Size = 8;

        break;

    case ND_INS_CMPXCHG16B:
    {
        // Compares the 128-bit value in RDX:RAX with the operand (destination operand). If the values are equal,
        // the 128-bit value in RCX:RBX is stored in the destination operand.
        // Otherwise, the value in the destination operand is loaded into RDX:RAX.
        // The destination operand is a 16-byte memory location.
        // For the RDX:RAX and RCX:RBX register pairs, RDX and RCX contain the high-order 64 bits and RAX and RBX
        // contain the low-order 64bits of a 128-bit value.

        OPERAND_VALUE destinationValue = { 0 };

        // get the operand value
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &destinationValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for CMPXCHG16B with status: 0x%x\n", status);
            return status;
        }

        // compare them
        if ((Registers->Rdx == destinationValue.Value.QwordValues[0]) &&
            (Registers->Rax == destinationValue.Value.QwordValues[1]))
        {
            WrittenValue->Value.QwordValues[0] = Registers->Rcx;
            WrittenValue->Value.QwordValues[1] = Registers->Rbx;
        }
        else
        {
            // destination remains unchanged
            WrittenValue->Value.QwordValues[0] = destinationValue.Value.QwordValues[0];
            WrittenValue->Value.QwordValues[1] = destinationValue.Value.QwordValues[1];
        }

        // return here
        WrittenValue->Size = 16;

        return INT_STATUS_SUCCESS;
    }

    // we need to take values from 2 operands for the next instructions
    case ND_INS_ADD:
    case ND_INS_SUB:
    case ND_INS_ADC:
    case ND_INS_SBB:
    case ND_INS_MUL:
    case ND_INS_DIV:
    case ND_INS_IDIV:
    case ND_INS_AND:
    case ND_INS_OR:
    case ND_INS_XOR:
    case ND_INS_RCL:
    case ND_INS_RCR:
    case ND_INS_ROL:
    case ND_INS_ROR:
    case ND_INS_BTS:
    case ND_INS_BTR:
    case ND_INS_BTC:
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &value1);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &value2);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        bComputeResult = TRUE;

        break;

    case ND_INS_XADD:
        if (ND_OP_MEM == Instrux->Operands[1].Type)
        {
            // get the value from the first operand
            status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &writtenValue);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }
        }
        else
        {
            // written value = operand1 + operand2
            status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &value1);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }

            status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &value2);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }

            bComputeResult = TRUE;
        }

        break;

    // 1 & 2 operands version: value1 = op1 value, value2 = op2 value
    // 3 operands version: value1 = op2 value, value2 = op3 value
    case ND_INS_IMUL:
        if (3 == Instrux->ExpOperandsCount)
        {
            status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &value1);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }

            status = IntGetValueFromOperand(Instrux, 2, Registers, MemoryValue, &value2);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }
        }
        else
        {
            status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &value1);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }

            status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &value2);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                        Instrux->Mnemonic, status);
                return status;
            }
        }

        bComputeResult = TRUE;

        break;

    case ND_INS_INC:
    case ND_INS_DEC:
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &value1);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        value2.Value.QwordValues[0] = 1;
        bComputeResult = TRUE;

        break;

    case ND_INS_NOT:
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        writtenValue.Value.QwordValues[0] = ~writtenValue.Value.QwordValues[0];

        break;

    case ND_INS_NEG:
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        writtenValue.Value.QwordValues[0] = 0 - writtenValue.Value.QwordValues[0];

        break;

    case ND_INS_LIDT:
    case ND_INS_LGDT:
        // don't use IntGetValueFromOperand because that function will try to read data from the memory address
        // we need to return the value that will be written intro IDTR/GDTR
        status = IntDecComputeLinearAddress(Instrux, &Instrux->Operands[0], Registers, &value);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecComputeLinearAddress failed for %s, operand 0: 0x%x\n", Instrux->Mnemonic, status);
            return status;
        }

        writtenValue.Value.QwordValues[0] = value;
        writtenValue.Size = (BYTE)Instrux->Operands[0].Size;

        break;

    case ND_INS_MOVDQU:
    case ND_INS_MOVAPD:
    case ND_INS_MOVAPS:
    case ND_INS_MOVUPD:
    case ND_INS_MOVUPS:
    {
        // Moves 128 bits of packed single-precision floating-point values from the source operand (second operand) to
        // the destination operand (first operand). This instruction can be used to load an XMM register from a 128-bit
        // memory location, to store the contents of an XMM register into a 128-bit memory location, or to move data
        // between two XMM registers.

        // get the operand value
        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, WrittenValue);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed for MOVUPS with status: 0x%x\n", status);
            return status;
        }

        return INT_STATUS_SUCCESS;
    }

    // we get here for cases in which the destination operand is memory and the source operand is a register,
    // in which case dest[31:0] = src[31:0] and dest[mxvl-1:32] = 0
    case ND_INS_MOVSS:
    {
        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        break;
    }

    case ND_INS_MOVHPS:
    case ND_INS_MOVHPD:
    {
        OPERAND_VALUE destinationValue = { 0 };

        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }
        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &destinationValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        WrittenValue->Value.QwordValues[1] = writtenValue.Value.QwordValues[0];
        WrittenValue->Value.QwordValues[0] = destinationValue.Value.QwordValues[0];
        WrittenValue->Size = 16;

        return INT_STATUS_SUCCESS;
    }

    case ND_INS_MOVLPS:
    case ND_INS_MOVLPD:
        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &writtenValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }
        break;

    case ND_INS_ADDPS:
    {
        OPERAND_VALUE source1 = { 0 };
        OPERAND_VALUE source2 = { 0 };

        status = IntGetValueFromOperand(Instrux, 0, Registers, MemoryValue, &source1);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }
        status = IntGetValueFromOperand(Instrux, 1, Registers, MemoryValue, &source2);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntGetValueFromOperand failed for instruction %s with status: 0x%x\n",
                    Instrux->Mnemonic, status);
            return status;
        }

        WrittenValue->Value.DwordValues[0] = source1.Value.DwordValues[0] + source2.Value.DwordValues[0];
        WrittenValue->Value.DwordValues[1] = source1.Value.DwordValues[1] + source2.Value.DwordValues[1];
        WrittenValue->Value.DwordValues[2] = source1.Value.DwordValues[2] + source2.Value.DwordValues[2];
        WrittenValue->Value.DwordValues[3] = source1.Value.DwordValues[3] + source2.Value.DwordValues[3];


        WrittenValue->Size = 16;

        return INT_STATUS_SUCCESS;
    }

    default:
        WARNING("[WARNING] Unsupported instruction: %s\n", Instrux->Mnemonic);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // now that we have the operand values, compute the instruction result (if we need to)
    if (bComputeResult)
    {
        BYTE opSize;

        opSize = (BYTE)Instrux->Operands[0].Size;

        switch (Instrux->Instruction)
        {
        case ND_INS_MOVSX:
        case ND_INS_MOVSXD:
            writtenValue.Value.QwordValues[0] = ND_SIGN_EX(value1.Size, value1.Value.QwordValues[0]);
            break;

        case ND_INS_ADD:
        case ND_INS_INC:  // we have 1 in value2, so we can treat INC as an ADD op1, 1
        case ND_INS_XADD: // temp = src + dest; src = dest; dest = temp; we are interested only in dest's value
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] + value2.Value.QwordValues[0];
            break;

        case ND_INS_SUB:
        case ND_INS_DEC: // we have 1 in value2, so we can treat DEC as an SUB op1, 1
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] - value2.Value.QwordValues[0];
            break;

        case ND_INS_ADC:
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] +
                                                value2.Value.QwordValues[0] +
                                                DEC_GET_FLAG(Registers->Flags, DEC_EFLAG_CF);
            break;

        case ND_INS_SBB:
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] -
                                                (value2.Value.QwordValues[0] +
                                                 DEC_GET_FLAG(Registers->Flags, DEC_EFLAG_CF));
            break;

        case ND_INS_MUL:
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] * value2.Value.QwordValues[0];
            break;

        case ND_INS_IMUL:
        {
            INT64 signedValue1 = (INT64)value1.Value.QwordValues[0];
            INT64 signedValue2 = (INT64)value2.Value.QwordValues[0];

            writtenValue.Value.QwordValues[0] = (QWORD)(signedValue1 * signedValue2);
            break;
        }

        case ND_INS_DIV:
            if (value2.Value.QwordValues[0] != 0)
            {
                writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] / value2.Value.QwordValues[0];
            }
            else
            {
                writtenValue.Value.QwordValues[0] = 0; // or -1 ?
            }
            break;

        case ND_INS_IDIV:
        {
            INT64 signedValue1 = (INT64)value1.Value.QwordValues[0];
            INT64 signedValue2 = (INT64)value2.Value.QwordValues[0];

            if (signedValue2 != 0)
            {
                writtenValue.Value.QwordValues[0] = (QWORD)(signedValue1 / signedValue2);
            }
            else
            {
                writtenValue.Value.QwordValues[0] = 0; // or -1 ?
            }
            break;
        }

        case ND_INS_AND:
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] & value2.Value.QwordValues[0];
            break;

        case ND_INS_OR:
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] | value2.Value.QwordValues[0];
            break;

        case ND_INS_XOR:
            writtenValue.Value.QwordValues[0] = value1.Value.QwordValues[0] ^ value2.Value.QwordValues[0];
            break;

        // see "RCL/RCR/ROL/ROR-Rotate" in Intel SDM 4.2 Instruction Set Reference, N-Z
        case ND_INS_RCL:
        {
            DWORD count = 0;
            BYTE cf = 0;

            if (ND_SIZE_8BIT == opSize)
            {
                count = (DWORD)((value2.Value.QwordValues[0] & 0x1F) % 9);
            }
            else if (ND_SIZE_16BIT == opSize)
            {
                count = (DWORD)((value2.Value.QwordValues[0] & 0x1F) % 17);
            }
            else if (ND_SIZE_32BIT == opSize)
            {
                count = (DWORD)(value2.Value.QwordValues[0] & 0x1F);
            }
            else if (ND_SIZE_64BIT == opSize)
            {
                count = (DWORD)(value2.Value.QwordValues[0] & 0x3F);
            }

            cf = DEC_GET_FLAG(Registers->Flags, DEC_EFLAG_CF);

            while (0 != count)
            {
                BYTE tempCf = ND_MSB(opSize, value1.Value.QwordValues[0]);

                value1.Value.QwordValues[0] = (value1.Value.QwordValues[0] << 1) + cf;

                cf = tempCf;

                count--;
            }

            writtenValue = value1;

            break;
        }

        case ND_INS_RCR:
        {
            DWORD count = 0;
            BYTE cf = 0;

            if (ND_SIZE_8BIT == opSize)
            {
                count = (DWORD)((value2.Value.QwordValues[0] & 0x1F) % 9);
            }
            else if (ND_SIZE_16BIT == opSize)
            {
                count = (DWORD)((value2.Value.QwordValues[0] & 0x1F) % 17);
            }
            else if (ND_SIZE_32BIT == opSize)
            {
                count = (DWORD)(value2.Value.QwordValues[0] & 0x1F);
            }
            else if (ND_SIZE_64BIT == opSize)
            {
                count = (DWORD)(value2.Value.QwordValues[0] & 0x3F);
            }

            cf = DEC_GET_FLAG(Registers->Flags, DEC_EFLAG_CF);

            while (0 != count)
            {
                BYTE tempCf = ND_LSB(opSize, value1.Value.QwordValues[0]);

                value1.Value.QwordValues[0] = (value1.Value.QwordValues[0] >> 1) + ((QWORD)cf << ((opSize * 8) - 1));

                cf = tempCf;

                count--;
            }

            writtenValue = value1;

            break;
        }

        case ND_INS_ROL:
            writtenValue.Value.QwordValues[0] = (value1.Value.QwordValues[0] << value2.Value.QwordValues[0]) |
                                                (value1.Value.QwordValues[0] >> ((opSize * 8ull) -
                                                                                 value2.Value.QwordValues[0]));

            break;

        case ND_INS_ROR:
            writtenValue.Value.QwordValues[0] = (value1.Value.QwordValues[0] >> value2.Value.QwordValues[0]) |
                                                (value1.Value.QwordValues[0] << ((opSize * 8ull) -
                                                                                 value2.Value.QwordValues[0]));

            break;

        case ND_INS_BTS:
            writtenValue.Value.QwordValues[0] = (value1.Value.QwordValues[0] | (1ULL << (value2.Value.QwordValues[0] %
                                                                                         (opSize * 8ull))));

            break;

        case ND_INS_BTR:
            writtenValue.Value.QwordValues[0] = (value1.Value.QwordValues[0] & ~(1ULL << (value2.Value.QwordValues[0] %
                                                                                          (opSize * 8ull))));

            break;

        case ND_INS_BTC:
            writtenValue.Value.QwordValues[0] = (value1.Value.QwordValues[0] ^ (1ULL << (value2.Value.QwordValues[0] %
                                                                                         (opSize * 8ull))));

            break;

        // this should never happen
        default:
            WARNING("[WARNING] Unsupported instruction: %s\n", Instrux->Mnemonic);
            return INT_STATUS_NOT_SUPPORTED;
        }

        writtenValue.Size = opSize;
    }

    *WrittenValue = writtenValue;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecEmulateInstruction(
    _In_ DWORD CpuNumber,
    _In_ PINSTRUX Instrux
    )
///
/// @brief Emulate a MOV or a PUSH instruction.
///
/// This function emulates the instruction currently pointed by RIP on the provided CpuNumber. It is intended to be
/// used only by detours handlers, and, as such, it only supports two instructions: PUSH and MOV. This function should
/// not be called outside a direct detour handler.
///
/// @param[in]  CpuNumber   The CPU context (should be #IG_CURRENT_VCPU).
/// @param[in]  Instrux     The decoded instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If an unsupported instruction is provided.
///
{
    INTSTATUS status;
    IG_ARCH_REGS regs;
    OPERAND_VALUE value = { 0 };

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntGetGprs(CpuNumber, &regs);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetGprs failed: 0x%08x\n", status);
        return status;
    }

    if (ND_INS_PUSH == Instrux->Instruction)
    {
        status = IntGetValueFromOperand(Instrux, 0, &regs, NULL, &value);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            return status;
        }

        status = IntSetValueForOperand(Instrux, 1, &regs, &value, TRUE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetValueForOperand failed: 0x%08x\n", status);
            return status;
        }
    }
    else if (ND_INS_MOV == Instrux->Instruction)
    {
        status = IntGetValueFromOperand(Instrux, 1, &regs, NULL, &value);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            return status;
        }

        status = IntSetValueForOperand(Instrux, 0, &regs, &value, TRUE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetValueForOperand failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (INT_SUCCESS(status))
    {
        regs.Rip += Instrux->Length;

        status = IntSetGprs(CpuNumber, &regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        }
    }

    return status;
}


static __forceinline QWORD
IntDecAtomicStore(
    _In_ void *Address,
    _In_ DWORD Size,
    _In_ QWORD New,
    _In_ QWORD Old
    )
///
/// @brief Atomically store a value in memory.
///
/// Atomically store a value in memory. Returns the actual memory value. If it is different from Old, New has not been
/// stored in memory.
///
/// @param[in]  Address Memory addresses where to atomic store will be made.
/// @param[in]  Size    Store size, in bytes.
/// @param[in]  New     The new value to be stored in memory.
/// @param[in]  Old     The old value present in memory.
///
/// @return The actual memory value. If the return value != Old, the store has not been made.
///
{
    if (8 == Size)
    {
        return (QWORD)_InterlockedCompareExchange64(Address, New, Old);
    }
    else if (4 == Size)
    {
        return (DWORD)_InterlockedCompareExchange(Address, New, Old);
    }
    else if (2 == Size)
    {
        return (WORD)_InterlockedCompareExchange16(Address, New, Old);
    }
    else
    {
        return (BYTE)_InterlockedCompareExchange8(Address, New, Old);
    }
}


INTSTATUS
IntDecEmulatePTWrite(
    _Out_ QWORD *NewValue
    )
///
/// @brief Emulate a page-table write.
///
/// Fast Page Table write emulator. This function makes some strong assumptions:
/// - since this is a PT memory write, there is no need to make PT validations - we operate directly on physical memory;
/// - since this is a PT memory write, there is no need to set A/D bits inside self-mapping PTs;
/// - the instruction has been cached internally, so modifying it from another CPU will not affect us;
/// - only the most common PT modifying instructions are supported (MOV, CMPXCHG, AND); all other will be emulated;
/// - the written size must not exceed 8 bytes;
/// - the instruction stores to memory;
/// This function operates on the context of the current VCPU, and assumes the current instruction, pointed by RIP, is
/// the one making the page-table entry modification.
///
/// @param[out] NewValue    The new value stored inside the page-table entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter has been supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If the instruction is not supported.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD gpa = 0, gla = 0, oldval = 0, newval = 0, actval = 0;
    DWORD pto = 0, size = 0;
    PBYTE pPage;
    OPERAND_VALUE src = { 0 };
    OPERAND_VALUE dst = { 0 };
    IG_ARCH_REGS shRegs;
    INSTRUX *instrux;

    if (NULL == NewValue)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    gpa = gVcpu->Gpa;
    gla = gVcpu->Gla;
    instrux = &gVcpu->Instruction;

    // Make sure this instruction does in fact a memory write.
    if (instrux->Operands[0].Type != ND_OP_MEM)
    {
        ERROR("[ERROR] First operand is not memory for PT instruction, type is %d!\n", instrux->Operands[0].Type);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (instrux->Operands[0].Size > 8)
    {
        ERROR("[ERROR] First operand is greater than 8 bytes in size, size is %d!\n", instrux->Operands[0].Size);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // The page table offset.
    pto = gpa & PAGE_OFFSET;

    // The memory access size. The memory is the first operand (checked above).
    size = instrux->Operands[0].Size;

    if (pto + size > PAGE_SIZE)
    {
        ERROR("[ERROR] Access spans outside the page: offset 0x%x, size %d!\n", pto, size);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // Get a reference to the actual PTE, so we can atomically make the modification.
    status = IntGpaCacheFindAndAdd(gGuest.GpaCache, gpa, &pPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheFetchAndAdd failed for GPA 0x%016llx, GLA 0x%016llx: 0x%08x\n", gpa, gla, status);
        return status;
    }

_retry_emulation:
    // We need to operate on a local copy of the registers until we can commit the modified regs. Note that if we retry
    // an emulation, the shadow regs state will be overwritten with the unmodified registers stored in VCPU, so we start
    // from scratch, basically.
    memcpy(&shRegs, &gVcpu->Regs, sizeof(IG_ARCH_REGS));

    // Fetch the old value from the PTE.
    oldval = (size == 8) ? *((QWORD *)(pPage + pto))
             : (size == 4) ? *((DWORD *)(pPage + pto))
             : (size == 2) ? *((WORD *)(pPage + pto))
             : *((BYTE *)(pPage + pto));

    // We support only a small subset of PT accessing instructions - the most common. All the rest will be emulated
    // by the hypervisor/integrator emulator or will be single-stepped.
    switch (instrux->Instruction)
    {
    case ND_INS_MOV:
    case ND_INS_STOS:
    {
        // Fetch the source.
        status = IntGetValueFromOperand(instrux, 1, &shRegs, NULL, &src);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // The new value is the instruction source operand.
        newval = ND_TRIM(src.Size, src.Value.QwordValues[0]);

        actval = IntDecAtomicStore(pPage + pto, size, newval, oldval);

        // Actual value in memory is not the same as the known old value - retry.
        if (actval != oldval)
        {
            goto _retry_emulation;
        }

        *NewValue = newval;
    }
    break;

    case ND_INS_XCHG:
    {
        // Fetch the source.
        status = IntGetValueFromOperand(instrux, 1, &shRegs, NULL, &src);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // The destination operand will be stored inside the source operand, and the source operand will be stored
        // in memory.
        dst.Size = (BYTE)size;
        dst.Value.QwordValues[0] = oldval;

        // Store the source. We know it's a register, so it's ok to do it without commit.
        status = IntSetValueForOperand(instrux, 1, &shRegs, &dst, FALSE);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetValueForOperand failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // The new value is the source operand.
        newval = src.Value.QwordValues[0];

        // Write the destination.
        actval = IntDecAtomicStore(pPage + pto, size, newval, oldval);

        // Actual value in memory is not the same as the known old value - retry.
        if (actval != oldval)
        {
            goto _retry_emulation;
        }

        *NewValue = newval;
    }
    break;

    case ND_INS_CMPXCHG:
    {
        QWORD rax;

        // Fetch the source.
        status = IntGetValueFromOperand(instrux, 1, &shRegs, NULL, &src);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // EAX/RAX is compared to the memory value. If they're equal, the source value is loaded in memory.
        // Otherwise, the memory value is loaded in EAX/RAX.
        rax = ND_TRIM(size, shRegs.Rax);

        // The (tentative) new value is the source operand.
        newval = src.Value.QwordValues[0];

        // Atomically handle the CMPXCHG operation.
        actval = IntDecAtomicStore(pPage + pto, size, newval, rax);

        IntDecSetFlags(rax - actval, rax, actval, src.Size, &shRegs, FM_SUB);

        // Note that we don't retry emulation on CMPXCHG; we simply set the flags and move on.
        if (actval == rax)
        {
            // Values equal, the exchange was made, the new value is the source operand.
            *NewValue = newval;
        }
        else
        {
            // The exchange wasn't made, the value is not changed.
            if ((src.Size == 4) && (ND_CODE_64 == instrux->DefCode))
            {
                shRegs.Rax = 0;
            }

            // Values are not equal, load the destination into the accumulator.
            memcpy(&shRegs.Rax, &actval, src.Size);

            *NewValue = actval;
        }
    }
    break;

    case ND_INS_CMPXCHG8B:
    {
        QWORD edx_eax;

        // The size is 8 bytes. We compare EDX:EAX and store ECX:EBX if ZF.
        edx_eax = ((shRegs.Rdx & 0xFFFFFFFF) << 32) | (shRegs.Rax & 0xFFFFFFFF);

        // The (tentative) new value is the ECX:EBX pair.
        newval = ((shRegs.Rcx & 0xFFFFFFFF) << 32) | (shRegs.Rbx & 0xFFFFFFFF);

        actval = _InterlockedCompareExchange64((INT64 *)(pPage + pto), newval, edx_eax);

        if (actval == edx_eax)
        {
            // Values equal, the exchange was made, the new value is the source operand.
            shRegs.Flags |= CPU_EFLAGS_ZF;

            *NewValue = newval;
        }
        else
        {
            // The exchange wasn't made, the value is not changed.
            shRegs.Flags &= ~CPU_EFLAGS_ZF;

            shRegs.Rdx = (actval >> 32) & 0xFFFFFFFF;
            shRegs.Rax = (actval & 0xFFFFFFFF);

            *NewValue = actval;
        }
    }
    break;

    case ND_INS_AND:
    case ND_INS_XOR:
    case ND_INS_OR:
    {
        QWORD res;

        // Fetch the source.
        status = IntGetValueFromOperand(instrux, 1, &shRegs, NULL, &src);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // Fetch the current memory value. We know the size of both operands will be the same!
        dst.Size = (BYTE)size;
        dst.Value.QwordValues[0] = oldval;

        res = (ND_INS_AND == instrux->Instruction) ? (dst.Value.QwordValues[0] & src.Value.QwordValues[0])
              : (ND_INS_XOR == instrux->Instruction) ? (dst.Value.QwordValues[0] ^ src.Value.QwordValues[0])
              : (dst.Value.QwordValues[0] | src.Value.QwordValues[0]);

        IntDecSetFlags(res, dst.Value.QwordValues[0], src.Value.QwordValues[0], src.Size, &shRegs, FM_LOGIC);

        // The new value is the AND/XOR/OR between the source operand and the old memory value (the destination).
        newval = res;

        // Write the destination.
        actval = IntDecAtomicStore(pPage + pto, size, newval, oldval);

        // Actual value in memory is not the same as the known old value - retry.
        if (actval != oldval)
        {
            goto _retry_emulation;
        }

        *NewValue = newval;
    }
    break;

    case ND_INS_BTC:
    case ND_INS_BTR:
    case ND_INS_BTS:
    {
        QWORD btgla, mask;

        // Compute the linear address encoded in the instruction.
        status = IntDecComputeLinearAddress(instrux, &instrux->Operands[0], &shRegs, &btgla);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecComputeLinearAddress failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // BT* instructions have bitbase addressing, so make sure the encoded gla is the same as the faulted gla.
        if (btgla != gVcpu->Gla)
        {
            TRACE("[PTEMU] GLA mismatch: 0x%016llx - 0x%016llx, will not emulate.\n", btgla, gVcpu->Gla);
            status = INT_STATUS_NOT_SUPPORTED;
            goto cleanup_and_exit;
        }

        // Get the bit offset.
        status = IntGetValueFromOperand(instrux, 1, &shRegs, NULL, &src);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetValueFromOperand failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // If the source operand is immediate, the bit offset is truncated to the max destination size.
        if (instrux->Operands[1].Type == ND_OP_IMM)
        {
            src.Value.QwordValues[0] %= instrux->Operands[0].Size * 8ull;
        }

        if (src.Value.QwordValues[0] >= instrux->Operands[0].Size * 8ull)
        {
            TRACE("[PTEMU] Bit offset to high: %llu\n", src.Value.QwordValues[0]);
            status = INT_STATUS_NOT_SUPPORTED;
            goto cleanup_and_exit;
        }

        mask = 1ULL << src.Value.QwordValues[0];

        dst.Size = (BYTE)size;
        dst.Value.QwordValues[0] = oldval;

        // Set/clear the CF.
        if (dst.Value.QwordValues[0] & mask)
        {
            shRegs.Flags |= CPU_EFLAGS_CF;
        }
        else
        {
            shRegs.Flags &= ~CPU_EFLAGS_CF;
        }

        // Set/clear/complement the bit.
        dst.Value.QwordValues[0] = (ND_INS_BTS == instrux->Instruction) ? (dst.Value.QwordValues[0] | mask)
                                   : (ND_INS_BTR == instrux->Instruction) ? (dst.Value.QwordValues[0] & ~mask)
                                   : (dst.Value.QwordValues[0] ^ mask);

        // The new value is the old memory value (destination operand) with the modified bit.
        newval = dst.Value.QwordValues[0];

        // Write the destination.
        actval = IntDecAtomicStore(pPage + pto, size, newval, oldval);

        // Actual value in memory is not the same as the known old value - retry.
        if (actval != oldval)
        {
            goto _retry_emulation;
        }

        *NewValue = newval;
    }
    break;

    default:
    {
        char text[ND_MIN_BUF_SIZE];

        NdToText(instrux, shRegs.Rip, ND_MIN_BUF_SIZE, text);

        ERROR("[ERROR] Instruction 0x%016llx:'%s' not supported, writing at GLA %llx, GPA %llx.\n",
              shRegs.Rip, text, gla, gpa);
        status = INT_STATUS_NOT_SUPPORTED;
        goto cleanup_and_exit;
    }
    }

cleanup_and_exit:
    if (INT_SUCCESS(status))
    {
        // In case of success, advance the RIP & commit the registers state.
        shRegs.Rip += instrux->Length;

        status = IntSetGprs(gVcpu->Index, &shRegs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        }
        else
        {
            memcpy(&gVcpu->Regs, &shRegs, sizeof(IG_ARCH_REGS));
        }
    }

    // Release the mapped PT.
    IntGpaCacheRelease(gGuest.GpaCache, gpa);

    return status;
}


INTSTATUS
IntDecGetAccessedMemCount(
    _In_ PINSTRUX Instrux,
    _Out_ DWORD *Count
    )
///
/// @brief Decode the number of memory locations accessed by an instruction.
///
/// Given the decoded instruction, this function will return in Count the number of memory locations accessed
/// by this instruction. There may be cases where an instruction accesses multiple locations - for example,
/// POP [mem] will read the from the memory (stack) and it will store to the provided mem address. Another
/// example includes instructions with VSIB addressing, which may access up to 16 different locations.
///
/// @param[in]  Instrux     The decoded instruction.
/// @param[out] Count       The number of memory locations accessed by the instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    DWORD i, count;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Count)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    count = 0;

    for (i = 0; i < Instrux->OperandsCount; i++)
    {
        // Ignore shadow stack - no CPUs support it for now.
        if ((Instrux->Operands[i].Type == ND_OP_MEM) && (!Instrux->Operands[i].Info.Memory.IsShadowStack))
        {
            // VSIB will lead to several memory accesses to be made.
            count += Instrux->Operands[i].Info.Memory.IsVsib ? Instrux->Operands[i].Info.Memory.Vsib.ElemCount : 1;
        }
    }

    *Count = count;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecGetAccessedMem(
    _In_ PINSTRUX Instrux,
    _In_opt_ PIG_ARCH_REGS Registers,
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _Out_writes_(*Count) MEMADDR *Gla,
    _Inout_ DWORD *Count
    )
///
/// @brief Decode each accessed address by an instruction.
///
/// Given an instruction, it computes every accessed linear address. It assumes the caller has already allocated enough
/// storage space inside Gla.
///
/// @param[in]  Instrux     The decoded instruction.
/// @param[in]  Registers   Optional pointer to the general purpose registers state.
/// @param[in]  XsaveArea   Optional pointer to the XSAVE area.
/// @param[out] Gla         Pointer to an array that will contain, upon return, each accessed Gla.
/// @param[in, out] Count   On function entry, contains the number of slots available inside Gla. On return, it contains
///                         the actual number of entries stored in Gla array.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_DATA_BUFFER_TOO_SMALL If the Gla array is too small.
///
{
    INTSTATUS status;
    IG_ARCH_REGS regs;
    DWORD i, count;

    if (NULL == Instrux)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Registers)
    {
        status = IntGetGprs(IG_CURRENT_VCPU, &regs);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        Registers = &regs;
    }

    if (NULL == Gla)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    count = 0;

    for (i = 0; i < Instrux->OperandsCount; i++)
    {
        if (Instrux->Operands[i].Type == ND_OP_MEM)
        {
            if (Instrux->Operands[i].Info.Memory.IsShadowStack)
            {
                continue;
            }

            if (count >= *Count)
            {
                return INT_STATUS_DATA_BUFFER_TOO_SMALL;
            }

            // Special handling for VSIB addressing.
            if (Instrux->Operands[i].Info.Memory.IsVsib)
            {
                // There can't be more than 16 accessed locations (ZMM size / DWORD = 16)
                QWORD vsibglas[16] = { 0 }, j = 0;

                if (Instrux->Operands[i].Info.Memory.Vsib.ElemCount > 16)
                {
                    ERROR("[ERROR] Too many VSIB elements accessed: %d\n",
                          Instrux->Operands[i].Info.Memory.Vsib.ElemCount);
                    continue;
                }

                status = IntDecComputeVsibLinearAddresses(Instrux, &Instrux->Operands[i],
                                                          Registers, XsaveArea, vsibglas);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntDecComputeVsibLinearAddresses failed: 0x%08x\n", status);
                    continue;
                }

                for (j = 0; j < Instrux->Operands[i].Info.Memory.Vsib.ElemCount; j++)
                {
                    if (count >= *Count)
                    {
                        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
                    }

                    Gla[count].Access = Instrux->Operands[i].Access.Access;
                    Gla[count].Size = Instrux->Operands[i].Info.Memory.Vsib.ElemSize;
                    Gla[count].Gla = vsibglas[j];

                    count++;
                }
            }
            else
            {
                status = IntDecComputeLinearAddress(Instrux, &Instrux->Operands[i], Registers, &Gla[count].Gla);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntDecComputeLinearAddress failed at op %d: 0x%08x", i, status);
                    continue;
                }

                status = IntDecDecodeOperandSize(Instrux, &Instrux->Operands[i], Registers, &Gla[count].Size);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntDecDecodeOperandSize failed: 0x%08x\n", status);
                    continue;
                }

                Gla[count].Access = Instrux->Operands[i].Access.Access;

                count++;
            }
        }
    }

    *Count = count;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntDecGetSetSseRegValue(
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _In_ DWORD Reg,
    _In_ DWORD Size,
    _When_(Set == TRUE, _In_) _When_(Set == FALSE, _Out_) OPERAND_VALUE *Value,
    _In_ BOOLEAN Set,
    _In_ BOOLEAN Commit
    )
///
/// @brief Gets or sets the value of a vector register.
///
/// @param[in]      XsaveArea   Optional XSAVE area. If NULL, it will be queried internally.
/// @param[in]      Reg         The vector register to be accessed.
/// @param[in]      Size        The size to return/set in the vector register.
/// @param[in, out] Value       The value of the vector register.
/// @param[in]      Set         If true, the vector register will be modified. Otherwise, it will return the vector
///                             register value.
/// @param[in]      Commit      If true, the vector registers state will be committed (use only if Set is true).
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If memory could not be allocated for the XSAVE area.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If an invalid register is specified (for example, XMM8 outside long-mode).
///
{
    INTSTATUS status;
    IG_XSAVE_AREA *xsave;
    XSAVE_AREA xa = { 0 };
    int cpuidregs[4];

    if (NULL == Value)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == XsaveArea)
    {
        // This may fail if the needed function is not implemented in Xen libs.
        status = IntGetXsaveArea(IG_CURRENT_VCPU, &xa);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetXsaveArea failed: 0x%08x\n", status);
            return status;
        }
    }
    else
    {
        xa.XsaveArea = XsaveArea;
    }

    xsave = xa.XsaveArea;

    // The XSAVE area format (the interesting parts, at least):
    // 0: FPU stuff
    //    MM0 .. MM7/ST0 .. ST7
    // 1: XMM0 .. XMM15
    //    XSAVE extended header
    // 2: YMM0_Hi .. YMM15_Hi (bits 128:255 of each YMM register; bits 0:127 are the same as XMM0 .. XMM15)
    // 3: MPX state
    // 5: AVX512 mask registers
    // 6: ZMM0_Hi .. ZMM15_Hi (bits 256:511 of ZMM0 .. ZMM15 registers; bits 128:255 are the same as YMM0_Hi.. YMM15_Hi,
    //                         bits 0:127 are the same as XMM0 .. XMM15)
    // 7: ZMM16 .. ZMM31
    // ...
    // In order to get the offset of a given state, we need to execute CPUID.(EAX=0DH,ECX=x), where x is the desired
    // state (1 - XMM, 2 - YMM, 7 - ZMM, etc.)

    if (ND_SIZE_64BIT == Size)
    {
        // MMX register requested.
        if (Reg >= ND_MAX_MMX_REGS)
        {
            status = INT_STATUS_INVALID_PARAMETER_3;
            goto cleanup_and_exit;
        }

        if (Set)
        {
            memcpy(&xsave->Mm0 + Reg, Value->Value.QwordValues, ND_SIZE_64BIT);
        }
        else
        {
            memcpy(Value->Value.QwordValues, &xsave->Mm0 + Reg, ND_SIZE_64BIT);
        }
    }
    else
    {
        // SSE register requested. Copy the content, chunk by chunk.
        if (Reg >= ND_MAX_SSE_REGS)
        {
            status = INT_STATUS_INVALID_PARAMETER_3;
            goto cleanup_and_exit;
        }

        if (!gGuest.Guest64 && Reg >= 8)
        {
            // Outside 64-bit mode, only registers 0-7 can be accessed
            status = INT_STATUS_NOT_SUPPORTED;
            goto cleanup_and_exit;
        }

        // Handle XMM register access.
        if (ND_SIZE_128BIT <= Size)
        {
            if (Reg < 16)
            {
                // XMM0 - XMM15 accessed, we can copy the content directly.
                if (Set)
                {
                    memcpy(&xsave->Xmm0 + Reg, Value->Value.QwordValues, ND_SIZE_128BIT);
                }
                else
                {
                    memcpy(Value->Value.QwordValues, &xsave->Xmm0 + Reg, ND_SIZE_128BIT);
                }
            }
            else
            {
                // XMM16 - XMM31 accessed. Get the offset of the Hi_ZMM16 - Hi_ZMM31, that contains the XMM16 .. XMM31
                // registers, and copy the low 128 bit.
                __cpuidex(cpuidregs, 0xD, 0x7);

                if (0 != cpuidregs[1])
                {
                    if (Set)
                    {
                        memcpy((PBYTE)xsave + cpuidregs[1] + (Reg - 16) * 64ull,
                               Value->Value.QwordValues,
                               ND_SIZE_128BIT);
                    }
                    else
                    {
                        memcpy(Value->Value.QwordValues,
                               (PBYTE)xsave + cpuidregs[1] + (Reg - 16) * 64ull,
                               ND_SIZE_128BIT);
                    }
                }
                else
                {
                    status = INT_STATUS_NOT_SUPPORTED;
                    goto cleanup_and_exit;
                }
            }
        }

        // Handle YMM register access.
        if (ND_SIZE_256BIT <= Size)
        {
            if (Reg < 16)
            {
                // Get the offset of the YMM0_Hi - YMM15_Hi, that contains the high portion of the YMM registers.
                __cpuidex(cpuidregs, 0xD, 0x2);

                if (0 != cpuidregs[1])
                {
                    if (Set)
                    {
                        memcpy((PBYTE)xsave + cpuidregs[1] + Reg * 16ull, Value->Value.ByteValues + 16, ND_SIZE_128BIT);
                    }
                    else
                    {
                        memcpy(Value->Value.ByteValues + 16, (PBYTE)xsave + cpuidregs[1] + Reg * 16ull, ND_SIZE_128BIT);
                    }
                }
                else
                {
                    status = INT_STATUS_NOT_SUPPORTED;
                    goto cleanup_and_exit;
                }
            }
            else
            {
                // Get the offset of the Hi16_ZMM16 - Hi16_ZMM31, that contain the YMM16-YMM31 registers.
                __cpuidex(cpuidregs, 0xD, 0x7);

                if (0 != cpuidregs[1])
                {
                    if (Set)
                    {
                        memcpy((PBYTE)xsave + cpuidregs[1] + (Reg - 16) * 64ull + 16,
                               Value->Value.ByteValues + 16, ND_SIZE_128BIT);
                    }
                    else
                    {
                        memcpy(Value->Value.ByteValues + 16,
                               (PBYTE)xsave + cpuidregs[1] + (Reg - 16) * 64ull + 16, ND_SIZE_128BIT);
                    }
                }
                else
                {
                    status = INT_STATUS_NOT_SUPPORTED;
                    goto cleanup_and_exit;
                }
            }
        }

        // Handle ZMM register access.
        if (ND_SIZE_512BIT <= Size)
        {
            if (Reg < 16)
            {
                // Get the offset of the ZMM0_Hi - ZMM15_Hi, that contains the high part of ZMM0 - ZMM15 registers.
                __cpuidex(cpuidregs, 0xD, 0x6);

                if (0 != cpuidregs[1])
                {
                    if (Set)
                    {
                        memcpy((PBYTE)xsave + cpuidregs[1] + Reg * 32ull, Value->Value.ByteValues + 32, ND_SIZE_256BIT);
                    }
                    else
                    {
                        memcpy(Value->Value.ByteValues + 32, (PBYTE)xsave + cpuidregs[1] + Reg * 32ull, ND_SIZE_256BIT);
                    }
                }
                else
                {
                    status = INT_STATUS_NOT_SUPPORTED;
                    goto cleanup_and_exit;
                }
            }
            else
            {
                // Get the offset of the Hi16_ZMM, that contains the high ZMM registers.
                __cpuidex(cpuidregs, 0xD, 0x7);

                if (0 != cpuidregs[1])
                {
                    if (Set)
                    {
                        memcpy((PBYTE)xsave + cpuidregs[1] + (Reg - 16) * 64ull + 32,
                               Value->Value.ByteValues + 32, ND_SIZE_256BIT);
                    }
                    else
                    {
                        memcpy(Value->Value.ByteValues + 32,
                               (PBYTE)xsave + cpuidregs[1] + (Reg - 16) * 64ull + 32, ND_SIZE_256BIT);
                    }
                }
                else
                {
                    status = INT_STATUS_NOT_SUPPORTED;
                    goto cleanup_and_exit;
                }
            }
        }
    }

    status = INT_STATUS_SUCCESS;

    if (Commit)
    {
        status = IntSetXsaveArea(IG_CURRENT_VCPU, &xa);
        if (!INT_SUCCESS(status))
        {
            ERROR("IntSetXsaveArea failed: 0x%08x\n", status);
        }
    }

cleanup_and_exit:
    if (xsave != XsaveArea)
    {
        IntFreeXsaveArea(xa);
    }

    return status;
}


INTSTATUS
IntDecGetSseRegValue(
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _In_ DWORD Reg,
    _In_ DWORD Size,
    _Out_ OPERAND_VALUE *Value
    )
///
/// @brief Get the value of a vector register. Wrapper over #IntDecGetSetSseRegValue.
///
/// @param[in]  XsaveArea   Optional XSAVE area. If NULL, it will be queried internally.
/// @param[in]  Reg         The vector register to be accessed.
/// @param[in]  Size        The size to return/set in the vector register.
/// @param[out] Value       The value of the vector register.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If memory could not be allocated for the XSAVE area.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If an invalid register is specified (for example, XMM8 outside long-mode).
///
{
    return IntDecGetSetSseRegValue(XsaveArea, Reg, Size, Value, FALSE, FALSE);
}


INTSTATUS
IntDecSetSseRegValue(
    _In_opt_ PIG_XSAVE_AREA XsaveArea,
    _In_ DWORD Reg,
    _In_ DWORD Size,
    _In_ OPERAND_VALUE *Value,
    _In_ BOOLEAN Commit
    )
///
/// @brief Sets the value of a vector register. Wrapper over #IntDecGetSetSseRegValue.
///
/// @param[in]  XsaveArea   Optional XSAVE area. If NULL, it will be queried internally.
/// @param[in]  Reg         The vector register to be accessed.
/// @param[in]  Size        The size to return/set in the vector register.
/// @param[in]  Value       The value of the vector register.
/// @param[in]  Commit      True if the vector register state must be committed.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If memory could not be allocated for the XSAVE area.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_SUPPORTED If an invalid register is specified (for example, XMM8 outside long-mode).
///
{
    return IntDecGetSetSseRegValue(XsaveArea, Reg, Size, Value, TRUE, Commit);
}


INTSTATUS
IntDecEmulatePageWalk(
    _In_ QWORD Gla,
    _In_ QWORD Cr3,
    _In_ DWORD Flags
    )
///
/// Emulates a page-walk by setting the A and/or D flags inside the required page-table levels. This function will
/// always set the A bit at every level of the page-tables. The D flag will be set if the page is already A, and
/// it has write permissions.
///
/// @param[in]  Gla     The guest linear address for which A/D bits will be set.
/// @param[in]  Cr3     The CR3 used for the translation of Gla.
/// @param[in]  Flags   Contains the page-walk flags: PW_FLAGS_SET_A in order to set the A bit, PW_FLAGS_SET_D in order
///                     to set the D bit.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    VA_TRANSLATION tr;

    status = IntTranslateVirtualAddressEx(Gla, Cr3, 0, &tr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
        return status;
    }

    // Bits 8:5 and 2:1 of the PDPTE are Reserved on x86 PAE.
    // Setting those will cause a #GP on a cr3 switch.
    for (DWORD i = (gGuest.PaeEnabled && !gGuest.Guest64) ? 1 : 0; i < tr.MappingsCount; i++)
    {
        PQWORD p;

        status = IntPhysMemMap(tr.MappingsTrace[i], 8, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed for 0x%016llx: 0x%08x\n", tr.MappingsTrace[i], status);
            return status;
        }

        if ((Flags & PW_FLAGS_SET_A) && (*p & PT_P))
        {
            *p |= PT_A;
        }

        if ((Flags & PW_FLAGS_SET_D) && ((i == tr.MappingsCount - 1) && (*p & PT_A) && (*p & PT_P) && (*p & PT_RW)))
        {
            *p |= PT_D;
        }

        IntPhysMemUnmap(&p);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDecGetMaxvl(
    _Out_ ND_OPERAND_SIZE *Maxvl
    )
///
/// @brief Computes the maximum vector length, given the enabled states inside the XCR0 register.
///
/// @param[out] Maxvl   Contains, upon successful return, the maximum vector length: 128, 256 or 512 bits.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If XCR0 contains an invalid combination of bits.
///
{
    QWORD xcr0;
    INTSTATUS status;

    status = IntGetXcr0(IG_CURRENT_VCPU, &xcr0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (XCR0_AVX_512_STATE == (xcr0 & XCR0_AVX_512_STATE))
    {
        *Maxvl = ND_SIZE_512BIT;
        return INT_STATUS_SUCCESS;
    }

    if (0 != (xcr0 & XCR0_YMM_HI128))
    {
        *Maxvl = ND_SIZE_256BIT;
        return INT_STATUS_SUCCESS;
    }

    if (0 != (xcr0 & XCR0_SSE))
    {
        *Maxvl = ND_SIZE_128BIT;
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}
