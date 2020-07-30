/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "shellcode.h"
#include "introcpu.h"
#include "guests.h"


static void
Shemuprint(
    _In_ PCHAR Data
    )
///
/// @brief Log data.
///
/// @param[in]  Data    Data to be logged.
///
{
    LOG("%s", Data);
}


INTSTATUS
IntShcIsSuspiciousCode(
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ DWORD CsType,
    _In_ IG_ARCH_REGS *Registers,
    _Out_ QWORD *ShellcodeFlags
    )
///
/// @brief Checks if the code located at the given guest virtual address is suspicious or not.
///
/// This function will call the shellcode emulator on the provided memory address. The shellcode emulator
/// looks after the following shellcode indicators:
/// 0. NOP sled;
/// 1. Store RIP in a reg (CALL/POP, FNSTENV/POP, LEA);
/// 2. Write self;
/// 3. Access via FS/GS register inside TEB (used for imports fixup);
/// 4. Direct SYSCALL/SYSENTER invocation;
/// 5. Strings built & referenced on the stack;
/// Some other potential useful indicators (although much weaker and FP prone) are:
/// 6. Branch inside an already executed instruction (CALL $+4, JMP);
/// 7. Weird data transfer sequences (PUSH/POP);
/// 8. Redundant prefixes (especially segment override!);
/// 9. Write ESP (this is done by NaCl for sure...);

/// These are not used, however.
///
/// @param[in]  Gva             Guest virtual address to be emulated.
/// @param[in]  Gpa             Guest physical address to be emulated.
/// @param[in]  CsType          Operating mode, should be 32 or 64 bit mode.
/// @param[in]  Registers       General purpose registers state.
/// @param[in]  ShellcodeFlags  Will contain, upon return, the shellcode flags identified by the shellcode emulator.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
///
{
    INTSTATUS status;
    PSHEMU_CONTEXT ctx;
    SHEMU_STATUS shstatus;
    IG_SEG_REGS segRegisters = { 0 };
    DWORD csType;

    if (0 == Gva)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Gpa)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == ShellcodeFlags)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    // shstatus is not used for release builds as it is inside a TRACE, not a LOG
    UNREFERENCED_PARAMETER(shstatus);

    ctx = &gGuest.Shemucontext;
    memzero(ctx, sizeof(*ctx));
    *ShellcodeFlags = 0;

    // Fill in the context.
    ctx->Shellcode = gGuest.ShemuShellcode;

    ctx->Stack = gGuest.ShemuStack;
    ctx->StackSize = SHEMU_STACK_SIZE;
    ctx->StackBase = (Registers->Rsp & PAGE_MASK) - PAGE_SIZE;
    memzero(ctx->Stack, ctx->StackSize);

    ctx->Intbuf = gGuest.ShemuInternal;
    ctx->IntbufSize = SHEMU_SHELLCODE_SIZE + SHEMU_STACK_SIZE;
    memzero(ctx->Intbuf, ctx->IntbufSize);

    if ((Registers->Rip & PAGE_OFFSET) >= 0xC00)
    {
        DWORD sizeread = 0;

        // The RIP is in the last 1K of the page, we will read the next page as well.
        status = IntVirtMemRead(Registers->Rip & PAGE_MASK, SHEMU_SHELLCODE_SIZE,
                                Registers->Cr3, ctx->Shellcode, &sizeread);
        if (!INT_SUCCESS(status) && (sizeread == 0))
        {
            ERROR("[ERROR] IntVirtMemRead shellcode failed for 0x%016llx : 0x%08x\n", Registers->Rip, status);
            return status;
        }

        ctx->ShellcodeSize = sizeread;
    }
    else
    {
        status = IntPhysicalMemRead(Gpa & PHYS_PAGE_MASK, PAGE_SIZE, ctx->Shellcode, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysicalMemRead shellcode failed for 0x%016llx : 0x%08x\n",
                  Registers->Rip & PAGE_MASK, status);
            return status;
        }

        ctx->ShellcodeSize = 0x1000;
    }

    ctx->ShellcodeBase = Registers->Rip & PAGE_MASK;

    // Read the stack. We don't care if this fails, we can still emulate the buffer with a NULL stack.
    // Note: we don't really need the stack - we can determine whether the code is malicious without it.
    // Anyways, the stack may be read successfully sometimes, and with error some other times.
    ///IntVirtMemRead(Registers->RegRsp & PAGE_MASK, SHEMU_STACK_SIZE, Registers->RegCr3, ctx->Stack, NULL);

    // Get the CS type for this cpu (we need it in order to see if it's in 16 bit, 32 bit or 64 bit).
    if (CsType != IG_CS_TYPE_INVALID)
    {
        csType = CsType;
    }
    else
    {
        status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
            return status;
        }
    }

    ctx->Registers.RegCr0 = Registers->Cr0;
    ctx->Registers.RegCr2 = Registers->Cr2;
    ctx->Registers.RegCr3 = Registers->Cr3;
    ctx->Registers.RegCr4 = Registers->Cr4;

    ctx->Registers.RegFlags = Registers->Flags;
    ctx->Registers.RegRip = Registers->Rip;
    ctx->Registers.RegRsp = Registers->Rsp;

    // Copy the general purpose registers.
    ctx->Registers.RegRax = Registers->Rax;
    ctx->Registers.RegRcx = Registers->Rcx;
    ctx->Registers.RegRdx = Registers->Rdx;
    ctx->Registers.RegRbx = Registers->Rbx;
    ctx->Registers.RegRbp = Registers->Rbp;
    ctx->Registers.RegRsi = Registers->Rsi;
    ctx->Registers.RegRdi = Registers->Rdi;
    ctx->Registers.RegR8 = Registers->R8;
    ctx->Registers.RegR9 = Registers->R9;
    ctx->Registers.RegR10 = Registers->R10;
    ctx->Registers.RegR11 = Registers->R11;
    ctx->Registers.RegR12 = Registers->R12;
    ctx->Registers.RegR13 = Registers->R13;
    ctx->Registers.RegR14 = Registers->R14;
    ctx->Registers.RegR15 = Registers->R15;

    // We don't need segment registers on Linux.
    if (gGuest.OSType == introGuestWindows)
    {
        if (csType == IG_CS_TYPE_64B)
        {
            ctx->Segments.Cs.Selector = 0x33;
            ctx->Segments.Ds.Selector = 0x2b;
            ctx->Segments.Es.Selector = 0x2b;
            ctx->Segments.Ss.Selector = 0x2b;
            ctx->Segments.Fs.Selector = 0x2b;
            ctx->Segments.Gs.Selector = 0x53;

            ctx->Segments.Fs.Base = 0;

            status = IntGsRead(IG_CURRENT_VCPU, &ctx->Segments.Gs.Base);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntGsRead failed: 0x%08x\n", status);
                ctx->Segments.Gs.Base = 0xBDBD0000;
            }

            ctx->TibBase = ctx->Segments.Gs.Base;
        }
        else if (csType == IG_CS_TYPE_32B)
        {
            status = IntGetSegs(IG_CURRENT_VCPU, &segRegisters);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntGetSegs failed: 0x%08x\n", status);
                return status;
            }

            ctx->Segments.Cs.Selector = segRegisters.CsSelector;
            ctx->Segments.Ds.Selector = segRegisters.DsSelector;
            ctx->Segments.Es.Selector = segRegisters.EsSelector;
            ctx->Segments.Ss.Selector = segRegisters.SsSelector;
            ctx->Segments.Fs.Selector = segRegisters.FsSelector;
            ctx->Segments.Gs.Selector = segRegisters.GsSelector;
            ctx->Segments.Fs.Base = segRegisters.FsBase;
            ctx->Segments.Gs.Base = segRegisters.GsBase;

            ctx->TibBase = ctx->Segments.Fs.Base;
        }
        else
        {
            ERROR("[ERROR] We don't support 16 bit!\n");
        }
    }

    ctx->Mode = (csType == IG_CS_TYPE_64B ? ND_CODE_64 : (csType == IG_CS_TYPE_32B ? ND_CODE_32 : ND_CODE_16));
    ctx->Ring = 3; // We only support user-mode shellcode emulation here.
    ctx->MaxInstructionsCount = SHEMU_MAX_INSTRUCTIONS;    // We bail out after 256 instructions.
    // Since we support beta/feedback per shemu flags, we cannot use SHEMU_FLAG_STOP_ON_EXPLOIT; If we do use it,
    // we may end up in a situation where the first set flag, which causes shemu to stop emulation, is marked
    // as feedback only. This way, the detection would be skipped, even if by emulating some more instructions we
    // would get other flags set, which are not feedback only.
    ctx->Options = 0;   
    ctx->Log = Shemuprint;

    // Use the default thresholds.
    ctx->NopThreshold = SHEMU_DEFAULT_NOP_THRESHOLD;
    ctx->StrThreshold = SHEMU_DEFAULT_STR_THRESHOLD;
    ctx->MemThreshold = SHEMU_DEFAULT_MEM_THRESHOLD;

    shstatus = ShemuEmulate(ctx);

    if (gGuest.OSType == introGuestLinux)
    {
        // On Linux we must drop the TIB access flag, it's not relevant
        ctx->Flags &= ~SHEMU_FLAG_TIB_ACCESS;
    }

    if (ctx->Flags != 0)
    {
        TRACE("[SHELLCODE] Emulation terminated with status 0x%08x, flags: 0x%lx, %d NOPs, emulated %d instructions, "
              "RIP %lx.\n", shstatus, ctx->Flags, ctx->NopCount, ctx->InstructionsCount, ctx->Registers.RegRip);
    }

    // Make sure we clear flags that must always be cleared.
    *ShellcodeFlags = ctx->Flags & ~gGuest.ShemuOptions.ForceOff;

    return INT_STATUS_SUCCESS;
}


