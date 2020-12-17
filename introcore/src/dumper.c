/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "dumper.h"
#include "decoder.h"
#include "guests.h"
#include "introcpu.h"
#include "lixprocess.h"
#include "lixksym.h"

///
/// @file dumper.c
///
/// @brief This file implements various functions used to dump (log) code and registers.
///

TIMER_FRIENDLY
__nonnull() void
IntDumpArchRegs(
    _In_ IG_ARCH_REGS const *Registers
    )
///
/// @brief      This function dumps the register values in a user friendly format.
///
/// @param[in]  Registers   The registers to be dumped (must NOT be NULL).
///
{
    LOG("Registers state:\n");

    LOG("RAX = 0x%016llx, RCX = 0x%016llx, RDX = 0x%016llx, RBX = 0x%016llx\n",
        Registers->Rax, Registers->Rcx, Registers->Rdx, Registers->Rbx);
    LOG("RSP = 0x%016llx, RBP = 0x%016llx, RSI = 0x%016llx, RDI = 0x%016llx\n",
        Registers->Rsp, Registers->Rbp, Registers->Rsi, Registers->Rdi);
    LOG("R8  = 0x%016llx, R9  = 0x%016llx, R10 = 0x%016llx, R11 = 0x%016llx\n",
        Registers->R8, Registers->R9, Registers->R10, Registers->R11);
    LOG("R12 = 0x%016llx, R13 = 0x%016llx, R14 = 0x%016llx, R15 = 0x%016llx\n",
        Registers->R12, Registers->R13, Registers->R14, Registers->R15);
    LOG("RIP = 0x%016llx, RFLAGS = 0x%016llx\n",
        Registers->Rip, Registers->Flags);
    LOG("CR0 = 0x%016llx, CR2 = 0x%016llx, CR3 = 0x%016llx, CR4 = 0x%016llx\n",
        Registers->Cr0, Registers->Cr2, Registers->Cr3, Registers->Cr4);
}


TIMER_FRIENDLY
__nonnull() void
IntDumpBuffer(
    _In_reads_bytes_(Length) const void *Buffer,
    _In_opt_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ DWORD RowLength,
    _In_opt_ DWORD ElementLength,
    _In_opt_ BOOLEAN LogHeader,
    _In_opt_ BOOLEAN DumpAscii
    )
///
/// @brief      This function dumps a given buffer in a user friendly format.
///
///
/// NOTE: Timer friendly only if Cr3 != 0 or gGuest.SystemCr3 != 0.
///
/// Example:\n
/// [DUMPER] Dumping buffer from GVA 0000000001482000 with size 591\n
/// 0000000001482000 : e8 00 00 00 00 58 c6 40 07 01 c3 cc 00 00 00 00 .....X.@........\n
/// 0000000001482010 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................\n
/// 0000000001482020 : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................\n
///
/// @param[in]  Buffer              The buffer to be dumped.
/// @param[in]  Gva                 The GVA mapped by the Buffer (it can be 0).
/// @param[in]  Length              The length of the buffer to be dumped.
/// @param[in]  RowLength           The number of elements to be printed on each row (valid values 1 -> 16 or 0
///                                 resulting in a default value - 8).
///
/// @param[in]  ElementLength       The length, in bytes, of one element (1, 2, 4 or 8 bytes).
/// @param[in]  LogHeader           If TRUE, a header will be logged (GVA and Length information).
/// @param[in]  DumpAscii           If TRUE, the ASCII values corresponding to the dumped buffer will be logged as well.
///
{
    char line[256] = {0};
    const unsigned char *buf = Buffer;

    if (0 == RowLength)
    {
        RowLength = 8;
    }

    if (0 == ElementLength)
    {
        ElementLength = 1;
    }

    if (1 != ElementLength && 2 != ElementLength && 4 != ElementLength && 8 != ElementLength)
    {
        WARNING("[WARNING] Only 1, 2, 4 or 8 element length are supported!\n");
        return;
    }

    if (RowLength > 16)
    {
        WARNING("[ERROR] Maximum 16 elements per row are supported!\n");
        return;
    }

#define IS_ASCII(x) ((x) >= 0x20 && (x) < 0x7f)

    if (LogHeader)
    {
        LOG("[DUMPER] Dumping buffer from GVA %016llx with size %d\n", Gva, Length);
    }

    for (size_t i = 0; i < Length; i += (size_t)RowLength * ElementLength)
    {
        char *l = line;
        int ret, rem = sizeof(line);
        char rest[sizeof(QWORD)];

        ret = snprintf(l, sizeof(line), "%016llx:", Gva + i);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            break;
        }

        rem -= ret;
        l += ret;

        for (size_t j = 0; j < (size_t)RowLength * ElementLength; j += ElementLength)
        {
            BOOLEAN over = (i + j + ElementLength) > Length;

            if (ElementLength != 1 && over)
            {
                memset(rest, 'x', sizeof(rest));

                if (i + j < Length)
                {
                    memcpy(rest, buf + i + j, (i + j + ElementLength) - Length);
                }
            }

            switch (ElementLength)
            {
            case 1:
                ret = snprintf(l, rem, " %02x",
                               over ? 'x' : buf[i + j]);
                break;
            case 2:
                ret = snprintf(l, rem, " %04x",
                               over ? * (WORD *)rest : * (const WORD *)(buf + i + j));
                break;
            case 4:
                ret = snprintf(l, rem, " %08x",
                               over ? * (DWORD *)rest : * (const DWORD *)(buf + i + j));
                break;
            case 8:
                ret = snprintf(l, rem, " %016llx",
                               over ? * (QWORD *)rest : * (const QWORD *)(buf + i + j));
                break;
            }

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }

            rem -= ret;
            l += ret;
        }

        if (DumpAscii)
        {
            ret = snprintf(l, rem, " ");
            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }

            rem -= ret;
            l += ret;

            for (size_t j = 0; j < (size_t)RowLength * ElementLength; j++)
            {
                ret = snprintf(l, rem, "%c", (i + j >= Length) ? 'x' : IS_ASCII(buf[i + j]) ? buf[i + j] : '.');
                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    break;
                }

                rem -= ret;
                l += ret;
            }
        }

        LOG("%s\n", line);
    }
}


TIMER_FRIENDLY void
IntDumpGvaEx(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_opt_ DWORD RowLength,
    _In_opt_ DWORD ElementLength,
    _In_opt_ BOOLEAN LogHeader,
    _In_opt_ BOOLEAN DumpAscii
    )
///
/// @brief      This function dumps a given GVA in a user friendly format. This function uses #IntDumpBuffer to perform
/// the dump, but it also does the memory mapping of the GVA given the address space (Cr3).
///
/// NOTE: Timer friendly only if Cr3 != 0 or gGuest.SystemCr3 != 0.
///
/// @param[in]  Gva                 The GVA of the buffer.
/// @param[in]  Length              The length of the buffer to be dumped.
/// @param[in]  Cr3                 The address space (if 0, the function uses the CR3 of the current VCPU).
/// @param[in]  RowLength           The number of elements to be printed on each row (valid values 1 -> 16 or 0
///                                 resulting in a default value - 8).
///
/// @param[in]  ElementLength       The length, in bytes, of one element (1, 2, 4 or 8 bytes).
/// @param[in]  LogHeader           If TRUE, a header will be logged (GVA and Length information).
/// @param[in]  DumpAscii           If TRUE, the ASCII values corresponding to the dumped buffer will be logged as well.
///
{
    BYTE *buf;
    INTSTATUS status;
    DWORD retLen;
    QWORD cr3;

    if (0 == Length)
    {
        return;
    }

    cr3 = Cr3;

    if (0 == cr3)
    {
        status = IntCr3Read(IG_CURRENT_VCPU, &cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCr3Read failed: %08x\n", status);
            return;
        }
    }

    buf = HpAllocWithTag(Length, IC_TAG_ALLOC);
    if (NULL == buf)
    {
        return;
    }

    status = IntVirtMemRead(Gva, Length, cr3, buf, &retLen);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemRead failed for GVA 0x%016llx and length 0x%x: 0x%08x\n", Gva, Length, status);
        goto _clean_leave;
    }

    IntDumpBuffer(buf, Gva, retLen, RowLength, ElementLength, LogHeader, DumpAscii);

_clean_leave:
    HpFreeAndNullWithTag(&buf, IC_TAG_ALLOC);
}


TIMER_FRIENDLY void
IntDumpGva(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3
    )
///
/// @brief      This function is a wrapper over #IntDumpGvaEx (it uses RowLength = 16, ElementLength = 1,
/// LogHeader = TRUE and DumpAscii = TRUE).
///
/// NOTE: Timer friendly only if Cr3 != 0 or gGuest.SystemCr3 != 0.
///
/// @param[in]  Gva                 The GVA of the buffer.
/// @param[in]  Length              The length of the buffer to be dumped.
/// @param[in]  Cr3                 The address space (if 0, the function uses the CR3 of the current VCPU).
///
{
    IntDumpGvaEx(Gva, Length, Cr3, 16, sizeof(BYTE), TRUE, TRUE);
}


void
IntDisasmBuffer(
    _In_ void *Buffer,
    _In_ DWORD Length,
    _In_opt_ QWORD Rip
    )
///
/// @brief      This function disassembles a given code buffer and then dumps the instructions (textual disassembly).
///
/// @param[in]  Buffer      The code buffer to be dumped.
/// @param[in]  Length      The length of the code buffer to be dumped.
/// @param[in]  Rip         The RIP value of the code to be dumped.
///
{
    INSTRUX instrux;
    INTSTATUS status;
    DWORD csType;
    BYTE *p = Buffer;

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return;
    }

    for (QWORD rip = Rip; rip < Rip + Length;)
    {
        char temp[ND_MIN_BUF_SIZE];
        char _line[ND_MIN_BUF_SIZE * 2];
        char *line = _line;
        int ret, rem = sizeof(_line);

        status = IntDecDecodeInstructionFromBuffer(p, Length - (rip - Rip), csType, &instrux);
        if (!INT_SUCCESS(status))
        {
            LOG("0x%llx db %02x\n", rip, *p);

            rip++;
            p++;

            continue;
        }

        NdToText(&instrux, rip, sizeof(temp), temp);

        ret = snprintf(line, rem, "0x%llx ", rip);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            break;
        }

        rem -= ret;
        line += ret;

        for (DWORD i = 0; i < 14; i++)
        {
            if (i < instrux.Length)
            {
                ret = snprintf(line, rem, "%02x", instrux.InstructionBytes[i]);
            }
            else
            {
                ret = snprintf(line, rem, "  ");
            }

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }

            rem -= ret;
            line += ret;
        }

        ret = snprintf(line, rem, "    %s", temp);
        if (ret < 0 || ret >= rem)
            {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            break;
        }

        rem -= ret;
        line += ret;

        QWORD ptr;

        switch (instrux.Instruction)
        {
        case ND_INS_CALLNR:
        case ND_INS_Jcc:
        case ND_INS_JMPNR:
            ptr = rip + instrux.Length + instrux.Operands[0].Info.RelativeOffset.Rel;

            break;

        default:
            ptr = 0;
        }

        if (ptr &&
            gGuest.OSType == introGuestLinux &&
            IN_RANGE_LEN(ptr, gGuest.KernelVa, gGuest.KernelSize))
        {
            QWORD symStart = 0;
            status = IntKsymFindByAddress(ptr, sizeof(temp), temp, &symStart, NULL);
            if (INT_SUCCESS(status))
            {
                if (symStart != ptr)
                {
                    ret = snprintf(line, rem, " (%s + 0x%llx)", temp, ptr - symStart);
                }
                else
                {
                    ret = snprintf(line, rem, " (%s)", temp);
                }

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    break;
                }

                line += ret;
                rem -= ret;
            }
        }

        LOG("%s\n", _line);

        rip += instrux.Length;
        p += instrux.Length;
    }
}


void
IntDisasmGva(
    _In_ QWORD Gva,
    _In_ DWORD Length
    )
///
/// @brief      This function disassembles a code buffer (given its GVA) and then dumps the instructions (textual
/// disassembly).
///
/// @param[in]  Gva         The GVA of the code to be dumped.
/// @param[in]  Length      The length of the code buffer to be dumped.
///
{
    INSTRUX instrux;
    INTSTATUS status;
    DWORD csType;
    QWORD rip = Gva, functionEnd = 0;

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return;
    }

    LOG("[DUMPER] Dumping first 0x%x bytes of instructions:\n", Length);

    while (rip < Gva + Length)
    {
        char temp[ND_MIN_BUF_SIZE];
        char _line[ND_MIN_BUF_SIZE * 2];
        char *line = _line;
        int ret, rem = sizeof(_line);

        if (gGuest.OSType == introGuestLinux &&
            rip > functionEnd &&
            IN_RANGE_LEN(rip, gGuest.KernelVa, gGuest.KernelSize))
        {
            status = IntKsymFindByAddress(rip, sizeof(temp), temp, NULL, &functionEnd);
            if (INT_SUCCESS(status))
            {
                LOG("%s\n", temp);
            }
        }

        status = IntDecDecodeInstruction(csType, rip, &instrux);
        if (!INT_SUCCESS(status))
        {
            BYTE b = 0xbd;

            IntVirtMemRead(Gva, 1, 0, &b, NULL);

            LOG("0x%llx db %02x\n", rip, b);

            rip++;
            continue;
        }

        NdToText(&instrux, rip, sizeof(temp), temp);

        ret = snprintf(line, rem, "0x%llx ", rip);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            break;
        }

        rem -= ret;
        line += ret;

        for (DWORD i = 0; i < 14; i++)
        {
            if (i < instrux.Length)
            {
                ret = snprintf(line, rem, "%02x", instrux.InstructionBytes[i]);
            }
            else
            {
                ret = snprintf(line, rem, "  ");
            }

            if (ret < 0 || ret >= rem)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                break;
            }

            rem -= ret;
            line += ret;
        }

        ret = snprintf(line, rem, "    %s", temp);
        if (ret < 0 || ret >= rem)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
            break;
        }

        rem -= ret;
        line += ret;

        QWORD ptr;

        switch (instrux.Instruction)
        {
        case ND_INS_CALLNR:
        case ND_INS_Jcc:
        case ND_INS_JMPNR:
            ptr = rip + instrux.Length + instrux.Operands[0].Info.RelativeOffset.Rel;

            break;

        default:
            ptr = 0;
        }

        if (ptr &&
            gGuest.OSType == introGuestLinux &&
            IN_RANGE_LEN(ptr, gGuest.KernelVa, gGuest.KernelSize))
        {
            QWORD symStart = 0;
            status = IntKsymFindByAddress(ptr, sizeof(temp), temp, &symStart, NULL);
            if (INT_SUCCESS(status))
            {
                if (symStart != ptr)
                {
                    ret = snprintf(line, rem, " (%s + 0x%llx)", temp, ptr - symStart);
                }
                else
                {
                    ret = snprintf(line, rem, " (%s)", temp);
                }

                if (ret < 0 || ret >= rem)
                {
                    ERROR("[ERROR] snprintf error: %d, size %d\n", ret, rem);
                    break;
                }

                line += ret;
                rem -= ret;
            }
        }

        LOG("%s\n", _line);

        rip += instrux.Length;
    }
}


TIMER_FRIENDLY void
IntDumpInstruction(
    _In_ INSTRUX *Instruction,
    _In_opt_ QWORD Rip
    )
///
/// @brief      This function dumps a given instruction (textual disassembly).
///
/// @param[in]  Instruction     The instruction to be dumped.
/// @param[in]  Rip             The RIP value of the instruction to be dumped.
///
{
    char nd[ND_MIN_BUF_SIZE] = {0};
    NDSTATUS status;

    if (NULL == Instruction)
    {
        return;
    }

    status = NdToText(Instruction, Rip, sizeof(nd), nd);
    if (!ND_SUCCESS(status))
    {
        snprintf(nd, sizeof(nd), "<invalid: %08x>", status);
    }

    LOG("[DUMPER] Dumping instruction at %llx: %s\n", Rip, nd);
    IntDumpBuffer(Instruction->InstructionBytes, Rip, Instruction->Length, 16, 1, TRUE, FALSE);
}


void
IntDisasmLixFunction(
    _In_ const char *FunctionName
    )
///
/// @brief      This function dumps a Linux function (textual disassembly) given its name.
///
/// @param[in]  FunctionName     The function to be dumped.
///
{
    QWORD start, end;

    start = IntKsymFindByName(FunctionName, &end);
    if (!start)
    {
        WARNING("[WARNING] IntKsymFindByName could not find %s\n", FunctionName);
        return;
    }

    IntDisasmGva(start, (DWORD)(end - start));
}


void
IntDumpCode(
    _In_ BYTE *Page,
    _In_ DWORD Offset,
    _In_ IG_CS_TYPE CsType,
    _In_ IG_ARCH_REGS *Registers
    )
///
/// @brief      This function dumps an entire page (textual disassembly and opcodes).
///
/// @param[in]  Page        The page to be dumped.
/// @param[in]  Offset      The offset to dump the code from.
/// @param[in]  CsType      The code segment type.
/// @param[in]  Registers   The registers (used to obtain the RIP).
///
{
    DWORD insCount, i;
    INTSTATUS status;
    INSTRUX instrux = { 0 };
    char text[ND_MIN_BUF_SIZE];

    i = insCount = 0;

    LOG("First 256 instructions:\n");

    while ((Offset + i < PAGE_SIZE) && (insCount++ < 256))
    {
        status = IntDecDecodeInstructionFromBuffer(Page + Offset + i, PAGE_SIZE - Offset - i, CsType, &instrux);
        if (!INT_SUCCESS(status))
        {
            i++;
        }
        else
        {
            NdToText(&instrux, Registers->Rip + i, ND_MIN_BUF_SIZE, text);

            LOG("    %llx: %s\n", Registers->Rip + i, text);

            i += instrux.Length;
        }
    }

    LOG("Raw page dump:\n");

    for (i = 0; i < PAGE_SIZE / 16; i++)
    {
        LOG("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
            Page[i * 16 + 0x0], Page[i * 16 + 0x1], Page[i * 16 + 0x2], Page[i * 16 + 0x3],
            Page[i * 16 + 0x4], Page[i * 16 + 0x5], Page[i * 16 + 0x6], Page[i * 16 + 0x7],
            Page[i * 16 + 0x8], Page[i * 16 + 0x9], Page[i * 16 + 0xA], Page[i * 16 + 0xB],
            Page[i * 16 + 0xC], Page[i * 16 + 0xD], Page[i * 16 + 0xE], Page[i * 16 + 0xF]);
    }
}


INTSTATUS
IntDumpCodeAndRegs(
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ IG_ARCH_REGS *Registers
    )
///
/// @brief      This function dumps an entire page (textual disassembly and opcodes) as well as the values of
/// the registers.
///
/// @param[in]  Gva         The GVA (used to obtain the offset in page).
/// @param[in]  Gpa         The GPA (it is mapped by this function).
/// @param[in]  Registers   The registers.
///
{
    INTSTATUS status;
    PBYTE pPage;
    DWORD offset, csType;

    pPage = NULL;
    csType = 0;

    status = IntPhysMemMap(Gpa & PHYS_PAGE_MASK, PAGE_SIZE, 0, &pPage);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
        return status;
    }

    offset = Gva & PAGE_OFFSET;

    // Get the CS type for this cpu (we need it in order to see if it's in 16 bit, 32 bit or 64 bit).
    status = IntGetCurrentMode(gVcpu->Index, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        IntPhysMemUnmap(&pPage);
        return status;
    }

    IntDumpCode(pPage, offset, csType, Registers);
    IntDumpArchRegs(Registers);

    IntPhysMemUnmap(&pPage);

    return INT_STATUS_SUCCESS;
}


void
IntDumpLixUmTrapFrame(
    _In_ LIX_TRAP_FRAME *TrapFrame
    )
///
/// @brief      This function dumps a Linux UM trap frame.
///
/// @param[in]  TrapFrame   The trap frame to be dumped.
///
{
    LOG("R15 = %016llx R14 = %016llx R13 = %016llx R12 = %016llx Rbp = %016llx\n",
        TrapFrame->R15, TrapFrame->R14, TrapFrame->R13, TrapFrame->R12, TrapFrame->Rbp);

    LOG("Rbx = %016llx R11 = %016llx R10 = %016llx R9  = %016llx R8  = %016llx \n",
        TrapFrame->Rbx, TrapFrame->R11, TrapFrame->R10, TrapFrame->R9, TrapFrame->R8);

    LOG("Rax = %016llx Rcx = %016llx Rdx = %016llx Rsi = %016llx Rdi = %016llx\n",
        TrapFrame->Rax, TrapFrame->Rcx, TrapFrame->Rdx, TrapFrame->Rsi, TrapFrame->Rdi);

    LOG("Oax = %016llx Rip = %016llx Cs  = %016llx Flg = %016llx Rsp = %016llx Ss = %016llx\n",
        TrapFrame->OrigRax, TrapFrame->Rip, TrapFrame->Cs, TrapFrame->Rflags, TrapFrame->Rsp, TrapFrame->Ss);
}


void
IntDumpWinTrapFrame64(
    _In_ KTRAP_FRAME64 *TrapFrame
    )
///
/// @brief      This function dumps a windows 64 guest trap frame.
///
/// @param[in]  TrapFrame   The trap frame to be dumped.
///
{
    LOG("RAX = %016llx RCX = %016llx RDX = %016llx R8 = %016llx R9 = %016llx\n",
        TrapFrame->Rax, TrapFrame->Rcx, TrapFrame->Rdx, TrapFrame->R8, TrapFrame->R9);

    LOG("R10 = %016llx GsSwap = %016llx DS = %04x ES = %04x FS = %04x \n",
        TrapFrame->R10, TrapFrame->GsSwap, TrapFrame->SegDs, TrapFrame->SegEs, TrapFrame->SegFs);

    LOG("GS = %04x RBX = %016llx RDI = %016llx RSI = %016llx RBP = %016llx\n",
        TrapFrame->SegGs, TrapFrame->Rbx, TrapFrame->Rdi, TrapFrame->Rsi, TrapFrame->Rbp);

    LOG("TrapFrame = 0x%016llx RIP = %016llx CS = %04x FLAGS = %08x RSP = %016llx SS = %04x\n",
        TrapFrame->TrapFrame, TrapFrame->Rip, TrapFrame->SegCs, TrapFrame->EFlags, TrapFrame->Rsp, TrapFrame->SegSs);
}


void
IntDumpWinTrapFrame32(
    _In_ KTRAP_FRAME32 *TrapFrame
    )
///
/// @brief      This function dumps a windows 64 guest trap frame.
///
/// @param[in]  TrapFrame   The trap frame to be dumped.
///
{
    LOG("GS = %08x ES = %08x DS = %08x EDX = %08x ECX = %08x\n",
        TrapFrame->SegGs, TrapFrame->SegEs, TrapFrame->SegDs, TrapFrame->Edx, TrapFrame->Ecx);

    LOG("EAX = %08x FS = %08x EDI = %08x ESI = %08x EBX = %08x \n",
        TrapFrame->Eax, TrapFrame->SegFs, TrapFrame->Edi, TrapFrame->Esi, TrapFrame->Ebx);

    LOG("EBP = %08x EIP = %08x CS = %08x FLAGS = %08x ESP = %08x SS = %08x\n",
        TrapFrame->Ebp,
        TrapFrame->Eip,
        TrapFrame->SegCs,
        TrapFrame->EFlags,
        TrapFrame->HardwareEsp,
        TrapFrame->HardwareSegSs);
}
