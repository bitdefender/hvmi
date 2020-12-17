/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   dumper.h
///
/// @brief  Exposes the functions used to used to dump (log) code and registers.
///

#ifndef _DUMPER_H_
#define _DUMPER_H_

#include "glue.h"
#include "bddisasm.h"
#include "wddefs.h"

typedef struct _LIX_TRAP_FRAME LIX_TRAP_FRAME;

TIMER_FRIENDLY
__nonnull() void
IntDumpArchRegs(
    _In_ IG_ARCH_REGS const *Registers
    );

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
    );

TIMER_FRIENDLY void
IntDumpGvaEx(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_opt_ DWORD RowLength,
    _In_opt_ DWORD ElementLength,
    _In_opt_ BOOLEAN LogHeader,
    _In_opt_ BOOLEAN DumpAscii
    );

TIMER_FRIENDLY void
IntDumpGva(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3
    );

__nonnull() void
IntDisasmBuffer(
    _In_ void *Buffer,
    _In_ DWORD Length,
    _In_opt_ QWORD Rip
    );

void
IntDisasmGva(
    _In_ QWORD Gva,
    _In_ DWORD Length
    );

TIMER_FRIENDLY void
IntDumpInstruction(
    _In_ INSTRUX *Instruction,
    _In_opt_ QWORD Rip
    );

__nonnull() void
IntDisasmLixFunction(
    _In_ const char *FunctionName
    );

__nonnull() void
IntDumpCode(
    _In_ BYTE *Page,
    _In_ DWORD Offset,
    _In_ IG_CS_TYPE CsType,
    _In_ IG_ARCH_REGS *Registers
    );

__nonnull() INTSTATUS
IntDumpCodeAndRegs(
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ IG_ARCH_REGS *Registers
    );

void
IntDumpLixUmTrapFrame(
    _In_ LIX_TRAP_FRAME *TrapFrame
    );

void
IntDumpWinTrapFrame64(
    _In_ KTRAP_FRAME64 *TrapFrame
    );

void
IntDumpWinTrapFrame32(
    _In_ KTRAP_FRAME32 *TrapFrame
    );

#endif // _DUMPER_H_
