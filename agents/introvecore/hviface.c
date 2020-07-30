/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hviface.h"
#include "asmlib.h"
#include "cpu.h"


//
// HvRaiseEpt
//
DWORD
HvRaiseEpt(
    void
    )
{
    QWORD rax, rbx, rcx, rdx, rdi, rsi;

    rax = VE_VMCALL_OP;
    rdi = VE_VMCALL_SUBOP;
    rsi = 0;
    rdx = VE_HCALL_RAISE_EPT;

    AsmVmcall(&rax, &rbx, &rcx, &rdx, &rdi, &rsi);

    return (DWORD)rax;
}


//
// HvBreak
//
DWORD
HvBreak(
    QWORD Reason,
    QWORD Argument
    )
{
    QWORD rax, rbx, rcx, rdx, rdi, rsi;

    rax = VE_VMCALL_OP;
    rdi = VE_VMCALL_SUBOP;
    rsi = 0;
    rdx = VE_HCALL_BREAK;
    rbx = Reason;
    rcx = Argument;

    AsmVmcall(&rax, &rbx, &rcx, &rdx, &rdi, &rsi);

    return (DWORD)rax;
}


//
// HvBreak
//
DWORD
HvTrace(
    QWORD Reason,
    QWORD Argument
    )
{
    QWORD rax, rbx, rcx, rdx, rdi, rsi;

    rax = VE_VMCALL_OP;
    rdi = VE_VMCALL_SUBOP;
    rsi = 0;
    rdx = VE_HCALL_TRACE;
    rbx = Reason;
    rcx = Argument;

    AsmVmcall(&rax, &rbx, &rcx, &rdx, &rdi, &rsi);

    return (DWORD)rax;
}
