/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SHELLCODE_H_
#define _SHELLCODE_H_

#include "introcore.h"

typedef struct _WIN_PROCESS_OBJECT WIN_PROCESS_OBJECT;

INTSTATUS
IntShcIsSuspiciousCode(
    _In_ QWORD Gva,
    _In_ QWORD Gpa,
    _In_ DWORD CsType,
    _In_ IG_ARCH_REGS *Registers,
    _Out_ QWORD *ShellcodeFlags
    );

#endif //_SHELLCODE_H_
