/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXSTACK_H_
#define _LIXSTACK_H_

#include "guest_stack.h"

#define MAX_FUNC_NAME               128     ///< The maximum number of characters allowed for a function name.

typedef struct _LIX_TASK_OBJECT  LIX_TASK_OBJECT;
typedef struct _LIX_TRAP_FRAME  LIX_TRAP_FRAME;

INTSTATUS
IntLixStackTraceGet(
    _In_opt_ QWORD Cr3,
    _In_ QWORD Stack,
    _In_ QWORD Rip,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    );

INTSTATUS
IntLixStackTraceGetReg(
    _In_opt_ QWORD Cr3,
    _In_ PIG_ARCH_REGS Registers,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    );

void
IntLixDumpStacktrace(
    _In_ DWORD MaxTraces
    );

void
IntLixStackDumpUmStackTrace(
    _In_ LIX_TASK_OBJECT *Task
    );

#endif //_LIXSTACK_H_
