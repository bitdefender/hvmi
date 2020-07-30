/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINSTACK_H_
#define _WINSTACK_H_

#include "guest_stack.h"

typedef struct _DPI_EXTRA_INFO DPI_EXTRA_INFO, *PDPI_EXTRA_INFO;
typedef struct _WIN_PROCESS_OBJECT WIN_PROCESS_OBJECT, *PWIN_PROCESS_OBJECT;

// CS selectors for 64-bit guests
#define CODE_SEG_UM_32_GUEST_64          0x23
#define CODE_SEG_UM_64_GUEST_64          0x33

#define CODE_SEG_UM_32_GUEST_32          0x1b


INTSTATUS
IntWinStackTraceGet(
    _In_ QWORD StackFrame,
    _In_ QWORD Rip,
    _In_ DWORD MaxNumberOfTraces,
    _In_ QWORD Flags,
    _Inout_ STACK_TRACE *StackTrace
    );

INTSTATUS
IntWinStackTraceGetUser(
    _In_ PIG_ARCH_REGS Registers,
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ DWORD MaxNumberOfTraces,
    _Out_ STACK_TRACE *StackTrace
    );

INTSTATUS
IntWinStackUserCheckIsPivoted(
    _In_ QWORD UserRsp,
    _In_ DWORD SegCs,
    _In_ BOOLEAN IsWow64Stack,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo,
    _Out_ BOOLEAN *IsPivoted
    );

INTSTATUS
IntWinStackUserTrapFrameGetGeneric(
    _Out_ QWORD *UserRsp,
    _Out_ DWORD *SegCs,
    _In_ BOOLEAN Fallback,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo
    );

INTSTATUS
IntWinStackWow64CheckIsPivoted(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ WIN_PROCESS_OBJECT *RealParent,
    _Inout_ DPI_EXTRA_INFO *DpiExtraInfo
    );

BOOLEAN
IntWinIsUmTrapFrame(
    _In_ void *TrapFrame
    );

#endif  // _WINSTACK_H_
