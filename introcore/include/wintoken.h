/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINTOKEN_H_
#define _WINTOKEN_H_

#include "guests.h"

typedef struct _WIN_PROCESS_OBJECT WIN_PROCESS_OBJECT, *PWIN_PROCESS_OBJECT;

TIMER_FRIENDLY INTSTATUS
IntWinTokenCheckIntegrity(
    void
    );

INTSTATUS
IntWinTokenPtrCheckIntegrityOnProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinTokenPrivsProtectOnProcess(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinTokenPrivsUnprotectOnProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinTokenPrivsCheckIntegrityOnProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    );

_Success_(return == TRUE)
BOOLEAN
IntWinTokenPtrIsStolen(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BOOLEAN Check,
    _Out_opt_ WIN_PROCESS_OBJECT **FromProcess,
    _Out_opt_ QWORD *OldValue,
    _Out_opt_ QWORD *NewValue
    );

INTSTATUS
IntWinTokenProtectPrivs(
    void
    );

INTSTATUS
IntWinTokenUnprotectPrivs(
    void
    );

INTSTATUS
IntWinTokenCheckCurrentPrivileges(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ QWORD TokenPtr,
    _In_ BOOLEAN IntegrityCheck,
    _Out_ BOOLEAN *PresentIncreased,
    _Out_ BOOLEAN *EnabledIncreased,
    _Out_opt_ QWORD *Present,
    _Out_opt_ QWORD *Enabled
    );

#endif
