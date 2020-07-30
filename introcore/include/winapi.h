/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINAPI_H_
#define _WINAPI_H_


#include "winguest.h"


INTSTATUS
IntWinApiHookAll(
    void
    );

void
IntWinApiUpdateHooks(
    void
    );

INTSTATUS
IntWinApiHookVeHandler(
    _In_ QWORD NewHandler,
    _Out_ void **Cloak,
    _Out_opt_ QWORD *OldHandler,
    _Out_opt_ DWORD *ReplacedCodeLen,
    _Out_writes_to_(38, *ReplacedCodeLen) BYTE *ReplacedCode
    );

INTSTATUS
IntWinApiUpdateHookDescriptor(
    _In_ WIN_UNEXPORTED_FUNCTION *Function,
    _In_ DWORD ArgumentsCount,
    _In_ const DWORD *Arguments
    );

#endif // _WINAPI_H_
