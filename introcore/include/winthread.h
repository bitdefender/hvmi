/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   winthread.h
///
/// @brief  Exposes the functions used to provide Windows Threads related support.
///

#ifndef _WINTHREAD_H_
#define _WINTHREAD_H_

#include "introtypes.h"

INTSTATUS
IntWinThrIterateThreads(
    _In_ QWORD Eprocess,
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    );

INTSTATUS
IntWinThrGetCurrentThread(
    _In_ DWORD CpuNumber,
    _Out_ QWORD *EthreadAddress
    );

INTSTATUS
IntWinThrGetCurrentTib(
    _In_ IG_CS_RING CurrentRing,
    _In_ IG_CS_TYPE CsType,
    _Out_ QWORD *Tib
    );

INTSTATUS
IntWinThrGetUmStackBaseAndLimitFromTib(
    _In_ QWORD Tib,
    _In_ IG_CS_TYPE CsType,
    _In_ QWORD Cr3,
    _Out_ QWORD *StackBase,
    _Out_ QWORD *StackLimit
    );

INTSTATUS
IntWinThrGetCurrentStackBaseAndLimit(
    _Out_ QWORD *TibBase,
    _Out_ QWORD *StackBase,
    _Out_ QWORD *StackLimit
    );

INTSTATUS
IntWinThrHandleThreadHijack(
    _In_ void *Detour
    );

INTSTATUS
IntWinThrHandleQueueApc(
    _In_ void *Detour
    );

INTSTATUS
IntWinThrPrepareApcHandler(
    _In_ QWORD FunctionAddress,
    _Inout_ void *Handler,
    _In_ void *Descriptor
    );

INTSTATUS
IntWinThrPatchThreadHijackHandler(
    _In_ QWORD FunctionAddress,
    _Inout_ void *Handler,
    _In_ void *Descriptor
    );

#endif // _WINTHREAD_H_
