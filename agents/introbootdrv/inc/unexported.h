/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UNEXPORTED_H_
#define _UNEXPORTED_H_

#include "introbootdrv_types.h"
#include <ntddk.h>

typedef NTSTATUS
(*PFUNC_ZwWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ void *BaseAddress,
    _In_ void *Buffer,
    _In_ ULONG NumberOfBytesToWrite,
    _Out_opt_ PULONG NumberOfBytesWritten
    );

typedef NTSTATUS
(*PFUNC_ZwProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ void **BaseAddress,
    _Inout_  PULONG NumberOfBytesToProtect,
    _In_ ULONG NewAccessProtection,
    _Out_ PULONG OldAccessProtection
    );

typedef NTSTATUS
(*PFUNC_ZwCreateThreadEx)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ void *StartRoutine,
    _In_opt_ void *Argument,
    _In_ ULONG CreateFlags,
    _In_opt_ ULONG_PTR ZeroBits,
    _In_opt_ SIZE_T StackSize,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ void *AttributeList
    );

#pragma warning(push)
#pragma warning(disable: 4201 4200)  // Nameless struct/union, Zero sized array in struct/union
typedef union _IREM_DRV_UEXFN
{
    struct 
    {
        // These are in the same order as intro stores them so we can
        // request them by index.
        PFUNC_ZwWriteVirtualMemory ZwWriteVirtualMemory;
        PFUNC_ZwProtectVirtualMemory ZwProtectVirtualMemory;
        PFUNC_ZwCreateThreadEx ZwCreateThreadEx;
    };
    void *_Funcs[];
} IREM_DRV_UEXFN;
#pragma warning(pop)

extern IREM_DRV_UEXFN gUnexported;

#define ZwWriteVirtualMemory        gUnexported.ZwWriteVirtualMemory
#define ZwProtectVirtualMemory      gUnexported.ZwProtectVirtualMemory
#define ZwCreateThreadEx            gUnexported.ZwCreateThreadEx

NTSTATUS
UexFindFunctions(
    void
    );

#endif // !_UNEXPORTED_H_

