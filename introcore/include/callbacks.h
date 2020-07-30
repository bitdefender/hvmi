/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CALLBACKS_H_
#define _CALLBACKS_H_

#include "glue.h"
#include "introdefs.h"


INTSTATUS
IntHandleEptViolation(
    _In_ void *GuestHandle,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_ QWORD LinearAddress,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action,
    _In_ IG_EPT_ACCESS AccessType
    );

INTSTATUS
IntHandleMsrViolation(
    _In_ void *GuestHandle,
    _In_ DWORD Msr,
    _In_ IG_MSR_HOOK_TYPE Flags,
    _Out_ INTRO_ACTION *Action,
    _In_opt_ QWORD OriginalValue,
    _Inout_opt_ QWORD *NewValue,
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntHandleCrWrite(
    _In_ void *GuestHandle,
    _In_ DWORD Cr,
    _In_ DWORD CpuNumber,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntHandleDtrViolation(
    _In_ void *GuestHandle,
    _In_ DWORD Flags,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntHandleIntroCall(
    _In_ void *GuestHandle,
    _In_ QWORD Rip,
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntHandleTimer(
    _In_ void *GuestHandle
    );

INTSTATUS
IntHandleXcrWrite(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntHandleBreakpoint(
    _In_ void *GuestHandle,
    _In_ QWORD GuestPhysicalAddress,
    _In_ DWORD CpuNumber
    );


INTSTATUS
IntCallbacksInit(
    void
    );

INTSTATUS
IntCallbacksUnInit(
    void
    );


static inline INTSTATUS
IntEnableEptNotifications(
    void
    )
{
    TRACE("[CALLBACK] Register the EPT callback...\n");

    INTSTATUS status = IntRegisterEPTHandler(IntHandleEptViolation);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterEPTHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntDisableEptNotifications(
    void
    )
{
    TRACE("[CALLBACK] Unregister the EPT callback...\n");

    INTSTATUS status = IntUnregisterEPTHandler();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntUnregisterEPTHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntEnableDtrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Register the DTR callback...\n");

    INTSTATUS status = IntRegisterDtrHandler(IntHandleDtrViolation);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterDtrHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntDisableDtrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Unregister the DTR callback...\n");

    INTSTATUS status = IntUnregisterDtrHandler();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntUnregisterDtrHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntEnableMsrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Register the MSR callback...\n");

    INTSTATUS status = IntRegisterMSRHandler(IntHandleMsrViolation);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterMSRHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntDisableMsrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Unregister the MSR callback...\n");

    INTSTATUS status = IntUnregisterMSRHandler();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntUnregisterMSRHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntEnableCrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Register the CR callback...\n");

    INTSTATUS status = IntRegisterCrWriteHandler(IntHandleCrWrite);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterCrWriteHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntDisableCrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Unregister the CR callback...\n");

    INTSTATUS status = IntUnregisterCrWriteHandler();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntUnregisterCrWriteHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntEnableXcrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Register the XCR callback...\n");

    INTSTATUS status = IntRegisterXcrWriteHandler(IntHandleXcrWrite);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterXcrWriteHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntDisableXcrNotifications(
    void
    )
{
    TRACE("[CALLBACK] Unregister the XCR callback...\n");

    INTSTATUS status = IntUnregisterXcrWriteHandler();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntUnregisterXcrHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntEnableBreakpointNotifications(
    void
    )
{
    TRACE("[CALLBACK] Register the INT3 callback...\n");

    INTSTATUS status = IntRegisterBreakpointHandler(IntHandleBreakpoint);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterBreakpointHandler failed: 0x%08x\n", status);
    }

    return status;
}


static inline INTSTATUS
IntDisableBreakpointNotifications(
    void
    )
{
    TRACE("[CALLBACK] Unregister the INT3 callback...\n");

    INTSTATUS status = IntUnregisterBreakpointHandler();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntUnregisterBreakpointHandler failed: 0x%08x\n", status);
    }

    return status;
}


#endif // _CALLBACKS_H_
