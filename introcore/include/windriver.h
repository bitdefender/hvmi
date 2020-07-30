/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   windriver.h
///
/// @brief  Exposes the types, constants and functions used to handle
/// Windows Drivers related events.
///
///

#ifndef _WINDRIVER_H_
#define _WINDRIVER_H_

#include "windrvobj.h"

//
// Internal definition of a loaded kernel driver.
//
typedef struct _WIN_KERNEL_DRIVER
{
    DWORD               TimeDateStamp;          ///< The driver`s internal timestamp (from the _IMAGE_FILE_HEADER).

    DWORD               PathHash;               ///< CRC32 hash value for the driver`s path.
    DWORD               PathLength;             ///< The driver`s path length (number of WCHARS).

    PWCHAR              Path;                   ///< The driver`s path.

    /// @brief The EP hook placed on the driver (we will be notified when the execution began) - useful to obtain
    /// the DriverObject in order to protect it.
    void                *EpHookObject;

    PBYTE               MzPeHeaders;            ///< The driver`s MZ/PE headers (cached internally).

    PWIN_DRIVER_OBJECT  DriverObject;           ///< The driver object.

    void                *HeadersSwapHandle;     ///< The swap handle used to read the driver`s headers.

    void                *EatReadHook;            ///< The read hook placed on the driver`s EAT.

    /// @brief  The number of EAT reads that took place from withing known drivers.
    QWORD               EatReadCount;

} WIN_KERNEL_DRIVER, *PWIN_KERNEL_DRIVER;


typedef struct _KERNEL_DRIVER KERNEL_DRIVER, *PKERNEL_DRIVER;

/// @brief  When iterating the guest PsLoadedModuleList, we won't go through more than this many entries,
/// in order to avoid a denial of service when crafted entries are present inside the guest.
#define DRIVER_MAX_ITERATIONS           4096


//
// Loaded drivers specific API
//
INTSTATUS
IntWinDrvIsListHead(
    _In_ QWORD PsLoadedModuleListGva,
    _In_ void *PsLoadedModuleList,
    _In_ QWORD KernelLdr
    );

INTSTATUS
IntWinDrvIterateLoadedModules(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    );

INTSTATUS
IntWinDrvCreateFromAddress(
    _In_ QWORD ModuleInfo,
    _In_ QWORD Flags
    );

INTSTATUS
IntWinDrvRemoveFromAddress(
    _In_ QWORD ModuleInfo
    );

INTSTATUS
IntWinDrvProtect(
    _In_ KERNEL_DRIVER *Driver,
    _In_ QWORD ProtectionFlag
    );

INTSTATUS
IntWinDrvUnprotect(
    _In_ KERNEL_DRIVER *Driver
    );

INTSTATUS
IntWinDrvHandleDriverEntry(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntWinDrvHandleWrite(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntWinDrvHandleRead(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );

INTSTATUS
IntWinProtectReadNtEat(
    void
    );

INTSTATUS
IntWinUnprotectReadNtEat(
    void
    );

INTSTATUS
IntWinDrvRemoveEntry(
    _In_ KERNEL_DRIVER *Driver
    );

INTSTATUS
IntWinDrvUpdateProtection(
    void
    );

#endif // _WINDRIVER_H_
