/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file windrv_protected.h
///
/// @brief Exposes the types, constants and functions used to describe
/// protected Windows Kernel modules and driver objects.
///

#ifndef _WINDRV_PROTECTED_H_
#define _WINDRV_PROTECTED_H_

#include "introtypes.h"
#include "drivers.h"

typedef struct _PROTECTED_MODULE_INFO PROTECTED_MODULE_INFO;

_Success_(return != NULL)
const PROTECTED_MODULE_INFO *
IntWinDrvIsProtected(
    _In_ const KERNEL_DRIVER *Driver
    );

_Success_(return != NULL)
const PROTECTED_MODULE_INFO *
IntWinDrvObjIsProtected(
    _In_ const WIN_DRIVER_OBJECT *DriverObject
    );

BOOLEAN
IntWinDrvHasDriverObject(
    _In_ const KERNEL_DRIVER *Driver
    );

BOOLEAN
IntWinDrvIsProtectedAv(
    _In_ const WCHAR *Driver
    );

BOOLEAN
IntWinDrvObjIsProtectedAv(
    _In_ const WCHAR *DrvObj
    );

#endif // !_WINDRV_PROTECTED_H_

