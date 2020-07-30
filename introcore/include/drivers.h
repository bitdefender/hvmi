/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DRIVER_H_
#define _DRIVER_H_

#include "lixmodule.h"
#include "windriver.h"

///
/// @brief  Describes an entry in the #gDriverExportCache.
///
typedef struct _DRIVER_EXPORT_CACHE_ENTRY
{
    QWORD Rip;              ///< The guest RIP for which this entry exists.

    struct
    {
        BYTE Unknown : 1;   ///< Set if the function at this RIP is not exported.
        BYTE Export  : 1;   ///< Set if the function at this RIP is exported.
    } Type;
} DRIVER_EXPORT_CACHE_ENTRY, *PDRIVER_EXPORT_CACHE_ENTRY;

///
/// @brief  Describes a kernel driver.
///
/// This structure contains information that is common for both Windows and Linux kernels, with the OS-specific
/// parts being saved in the Win or Lix fields.
typedef struct _KERNEL_DRIVER
{
    /// @brief  Entry inside the #gKernelDrivers list.
    LIST_ENTRY  Link;

    /// @brief  The guest virtual address at which this object resides.
    ///
    /// For windows guests this is the address of the _DRIVER_OBJECT structure, for Linux guests this is the
    /// address of the 'struct module' structure.
    QWORD       ObjectGva;
    /// @brief  The guest virtual address of the kernel module that owns this driver object.
    QWORD       BaseVa;
    /// @brief  The size of the kernel module that owns this driver object.
    QWORD       Size;
    /// @brief  The entry point of this driver.
    QWORD       EntryPoint;
    /// @brief  The introcore option that decided that this driver must be protected.
    ///
    /// See @ref group_options for valid values.
    QWORD       ProtectionFlag;

    /// @brief  The name of the driver.
    ///
    /// This is saved as a void* because on Windows it will be a WCHAR* and on Linux it will be a CHAR*.
    void        *Name;
    /// @brief  The length of the Name. This is the number of characters in the Name buffer.
    SIZE_T      NameLength;

    /// @brief  The hash of the name.
    DWORD       NameHash;

    /// @brief  The hook object used to protect this driver. NULL if the driver is not protected.
    void        *HookObject;

    /// @brief  True if the driver is protected, False if it is not.
    BOOLEAN     Protected;

    /// @brief  OS-specific information.
    union
    {
        WIN_KERNEL_DRIVER   Win;  ///< Valid only for Windows guests.
        LIX_KERNEL_MODULE   Lix;  ///< Valid only for Linux guests.
    };
} KERNEL_DRIVER, *PKERNEL_DRIVER;


INTSTATUS
IntDriverLoadHandler(
    _In_ void const *Detour
    );

INTSTATUS
IntDriverUnloadHandler(
    _In_ void const *Detour
    );

KERNEL_DRIVER *
IntDriverFindByAddress(
    _In_ QWORD Gva
    );

KERNEL_DRIVER *
IntDriverFindByBase(
    _In_ QWORD Gva
    );

KERNEL_DRIVER *
IntDriverFindByLoadOrder(
    _In_ DWORD LoadOrder
    );

KERNEL_DRIVER *
IntDriverFindByName(
    _In_ const void *Name
    );

KERNEL_DRIVER *
IntDriverFindByPath(
    _In_ const WCHAR *Path
    );

void
IntDriverUninit(
    void
    );

void
IntDriverDump(
    void
    );

void
IntDriverCacheCreateExport(
    _In_ const QWORD Rip
    );

void
IntDriverCacheCreateUnknown(
    _In_ const QWORD Rip
    );

DRIVER_EXPORT_CACHE_ENTRY *
IntDriverCacheExportFind(
    _In_ const QWORD Rip
    );

void
IntDriverCacheInv(
    _In_ const QWORD BaseAddress,
    _In_ const QWORD Length
    );

#endif // _DRIVER_H_
