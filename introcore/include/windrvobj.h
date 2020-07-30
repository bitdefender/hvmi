/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINDRVOBJ_H_
#define _WINDRVOBJ_H_

#include "introtypes.h"

///
/// @brief      Holds information about a driver object.
///
typedef struct _WIN_DRIVER_OBJECT
{
    /// @brief  Entry inside the #gWinDriverObjects list.
    LIST_ENTRY  Link;
    /// @brief  The guest virtual address of the guest _DRIVER_OBJECT represented by this structure.
    QWORD       DriverObjectGva;
    /// @brief  The guest physical address of the guest _DRIVER_OBJECT represented by this structure.
    ///
    /// A driver object may be referenced by multiple GVAs, so we also keep the GPA to which DriverObjectGva
    /// translates to. Note that we do not update this when the translation for DriverObjectGva changes, but
    /// when an EPT violation is triggered for it (the hooked GPA is automatically updated by the EPT hooking
    /// mechanism).
    QWORD       DriverObjectGpa;
    /// @brief  The guest virtual address of the _FAST_IO_DISPATCH structure used by this driver object. May be 0.
    QWORD       FastIOTableAddress;
    /// @brief  NULL-terminated wide-char string containing the name of the driver, as taken from the guest driver
    /// object.
    PWCHAR      Name;
    /// @brief  The length, in characters, of Name, not including the NULL-terminator.
    DWORD       NameLen;
    /// @brief  Hash of the Name.
    DWORD       NameHash;
    /// @brief  Guest virtual address of the kernel module that owns this driver object.
    ///
    /// This is the module in which the DriverStart routine from the driver object is located.
    QWORD       Owner;

    /// @brief  The EPT hook object used for the _DRIVER_OBJECT structure.
    ///
    /// Only valid when Aligned is True.
    void        *DrvobjHookObject;
    /// @brief  The integrity object used for the _DRIVER_OBJECT structure.
    ///
    /// Only valid when Aligned is False.
    void        *DrvobjIntegrityObject;
    /// @brief  The integrity object used for the _FAST_IO_DISPATCH structure.
    ///
    /// The fast IO dispatch is always protected with the integrity mechanism as it can be in memory zones that are
    /// written a lot.
    void        *FiodispIntegrityObject;

    /// @brief  True if the driver object structure is protected.
    BOOLEAN     DrvobjProtected;
    /// @brief  True if the fast IO dispatch structure is protected.
    BOOLEAN     FiodispProtected;
    /// @brief  True if the driver object allocation is page aligned.
    ///
    /// This can happen if prior to the driver object creation we intercept the memory allocation for it. In that
    /// case, #IntWinPoolHandleAlloc will change the allocation size to ensure that the driver object is allocated
    /// in an entire page. The same is true for fast IO dispatch allocations.
    /// This allows us to protect the driver object and its fast IO dispatch structure using an EPT hook; otherwise,
    /// that may not be doable, as we don't know what other structures are in that page and we can end up with a lot
    /// of VMEXITs that do not interest us, which will have a negative performance impact.
    BOOLEAN     Aligned;
} WIN_DRIVER_OBJECT, *PWIN_DRIVER_OBJECT;


BOOLEAN
IntWinDrvObjIsValidDriverObject(
    _In_ QWORD DriverObjectAddress
    );

PWIN_DRIVER_OBJECT
IntWinDrvObjFindByDrvObj(
    _In_ QWORD Gva
    );

PWIN_DRIVER_OBJECT
IntWinDrvObjFindByOwnerAddress(
    _In_ QWORD Owner
    );

INTSTATUS
IntWinDrvObjCreateFromAddress(
    _In_ QWORD GuestAddress,
    _In_ BOOLEAN StaticDetected,
    _Out_opt_ PWIN_DRIVER_OBJECT *DriverObject
    );

INTSTATUS
IntWinDrvObjRemoveFromAddress(
    _In_ QWORD DriverObjectAddress
    );

INTSTATUS
IntWinDrvObjProtect(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    );

INTSTATUS
IntWinDrvObjUnprotect(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    );

INTSTATUS
IntWinDrvObjRemove(
    _Inout_ WIN_DRIVER_OBJECT *DriverObject
    );

INTSTATUS
IntWinDrvObjUpdateProtection(
    void
    );

INTSTATUS
IntWinDrvObjUninit(
    void
    );

#endif // _WINDRVOBJ_H_
