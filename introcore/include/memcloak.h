/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _MEMCLOAK_H_
#define _MEMCLOAK_H_

///
/// @defgroup   group_memclk Memory cloaking
/// @ingroup    group_internal
/// @brief      Hides memory contents from the guest
///
/// Introcore may inject code or data, or modify existing guest code or data. This raises a series of problems, from
/// hiding from the guest the fact that it is introspected, to making sure the changes are not seen by integrity
/// mechanisms used by the guest (like patch guard on Windows). We also need to make sure that attackers can not
/// modify code or data owned by introcore, while allowing us to easily modify and use those.
/// This is handled here, by the memory cloak mechanism, which employs three memory hooks:
///     - read hooks - this ensures that we control what is seen when the guest tries to read from a hidden memory
///     region.
///     - write hooks - this ensures that the guest can not modify the contents of those memory regions.
///     - swap hooks - this ensures that at swap-out the original memory contents are saved and that at swap-in the
///     contents injected by us will be present in the guest memory.
///
/// @{
///

#include "introtypes.h"

///
/// @brief  The type of custom write handlers that can be used by cloak regions.
///
/// @param[in]  Hook                    The hook that triggered the event.
/// @param[in]  Address                 The physical address written.
/// @param[in]  RegionVirtualAddress    The virtual address at which the region starts.
/// @param[in]  CloakHandle             The cloak handle returned by IntMemClkCloakRegion.
/// @param[out] Action                  The action that must be taken. This will overwrite the default action, which.
///                                     is #introGuestNotAllowed.
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value. Returning an error values
///             will make the returned Action to be ignored, and the default one will be used.
///
typedef INTSTATUS (*PFUNC_IntMemCloakWriteHandle)(
    _In_ void *Hook,
    _In_ QWORD Address,
    _In_ QWORD RegionVirtualAddress,
    _In_ void *CloakHandle,
    _Out_ INTRO_ACTION *Action);

///
/// @brief  Options that control the way a cloaked memory region is handled.
///
typedef enum
{
    MEMCLOAK_OPT_ALLOW_INTERNAL = 0x00000001,   ///< Allows the code inside the region to modify the region.
    MEMCLOAK_OPT_APPLY_PATCH = 0x00000002,      ///< Will write the contents of the patched data inside the guest.
} MEMCLOAK_OPTIONS;


//
// API
//
INTSTATUS
IntMemClkCloakRegion(
    _In_ QWORD VirtualAddress,
    _In_ QWORD Cr3,
    _In_ DWORD Size,
    _In_ DWORD Options,
    _In_opt_ PBYTE OriginalData,
    _In_opt_ PBYTE PatchedData,
    _In_opt_ PFUNC_IntMemCloakWriteHandle WriteHandler,
    _Out_ void **CloakHandle
    );

INTSTATUS
IntMemClkModifyOriginalData(
    _In_ void *CloakHandle,
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _In_ void *Data
    );

INTSTATUS
IntMemClkModifyPatchedData(
    _In_ void *CloakHandle,
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _In_opt_ const void *Data
    );

INTSTATUS
IntMemClkUncloakRegion(
    _In_ void *CloakHandle,
    _In_ DWORD Options
    );

INTSTATUS
IntMemClkHashRegion(
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Size,
    _Out_ DWORD *Crc32
    );

BOOLEAN
IntMemClkIsPtrInCloak(
    _In_ const void *Cloak,
    _In_ QWORD Ptr
    );

INTSTATUS
IntMemClkGetOriginalData(
    _In_ void *CloakHandle,
    _Out_ BYTE **OriginalData,
    _Out_ DWORD *Length
    );

INTSTATUS
IntMemClkUnInit(
    void
    );

void
IntMemClkDump(
    void
    );

/// @}

#endif // _MEMCLOAK_H_
