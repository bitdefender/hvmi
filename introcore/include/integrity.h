/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTEGRITY_H_
#define _INTEGRITY_H_

#include "introtypes.h"

///
/// @brief  Integrity violation callback.
///
/// A callback provided to #IntIntegrityAddRegion which will be called by the integrity mechanism
/// if, while checking once every second, detects any modification on the given region.
///
/// @param[in]  IntegrityRegion The #INTEGRITY_REGION structure associated with the region where
///                             the modification was detected by the integrity mechanism.
///
typedef INTSTATUS
(*PFUNC_IntegrityViolationCallback)(
    _In_ void *IntegrityRegion
    );


///
/// Structure describing a region protected through integrity mechanism.
///
typedef struct _INTEGRITY_REGION
{
    LIST_ENTRY                          Link;               ///< Link to the next integrity region.
    QWORD                               Gva;                ///< The guest virtual address where the region starts.
    DWORD                               Length;             ///< The length of the current region, in bytes.
    DWORD                               OriginalHash;       ///< The computed hash of the region.
    /// @brief  The newly computed hash when a modification is detected.
    DWORD                               ModifiedHash;
    /// @brief  The number of detected modifications on the given region.
    DWORD                               ViolationCount;
    /// @brief  The associated #INTRO_OBJECT_TYPE with the protected region.
    INTRO_OBJECT_TYPE                   Type;
    /// @brief  User supplied context, see #IntIntegrityAddRegion for an example.
    void                                *Context;
    /// @brief  A buffer containing the original bytes of the associated region.
    void                                *OriginalContent;
    /// @brief  The callback to be called when a violation occurs
    PFUNC_IntegrityViolationCallback    Callback;
    /// @brief  Set TRUE for postpone deleting of integrity regions (e.g. deleting from callback)
    BOOLEAN                             Deleted;
} INTEGRITY_REGION, *PINTEGRITY_REGION;


//
// API
//
INTSTATUS
IntIntegrityCheckAll(
    void
    );

INTSTATUS
IntIntegrityAddRegion(
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_ INTRO_OBJECT_TYPE Type,
    _In_opt_ void *Context,
    _In_ PFUNC_IntegrityViolationCallback Callback,
    _In_ BOOLEAN CopyContent,
    _Out_ void **Descriptor
    );

INTSTATUS
IntIntegrityRecalculate(
    _In_ INTEGRITY_REGION *IntegrityRegion
    );

INTSTATUS
IntIntegrityRemoveRegion(
    _In_ void *Descriptor
    );

INTSTATUS
IntIntegrityDeleteRegion(
    _In_ void *Descriptor
    );

void
IntIntegrityDump(
    void
    );

INTSTATUS
IntIntegrityUninit(
    void
    );

#endif  // _INTEGRITY_H_
