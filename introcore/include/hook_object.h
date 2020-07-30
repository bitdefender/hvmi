/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_STRUCTURE_H_
#define _HOOK_STRUCTURE_H_

#include "guests.h"

typedef struct _HOOK_HEADER HOOK_HEADER;


///
/// Describes an object. An object may contain multiple regions. The regions need not be contiguous or of the same type.
///
typedef struct _HOOK_OBJECT_DESCRIPTOR
{
    LIST_ENTRY          Link;           ///< The list entry element.
    LIST_HEAD           Regions;        ///< The list of hooked regions belonging to this object.
    /// @brief  All the removed regions are inserted here. The regions must be committed in the exact same order
    /// they were removed, otherwise, we may end up with inconsistent EPT rights.
    LIST_HEAD           RemovedRegions;
    DWORD               ObjectType;     ///< One of the #INTRO_OBJECT_TYPE values.
    QWORD               Cr3;            ///< The CR3 of the object. If this is a kernel object, Cr3 must be 0.
    DWORD               Flags;          ///< Hook flags.

    /// @brief  True if regions have been removed from this object (used by the commit function).
    BOOLEAN             RegionsRemoved;
} HOOK_OBJECT_DESCRIPTOR, *PHOOK_OBJECT_DESCRIPTOR;


///
/// Describes a region. A given object may contain several different protected regions. The regions can be of different
/// types, but a given region can be of only one type.
///
typedef struct _HOOK_REGION_DESCRIPTOR
{
    HOOK_HEADER             Header;         ///< The hook header.
    LIST_ENTRY              Link;           ///< The list entry element.
    QWORD                   HookStart;      ///< Guest virtual address of the hooked region.
    QWORD                   HookLength;     ///< Length of the hooked region. May span multiple pages.
    DWORD                   HooksCount;     ///< Number of hooks set for this region of memory.
    void                    **Hooks;        ///< Array of hooks. They will usually be #HOOK_GVA objects.

    /// @brief  Parent object. Optional, but it is strongly recommended to link a region to an object.
    PHOOK_OBJECT_DESCRIPTOR Object;
} HOOK_REGION_DESCRIPTOR, *PHOOK_REGION_DESCRIPTOR;


///
/// Global hook object state.
///
typedef struct _HOOK_OBJECTS_STATE
{
    LIST_HEAD           Objects;        ///< List of objects.
    BOOLEAN             ObjectsRemoved; ///< True whenever an object has been removed.
} HOOK_OBJECT_STATE, *PHOOK_OBJECT_STATE;


//
// API
//
INTSTATUS
IntHookObjectCreate(
    _In_ DWORD ObjectType,
    _In_ QWORD Cr3,
    _Out_ void **Object
    );

INTSTATUS
IntHookObjectHookRegion(
    _In_ void *Object,
    _In_ QWORD Cr3,
    _In_ QWORD Gla,
    _In_ SIZE_T Length,
    _In_ BYTE Type,
    _In_ void *Callback,
    _In_opt_ void *Context,
    _In_opt_ DWORD Flags,
    _Out_opt_ HOOK_REGION_DESCRIPTOR **Region
    );

INTSTATUS
IntHookObjectRemoveRegion(
    _Inout_ HOOK_REGION_DESCRIPTOR **Region,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookObjectDestroy(
    _Inout_ HOOK_OBJECT_DESCRIPTOR **Object,
    _In_ DWORD Flags
    );

void *
IntHookObjectFindRegion(
    _In_ QWORD Gva,
    _In_ void *HookObject,
    _In_ BYTE HookType
    );

INTSTATUS
IntHookObjectCommit(
    void
    );

INTSTATUS
IntHookObjectInit(
    void
    );

INTSTATUS
IntHookObjectUninit(
    void
    );

#endif // _HOOK_STRUCTURE_H_
