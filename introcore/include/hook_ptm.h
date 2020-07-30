/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_PTM_H_
#define _HOOK_PTM_H_

#include "hook_gpa.h"


///
/// This structure describes one monitored page-table.
///
typedef struct _HOOK_PTM_TABLE
{
    HOOK_HEADER         Header;         ///< Hook header - used by all memory hooks.
    LIST_ENTRY          Link;           ///< List entry link.
    QWORD               Gpa;            ///< The page-table guest physical address.
    PHOOK_GPA           GpaHook;        ///< The GPA hook set on this page-table.
    BOOLEAN             GpaHookSet;     ///< True if the GPA hook is set.
    /// @brief  Number of references - number of #HOOK_PTM structures that point to this entry.
    DWORD               RefCount;
    DWORD               DelCount;       ///< Number of delete requests. The entry will be deleted when this reaches 0.
    DWORD               EntriesCount;   ///< Number of entries present inside this page-table. 4, 1024 or 512.
    /// @brief  A list of hooked entries. When a #HOOK_PTS_ENTRY is created for entry at offset X,
    /// Entries[x] will contain a pointer to that entry.
    LIST_ENTRY          *Entries;
} HOOK_PTM_TABLE, *PHOOK_PTM_TABLE;


///
/// Public handle for the page-table hooks. Each call to IntHookPtmSetHook will return a freshly allocated
/// #HOOK_PTM structure. However, only a single #HOOK_PTM_TABLE will be allocated for each distinct page-table.
/// Therefore, removing a #HOOK_PTM will only decrement the reference count of the associated #HOOK_PTM_TABLE
/// hook, which will be removed only when the last pointing #HOOK_PTM is removed.
///
typedef struct _HOOK_PTM
{
    HOOK_HEADER                 Header;         ///< Hook header - used by all memory hooks.
    LIST_ENTRY                  Link;           ///< List entry link.
    QWORD                       Address;        ///< Guest physical address of the monitored page-table entry.
    PHOOK_PTM_TABLE             PtHook;         ///< The actual page-table hook.
    /// @brief  Modification callback, called whenever an entry inside this page-table is modified.
    PFUNC_EptViolationCallback  Callback;
} HOOK_PTM, *PHOOK_PTM;


#define PTM_HOOK_TABLE_SIZE             1024
#define PTM_HOOK_ID(addr)               (((addr) >> 12) & (PTM_HOOK_TABLE_SIZE - 1))
#define PTM_PAE_ROOT_HOOK_ID(addr)      (((addr) >>  5) & (PTM_HOOK_TABLE_SIZE - 1))


///
/// Global page-table hook state.
///
typedef struct _HOOK_PTM_STATE
{
    LIST_ENTRY          PtmHooks[PTM_HOOK_TABLE_SIZE];  ///< Hash of monitored address spaces.
    LIST_ENTRY          RemovedPtmHooks;    ///< List of removed page-table hooks (#HOOK_PTM_TABLE).
    LIST_ENTRY          RemovedPtHooks;     ///< List of removed PTM hooks (#HOOK_PTM).
    BOOLEAN             HooksRemoved;       ///< True if hooks have been removed.
} HOOK_PTM_STATE, *PHOOK_PTM_STATE;


//
// API
//
INTSTATUS
IntHookPtmSetHook(
    _In_ QWORD Address,
    _In_ PFUNC_EptViolationCallback Callback,
    _In_ void *Context,
    _In_ void *ParentHook,
    _In_ DWORD Flags,
    _Out_opt_ PHOOK_PTM *Hook
    );

INTSTATUS
IntHookPtmRemoveHook(
    _Inout_ HOOK_PTM **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookPtmDeleteHook(
    _In_ HOOK_PTM **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookPtmCommitHooks(
    void
    );

INTSTATUS
IntHookPtmInit(
    void
    );

#endif // _HOOK_PTM_H_
