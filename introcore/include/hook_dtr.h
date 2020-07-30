/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_DTR_H_
#define _HOOK_DTR_H_

#include "introcpu.h"
#include "introtypes.h"


///
/// @brief Called when a descriptor table register is accessed.
///
/// @param[in]  OldDtr      Old descriptor table register value.
/// @param[in]  NewDtr      New descriptor table register value.
/// @param[in]  Flags       A combination of #IG_DESC_ACCESS.
/// @param[out] Action      The desired action.
///
typedef INTSTATUS
(*PFUNC_DtrReadWriteHookCallback)(
    _In_ DTR *OldDtr,
    _In_ DTR *NewDtr,
    _In_ DWORD Flags,
    _Out_ INTRO_ACTION *Action
    );


///
/// Global DTR hooks state.
///
typedef struct _DTR_HOOK_STATE
{
    LIST_HEAD   DtrHooksList;   ///< The list of DTR hooks.
    INT64       HooksCount;     ///< The total number of DTR hooks.
} DTR_HOOK_STATE, *PDTR_HOOK_STATE;


///
/// Describes a DTR hook.
///
typedef struct _HOOK_DTR
{
    LIST_ENTRY                      Link;       ///< List entry element.
    DWORD                           Flags;      ///< Hook flags, a combination of #IG_DESC_ACCESS.
    BOOLEAN                         Disabled;   ///< True if the hook has been removed/disabled.
    PFUNC_DtrReadWriteHookCallback  Callback;   ///< The callback.
} HOOK_DTR, *PHOOK_DTR;


//
// DTR hooks related API
//
INTSTATUS
IntHookDtrSetHook(
    _In_ DWORD Flags,
    _In_ PFUNC_DtrReadWriteHookCallback Callback,
    _Out_opt_ void **Hook
    );

INTSTATUS
IntHookDtrRemoveHook(
    _In_ HOOK_DTR *Hook
    );

INTSTATUS
IntHookDtrCommit(
    void
    );

INTSTATUS
IntHookDtrInit(
    void
    );

INTSTATUS
IntHookDtrUninit(
    void
    );

#endif // _HOOK_DTR_H_
