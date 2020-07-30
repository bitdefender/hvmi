/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_CR_H_
#define _HOOK_CR_H_

#include "introtypes.h"


///
/// @brief Called when a control-register write takes place.
///
/// @param[in]  Context     The context, as provided when the CR hook was set.
/// @param[in]  Cr          The written CR.
/// @param[in]  OldValue    Old CR value.
/// @param[in]  NewValue    New CR value.
/// @param[out] Action      Desired action.
///
typedef INTSTATUS
(*PFUNC_CrWriteHookCallback)(
    _In_opt_ void *Context,
    _In_ DWORD Cr,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _Out_ INTRO_ACTION *Action
    );


///
/// Global CR hooks state.
///
typedef struct _CR_HOOK_STATE
{
    LIST_HEAD   CrHooksList;    ///< The list of CR hooks.
    INT64       HooksCount;     ///< Total number of CR hooks.
} CR_HOOK_STATE, *PCR_HOOK_STATE;


///
/// Describes one CR hook.
///
typedef struct _HOOK_CR
{
    LIST_ENTRY            Link;         ///< List entry link.
    DWORD                 Flags;        ///< Flags. Can be used by the caller.
    DWORD                 Cr;           ///< The CR number.
    BOOLEAN               Disabled;     ///< If true, the hook is disabled, and the callback will no longer be called.
    PFUNC_CrWriteHookCallback Callback; ///< Callback.
    void                 *Context;      ///< Optional context, will be passed to the callback.
} HOOK_CR, *PHOOK_CR;


//
// CR hooks related API
//
INTSTATUS
IntHookCrSetHook(
    _In_ DWORD Cr,
    _In_ DWORD Flags,
    _In_ PFUNC_CrWriteHookCallback Callback,
    _In_opt_ void *Context,
    _Out_opt_ HOOK_CR **Hook
    );

INTSTATUS
IntHookCrRemoveHook(
    _In_ HOOK_CR *Hook
    );

INTSTATUS
IntHookCrCommit(
    void
    );

INTSTATUS
IntHookCrInit(
    void
    );

INTSTATUS
IntHookCrUninit(
    void
    );

#endif // _HOOK_CR_H_
