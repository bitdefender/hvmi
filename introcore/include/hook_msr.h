/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_MSR_H_
#define _HOOK_MSR_H_

#include "introtypes.h"


///
/// @brief Model specific register access callback.
///
/// @param[in]  Msr             The accessed MSR.
/// @param[in]  Flags           Indicates read or write access. See #IG_MSR_HOOK_TYPE.
/// @param[out] Action          Desired action.
/// @param[in]  Context         Optional context, as passed to the hook set function.
/// @param[in]  OriginalValue   Original MSR value.
/// @param[in, out] NewValue    New MSR value. Can be overridden, but whether this is handled by the HV or not
///                             is implementation specific. It is advisable to not modify this value.
///
typedef INTSTATUS
(*PFUNC_MsrReadWriteHookCallback)(
    _In_ DWORD Msr,
    _In_ DWORD Flags,
    _Out_ INTRO_ACTION *Action,
    _In_opt_ void *Context,
    _In_opt_ QWORD OriginalValue,
    _Inout_opt_ QWORD *NewValue
    );


///
/// Global MSR hooks state.
///
typedef struct _MSR_HOOK_STATE
{
    LIST_HEAD   MsrHooksList;   ///< The list of MSR hooks.
    INT64       HooksCount;     ///< Total number of MSR hooks.
} MSR_HOOK_STATE, *PMSR_HOOK_STATE;


///
/// Describes a MSR hook.
///
typedef struct _HOOK_MSR
{
    LIST_ENTRY                      Link;           ///< List entry element.
    DWORD                           Msr;            ///< The hooked MSR.
    DWORD                           Flags;          ///< Access flags. See #IG_MSR_HOOK_TYPE.
    BOOLEAN                         WasEnabled;     ///< True if MSR exiting for this MSR was already enabled.
    BOOLEAN                         Disabled;       ///< True if this hook has been removed/disabled.
    PFUNC_MsrReadWriteHookCallback  Callback;       ///< The callback.
    void                            *Context;       ///< Optional context.
} HOOK_MSR, *PHOOK_MSR;


//
// MSR hooks related API
//
INTSTATUS
IntHookMsrSetHook(
    _In_ DWORD Msr,
    _In_ DWORD Flags,
    _In_ PFUNC_MsrReadWriteHookCallback Callback,
    _In_opt_ void *Context,
    _Out_opt_ void **Hook
    );

INTSTATUS
IntHookMsrRemoveHook(
    _In_ HOOK_MSR *Hook
    );

INTSTATUS
IntHookMsrCommit(
    void
    );

INTSTATUS
IntHookMsrInit(
    void
    );

INTSTATUS
IntHookMsrUninit(
    void
    );

#endif // _HOOK_MSR_H_
