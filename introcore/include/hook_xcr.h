/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_XCR_H_
#define _HOOK_XCR_H_

#include "introtypes.h"


///
/// @brief Extended control register write callback.
///
/// @param[in]  Context     The optional context, as passed to the XCR set hook function.
/// @param[in]  Xcr         The written XCR.
/// @param[out] Action      Desired action.
///
typedef INTSTATUS
(*PFUNC_XcrWriteHookCallback)(
    _In_opt_ void *Context,
    _In_ DWORD Xcr,
    _Out_ INTRO_ACTION *Action
    );


///
/// Global XCR hooks state.
///
typedef struct _XCR_HOOK_STATE
{
    LIST_HEAD           XcrHooksList;   ///< The list of XCR hooks.
    INT64               HooksCount;     ///< Total number of XCR hooks.
} XCR_HOOK_STATE, *PXCR_HOOK_STATE;


///
/// Describes an XCR hook.
///
typedef struct _HOOK_XCR
{
    LIST_ENTRY                  Link;       ///< List entry element.
    DWORD                       Flags;      ///< Flags. Can be used by the caller.
    DWORD                       Xcr;        ///< Intercepted XCR.
    BOOLEAN                     Disabled;   ///< If true, the hook has been removed/disabled.
    PFUNC_XcrWriteHookCallback  Callback;   ///< Callback.
    void                        *Context;   ///< Optional context.
} HOOK_XCR, *PHOOK_XCR;


//
// XCR hooks related API
//
INTSTATUS
IntHookXcrSetHook(
    _In_ DWORD Xcr,
    _In_ DWORD Flags,
    _In_ PFUNC_XcrWriteHookCallback Callback,
    _In_opt_ void *Context,
    _Out_opt_ HOOK_XCR **Hook
    );

INTSTATUS
IntHookXcrRemoveHook(
    _In_ HOOK_XCR *Hook
    );

INTSTATUS
IntHookXcrCommit(
    void
    );

INTSTATUS
IntHookXcrInit(
    void
    );

INTSTATUS
IntHookXcrUninit(
    void
    );

#endif // _HOOK_XCR_H_
