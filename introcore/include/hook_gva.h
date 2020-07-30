/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_GVA_H_
#define _HOOK_GVA_H_

#include "hook_gpa.h"
#include "hook_pts.h"

typedef struct _HOOK_HEADER HOOK_HEADER;


///
/// This structures describes a hooked guest virtual page. Page-table interception and guest physical page
/// hooks are handled internally.
///
typedef struct _HOOK_GVA
{
    HOOK_HEADER         Header;             ///< The hook header.
    LIST_ENTRY          Link;               ///< List entry element.
    union
    {
        /// @brief  The read/write/execute access callback. Valid if Type != #IG_EPT_HOOK_NONE.
        PFUNC_EptViolationCallback Access;
        PFUNC_SwapCallback          Swap;   ///< The swap callback. Valid if Type == #IG_EPT_HOOK_NONE.
    } Callback;

    /// @brief   The actual guest physical page hook. Valid as long as the page is mapped.
    PHOOK_GPA           GpaHook;
    PHOOK_PTS           PtsHook;            ///< The page tables hook.
    QWORD               GvaPage;            ///< Guest virtual page base address, aligned to 4K.
    WORD                Offset;             ///< Offset inside the 4K page, interval [0, 4095].
    WORD                Length;             ///< Length of the hook, interval [1, 4096].
    /// @brief  Hash computed on the content of the page. Valid only if IsIntegrityOn is true.
    DWORD               Hash;
    /// @brief  True if integrity checks are enabled for this page. Integrity checks are enabled
    /// if the this is a write hook on a kernel page.
    BOOLEAN             IsIntegrityOn;
    BOOLEAN             IsPageWritable;     ///< True if the page is writable, false otherwise.
} HOOK_GVA, *PHOOK_GVA;


///
/// Global GVA hooks state.
///
typedef struct _HOOK_GVA_STATE
{
    LIST_HEAD           GvaHooks;           ///< The list of GVA hooks.
    LIST_HEAD           RemovedHooksList;   ///< The list of removed GVA hooks. Hooks will stay in this list until the
    ///< #IntHookGvaCommitHooks function is called.
    BOOLEAN             HooksRemoved;       ///< True if at least one hook has been removed since the last commit.
} HOOK_GVA_STATE, *PHOOK_GVA_STATE;



//
// API
//
INTSTATUS
IntHookGvaSetHook(
    _In_ QWORD Cr3,
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_ BYTE Type,
    _In_ void *Callback,
    _In_opt_ void *Context,
    _In_opt_ void *ParentHook,
    _In_opt_ DWORD Flags,
    _Out_opt_ HOOK_GVA **GvaHook
    );

INTSTATUS
IntHookGvaRemoveHook(
    _Inout_ HOOK_GVA **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookGvaDeleteHook(
    _Inout_ HOOK_GVA **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookGvaCommitHooks(
    void
    );

INTSTATUS
IntHookGvaInit(
    void
    );

#endif // _HOOK_GVA_H_
