/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_GPA_H_
#define _HOOK_GPA_H_

#include "queue.h"

typedef struct _HOOK_HEADER HOOK_HEADER;

///
/// @brief EPT callback handler.
///
/// Such a callback is called whenever an access is made to a hooked memory region. The callback must set the
/// Action argument to the desired action upon return. In order to allow an access, set it to #introGuestAllowed.
/// In order to block an attempt, set it to #introGuestNotAllowed. In order to retry the instruction, set it to
/// #introGuestRetry. Note that if multiple callbacks exist for the same region, each one will return its own
/// action. In this case, actions have a predetermined priority: the least priority is #introGuestAllowed, while
/// the highest priority is #introGuestRetry. This means that if two callbacks return different actions, the
/// numerically higher action (as given by the enum values) will be considered.
///
/// @param[in]  Context     User-supplied context (may contain anything, including NULL).
/// @param[in]  Hook        The hook handle (points to the GPA hook structure).
/// @param[in]  Address     The accessed guest physical address.
/// @param[out] Action      Upon return, it must contain the action Introcore and the HV must take for the access.
///                         Please refer to #INTRO_ACTION member fields for more info.
///
typedef INTSTATUS
(*PFUNC_EptViolationCallback)(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    );


///
/// Describes one guest physical address hook, for a given access type.
///
typedef struct _HOOK_GPA
{
    HOOK_HEADER                 Header;         ///< Hook header.
    LIST_ENTRY                  Link;           ///< List entry element.

    QWORD                       GpaPage;        ///< The page where the hook is set.
    WORD                        Offset;         ///< The offset within the page where the hook starts. 0-4095 valid.
    WORD                        Length;         ///< The length, in bytes, of the hook. 1-4096 valid.

    PFUNC_EptViolationCallback  Callback;       ///< The callback for this hook.

    QUEUE_ENTRY                 LinkRemoved;    ///< Link element for the removed hooks list.
} HOOK_GPA, *PHOOK_GPA;


///
/// Describes one sub-page permissions hook entry. Such entries are allocated only for write hooks that span
/// less than a page (4K) in size.
///
typedef struct _HOOK_SPP_ENTRY
{
    QWORD               OldSpp;         ///< Old SPP value. Usually indicates full write access to the entire page.
    QWORD               CurSpp;         ///< Current SPP permissions.
    DWORD               SppCount[32];   ///< Number of write hooks placed on each 128 bytes region within the page.
} HOOK_SPP_ENTRY, *PHOOK_SPP_ENTRY;


///
/// Introcore shadow EPT structure. Each guest physical page that is hooked by Introcore
/// will have such an entry associated.
///
typedef struct _HOOK_EPT_ENTRY
{
    LIST_ENTRY          Link;           ///< List entry element.
    QWORD               GpaPage;        ///< Guest physical page address.

    DWORD               ReadCount;      ///< Number of read EPT hooks.
    DWORD               WriteCount;     ///< Number of write EPT hooks.
    DWORD               ExecuteCount;   ///< Number of execute EPT hooks.
    DWORD               PtCount;        ///< Number of PT hooks.
    DWORD               ConvCount;      ///< Number of convertible pages.
    /// @brief SPP entry. Allocated only for write hooks that are less than a page in size.
    HOOK_SPP_ENTRY      *Spp;
} HOOK_EPT_ENTRY, *PHOOK_EPT_ENTRY;


#define GPA_HOOK_TABLE_SIZE             1024    ///< Size of the GPA hook hash.
#define GPA_HOOK_ID(addr)               (((addr) >> 12) & (GPA_HOOK_TABLE_SIZE - 1))

#define GPA_EPT_TABLE_SIZE              4096    ///< Size of the EPT entries hash.
#define GPA_EPT_ID(addr)                (((addr) >> 12) & (GPA_EPT_TABLE_SIZE - 1))

#define GPA_REF_COUNT(epte)             (((QWORD)((epte)->ReadCount) + \
                                        (QWORD)((epte)->WriteCount) + \
                                        ((QWORD)(epte)->ExecuteCount) + \
                                        ((QWORD)(epte)->PtCount)))

#define MAX_HOOK_COUNT                  UINT32_MAX  ///< Total number of hooks supported for each type.


///
/// Global GPA hooks state.
///
typedef struct _HOOK_GPA_STATE
{
    LIST_HEAD           GpaHooksWrite[GPA_HOOK_TABLE_SIZE];     ///< Hash table of write hooks.
    LIST_HEAD           GpaHooksRead[GPA_HOOK_TABLE_SIZE];      ///< Hash table of read hooks.
    LIST_HEAD           GpaHooksExecute[GPA_HOOK_TABLE_SIZE];   ///< Hash table of execute hooks.

    QUEUE_HEAD          RemovedHooksWrite;              ///< List of removed write hooks.
    QUEUE_HEAD          RemovedHooksRead;               ///< List of removed read hooks.
    QUEUE_HEAD          RemovedHooksExecute;            ///< List of removed execute hooks.

    /// @brief Hash table containing the EPT entries elements (HOOK_EPT_ENTRY).
    LIST_HEAD           EptEntries[GPA_EPT_TABLE_SIZE];

    INT64               HooksCount;                     ///< Total number of hooks set.

    BOOLEAN             HooksRemoved;                   ///< True if hooks were removed, and we must do the cleanup..
    BOOLEAN             VeEnabled;                      ///< True if VE filtering is enabled.
    BOOLEAN             PtCacheEnabled;                 ///< True if the PT cache is active inside the guest.
    BOOLEAN             SppEnabled;                     ///< True if SPP support is present and enabled.
} HOOK_GPA_STATE, *PHOOK_GPA_STATE;


//
// API
//
PHOOK_EPT_ENTRY
IntHookGpaGetExistingEptEntry(
    _In_ QWORD GpaPage
    );

INTSTATUS
IntHookGpaSetHook(
    _In_ QWORD Gpa,
    _In_ DWORD Length,
    _In_ BYTE  Type,
    _In_ PFUNC_EptViolationCallback Callback,
    _In_opt_ void *Context,
    _In_opt_ void *ParentHook,
    _In_opt_ DWORD Flags,
    _Out_opt_ HOOK_GPA **Hook
    );

INTSTATUS
IntHookGpaRemoveHook(
    _Inout_ HOOK_GPA **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookGpaDeleteHook(
    _In_ HOOK_GPA **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookGpaDisableHook(
    _In_ HOOK_GPA *Hook
    );

INTSTATUS
IntHookGpaEnableHook(
    _In_ HOOK_GPA *Hook
    );

INTSTATUS
IntHookGpaCommitHooks(
    void
    );

INTSTATUS
IntHookGpaIsPageHooked(
    _In_ QWORD Gpa,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    );

INTSTATUS
IntHookGpaEnableVe(
    void
    );

INTSTATUS
IntHookGpaDisableVe(
    void
    );

INTSTATUS
IntHookGpaInit(
    void
    );

void
IntHookGpaDump(
    void
    );

INTSTATUS
IntHookGpaEnablePtCache(
    void
    );

INTSTATUS
IntHookGpaDisablePtCache(
    void
    );

INTSTATUS
IntHookGpaGetEPTPageProtection(
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    );

INTSTATUS
IntHookGpaFindConvertible(
    void
    );

#endif // _HOOK_GPA_H_
