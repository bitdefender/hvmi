/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_PTS_H_
#define _HOOK_PTS_H_

#include "hook_ptwh.h"


//
// Definitions, flags & constants.
//
#define HOOK_PTS_FLG_DELETE_PT_HOOK     0x00000100
#define HOOK_PTS_FLG_DELETE_PD_HOOK     0x00000200

/// Monitored bits inside the page-table entries. If any of these bits is modified, the translation modification
/// callback will be called.
#define HOOK_PTS_MONITORED_BITS         (PT_P | PD_PS | PT_US | PT_RW | 0x000FFFFFFFFFF000)

#define HOOK_PT_HASH_SIZE               64
#define HOOK_PT_HASH_ID(x)              (((x) >> 12) & (HOOK_PT_HASH_SIZE - 1))
#define HOOK_PT_PAE_ROOT_HASH_ID(x)     (((x) >>  5) & (HOOK_PT_HASH_SIZE - 1))


///
/// @brief Callback invoked on translation modifications.
///
/// This callback is invoked whenever a translation modification takes place for a monitored virtual address.
/// NOTE: If the function needs the virtual address space, it can simply query the current Cr3 value, as
/// translation modification callbacks are always called in the virtual address space in which they happened.
///
/// @param[in]  Context         The user provided context when establishing the swap hook.
/// @param[in]  VirtualAddress  The monitored virtual address.
/// @param[in]  OldEntry        Old page-table entry.
/// @param[in]  NewEntry        New page-table entry.
/// @param[in]  OldPageSize     Old page size.
/// @param[in]  NewPageSize     New page size.
///
typedef INTSTATUS
(*PFUNC_SwapCallback)(
    _In_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    );


///
/// Describes one page table entry hook. Please note that "Page Table" is being generically referred to, as it may be
/// any level page table (PT, PD, PDP, PML4, PML5). Each monitored page-table entry will have exactly one such
/// structure attached. If multiple virtual addresses which translate through this entry are monitored, the ref count
/// will simply be incremented accordingly.
///
typedef struct _HOOK_PTS_ENTRY
{
    HOOK_HEADER         Header;         ///< Hook header - must be present for every hook.
    PHOOK_PTM           PtPaHook;       ///< The PA hook on the PT/PD/PDP/PML4/PML5 entry.
    /// @brief  Physical address of the PT/PD/PDP/PML4/PML5 entry associated to this particular page.
    QWORD               PtPaAddress;
    BOOLEAN             PtPaHookSet;    ///< True if a hook is placed on the PT entry.
    BOOLEAN             IsLeaf;         ///< True if this is the last level of translation.
    /// @brief  This referrers to the entry contained by this PTE. If true, it points to a valid table.
    BOOLEAN             IsValid;
    BOOLEAN             IsPs;           ///< True if this entry is a page size extension, and points to a 2M/4M/1G page.
    BYTE                EntrySize;      ///< 4 (32 bit paging) or 8 (PAE or 64 bit paging)
    BYTE                Level;          ///< Page table level (1 - PT, 5 - PML5)
    HOOK_PTEWS          WriteState;     ///< Write state.
    LIST_ENTRY          Link;           ///< Link inside the containing list.
    LIST_HEAD           ChildrenEntries;///< Children entries. Will be empty for leafs. Each entry is a #HOOK_PTS_ENTRY.
    LIST_HEAD           ContextEntries; ///< The actual contexts. Each context will be a #HOOK_PTS structure.
    DWORD               RefCount;       ///< Number of references.
    WORD                EntryOffset;    ///< Entry offset inside the monitored page-table.
} HOOK_PTS_ENTRY, *PHOOK_PTS_ENTRY;


///
/// A handle to a virtual address monitoring hook. Each hook placed on a virtual address will create such a structure.
/// Placing multiple hooks on the same virtual address will result in multiple such structures being allocated, but
/// the low-level hook structures (for example, #HOOK_PTS_ENTRY) will remain the same. Removing one such hook will not
/// affect other swap hooks set on the same virtual address.
///
typedef struct _HOOK_PTS
{
    HOOK_HEADER         Header;         ///< Hook header - must be present for every hook.
    QWORD               Cr3;            ///< Virtual address space where the address is monitored.
    QWORD               VirtualAddress; ///< The monitored virtual address.
    QWORD               CurEntry;       ///< Current page-table entry.
    QWORD               OldEntry;       ///< Previous page-table entry.
    QWORD               CurPageSize;    ///< Current page size.
    QWORD               OldPageSize;    ///< Previous page size.
    LIST_ENTRY          Link;           ///< List element.
    LIST_ENTRY          PtsLink;        ///< Link inside the HooksPtsList
    PHOOK_PTS_ENTRY     Parent;         ///< The leaf page-table entry hook associated with this address.
    PFUNC_SwapCallback  Callback;       ///< Swap callback.
    BOOLEAN             IntegrityCheckFailed;   ///< True if integrity checks failed on this translation.
} HOOK_PTS, *PHOOK_PTS;


///
/// Global swap hooks state.
///
typedef struct _HOOK_PTS_STATE
{
    LIST_HEAD           *CallbacksList; ///< List of callbacks.
    LIST_HEAD           HooksPtsList;   ///< List of swap hooks.
    LIST_HEAD           HooksRootList[HOOK_PT_HASH_SIZE];   ///< Hash of monitored virtual address spaces.
    LIST_HEAD           RemovedHooksRootList;   ///< List of removed root entries.
    LIST_HEAD           RemovedHooksPtsList;    ///< List of removed PTS entries.
    LIST_HEAD           RemovedHooksPtList;     ///< List of removed page-table entry hooks.
    LIST_HEAD           RemovedHooksPdList;     ///< List of removed page-directory entry hooks.
    LIST_HEAD           RemovedHooksPdpList;    ///< List of removed page-directory pointer entry hooks.
    LIST_HEAD           RemovedHooksPml4List;   ///< List of removed PML4 entry hooks.
    LIST_HEAD           RemovedHooksPml5List;   ///< List of removed PML5 entry hooks.
    BOOLEAN             HooksRemoved;           ///< True if any hook has been removed.
} HOOK_PTS_STATE, *PHOOK_PTS_STATE;



//
// API
//
INTSTATUS
IntHookPtsSetHook(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ PFUNC_SwapCallback Callback,
    _In_opt_ void *Context,
    _In_opt_ void *Parent,
    _In_ DWORD Flags,
    _Out_ PHOOK_PTS *Hook
    );

INTSTATUS
IntHookPtsRemoveHook(
    _Inout_ HOOK_PTS **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookPtsDeleteHook(
    _Inout_ HOOK_PTS **Hook,
    _In_ DWORD Flags
    );

INTSTATUS
IntHookPtsCommitHooks(
    void
    );

INTSTATUS
IntHookPtsInit(
    void
    );

INTSTATUS
IntHookPtsWriteEntry(
    _In_ PHOOK_PTS_ENTRY Entry,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue
    );

INTSTATUS
IntHookPtsCheckIntegrity(
    void
    );

void
IntHookPtsDump(
    void
    );

#endif // _HOOK_PTS_H
