/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VASMONITOR_H_
#define _VASMONITOR_H_

#include "hook_ptwh.h"


///
/// @brief Translation modification callback.
///
/// Callback invoked for VA space modifications. Whenever a translation is modified, the callback is invoked.
/// IMPORTANT: PageSize is the size of the NewEntry. If OldEntry and NewEntry are ALWAYS the entries located
/// at the same level: for example, PD. Even if VirtualAddress was mapped as a 4K page and then it is remapped
/// as a 2M page, OldEntry and NewEntry will both be the PD entries, so be careful.
///
/// @param[in]  Context         The context, as supplied when starting to monitor the address space.
/// @param[in]  VirtualAddress  Modified virtual address.
/// @param[in]  OldEntry        Old page-table entry.
/// @param[in]  NewEntry        New page-table entry.
/// @param[in]  PageSize        The size of the newly mapped page.
///
typedef INTSTATUS
(*PFUNC_VaSpaceModificationCallback)(
    _In_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD PageSize
    );


#define VAS_COMPUTE_GLA_64(Base, Index, Level)      (PAGE_SX((Base) | ((QWORD)(Index) << ((((Level) - 1) * 9) + 12))))
#define VAS_COMPUTE_GLA_PAE(Base, Index, Level)     ((Base) | ((QWORD)(Index) << ((((Level) - 1) * 9) + 12)))
#define VAS_COMPUTE_GLA_32(Base, Index, Level)      ((Base) | ((QWORD)(Index) << ((((Level) - 1) * 10) + 12)))

#define VAS_COMPUTE_GLA(Base, Index, Level, Pg)     (                           \
        (Pg) == PAGING_5_LEVEL_MODE ? VAS_COMPUTE_GLA_64((Base), (Index), (Level)) : \
        (Pg) == PAGING_4_LEVEL_MODE ? VAS_COMPUTE_GLA_64((Base), (Index), (Level)) : \
        (Pg) == PAGING_PAE_MODE ? VAS_COMPUTE_GLA_PAE((Base), (Index), (Level)) : \
        (Pg) == PAGING_NORMAL_MODE ? VAS_COMPUTE_GLA_32((Base), (Index), (Level)) : 0 \
    )

#define VAS_TRANSITIONS_THRESHOLD       64
#define VAS_TOTAL_WRITES_THESHOLD       4096


///
/// One page table entry that points to another table.
///
typedef struct _VAS_TABLE_ENTRY
{
    HOOK_PTEWS          WriteState;     ///< Write state of each page-table entry.
} VAS_TABLE_ENTRY, *PVAS_TABLE_ENTRY;


///
/// Describes one entire monitored page table.
///
typedef struct _VAS_TABLE
{
    struct _VAS_ROOT    *Root;          ///< The root handle.
    void                *WriteHook;     ///< The write hook handle.
    PVAS_TABLE_ENTRY    Entries;        ///< Children entries.
    struct _VAS_TABLE   **Tables;       ///< Pointer to children tables, for each valid entry. NULL for leafs.
    QWORD               LinearAddress;  ///< The first linear address translated by this table.
    DWORD               WriteCount;     ///< The number of times this table has been written.
    /// @brief  The number of entries. It can vary from 4 to 512 to 1024, depending on mode.
    WORD                EntriesCount;
    BYTE                Level;          ///< The level of the current page table.
    BYTE                PagingMode;     ///< Paging mode.
} VAS_TABLE, *PVAS_TABLE;


///
/// The root structure. This structure is used as a handle when placing virtual address space hooks.
///
typedef struct _VAS_ROOT
{
    LIST_ENTRY          Link;           ///< List entry link.
    QWORD               Cr3;            ///< Monitored virtual address space.
    void                *Context;       ///< Optional context, will be passed to the callback.
    QWORD               MonitoredBits;  ///< Monitored bits inside page-table entries.
    PFUNC_VaSpaceModificationCallback Callback; ///< Will be invoked whenever the VA described by this entry modifies.
    /// @brief  This entry will contain the data associated to the PML4/PDP/PD - the first level.
    PVAS_TABLE          Table;
} VAS_ROOT, *PVAS_ROOT;



//
// API
//
INTSTATUS
IntVasStartMonitorVaSpace(
    _In_ QWORD Cr3,
    _In_ PFUNC_VaSpaceModificationCallback Callback,
    _In_ void *Context,
    _In_ QWORD MonitoredBits,
    _Out_ void **Root
    );

INTSTATUS
IntVasStopMonitorVaSpace(
    _In_opt_ QWORD Cr3,
    _In_opt_ PVAS_ROOT Root
    );

INTSTATUS
IntVasDump(
    _In_ QWORD Cr3
    );

INTSTATUS
IntVasInit(
    void
    );

INTSTATUS
IntVasUnInit(
    void
    );


#endif // _VASMONITOR_H_
