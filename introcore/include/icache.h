/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ICACHE_H_
#define _ICACHE_H_

#include "introtypes.h"
#include "bddisasm.h"


///
/// Describes one invalidation entry. Invalidation entries are created for each guest page that contains cached
/// instructions. If multiple instructions are cached within the same guest page, a single such invalidation
/// entry is created, and the reference count is incremented accordingly. Whenever a write or a remapping takes
/// place for a page that contains cached instructions, this structure will be used to locate all cached
/// instructions, in order to invalidate them.
///
typedef struct _INS_CACHE_INV_ENTRY
{
    LIST_ENTRY          Link;           ///< List entry element.
    QWORD               Gva;            ///< The guest virtual page described by this entry.
    QWORD               Gpa;            ///< The guest physical page described by this entry.
    QWORD               Cr3;            ///< Virtual address space the page belongs to.
    void                *WriteHook;     ///< EPT write hook handle.
    void                *SwapHook;      ///< Swap handle.
    DWORD               RefCount;       ///< Reference count - number of instructions cached inside this page.
    /// @brief  True if there is an instruction inside this entry that spills inside the next page.
    BOOLEAN             Spill;
} INS_CACHE_INV_ENTRY, *PINS_CACHE_INV_ENTRY;


///
/// Describes one cached instruction.
///
typedef struct _INS_CACHE_ENTRY
{
    INSTRUX             Instruction;    ///< The decoded instruction.
    QWORD               Gva;            ///< The instruction guest virtual address
    QWORD               Cr3;            ///< Virtual address space containing the instruction. Can be #IC_ANY_VAS.
    DWORD               RefCount;       ///< Number of times this instruction has been hit.
    INS_CACHE_INV_ENTRY *Invd1;         ///< Invalidation entry for the page containing the instruction.
    INS_CACHE_INV_ENTRY *Invd2;         ///< Invalidation entry for the instructions that cross the page boundary.
    BOOLEAN             Valid;          ///< True if the entry is valid.
    BOOLEAN             Pinned;         ///< True if the entry is pinned (it cannot be evicted).
    BOOLEAN             Global;         ///< True if the entry is global (shared in multiple processes).
} INS_CACHE_ENTRY, *PINS_CACHE_ENTRY;


///
/// One cache line containing multiple entries.
///
typedef struct _INS_CACHE_LINE
{
    INS_CACHE_ENTRY     *Entries;       ///< Array containing the entries.
} INS_CACHE_LINE, *PINS_CACHE_LINE;


///
/// The instruction cache structure.
///
typedef struct _INS_CACHE
{
    DWORD               LinesCount;     ///< Number of lines inside the cache. Must be a power of 2.
    DWORD               EntriesCount;   ///< Number of entries inside each line.
    DWORD               InvCount;       ///< Number of lines inside the invalidation array. Must be a power of 2.

    DWORD               HitCount;       ///< Number of cache hits.
    DWORD               MissCount;      ///< Number of cache misses.
    DWORD               FillRate;       ///< How many entries or occupied by valid instructions.
    DWORD               FlushCount;     ///< Number of times the cache has been flushed.
    DWORD               ReplaceCount;   ///< Number of times entries were evicted & replaced by other ones.
    DWORD               PageFlushCount; ///< Number of page flushes.
    BOOLEAN             Dirty;          ///< True if the ache was modified after the last flush.
    BOOLEAN             Disabled;       ///< True if the cache has been deactivated.
    BYTE                _Reserved1[2];  ///< Padding.
    INS_CACHE_LINE      *Lines;         ///< Array of cache lines.
    LIST_HEAD           *InsInvGva;     ///< Array of invalidation entries.
} INS_CACHE, *PINS_CACHE;


///
/// Constant used to indicate that a cache operation should be applied to every virtual address space. Instructions
/// cached inside kernel space must use this value instead of an actual Cr3 value.
///
#define IC_ANY_VAS      0


//
// API
//
INTSTATUS
IntIcLookupInstruction(
    _In_ PINS_CACHE Cache,
    _Out_ PINSTRUX Instrux,
    _In_ QWORD Gva,
    _In_ QWORD Cr3
    );

INTSTATUS
IntIcFlush(
    _In_ PINS_CACHE Cache
    );

INTSTATUS
IntIcFlushAddress(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva,
    _In_ QWORD Cr3
    );

INTSTATUS
IntIcFlushGvaPage(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Spill
    );

INTSTATUS
IntIcFlushGpaPage(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gpa
    );

INTSTATUS
IntIcFlushVaSpace(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Cr3
    );

INTSTATUS
IntIcAddInstruction(
    _In_ PINS_CACHE Cache,
    _In_ PINSTRUX Instruction,
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Global
    );

INTSTATUS
IntIcCreate(
    _Inout_ INS_CACHE **Cache,
    _In_ DWORD LinesCount,
    _In_ DWORD EntriesCount,
    _In_ DWORD InvCount
    );

INTSTATUS
IntIcDestroy(
    _Inout_ PINS_CACHE *Cache
    );

void
IntIcDumpIcache(
    void
    );

#endif // _ICACHE_H_
