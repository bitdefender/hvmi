/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GPACACHE_H_
#define _GPACACHE_H_

#include "introtypes.h"


///
/// Describes on GPA cache entry.
///
typedef struct _GPA_CACHE_ENTRY
{
    QWORD       Gpa;        ///< Gpa this entry maps to.
    void        *Hva;       ///< Host pointer which maps to Gpa.
    DWORD       HitCount;   ///< Number of times this entry was accessed.
    DWORD       UseCount;   ///< Reference count, incremented by calls to #IntGpaCacheFindAndAdd.
    BOOLEAN     Valid;      ///< True if the entry is valid, false otherwise.
} GPA_CACHE_ENTRY, *PGPA_CACHE_ENTRY;


///
/// Describes one GPA cache line. A line consists of multiple entries.
///
typedef struct _GPA_CACHE_LINE
{
    GPA_CACHE_ENTRY     *Entries;   ///< An array of cache entries.
} GPA_CACHE_LINE, *PGPA_CACHE_LINE;


///
/// Describes one victim cache entry. Entries are added to the victim cache if their UseCount is non-zero
/// on eviction.
///
typedef struct _GPA_CACHE_VICTIM
{
    LIST_ENTRY          Link;       ///< Linked list entry.
    GPA_CACHE_ENTRY     Entry;      ///< The actual cache entry.
} GPA_CACHE_VICTIM, *PGPA_CACHE_VICTIM;


///
/// Describes a GPA cache. The layout consists of LinesCount lines x EntriesCount entries. One can think at
/// it as being EntriesCount associative.
///
typedef struct _GPA_CACHE
{
    DWORD               LinesCount; ///< Number of lines.
    DWORD               EntriesCount; ///< Number of entries per line.

    GPA_CACHE_LINE      *Lines;     ///< Actual array of cache lines.

    LIST_ENTRY          Victims;    ///< List of victim entries evicted from the cache while UseCount is not 0.
} GPA_CACHE, *PGPA_CACHE;


void
IntGpaCacheDump(
    _In_ PGPA_CACHE Cache
    );

INTSTATUS
IntGpaCacheInit(
    _Inout_ PGPA_CACHE *Cache,
    _In_ DWORD LinesCount,
    _In_ DWORD EntriesCount
    );

INTSTATUS
IntGpaCacheUnInit(
    _In_ PGPA_CACHE *Cache
    );

INTSTATUS
IntGpaCacheRelease(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa
    );

INTSTATUS
IntGpaCacheFindAndAdd(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _Out_ void **Hva
    );

INTSTATUS
IntGpaCacheFetchAndAdd(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _In_ DWORD Size,
    _Out_ PBYTE Buffer
    );

INTSTATUS
IntGpaCachePatchAndAdd(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _In_ DWORD Size,
    _In_ PBYTE Buffer
    );

INTSTATUS
IntGpaCacheFlush(
    _In_ PGPA_CACHE Cache
    );

#endif // _GPACACHE_H_
