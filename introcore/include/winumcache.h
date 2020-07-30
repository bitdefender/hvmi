/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINUM_CACHE_H_
#define _WINUM_CACHE_H_

#include "introcrt.h"

typedef struct _WIN_PROCESS_MODULE WIN_PROCESS_MODULE;

/// We can have up to this many exports pointing to the same RVA.
#define MAX_OFFSETS_PER_NAME    10


///
/// Describes a cached exported RVA (Relative Virtual Address).
///
typedef struct _WINUM_CACHE_EXPORT
{
    RBNODE      RbNode;                             ///< RB tree node entry.

    DWORD       Rva;                                ///< The RVA of this export.
    DWORD       NameHashes[MAX_OFFSETS_PER_NAME];   ///< Hashes of the names pointing to this RVA.
    DWORD       NameLens[MAX_OFFSETS_PER_NAME];     ///< Length of each name pointing to this RVA.
    DWORD       NameOffsets[MAX_OFFSETS_PER_NAME];  ///< Name RVAs pointing to this exported RVA.
    DWORD       NumberOfOffsets;                    ///< Number of symbols pointing to the exported RVA.

    /// @brief The names pointing to this RVA. Each name will point inside
    /// the Names structure inside #WINUM_CACHE_EXPORTS.
    PCHAR       Names[MAX_OFFSETS_PER_NAME];
} WINUM_CACHE_EXPORT, *PWINUM_CACHE_EXPORT;


///
/// This structure describes the exported memory related functions.
///
typedef struct _WINUM_CACHE_MEMORY_FUNCS
{
    union
    {
        struct
        {
            DWORD       MemcpyRva;          ///< RVA of the memcpy function.
            DWORD       MemcpySRva;         ///< RVA of the memcpys function.
            DWORD       MemmoveRva;         ///< RVA of the memmove function.
            DWORD       MemmoveSRva;        ///< RVA of the memmoves function.
            DWORD       MemsetRva;          ///< RVA of the memset function.
        };

        DWORD           FuncArray[5];       ///< Array aliasing the above exported memory functions.
    };
} WINUM_CACHE_MEMORY_FUNCS, *PWINUM_CACHE_MEMORY_FUNCS;


///
/// Describes an exports cache.
///
typedef struct _WINUM_CACHE_EXPORTS
{
    RBTREE                  Tree;           ///< The RB tree containing all the exports (#WINUM_CACHE_EXPORT entries).
    WINUM_CACHE_EXPORT      *Array;         ///< The array of #WINUM_CACHE_EXPORT entries.

    /// @brief  A pointer to a contiguous memory area containing all the exported names.
    PCHAR                   Names;

    DWORD                   StartNames;     ///< First RVA pointing to the exported names.
    DWORD                   EndNames;       ///< Last RVA pointing to the exported names.

} WINUM_CACHE_EXPORTS, *PWINUM_CACHE_EXPORTS;


///
/// Describes one module cache.
///
typedef struct _WINUM_MODULE_CACHE
{
    LIST_ENTRY                  Link;           ///< Link inside the global list of module caches.

    DWORD                       ModuleNameHash; ///< The hash on the name of the cached module.

    struct
    {
        DWORD                   EatRva;         ///< RVA of the exports table.
        DWORD                   EatSize;        ///< Size of the exports table.

        DWORD                   IatRva;         ///< RVA of the imports table.
        DWORD                   IatSize;        ///< Size of the imports table.

        DWORD                   TimeDateStamp;  ///< Module time & date stamp.
        DWORD                   SizeOfImage;    ///< Size of image.
    } Info;

    WINUM_CACHE_EXPORTS         Exports;        ///< The exports cache.
    WINUM_CACHE_MEMORY_FUNCS    MemFuncs;       ///< Memory related functions RVAs.

    BYTE                        *Headers;       ///< A buffer containing the MZ/PE headers of this module.

    BOOLEAN                     Wow64;          ///< True if this module is Wow64.

    BOOLEAN                     ExportDirRead;  ///< True if the exports directory has been read.
    BOOLEAN                     MemoryFuncsRead;///< True if the memory functions have been identified.

    /// @brief  True if this caches was created for a module loaded by a statically detected process. Dirty caches
    /// are NOT reused by other loaded modules, and they will be destroyed when the module is unloaded.
    BOOLEAN                     Dirty;

} WINUM_MODULE_CACHE, *PWINUM_MODULE_CACHE;


/// @brief  We will not cache more than this many exports.
#define WINUMCACHE_MAX_EXPORTS  10000u


//
// API
//
INTSTATUS
IntWinUmModCacheSetHeaders(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_reads_bytes_(4096) BYTE *Headers
    );

void
IntWinUmModCacheGet(
    _In_ WIN_PROCESS_MODULE *Module
    );

void
IntWinUmModCacheRelease(
    _In_ WINUM_MODULE_CACHE *Cache
    );

void
IntWinUmCacheUninit(
    void
    );

WINUM_CACHE_EXPORT *
IntWinUmModCacheExportFind(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ DWORD Rva,
    _In_ DWORD ErrorRange
    );

BOOLEAN
IntWinUmCacheIsExportDirRead(
    _In_ WIN_PROCESS_MODULE *Module
    );

WINUM_CACHE_EXPORT *
IntWinUmCacheGetExportFromRange(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ QWORD Gva,
    _In_ DWORD Length
    );

#endif // _WINUM_CACHE_H_
