/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "gpacache.h"
#include "glue.h"
#include "introcrt.h"


static __inline DWORD
IntGpaCacheHashLine(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa
    )
///
/// @brief Compute the line index for a given address.
///
/// Computes the line index from a Gpa. The lines index simply represents the lowest page number bits; for
/// example, if 16 lines count are used, and the Gpa is 0x12345678, the hash/line index will be
/// (0x12345678 >> 12) & (16 - 1) = 5.
///
/// @param[in] Cache The GPA cache.
/// @param[in] Gpa   The Gpa for which we compute the line index.
///
/// @return The line index computed from the given Gpa.
///
{
    return (Gpa >> 12) & (Cache->LinesCount - 1);
}


static INTSTATUS
IntGpaCacheAddVictim(
    _In_ PGPA_CACHE Cache,
    _In_ PGPA_CACHE_ENTRY Entry
    )
///
/// @brief Add an entry in the victim cache.
///
/// Adds a victim entry for the provided GPA cache. Victims are added when entries which are still referenced
/// must be evicted to make space for other entries. The victim cache is simply a linked list of evicted entries.
///
/// @param[in] Cache The GPA cache.
/// @param[in] Entry The cache entry that must be added to the victim cache.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return #INT_STATUS_INSUFFICIENT_RESOURCES If memory could not be allocated for the victim entry.
///
{
    GPA_CACHE_VICTIM *pVictim = HpAllocWithTag(sizeof(*pVictim), IC_TAG_GPCV);
    if (NULL == pVictim)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(&pVictim->Entry, Entry, sizeof(GPA_CACHE_ENTRY));

    InsertTailList(&Cache->Victims, &pVictim->Link);

    return INT_STATUS_SUCCESS;
}


void
IntGpaCacheDump(
    _In_ PGPA_CACHE Cache
    )
///
/// @brief Dumps the entire contents of the GPA cache.
///
/// @param [in] Cache The GPA cache to dump.
///
{
    DWORD i, j;
    QWORD totalHitCount = 0;

    LOG("Gpa Cache:\n");

    NLOG("Number of lines:  %d\n", Cache->LinesCount);
    NLOG("Entries per line: %d\n", Cache->EntriesCount);

    // Dump the entries inside the Cache
    for (i = 0; i < Cache->LinesCount; i++)
    {
        QWORD lineHitCount = 0;

        for (j = 0; j < Cache->EntriesCount; j++)
        {
            if (Cache->Lines[i].Entries[j].Valid)
            {
                NLOG("%04d:%02d: 0x%016llx:%p, %04d %04d %d\n",
                     i, j,
                     Cache->Lines[i].Entries[j].Gpa,
                     Cache->Lines[i].Entries[j].Hva,
                     Cache->Lines[i].Entries[j].HitCount,
                     Cache->Lines[i].Entries[j].UseCount,
                     Cache->Lines[i].Entries[j].Valid);

                totalHitCount += Cache->Lines[i].Entries[j].HitCount;
                lineHitCount += Cache->Lines[i].Entries[j].HitCount;
            }
        }

        if (lineHitCount > 0)
        {
            NLOG("    HitCount: %lld\n", lineHitCount);
        }
    }

    NLOG("TOTALHC: %lld\n", totalHitCount);
}


INTSTATUS
IntGpaCacheInit(
    _Inout_ PGPA_CACHE *Cache,
    _In_ DWORD LinesCount,
    _In_ DWORD EntriesCount
    )
///
/// @brief Initialize a GPA cache.
///
/// Initializes a new GPA cache. The GPA cache will have a layout given by LinesCount and EntriesCount:
/// it will be EntriesCount associative, with LinesCount lines, for a total of EntriesCount * LinesCount
/// entries.
///
/// @param[in,out] Cache        Will contain, upon successful return, the allocated GPA cache.
/// @param[in]    LinesCount    The number of cache lines.
/// @param[in]    EntriesCount  The number of entries per cache line.
///
/// @return #INT_STATUS_SUCCESS if the cache has been successfully created.
/// @return #INT_STATUS_INSUFFICIENT_RESOURCES If memory could not be allocated.
/// @return INT_STATUS_INVALID_PARAMETER If an invalid parameter has been supplied.
///
{
    INTSTATUS status;
    GPA_CACHE *pCache;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // LinesCount must be power of two.
    if (0 != (LinesCount & (LinesCount - 1)))
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pCache = HpAllocWithTag(sizeof(*pCache), IC_TAG_GPCA);
    if (NULL == pCache)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pCache->LinesCount = LinesCount;
    pCache->EntriesCount = EntriesCount;

    pCache->Lines = HpAllocWithTag(sizeof(*pCache->Lines) * LinesCount, IC_TAG_GPCA);
    if (NULL == pCache->Lines)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    for (DWORD i = 0; i < LinesCount; i++)
    {
        pCache->Lines[i].Entries = HpAllocWithTag(sizeof(*pCache->Lines[i].Entries) * EntriesCount, IC_TAG_GPCA);
        if (NULL == pCache->Lines[i].Entries)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_and_exit;
        }
    }

    InitializeListHead(&pCache->Victims);

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pCache)
        {
            if (NULL != pCache->Lines)
            {
                for (DWORD i = 0; i < LinesCount; i++)
                {
                    if (NULL != pCache->Lines[i].Entries)
                    {
                        HpFreeAndNullWithTag(&pCache->Lines[i].Entries, IC_TAG_GPCA);
                    }
                }

                HpFreeAndNullWithTag(&pCache->Lines, IC_TAG_GPCA);
            }

            HpFreeAndNullWithTag(&pCache, IC_TAG_GPCA);
        }
    }

    *Cache = pCache;

    return status;
}


INTSTATUS
IntGpaCacheUnInit(
    _In_ PGPA_CACHE *Cache
    )
///
/// @brief Uninit a GPA cache.
///
/// Frees a previously initialized GPA cache. All entries, including entries inside the victim cache, will
/// be removed. This function should be called only during uninit, as it carries to risk of leaving dangling
/// pointers, if all Gpa entries were not released before calling this function.
///
/// @param[in, out]     Cache The previously allocated GPA cache.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return #INT_STATUS_NOT_INITIALIZED_HINT If the provided Cache is not allocated (it is NULL).
///
{
    DWORD i, j;
    PGPA_CACHE pCache;
    LIST_ENTRY *list;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pCache = *Cache;
    if (NULL == pCache)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    for (i = 0; i < pCache->LinesCount; i++)
    {
        for (j = 0; j < pCache->EntriesCount; j++)
        {
            if (pCache->Lines[i].Entries[j].Valid)
            {
                IntPhysMemUnmap(&pCache->Lines[i].Entries[j].Hva);
            }
        }

        HpFreeAndNullWithTag(&pCache->Lines[i].Entries, IC_TAG_GPCA);
    }

    HpFreeAndNullWithTag(&pCache->Lines, IC_TAG_GPCA);

    list = pCache->Victims.Flink;

    while (list != &pCache->Victims)
    {
        PGPA_CACHE_VICTIM pVictim = CONTAINING_RECORD(list, GPA_CACHE_VICTIM, Link);

        list = list->Flink;

        if (pVictim->Entry.Valid && (pVictim->Entry.UseCount > 0) && (NULL != pVictim->Entry.Hva))
        {
            IntPhysMemUnmap(&pVictim->Entry.Hva);
        }

        RemoveEntryList(&pVictim->Link);

        HpFreeAndNullWithTag(&pVictim, IC_TAG_GPCV);
    }

    HpFreeAndNullWithTag(Cache, IC_TAG_GPCA);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntGpaCacheAddEntry(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _Out_ PGPA_CACHE_ENTRY *Entry
    )
///
/// @brief Add a new entry inside the GPA cache.
///
/// Internal function used to add an entry to the GPA cache. This function will iterate the entries inside the
/// Gpa cache line, and will select one of the following:
/// - The first invalid entry, or
/// - The entry with the lowest number of hits which is not in use, or
/// - A random entry
/// If the entry is valid, but not referenced, it will be evicted from the cache. If the entry is valid and referenced,
/// it will be added to the victim cache.
/// A new PGPA_CACHE_ENTRY structure will be allocated for the newly allocated entry, and it will be returned.
///
/// @param[in]  Cache  The GPA cache.
/// @param[in]  Gpa    The Gpa to be added in the cache.
/// @param[out] Entry  The freshly allocated GPA cache entry.
///
/// @return #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD line, entry, minHits;

    entry = 0;
    line = IntGpaCacheHashLine(Cache, Gpa);
    minHits = 0xFFFFFFFF;

    // GPA must be 4K aligned.
    Gpa &= PHYS_PAGE_MASK;

    for (DWORD i = 0; i < Cache->EntriesCount; i++)
    {
        if (!Cache->Lines[line].Entries[i].Valid)
        {
            entry = i;
            break;
        }
        else
        {
            // Select the entry with the lowest LFU score, as long as it is not in use.
            if ((minHits > Cache->Lines[line].Entries[i].HitCount) && (0 == Cache->Lines[line].Entries[i].UseCount))
            {
                minHits = Cache->Lines[line].Entries[i].HitCount;
                entry = i;
            }
        }
    }

    // Couldn't decide upon selecting a proper entry to evict, select a random one.
    if (minHits == 0xFFFFFFFF)
    {
        entry = __rdtsc() % Cache->EntriesCount;
    }

    // If the entry is in use, add it to the victim cache, and wait for it to be released.
    if (Cache->Lines[line].Entries[entry].Valid && (Cache->Lines[line].Entries[entry].UseCount > 0))
    {
        TRACE("[GPACACHE] Adding victim entry for GPA %llx, use count %d...\n",
              Cache->Lines[line].Entries[entry].Gpa, Cache->Lines[line].Entries[entry].UseCount);

        status = IntGpaCacheAddVictim(Cache, &Cache->Lines[line].Entries[entry]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGpaCacheAddVictim failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }
    else if (Cache->Lines[line].Entries[entry].Valid && (Cache->Lines[line].Entries[entry].UseCount == 0))
    {
        IntPhysMemUnmap(&Cache->Lines[line].Entries[entry].Hva);
    }

    // Map it and leave
    status = IntPhysMemMap(Gpa, PAGE_SIZE, PHYS_MAP_FLG_NO_FASTMAP, &Cache->Lines[line].Entries[entry].Hva);

    if (INT_SUCCESS(status))
    {
        Cache->Lines[line].Entries[entry].Valid = TRUE;
        Cache->Lines[line].Entries[entry].HitCount = 0;
        Cache->Lines[line].Entries[entry].UseCount = 0;
        Cache->Lines[line].Entries[entry].Gpa = Gpa;
    }
    else
    {
        Cache->Lines[line].Entries[entry].Valid = FALSE;
        Cache->Lines[line].Entries[entry].Gpa = 0;
    }

    *Entry = &Cache->Lines[line].Entries[entry];

cleanup_and_exit:
    return status;
}


static INTSTATUS
IntGpaCacheLookupEntry(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _Out_ PGPA_CACHE_ENTRY *Entry
    )
///
/// @brief Search an entry in the GPA cache.
///
/// It will search, inside the provided GPA cache, for an entry associated with the provided Gpa.
///
/// @param[in]  Cache  The GPA cache.
/// @param[in]  Gpa    The Gpa to be searched.
/// @param[out] Entry  Will contain, upon successful return, the entry associated with the provided Gpa.
///
/// @return #INT_STATUS_SUCCESS On success (Entry will be valid).
/// @return #INT_STATUS_NOT_FOUND If no entry associated with Gpa is present inside the cache.
///
{
    DWORD line, i;
    BOOLEAN bFound;
    LIST_ENTRY *list;

    bFound = FALSE;

    line = IntGpaCacheHashLine(Cache, Gpa);

    // Gpa must be page-aligned.
    Gpa &= PHYS_PAGE_MASK;

    for (i = 0; i < Cache->EntriesCount; i++)
    {
        if (Cache->Lines[line].Entries[i].Valid && (Cache->Lines[line].Entries[i].Gpa == Gpa))
        {
            *Entry = &Cache->Lines[line].Entries[i];
            bFound = TRUE;
            break;
        }
    }

    if (!bFound)
    {
        // Search the victim cache. If an entry is found in the victim cache, it could be brought back to the
        // main cache.
        list = Cache->Victims.Flink;

        while (list != &Cache->Victims)
        {
            PGPA_CACHE_VICTIM pVictim = CONTAINING_RECORD(list, GPA_CACHE_VICTIM, Link);

            list = list->Flink;

            if (pVictim->Entry.Valid && pVictim->Entry.Gpa == Gpa)
            {
                TRACE("[GPACACHE] Entry %llx found in victim cache, will not add it back...\n", Gpa);
                *Entry = &pVictim->Entry;
                bFound = TRUE;
                break;
            }
        }
    }

    if (bFound)
    {
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntGpaCacheFindAndAdd(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _Out_ void **Hva
    )
///
/// @brief Search for an entry in the GPA cache, and add it, if it wasn't found.
///
/// Checks if the provided Gpa is inside the cache. If it is, it will return a pointer to an already mapped page
/// pointing to the given Gpa. If it isn't, it will first add the entry to the cache, and then return a pointer
/// to the mapped page. The pointer to the mapped page is reference-counted, meaning that once this function is
/// called, the mapped Gpa will be locked (it will not be evicted from the cache and the returned pointer will
/// not be unmapped). In order to properly release the mapped Gpa, IntGpaCacheRelease must be called on Gpa.
///
/// @param[in]  Cache The GPA cache.
/// @param[in]  Gpa   The guest physical address that must be returned from the cache.
/// @param[out] Hva   A mapped page tat points to the provided Gpa.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER If an invalid parameter has been supplied.
///
{
    INTSTATUS status;
    PGPA_CACHE_ENTRY entry;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Hva)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    entry = NULL;

    status = IntGpaCacheLookupEntry(Cache, Gpa, &entry);
    if (!INT_SUCCESS(status))
    {
        status = IntGpaCacheAddEntry(Cache, Gpa, &entry);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    entry->HitCount++;
    entry->UseCount++;

    *Hva = entry->Hva;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGpaCacheFetchAndAdd(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _In_ DWORD Size,
    _Out_ PBYTE Buffer
    )
///
/// @brief Fetch data from a cached entry, or add it to the cache, of not already present.
///
/// This function will search for the guest physical address Gpa inside the cache. If it is not present, it will
/// be added to the cache. Afterwards, it will copy Size bytes from the given Gpa into the provided Buffer. Gpa
/// doesn't have to be page aligned. This function assumes that Buffer is large enough to accommodate at least the
/// required size.
///
/// @param[in]  Cache  The GPA cache.
/// @param[in]  Gpa    The Gpa to be accessed.
/// @param[in]  Size   Number of bytes to copy from Gpa into Buffer.
/// @param[out] Buffer Will contain, upon successful return, Size bytes copied from Gpa.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @return #INT_STATUS_NOT_SUPPORTED If a page overrun is encountered (Gpa + Size points outside the page).
///
{
    INTSTATUS status;
    PGPA_CACHE_ENTRY entry;
    PBYTE data;
    DWORD offset;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    entry = NULL;
    offset = Gpa & PAGE_OFFSET;

    if (offset + Size > PAGE_SIZE)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = IntGpaCacheLookupEntry(Cache, Gpa, &entry);
    if (!INT_SUCCESS(status))
    {
        status = IntGpaCacheAddEntry(Cache, Gpa, &entry);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    entry->HitCount++;

    data = (PBYTE)entry->Hva + offset;

    switch (Size)
    {
    case 8:
        *(PQWORD)Buffer = *(PQWORD)data;
        break;
    case 4:
        *(PDWORD)Buffer = *(PDWORD)data;
        break;
    case 2:
        *(PWORD)Buffer = *(PWORD)data;
        break;
    case 1:
        *Buffer = *data;
        break;
    default:
        memcpy(Buffer, data, Size);
        break;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGpaCachePatchAndAdd(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa,
    _In_ DWORD Size,
    _In_ PBYTE Buffer
    )
///
/// @brief Patch data in a cached entry, or add it to the cache, of not already present.
///
/// This function will search for the guest physical address Gpa inside the cache. If it is not present, it will
/// be added to the cache. Afterwards, it will copy Size bytes from the provided Buffer into the given Gpa. Gpa
/// doesn't have to be page aligned. This function assumes that Buffer is large enough to accommodate at least the
/// required size.
///
/// @param[in]  Cache  The GPA cache.
/// @param[in]  Gpa    The Gpa to be accessed.
/// @param[in]  Size   Number of bytes to copy from Gpa into Buffer.
/// @param[in]  Buffer Contains the data to be copied at Gpa.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @return #INT_STATUS_NOT_SUPPORTED If a page overrun is encountered (Gpa + Size points outside the page).
///
{
    INTSTATUS status;
    PGPA_CACHE_ENTRY entry;
    PBYTE data;
    DWORD offset;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    entry = NULL;
    offset = Gpa & PAGE_OFFSET;

    if (offset + Size > PAGE_SIZE)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    status = IntGpaCacheLookupEntry(Cache, Gpa, &entry);
    if (!INT_SUCCESS(status))
    {
        status = IntGpaCacheAddEntry(Cache, Gpa, &entry);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    entry->HitCount++;

    data = (PBYTE)entry->Hva + offset;

    switch (Size)
    {
    case 8:
        *(PQWORD)data = *(PQWORD)Buffer;
        break;
    case 4:
        *(PDWORD)data = *(PDWORD)Buffer;
        break;
    case 2:
        *(PWORD)data = *(PWORD)Buffer;
        break;
    case 1:
        *data = *Buffer;
        break;
    default:
        memcpy(data, Buffer, Size);
        break;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntGpaCacheRelease(
    _In_ PGPA_CACHE Cache,
    _In_ QWORD Gpa
    )
///
/// @brief Release a previously used cached entry.
///
/// Releases a previously mapped Gpa. This function must be called once the pointer returned by IntGpaCacheFindAndAdd
/// is no longer needed. Calling this function for Gpa values that were not previously mapped using
/// IntGpaCacheFindAndAdd will lead to undefined behavior. Note that the Gpa may have been moved inside the victim
/// cache, if space was needed inside that particular cache line for another entry. This, however, is transparent to
/// the caller.
///
/// @param[in] Cache The GPA cache.
/// @param[in] Gpa   The Gpa previously mapped using IntGpaCacheFindAndAdd.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @return #INT_STATUS_NOT_FOUND If the provided Gpa is not found inside the cache.
///
{
    DWORD line, i;
    BOOLEAN bFound;
    LIST_ENTRY *list;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    bFound = FALSE;

    line = IntGpaCacheHashLine(Cache, Gpa);

    // Gpa must be page-aligned.
    Gpa &= PHYS_PAGE_MASK;

    for (i = 0; i < Cache->EntriesCount; i++)
    {
        if (Cache->Lines[line].Entries[i].Valid && (Cache->Lines[line].Entries[i].Gpa == Gpa))
        {
            if (Cache->Lines[line].Entries[i].UseCount > 0)
            {
                Cache->Lines[line].Entries[i].UseCount--;
            }

            bFound = TRUE;
            break;
        }
    }

    if (!bFound)
    {
        TRACE("[GPACACHE] Entry %llx not found in main cache, searching victim cache...\n", Gpa);

        list = Cache->Victims.Flink;

        while (list != &Cache->Victims)
        {
            PGPA_CACHE_VICTIM pVictim = CONTAINING_RECORD(list, GPA_CACHE_VICTIM, Link);

            list = list->Flink;

            if (pVictim->Entry.Gpa == Gpa)
            {
                if (pVictim->Entry.UseCount > 0)
                {
                    pVictim->Entry.UseCount--;
                }

                TRACE("[GPACACHE] Entry %llx is victim, use = %d\n", Gpa, pVictim->Entry.UseCount);

                if (0 == pVictim->Entry.UseCount)
                {
                    IntPhysMemUnmap(&pVictim->Entry.Hva);

                    RemoveEntryList(&pVictim->Link);

                    HpFreeAndNullWithTag(&pVictim, IC_TAG_GPCV);
                }

                bFound = TRUE;

                break;
            }
        }
    }

    if (bFound)
    {
        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntGpaCacheFlush(
    _In_ PGPA_CACHE Cache
    )
///
/// @brief Flush the entire GPA cache.
///
/// Flushes the entire GPA cache - unmaps & removes all the entries cached so far. Note that entries that are in use
/// (GPAs for which IntGpaCacheFindAndAdd was called, without releasing them using IntGpaCacheRelease) will be moved
/// inside the victim cache, and references to those pages will remain valid until the victim cache is flushed.
///
/// @param[in] Cache The GPA cache.
///
/// @return #INT_STATUS_SUCCESS On success.
/// @return INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    DWORD i, j;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    for (i = 0; i < Cache->LinesCount; i++)
    {
        for (j = 0; j < Cache->EntriesCount; j++)
        {
            if (Cache->Lines[i].Entries[j].Valid)
            {
                if (Cache->Lines[i].Entries[j].UseCount == 0)
                {
                    IntPhysMemUnmap(&Cache->Lines[i].Entries[j].Hva);
                }
                else
                {
                    status = IntGpaCacheAddVictim(Cache, &Cache->Lines[i].Entries[j]);
                    if (!INT_SUCCESS(status))
                    {
                        ERROR("[ERROR] IntGpaCacheAddVictim failed: 0x%08x\n", status);
                    }
                }

                Cache->Lines[i].Entries[j].Valid = FALSE;
                Cache->Lines[i].Entries[j].Gpa = 0;
                Cache->Lines[i].Entries[j].HitCount = 0;
                Cache->Lines[i].Entries[j].UseCount = 0;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}
