/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "icache.h"
#include "hook.h"


static __inline DWORD
IntIcHashInv(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva
    )
///
/// @brief Compute the invalidation entry index.
///
/// Computes the index for the invalidation entry of a given instruction cache entry. The lowest log2(InvCount)
/// bits from the Gva page number are used.
///
/// @param[in] Cache The instruction cache.
/// @param[in] Gva   The Gva for which the invalidation index is computed.
///
/// @returns The invalidation entry index for the given Gva.
///
{
    // We must include the entire page in this hash-table. Can't use bits lower than 12.
    return (Gva >> 12) & (Cache->InvCount - 1);
}


static __inline DWORD
IntIcHashLine(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva
    )
///
/// @brief Compute an instruction line index.
///
/// Computes the line index for a given guest virtual address. The line index depends on the cache layout, as the lowest
/// log2(LinesCount) bits from the Gva page number are used.
///
/// @param[in] Cache The instruction cache.
/// @param[in] Gva   The Gva for which the line index is computed.
///
/// @returns The line index for the given Gva.
///
{
    // We use the frame number, so we can do fast invalidation on modified GVAs. Otherwise, we'd have to iterate
    // the entire cache, which is very slow.
    return (Gva >> 12) & (Cache->LinesCount - 1);
}


void
IntIcDumpIcache(
    void
    )
///
/// @brief Dumps the entire contents of the implicit, per guest, instruction cache.
///
{
    PINS_CACHE cache;
    DWORD i, j;
    LIST_ENTRY *list;

    cache = (PINS_CACHE)gGuest.InstructionCache;

    LOG("Instruction cache:\n");

    NLOG("Number of lines:  %d\n", cache->LinesCount);
    NLOG("Entries per line: %d\n", cache->EntriesCount);
    NLOG("Invalidation size:%d\n", cache->InvCount);
    NLOG("Fill count:       %d\n", cache->FillRate);
    NLOG("Flush count:      %d\n", cache->FlushCount);
    NLOG("Hit count:        %d\n", cache->HitCount);
    NLOG("Miss count:       %d\n", cache->MissCount);
    NLOG("Replace count:    %d\n", cache->ReplaceCount);
    NLOG("Pgflush count:    %d\n", cache->PageFlushCount);


    // Dump the entries inside the cache
    for (i = 0; i < cache->LinesCount; i++)
    {
        for (j = 0; j < cache->EntriesCount; j++)
        {
            if (cache->Lines[i].Entries[j].Valid)
            {
                char text[ND_MIN_BUF_SIZE] = {0};

                NdToText(&cache->Lines[i].Entries[j].Instruction,
                         cache->Lines[i].Entries[j].Gva,
                         ND_MIN_BUF_SIZE,
                         text);

                NLOG("-> %04d - %04d: 0x%016llx:0x%016llx, %08d %d %d %d > %s\n",
                     i, j,
                     cache->Lines[i].Entries[j].Gva,
                     cache->Lines[i].Entries[j].Cr3,
                     cache->Lines[i].Entries[j].RefCount,
                     cache->Lines[i].Entries[j].Valid,
                     cache->Lines[i].Entries[j].Pinned,
                     cache->Lines[i].Entries[j].Global,
                     text);
            }
        }
    }

    NLOG("Invalidation queue:\n");

    // Dump the invalidation queue
    for (i = 0; i < cache->InvCount; i++)
    {
        if (IsListEmpty(&cache->InsInvGva[i]))
        {
            continue;
        }

        NLOG("%04d: ", i);

        list = cache->InsInvGva[i].Flink;
        while (list != &cache->InsInvGva[i])
        {
            PINS_CACHE_INV_ENTRY pInv = CONTAINING_RECORD(list, INS_CACHE_INV_ENTRY, Link);

            list = list->Flink;

            NLOG("0x%016llx:0x%016llx:0x%016llx:%04d    ", pInv->Gva, pInv->Gpa, pInv->Cr3, pInv->RefCount);
        }

        NLOG("\n");
    }
}


static INTSTATUS
IntIcFreeInvdEntry(
    _In_ PINS_CACHE_INV_ENTRY Invd
    )
///
/// @brief Free an invalidation entry.
///
/// Frees the provided invalidation entry, by removing the swap hook and the write hook from the memory page
/// that contains cached instructions.
///
/// @param[in] Invd The invalidation entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = INT_STATUS_SUCCESS;

    if (NULL != Invd->SwapHook)
    {
        status = IntHookPtsRemoveHook((HOOK_PTS **)&Invd->SwapHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsRemoveHook failed: 0x%08x\n", status);
        }
    }

    if (NULL != Invd->WriteHook)
    {
        status = IntHookGpaRemoveHook((HOOK_GPA **)&Invd->WriteHook, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaRemoveHook failed: 0x%08x\n", status);
        }
    }

    HpFreeAndNullWithTag(&Invd, IC_TAG_IINV);

    return status;
}


static INTSTATUS
IntIcRemoveAllInvdEntries(
    _In_ PINS_CACHE Cache
    )
///
/// @brief Removes all the invalidation entries contained in this cache. This should be used only during uninit.
///
/// @param[in] Cache The instruction cache.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD i;

    for (i = 0; i < Cache->InvCount; i++)
    {
        LIST_ENTRY *list = Cache->InsInvGva[i].Flink;

        while (list != &Cache->InsInvGva[i])
        {
            PINS_CACHE_INV_ENTRY pInv = CONTAINING_RECORD(list, INS_CACHE_INV_ENTRY, Link);
            list = list->Flink;

            pInv->RefCount = 0;

            RemoveEntryList(&pInv->Link);

            status = IntIcFreeInvdEntry(pInv);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntIcFreeInvdEntry failed: 0x%08x\n", status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntIcInvdEntry(
    _In_ PINS_CACHE Cache,
    _Inout_ PINS_CACHE_INV_ENTRY Invd
    )
///
/// @brief Decrements the reference count of the provided invalidation entry, and, if it reaches 0, it completely
/// frees it.
///
/// @param[in]      Cache The instruction cache.
/// @param[in, out] Invd  The invalidation entry.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Cache);

    if (0 == Invd->RefCount)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    Invd->RefCount--;

    if (0 == Invd->RefCount)
    {
        RemoveEntryList(&Invd->Link);

        status = IntIcFreeInvdEntry(Invd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcFreeInvdEntry failed: 0x%08x\n", status);
            return status;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntIcInvdCacheEntry(
    _In_ PINS_CACHE Cache,
    _In_ PINS_CACHE_ENTRY Entry
    )
///
/// @brief Invalidate an instruction cache entry.
///
/// Provided an instruction cache entry, it will invalidate it. Note that for each entry, there are potentially two
/// invalidation entries, if the instruction spans in two pages (one invalidation entry for each page).
///
/// @param[in] Cache The instruction cache.
/// @param[in] Entry The instruction cache entry to be invalidated.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    if (NULL != Entry->Invd1)
    {
        status = IntIcInvdEntry(Cache, Entry->Invd1);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcInvdEntry failed: 0x%08x\n", status);
        }

        Entry->Invd1 = NULL;
    }

    if (NULL != Entry->Invd2)
    {
        status = IntIcInvdEntry(Cache, Entry->Invd2);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcInvdEntry failed: 0x%08x\n", status);
        }

        Entry->Invd2 = NULL;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntIcWriteHandler(
    _In_ INS_CACHE_INV_ENTRY const *Context,
    _In_ void const *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Cached instruction page write handler.
///
/// This callback is called whenever writes take place inside a page that contains cached instruction. Upon writing such
/// a page, all the instructions cached from this page will be removed from the cache.
/// Note that we are OK with regard to 2M/4M pages, because inside the HV, only 4K pages are considered. Therefore,
/// for a 2M page, there would be separate entries & hooks for each 4K HPA page.
///
/// @param[in]  Context The optional hook context, which in this case, represents the invalidation entry.
/// @param[in]  Hook    The hook handle.
/// @param[in]  Address The written guest physical address.
/// @param[out] Action  Will always be set on introGuestAllowed, in order to allow the write.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    PINS_CACHE pCache;
    INS_CACHE_INV_ENTRY const *pInv;
    QWORD gva, cr3;
    BOOLEAN spill;

    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Hook);

    // Get the cache.
    pCache = (PINS_CACHE)gGuest.InstructionCache;
    pInv = Context;

    gva = pInv->Gva;
    cr3 = pInv->Cr3;
    spill = pInv->Spill;

    // Note: calls to IntIcFlushGvaPage will remove the hook and will free the pInvd entry if the ref count reaches 0.
    // We cannot safely access the pInvd entry after calling IntIcFlushGvaPage.

    // Flush the instructions contained inside this (virtual) page.
    IntIcFlushGvaPage(pCache, gva, cr3, FALSE);

    if (spill)
    {
        // If this page contains spilled instructions, invalidate those too.
        IntIcFlushGvaPage(pCache, gva - 0x1000, cr3, TRUE);
    }

    // Obviously, we allow the write.
    *Action = introGuestAllowed;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntIcSwapHandler(
    _In_ void *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief Cache instruction page swap handler.
///
/// This callback will be called whenever a remapping takes place on a guest virtual page which has instructions cached.
/// Whenever the page-table entry that maps a cache page is modified (except for A/D bits), the entire page will be
/// invalidated, thus removing the instructions from the cache.
///
/// @param[in] Context          The invalidation entry associated with the remapped page.
/// @param[in] VirtualAddress   The guest virtual address that is being remapped.
/// @param[in] OldEntry         Old page table entry associated with VirtualAddress.
/// @param[in] NewEntry         New page table entry associated with VirtualAddress.
/// @param[in] OldPageSize      Old page size (4K, 2M, 1G).
/// @param[in] NewPageSize      New page size (4K, 2M, 1G).
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    PINS_CACHE pCache;
    PINS_CACHE_INV_ENTRY pInv;
    QWORD gva, cr3;
    BOOLEAN spill;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(OldPageSize);
    UNREFERENCED_PARAMETER(NewPageSize);

    pCache = (PINS_CACHE)gGuest.InstructionCache;
    pInv = (PINS_CACHE_INV_ENTRY)Context;

    gva = pInv->Gva;
    cr3 = pInv->Cr3;
    spill = pInv->Spill;

    // Note: calls to IntIcFlushGvaPage will remove the hook and will free the pInvd entry if the ref count reaches 0.

#define INV_MASK (~0x60ULL)

    if ((OldEntry & INV_MASK) != (NewEntry & INV_MASK))
    {
        // Flush the instructions contained inside this page.
        IntIcFlushGvaPage(pCache, gva, cr3, FALSE);

        if (spill)
        {
            // If this page contains spilled instructions, invalidate those too.
            IntIcFlushGvaPage(pCache, gva - 0x1000, cr3, TRUE);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntIcLookupInstructionInternal(
    _In_ PINS_CACHE Cache,
    _Out_ PINSTRUX Instrux,
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ DWORD Lru
    )
///
/// @brief Lookup an instruction inside the cache.
///
/// Will check the instruction cache to see if it contains a decoded instruction which is tagged with Gva.
/// If so, it will copy the decoded instruction inside the buffer pointed by Instrux.
/// Otherwise, it will return #INT_STATUS_NOT_FOUND.
///
/// @param[in]  Cache    The instruction cache.
/// @param[out] Instrux  Will contain, upon successful return, the decoded instruction.
/// @param[in]  Gva      The Gva which contains the instruction.
/// @param[in]  Cr3      The virtual address space which contains the instruction.
/// @param[in]  Lru      The instruction ref count will be updated using this value.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no instruction is cached with the given Gva.
///
{
    INTSTATUS status;
    DWORD line, i;

    // This function is internal, there's no point on validating the parameters - they have already been
    // validated by the caller.

    // Get the cache line for this address
    line = IntIcHashLine(Cache, Gva);

    status = INT_STATUS_NOT_FOUND;

    // Check every set for the tag & valid bit
    for (i = 0; i < Cache->EntriesCount; i++)
    {
        if ((Cache->Lines[line].Entries[i].Gva == Gva) &&
            (Cache->Lines[line].Entries[i].Valid) &&
            ((Cache->Lines[line].Entries[i].Cr3 == Cr3) ||
             (IC_ANY_VAS == Cr3) ||
             (Cache->Lines[line].Entries[i].Global)))
        {
            memcpy(Instrux, &Cache->Lines[line].Entries[i].Instruction, sizeof(INSTRUX));

            Cache->Lines[line].Entries[i].RefCount += Lru;

            status = INT_STATUS_SUCCESS;

            break;
        }
    }

    if (INT_STATUS_NOT_FOUND == status)
    {
        Cache->MissCount++;
    }
    else
    {
        Cache->HitCount++;
    }

    return status;
}


INTSTATUS
IntIcLookupInstruction(
    _In_ PINS_CACHE Cache,
    _Out_ PINSTRUX Instrux,
    _In_ QWORD Gva,
    _In_ QWORD Cr3
    )
///
/// @brief Lookup an instruction inside the cache.
///
/// Will check the instruction cache to see if it contains a decoded instruction which is tagged with
/// Gva. If so, it will copy the decoded instruction inside the buffer pointed by Instrux. Otherwise,
/// it will return #INT_STATUS_NOT_FOUND. Note that this is a wrapper over #IntIcLookupInstructionInternal,
/// and this function is publicly exposed to the callers.
///
/// @param[in]  Cache   The instruction cache.
/// @param[out] Instrux Will contain, upon successful return, the decoded instruction.
/// @param[in]  Gva     The Gva that contains the instruction.
/// @param[in]  Cr3     The virtual address space that contains the instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no instruction is cached with the given Gva.
///
{
    INTSTATUS status;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Instrux == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntIcLookupInstructionInternal(Cache, Instrux, Gva, Cr3, 1);

    return status;
}


INTSTATUS
IntIcFlush(
    _In_ PINS_CACHE Cache
    )
///
/// @brief Flush the entire instruction cache.
///
/// Will invalidate the contents of the given instruction cache. This is done by marking every cached entry as invalid.
///
/// @param[in] Cache The instruction cache.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
//
{
    INTSTATUS status;
    DWORD i, j;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!Cache->Dirty)
    {
        return INT_STATUS_SUCCESS;
    }

    for (i = 0; i < Cache->LinesCount; i++)
    {
        for (j = 0; j < Cache->EntriesCount; j++)
        {
            if (Cache->Lines[i].Entries[j].Valid)
            {
                Cache->Lines[i].Entries[j].Gva = 0;
                Cache->Lines[i].Entries[j].Cr3 = 0;
                Cache->Lines[i].Entries[j].Invd1 = NULL;
                Cache->Lines[i].Entries[j].Invd2 = NULL;
                Cache->Lines[i].Entries[j].Pinned = FALSE;
                Cache->Lines[i].Entries[j].Global = FALSE;
                Cache->Lines[i].Entries[j].RefCount = 0;
                Cache->Lines[i].Entries[j].Valid = FALSE;
            }
        }
    }

    status = IntIcRemoveAllInvdEntries(Cache);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIcRemoveAllInvdEntries failed: 0x%08x\n", status);
    }

    Cache->FillRate = 0;
    Cache->FlushCount++;
    Cache->Dirty = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIcFlushAddress(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva,
    _In_ QWORD Cr3
    )
///
/// @brief Flush entries cached from a given address.
///
/// Will invalidate the entry tagged with Gva. If no entry with the given tag exists, it will
/// return #INT_STATUS_NOT_FOUND. This function will invalidate cached entries for a single address, not for
/// an entire page. The function will invalidate only entries inside the provided address space given by
/// Cr3, but it will always invalidate Global entries. If Cr3 == #IC_ANY_VAS, entries in all address spaces will be
/// invalidated.
/// NOTE: After an entry is invalidated, it will no longer be used in any ways. It may be replaced
/// by other entries that must be cached, if no other slots are available.
///
/// @param[in] Cache    The instruction cache.
/// @param[in] Gva      The address to be invalidated.
/// @param[in] Cr3      The target virtual address space. If Cr3 == #IC_ANY_VAS, entries in all address spaces will
///                     be invalidated.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no instruction is cached with the tag Gva.
///
{
    INTSTATUS status;
    DWORD line, i;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    line = IntIcHashLine(Cache, Gva);

    status = INT_STATUS_NOT_FOUND;

    for (i = 0; i < Cache->EntriesCount; i++)
    {
        if ((Cache->Lines[line].Entries[i].Gva == Gva) &&
            (Cache->Lines[line].Entries[i].Valid) &&
            ((Cache->Lines[line].Entries[i].Cr3 == Cr3) ||
             (IC_ANY_VAS == Cr3) ||
             (Cache->Lines[line].Entries[i].Global)))
        {
            // Invalidate the Invd entry.
            status = IntIcInvdCacheEntry(Cache, &Cache->Lines[line].Entries[i]);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntIcInvdCacheEntry failed: 0x%08x\n", status);
            }

            Cache->Lines[line].Entries[i].Valid = 0;
            Cache->Lines[line].Entries[i].Gva = 0;
            Cache->Lines[line].Entries[i].Cr3 = 0;
            Cache->Lines[line].Entries[i].Invd1 = NULL;
            Cache->Lines[line].Entries[i].Invd2 = NULL;

            status = INT_STATUS_SUCCESS;
        }
    }

    return status;
}


INTSTATUS
IntIcFlushGvaPage(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Spill
    )
///
/// @brief Flush all entries cached from a given guest virtual page.
///
/// Will invalidate all the instructions cached inside the provided virtual page. Low 12 bits inside Gva are ignored.
/// If Spill is TRUE, it will only invalidate the last instruction in the page, if it spills inside the next page.
/// NOTE: After an entry is invalidated, it will no longer be used in any ways. It may be replaced
/// by other entries that must be cached, if no other slots are available.
///
/// @param[in] Cache The instruction cache.
/// @param[in] Gva   The page that must be invalidated.
/// @param[in] Cr3   The target virtual address space. If Cr3 == #IC_ANY_VAS, all address spaces will be flushed.
/// @param[in] Spill If true, only the last instruction in the page will be invalidated, if it spills in the next page.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no instruction is cached with the tag Gva.
///
{
    INTSTATUS status;
    DWORD line, i;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    Cache->PageFlushCount++;

    line = IntIcHashLine(Cache, Gva);

    Gva &= PAGE_MASK;
    status = INT_STATUS_NOT_FOUND;

    for (i = 0; i < Cache->EntriesCount; i++)
    {
        if (((Cache->Lines[line].Entries[i].Gva & PAGE_MASK) == Gva) &&
            (Cache->Lines[line].Entries[i].Valid) &&
            ((Cache->Lines[line].Entries[i].Cr3 == Cr3) ||
             (IC_ANY_VAS == Cr3) ||
             (Cache->Lines[line].Entries[i].Global)) &&
            ((!Spill) || ((Cache->Lines[line].Entries[i].Gva & PAGE_OFFSET) +
                          Cache->Lines[line].Entries[i].Instruction.Length > PAGE_SIZE)))
        {
            // Invalidate the Invd entry.
            status = IntIcInvdCacheEntry(Cache, &Cache->Lines[line].Entries[i]);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntIcInvdCacheEntry failed: 0x%08x\n", status);
            }

            Cache->Lines[line].Entries[i].Valid = 0;
            Cache->Lines[line].Entries[i].Gva = 0;
            Cache->Lines[line].Entries[i].Cr3 = 0;
            Cache->Lines[line].Entries[i].Invd1 = NULL;
            Cache->Lines[line].Entries[i].Invd2 = NULL;

            status = INT_STATUS_SUCCESS;
        }
    }

    return status;
}


INTSTATUS
IntIcFlushGpaPage(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gpa
    )
///
/// @brief Flush all entries cached from a given guest physical page.
///
/// Will invalidate all entries cached inside the provided physical page. Low 12 bits inside Gpa are ignored.
/// NOTE: After an entry is invalidated, it will no longer be used in any ways. It may be replaced
/// by other entries that must be cached, if no other slots are available.
///
/// @param[in] Cache The instruction cache.
/// @param[in] Gpa   The physical page to be invalidated.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If no instruction is cached with the tag Gva.
///
{
    INTSTATUS status;
    DWORD i, j;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = INT_STATUS_NOT_FOUND;

    Gpa &= PHYS_PAGE_MASK;

    Cache->PageFlushCount++;

    for (i = 0; i < Cache->LinesCount; i++)
    {
        for (j = 0; j < Cache->EntriesCount; j++)
        {
            if ((Cache->Lines[i].Entries[j].Valid) &&
                (((NULL != Cache->Lines[i].Entries[j].Invd1) && (Cache->Lines[i].Entries[j].Invd1->Gpa == Gpa)) ||
                 ((NULL != Cache->Lines[i].Entries[j].Invd2) && (Cache->Lines[i].Entries[j].Invd2->Gpa == Gpa))))
            {
                // Invalidate the Invd entry.
                status = IntIcInvdCacheEntry(Cache, &Cache->Lines[i].Entries[j]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIcInvdCacheEntry failed: 0x%08x\n", status);
                }

                Cache->Lines[i].Entries[j].Valid = 0;
                Cache->Lines[i].Entries[j].Gva = 0;
                Cache->Lines[i].Entries[j].Cr3 = 0;
                Cache->Lines[i].Entries[j].Invd1 = NULL;
                Cache->Lines[i].Entries[j].Invd2 = NULL;

                status = INT_STATUS_SUCCESS;
            }
        }
    }

    return status;
}


INTSTATUS
IntIcFlushVaSpace(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Cr3
    )
///
/// @brief Flush an entire virtual address space.
///
/// Flushes all the instruction cached inside the provided virtual address space Cr3. If Cr3 == #IC_ANY_VAS,
/// instructions in every virtual address space will be flushed.
///
/// @param[in] Cache The instruction cache.
/// @param[in] Cr3   The target virtual address space. If Cr3 == #IC_ANY_VAS, all address spaces will be flushed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD i, j;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = INT_STATUS_SUCCESS;

    for (i = 0; i < Cache->LinesCount; i++)
    {
        for (j = 0; j < Cache->EntriesCount; j++)
        {
            if ((Cache->Lines[i].Entries[j].Cr3 == Cr3) || (IC_ANY_VAS == Cr3))
            {
                // Invalidate the Invd entry.
                status = IntIcInvdCacheEntry(Cache, &Cache->Lines[i].Entries[j]);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntIcInvdCacheEntry failed: 0x%08x\n", status);
                }

                Cache->Lines[i].Entries[j].Valid = 0;
                Cache->Lines[i].Entries[j].Gva = 0;
                Cache->Lines[i].Entries[j].Cr3 = 0;
                Cache->Lines[i].Entries[j].Invd1 = NULL;
                Cache->Lines[i].Entries[j].Invd2 = NULL;

                status = INT_STATUS_SUCCESS;
            }
        }
    }

    return status;
}


static INTSTATUS
IntIcAddInvdForInstruction(
    _In_ PINS_CACHE Cache,
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _Out_ PINS_CACHE_INV_ENTRY *Invd
    )
///
/// @brief Add invalidation entries for a newly cached instruction.
///
/// Provided the virtual address Gva inside address space Cr3, this function will create & return an invalidation
/// entry. Invalidation entries are used to keep track of all the instructions that must be invalidated inside
/// a give page of memory.
///
/// @param[in]  Cache The instruction cache.
/// @param[in]  Gva   The instruction virtual address.
/// @param[in]  Cr3   The virtual address space. Can be #IC_ANY_VAS for instructions which are inside kernel space.
/// @param[out] Invd  Will contain upon successful return the invalidation entry created for the given address.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation failed.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;
    DWORD invline;
    BOOLEAN bFound;
    PINS_CACHE_INV_ENTRY pInv;
    VA_TRANSLATION tr = { 0 };

    bFound = FALSE;
    pInv = NULL;

    invline = IntIcHashInv(Cache, Gva);

    // We first iterate the existing list of invalidation entries and simply increment the refcount of an existing
    // entry, if available.
    list = Cache->InsInvGva[invline].Flink;
    while (list != &Cache->InsInvGva[invline])
    {
        pInv = CONTAINING_RECORD(list, INS_CACHE_INV_ENTRY, Link);
        list = list->Flink;

        if ((pInv->Gva == (Gva & PAGE_MASK)) && (pInv->Cr3 == Cr3))
        {
            pInv->RefCount++;

            bFound = TRUE;

            break;
        }
    }

    // Invalidation entry not added yet - allocate it & add it now.
    if (!bFound)
    {
        status = IntTranslateVirtualAddressEx(Gva & PAGE_MASK, Cr3 != 0 ? Cr3 : gGuest.Mm.SystemCr3, TRFLG_NONE, &tr);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        pInv = HpAllocWithTag(sizeof(*pInv), IC_TAG_IINV);
        if (NULL == pInv)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        pInv->Cr3 = Cr3;
        pInv->RefCount = 1;
        pInv->Gva = Gva & PAGE_MASK;
        pInv->Gpa = tr.PhysicalAddress & PHYS_PAGE_MASK;

        status = IntHookPtsSetHook(Cr3, pInv->Gva, IntIcSwapHandler, pInv, NULL, 0, (PHOOK_PTS *)&pInv->SwapHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookPtsSetHook failed: 0x%08x\n", status);
            IntIcFreeInvdEntry(pInv);
            return status;
        }

        status = IntHookGpaSetHook(pInv->Gpa, PAGE_SIZE, IG_EPT_HOOK_WRITE, IntIcWriteHandler,
                                   pInv, NULL, 0, (PHOOK_GPA *)&pInv->WriteHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaSetHook failed on %llx: 0x%08x\n", pInv->Gva, status);
            IntIcFreeInvdEntry(pInv);
            return status;
        }

        // Insert the invalidation line inside the list.
        InsertTailList(&Cache->InsInvGva[invline], &pInv->Link);
    }

    *Invd = pInv;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIcAddInstruction(
    _In_ PINS_CACHE Cache,
    _In_ PINSTRUX Instruction,
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ BOOLEAN Global
    )
///
/// @brief Adds an instruction to the cache.
///
/// Will add the given instruction to the decoded instruction cache. If an invalid entry is found, the instruction will
/// be added there. If not, a random entry will be selected for eviction. The instruction address Gva is used as a tag,
/// and the address space Cr3 is used to indicate the process the instruction belongs to. If the instruction is in
/// kernel, Cr3 must be #IC_ANY_VAS and Global must be true, otherwise the instruction may be evicted from the cache
/// even if the page it lies in is still valid.
/// This function will automatically create the invalidation entries for this instruction, or reference an already
/// existing invalidation entry, if instructions from this page have already been cached.
///
/// @param[in] Cache        The instruction cache.
/// @param[in] Instruction  The decoded instruction to be added inside the cache.
/// @param[in] Gva          Instruction address.
/// @param[in] Cr3          Address space. Must be #IC_ANY_VAS for kernel instructions.
/// @param[in] Global       True if the instruction is global (shared among multiple address spaces).
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD line, target, i;

    if (Cache == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Instruction == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    line = IntIcHashLine(Cache, Gva);

    target = 0xFFFFFFFF;

    for (i = 0; i < Cache->EntriesCount; i++)
    {
        if (!Cache->Lines[line].Entries[i].Valid)
        {
            Cache->FillRate++;

            target = i;

            break;
        }
    }

    if (0xFFFFFFFF == target)
    {
        target = __rdtsc() % Cache->EntriesCount;
    }

    // Check if we need to decrement the refcount for the entry
    if (Cache->Lines[line].Entries[target].Valid)
    {
        status = IntIcInvdCacheEntry(Cache, &Cache->Lines[line].Entries[target]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcInvdCacheEntry failed: 0x%08x\n", status);
        }
    }

    // Mark the entry as invalid, until we completely initialize it - this includes an invalidation entry, if
    // needed.
    Cache->Lines[line].Entries[target].Valid = FALSE;

    Cache->Lines[line].Entries[target].Gva = Gva;
    Cache->Lines[line].Entries[target].Cr3 = Cr3;
    Cache->Lines[line].Entries[target].RefCount = 0;
    Cache->Lines[line].Entries[target].Pinned = FALSE;
    Cache->Lines[line].Entries[target].Global = Global;

    memcpy(&Cache->Lines[line].Entries[target].Instruction, Instruction, sizeof(INSTRUX));

    Cache->Lines[line].Entries[target].Invd1 = NULL;
    Cache->Lines[line].Entries[target].Invd2 = NULL;

    // Add the invalidation entry for this page.
    status = IntIcAddInvdForInstruction(Cache, Gva, Cr3, &Cache->Lines[line].Entries[target].Invd1);
    if (!INT_SUCCESS(status))
    {
        if ((INT_STATUS_PAGE_NOT_PRESENT != status) &&
            (INT_STATUS_NO_MAPPING_STRUCTURES != status))
        {
            ERROR("[ERROR] IntIcAddInvdForInstruction failed: 0x%08x\n", status);
        }

        return status;
    }

    // Handle instructions that cross the page boundary.
    if ((Gva & PAGE_MASK) != ((Gva + Instruction->Length - 1) & PAGE_MASK))
    {
        TRACE("[ICACHE] Instruction at %llx:%d spills the page...\n", Gva, Instruction->Length);

        status = IntIcAddInvdForInstruction(Cache, (Gva & PAGE_MASK) + 0x1000, Cr3,
                                            &Cache->Lines[line].Entries[target].Invd2);
        if (!INT_SUCCESS(status))
        {
            if ((INT_STATUS_PAGE_NOT_PRESENT != status) &&
                (INT_STATUS_NO_MAPPING_STRUCTURES != status))
            {
                ERROR("[ERROR] IntIcAddInvdForInstruction failed: 0x%08x\n", status);
            }

            IntIcInvdEntry(Cache, Cache->Lines[line].Entries[target].Invd1);

            return status;
        }

        // We need to know if this entry is the spill page, so we can properly invalidate the previous page in case
        // if swap/writes.
        Cache->Lines[line].Entries[target].Invd2->Spill = TRUE;
    }

    // Successfully added, the entry is now valid!
    Cache->Lines[line].Entries[target].Valid = TRUE;

    Cache->Dirty = TRUE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIcCreate(
    _Inout_ INS_CACHE **Cache,
    _In_ DWORD LinesCount,
    _In_ DWORD EntriesCount,
    _In_ DWORD InvCount
    )
///
/// @brief Create anew instruction cache.
///
/// Will create a new instruction cache. The layout will be given by LinesCount and EntriesCount, thus creating
/// LinesCount x EntriesCount total entries inside the cache. InvCount give the number of entries for the
/// invalidation structures, which are used to invalidate all instruction belonging to the same page.
///
/// @param[in, out] Cache           An address to a pointer that will contain the instruction cache address.
/// @param[in]      LinesCount      Number of lines.
/// @param[in]      EntriesCount    Number of entries per line.
/// @param[in]      InvCount        Number of lines for invalidation entries.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    INS_CACHE *pCache;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // LinesCount and InvCount must be powers of two.
    if (0 != (LinesCount & (LinesCount - 1)))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 != (InvCount & (InvCount - 1)))
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    pCache = HpAllocWithTag(sizeof(*pCache), IC_TAG_INSC);
    if (NULL == pCache)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pCache->LinesCount = LinesCount;
    pCache->EntriesCount = EntriesCount;
    pCache->InvCount = InvCount;

    pCache->HitCount = 0;
    pCache->MissCount = 0;
    pCache->FillRate = 0;
    pCache->FlushCount = 0;
    pCache->ReplaceCount = 0;
    pCache->PageFlushCount = 0;

    pCache->Lines = HpAllocWithTag(sizeof(*pCache->Lines) * LinesCount, IC_TAG_INSC);
    if (NULL == pCache->Lines)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    for (DWORD i = 0; i < LinesCount; i++)
    {
        pCache->Lines[i].Entries = HpAllocWithTag(sizeof(*pCache->Lines[0].Entries) * EntriesCount, IC_TAG_INSC);
        if (NULL == pCache->Lines[i].Entries)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_and_exit;
        }
    }

    pCache->InsInvGva = HpAllocWithTag(sizeof(*pCache->InsInvGva) * InvCount, IC_TAG_INSC);
    if (NULL == pCache->InsInvGva)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    for (DWORD j = 0; j < InvCount; j++)
    {
        InitializeListHead(&pCache->InsInvGva[j]);
    }

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pCache)
        {
            if (NULL != pCache->InsInvGva)
            {
                HpFreeAndNullWithTag(&pCache->InsInvGva, IC_TAG_INSC);
            }

            if (NULL != pCache->Lines)
            {
                for (DWORD i = 0; i < LinesCount; i++)
                {
                    if (NULL != pCache->Lines[i].Entries)
                    {
                        HpFreeAndNullWithTag(&pCache->Lines[i].Entries, IC_TAG_INSC);
                    }
                }

                HpFreeAndNullWithTag(&pCache->Lines, IC_TAG_INSC);
            }

            HpFreeAndNullWithTag(&pCache, IC_TAG_INSC);
        }
    }
    else
    {
        IntIcFlush(pCache);
    }

    *Cache = pCache;

    return status;
}


INTSTATUS
IntIcDestroy(
    _Inout_ PINS_CACHE *Cache
    )
///
/// @brief Destroy an instruction cache.
///
/// Frees an instruction cache previously created using IntIcCreate.
///
/// @param[in, out] Cache The previously created instruction cache.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the provided cache was not allocated.
///
{
    INTSTATUS status;
    DWORD i;
    PINS_CACHE pCache;

    if (NULL == Cache)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pCache = *Cache;
    if (NULL == pCache)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    status = IntIcRemoveAllInvdEntries(*Cache);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIcRemoveAllInvdEntries failed: 0x%08x\n", status);
    }

    for (i = 0; i < pCache->LinesCount; i++)
    {
        HpFreeAndNullWithTag(&pCache->Lines[i].Entries, IC_TAG_INSC);
    }

    HpFreeAndNullWithTag(&pCache->Lines, IC_TAG_INSC);

    HpFreeAndNullWithTag(&pCache->InsInvGva, IC_TAG_INSC);

    HpFreeAndNullWithTag(Cache, IC_TAG_INSC);

    return INT_STATUS_SUCCESS;
}
