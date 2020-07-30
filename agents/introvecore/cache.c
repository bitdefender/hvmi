/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cache.h"

#pragma section("VECACHE", read,write,nopage)

// The page-table cache.
__declspec(allocate("VECACHE"))
VE_CACHE_LINE VeCoreCache[VE_CACHE_LINES];


/// IMPORTANT
// There is no need for locking in the cache, due to the way it works. The cache holds page-table entry addresses
// which are NOT monitored by HVI. If an Address is present inside the cache, we will not issue a VMCALL to notify HVI
// about modifications in it. The locks are not needed because we work with QWORD quantities: this agent only reads 
// values, and HVI only writes values inside the cache (both atomically by default, since we are dealing with aligned
// QWORDs). The cache layout is as follows:
// - bits [12, 17] of the PTE Address select a Line. A line is exactly a page in size, and there are 64 lines (pages).
// - bits [3, 8] of the PTE Address select a Bucket. A bucket will contain up to 8 entries.
// If HVI adds an entry to the cache while this is verified by the agent, the worst that could happen is to issue
// a VMCALL for an entry which is not monitored.
// If HVI removed an entry for a PTE which is verified, the worst that could happen is to NOT issue a VMCALL for that 
// entry. However, this is not a problem, since if a CPU enables monitoring for an entry, another CPU may try to 
// modify it, but this would be a race already, since the EPT hook may be commited AFTER that modification is done.


//
// VeCacheIsEntryHooked
//
BOOLEAN
VeCacheIsEntryHooked(
    QWORD Address
    )
//
// Note that this function returns TRUE if an address is EPT hooked, NOT if an address is present in the cache.
//
{
    QWORD line, bucket, i;

    line = VE_CACHE_GET_LINE(Address);
    bucket = VE_CACHE_GET_BUCKET(Address);

    for (i = 0; i < VE_CACHE_ENTRIES; i++)
    {
        if (VeCoreCache[line].Entries[bucket][i] == Address)
        {
            return FALSE;
        }
    }

    return TRUE;
}
