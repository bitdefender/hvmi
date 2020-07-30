/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winpool.h"
#include "introcore.h"
#include "windrvobj.h"
#include "detours.h"
#include "guests.h"


INTSTATUS
IntWinPoolHandleAlloc(
    _In_ void *Detour
    )
///
/// @brief      Detour callback for ExAllocatePoolWithTag.
/// @ingroup    group_detours
///
/// Handles allocations within a Windows guest, executed using the ExAllocatePoolWithTag API.
/// Basically, it will check the tag of the allocation, and if it identifies an allocation
/// for a driver object or a fast I/O dispatch, it will patch the Size argument of the call
/// so that it's almost a page. This ensures us that critical structures protected by the
/// introspection will be allocated alone in each page, which gives us an enormous performance
/// boost.
///
/// @param[in]  Detour The detour object.
///
/// @returns          #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    DWORD tag;
    DWORD size;
    // DWORD poolType;
    QWORD args[3];

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntDetGetArguments(Detour, 3, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // poolType = (DWORD)args[0];
    size = (DWORD)args[1];
    tag = (DWORD)args[2];

    // The allocator will always assign a BlockSize to the given pool header, representing the sum of the
    // allocation size and the size of POOL_HEADER, divided by 0x10 on x64 guests, respectively by 0x8 on x86
    // guests. Note that, if we force an allocation of size 0x1000 - sizeof(POOL_HEADER), which means that
    // both the allocation and the pool header should reside in the same page, the allocator will notice
    // that this is >= 0x1000, thus overflowing the BlockSize (8 bits on x64, 9 bits on x86) when divided,
    // thus making the current allocation a big pool allocation. As we don't desire this, we will, instead
    // make a subtraction of 2 * sizeof(POOL_HEADER). This will ensure both that the given allocation will 
    // not be a big pool allocation, and that there won't be any other allocations in the given page, as
    // there will be space on the current page for just a POOL_HEADER, hence an allocation with size 0.
    // Notice that this will always result in an allocation with BlockSize = 0xFF on x64 guests and
    // BlockSize = 0x1FF on x86 guests respectively.

    // The size is 472 bytes on Windows 7 x64, 488 bytes on Windows 8 x64 & 236 bytes on Windows 7 x32.
    if (((tag == WIN_POOL_TAG_DRIV) || (tag == WIN_POOL_TAG_DRIV2)))
    {
        // This is a _DRIVER_OBJECT
        if (size < PAGE_SIZE - 2 * WIN_POOL_HEADER_SIZE)
        {
            size = PAGE_SIZE - 2 * WIN_POOL_HEADER_SIZE;
        }
    }
    else if (tag == WIN_POOL_TAG_FMFI)
    {
        // This is a _FAST_IO_DISPATCH
        if (size < PAGE_SIZE - 2 * WIN_POOL_HEADER_SIZE)
        {
            size = PAGE_SIZE - 2 * WIN_POOL_HEADER_SIZE;
        }
    }
    else if (tag == WIN_POOL_TAG_TOKE || tag == WIN_POOL_TAG_TOKE2)
    {
        // This is a _TOKEN
        if (size < PAGE_SIZE - 2 * WIN_POOL_HEADER_SIZE)
        {
            size = PAGE_SIZE - 2 * WIN_POOL_HEADER_SIZE;
        }
    }

    // Patch back the size
    status = IntDetPatchArgument(Detour, 1, size);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetPatchArgument failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    return status;
}


INTSTATUS
IntWinPoolHandleFree(
    _In_ void *Detour
    )
///
/// @brief      Detour callback for ExFreePoolWithTag.
/// @ingroup    group_detours
///
/// This function handles de-allocation requests executed by the guest. It will check the
/// list of hooked structures to check if any of the structures is being de-allocated, in
/// which case, it will remove the EPT protection on that structure.
///
/// @param[in]  Detour The detour object.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    DWORD tag;
    QWORD address;
    QWORD args[2];

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntDetGetArguments(Detour, 2, args);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    tag = (DWORD)args[0];
    address = args[1];

    // Handle the free, if it's a tag that interests us.
    if ((tag == 0xF6697244) || (tag == 0x76697244) || (tag == 0x69664d46)) // Driver object or fast I/O dispatch
    {
        status = IntWinDrvObjRemoveFromAddress(address);
        if (!INT_SUCCESS(status) && (INT_STATUS_NOT_FOUND != status))
        {
            ERROR("[ERROR] IntWinDrvObjRemove failed: 0x%08x\n", status);
        }
    }

cleanup_and_exit:
    return status;
}

//
// IntWinPoolGetPoolHeaderInPage
//
const POOL_HEADER*
IntWinPoolGetPoolHeaderInPage(
    _In_ const void* Page,
    _In_ DWORD StartOffset,
    _In_ DWORD Tag
    )
///
/// @brief         Search for a pool header with given tag in a buffer.
///
/// Will simply iterate the map in a backwards direction, checking if any
/// memory blocks resemble a nt!_POOL_HEADER and matches the given pool
/// tag
///
/// @param[in]     Page         Pointer to a mapped guest page.
/// @param[in]     StartOffset  Offset in given page from where to begin searching.
/// @param[in]     Tag          Pool tag to match.
///
/// @returns       A pointer to the found pool header inside the map, or NULL.
///
{
    const POOL_HEADER *phs;
    int i;

    if (NULL == Page)
    {
        return NULL;
    }

    if ((QWORD)StartOffset + sizeof(POOL_HEADER) > PAGE_SIZE)
    {
        return NULL;
    }

    i = StartOffset;

    while (i >= 0)
    {
        phs = (const POOL_HEADER*)((size_t)Page + i);

        if (Tag == (gGuest.Guest64 ? phs->Header64.PoolTag : phs->Header32.PoolTag))
        {
            return phs;
        }

        i -= WIN_POOL_HEADER_SIZE;
    }

    return NULL;
}
