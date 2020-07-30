/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "kernvm.h"
#include "hook.h"
#include "icache.h"
#include "introcpu.h"


INTSTATUS
IntSplitVirtualAddress(
    _In_ QWORD VirtualAddress,
    _Out_ DWORD *OffsetsCount,
    _Out_writes_(MAX_TRANSLATION_DEPTH) QWORD *OffsetsTrace
    )
///
/// @brief Split a linear address into page-table indexes.
///
/// Splits the given virtual address in indexes inside the paging structures. It handles every possible paging mode.
/// For example, in 4 level paging, OffsetsTrace[0] will contain PML4 index, OffsetsTrace[1], PDP index, etc.
///
/// @param[in]  VirtualAddress  The virtual address to be split in indexes.
/// @param[out] OffsetsCount    The number of offsets extracted.
/// @param[out] OffsetsTrace    Will contain, upon return, each index inside each page-table level.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    DWORD count;

    if (NULL == OffsetsCount)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == OffsetsTrace)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    count = 0;

    if (gGuest.Guest64 && gGuest.LA57)
    {
        OffsetsTrace[count++] = 8ull * PML5_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PML4_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PDP_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PD_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PT_INDEX(VirtualAddress);
    }
    else if (gGuest.Guest64)
    {
        OffsetsTrace[count++] = 8ull * PML4_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PDP_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PD_INDEX(VirtualAddress);
        OffsetsTrace[count++] = 8ull * PT_INDEX(VirtualAddress);
    }
    else
    {
        if (gGuest.PaeEnabled)
        {
            // PAE paging
            OffsetsTrace[count++] = 8ull * (((DWORD)VirtualAddress & 0xC0000000) >> 30);
            OffsetsTrace[count++] = 8ull * PD_INDEX(VirtualAddress);
            OffsetsTrace[count++] = 8ull * PT_INDEX(VirtualAddress);
        }
        else
        {
            // Standard 32 bit paging
            OffsetsTrace[count++] = 4ull * PD32_INDEX(VirtualAddress);
            OffsetsTrace[count++] = 4ull * PT32_INDEX(VirtualAddress);
        }
    }

    *OffsetsCount = count;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntIterateVirtualAddressSpaceRec(
    _In_ QWORD VirtualAddress,
    _In_ QWORD Cr3,
    _In_ QWORD CurrentPage,
    _In_ BYTE PagingMode,
    _In_ BYTE Level,
    _In_ PFUNC_VirtualAddressSpaceCallback Callback
    )
///
/// @brief Iterate, recursively, an entire virtual address space.
///
/// Recursively iterate the entire virtual address space identified by Cr3. For each valid, mapped linear address,
/// it will call the provided callback, passing the virtual address, virtual address space, page size and the
/// page-table entry as parameters.
///
/// @param[in]  VirtualAddress  Current linear address.
/// @param[in]  Cr3             Virtual address space to be iterated.
/// @param[in]  CurrentPage     Current page table to be parsed.
/// @param[in]  PagingMode      Paging mode: legacy, PAE, 4-level, 5-level.
/// @param[in]  Level           Current page-table level (PML4 - 0, PDP - 1, etc.)
/// @param[in]  Callback        Callback to be called for each valid mapped linear address.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    QWORD localVirtualAddress;
    DWORD i;

    if (0 == CurrentPage)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (0 == Level)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (PAGING_5_LEVEL_MODE == PagingMode)
    {
        PQWORD pPage;

        status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        for (i = 0; i < PAGE_SIZE / 8; i++)
        {
            localVirtualAddress = PAGE_SX(VirtualAddress | ((QWORD)i << (12 + (9 * (Level - 1)))));

            if (pPage[i] & 1)
            {
                if (1 == Level)
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_4K);
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_2M);
                }
                else if ((3 == Level) && (0 != (pPage[i] & PDP_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_1G);
                }
                else if ((4 == Level) && (0 != (pPage[i] & PDP_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], 512 * PAGE_SIZE_1G);
                }
                else
                {
                    status = IntIterateVirtualAddressSpaceRec(localVirtualAddress,
                                                              Cr3,
                                                              pPage[i] & PHYS_PAGE_MASK,
                                                              PagingMode,
                                                              Level - 1,
                                                              Callback);
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else if (PAGING_4_LEVEL_MODE == PagingMode)
    {
        PQWORD pPage;

        status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        for (i = 0; i < PAGE_SIZE / 8; i++)
        {
            localVirtualAddress = PAGE_SX(VirtualAddress | ((QWORD)i << (12 + (9 * (Level - 1)))));

            if (pPage[i] & 1)
            {
                if ((pPage[i] & PHYS_PAGE_MASK) == (CurrentPage & PHYS_PAGE_MASK))
                {
                    // self-map, ignore.
                    continue;
                }

                if (1 == Level)
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_4K);
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_2M);
                }
                else if ((3 == Level) && (0 != (pPage[i] & PDP_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_1G);
                }
                else
                {
                    status = IntIterateVirtualAddressSpaceRec(localVirtualAddress,
                                                              Cr3,
                                                              pPage[i] & PHYS_PAGE_MASK,
                                                              PagingMode,
                                                              Level - 1,
                                                              Callback);
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else if (PAGING_PAE_MODE == PagingMode)
    {
        PQWORD pPage;

        if (3 == Level)
        {
            status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        }
        else
        {
            status = IntPhysMemMap(CurrentPage, 32, 0, &pPage);
        }
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        for (i = 0; i < (DWORD)((3 == Level) ? 4 : (PAGE_SIZE / 8)); i++)
        {
            localVirtualAddress = ((DWORD)VirtualAddress | (i << (12 + (9 * (Level - 1)))));

            if ((pPage[i] & PHYS_PAGE_MASK) == (CurrentPage & PHYS_PAGE_MASK))
            {
                // self-map, ignore.
                continue;
            }

            if (pPage[i] & 1)
            {
                if (1 == Level)
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_4K);
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_2M);
                }
                else
                {
                    status = IntIterateVirtualAddressSpaceRec(localVirtualAddress,
                                                              Cr3,
                                                              pPage[i] & PHYS_PAGE_MASK,
                                                              PagingMode,
                                                              Level - 1,
                                                              Callback);
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else if (PAGING_NORMAL_MODE == PagingMode)
    {
        PDWORD pPage;

        status = IntPhysMemMap(CurrentPage, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        for (i = 0; i < PAGE_SIZE / 4; i++)
        {
            localVirtualAddress = ((DWORD)VirtualAddress | (i << (12 + (10 * (Level - 1)))));

            if (pPage[i] & 1)
            {
                if (((QWORD)pPage[i] & PHYS_PAGE_MASK) == (CurrentPage & PHYS_PAGE_MASK))
                {
                    // self-map, ignore.
                    continue;
                }

                if (1 == Level)
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_4K);
                }
                else if ((2 == Level) && (0 != (pPage[i] & PD_PS)))
                {
                    status = Callback(Cr3, localVirtualAddress, pPage[i], PAGE_SIZE_4M);
                }
                else
                {
                    status = IntIterateVirtualAddressSpaceRec(localVirtualAddress,
                                                              Cr3,
                                                              pPage[i] & PHYS_PAGE_MASK,
                                                              PagingMode,
                                                              Level - 1,
                                                              Callback);
                }
            }
        }

        IntPhysMemUnmap(&pPage);

    }
    else
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    return status;
}


INTSTATUS
IntIterateVirtualAddressSpace(
    _In_ QWORD Cr3,
    _In_ PFUNC_VirtualAddressSpaceCallback Callback
    )
///
/// @brief Iterate an entire virtual address space.
///
/// Iterate the entire virtual address space identified by Cr3. For each valid, mapped linear address,
/// it will call the provided callback, passing the virtual address, virtual address space, page size and the
/// page-table entry as parameters.
///
/// @param[in]  Cr3         Virtual address space to be iterated.
/// @param[in]  Callback    Callback to be called for each valid mapped linear address.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    QWORD efer, cr0, cr4;

    if ((0 == Cr3) || (0 != (Cr3 & PAGE_OFFSET)))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    efer = 0;
    cr0 = 0;
    cr4 = 0;

    status = IntCr0Read(IG_CURRENT_VCPU, &cr0);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntCr4Read(IG_CURRENT_VCPU, &cr4);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntEferRead(IG_CURRENT_VCPU, &efer);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (0 != (efer & EFER_LMA) && 0 != (cr4 & CR4_LA57))
    {
        status = IntIterateVirtualAddressSpaceRec(0, Cr3, Cr3, PAGING_5_LEVEL_MODE, 5, Callback);
    }
    else if (0 != (efer & EFER_LMA))
    {
        status = IntIterateVirtualAddressSpaceRec(0, Cr3, Cr3, PAGING_4_LEVEL_MODE, 4, Callback);
    }
    else if (0 != (cr4 & CR4_PAE))
    {
        status = IntIterateVirtualAddressSpaceRec(0, Cr3, Cr3, PAGING_PAE_MODE, 3, Callback);
    }
    else if (0 != (cr0 & CR0_PG))
    {
        status = IntIterateVirtualAddressSpaceRec(0, Cr3, Cr3, PAGING_NORMAL_MODE, 2, Callback);
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntValidateRangeForWrite(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ DWORD Size,
    _In_ DWORD Ring
    )
///
/// @brief Validate a range of virtual memory for write.
///
/// This function will make sure that the virtual address range [VirtualAddress, VirtualAddress + Size] is accessible:
/// - each page must be mapped
/// - each page must be writable
/// - each page must be kernel page if ring is 0, user page if ring is 3
/// - each page must be writable in EPT
/// Note: when writing guest memory, it is highly indicated to pause all the VCPUS while this and the write functions
/// are called; this eliminates possible race conditions induced by an attacker in order to make us modify undesired
/// memory areas.
///
/// @param[in]  Cr3             Virtual address space for the modification.
/// @param[in]  VirtualAddress  Virtual address to be validated.
/// @param[in]  Size            Size of the write.
/// @param[in]  Ring            Required privilege level for the write.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_PAGE_NOT_PRESENT If the page is not present.
/// @retval #INT_STATUS_ACCESS_DENIED If at least one check did not pass, and the caller should not write the
/// target address.
///
{
    INTSTATUS status;
    VA_TRANSLATION tr = {0};
    QWORD va;
    BYTE r, w, x;

    r = w = x = 0;

    for (va = VirtualAddress & PAGE_MASK; va < VirtualAddress + Size; va += PAGE_SIZE)
    {
        status = IntTranslateVirtualAddressEx(va, Cr3, TRFLG_NONE, &tr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
            return status;
        }

        // Make sure the page is present.
        if (0 == (tr.Flags & PT_P))
        {
            ERROR("[ERROR] Page %llx is not present!\n", va);
            return INT_STATUS_PAGE_NOT_PRESENT;
        }

        // Make sure the page is writable.
        if (!tr.IsWritable)
        {
            ERROR("[ERROR] Page %llx is not writable!\n", va);
            return INT_STATUS_ACCESS_DENIED;
        }

        // Make sure rings match.
        if ((0 == Ring) && tr.IsUser)
        {
            ERROR("[ERROR] Page %llx is not a kernel page!\n", va);
            return INT_STATUS_ACCESS_DENIED;
        }

        if ((3 == Ring) && !tr.IsUser)
        {
            ERROR("[ERROR] Page %llx is not a user page!\n", va);
            return INT_STATUS_ACCESS_DENIED;
        }

        // Make sure it is writable in EPT.
        status = IntHookGpaGetEPTPageProtection(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &r, &w, &x);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaGetEPTPageProtection failed: 0x%08x\n", status);
            return status;
        }

        if (w == 0)
        {
            ERROR("[ERROR] Page %llx is not a writable in EPT!\n", va);
            return INT_STATUS_ACCESS_DENIED;
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntVirtMemSafeWrite(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ DWORD Size,
    _In_reads_bytes_(Size) void *Buffer,
    _In_ DWORD Ring
    )
///
/// @brief Safely modify guest memory.
///
/// Safely write the destination virtual address, after making sure that all checks have passed, by calling
/// #IntValidateRangeForWrite.
///
/// @param[in]  Cr3             Target virtual address space.
/// @param[in]  VirtualAddress  Virtual address to be modified.
/// @param[in]  Size            Number of bytes to write at VirtualAddress. 
/// @param[in]  Buffer          The source buffer.
/// @param[in]  Ring            The required privilege level for the write.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory allocation function failed.
/// @retval #INT_STATUS_PAGE_NOT_PRESENT If the target page is not present.
/// @retval #INT_STATUS_ACCESS_DENIED If at least a check failed, and it is not safe to modify VirtualAddress.
///
{
    INTSTATUS status;
    VA_TRANSLATION tr = {0};
    PBYTE *pa;
    QWORD va;
    DWORD pagesCount, i, left, offset;
    BYTE r, w, x;
    PBYTE pbuf;

    pa = NULL;
    i = 0;
    r = w = x = 0;
    pbuf = NULL;

    // Handle potential overflows.
    if (Size == 0)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (VirtualAddress + Size - 1 < VirtualAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pagesCount = Size / PAGE_SIZE + 2;

    pa = HpAllocWithTag(pagesCount * sizeof(void *), IC_TAG_ALLOC);
    if (NULL == pa)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Before actually parsing & injecting our code/data inside the guest, we must invalidate the instruction cache.
    // In some cases, Windows re-uses the INIT section of the kernel as non-paged memory. However, the original
    // translations are not modified and the physical pages are not written, so there's no reason to invalidate
    // those pages inside the cache. However, when we write guest memory, we may patch cached pages, which may lead
    // to problems. In order to make things safe, we invalidate the cache.
    if (NULL != gGuest.InstructionCache)
    {
        status = IntIcFlush(gGuest.InstructionCache);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIcFlush failed: 0x%08x\n", status);
        }
    }

    if (0 == Cr3)
    {
        status = IntCr3Read(IG_CURRENT_VCPU, &Cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    for (va = VirtualAddress & PAGE_MASK; va <= VirtualAddress + Size - 1; va += PAGE_SIZE)
    {
        // Translate the given VA
        status = IntTranslateVirtualAddressEx(va, Cr3, TRFLG_NONE, &tr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        // Make sure the page is present.
        if (0 == (tr.Flags & PT_P))
        {
            ERROR("[ERROR] Page %llx is not present!\n", va);
            status = INT_STATUS_PAGE_NOT_PRESENT;
            goto cleanup_and_exit;
        }

        // Make sure the page is writable. No need to check CR0.WP, as we deny writes if the page is not writable.
        if (!tr.IsWritable)
        {
            ERROR("[ERROR] Page %llx is not writable!\n", va);
            status = INT_STATUS_ACCESS_DENIED;
            goto cleanup_and_exit;
        }

        // Make sure rings match. No need to check SMAP, since we write user pages only for ring3. No need to check
        // SMEP either, as we're only concerned with writes.
        if ((0 == Ring) && tr.IsUser)
        {
            ERROR("[ERROR] Page %llx is not a kernel page!\n", va);
            status = INT_STATUS_ACCESS_DENIED;
            goto cleanup_and_exit;
        }

        if ((3 == Ring) && !tr.IsUser)
        {
            ERROR("[ERROR] Page %llx is not a user page!\n", va);
            status = INT_STATUS_ACCESS_DENIED;
            goto cleanup_and_exit;
        }

        // Make sure it is writable in EPT.
        status = IntHookGpaGetEPTPageProtection(gGuest.UntrustedEptIndex, tr.PhysicalAddress, &r, &w, &x);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGpaGetEPTPageProtection failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }

        if (w == 0)
        {
            BYTE ir, iw, ix;

            ir = iw = ix = 1;

            status = IntHookGpaIsPageHooked(tr.PhysicalAddress, &ir, &iw, &ix);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGpaIsPageHooked failed: 0x%08x\n", status);
                goto cleanup_and_exit;
            }

            if (iw == 0)
            {
                ERROR("[ERROR] Page %llx/%llx is not a writable in EPT!\n", va, tr.PhysicalAddress);
                status = INT_STATUS_ACCESS_DENIED;
                goto cleanup_and_exit;
            }
        }

        status = IntPhysMemMap(tr.PhysicalAddress, PAGE_SIZE, 0, &pa[i++]);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    // Do the actual writes inside the mapped pages.
    pbuf = (PBYTE)Buffer;
    left = Size;
    va = VirtualAddress;
    offset = 0;
    i = 0;

    pa[0] += VirtualAddress & 0xFFF;

    while (left > 0)
    {
        DWORD currentSize = MIN(left, PAGE_REMAINING(va));

        memcpy(pa[i++], pbuf + offset, currentSize);

        left -= currentSize;

        va += currentSize;

        offset += currentSize;
    }

    pa[0] -= VirtualAddress & 0xFFF;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (NULL != pa)
    {
        for (i = 0; i < pagesCount; i++)
        {
            if (NULL != pa[i])
            {
                IntPhysMemUnmap(&pa[i]);
            }
        }

        HpFreeAndNullWithTag(&pa, IC_TAG_ALLOC);
    }

    return status;
}
