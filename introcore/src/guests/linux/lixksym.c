/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixksym.h"
#include "guests.h"


#define KSYM_NUM_SYMBOLS_CAP        200000  ///< The maximum number of symbols allowed to be in kallsyms.
#define KSYM_TOKEN_TABLE_SIZE_CAP   2000    ///< The maximum size allowed for the tokens table size.
#define KSYM_NAMES_CACHE_SIZE_CAP   2000000 ///< The maximum size allowed for the names.
#define KSYM_TOKEN_ARRAY_CACHE_SIZE 256     ///< The size of tokens array cache.
#define KSYM_MARKERS_RANGE_MAX      0x3000  ///< The maximum value for [ksym_marker, ksym_marker + 1] range

///
/// @brief Describes the structure of the internal kallsyms buffers and other data required for
/// the semantic reconstruction.
///
typedef struct _KALLSYMS_BUFFERS
{

    QWORD           RelativeBase;           ///< The relative base for relative indexes. This has to
                                            ///< have the same value as gGuest.KernelVA.

    /// Guest virtual address of either Indexes table (for kernels compiled with CONFIG_KALLSYMS_BASE_RELATIVE)
    /// or Addresses table (for those kernels compile without the previously mentioned flag).
    union
    {
        QWORD       Addresses;              ///< The guest virtual address of Addresses table.
        QWORD       Indexes;                ///< The guest virtual address of Indexes table.
    };

    INT32           NumberOfNames;          ///< The number of symbols available in kallsyms.
    QWORD           Names;                  ///< The guest virtual address of the names table.

    char            *NamesBuffer;           ///< The internal name cache used for a faster symbol lookup.
    DWORD           NamesBufferSize;        ///< The size of NamesBuffer.

    union
    {
        QWORD       *AddressesBuffer;       ///< The internal addresses buffer.
        INT32       *IndexesBuffer;         ///< The Internal indexes buffer.
    };

    char            *TokenTable;            ///< The internal tokens table.
    DWORD           TokenTableSize;         ///< The size of the internal tokens table.

    WORD            TokenIndex[KSYM_TOKEN_ARRAY_CACHE_SIZE]; ///< The tokens array cached internally.

    BOOLEAN         Initialized;            ///< The flag that marks whether the kallsyms module is initialized or not.
} KALLSYMS_BUFFERS, *PKALLSYMS_BUFFERS;


///
/// @brief Contains information about kallsyms required for the semantic reconstruction.
///
static KALLSYMS_BUFFERS gKallsymsBuffers;


static DWORD
IntKsymExpandSymbol(
    _In_ DWORD Offset,
    _In_ DWORD MaxLength,
    _Out_ char *Name
    )
///
/// @brief Expands a kallsyms symbol name.
///
/// If the name buffer is not large enough then the symbol name will be truncated to fit.
///
/// @param[in]  Offset    The symbol name offset in #KALLSYMS_BUFFERS::NamesBuffer array.
/// @param[in]  MaxLength The maximum symbol length. Usually #LIX_SYMBOL_NAME_LEN is enough.
/// @param[out] Name      The buffer where the name would be stored.
///
/// @return The offset of the next symbol
///
{
    BOOLEAN skipped = FALSE;
    char *pKallsymsNames = NULL;
    const BYTE *pData = NULL;
    BYTE length = 0;
    DWORD nextOffset = 0;

    if (Offset >= gKallsymsBuffers.NamesBufferSize)
    {
        ERROR("[ERROR] The provided offset is greater than the size of names buffer\n");
        return 0;
    }

    pKallsymsNames = gKallsymsBuffers.NamesBuffer + Offset;
    pData = (const BYTE *)pKallsymsNames;
    length = *pData;

    if (0 == length)
    {
        WARNING("[WARNING] Wrong symbol size %d\n", length);
        return 0;
    }

    pData++;
    nextOffset = Offset + length + 1;

    if (Offset + length >= gKallsymsBuffers.NamesBufferSize)
    {
        ERROR("[ERROR] The length of symbol exceeds the names buffer\n");
        return 0;
    }

    if (nextOffset >= gKallsymsBuffers.NamesBufferSize)
    {
        ERROR("[ERROR] The next offset exceeds the names buffer\n");
        return 0;
    }

    while (length)
    {
        char *tptr = NULL;
        const DWORD idx = gKallsymsBuffers.TokenIndex[*pData];

        if (idx >= gKallsymsBuffers.TokenTableSize)
        {
            ERROR("[ERROR] The token_index is greater than the size of token table\n");
            return 0;
        }

        tptr = &gKallsymsBuffers.TokenTable[idx];
        pData++;
        length--;

        while (*tptr && ((QWORD)tptr < (QWORD)gKallsymsBuffers.TokenTable + gKallsymsBuffers.TokenTableSize))
        {
            if (skipped)
            {
                if (MaxLength <= 1)
                {
                    goto _tail;
                }

                *Name = *tptr;
                Name++;
                MaxLength--;
            }
            else
            {
                skipped = TRUE;
            }

            ++tptr;
        }
    }

_tail:
    if (MaxLength)
    {
        // Put the final NULL-terminator
        *Name = '\0';
    }

    return nextOffset;
}


static QWORD
IntKsymGetAddress(
    _In_ INT32 Index
    )
///
/// @brief Returns the address of the symbol located at the given index in the symbols table.
///
/// @param[in] Index The symbol index.
///
/// @retval The guest virtual address of the symbol.
///
{
    if (!LIX_FIELD(Info, HasKsymRelative))
    {
        return gKallsymsBuffers.AddressesBuffer[Index];
    }

    if (!LIX_FIELD(Info, HasKsymAbsolutePercpu))
    {
        return gKallsymsBuffers.RelativeBase + (DWORD)gKallsymsBuffers.IndexesBuffer[Index];
    }

    if (gKallsymsBuffers.IndexesBuffer[Index] >= 0)
    {
        return gKallsymsBuffers.IndexesBuffer[Index];
    }

    return gKallsymsBuffers.RelativeBase - 1 - gKallsymsBuffers.IndexesBuffer[Index];
}


static INTSTATUS
IntKsymRelativeFindOffsetTableStart(
    _Out_ QWORD *Address
    )
///
/// @brief Finds the start of 'kallsyms_offsets' memory region.
///
/// The function searches for 16 ordered int's; then the whole page is checked if contains ordered int's.
///
/// @param[in]  Address     The address of 'kallsyms_offsets'.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the start of 'kallsyms_offsets' is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD currentAddr = gLixGuest->Layout.RoDataStart & PAGE_MASK;
    QWORD startAddr = 0;
    INT32 *ptr = NULL;

    ptr = HpAllocWithTag(PAGE_SIZE, IC_TAG_ALLOC);
    if (!ptr)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    for (; currentAddr < gLixGuest->Layout.RoDataEnd; currentAddr += PAGE_SIZE)
    {
        INT32 *pPage = NULL;

        status = IntVirtMemMap(currentAddr, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
            break;
        }

        for (DWORD i = 0; i < (PAGE_SIZE / 4) - 16; i++)
        {
            if (pPage[i] < 0)
            {
                continue;
            }

            // 16 ordered int's (assume they are > 0)
            if (pPage[i] > pPage[i + 1] ||
                pPage[i + 1] >= pPage[i + 2] ||
                pPage[i + 2] >= pPage[i + 3] ||
                pPage[i + 3] >= pPage[i + 4] ||
                pPage[i + 4] >= pPage[i + 5] ||
                pPage[i + 5] >= pPage[i + 6] ||
                pPage[i + 6] >= pPage[i + 7] ||
                pPage[i + 7] >= pPage[i + 8] ||
                pPage[i + 8] >= pPage[i + 9] ||
                pPage[i + 9] >= pPage[i + 10] ||
                pPage[i + 10] >= pPage[i + 11] ||
                pPage[i + 11] >= pPage[i + 12] ||
                pPage[i + 12] >= pPage[i + 13] ||
                pPage[i + 13] >= pPage[i + 14] ||
                pPage[i + 14] >= pPage[i + 15])
            {
                continue;
            }

            startAddr = currentAddr + i * 4ull;

            break;
        }

        if (startAddr)
        {
            status = IntVirtMemRead(startAddr, PAGE_SIZE, gGuest.Mm.SystemCr3, ptr, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", startAddr, status);

                IntVirtMemUnmap(&pPage);

                break;
            }

            for (DWORD i = 1; i < PAGE_SIZE / 4 - 3; i++)
            {
                // Is this is the startup_64/_text ?
                if (LIX_FIELD(Info, HasKsymAbsolutePercpu))
                {
                    if (ptr[i] == -1 && ptr[i + 1] == -1)
                    {
                        break;
                    }
                }
                else
                {
                    if (ptr[i] == 0 && ptr[i + 1] == 0)
                    {
                        break;
                    }
                }

                // everything must be ordered
                if (ptr[i] < ptr[i - 1])
                {
                    startAddr = 0;
                    break;
                }
            }
        }

        IntVirtMemUnmap(&pPage);

        if (startAddr)
        {
            TRACE("[KALLSYMS RELATIVE] Found indexes start @%llx\n", startAddr);
            break;
        }
    }

    HpFreeAndNullWithTag(&ptr, IC_TAG_ALLOC);

    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (!startAddr)
    {
        return INT_STATUS_NOT_FOUND;
    }

    *Address = startAddr;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntKsymRelativeFindOffsetTableEnd(
    _In_ QWORD StartAddress
    )
///
/// @brief Finds the end of 'kallsyms_offsets' memory region.
///
/// In order to find the end of 'kallsyms_offsets', the function tries to find the 'kallsyms_relative_base' or an
/// offset that is equal to 0.
/// The 'kallsyms_num_syms', 'kallsyms_relative_base' and 'kallsyms_relative_base' symbols are fetched.
///
/// @param[in]  StartAddress        The guest virtual address of 'kallsyms_offsets'.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the end of 'kallsyms_offsets' is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD currentAddr = 0;
    QWORD endAddr = 0;
    BOOLEAN firstNegative = FALSE;
    BOOLEAN firstPositive = FALSE;

    for (currentAddr = StartAddress; currentAddr < gLixGuest->Layout.RoDataEnd;)
    {
        INT32 *pPage = NULL;
        DWORD offset = currentAddr & PAGE_OFFSET;

        status = IntVirtMemMap(currentAddr, PAGE_SIZE - offset, gGuest.Mm.SystemCr3, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
            return status;
        }

        for (DWORD i = 0; i < ((PAGE_SIZE - offset) / 4) - 1; i++)
        {
            if (pPage[i] == -1 && pPage[i + 1] == -1)
            {
                firstNegative = TRUE;
                continue;
            }

            if (!firstNegative)
            {
                continue;
            }

            if (!firstPositive && pPage[i] > 0)
            {
                firstPositive = TRUE;
                continue;
            }

            if (*(QWORD *)(pPage + i) == gGuest.KernelVa)
            {
                endAddr = currentAddr + i * 4ull;
                break;
            }

            if (pPage[i] == 0)
            {
                endAddr = currentAddr + i * 4ull;
                break;
            }

            if (LIX_FIELD(Info, HasKsymAbsolutePercpu))
            {
                if ((!firstPositive && pPage[i] < 0) ||
                    (firstPositive && pPage[i + 1] >= pPage[i]))
                {
                    continue;
                }
            }
            else
            {
                if (pPage[i] <= pPage[i + 1])
                {
                    continue;
                }
            }

            endAddr = currentAddr + i * 4ull;
            break;
        }

        IntVirtMemUnmap(&pPage);

        currentAddr += PAGE_SIZE - offset;

        if (endAddr)
        {
            QWORD relativeBase = 0;
            DWORD numberOfNames = 0;
            DWORD foundNames = (DWORD)(endAddr - StartAddress) / 4;

            status = IntKernVirtMemFetchQword(ALIGN_UP(endAddr, 8), &relativeBase);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemFetchQword failed for GVA 0x%016llx with status: 0x%08x\n",
                      endAddr, status);
                endAddr = 0;
                continue;
            }

            if (relativeBase != gGuest.KernelVa)
            {
                endAddr = 0;
                continue;
            }

            if (LIX_FIELD(Info, HasKsymSize))
            {
                // Skip the sizes region
                // * 2 because each offset entry is 4 bytes long and the size of a kallsmys_size entry is 8 bytes.
                endAddr += (endAddr - StartAddress) * 2;
            }

            status = IntKernVirtMemFetchDword(ALIGN_UP(endAddr, 8) + 8, &numberOfNames);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemFetchDword failed for GVA 0x%016llx with status: 0x%08x\n",
                      endAddr, status);
                endAddr = 0;
                continue;
            }

            TRACE("[KALLSYMS] num_symbols (found): %d\n", foundNames);

            // Did we parsed too much or too little (assume an error of 0x40)
            if ((foundNames > numberOfNames &&
                 foundNames - numberOfNames > 0x40) ||
                (foundNames < numberOfNames &&
                 numberOfNames - foundNames > 0x40))
            {
                endAddr = 0;
                continue;
            }

            if (numberOfNames > KSYM_NUM_SYMBOLS_CAP)
            {
                ERROR("[ERROR] Kallsyms number of names exceeds the limit: %u vs %u",
                      numberOfNames, KSYM_NUM_SYMBOLS_CAP);
                continue;
            }

            gKallsymsBuffers.RelativeBase = relativeBase;

            gKallsymsBuffers.NumberOfNames = numberOfNames;
            gKallsymsBuffers.Indexes = ALIGN_DOWN(endAddr - numberOfNames * 4ull, 8);

            if (LIX_FIELD(Info, HasKsymSize))
            {
                // Also skip the sizes region ( 8 * numberOfSymbols)
                gKallsymsBuffers.Indexes -= numberOfNames * 8ull;
            }

            gKallsymsBuffers.Names = ALIGN_UP(endAddr, 8) + 16;

            break;
        }
    }

    if (0 == gKallsymsBuffers.NumberOfNames)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntKsymInitRelative(
    void
    )
///
/// @brief Initializes the kallsyms subsystem for kernels compiled with CONFIG_KALLSYMS_BASE_RELATIVE.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If any structures were not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD tableOffsetsStartAddr = 0;

    status = IntKsymRelativeFindOffsetTableStart(&tableOffsetsStartAddr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKsymRelativeFindOffsetTableStart failed with status: 0x%08x\n", status);
        return status;
    }

    status = IntKsymRelativeFindOffsetTableEnd(tableOffsetsStartAddr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKsymRelativeFindOffsetTableEnd failed with status: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntKsymInitAbsolute(
    void
    )
///
/// @brief Initializes the kallsyms subsystem for kernels compiled without CONFIG_KALLSYMS_BASE_RELATIVE.
///
/// @retval INT_STATUS_SUCCESS If the initialization completed without any errors.
/// @retval INT_STATUS_NOT_FOUND If any structures were not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD gvaStart = gLixGuest->Layout.RoDataStart & PAGE_MASK;
    QWORD addrStart = 0;
    QWORD numGva = 0;
    QWORD prev = 0;
    INT32 num = 0;
    QWORD *pPage = NULL;
    BOOLEAN foundStart = FALSE;

    while (gvaStart < gLixGuest->Layout.RoDataEnd)
    {
        BOOLEAN redoPage = FALSE;

        status = IntVirtMemMap(gvaStart, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with status: 0x%08x\n", gvaStart, status);
            return status;
        }

        if (!foundStart)
        {
            for (DWORD i = 0; i < (PAGE_SIZE / 8) - 8; i++)
            {
                // Make sure each of the eight pointers point inside the code section...
                if ((pPage[i] < gLixGuest->Layout.CodeStart || pPage[i] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 1] < gLixGuest->Layout.CodeStart || pPage[i + 1] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 2] < gLixGuest->Layout.CodeStart || pPage[i + 2] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 3] < gLixGuest->Layout.CodeStart || pPage[i + 3] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 4] < gLixGuest->Layout.CodeStart || pPage[i + 4] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 5] < gLixGuest->Layout.CodeStart || pPage[i + 5] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 6] < gLixGuest->Layout.CodeStart || pPage[i + 6] > gLixGuest->Layout.CodeEnd) ||
                    (pPage[i + 7] < gLixGuest->Layout.CodeStart || pPage[i + 7] > gLixGuest->Layout.CodeEnd))
                {
                    continue;
                }

                // ... and each one points inside the first two pages...
                if (pPage[i] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 1] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 2] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 3] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 4] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 5] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 6] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE ||
                    pPage[i + 7] - gLixGuest->Layout.CodeStart > 3 * PAGE_SIZE)
                {
                    continue;
                }

                // ... and they are ordered.
                if (pPage[i] < pPage[i + 1] &&
                    pPage[i + 1] < pPage[i + 2] &&
                    pPage[i + 2] < pPage[i + 3] &&
                    pPage[i + 3] < pPage[i + 4] &&
                    pPage[i + 4] < pPage[i + 5] &&
                    pPage[i + 5] < pPage[i + 6] &&
                    pPage[i + 6] < pPage[i + 7])
                {
                    addrStart = gvaStart + i * 8ull;
                    prev = pPage[i];

                    foundStart = TRUE;

                    break;
                }
            }
        }
        else
        {
            for (DWORD i = 0; i < PAGE_SIZE / 8; i++)
            {
                QWORD val = pPage[i];

                if ((val > 0) && (val < 0x3FFFF))
                {
                    num = (INT32)val;
                    numGva = gvaStart + i * 8ull;
                    TRACE("[INFO] Found num_symbols start at 0x%016llx: %d\n", gvaStart + i * 8ull, num);
                    break;
                }

                // Is the pointer still good ?!
                if (IS_KERNEL_POINTER_LIX(val) && prev <= val)
                {
                    prev = val;
                    continue;
                }

                if (IS_KERNEL_POINTER_LIX(val) && prev > val)
                {
                    WARNING("[WARNING] Unordered list: 0x%016llx 0x%016llx\n", prev, val);
                }

                redoPage = TRUE;
                foundStart = FALSE;
                addrStart = num = 0;

                WARNING("[WARNING] Found an invalid pointer (prev 0x%016llx) 0x%016llx @ 0x%016llx\n",
                        prev, val, gvaStart + i * 8ull);
                break;
            }
        }

        IntVirtMemUnmap(&pPage);

        if (addrStart && num)
        {
            break;
        }

        if (!redoPage)
        {
            gvaStart += PAGE_SIZE;
        }
    }

    if (!addrStart || !num)
    {
        return INT_STATUS_NOT_FOUND;
    }

    // Now it's the to calculate and determine addresses
    gKallsymsBuffers.NumberOfNames = num;
    gKallsymsBuffers.Addresses = numGva - num * 8ull;
    gKallsymsBuffers.Names = numGva + 8;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntKsymFindMarkersTableEnd(
    _In_ QWORD StartAddress,
    _Out_ QWORD *EndAddress
    )
///
/// @brief Finds the end of 'kallsyms_markers' table.
///
/// The 'marker' size is equal to 8; if the 'marker' value if 0xffffffff, then the end of 'kallsyms_markers' is found.
///
/// @param[in]  StartAddress    The start guest virtual address of 'kallsyms_markers'.
/// @param[out] EndAddress      The end guest virtual address of 'kallsyms_markers'.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the end of 'kallsyms_markers' is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD *pMarkers = NULL;
    QWORD *pAddr = NULL;
    QWORD currentAddr = StartAddress;
    QWORD prevAddr = 0;

    if (StartAddress % sizeof(QWORD) != 0)
    {
        ERROR("[ERROR] The provided address is not aligned (0x%016llx)!\n", StartAddress);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // Skip all the QWORDS until we have a one bigger than 0xffffffff (that's where the token table starts)
    for (DWORD i = 0; i < 2 * PAGE_SIZE / 8; i++)
    {
        if (PAGE_FRAME_NUMBER(prevAddr) != PAGE_FRAME_NUMBER(currentAddr))
        {
            status = IntVirtMemMap(currentAddr, PAGE_REMAINING(currentAddr & PAGE_OFFSET), gGuest.Mm.SystemCr3, 0, &pMarkers);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
                return status;
            }

            pAddr = pMarkers;
        }

        if (pMarkers == NULL)
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (*pMarkers > 0xffffffff)
        {
            *EndAddress = currentAddr;

            status = INT_STATUS_SUCCESS;
            goto _exit;
        }

        prevAddr = currentAddr;
        currentAddr += 8;

        if (PAGE_FRAME_NUMBER(prevAddr) != PAGE_FRAME_NUMBER(currentAddr))
        {
            IntVirtMemUnmap(&pAddr);
            pMarkers = NULL;
        }
        else
        {
            pMarkers++;
        }
    }

    status = INT_STATUS_NOT_FOUND;

_exit:
    if (pMarkers != NULL)
    {
        IntVirtMemUnmap(&pMarkers);
    }

    return status;
}

static INTSTATUS
IntKsymFindMarkersReducedTableEnd(
    _In_ QWORD StartAddress,
    _In_ QWORD *EndAddress
    )
///
/// @brief Finds the end of 'kallsyms_markers' table.
///
/// The 'marker' size is equal to 4; if a sequence of 'markers' is unordered, then the end of 'kallsyms_markers' is found.
///
/// NOTE: This function is used only on kernel version 5.x.x.
///
/// @param[in]  StartAddress    The start guest virtual address of 'kallsyms_markers'.
/// @param[out] EndAddress      The end guest virtual address of 'kallsyms_markers'.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the end of 'kallsyms_markers' is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    DWORD *pMarkers = NULL;
    DWORD *pAddr = NULL;
    DWORD size = 0;
    DWORD remaining = 0;
    QWORD currentAddr = StartAddress;

    if (StartAddress % sizeof(DWORD) != 0)
    {
        ERROR("[ERROR] The provided address is not aligned (0x%016llx)!\n", StartAddress);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // We iterate max 2048 integers to find the end of kallsyms_markers table.
    for (DWORD i = 0; i < (2 * PAGE_SIZE) / sizeof(*pMarkers); i++)
    {
        if (NULL == pMarkers)
        {
            // Because we compare pMarkers[i] with pMarkers[i + 1] we have to make sure that we are always mapping
            // at least 2 * sizeof(*pMarkers) bytes.
            size = PAGE_REMAINING(currentAddr);

            // This is ok, because size will never be 0, and any currentAddr is always incremented by sizeof(DWORD).
            // StartAddress is also aligned to 8-bytes.
            if (size == sizeof(*pMarkers))
            {
                // Here, we can actually add PAGE_SIZE, but it will then go through the slow IntVirtMemMap mechanism
                // which copies the mapped memory into an allocated buffer, because the memory will be split into two
                // pages. It should be faster to do it this way, because we avoid the huge memcpy and the mapping is
                // cached, so for the second page another call to xen will not be issued.
                size += sizeof(*pMarkers);
            }

            remaining = size - sizeof(*pMarkers);

            status = IntVirtMemMap(currentAddr, size, gGuest.Mm.SystemCr3, 0, &pAddr);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
                return status;
            }

            pMarkers = pAddr;
        }

        currentAddr += sizeof(*pMarkers);
        remaining -= sizeof(*pMarkers);

        if ((*pMarkers >= * (pMarkers + 1)) || ((*(pMarkers + 1) - *pMarkers) >= KSYM_MARKERS_RANGE_MAX))
        {
            *EndAddress = currentAddr;

            status = INT_STATUS_SUCCESS;
            goto _exit;
        }

        pMarkers++;

        if (remaining == 0)
        {
            IntVirtMemUnmap(&pAddr);
            pMarkers = NULL;
        }
    }

    status = INT_STATUS_NOT_FOUND;

_exit:
    if (pMarkers != NULL)
    {
        IntVirtMemUnmap(&pMarkers);
    }

    return status;
}


static INTSTATUS
IntKsymFindNamesTableEnd(
    _In_ QWORD StartAddress,
    _In_ QWORD *EndAddress
    )
///
/// @brief Finds the end of 'kallsyms_names' table.
///
/// Each 'name' entry contains the length and the content of it; for each name the current pointer is incremented with
/// the length of the 'name' entry.
///
/// @param[in]  StartAddress    The start guest virtual address of 'kallsyms_names'.
/// @param[out] EndAddress      The end guest virtual address of 'kallsyms_names'.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the end of 'kallsyms_names' is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BYTE *pSymbol = NULL;
    QWORD prevAddr = 0;
    QWORD currentAddr = StartAddress;

    for (INT32 i = 0; i < gKallsymsBuffers.NumberOfNames; i++)
    {
        if (PAGE_FRAME_NUMBER(prevAddr) != PAGE_FRAME_NUMBER(currentAddr))
        {
            status = IntVirtMemMap(currentAddr, PAGE_REMAINING(currentAddr & PAGE_OFFSET), gGuest.Mm.SystemCr3, 0, &pSymbol);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", currentAddr, status);
                return status;
            }
        }

        if (pSymbol == NULL)
        {
            return INT_STATUS_NOT_FOUND;
        }

        prevAddr = currentAddr;
        currentAddr += *pSymbol + 1ull;

        if (PAGE_FRAME_NUMBER(prevAddr) != PAGE_FRAME_NUMBER(currentAddr))
        {
            IntVirtMemUnmap(&pSymbol);
            pSymbol = NULL;
        }
        else
        {
            pSymbol += *pSymbol + 1ull;
        }
    }

    if (NULL != pSymbol)
    {
        IntVirtMemUnmap(&pSymbol);
    }

    *EndAddress = currentAddr;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntKsymFindIndexesTableStart(
    _In_ QWORD TokenTableStart,
    _Out_ QWORD *IndexesTableStart
    )
///
/// @brief Finds the start of 'kallsyms_token_index' table.
///
/// The first 5 indexes are computed based on token table; these indexes are used to find the 'kallsyms_token_index'
/// region.
///
/// @param[in]  TokenTableStart     The start guest virtual address of 'kallsyms_token_table'.
/// @param[out] IndexesTableStart   The start guest virtual address of 'kallsyms_token_index'.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the start of 'kallsyms_token_index' is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    WORD indexes[0x5] = { 0 };
    char tokenSlice[0x30] = { 0 };
    DWORD remainingTokenLength = (DWORD)sizeof(tokenSlice);
    QWORD currentAddr = TokenTableStart;
    QWORD prevAddr = 0;
    WORD *pIndex = NULL;

    status = IntKernVirtMemRead(TokenTableStart, sizeof(tokenSlice), tokenSlice, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", TokenTableStart, status);
        return status;
    }

    indexes[0] = 0;
    for (DWORD i = 1; i < ARRAYSIZE(indexes); i++)
    {
        WORD length = (WORD)strlen_s(&tokenSlice[indexes[i - 1]], remainingTokenLength) + 1;
        indexes[i] = indexes[i - 1] + length;
        remainingTokenLength -= length;

        if ((int)remainingTokenLength < 0)
        {
            ERROR("[ERROR] %zu bytes not enough to find indexes. Stopped at %d!\n", sizeof(tokenSlice), i);
            return INT_STATUS_INVALID_DATA_STATE;
        }
    }

    // Now search the indexes in memory, WORD by WORD
    for (DWORD i = 0; i < PAGE_SIZE / 8; i++)
    {
        WORD idx[sizeof(indexes) / sizeof(indexes[0])];
        DWORD j;
        BOOLEAN found = FALSE;

        if (PAGE_FRAME_NUMBER(prevAddr) != PAGE_FRAME_NUMBER(currentAddr))
        {
            status = IntVirtMemMap(currentAddr, PAGE_REMAINING(currentAddr & PAGE_OFFSET), gGuest.Mm.SystemCr3, 0, &pIndex);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
                return status;
            }
        }

        if (PAGE_FRAME_NUMBER(currentAddr + sizeof(idx)) != PAGE_FRAME_NUMBER(currentAddr))
        {
            status = IntKernVirtMemRead(currentAddr, sizeof(idx), idx, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
                break;
            }
        }
        else
        {
            if (pIndex == NULL)
            {
                return INT_STATUS_NOT_FOUND;
            }

            memcpy(idx, pIndex, sizeof(idx));
        }

        found = TRUE;
        for (j = 0; j < ARRAYSIZE(idx); j++)
        {
            if (idx[j] != indexes[j])
            {
                found = FALSE;
                break;
            }
        }

        if (found)
        {
            *IndexesTableStart = currentAddr;

            status = INT_STATUS_SUCCESS;
            goto _exit;
        }

        prevAddr = currentAddr;
        currentAddr += 8;

        if (PAGE_FRAME_NUMBER(prevAddr) != PAGE_FRAME_NUMBER(currentAddr))
        {
            IntVirtMemUnmap(&pIndex);
            pIndex = NULL;
        }
        else
        {
            pIndex = (WORD *)((BYTE *)pIndex + 8);
        }
    }

    status = INT_STATUS_NOT_FOUND;

_exit:
    if (pIndex != NULL)
    {
        IntVirtMemUnmap(&pIndex);
    }

    return status;
}


INTSTATUS
IntKsymInit(
    void
    )
///
/// @brief Initialize the kallsyms subsystem based on the os info provided by LIX_FIELD(Info, HasKsym*).
///
/// Before calling this function the following subsystem must be fully initialized.
///     * gGuest
///     * Linux kernel layout
///     * Mm subsystem
///     * CAMI subsystem
///
/// @return INT_STATUS_SUCCESS if the initialization completed without any errors.
/// @return INT_STATUS_INSUFFICIENT_RESOURCES if there is not enough available memory.
/// @return INT_STATUS_NOT_FOUND if any guest structures were not found.
/// @return INT_STATUS_INVALID_DATA_STATE if any structure was found in an unexpected state.
/// @return INT_STATUS_INVALID_INTERNAL_STATE if the active OS type is not Linux.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD currentAddr = 0;
    QWORD tokenTableStart = 0;
    DWORD size = 0;
    char *pTokenTable = NULL;
    char *pNames = NULL;
    QWORD *pAddresses = NULL;

    if (gGuest.OSType != introGuestLinux)
    {
        BUG_ON(TRUE);

        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    if (LIX_FIELD(Info, HasKsymRelative))
    {
        status = IntKsymInitRelative();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKsymInitRelative failed: %08x\n", status);
            return status;
        }

        TRACE("[KALLSYMS] indexes     : 0x%016llx\n", gKallsymsBuffers.Indexes);
        TRACE("[KALLSYMS] rel_base    : 0x%016llx\n", gKallsymsBuffers.RelativeBase);
    }
    else
    {
        status = IntKsymInitAbsolute();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKsymInitAbsolute failed: %08x\n", status);
            return status;
        }

        TRACE("[KALLSYMS] addresses   : 0x%016llx\n", gKallsymsBuffers.Addresses);
    }

    TRACE("[KALLSYMS] num_symbols : %d\n", gKallsymsBuffers.NumberOfNames);
    TRACE("[KALLSYMS] names       : 0x%016llx\n", gKallsymsBuffers.Names);

    status = IntKsymFindNamesTableEnd(gKallsymsBuffers.Names, &currentAddr);
    if(!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKsymFindNamesTableEnd failed with status: 0x%08x\n", status);
    }

    currentAddr = ALIGN_UP(currentAddr, 8);

    if (LIX_FIELD(Info, HasKsymReducedSize))
    {
        status = IntKsymFindMarkersReducedTableEnd(currentAddr, &currentAddr);
    }
    else
    {
        status = IntKsymFindMarkersTableEnd(currentAddr, &currentAddr);
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed finding the start of token_table!\n");
        return INT_STATUS_NOT_FOUND;
    }

    tokenTableStart = ALIGN_UP(currentAddr, 8);
    TRACE("[KALLSYMS] token_table : 0x%016llx\n", tokenTableStart);

    status = IntKsymFindIndexesTableStart(tokenTableStart, &currentAddr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKsymFindIndexesTableStart failed with status: 0x%08x\n", status);
        return status;
    }

    gKallsymsBuffers.TokenTableSize = (DWORD)(currentAddr - tokenTableStart);

    if (gKallsymsBuffers.TokenTableSize > KSYM_TOKEN_TABLE_SIZE_CAP)
    {
        ERROR("[ERROR] Tokens table size exceeds the introcore limit: %u vs %u\n",
              gKallsymsBuffers.TokenTableSize, KSYM_TOKEN_TABLE_SIZE_CAP);

        return INT_STATUS_INVALID_DATA_SIZE;
    }

    TRACE("[KALLSYMS] token_size  : %08x\n", gKallsymsBuffers.TokenTableSize);
    TRACE("[KALLSYMS] token_index : 0x%016llx\n", currentAddr);

    status = IntKernVirtMemRead(currentAddr,
                                sizeof(gKallsymsBuffers.TokenIndex),
                                gKallsymsBuffers.TokenIndex,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
        return status;
    }

    pTokenTable = HpAllocWithTag(gKallsymsBuffers.TokenTableSize, IC_TAG_KSYM);
    if (NULL == pTokenTable)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntKernVirtMemRead(tokenTableStart, gKallsymsBuffers.TokenTableSize, pTokenTable, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
        goto _exit;
    }

    size = (DWORD)(tokenTableStart - gKallsymsBuffers.Names);

    if (size > KSYM_NAMES_CACHE_SIZE_CAP)
    {
        ERROR("[ERROR] Kallsyms names size exceeds the introcore limit: %u vs %u",
              size, KSYM_NAMES_CACHE_SIZE_CAP);

        status = INT_STATUS_INVALID_DATA_SIZE;
        goto _exit;
    }

    // Cache the names. Ubuntu 16.04 takes ~1.1MB

    TRACE("[INFO] Cache kallsyms names: %d bytes\n", size);

    pNames = HpAllocWithTag(size, IC_TAG_KSYM);
    if (NULL == pNames)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _exit;
    }

    status = IntKernVirtMemRead(gKallsymsBuffers.Names, size, pNames, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
        goto _exit;
    }

    gKallsymsBuffers.NamesBufferSize = size;

    // Cache the addresses (an array of sorted QWORDS). Ubuntu 16.04 takes ~800kb

    size = (DWORD)(gKallsymsBuffers.NumberOfNames * 8);

    TRACE("[INFO] Cache kallsyms addresses: %d bytes\n", size);

    pAddresses = HpAllocWithTag(size, IC_TAG_KSYM);
    if (NULL == pAddresses)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _exit;
    }

    status = IntKernVirtMemRead(gKallsymsBuffers.Addresses, size, pAddresses, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for GVA 0x%016llx with status: 0x%08x\n", currentAddr, status);
        goto _exit;
    }

    gKallsymsBuffers.TokenTable = pTokenTable;
    gKallsymsBuffers.AddressesBuffer = pAddresses;
    gKallsymsBuffers.NamesBuffer = pNames;

    gKallsymsBuffers.Initialized = TRUE;

    return INT_STATUS_SUCCESS;

_exit:
    if (NULL != pTokenTable)
    {
        HpFreeAndNullWithTag(&pTokenTable, IC_TAG_KSYM);
    }

    if (NULL != pAddresses)
    {
        HpFreeAndNullWithTag(&pAddresses, IC_TAG_KSYM);
    }

    if (NULL != pNames)
    {
        HpFreeAndNullWithTag(&pNames, IC_TAG_KSYM);
    }

    return status;
}


void
IntKsymUninit(
    void
    )
///
/// Tries to free the kallsyms internal buffers if they are initialized.
///
{
    if (NULL != gKallsymsBuffers.TokenTable)
    {
        HpFreeAndNullWithTag(&gKallsymsBuffers.TokenTable, IC_TAG_KSYM);
    }

    if (NULL != gKallsymsBuffers.AddressesBuffer)
    {
        HpFreeAndNullWithTag(&gKallsymsBuffers.AddressesBuffer, IC_TAG_KSYM);
    }

    if (NULL != gKallsymsBuffers.NamesBuffer)
    {
        HpFreeAndNullWithTag(&gKallsymsBuffers.NamesBuffer, IC_TAG_KSYM);
    }

    gKallsymsBuffers.Initialized = FALSE;
}


INTSTATUS
IntKsymFindByAddress(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _Out_ char *SymName,
    _Out_opt_ QWORD *SymStart,
    _Out_opt_ QWORD *SymEnd
    )
///
/// @brief Finds the symbol which is located at the given address.
///
/// If there are multiple symbols starting at the same address only the
/// last one will be taken into account.
///
/// @param[in]  Gva         The address of the searched symbol.
/// @param[in]  Length      SymName buffer size.
/// @param[out] SymName     Buffer which will store the symbol name.
/// @param[out] SymStart    The symbol start address.
/// @param[out] SymEnd      The symbol end address (makes sense only for function names).
///
/// @return INT_STATUS_SUCCESS if the symbol was found
/// @return INT_STATUS_NOT_FOUND if the symbol was not found
/// @return INT_STATUS_UNSUCCESSFUL if any error occurred
/// @return INT_STATUS_INVALID_PARAMETER if and invalid parameter was given.
/// @return INT_STATUS_INVALID_INTERNAL_STATE if the active OS type is not Linux.
/// @return INT_STATUS_NOT_INITIALIZED if this function is called before IntKsymInit or after IntKsymUninit.
///
{
    DWORD offset;
    QWORD symStart;

    INT32 high, low;

    if (NULL == SymName)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (!gKallsymsBuffers.Initialized)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    // Directly return if we are outside of the kernel
    if (Gva > gGuest.KernelVa + gGuest.KernelSize)
    {
        return INT_STATUS_NOT_FOUND;
    }

    low = 0;
    offset = 0;
    high = gKallsymsBuffers.NumberOfNames;

    while (high - low > 1)
    {
        INT32 mid = low + (high - low) / 2;

        if (IntKsymGetAddress(mid) <= Gva)
        {
            low = mid;
        }
        else
        {
            high = mid;
        }
    }

    // Search for the first aliased symbol. Aliased symbols are symbols with the same address.
    while (low && IntKsymGetAddress(low - 1) == IntKsymGetAddress(low))
    {
        --low;
    }

    symStart = IntKsymGetAddress(low);

    if (SymEnd)
    {
        INT32 next = low + 1;

        // Skip until the next one is bigger
        while (next < gKallsymsBuffers.NumberOfNames &&
               symStart == IntKsymGetAddress(next))
        {
            ++next;
        }

        *SymEnd = IntKsymGetAddress(next);
    }

    if (SymStart)
    {
        *SymStart = symStart;
    }

    for (INT32 i = 0; i < low; i++)
    {
        // When using 0 as symbol length, it just gets the next offset.
        offset = IntKsymExpandSymbol(offset, 0, SymName);
        if (!offset)
        {
            ERROR("[ERROR] Failed expanding symbol (offset: %d)!\n", offset);
            return INT_STATUS_UNSUCCESSFUL;
        }
    }

    offset = IntKsymExpandSymbol(offset, Length, SymName);
    if (!offset)
    {
        ERROR("[ERROR] Failed expanding symbol (offset: %d)!\n", offset);
        return INT_STATUS_UNSUCCESSFUL;
    }

    return INT_STATUS_SUCCESS;
}


QWORD
IntKsymFindByName(
    _In_ const char *Name,
    _Out_opt_ QWORD *SymEnd
    )
///
/// @brief Searches the given Name in kallsyms and returns the Start & End offset.
///
/// If the symbol represents a variable, then the SymEnd may be wrong (we return the address of the next
/// symbol).
/// Supports a very basic regex: '*' at the end means we will do a memcmp only until there.
///
/// @param[in]  Name   The name of the symbol to be found
/// @param[out] SymEnd Upon successfully return will contain the address of the following symbol (if not NULL)
//
/// @returns The GVA of the given symbol on success or 0 if the symbol was not found
///
{
    DWORD next = 0;
    size_t nameLen;
    BOOLEAN regexp;
    QWORD start;

    if (gGuest.OSType != introGuestLinux || !gKallsymsBuffers.Initialized)
    {
        BUG_ON(TRUE);

        return 0;
    }

    if (NULL == Name)
    {
        return 0;
    }

    if (SymEnd)
    {
        *SymEnd = 0;
    }

    nameLen = strlen(Name);
    regexp = Name[nameLen - 1] == '*';

    for (INT32 i = 0; i < gKallsymsBuffers.NumberOfNames; i++)
    {
        CHAR symName[LIX_SYMBOL_NAME_LEN] = { 0 };

        next = IntKsymExpandSymbol(next, sizeof(symName), symName);
        if (!next)
        {
            ERROR("[ERROR] Failed expanding symbol\n");
            return 0;
        }

        if ((!regexp && 0 == strcmp(Name, symName)) ||
            (regexp && strlen(symName) >= nameLen && 0 == memcmp(Name, symName, nameLen - 1)))
        {
            start = IntKsymGetAddress(i);

            if (SymEnd)
            {
                ++i;

                while (i < gKallsymsBuffers.NumberOfNames && start == IntKsymGetAddress(i))
                {
                    ++i;
                }

                *SymEnd = IntKsymGetAddress(i);
            }

            return start;
        }
    }

    return 0;
}
