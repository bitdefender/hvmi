/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcore.h"
#include "guests.h"
#include "introstatus.h"
#include "lixguest.h"

static QWORD gMappedGva = 0;  ///< The guest virtual address that is currently mapped.

static BYTE *gMapping1 = NULL; ///< The mapping point of the first page mapped.
static BYTE *gMapping2 = NULL; ///< The mapping point of the second page mapped.


INTSTATUS
IntLixFsrInitMap(
    _In_ QWORD Gva
    )
///
/// @brief Initialize the fast read mechanism.
///
/// This function will map two pages starting from the Gva parameter.
///
/// @param[in] Gva The guest virtual address to be mapped.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns #INT_STATUS_ALREADY_INITIALIZED If the fast read mechanism is already initialized.
/// @returns The status returned by #IntVirtMemMap if a mapping error occurs.
///
{
    INTSTATUS status;

    if (IS_KERNEL_POINTER_LIX(gMappedGva))
    {
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    if (!IS_KERNEL_POINTER_LIX(Gva))
    {
        // We allow only kernel memory.
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntVirtMemMap(Gva, PAGE_REMAINING(Gva), gGuest.Mm.SystemCr3, 0, &gMapping1);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for %llx: %08x\n", Gva, status);

        gMapping1 = NULL;

        return status;
    }

    gMappedGva = Gva;

    return INT_STATUS_SUCCESS;
}


void
IntLixFsrUninitMap(
    void
    )
///
/// @brief Uninitialize the fast read mechanism.
///
{
    if (NULL != gMapping1)
    {
        IntVirtMemUnmap(&gMapping1);
    }

    if (NULL != gMapping2)
    {
        IntVirtMemUnmap(&gMapping2);
    }

    gMappedGva = 0;

    gMapping1 = gMapping2 = NULL;
}


INTSTATUS
IntLixFsrRead(
    _In_ QWORD Gva,
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _Out_ void *Buffer
    )
///
/// @brief Performs a read from a previously mapped guest virtual address.
///
/// @param[in]  Gva    The guest virtual address supplied to a previous #IntLixFsrInitMap call.
/// @param[in]  Offset The offset relative to the guest virtual address supplied to the #IntLixFsrInitMap.
/// @param[in]  Size   The number of bytes which follows to be fetched.
/// @param[out] Buffer The buffer that stores the read outcome.
///
/// @returns #INT_STATUS_SUCCESS On success.
/// @returns #INT_STATUS_NOT_INITIALIZED If the mechanism is not yet initialized (via #IntLixFsrInitMap).
/// @returns #INT_STATUS_INVALID_PARAMETER_1 If the Gva parameter is different from the mapped address.
/// @returns #INT_STATUS_INVALID_PARAMETER_3 If Buffer parameter does not point to a valid memory location.
/// @returns #INT_STATUS_INVALID_PARAMETER_MIX If the requested memory range spills out of the mapped range.
///
{
    QWORD gva;

    if (NULL == gMapping1)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    if (gMappedGva != Gva)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (PAGE_COUNT(gMappedGva, Offset + Size) > 2)
    {
        return INT_STATUS_INVALID_PARAMETER_MIX;
    }

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    gva = gMappedGva + Offset;

    if (PAGE_COUNT(gMappedGva, (QWORD)Offset + Size) > 1)
    {
        DWORD remaining = Size;

        if (NULL == gMapping2)
        {
            INTSTATUS status;
            QWORD secondPage;

            secondPage = (gMappedGva + PAGE_SIZE) & PAGE_MASK;

            status = IntVirtMemMap(secondPage, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &gMapping2);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for 0x%llx with status 0x%08x", secondPage, status);

                gMapping2 = NULL;

                return status;
            }
        }

        if (PAGE_FRAME_NUMBER(gMappedGva) == PAGE_FRAME_NUMBER(gva))
        {
            DWORD toRead = PAGE_REMAINING(gva);

            memcpy(Buffer, gMapping1 + Offset, toRead);

            remaining -= toRead;
        }

        memcpy((BYTE *)Buffer + (Size - remaining), gMapping2 + ((gva + Size - remaining) & PAGE_OFFSET), remaining);
    }
    else
    {
        // The whole it's in the first page
        memcpy(Buffer, gMapping1 + Offset, Size);
    }

    return INT_STATUS_SUCCESS;
}
