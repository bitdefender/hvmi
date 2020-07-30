/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winguest_supported.h"
#include "guests.h"
#include "winpe.h"
#include "update_guests.h"


INTSTATUS
IntWinGuestIsSupported(
    void
    )
///
/// @brief Load os information from cami.
///
/// Loads all os specific information from cami, for the current guest
/// described by #GUEST_STATE.OSVersion and #GUEST_STATE.KptiInstalled,
/// then sets #GUEST_STATE.SafeToApplyOptions.
///
/// #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;

    LOG("Searching for an OS with NtBuildNUmber = %d and kpti = %d\n", gGuest.OSVersion, gGuest.KptiInstalled);

    status = IntCamiLoadSection(CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_WINDOWS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to fetch valid Os info for %d: 0x%08x\n", gGuest.OSVersion, status);
        return status;
    }

    gGuest.SafeToApplyOptions = TRUE;

    return INT_STATUS_SUCCESS;
}


BOOLEAN
IntWinGuestIsIncreasedUserVa(
    void
    )
///
/// @brief Check if the guest has an increased user address space.
///
/// @returns TRUE If the guest is x86 and the value in MmHighestUserAddress is greater
/// than 2GB, FALSE otherwise.
///
{
    INTSTATUS status;
    QWORD expGva = 0;
    DWORD value = 0;

    if (gGuest.Guest64)
    {
        return FALSE;
    }

    status = IntPeFindKernelExport("MmHighestUserAddress", &expGva);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed to find MmHighestUserAddress: %08x\n", status);
        return FALSE;
    }

    status = IntKernVirtMemFetchDword(expGva, &value);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed to read MmHighestUserAddress value!\n");
        return FALSE;
    }

    LOG("[INTRO-INIT] Found MmHighestUserAddress at GVA 0x%08llx with value 0x%08x\n", expGva, value);

    return (value >= 2 * ONE_GIGABYTE);
}
