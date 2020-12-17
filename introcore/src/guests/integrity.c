/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "integrity.h"
#include "crc32.h"
#include "gpacache.h"
#include "guests.h"

///
/// @file integrity.c
///
/// @brief This file contains the integrity checking mechanism, consisting in checking
/// certain guest regions every second to see if there were any modifications.
///
/// The integrity mechanism makes sure that certain in-guest regions are not modified
/// during guest execution. The mechanism is triggered once every second through the timer
/// callback. The main need for this mechanism is the problem that we can hook synchronously
/// against writes (e.g. we are notified exactly at the moment of the write, through an EPT
/// violation) only with a length of 4Kb, which is the page size. Thus, structures which are
/// shorter than the page size, and reside in places that are written frequently, for example
/// nt's .data section, cannot be protected through EPT. For this reason, integrity checks
/// can significantly improve performance, by asynchronously checking once every second the
/// integrity of a structure, meaning that we check to see if any byte of the structure was
/// modified. The main disadvantage of this mechanism is that we don't have much information
/// about the possible malicious modification, as we detect the modification asynchronously,
/// after the write has been done. Some protected structures through the integrity mechanism
/// are the Hal Dispatch Table, the Interrupt Descriptor Table, the WMI_LOGGER_CONTEXT used
/// for Circular Kernel Logging (the GetCpuClock function which can be overwritten through
/// infinity hook), as well as static detected drivers, where the allocation could not be
/// intercepted by the introspection engine, thus the page size allocation could not be
/// enforced.
///


///
/// @brief  The global list of integrity regions, represented by #INTEGRITY_REGION structures.
///
static LIST_HEAD gIntegrityRegions = LIST_HEAD_INIT(gIntegrityRegions);

///
/// @brief  Useful macro for iterating through the list of #INTEGRITY_REGION structures.
///
#define for_each_region(_var_name)      list_for_each(gIntegrityRegions, INTEGRITY_REGION, _var_name)


static BOOLEAN
IntIntegrityIsOverlappedRegions(
    _In_ INTEGRITY_REGION *Descriptor
    )
///
/// @brief  Checks if an integrity region is overlapped with any of the integrity regions already
///         in the list.
///
/// While this function is used for a purely informative purpose, it is pretty useful in order to
/// avoid double protection for various regions through integrity. Even if overlapping regions are
/// not a problem for the mechanism, they are indicating that a misuse of the integrity mechanism
/// was made, and there is probably a bug in the code which calls the mechanism.
///
/// @param[in]  Descriptor  The #INTEGRITY_REGION which is checked to not be overlapped with the
///                         other regions in the list.
///
/// @retval     TRUE    If there is any #INTEGRITY_REGION in #gIntegrityRegions that overlaps with
///                     the current region.
/// @retval     FALSE   If the current #INTEGRITY_REGION passed by the Descriptor parameter does
///                     not overlap with any of the regions in the #gIntegrityRegions list.
///
{
    for_each_region(pIntRegion)
    {
        if ((Descriptor->Gva >= pIntRegion->Gva &&
             Descriptor->Gva < pIntRegion->Gva + pIntRegion->Length) ||
            (Descriptor->Gva + Descriptor->Length > pIntRegion->Gva &&
             Descriptor->Gva + Descriptor->Length <= pIntRegion->Gva + pIntRegion->Length) ||
            (pIntRegion->Gva >= Descriptor->Gva &&
             pIntRegion->Gva < Descriptor->Gva + Descriptor->Length) ||
            (pIntRegion->Gva + pIntRegion->Length > Descriptor->Gva &&
             pIntRegion->Gva + pIntRegion->Length < Descriptor->Gva + Descriptor->Length))
        {
            WARNING("[WARNING] Found integrity regions overlapped @ %llx (0x%08X) - @ %llx (0x%08X)",
                    pIntRegion->Gva, pIntRegion->Length, Descriptor->Gva, Descriptor->Length);
            return TRUE;
        }
    }

    return FALSE;
}


INTSTATUS
IntIntegrityAddRegion(
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_ INTRO_OBJECT_TYPE Type,
    _In_opt_ void *Context,
    _In_ PFUNC_IntegrityViolationCallback Callback,
    _In_ BOOLEAN CopyContent,
    _Out_ void **Descriptor
    )
///
/// @brief      Creates an #INTEGRITY_REGION object and adds it to the #gIntegrityRegions list.
///
/// This function will create the #INTEGRITY_REGION object based on the given parameters and
/// will append it to the #gIntegrityRegions list, meaning that once every second, when the
/// timer is called, the integrity mechanism will check the added integrity region and will
/// call the given callback if the current computed hash of the region is not the same as the
/// hash from the time when the region was added, or when a recalculation has been issued on
/// the given region. Basically, the mechanism will check every second if any bit of the given
/// region, starting from VirtualAddress and having Length bytes, has been modified, and will
/// call the given Callback if any modification has been detected. Note that the mechanism
/// can be used only for protecting kernel regions, and user-space virtual addresses will
/// cause this function to fail.
///
/// @param[in]  VirtualAddress  The guest virtual address which describes the start of the region.
/// @param[in]  Length          The number of bytes which are desired to be protected through integrity.
/// @param[in]  Type            The #INTRO_OBJECT_TYPE which associates the integrity region with the
///                             protected object.
/// @param[in]  Context         An user-provided context which will be saved in the #INTEGRITY_REGION
///                             structure (e.g. for protecting a field from EPROCESS one may decide
///                             to provide the #WIN_PROCESS_OBJECT structure associated with that EPROCESS).
/// @param[in]  Callback        The callback which is called by the integrity mechanism in case of any
///                             modification being detected in the given region.
/// @param[in]  CopyContent     Set this parameter to TRUE if one needs the original content of the
///                             given region to be saved in the #INTEGRITY_REGION structure. This is useful
///                             for re-writing the original content in the Callback function once it decides
///                             that the current state of the region seems to be malicious.
/// @param[out] Descriptor      The returned #INTEGRITY_REGION object.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the given virtual address is not a kernel pointer.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2     If the length of the region is 0.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If any allocation fails due to lack of resources.
///
{
    INTSTATUS status;
    INTEGRITY_REGION *pIntegrityRegion;
    BYTE *pOriginalContent = NULL;
    DWORD left = Length;
    DWORD crc32 = INITIAL_CRC_VALUE;
    QWORD gva = VirtualAddress;

    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (gGuest.OSType == introGuestWindows &&
        !IS_KERNEL_POINTER_WIN(gGuest.Guest64, VirtualAddress))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (gGuest.OSType == introGuestLinux &&
        !IS_KERNEL_POINTER_LIX(VirtualAddress))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pIntegrityRegion = HpAllocWithTag(sizeof(*pIntegrityRegion), IC_TAG_ITGR);
    if (NULL == pIntegrityRegion)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    if (CopyContent)
    {
        pIntegrityRegion->OriginalContent = HpAllocWithTag(Length, IC_TAG_ITGR);
        if (NULL == pIntegrityRegion->OriginalContent)
        {
            HpFreeAndNullWithTag(&pIntegrityRegion, IC_TAG_ITGR);

            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        pOriginalContent = pIntegrityRegion->OriginalContent;
    }

    do
    {
        void *p;
        DWORD size = MIN(left, PAGE_REMAINING(gva));

        // SystemCr3 is OK, since we only support integrity regions for kernel memory only.
        status = IntVirtMemMap(gva, size, gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping GVA 0x%016llx to host: 0x%08x\n", VirtualAddress, status);
            goto cleanup_and_leave;
        }

        crc32 = Crc32ComputeFast(p, size, crc32);

        if (pOriginalContent)
        {
            memcpy(pOriginalContent, p, size);
            pOriginalContent += size;
        }

        IntVirtMemUnmap(&p);

        // The next one will be page-aligned
        gva = gva + size;

        left -= size;
    } while (gva < VirtualAddress + Length);

    pIntegrityRegion->Gva = VirtualAddress;
    pIntegrityRegion->Length = Length;
    pIntegrityRegion->Type = Type;
    pIntegrityRegion->OriginalHash = crc32;
    pIntegrityRegion->ViolationCount = 0;
    pIntegrityRegion->Callback = Callback;
    pIntegrityRegion->Context = Context;
    pIntegrityRegion->Deleted = FALSE;

    IntIntegrityIsOverlappedRegions(pIntegrityRegion);

    InsertTailList(&gIntegrityRegions, &pIntegrityRegion->Link);

    TRACE("[INFO] Add integrity region @ %llx (%d).\n", pIntegrityRegion->Gva, pIntegrityRegion->Length);

    *Descriptor = pIntegrityRegion;

    status = INT_STATUS_SUCCESS;

cleanup_and_leave:
    if (!INT_SUCCESS(status))
    {
        if (NULL != pIntegrityRegion->OriginalContent)
        {
            HpFreeAndNullWithTag(&pIntegrityRegion->OriginalContent, IC_TAG_ITGR);
        }

        HpFreeAndNullWithTag(&pIntegrityRegion, IC_TAG_ITGR);
    }

    return status;
}


INTSTATUS
IntIntegrityRecalculate(
    _In_ INTEGRITY_REGION *IntegrityRegion
    )
///
/// @brief  Recalculates the hash and reads the original content again for a given region.
///
/// The main use of this function is when a modification was detected inside the region
/// described by the given #INTEGRITY_REGION, the given callback was called, but the callback
/// decides that the modification is not malicious, and the modification should be ignored
/// in further checks done by the integrity mechanism. For this purpose, the callback will call
/// this function, which will re-compute the hash of the given region, with the current modified
/// values which are in the guest, and copies the current content to the OriginalContent field
/// if the integrity region was added with the CopyContent parameter of #IntIntegrityAddRegion
/// set to TRUE. Failure to call this function in the above mentioned case will result in the
/// integrity mechanism calling the associated Callback every second, as it will see that certain
/// parts of the region are modified with respect to the time when the integrity region was added
/// through a call to #IntIntegrityAddRegion. This is not desired, especially when beta alerts
/// are activated, or when one might use the integrity mechanism for various initialization
/// purposes (e.g. initialize some protection only when some field in a given structure was written,
/// a good example for this use case would be the infinity hook protection in wininfinityhook.c).
///
/// @param[in]  IntegrityRegion     The #INTEGRITY_REGION object for which the recalculation is desired.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    QWORD gva = IntegrityRegion->Gva;
    DWORD left = IntegrityRegion->Length;
    DWORD crc32 = INITIAL_CRC_VALUE;
    BYTE *pOriginalContent = IntegrityRegion->OriginalContent;
    INTSTATUS status = INT_STATUS_SUCCESS;

    do
    {
        DWORD size = MIN(left, PAGE_REMAINING(gva));
        void *p;

        // SystemCr3 is ok, since we support integrity regions for kernel memory only.
        status = IntVirtMemMap(gva, size, gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed mapping GVA 0x%016llx to host: 0x%08x\n", IntegrityRegion->Gva, status);
            goto cleanup_and_exit;
        }

        crc32 = Crc32ComputeFast(p, size, crc32);

        if (NULL != pOriginalContent)
        {
            memcpy(pOriginalContent, p, size);
            pOriginalContent += size;
        }

        IntVirtMemUnmap(&p);

        // the next one will be page-aligned
        gva = gva + size;
        left -= size;
    } while (gva < IntegrityRegion->Gva + IntegrityRegion->Length);

    IntegrityRegion->OriginalHash = crc32;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:

    return status;
}


INTSTATUS
IntIntegrityRemoveRegion(
    _In_ void *Descriptor
    )
///
/// @brief  Removes an integrity region from the #gIntegrityRegions list.
///
/// This function will remove an integrity region object, which was previously added with #IntIntegrityAddRegion.
/// Note: One should not call this function from within an integrity callback associated
/// to an #INTEGRITY_REGION, but rather should call #IntIntegrityDeleteRegion for this purpose
/// which will only mark the region for deletion. This function should be called when uninitializing
/// an integrity protection.
///
/// @param[in]  Descriptor  The integrity region object as returned by #IntIntegrityAddRegion.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTEGRITY_REGION *pIntegrityRegion = Descriptor;

    TRACE("[INFO] Remove integrity region @ %llx (%d).", pIntegrityRegion->Gva, pIntegrityRegion->Length);

    RemoveEntryList(&pIntegrityRegion->Link);

    if (NULL != pIntegrityRegion->OriginalContent)
    {
        HpFreeAndNullWithTag(&pIntegrityRegion->OriginalContent, IC_TAG_ITGR);
    }

    HpFreeAndNullWithTag(&pIntegrityRegion, IC_TAG_ITGR);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntIntegrityDeleteRegion(
    _In_ void *Descriptor
    )
///
/// @brief  Marks the given integrity region for deletion. It will be removed after calling all
///         the integrity callbacks.
///
/// This function should be called when deleting an integrity region from an integrity callback,
/// as opposed to #IntIntegrityRemoveRegion. This will ensure that the list is kept properly and
/// then remove the deleted regions after all (non-deleted) callbacks are called.
///
/// @param[in]  Descriptor  The integrity region as returned by #IntIntegrityAddRegion or provided
///                         as a parameter in a callback.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTEGRITY_REGION *pIntegrityRegion = Descriptor;

    TRACE("[INFO] Deleting integrity region @ %llx (%d) after calling callbacks.", pIntegrityRegion->Gva,
          pIntegrityRegion->Length);

    pIntegrityRegion->Deleted = TRUE;

    return INT_STATUS_SUCCESS;
}


TIMER_FRIENDLY INTSTATUS
IntIntegrityCheckAll(
    void
    )
///
/// @brief  The function which is called once every second and checks all the integrity regions.
///
/// This function is called every second and will check all #INTEGRITY_REGION previously added through
/// calls to #IntIntegrityAddRegion. It will call the provided callbacks associated to the regions if
/// any modification was detected and a callback has been provided. After all the callbacks are called
/// for the regions which are not marked for deletion (due to calls to #IntIntegrityDeleteRegion from
/// within an integrity callback), those latter regions will be removed through calls to
/// #IntIntegrityRemoveRegion.
///
/// @retval #INT_STATUS_SUCCESS On success or if there is nothing to be done as the protection is not
///                             activated.
///
{
    // If introspection is disabled we skip all checks
    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_SUCCESS;
    }

    for_each_region(pIntRegion)
    {
        QWORD gva = pIntRegion->Gva;
        DWORD left = pIntRegion->Length;
        BOOLEAN skipThis = FALSE;
        DWORD crc32 = INITIAL_CRC_VALUE;
        INTSTATUS status;

        if (pIntRegion->Deleted)
        {
            continue;
        }

        do
        {
            BYTE *p;
            QWORD gpa;
            DWORD size = MIN(left, PAGE_REMAINING(gva));

            status = IntTranslateVirtualAddress(gva & PAGE_MASK, gGuest.Mm.SystemCr3, &gpa);
            if (!INT_SUCCESS(status))
            {
                skipThis = TRUE;
                break;
            }

            status = IntGpaCacheFindAndAdd(gGuest.GpaCache, gpa, &p);
            if (!INT_SUCCESS(status))
            {
                // Do not show error messages since at sleep/hibernate the pages may not be present!
                // We could hook the pt and see when the pages swap-out but the performance impact is too visible
                skipThis = TRUE;
                break;
            }

            p += gva & PAGE_OFFSET;
            crc32 = Crc32ComputeFast(p, size, crc32);
            p -= gva & PAGE_OFFSET;

            IntGpaCacheRelease(gGuest.GpaCache, gpa);

            // the next one will be page-aligned
            gva += size;

            left -= size;
        } while (gva < pIntRegion->Gva + pIntRegion->Length);

        if (skipThis)
        {
            continue;
        }

        if (crc32 != pIntRegion->OriginalHash)
        {
            pIntRegion->ViolationCount++;

            if (NULL != pIntRegion->Callback)
            {
                // From here on, we can safely use any CPU state/virtual mem map functions/etc.
                status = pIntRegion->Callback(pIntRegion);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Integrity violation callback failed with status: 0x%08x\n", status);
                }
            }
            else if (pIntRegion->ModifiedHash != crc32)
            {
                pIntRegion->ModifiedHash = crc32;
            }
        }
    }

    // Finally remove the regions that were deleted during calling the integrity callbacks
    for_each_region(pIntRegion)
    {
        if (pIntRegion->Deleted)
        {
            IntIntegrityRemoveRegion(pIntRegion);
        }
    }

    return INT_STATUS_SUCCESS;
}


void
IntIntegrityDump(
    void
    )
///
/// @brief  Dumps all the #INTEGRITY_REGION structures from #gIntegrityRegions. Used mainly for debugging.
///
{
    for_each_region(pIntRegion)
    {
        LOG("Gva: 0x%016llx, Length: %d, OriginalContent: %p, Type: %d, OriginalHash: 0x%08x\n",
            pIntRegion->Gva, pIntRegion->Length, pIntRegion->OriginalContent, pIntRegion->Type,
            pIntRegion->OriginalHash);
    }
}


INTSTATUS
IntIntegrityUninit(
    void
    )
///
/// @brief  Uninits the integrity mechanism by removing every integrity region from the list.
///
/// Note that an error is issued for every region in the list, since the caller which adds
/// the region through #IntIntegrityAddRegion is responsible to remove it when removing the
/// protection on the desired structure. The fact that the protection is not removed is
/// considered an error, and the caller should always remove the returned integrity regions
/// when they are not needed anymore.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    for_each_region(pIntRegion)
    {
        LOG("[ERROR] There should be no regions remaining... Got one on %llx!\n", pIntRegion->Gva);

        IntIntegrityRemoveRegion(pIntRegion);
    }

    return INT_STATUS_SUCCESS;
}
