/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "slack.h"
#include "guests.h"
#include "winpe.h"
#include "alerts.h"


///
/// @file slack.c
///
/// @brief Handles in-guest memory allocations.
///
/// This module deals with in-guest memory allocations. However, it can only allocate guest memory inside the
/// padding area located at the end of MZ/PE sections (Windows) or inside the first 2 pages of the kernel
/// image (Linux). We call this unused space "slack". Generally, this is available because sections rarely use
/// the entire last page, but, because section alignment is usually equal to the size of a page (4K), this leaves
/// some unused space we can claim. For example, if the .text section of the NT image has a virtual size of
/// 0x329838 bytes, this leaves 0x1000 - 0x838 = 0x7C8 (1992) bytes unused inside the last page of the section.
/// (assuming regular 0x1000 section alignment).
/// This is more than enough for our current use-cases.
/// NOTE: Patch-guard protects the sections slack space (it should be filled with zeros). Because of this,
/// when allocating slack space and writing data inside it, make sure you use memcloak in order to hide the
/// written contents, so as to when PatchGuard reads that area, zeros are returned instead.
///


///
/// One slack allocation.
///
typedef struct _SLACK_SPACE
{
    LIST_ENTRY          Link;               ///< List entry element.
    QWORD               ModuleBase;         ///< The module base used for the allocation.
    QWORD               Gva;                ///< The guest virtual address of the actual allocation.

    union
    {
        struct
        {
            DWORD       Section;            ///< The section index (zero based) inside the module.
            DWORD       SectionOffset;      ///< The offset inside the section of the allocation.
            DWORD       SectionSize;        ///< The size of the section.
            DWORD       AllocationOffset;   ///< The allocation offset, within the last page of the section.
        } Windows;
    };

    DWORD               AllocationSize;     ///< The number of bytes allocated.
} SLACK_SPACE, *PSLACK_SPACE;


static LIST_HEAD gSlackAllocations = LIST_HEAD_INIT(gSlackAllocations);

#define for_each_slack(_var_name)                    list_for_each(gSlackAllocations, SLACK_SPACE, _var_name)


static INTSTATUS
IntSlackSendIntegrityAlert(
    _In_ QWORD VirtualAddress,
    _In_ DWORD Size,
    _In_ BYTE Value
    )
///
/// @brief Sends an integrity alert if the slack buffer not 0-filled/NOP-filled.
///
/// @param[in]  VirtualAddress  The beginning guest virtual address of the slack memory region.
/// @param[in]  Size            The size of the slack memory region.
/// @param[in]  Value           The first value that is not equal to zero.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_INTEGRITY_VIOLATION *pEvent = &gAlert.Integrity;
    KERNEL_DRIVER *pDriver = NULL;

    memzero(pEvent, sizeof(*pEvent));

    pEvent->Header.Action = introGuestAllowed;
    pEvent->Header.Reason = introReasonAllowed;
    pEvent->Header.MitreID = idHooking;

    pEvent->Header.Flags &= ~ALERT_FLAG_NOT_RING0;

    IntAlertFillVersionInfo(&pEvent->Header);
    IntAlertFillCpuContext(FALSE, &pEvent->Header.CpuContext);

    pDriver = IntDriverFindByAddress(VirtualAddress);
    if (pDriver)
    {
        if (gGuest.OSType == introGuestWindows)
        {
            IntAlertFillWinKmModule(pDriver, &pEvent->Originator.Module);
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            IntAlertFillLixKmModule(pDriver, &pEvent->Originator.Module);
        }
    }

    pEvent->Header.CpuContext.Valid = FALSE;
    pEvent->Victim.Type = introObjectTypeSlackSpace;

    pEvent->BaseAddress = VirtualAddress;
    pEvent->VirtualAddress = VirtualAddress;
    pEvent->Size = Size;

    pEvent->WriteInfo.Size = Size;
    memcpy(pEvent->WriteInfo.NewValue, &Value, sizeof(BYTE));

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntSlackAllocWindows(
    _In_ BOOLEAN Pageable,
    _In_ QWORD ModuleBase,
    _In_ DWORD Size,
    _Out_ QWORD *Buffer,
    _In_opt_ QWORD SecHint
    )
///
/// @brief Allocate memory inside the guest.
///
/// This function will iterate through all the non-discardable, non-writable, executable sections of module pointed
/// by ModuleBase, and it will search padding areas, between sections, after the virtual size of the given section.
/// Inside this padding area, we can store Introcore specific data.
/// NOTE: This function takes into considerations other code injections that may have been previously done.
/// It will iterate through the list of currently allocated slacks, in order to ensure that it will never return
/// an address that would lead to the corruption of already injected code/data chunks.
/// NOTE: Slack space is a very limited resource (expect roughly a few kilobytes of it to be available inside the
/// NT image, for example), so use it wisely. The main use-cases for the slack space are:
/// 1. Detour handlers. For each detours function, we place a very small filtering code inside the guest, which
/// is capable of eliminating unwanted VM exits (for example, we don't do a VM exit if a VAD is being allocated
/// inside an unprotected process);
/// 2. Agent trampoline code;
/// 3. Agent bootrstrap code.
/// NOTE: Since the slack space is located at the end of sections (in the last page of a section), large allocations
/// will always fail (for example, you could never allocate 4K of slack space).
/// NOTE: Since we expect the slack space to be filled with zeros, this function will fail if it allocates a slack
/// region which is not filled with zeros. Therefore, please make sure that any in-guest slack space is freed when
/// unloading Introcore.
///
/// @param[in]  Pageable        If true, the slack space can be allocated inside a pageable section.
/// @param[in]  ModuleBase      The kernel module in which we wish to allocate slack space.
/// @param[in]  Size            Size to be allocated.
/// @param[out] Buffer          Will contain, upon successful return, the guest virtual address of the allocated
///                             slack buffer inside the given module.
/// @param[in]  SecHint         Optional section hint - if provided (non-zero), slack will be allocated inside the
///                             given section (note that this is a section name, not index).
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails or if enough slack space was not found inside
///         the given module.
///
{
    INTSTATUS status;
    IMAGE_SECTION_HEADER sec = { 0 };
    INTRO_PE_INFO peInfo = { 0 };
    BYTE *moduleBuffer = NULL;
    DWORD bufferSize = 0;


    if (ModuleBase == gGuest.KernelVa)
    {
        moduleBuffer = gWinGuest->KernelBuffer;
        bufferSize = gWinGuest->KernelBufferSize;
    }

    status = IntPeValidateHeader(ModuleBase, moduleBuffer, bufferSize, &peInfo, gGuest.Mm.SystemCr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed with status: 0x%08x\n", status);
        return status;
    }

    // Get the base address of the section headers and set an EPT hook on every section that it's not writable.
    // The idea is that this way, we will protect the code, IAT, EAT with one shot, since both the IAT & EAT are
    // placed by the compiler inside a read-only section.

    // Parse the section headers, in order to find some empty space.
    for (DWORD i = 0; i < peInfo.NumberOfSections; i++)
    {
        if (moduleBuffer != NULL && peInfo.SectionOffset + sizeof(IMAGE_SECTION_HEADER) * (i + 1ull) < bufferSize)
        {
            sec = *(IMAGE_SECTION_HEADER *)(moduleBuffer + peInfo.SectionOffset + sizeof(IMAGE_SECTION_HEADER) * i);
        }
        else
        {
            status = IntKernVirtMemRead(ModuleBase + peInfo.SectionOffset + sizeof(IMAGE_SECTION_HEADER) * i,
                                        sizeof(IMAGE_SECTION_HEADER), &sec, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed reading IMAGE_SECTION_HEADER %d for module 0x%016llx: 0x%08x\n",
                      i, ModuleBase, status);
                return status;
            }
        }

        if ((0 != SecHint) && (0 != memcmp(&SecHint, sec.Name, 8)))
        {
            continue;
        }

        // The section where we will place the hook must NOT be writable, discardable or pageable.
        if ((sec.Characteristics & IMAGE_SCN_MEM_WRITE) ||
            (sec.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) ||
            (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) ||
            (!(sec.Characteristics & IMAGE_SCN_MEM_NOT_PAGED) && !Pageable) ||
            ((sec.Characteristics & IMAGE_SCN_MEM_NOT_PAGED) && Pageable))
        {
            continue;
        }

        // INITKDBG is overwritten at some times by kdbg... We really don't want to store our code there.
        if ((memcmp(sec.Name, "INITKDBG", 8) == 0))
        {
            continue;
        }

        // Ignore page-aligned sections.
        if (sec.Misc.VirtualSize % PAGE_SIZE == 0)
        {
            continue;
        }

        if (PAGE_REMAINING(sec.Misc.VirtualSize) >= Size)
        {
            // We found a suitable section; we must validate that it won't overlap with an already set hook
            DWORD totalUsedSpace;
            DWORD totalSpace;
            DWORD maxOffset;

            totalUsedSpace = 0;
            maxOffset = 0;
            totalSpace = PAGE_REMAINING(sec.Misc.VirtualSize);

            for_each_slack(pSlack)
            {
                if ((pSlack->Windows.Section == i) && (pSlack->ModuleBase == ModuleBase))
                {
                    if (pSlack->Windows.SectionOffset > maxOffset)
                    {
                        maxOffset = pSlack->Windows.SectionOffset;

                        totalUsedSpace = maxOffset - sec.Misc.VirtualSize + pSlack->AllocationSize;
                    }
                }
            }

            // Make sure enough space still remains. Also, make sure the slack buffer is filled with zeros.
            if (totalSpace - totalUsedSpace >= Size)
            {
                SLACK_SPACE *pSlack;
                QWORD gva = ModuleBase + sec.VirtualAddress + sec.Misc.VirtualSize + totalUsedSpace, j;

                // The Size parameter is validated by the caller.
                BYTE *buf = HpAllocWithTag(Size, IC_TAG_ALLOC);
                if (NULL == buf)
                {
                    return INT_STATUS_INSUFFICIENT_RESOURCES;
                }

                status = IntKernVirtMemRead(gva, Size, buf, NULL);
                if (!INT_SUCCESS(status))
                {
                    HpFreeAndNullWithTag(&buf, IC_TAG_ALLOC);
                    ERROR("[ERROR] IntKernVirtMemRead failed GVA 0x%016llx: 0x%08x\n", gva, status);
                    return status;
                }

                for (j = 0; j < Size; j++)
                {
                    if (0 != buf[j])
                    {
                        IntSlackSendIntegrityAlert(gva, Size, buf[j]);

                        ERROR("[ERROR] Slack buffer not 0-filled! 0x%016llx\n", gva + j);
                        IntDumpBuffer(buf, gva, Size, 8, 1, TRUE, TRUE);
                        HpFreeAndNullWithTag(&buf, IC_TAG_ALLOC);
                        return INT_STATUS_NOT_SUPPORTED;
                    }
                }

                HpFreeAndNullWithTag(&buf, IC_TAG_ALLOC);

                pSlack = HpAllocWithTag(sizeof(*pSlack), IC_TAG_SLKE);
                if (NULL == pSlack)
                {
                    return INT_STATUS_INSUFFICIENT_RESOURCES;
                }

                TRACE("[SLACK] Found %d bytes of space, used %d bytes, in section %d, "
                      "at offset %08x in module 0x%016llx\n", totalSpace, totalUsedSpace, i,
                      sec.VirtualAddress + sec.Misc.VirtualSize, ModuleBase);

                pSlack->Gva = gva;
                pSlack->AllocationSize = Size;
                pSlack->ModuleBase = ModuleBase;
                pSlack->Windows.AllocationOffset = (sec.Misc.VirtualSize & PAGE_OFFSET) + totalUsedSpace;
                pSlack->Windows.Section = i;
                pSlack->Windows.SectionOffset = sec.Misc.VirtualSize + totalUsedSpace;
                pSlack->Windows.SectionSize = sec.Misc.VirtualSize;

                InsertTailList(&gSlackAllocations, &pSlack->Link);

                *Buffer = pSlack->Gva;

                return INT_STATUS_SUCCESS;
            }
        }
    }

    return INT_STATUS_INSUFFICIENT_RESOURCES;
}


static INTSTATUS
IntSlackAllocLinux(
    _In_ DWORD Size,
    _Out_ QWORD *Buffer
    )
///
/// @brief Allocate slack space on Linux.
///
/// On Linux we don't have space between sections since they aren't aligned. But we do have the first two pages where
/// there should be hypercall_page and *theoretically* there should be enough space.
///
/// @param[in]  Size    Size of the buffer to be allocated.
/// @param[out] Buffer  Guest virtual address of the allocated buffer.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails or if enough slack space was not found inside
///         the given module.
///
{
    INTSTATUS status;
    QWORD gva = gGuest.KernelVa;
    QWORD maxGva = gGuest.KernelVa + (2 * PAGE_SIZE);

    //
    // If we have other allocations, don't bother to parse pages inside the kernel, just skip right after the
    // last one. The NOPs are in a contiguous big block, so no need for any complicated logic.
    //
    if (!IsListEmpty(&gSlackAllocations))
    {
        SLACK_SPACE *pSlack = CONTAINING_RECORD(gSlackAllocations.Blink, SLACK_SPACE, Link);

        gva = pSlack->Gva + pSlack->AllocationSize;
    }

    for (; gva < maxGva; gva += PAGE_REMAINING(gva))
    {
        BYTE *p;
        DWORD maxOffset;

        // A limitation for now: the allocation has to be fully in one page
        if (Size > PAGE_REMAINING(gva))
        {
            continue;
        }

        maxOffset = PAGE_REMAINING(gva) - Size;

        status = IntVirtMemMap(gva, PAGE_REMAINING(gva), gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for %llx: 0x%08x\n", gva, status);
            return status;
        }

        for (DWORD offset = 0; offset < maxOffset; offset++)
        {
            DWORD foundSize = 0;

            // Skip until the first NOP
            while (offset < maxOffset && (p[offset] != 0x90))
            {
                offset++;
            }

            // p[maxOffset + Size] last valid is [maxOffset + Size - 1]
            // offset goes from 0 -> maxOffset so last valid is maxOffset - 1
            // foundSize goes from 0 -> Size so last valid is Size - 1
            // worst case: p[maxOffset - 1 + Size - 1] = p[maxOffset + Size - 2] which is in the buffer still
            while ((foundSize < Size) && (p[offset + foundSize] == 0x90))
            {
                foundSize++;
            }

            if (foundSize == Size)
            {
                // Found a suitable area filled with NOPs, let's just use that
                SLACK_SPACE *pSlack = HpAllocWithTag(sizeof(*pSlack), IC_TAG_SLKE);
                if (NULL == pSlack)
                {
                    return INT_STATUS_INSUFFICIENT_RESOURCES;
                }

                pSlack->Gva = gva + offset;
                pSlack->AllocationSize = Size;
                pSlack->ModuleBase = gGuest.KernelVa;

                TRACE("[SLACK] Found %d bytes of space at 0x%016llx\n", foundSize, pSlack->Gva);

                InsertTailList(&gSlackAllocations, &pSlack->Link);

                *Buffer = pSlack->Gva;

                IntVirtMemUnmap(&p);

                return INT_STATUS_SUCCESS;
            }
        }

        IntVirtMemUnmap(&p);
    }

    IntSlackSendIntegrityAlert(gva, Size, 0);

    return INT_STATUS_INSUFFICIENT_RESOURCES;
}


INTSTATUS
IntSlackAlloc(
    _In_opt_ QWORD ModuleBase,
    _In_ BOOLEAN Pageable,
    _In_ DWORD Size,
    _Out_ QWORD *Buffer,
    _In_opt_ QWORD SecHint
    )
///
/// @brief Allocate slack inside the guest.
///
/// Please see the description of the #IntSlackAllocWindows function for Windows, and #IntSlackAllocLinux for Linux.
/// This function is just a wrapper for them.
///
/// @param[in]  Pageable        If true, the slack space can be allocated inside a pageable section.
/// @param[in]  ModuleBase      The kernel module in which we wish to allocate slack space.
/// @param[in]  Size            Size to be allocated.
/// @param[out] Buffer          Will contain, upon successful return, the guest virtual address of the allocated
///                             slack buffer inside the given module.
/// @param[in]  SecHint         Optional section hint - if provided (non-zero), slack will be allocated inside the
///                             given section (note that this is a section name, not index).
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails or if enough slack space was not found inside
///         the given module.
///
{
    INTSTATUS status;

    if (0 == Size)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (introGuestWindows == gGuest.OSType)
    {
        if (0 == ModuleBase)
        {
            return INT_STATUS_INVALID_PARAMETER_1;
        }

        status = IntSlackAllocWindows(Pageable, ModuleBase, Size, Buffer, SecHint);
    }
    else if (introGuestLinux == gGuest.OSType)
    {
        status = IntSlackAllocLinux(Size, Buffer);
    }
    else
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntSlackFree(
    _In_ QWORD Buffer
    )
///
/// @brief Free slack space.
///
/// Will free the given buffer allocated inside a loaded modules' slack space.
///
/// @param[in]  Buffer  The allocate slack address.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If the given slack was not found among the valid allocations.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is used.
///
{
    if (0 == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    for_each_slack(pSlack)
    {
        if (pSlack->Gva == Buffer)
        {
            RemoveEntryList(&pSlack->Link);

            HpFreeAndNullWithTag(&pSlack, IC_TAG_SLKE);

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


void
IntSlackUninit(
    void
    )
///
/// @brief Uninit the slack system. Must be called only during uninit.
///
{
    for_each_slack(pSlack)
    {
        RemoveEntryList(&pSlack->Link);

        HpFreeAndNullWithTag(&pSlack, IC_TAG_SLKE);
    }
}
