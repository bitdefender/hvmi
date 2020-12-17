/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winguest.h"
#include "callbacks.h"
#include "cr_protection.h"
#include "decoder.h"
#include "drivers.h"
#include "dtr_protection.h"
#include "guests.h"
#include "introcpu.h"
#include "msr_protection.h"
#include "swapgs.h"
#include "swapmem.h"
#include "vecore.h"
#include "winagent.h"
#include "winapi.h"
#include "winguest_supported.h"
#include "winhal.h"
#include "winidt.h"
#include "winpe.h"
#include "winpfn.h"
#include "winprocesshp.h"
#include "hook.h"
#include "exceptions.h"
#include "alerts.h"
#include "winthread.h"
#include "winsud.h"
#include "winintobj.h"

///
/// @brief  Global variable holding the state of a Windows guest
///
/// This is not dynamically allocated. It points to the _WindowsGuest field of the #gGuest variable.
/// Its value is set by #IntWinGuestNew.
WINDOWS_GUEST *gWinGuest = NULL;

///
/// @brief  The maximum size of the area of memory in which the kernel base is searched for
///
/// The Windows kernel is around 9MB in size, so setting this to 16MB should be enough
#define KERNEL_SEARCH_LIMIT                 (16 * ONE_MEGABYTE)


//
// These are mostly constant on supported os versions
// If any windows update would fail the init because we can't find the idle process'
// cr3, simply change those and it SHOULD work.
//

/// @brief  The offset of the IdleThread field inside the _KPCR
///
/// This is part of the constant fields of the _KPCR and should not change
#define IDLE_THREAD_OFFSET_PCR              ((gGuest.Guest64) ? 0x198 : 0x12C)

/// @brief  The upper limit of the area in which the idle process is searched
#define PROCESS_SEARCH_LIMIT_THREAD_UPPER   (DWORD)((gGuest.Guest64) ? 0x220 : 0x150)

/// @brief  The lower limit of the area in which the idle process is searched
#define PROCESS_SEARCH_LIMIT_THREAD_LOWER   (DWORD)((gGuest.Guest64) ? 0x210 : 0x150)

/// @brief  The offset of the DirectoryTableBase field inside _KPROCESS
///
/// We also have this information available in #WIN_OPAQUE_FIELDS, from CAMI, but we need this offset
/// earlier in the initialization phase, before we know the Windows version, so we can't reliably load any
/// settings from CAMI. Since this offset remained constant on all Windows versions from 7 to 10, it is safe
/// to have it defined here.
#define CR3_OFFSET_IN_KPROCESS              (DWORD)((gGuest.Guest64) ? 0x28 : 0x18)


static INTSTATUS
IntWinGuestFindKernelObjectsInternal(
    void
    )
///
/// @brief  Finds all the objects of interest from the Windows kernel
///
/// This searches for the PsLoadedModuleList and PsActiveProcessHead kernel variables, and for the address of the
/// PFN data base.
/// The search is done in the ALMOSTRO and .data sections of the kernel, using the WINDOWS_GUEST.KernelBuffer, if it
/// is available. Since some Windows versions have been observed to have multiple sections with the name ALMOSTRO, the
/// functions tries to account for this, and allocates enough space for multiple sections.
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
/// @retval #INT_STATUS_NOT_FOUND if not all the objects were found
///
{
    INTSTATUS status;
    DWORD sectionCount;

    // hopefully, we won't have a total of more than 10 sections with names .data or ALMOSTRO
    const DWORD maxSecCount = 10;
    const DWORD objCount = 3;

    DWORD objectsFound = 0;

    QWORD kernelBase = gGuest.KernelVa;
    BYTE *pKernel = gWinGuest->KernelBuffer;

    IMAGE_SECTION_HEADER *pSections = HpAllocWithTag(sizeof(*pSections) * maxSecCount, IC_TAG_IMGE);
    if (NULL == pSections)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntPeGetSectionHeadersByName(kernelBase, pKernel, "ALMOSTRO", maxSecCount - 1, gGuest.Mm.SystemCr3,
                                          pSections, &sectionCount);
    if (!INT_SUCCESS(status) || (0 == sectionCount))
    {
        ERROR("[ERROR] IntPeGetSectionHeadersByName failed for `ALMOSTRO`: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    status = IntPeGetSectionHeadersByName(kernelBase, pKernel, ".data", 1, gGuest.Mm.SystemCr3,
                                          &pSections[sectionCount], NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeGetSectionHeadersByName failed for `.data`: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    sectionCount++;

    // Iterate the kernel sections in order to get the internal variables.
    for (DWORD i = 0; i < sectionCount; i++)
    {
        PIMAGE_SECTION_HEADER pSec = &pSections[i];
        DWORD pageCount = ROUND_UP(pSec->Misc.VirtualSize, PAGE_SIZE) / PAGE_SIZE;

        for (DWORD j = 0; j < pageCount; j++)
        {
            DWORD offset = pSec->VirtualAddress + j * PAGE_SIZE;
            DWORD sizeToParse;
            union
            {
                void *ptrValue;
                DWORD *pPage32;
                QWORD *pPage64;
            } pPage;

            QWORD target = kernelBase + offset;

            pPage.ptrValue = NULL;

            if (offset > gWinGuest->KernelBufferSize)
            {
                status = IntVirtMemMap(target, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &pPage.ptrValue);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Failed mapping page %d of section %d: 0x%08x\n", j, i, status);
                    continue;
                }
            }
            else
            {
                pPage.ptrValue = pKernel + offset;
            }

            // If this is the last page, parse only what's left
            if (j == pageCount - 1)
            {
                sizeToParse = pSec->Misc.VirtualSize & PAGE_OFFSET;
            }
            else
            {
                sizeToParse = PAGE_SIZE;
            }

            // Analyze this page - we will parse DWORD entities, since we're running on x86 here.
            for (DWORD parsed = 0; parsed < sizeToParse / gGuest.WordSize;)
            {
                QWORD p = gGuest.Guest64 ? pPage.pPage64[parsed] : pPage.pPage32[parsed];
                void *hostPtr = gGuest.Guest64 ? (void *)&pPage.pPage64[parsed] : (void *)&pPage.pPage32[parsed];

                if (!gGuest.Guest64 &&
                    (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, p) ||
                     (p == 0xffffffff) ||
                     (p % 4 != 0)))
                {
                    goto _continue;
                }

                if (gGuest.Guest64 &&
                    (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, p) ||
                     (p % 4 != 0) ||
                     ((p & 0xFFFFFFFF00000000) == 0xFFFFFFFF00000000)))
                {
                    goto _continue;
                }

                if (pSec->Name[0] != '.')
                {
                    goto _almostro;
                }

                if (0 == gWinGuest->PsLoadedModuleList)
                {
                    status = IntWinDrvIsListHead(target, hostPtr, p);
                    if (INT_SUCCESS(status))
                    {
                        gWinGuest->PsLoadedModuleList = target;

                        TRACE("[INTRO-INIT] Found loaded module list: 0x%llx\n", target);

                        objectsFound++;

                        goto _continue;
                    }
                }

                if (0 == gWinGuest->PsActiveProcessHead)
                {
                    // p now points to what we believe is the EPROCESS of the System process.
                    status = IntWinProcIsPsActiveProcessHead(p);
                    if (INT_SUCCESS(status))
                    {
                        gWinGuest->PsActiveProcessHead = target;

                        TRACE("[INTRO-INIT] Found process list head: 0x%llx\n", target);

                        objectsFound++;

                        goto _continue;
                    }
                }

_almostro:
                if (pSec->Name[0] == '.')
                {
                    goto _continue;
                }

                if (gWinGuest->MmPfnDatabase == 0)
                {
                    status = IntWinPfnIsMmPfnDatabase(p);
                    if (INT_SUCCESS(status))
                    {
                        // Save the actual location, not the kernel pointer to it
                        gWinGuest->MmPfnDatabase = p;

                        TRACE("[INTRO-INIT] Found PFN database: 0x%llx\n", p);

                        // There are cases where pfn is before non-paged pool size
                        objectsFound++;

                        goto _continue;
                    }
                }

_continue:
                parsed++;

                target += gGuest.WordSize;

                if (objectsFound == objCount)
                {
                    break;
                }
            }

            if (offset > gWinGuest->KernelBufferSize)
            {
                IntVirtMemUnmap(&pPage.ptrValue);
            }

            if (objectsFound == objCount)
            {
                break;
            }
        }
    }

    if (objectsFound < objCount)
    {
        status = INT_STATUS_NOT_FOUND;

        // Be more explicit
        if (0 == gWinGuest->MmPfnDatabase)
        {
            ERROR("[ERROR] MmPfnDatabase not found!\n");
        }

        if (0 == gWinGuest->PsLoadedModuleList)
        {
            ERROR("[ERROR] PsLoadedModuleList not found!\n");
        }

        if (0 == gWinGuest->PsActiveProcessHead)
        {
            ERROR("[ERROR] PsActiveProcessHead not found!\n");
        }
    }
    else
    {
        status = INT_STATUS_SUCCESS;
    }

cleanup_and_exit:
    if (NULL != pSections)
    {
        HpFreeAndNullWithTag(&pSections, IC_TAG_IMGE);
    }

    return status;
}


static INTSTATUS
IntWinGuestFindKernelObjects(
    void
    )
///
/// @brief  Searches for kernel objects
///
/// This function will delegate a part of the search to #IntWinGuestFindKernelObjectsInternal, which will obtain the
/// PsLoadedModuleList and PsActiveProcessHead kernel variables, and the address of the PFN data base. Then, it will
/// use the PsActiveProcessHead to obtain the _EPROCESS address of the system process and read the system Cr3 from it.
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
/// @retval #INT_STATUS_NOT_FOUND if not all the objects were found
///
{
    INTSTATUS status;
    QWORD systemProcess = 0;

    status = IntWinGuestFindKernelObjectsInternal();
    if (!INT_SUCCESS(status))
    {
        TRACE("[INTRO-INIT] IntWinGuestFindKernelObjects%d: 0x%08x\n", gGuest.Guest64 ? 64 : 32, status);
        return status;
    }

    status = IntKernVirtMemRead(gWinGuest->PsActiveProcessHead,
                                gGuest.WordSize,
                                &systemProcess,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemFetchQword(systemProcess -
                                      WIN_KM_FIELD(Process, ListEntry) +
                                      WIN_KM_FIELD(Process, Cr3),
                                      &gGuest.Mm.SystemCr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
        return status;
    }

    // The CR3 (DirectoryTableBase field in KPROCESS) is 8 bytes only in long mode.
    if (!gGuest.Guest64)
    {
        gGuest.Mm.SystemCr3 &= 0xFFFFFFFF;
    }

    TRACE("[INTRO-INIT] System CR3 is 0x%016llx!\n", gGuest.Mm.SystemCr3);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinGuestFindSelfMapIndex(
    void
    )
///
/// @brief  Finds the self map index
///
/// In order to map the paging tables, the 64-bit Windows kernel uses the self mapping mechanism. This means that one
/// of the entries in the PML4 paging structure points to itself. This essentially gives access to all the paging
/// structures. The kernel randomizes the index used for the self map entry at boot, but due to the fact that it must
/// map to a kernel virtual address, we know that it must be situated in the upper half of the page table entries,
/// so it is between 256 and 511 (inclusive).
/// The search is easy: we must find an entry that points back to the Cr3 value.
/// On success, the gGuest.Mm.SelfMapIndex variable is set to the value of the self map index used by the OS.
/// We need this for various things, from the self map protection offered by #INTRO_OPT_PROT_KM_SELF_MAP_ENTRY, to the
/// PT filtering and \#VE agent.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the guest is not using 4- or 5-level paging
/// @retval     #INT_STATUS_NOT_FOUND if the value of the self map index is not found
///
{
    INTSTATUS status;
    QWORD *p;

    if (gGuest.Mm.Mode != PAGING_4_LEVEL_MODE &&
        gGuest.Mm.Mode != PAGING_5_LEVEL_MODE)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntPhysMemMap(gGuest.Mm.SystemCr3 & PHYS_PAGE_MASK, PAGE_SIZE, 0, &p);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysMemMap failed for 0x%016llx: 0x%08x\n", gGuest.Mm.SystemCr3 & PHYS_PAGE_MASK, status);
        return status;
    }

    for (DWORD i = 256; i < 512; i++)
    {
        if (((p[i] & PHYS_PAGE_MASK) == (gGuest.Mm.SystemCr3 & PHYS_PAGE_MASK)) && (0 == (p[i] & 0x800)))
        {
            LOG("[SELFMAP] Found index = %d (0x%x)\n", i, i);
            gGuest.Mm.SelfMapIndex = i;
            status = INT_STATUS_SUCCESS;
            break;
        }
    }

    if (0 == gGuest.Mm.SelfMapIndex)
    {
        ERROR("[ERROR] Self map index not found!\n");
        IntDumpBuffer((PBYTE)p, gGuest.Mm.SystemCr3 & PHYS_PAGE_MASK, PAGE_SIZE, 2, 8, TRUE, FALSE);
        status = INT_STATUS_NOT_FOUND;
    }

    IntPhysMemUnmap(&p);

    return status;
}


static BOOLEAN
IntWinGuestIsSystemCr3(
    _In_ QWORD KernelAddress,
    _In_ const VA_TRANSLATION *GvaTranslation,
    _In_ QWORD Cr3
    )
///
/// @brief  Checks if a Cr3 is the system Cr3
///
/// @param[in]  KernelAddress   The address of the kernel image
/// @param[in]  GvaTranslation  The translation information for KernelAddress
/// @param[in]  Cr3             Cr3 value to be checked. Must be page aligned.
///
/// @retval     True if Cr3 is the system Cr3
/// @retval     False if is not
///
/// @deprecated This function is no longer used
///
{
    INTSTATUS status;
    VA_TRANSLATION nkt;
    BOOLEAN valid = FALSE;
    QWORD *p;

    // Try to translate the kernel virtual address and see if it matches
    // Also, don't add the GPAs to the cache since they will be mostly wrong

    status = IntTranslateVirtualAddressEx(KernelAddress, Cr3, TRFLG_NONE, &nkt);
    if (!INT_SUCCESS(status))
    {
        return FALSE;
    }

    if (0 == (nkt.Flags & PT_P))
    {
        return FALSE;
    }

    if ((nkt.PhysicalAddress != GvaTranslation->PhysicalAddress) ||
        (nkt.MappingsCount != GvaTranslation->MappingsCount))
    {
        return FALSE;
    }

    status = IntPhysMemMap(Cr3, PAGE_SIZE, 0, &p);
    if (!INT_SUCCESS(status))
    {
        return FALSE;
    }

    if (GvaTranslation->PagingMode == PAGING_4_LEVEL_MODE ||
        GvaTranslation->PagingMode == PAGING_5_LEVEL_MODE)
    {
        // On 4-level paging, make sure the self map entry doesn't have bit 11 set.
        BOOLEAN selfMapOk = FALSE;

        for (DWORD i = 256; i < 512; i++)
        {
            if (((p[i] & PHYS_PAGE_MASK) == Cr3) && (0 == (p[i] & 0x800)))
            {
                selfMapOk = TRUE;
                break;
            }
        }

        if (!selfMapOk)
        {
            valid = FALSE;
            goto _cleanup_and_leave;
        }
    }
    else if (GvaTranslation->PagingMode == PAGING_PAE_MODE)
    {
        // On PAE paging, make sure the rest of the page is zero.
        for (DWORD i = 4; i < 512; i++)
        {
            if (p[i] != 0)
            {
                valid = FALSE;
                goto _cleanup_and_leave;
            }
        }
    }
    else
    {
        // Ignore normal paging mode.
    }

    if (GvaTranslation->PhysicalAddress != nkt.PhysicalAddress)
    {
        WARNING("[WARNING] We have a translation, but different physical addresses for 0x%016llx: "
                "0x%016llx != 0x%016llx\n", KernelAddress, GvaTranslation->PhysicalAddress, nkt.PhysicalAddress);

        valid = FALSE;
        goto _cleanup_and_leave;
    }

    valid = TRUE;

_cleanup_and_leave:
    IntPhysMemUnmap(&p);

    return valid;
}


static INTSTATUS
IntWinGuestFindSystemCr3(
    _In_ QWORD KernelAddress,
    _Out_ QWORD *SystemCr3,
    _In_ QWORD StartPhysical,
    _In_ QWORD EndPhysical
    )
///
/// @brief  Searches for the system Cr3 in a range of physical addresses
///
/// @param[in]  KernelAddress   The address of the kernel image
/// @param[out] SystemCr3       The value of the system Cr3
/// @param[in]  StartPhysical   The start of the memory range in which the search will be done
/// @param[in]  EndPhysical     The end of the memory range in which the search will be done
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if SystemCr3 is NULL
/// @retval     #INT_STATUS_NOT_FOUND if the system cr3 value is not found
///
/// @deprecated This function is no longer used
///
{
    INTSTATUS status;
    const QWORD startPhys = StartPhysical;
    const QWORD endPhys = EndPhysical;
    QWORD currentCr3 = 0;
    VA_TRANSLATION kt;

    if (NULL == SystemCr3)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntCr3Read(IG_CURRENT_VCPU, &currentCr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
        return status;
    }

    if (currentCr3 >= startPhys && currentCr3 < endPhys)
    {
        LOG("[WINGUEST STATIC] The current CR3 0x%016llx is already the system cr3!\n", currentCr3);
        *SystemCr3 = currentCr3;

        return INT_STATUS_SUCCESS;
    }

    status = IntTranslateVirtualAddressEx(KernelAddress, currentCr3, TRFLG_NONE, &kt);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed for 0x%016llx with cr3 0x%016llx: 0x%08x\n",
              KernelAddress, currentCr3, status);
        return status;
    }

    for (QWORD gpa = startPhys; gpa < endPhys; gpa += PAGE_SIZE)
    {
        if (IntWinGuestIsSystemCr3(KernelAddress, &kt, gpa))
        {
            *SystemCr3 = gpa;

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


void
IntWinGuestCancelKernelRead(
    void
    )
///
/// @brief  Cancels the kernel read
///
/// This function cancels all the pending page faults that were scheduled in order to read the
/// #WINDOWS_GUEST.KernelBuffer.
///
{
    INTSTATUS status;
    LIST_ENTRY *initEntry;

    initEntry = gWinGuest->InitSwapHandles.Flink;
    while (initEntry != &gWinGuest->InitSwapHandles)
    {
        PWIN_INIT_SWAP pInitSwap = CONTAINING_RECORD(initEntry, WIN_INIT_SWAP, Link);
        initEntry = initEntry->Flink;

        status = IntSwapMemRemoveTransaction(pInitSwap->SwapHandle);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSwapMemRemoveTransaction failed for %llx:%x: 0x%08x\n",
                  pInitSwap->VirtualAddress, pInitSwap->Size, status);
        }

        RemoveEntryList(&pInitSwap->Link);

        HpFreeAndNullWithTag(&pInitSwap, IC_TAG_WSWP);
    }
}


INTSTATUS
IntWinGuestInit(
    void
    )
///
/// @brief  Initializes a new Windows guest
///
/// Any operations that should be done after basic information about the guest is obtained should be done here.
/// Breakpoint exits are enabled here and not in #IntCallbacksInit where all the other events are enabled because
/// activating the break point exits earlier may cause a slow boot on Linux OS so this activation step is done by each
/// OS as a custom step in the initialization phase.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    status = IntRegisterBreakpointHandler(IntHandleBreakpoint);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntRegisterBreakpointHandler failed: 0x%08x\n", status);
        return status;
    }

    gGuest.GuestInitialized = TRUE;

    return INT_STATUS_SUCCESS;
}


void
IntWinGuestUninit(
    void
    )
///
/// @brief  Uninits a Windows guest
///
/// This will run the uninit routines for all the Windows subsystems and will also free any resources held by
/// the #WINDOWS_GUEST state. After this function returns, the GuestInitialized field of #gGuest will be set to False.
///
{
    INTSTATUS status;

    if (!gGuest.GuestInitialized || NULL == gWinGuest)
    {
        return;
    }

    if (gWinGuest->KernelBuffer)
    {
        HpFreeAndNullWithTag(&gWinGuest->KernelBuffer, IC_TAG_KRNB);
    }

    IntDriverUninit();

    status = IntWinDrvObjUninit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinDrvObjUninit failed: 0x%08x\n", status);
    }

    IntWinHalUninit();

    IntWinProcUninit();

    // Do this after the process subsystem uninits, so we can free there whatever
    // caches that weren't fully formed (only allocated)
    IntWinUmCacheUninit();

    if (NULL != gWinGuest->NtBuildLabString)
    {
        HpFreeAndNullWithTag(&gWinGuest->NtBuildLabString, IC_TAG_NAME);
    }

    if (NULL != gWinGuest->VersionString)
    {
        HpFreeAndNullWithTag(&gWinGuest->VersionString, IC_TAG_NAME);
    }

    if (NULL != gWinGuest->ServerVersionString)
    {
        HpFreeAndNullWithTag(&gWinGuest->ServerVersionString, IC_TAG_NAME);
    }

    status = IntCr4Unprotect();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr4Unprotect failed: 0x%08x\n", status);
    }

    IntWinAgentUnInit();

    gGuest.GuestInitialized = FALSE;
}


INTSTATUS
IntWinGuestActivateProtection(
    void
    )
///
/// @brief  Activates the protection for a Windows guest
///
/// Depending on the @ref group_options used, this will activate various protection mechanisms: IDT, Syscall MSR, Cr4,
/// IDTR, and GDTR.
/// The ProtectionActivated field of #gGuest will be set to True.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDT)
    {
        status = IntWinIdtProtectAll();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinIdtProtectAll failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_MSR_SYSCALL)
    {
        status = IntMsrSyscallProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMsrSyscallProtect failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CR4)
    {
        status = IntCr4Protect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCr4Protect failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDTR)
    {
        status = IntIdtrProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntIdtrProtect failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_GDTR)
    {
        status = IntGdtrProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGdtrProtect failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SUD_EXEC)
    {
        status = IntWinSudProtectSudExec();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSudProtectSudExec failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SUD_INTEGRITY)
    {
        status = IntWinSudProtectIntegrity();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinSudProtectIntegrity failed: 0x%08x\n", status);
            return status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_INTERRUPT_OBJ)
    {
        status = IntWinIntObjProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinIntObjProtect failed: 0x%08x\n", status);
            return status;
        }
    }

    // Flag the protection
    gGuest.ProtectionActivated = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinGuestResolveImports(
    void
    )
///
/// @brief  Obtains the addresses of public variable and functions exposed by the Windows kernel
///
/// On success, this will obtain the addresses of PsCreateSystemThread, ExAllocatePoolWithTag, ExFreePoolWithTag,
/// NtBuildNumber, NtBuildLab, the value of the NtBuildNumber, and the contents of the NtBuildLab string. For 32-bit
/// guests, it will also obtain the address of the KeServiceDescriptorTable and the number of services in the SSDT.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    QWORD expGva;

    status = IntPeFindKernelExport("PsCreateSystemThread", &gWinGuest->PsCreateSystemThread);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] %s not found: 0x%08x\n", "PsCreateSystemThread", status);
        return status;
    }

    TRACE("[INTRO-INIT] Found API function PsCreateSystemThread @ 0x%016llx...\n", gWinGuest->PsCreateSystemThread);

    status = IntPeFindKernelExport("ExAllocatePoolWithTag", &gWinGuest->ExAllocatePoolWithTag);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] %s not found: 0x%08x\n", "ExAllocatePoolWithTag", status);
        return status;
    }

    TRACE("[INTRO-INIT] Found API function ExAllocatePoolWithTag @ 0x%016llx...\n", gWinGuest->ExAllocatePoolWithTag);

    status = IntPeFindKernelExport("ExFreePoolWithTag", &gWinGuest->ExFreePoolWithTag);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] %s not found: 0x%08x\n", "ExFreePoolWithTag", status);
        return status;
    }

    TRACE("[INTRO-INIT] Found API function ExFreePoolWithTag @ 0x%016llx...\n", gWinGuest->ExFreePoolWithTag);

    status = IntPeFindKernelExport("NtBuildNumber", &expGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] %s not found: 0x%08x\n", "NtBuildNumber", status);
        return status;
    }

    status = IntKernVirtMemFetchDword(expGva, &gWinGuest->NtBuildNumberValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting NtBuildNumber value: %08x\n", status);
        return status;
    }

    TRACE("[INTRO-INIT] Found NtBuildNumber @ 0x%016llx with value 0x%08x...\n",
          expGva, gWinGuest->NtBuildNumberValue);

    status = IntPeFindKernelExport("NtBuildLab", &expGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] %s not found: 0x%08x\n", "NtBuildLab", status);
        return status;
    }

    status = IntReadString(expGva, 16, FALSE, &gWinGuest->NtBuildLabString, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting NtBuildLab value for kernel base 0x%016llx:0x%08x\n", gGuest.KernelVa, status);
        return status;
    }

    TRACE("[INTRO-INIT] Found NtBuildLab @ 0x%016llx with value: `%s`\n",
          expGva, gWinGuest->NtBuildLabString);

    if (!gGuest.Guest64)
    {
        status = IntPeFindKernelExport("KeServiceDescriptorTable", &gWinGuest->KeServiceDescriptorTable);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] %s not found: 0x%08x\n", "KeServiceDescriptorTable RVA", status);
            return status;
        }

        status = IntKernVirtMemFetchDword(gWinGuest->KeServiceDescriptorTable, (DWORD *)&gWinGuest->Ssdt);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting KeServiceDescriptorTable value: %08x\n", status);
            return status;
        }

        // Now get the number of services. The KeServiceDescriptorTable is a struct, and the number of services
        // is the third DWORD inside this structure.
        status = IntKernVirtMemFetchDword(gWinGuest->KeServiceDescriptorTable + 8, &gWinGuest->NumberOfServices);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting KeServiceDescriptorTable number of services: %08x\n", status);
            return status;
        }

        if (gWinGuest->NumberOfServices > 1024)
        {
            ERROR("[ERROR] The number of services in the SSDT is higher than expected: %u\n",
                  gWinGuest->NumberOfServices);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        TRACE("[INTRO-INIT] Found KeServiceDescriptorTable @ 0x%016llx with table at 0x%016llx and %d functions...\n",
              gWinGuest->KeServiceDescriptorTable, gWinGuest->Ssdt, gWinGuest->NumberOfServices);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinGuestFetchProductType(
    _Out_ WIN_PRODUCT_TYPE *ProductType
    )
///
/// @brief      Obtains the Windows product type
///
/// This information is available in the _KUSER_SHARED_DATA structure
///
/// @param[out] ProductType The type of the Windows product
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_NEEDED_HINT for 32-bit guests, when ProductType is always #winProductTypeWinNt
/// @retval     #INT_STATUS_INVALID_DATA_VALUE if the type obtained from the guest is not a known good value as
///             described by the #WIN_PRODUCT_TYPE enum
///
{
// It seems it is hardcoded on every os but we might think about moving it to cami.
#define WIN_SHARED_USER_DATA_OFFSET_PRODUCT     0x264

    INTSTATUS status;
    DWORD productType;

    if (!gGuest.Guest64)
    {
        *ProductType = winProductTypeWinNt;
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntKernVirtMemFetchDword(WIN_SHARED_USER_DATA_PTR + WIN_SHARED_USER_DATA_OFFSET_PRODUCT, &productType);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (productType != winProductTypeWinNt &&
        productType != winProductTypeLanManNt &&
        productType != winProductTypeServer)
    {
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    *ProductType = productType;

    return INT_STATUS_SUCCESS;

#undef WIN_SHARED_USER_DATA_OFFSET_PRODUCT
}


static INTSTATUS
IntWinGuestFinishInit(
    void
    )
///
/// @brief  Finalizes the Windows initialization once the entire kernel is read
///
/// This function is called wen the entire #WINDOWS_GUEST.KernelBuffer is read and does the last steps of the
/// initialization. It will resolve the address and values of any global kernel variable and functions and objects
/// needed by introcore, will obtain the Windows product type, will validate that the OS version is supported and
/// will notify the integrator about the detected operating system. It will also set all the needed API hooks, deploy
/// any performance or mitigation agents and obtain the list of processes and kernel modules.
/// If no errors are encountered, at the end it will send an activation notification to the integrator.
/// If any steps can not be done because of an error an appropriate error state will be set and the initialization
/// will be stopped.
///
/// @retval #INT_STATUS_SUCCESS in case of success
/// @retval #INT_STATUS_GUEST_OS_NOT_SUPPORTED if the OS version is not supported
///
{
    INTSTATUS status;

    status = IntWinGuestResolveImports();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestResolveImports failed: 0x%08x\n", status);

        IntGuestSetIntroErrorState(intErrGuestExportNotFound, NULL);

        goto leave_and_unload;
    }

    if (IntWinGuestIsIncreasedUserVa())
    {
        ERROR("[ERROR] Guest %d booted with /3GB is not supported!\n", gGuest.OSVersion);

        IntGuestSetIntroErrorState(intErrGuestNotSupported, NULL);

        status = INT_STATUS_GUEST_OS_NOT_SUPPORTED;

        goto leave_and_unload;
    }

    // Set the OS specific fields in the guest-state structure
    gGuest.OSVersion = gWinGuest->NtBuildNumberValue & 0xFFFF;
    gGuest.IntroActiveEventId = gEventId;

    status = IntWinGuestFetchProductType(&gWinGuest->ProductType);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinGuestFetchProductType failed: 0x%08x, will not be able to determine whether it is a "
                "server or not\n", status);
        gWinGuest->ProductType = winProductTypeUnknown;
    }

    status = IntWinGuestIsSupported();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] NtBuildNumber %04x is not supported!\n", gGuest.OSVersion);

        IntGuestSetIntroErrorState(intErrGuestNotSupported, NULL);

        status = INT_STATUS_GUEST_OS_NOT_SUPPORTED;

        goto leave_and_unload;
    }

    LOG("[INFO] Identified OS type Windows, version %d\n", gGuest.OSVersion);
    LOG("[INFO] Guest has KPTI %s\n", gGuest.KptiInstalled ? "Installed" : "Not installed");

    IntNotifyIntroDetectedOs(gGuest.OSType, gGuest.OSVersion, gGuest.Guest64);

    // Fill in the auxiliary data. These fields may not be persistent and may change during the
    // normal execution of the OS, so these APIs may be called as many times as necessarily
    // (example, one could register a callback for a given event and call these functions again
    // anytime that event is triggered). However, all the fields are lists of some sort, and the
    // head will remain valid during the normal execution of the guest.

    status = IntWinGuestFindKernelObjects();
    if (!INT_SUCCESS(status))
    {
        if (INT_STATUS_LOAD_ABORTED != status)
        {
            ERROR("[ERROR] IntWinGuestFindKernelObjects failed: 0x%08x\n", status);

            IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        }
        else
        {
            WARNING("[WARNING] Introcore load was aborted!\n");
        }

        goto leave_and_unload;
    }

    TRACE("[INTRO-INIT] Kernel objects successfully identified!\n");

    status = IntWinAgentInjectTrampoline();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentInjectTrampoline failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    status = IntWinApiHookAll();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinApiHookAll failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    status = IntSwapgsStartMitigation();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSwapgsStartMitigation failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    status = IntWinDrvIterateLoadedModules(IntWinDrvCreateFromAddress, FLAG_STATIC_DETECTION);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinDrvIterateLoadedModules failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    gGuest.KernelDriver = IntDriverFindByAddress(gGuest.KernelVa);
    if (NULL == gGuest.KernelDriver)
    {
        ERROR("[ERROR] Failed finding kernel module!\n");
        goto leave_and_unload;
    }

    LOG("[INTRO-INIT] Kernel loaded @ 0x%016llx size of image = 0x%llx timedate stamp = 0x%08x\n",
        gGuest.KernelDriver->BaseVa, gGuest.KernelDriver->Size, gGuest.KernelDriver->Win.TimeDateStamp);

    status = IntWinHalCreateHalData();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinHalCreateHalData failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    status = IntWinProcIterateGuestProcesses(IntWinProcAdd, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinProcIterateGuestProcesses failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    status = IntWinGuestActivateProtection();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestActivateProtection failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_VE)
    {
        status = IntVeDeployAgent();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVeDeployAgent failed: 0x%08x\n", status);
        }
    }

    // Make sure no threads have a RIP pointing in a modified code region.
    TRACE("[WINGUEST] Ensuring no thread will return into our hooks!\n");

    status = IntThrSafeCheckThreads(THS_CHECK_DETOURS | THS_CHECK_SWAPGS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntThrSafeCheckThreads failed: 0x%08x\n", status);
        goto leave_and_unload;
    }

    IntNotifyIntroActive();

    IntGuestSetIntroErrorState(intErrNone, NULL);

    TRACE("[WINGUEST] Introspection successfully initialized!\n");

    return INT_STATUS_SUCCESS;

leave_and_unload:
    gGuest.DisableOnReturn = TRUE;
    return status;
}


static INTSTATUS
IntWinGuestSectionInMemory(
    _Inout_ WIN_INIT_SWAP *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      Handles the swap in of a kernel section done while the #WINDOWS_GUEST.KernelBuffer is read
///
/// This is the IntSwapMemRead handler set by #IntWinGuestReadKernel that will read a kernel section into the
/// kernel buffer. It will set the appropriate part of the #WINDOWS_GUEST.KernelBuffer with the data obtained from the
/// guest and will decrement the #WINDOWS_GUEST.RemainingSections counter. It will also remove Context from the
/// #WINDOWS_GUEST.InitSwapHandles list and will free it.
///
/// @param[in]  Context         The init swap handle used for this section
/// @param[in]  Cr3             Ignored
/// @param[in]  VirtualAddress  Ignored
/// @param[in]  PhysicalAddress Ignored
/// @param[in]  Data            The data read from the kernel
/// @param[in]  DataSize        The size of the Data buffer
/// @param[in]  Flags           A combination of flags describing the way in which the data was read. This function
///                             checks only for the #SWAPMEM_FLAG_ASYNC_CALL flag. If it is present, it means that it
///                             was invoked asynchronously, in which case it will pause the VCPUs in order to ensure
///                             consistency of the data. If the #WINDOWS_GUEST.RemainingSections is set to 0 by this
///                             callback while #SWAPMEM_FLAG_ASYNC_CALL is set, it will also finalize the initialization
///                             using #IntWinGuestFinishInit since there are no more sections left to read. If all
///                             the sections are read synchronously, this action will be done by #IntWinGuestReadKernel.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    PWIN_INIT_SWAP pSwp;
    QWORD va;
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);

    if (Flags & SWAPMEM_FLAG_ASYNC_CALL)
    {
        IntPauseVcpus();
    }

    status = INT_STATUS_SUCCESS;

    pSwp = Context;
    va = pSwp->VirtualAddress;

    // Remove the context. The caller knows this may happen & won't use it after IntSwapMemReadData
    RemoveEntryList(&pSwp->Link);
    HpFreeAndNullWithTag(&pSwp, IC_TAG_WSWP);

    if (0 == gWinGuest->RemainingSections)
    {
        ERROR("[ERROR] Callback came after we have no more sections to read...\n");
        status = INT_STATUS_INVALID_INTERNAL_STATE;
        goto resume_and_exit;
    }

    memcpy(gWinGuest->KernelBuffer + va, Data, DataSize);

    gWinGuest->RemainingSections--;

    if ((0 == gWinGuest->RemainingSections) && (Flags & SWAPMEM_FLAG_ASYNC_CALL))
    {
        TRACE("[WINGUEST STATIC] Since we are called asynchronously we will finish the initialization...\n");

        status = IntWinGuestFinishInit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinGuestFinishInit failed: 0x%08x\n", status);
        }
    }

resume_and_exit:
    if (Flags & SWAPMEM_FLAG_ASYNC_CALL)
    {
        IntResumeVcpus();
    }

    return status;
}


static INTSTATUS
IntWinGuestReadKernel(
    _In_ PBYTE KernelHeaders
    )
///
/// @brief      Reads the whole kernel image in memory, including swapped-out sections
///
/// This will allocate and fill #WINDOWS_GUEST.KernelBuffer. For the swapped-out sections, IntSwapMemRead will be used
/// with #IntWinGuestSectionInMemory as the swap-in handler. Discardable sections will be filled with 0, as those
/// can not be brought back into memory. The same thing will be done for the INITKDBG and ERRATA sections.
/// If all the sections are already present in memory, this function will finalize the initialization calling
/// #IntWinGuestFinishInit. If not, this step is left to the last invocation of the #IntWinGuestSectionInMemory
/// callback. Once #IntWinGuestFinishInit is called the kernel buffer can be safely used.
///
/// @param[in]  KernelHeaders   A buffer containing the MZPE headers of the kernel. This buffer should be at least
///                             #PAGE_SIZE in size.
///
/// @retval     #INT_STATUS_SUCCESS in case of success. Note that even if this function exits with a success status,
///             the kernel buffer is not necessarily valid yet, as parts of it may be read in an asynchronous manner.
/// @retval     #INT_STATUS_INVALID_OBJECT_TYPE if the MZPE validation of the headers fails
/// @retval     #INT_STATUS_NOT_SUPPORTED if a section header can not be parsed
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE if an internal error is encountered
///
{
    BOOLEAN unmapNtHeaders;
    DWORD secStartOffset, secCount;
    PIMAGE_DOS_HEADER pDosHeader;
    INTSTATUS status;
    INTRO_PE_INFO peInfo = { 0 };

    unmapNtHeaders = FALSE;
    pDosHeader = (PIMAGE_DOS_HEADER)KernelHeaders;

    // First thing, validate the buffer
    status = IntPeValidateHeader(gGuest.KernelVa, KernelHeaders, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        return status;
    }

    if (gGuest.Guest64 != peInfo.Image64Bit)
    {
        ERROR("[ERROR] Inconsistent MZPE image!\n");
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // Update the size of the kernel
    gGuest.KernelSize = peInfo.SizeOfImage;

    if (peInfo.Image64Bit)
    {
        PIMAGE_NT_HEADERS64 pNth64;

        if ((QWORD)(DWORD)pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) < PAGE_SIZE)
        {
            // We are in the same page, so it's safe to use this
            pNth64 = (PIMAGE_NT_HEADERS64)(KernelHeaders + pDosHeader->e_lfanew);
        }
        else
        {
            status = IntVirtMemMap(gGuest.KernelVa + pDosHeader->e_lfanew, sizeof(*pNth64),
                                   gGuest.Mm.SystemCr3, 0, &pNth64);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n",
                      gGuest.KernelVa + pDosHeader->e_lfanew, status);
                return status;
            }

            unmapNtHeaders = TRUE;
        }

        secCount = 0xffff & pNth64->FileHeader.NumberOfSections;
        secStartOffset = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
                         pNth64->FileHeader.SizeOfOptionalHeader;

        if (unmapNtHeaders)
        {
            IntVirtMemUnmap(&pNth64);
        }
    }
    else
    {
        PIMAGE_NT_HEADERS32 pNth32;

        if ((QWORD)(DWORD)pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) < PAGE_SIZE)
        {
            // We are in the same page, so it's safe to use this
            pNth32 = (PIMAGE_NT_HEADERS32)(KernelHeaders + pDosHeader->e_lfanew);
        }
        else
        {
            status = IntVirtMemMap(gGuest.KernelVa + pDosHeader->e_lfanew, sizeof(*pNth32),
                                   gGuest.Mm.SystemCr3, 0, &pNth32);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n",
                      gGuest.KernelVa + pDosHeader->e_lfanew, status);
                return status;
            }

            unmapNtHeaders = TRUE;
        }

        secCount = 0xffff & pNth32->FileHeader.NumberOfSections;
        secStartOffset = pDosHeader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
                         pNth32->FileHeader.SizeOfOptionalHeader;

        if (unmapNtHeaders)
        {
            IntVirtMemUnmap(&pNth32);
        }
    }

    if (secStartOffset >= PAGE_SIZE)
    {
        ERROR("[ERROR] Sections get outside the first page. We don't support this yet!\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (secStartOffset + secCount * sizeof(IMAGE_SECTION_HEADER) > PAGE_SIZE)
    {
        ERROR("[ERROR] Sections get outside the first page. We don't support this yet!\n");
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (peInfo.SizeOfImage < PAGE_SIZE)
    {
        ERROR("[ERROR] SizeOfImage too small: %d!\n", peInfo.SizeOfImage);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // Now finally initialize the lock & kernel buffer
    gWinGuest->KernelBuffer = HpAllocWithTag(peInfo.SizeOfImage, IC_TAG_KRNB);
    if (NULL == gWinGuest->KernelBuffer)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    gWinGuest->KernelBufferSize = peInfo.SizeOfImage;
    memcpy(gWinGuest->KernelBuffer, KernelHeaders, PAGE_SIZE);

    gWinGuest->RemainingSections = secCount;

    for (DWORD i = 0; i < secCount; i++)
    {
        DWORD secActualSize;

        PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)(gWinGuest->KernelBuffer + secStartOffset +
                                                             i * sizeof(IMAGE_SECTION_HEADER));

        secActualSize = ROUND_UP(pSec->Misc.VirtualSize, PAGE_SIZE);

        if (0 == pSec->VirtualAddress)
        {
            ERROR("[ERROR] We cannot have a section starting at 0!\n");

            return INT_STATUS_NOT_SUPPORTED;
        }

        if (0 == pSec->Misc.VirtualSize)
        {
            ERROR("[ERROR] We cannot have a section starting at 0!\n");

            return INT_STATUS_NOT_SUPPORTED;
        }

        // Make sure the section fits within the allocated buffer. We must avoid cases where the SizeOfImage or
        // section headers are maliciously altered.
        if ((pSec->VirtualAddress >= peInfo.SizeOfImage) ||
            (secActualSize > peInfo.SizeOfImage) ||
            (pSec->VirtualAddress + secActualSize > peInfo.SizeOfImage))
        {
            ERROR("[ERROR] Section %d seems corrupted: sizeOfImage = 0x%x, secstart = 0x%x, secsize = 0x%x\n",
                  i, peInfo.SizeOfImage, pSec->VirtualAddress, pSec->Misc.VirtualSize);

            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if ((pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) ||
            (0 == memcmp(pSec->Name, "INITKDBG", sizeof("INITKDBG") - 1) ||
             (0 == memcmp(pSec->Name, "ERRATA", sizeof("ERRATA") - 1))))
        {
            memset(gWinGuest->KernelBuffer + pSec->VirtualAddress, 0, secActualSize);

            gWinGuest->RemainingSections--;
        }
        else if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
        {
            // The section will be present, so read it now
            status = IntKernVirtMemRead(gGuest.KernelVa + pSec->VirtualAddress,
                                        secActualSize,
                                        gWinGuest->KernelBuffer + pSec->VirtualAddress,
                                        NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntKernVirtMemRead failed for 0x%016llx -> 0x%016llx %s: 0x%08x\n",
                      gGuest.KernelVa + pSec->VirtualAddress,
                      gGuest.KernelVa + pSec->VirtualAddress + secActualSize,
                      pSec->Name, status);

                return status;
            }

            gWinGuest->RemainingSections--;
        }
        else
        {
            DWORD retSize = 0;

            // Use the swap mechanism only if we can't directly read the memory; this avoids unnecessary
            // recursive function calls.
            status = IntKernVirtMemRead(gGuest.KernelVa + pSec->VirtualAddress,
                                        secActualSize,
                                        gWinGuest->KernelBuffer + pSec->VirtualAddress,
                                        &retSize);
            if (!INT_SUCCESS(status))
            {
                PWIN_INIT_SWAP pSwp = NULL;
                void *swapHandle = NULL;

                pSwp = HpAllocWithTag(sizeof(*pSwp), IC_TAG_WSWP);
                if (NULL == pSwp)
                {
                    return INT_STATUS_INSUFFICIENT_RESOURCES;
                }

                pSwp->VirtualAddress = pSec->VirtualAddress;
                pSwp->Size = secActualSize;

                InsertTailList(&gWinGuest->InitSwapHandles, &pSwp->Link);

                WARNING("Section %d / %d is not in memory, will do a swap mem read\n", i, secCount);

                status = IntSwapMemReadData(0,
                                            gGuest.KernelVa + pSec->VirtualAddress,
                                            secActualSize,
                                            SWAPMEM_OPT_BP_FAULT,
                                            pSwp,
                                            0,
                                            IntWinGuestSectionInMemory,
                                            NULL,
                                            &swapHandle);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntSwapMemReadData failed: 0x%08x\n", status);
                    return status;
                }

                // The callback will be called async, save the handle in case an uninit will come
                if (NULL != swapHandle)
                {
                    pSwp->SwapHandle = swapHandle;
                }
            }
            else
            {
                if (retSize != secActualSize)
                {
                    ERROR("We requested %08x bytes, but got %08x!\n", secActualSize, retSize);
                    return INT_STATUS_INVALID_INTERNAL_STATE;
                }

                gWinGuest->RemainingSections--;
            }
        }
    }

    // We managed to read everything here, so continue the initialization
    if (0 == gWinGuest->RemainingSections)
    {
        TRACE("[WINGUEST STATIC] All sections were present in memory!\n");

        status = IntWinGuestFinishInit();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinGuestFinishInit failed: 0x%08x\n", status);
        }
    }

    return status;
}


static INTSTATUS
IntWinGuestKernelHeadersInMemory(
    _Inout_ WIN_INIT_SWAP *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief      Handles the swap in of the kernel MZPE headers
///
/// This is the IntSwapMemRead callback set by #IntWinGuestNew in order to get the kernel MZPE headers in memory
/// and start the read of the kernel image. It will pause the VCPUs while running in order to ensure the consistency
/// of the data.
///
/// @param[in]  Context         The init swap handle used for the headers
/// @param[in]  Cr3             Ignored
/// @param[in]  VirtualAddress  Ignored
/// @param[in]  PhysicalAddress Ignored
/// @param[in]  Data            The data read from the guest. This buffer is valid until this function returns.
/// @param[in]  DataSize        Ignored
/// @param[in]  Flags           Ignored
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    PWIN_INIT_SWAP pSwp;

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(DataSize);

    IntPauseVcpus();

    // Remove the context. The caller knows this may happen & won't use it after IntSwapMemReadData
    pSwp = Context;
    RemoveEntryList(&pSwp->Link);
    HpFreeAndNullWithTag(&pSwp, IC_TAG_WSWP);

    status = IntWinGuestReadKernel(Data);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestReadKernel failed: 0x%08x\n", status);

        // We don't care about specifics, but the introspection MUST be unloaded
        gGuest.DisableOnReturn = TRUE;
    }

    IntResumeVcpus();

    return status;
}


static INTSTATUS
IntWinGuestFindBuildNumber(
    _In_ QWORD KernelGva,
    _In_ BOOLEAN Guest64,
    _In_ BOOLEAN IsKptiInstalled,
    _Out_ DWORD *NtBuildNumber
    )
///
/// @brief      Finds the NtBuildNumber kernel variable
///
/// Even if this is exported by the kernel, we may not always be able to obtain its address, since the export
/// directory might be swapped-out. We need its value before reading the #WINDOWS_GUEST.KernelBuffer so we also
/// try to find it by applying some invariant rules. It will try to match the found value with one of the supported
/// Windows versions supplied by CAMI.
///
/// @param[in]  KernelGva           The guest virtual address of the base of the kernel image
/// @param[in]  Guest64             True for 64-bit guests, False for 32-bit guests
/// @param[in]  IsKptiInstalled     True if KPTI is enabled, False if it is not
/// @param[out] NtBuildNumber       The value of the NtBuildNumber
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if NtBuildNumber was not found
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
///
{
    INTSTATUS status;
    DWORD limit, cb;
    DWORD smallestBuild, biggestBuild;
    QWORD gva, cr3;
    PDWORD pPage;
    BOOLEAN found;
    PDWORD pNtList;

    limit = 0;
    gva = KernelGva & PAGE_MASK;
    pNtList = NULL;
    pPage = NULL;
    found = FALSE;
    cb = 0;

    status = IntCamiGetWinSupportedList(IsKptiInstalled, Guest64, pNtList, &cb);
    if (!INT_SUCCESS(status) || 0 == cb)
    {
        ERROR("[ERROR] IntCamiGetWinSupportedList failed with count %u: 0x%08x\n", cb, status);
        return INT_STATUS_NOT_FOUND;
    }

    TRACE("[INFO] %d supported os versions from cami\n", cb);

    pNtList = HpAllocWithTag(sizeof(*pNtList) * cb, IC_TAG_CAMI);
    if (NULL == pNtList)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntCamiGetWinSupportedList(IsKptiInstalled, Guest64, pNtList, &cb);
    if (!INT_SUCCESS(status) || 0 == cb)
    {
        ERROR("[ERROR] IntCamiGetWinSupportedList failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    // pNtList is sorted.
    smallestBuild = pNtList[0];
    biggestBuild = pNtList[cb - 1];

    cr3 = gGuest.Mm.SystemCr3;

    found = FALSE;
    while (limit < KERNEL_SEARCH_LIMIT)
    {
        status = IntVirtMemMap(gva, PAGE_SIZE, cr3, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            pPage = NULL;
            goto _next_page;
        }

        for (DWORD i = 0; i < PAGE_SIZE / sizeof(DWORD); i++)
        {
            DWORD val = pPage[i];

            if ((val & 0xf0000000) != 0xf0000000 ||
                (val & 0xf000ffff) != val ||
                (val & 0xffff) > biggestBuild ||
                (val & 0xffff) < smallestBuild)
            {
                continue;
            }

            for (DWORD j = 0; j < cb; j++)
            {
                if (pNtList[j] == (val & 0xFFFF))
                {
                    TRACE("[WINGUEST STATIC] Found an NtBuildNumber 0x%08x (%d) @ 0x%016llx\n",
                          val, val & 0xffff, gva + i * sizeof(DWORD));

                    *NtBuildNumber = pNtList[j];
                    found = TRUE;
                    goto cleanup_and_exit;
                }
            }
        }

_next_page:
        if (NULL != pPage)
        {
            IntVirtMemUnmap(&pPage);
        }

        if (found)
        {
            break;
        }

        gva += PAGE_SIZE;
        limit += PAGE_SIZE;
    }

cleanup_and_exit:
    if (NULL != pPage)
    {
        IntVirtMemUnmap(&pPage);
    }

    if (NULL != pNtList)
    {
        HpFreeAndNullWithTag(&pNtList, IC_TAG_CAMI);
    }

    if (!found)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinGuestValidateKernel(
    _In_ QWORD KernelBase,
    _In_ QWORD KernelGva,
    _In_ BYTE *KernelHeaders
    )
///
/// @brief  Validates if the presumed kernel base is the real kernel base, based on various checks.
///
/// The checks include verifying if the KernelGva from which the search has started is contained inside
/// a non-writable, non-discardable and executable section. Another check is to verify if the current kernel
/// base is found in the .data/ALMOSTRO section. Note that this should always be true, due to the presence of
/// PsNtosImageBase variable in .data, which is used for various purposes inside the kernel, such as
/// fetching a function address (through a MmGetSystemRoutineAddress call).
///
/// @param[in]  KernelBase      The currently presumed kernel base.
/// @param[in]  KernelGva       The address from where the search for the kernel base has been started.
/// @param[in]  KernelHeaders   A mapping containing the first page of the presumed kernel base.
///
/// @retval     #INT_STATUS_SUCCESS             If all the validations pass.
/// @retval     #INT_STATUS_INVALID_DATA_STATE  If the KernelGva address is not in a non-writable,
///                                             non-discardable and executable section, or the .data
///                                             or ALMOSTRO sections do not exist.
/// @retval     #INT_STATUS_ALIGNMENT_INCONSISTENCY     If the .data section is not page aligned.
/// @retval     #INT_STATUS_NOT_FOUND           If the PsNtosImageBase variable could not be found.
/// @retval     #INT_STATUS_INVALID_DATA_SIZE   If any of the parsed sections has a size exceeding 2MB.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES      If there are not enough resources for auxiliary
///                                                     allocations.
///
{
    IMAGE_SECTION_HEADER *pSec = NULL;
    const DWORD maxSecCount = 10;
    DWORD sectionCount = 0;
    INTSTATUS status;
    BOOLEAN found = FALSE;
    void *mappedSecPage = NULL;

    pSec = HpAllocWithTag(sizeof(*pSec) * maxSecCount, IC_TAG_IMGE);
    if (NULL == pSec)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Check if the current GVA is inside any section, as on 20h1 we have some mapped MZPEs inside kernel.
    status = IntPeGetSectionHeaderByRva(KernelBase, KernelHeaders, (DWORD)(KernelGva - KernelBase), &pSec[0]);
    if (INT_SUCCESS(status))
    {
        if ((pSec[0].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) ||
            (pSec[0].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
            (pSec[0].Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            WARNING("[WARNING] Gva 0x%016llx is not in a good section of 0x%016llx, discardable: %d, "
                    "execute: %d, writable: %d",
                    KernelGva, KernelBase, !!(pSec[0].Characteristics & IMAGE_SCN_MEM_DISCARDABLE),
                    !!(pSec[0].Characteristics & IMAGE_SCN_MEM_EXECUTE),
                    !!(pSec[0].Characteristics & IMAGE_SCN_MEM_WRITE));
            status = INT_STATUS_INVALID_DATA_STATE;
            goto cleanup_and_exit;
        }
    }

    // The GVA is inside a good section, now verify if we can find PsNtosImageBase in ALMOSTRO or .data.
    status = IntPeGetSectionHeadersByName(KernelBase, KernelHeaders, "ALMOSTRO", maxSecCount - 1, gGuest.Mm.SystemCr3,
                                          pSec, &sectionCount);
    if (!INT_SUCCESS(status) || (0 == sectionCount))
    {
        WARNING("[WARNING] IntPeGetSectionHeadersByName failed for `ALMOSTRO`: 0x%08x, secCount = %d\n", status, sectionCount);
        // Overwrite the status, as ALMOSTRO should always be available, we will return INT_STATUS_INVALID_DATA_STATE;
        status = INT_STATUS_INVALID_DATA_STATE;
        goto cleanup_and_exit;
    }

    status = IntPeGetSectionHeaderByName(KernelBase, KernelHeaders, ".data", gGuest.Mm.SystemCr3, &pSec[sectionCount]);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Presumed base 0x%016llx has no .data section!\n", KernelBase);
        status = INT_STATUS_INVALID_DATA_STATE;
        goto cleanup_and_exit;
    }

    sectionCount++;

    for (DWORD iSec = 0; iSec < sectionCount; iSec++)
    {
        if ((pSec[iSec].VirtualAddress & PAGE_OFFSET) != 0)
        {
            WARNING("[WARNING] Base 0x%016llx has section start 0x%08x which is not page aligned!\n",
                    KernelBase, pSec[iSec].VirtualAddress);
            status = INT_STATUS_ALIGNMENT_INCONSISTENCY;
            goto cleanup_and_exit;
        }

        if (pSec[iSec].Misc.VirtualSize > 2 * ONE_MEGABYTE)
        {
            WARNING("[WARNING] Section %d has size too big: 0x%08x\n", iSec, pSec[iSec].Misc.VirtualSize);
            status = INT_STATUS_INVALID_DATA_SIZE;
            goto cleanup_and_exit;
        }

        for (QWORD page = KernelBase + pSec[iSec].VirtualAddress;
             page < KernelBase + pSec[iSec].VirtualAddress + pSec[iSec].Misc.VirtualSize;
             page += PAGE_SIZE)
        {
            DWORD sizeToMap = PAGE_SIZE;

            if (page == ((KernelBase + pSec[iSec].VirtualAddress + pSec[iSec].Misc.VirtualSize) & PAGE_MASK))
            {
                sizeToMap = ALIGN_DOWN(PAGE_REMAINING(pSec[iSec].Misc.VirtualSize), gGuest.WordSize);
            }

            status = IntVirtMemMap(page, sizeToMap, gGuest.Mm.SystemCr3, 0, &mappedSecPage);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntVirtMemMap failed for 0x%016llx: 0x%08x. .data seems paged "
                        "out for 0x%016llx!\n", page, status, KernelBase);
                goto cleanup_and_exit;
            }

            for (DWORD current = 0; current < sizeToMap; current += gGuest.WordSize)
            {
                QWORD currentptr = gGuest.Guest64 ? *(QWORD *)((size_t)mappedSecPage + current) :
                    *(DWORD *)((size_t)mappedSecPage + current);

                if (currentptr == KernelBase)
                {
                    TRACE("[INFO] Found PsNtosImageBase = 0x%016llx at address 0x%016llx!\n",
                          KernelBase, page + current);
                    found = TRUE;
                    goto cleanup_and_exit;
                }
            }

            IntVirtMemUnmap(&mappedSecPage);
        }
    }

cleanup_and_exit:
    if (NULL != mappedSecPage)
    {
        IntVirtMemUnmap(&mappedSecPage);
    }

    if (NULL != pSec)
    {
        HpFreeAndNullWithTag(&pSec, IC_TAG_IMGE);
    }

    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (!found)
    {
        WARNING("[WARNING] PsNtosImageBase not found for 0x%016llx!\n", KernelBase);
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinGuestFindKernel(
    _In_ QWORD KernelGva,
    _Out_ QWORD *KernelBase
    )
///
/// @brief      Searches for the base of the Windows kernel image
///
/// This is done by using a guest virtual address that is already known to be in the kernel (like the address of the
/// syscall handler, for example) and searching backwards for a valid MZPE signature. The searched area is limited to
/// #KERNEL_SEARCH_LIMIT bytes.
///
/// @param[in]  KernelGva   A guest virtual address that is known to be inside the kernel image
/// @param[out] KernelBase  The base of the kernel image
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if the kernel base was not found
///
{
    INTSTATUS status;
    PBYTE hostPage;
    QWORD kernelBase, limit;
    BOOLEAN found;

    hostPage = NULL;
    kernelBase = KernelGva & PAGE_MASK;
    limit = 0;
    found = FALSE;

    // Take a walk from page 2 page, until we find the DOS headers or a non-present page (which we
    // assume it's the MZPE headers, since the KernelGva points inside .text)
    while (limit < KERNEL_SEARCH_LIMIT)
    {
        status = IntVirtMemMap(kernelBase, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &hostPage);
        if (!INT_SUCCESS(status))
        {
            hostPage = NULL;
            goto _next_page;
        }

        if ((hostPage[0] == 'M' && hostPage[1] == 'Z'))
        {
            status = IntWinGuestValidateKernel(kernelBase, KernelGva, hostPage);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinGuestValidateKernel failed: 0x%08x\n", status);
            }
            else
            {
                found = TRUE;
                break;
            }
        }

        IntVirtMemUnmap(&hostPage);

_next_page:
        kernelBase -= PAGE_SIZE;
        limit += PAGE_SIZE;
    }

    if (NULL != hostPage)
    {
        IntVirtMemUnmap(&hostPage);
    }

    if (!found && (limit == KERNEL_SEARCH_LIMIT))
    {
        ERROR("[ERROR] Could not find the kernel headers in the first %lldMB!\n",
              KERNEL_SEARCH_LIMIT / ONE_MEGABYTE);
        return INT_STATUS_NOT_FOUND;
    }

    *KernelBase = kernelBase;

    return INT_STATUS_SUCCESS;
}


static DWORD
IntWinGetActiveCpuCount(
    _In_ DWORD CpuCount
    )
///
/// @brief      Gets the number of active CPUs used by the guest
///
/// The number of VCPUs exposed by the hypervisor may not match the actual number of CPUs that the guest will use.
/// This can happen if someone uses the msconfig or the bcdedit utilities to change the number of cores used by the
/// OS. In that case we want to mark the unused cores as not being used (#VCPU_STATE.Initialized will be set to False).
/// Any CPU that has its Cr3 set to 0 or has the paging bit in Cr0 cleared is considered to be inactive.
///
/// @param[in]  CpuCount    The number of VCPUs reported by the integrator
///
/// @returns    The actual number of CPUs used by the guest
///
{
    DWORD activeCount = CpuCount;

    // For each CPU reported by the integrator, try to read and validate CR3.
    for (DWORD i = 0; i < CpuCount; i++)
    {
        INTSTATUS status;
        QWORD cr3, cr0;

        status = IntCr3Read(i, &cr3);
        if (!INT_SUCCESS(status))
        {
            cr3 = 0;
        }

        status = IntCr0Read(i, &cr0);
        if (!INT_SUCCESS(status))
        {
            cr0 = 0;
        }

        if (0 == cr3 || 0 == (cr0 & CR0_PG))
        {
            activeCount--;
            gGuest.VcpuArray[i].Initialized = FALSE;
        }
    }

    if (activeCount != CpuCount)
    {
        WARNING("[WARNING] The active cpu count (%d) is different than the actual cpu count (%d)\n",
                activeCount, CpuCount);
    }

    TRACE("[INTRO-INIT] Active CPU Count: %d\n", activeCount);

    return activeCount;
}


static INTSTATUS
IntWinGuestFindKernelCr3(
    _In_ QWORD Syscall
    )
///
/// @brief      Searches for the kernel Cr3
///
/// This is done by analyzing the syscall handler and looking for an instruction that loads the cr3 register with
/// a value obtained from the _KPCR (using the gs segment register for 64-bit kernels, and the fs segment register
/// for the 32-bit kernels).
/// The sequence of instructions should be:
/// @code
///     mov     reg, qword [gs:offset]/dword [fs:offset]
///     mov     cr3, reg
/// @endcode
/// The offset used to access the gs or fs segment is then used to read the kernel Cr3 value from the _KPCR.
/// The _KPCR address is obtained using #IntFindKernelPcr.
///
/// @param[in]  Syscall     The guest virtual address of the syscall handler
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if the kernel cr3 value is not found
///
{
    INTSTATUS status;
    QWORD kernelCr3OffsetPcr;
    QWORD kpcr;
    PBYTE pPage;
    BOOLEAN bFound;
    DWORD csType, mapSize;
    INSTRUX offsetInstrux;

    bFound = FALSE;
    pPage = NULL;
    csType = gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B;
    kernelCr3OffsetPcr = kpcr = 0;
    mapSize = PAGE_SIZE;

    //
    // We map 4K starting from the syscall
    //
    status = IntVirtMemMap(Syscall, mapSize, 0, 0, &pPage);
    if (!INT_SUCCESS(status))
    {
        //
        // Map the remaining of the page Syscall is in. It SHOULD contain the instructions we're looking for.
        //
        mapSize -= (Syscall & PAGE_OFFSET);
        status = IntVirtMemMap(Syscall, mapSize, 0, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to map Syscall page: 0x%08x\n", status);
            goto cleanup_and_exit;
        }
    }

    //
    // We will search for two instructions here:
    //      1. mov regx, q/dword ptr gs/fs:[KernelCr3OffsetInPcr]
    //      2. mov cr3, regx
    //
    for (DWORD i = 0; i < mapSize;)
    {
        INSTRUX instrux;

        CHAR nd[ND_MIN_BUF_SIZE] = { 0 };

        status = IntDecDecodeInstructionFromBuffer(pPage + i, mapSize - i, csType, &instrux);
        if (!INT_SUCCESS(status))
        {
            i++;
            continue;
        }

#ifdef DEBUG
        NdToText(&instrux, 0, sizeof(nd), nd);
#endif // DEBUG

        //
        // If we haven't found the mov regx, gs/fs:[KernelCr3OffsetInPcr] instr
        // or we found an instruction that uses the same register as destination
        //
        if (ND_INS_MOV == instrux.Instruction && 2 == instrux.ExpOperandsCount &&
            ND_OP_REG == instrux.Operands[0].Type &&
            ND_REG_GPR == instrux.Operands[0].Info.Register.Type)
        {
            if (!bFound ||
                (instrux.Operands[0].Info.Register.Reg == offsetInstrux.Operands[0].Info.Register.Reg))
            {
                //
                // mov regx, gs/fs:[KernelCr3OffsetInPcr] instr
                //
                if (ND_OP_MEM == instrux.Operands[1].Type && instrux.Operands[1].Info.Memory.HasSeg &&
                    instrux.Operands[1].Info.Memory.HasDisp &&
                    ((gGuest.Guest64 && NDR_GS == instrux.Operands[1].Info.Memory.Seg) ||
                     (!gGuest.Guest64 && NDR_FS == instrux.Operands[1].Info.Memory.Seg)))
                {
                    memcpy(&offsetInstrux, &instrux, sizeof(instrux));
                    bFound = TRUE;

                    TRACE("[INFO] Found a possible offset instruction: %s\n", nd);
                }
                //
                // This instruction overwrites the register that holds the gs/fs:[something]
                // so the last valid instruction we found is no longer valid
                //
                else
                {
                    memzero(&offsetInstrux, sizeof(offsetInstrux));
                    bFound = FALSE;
                }
            }
        }
        //
        // We found the first valid instruction, now we search for a mov cr3, regx
        //
        else if (bFound && ND_INS_MOV_CR == instrux.Instruction && 2 == instrux.ExpOperandsCount &&
                 ND_OP_REG == instrux.Operands[0].Type && ND_OP_REG == instrux.Operands[1].Type &&
                 ND_REG_CR == instrux.Operands[0].Info.Register.Type &&
                 NDR_CR3 == instrux.Operands[0].Info.Register.Reg &&
                 offsetInstrux.Operands[0].Info.Register.Reg == instrux.Operands[1].Info.Register.Reg)
        {
            kernelCr3OffsetPcr = offsetInstrux.Operands[1].Info.Memory.Disp;

            TRACE("[INFO] Found a valid second instruction: %s\n", nd);
            TRACE("[INFO] We will use the last possible offset instruction!\n");

            break;
        }

        i += instrux.Length;
    }

    if (0 == kernelCr3OffsetPcr)
    {
        ERROR("[ERROR] Could not find a valid instruction to get kernel cr3!");
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    TRACE("[INTRO-INIT] Found KernelDirectoryTableBase offset in PCR at %llx\n", kernelCr3OffsetPcr);

    status = IntFindKernelPcr(IG_CURRENT_VCPU, &kpcr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntFindKernelPcr failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    TRACE("[INTRO-INIT] Found PCR at 0x%016llx\n", kpcr);

    status = IntKernVirtMemRead(kpcr + kernelCr3OffsetPcr, gGuest.WordSize, &gGuest.Mm.SystemCr3, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

cleanup_and_exit:

    if (NULL != pPage)
    {
        IntVirtMemUnmap(&pPage);
    }

    return status;
}


INTSTATUS
IntWinGuestFindIdleCr3(
    void
    )
///
/// @brief      Searches the Cr3 used by the idle process
///
/// This will read the address of the idle thread from the currently loaded _KPCR and then search for the address
/// of the process that owns that thread and get the Cr3 value from that process.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_FOUND if the Cr3 was not found
///
{
    INTSTATUS status;
    QWORD pcr, idleThread, idleProcess;
    PBYTE pMap;
    DWORD mapSize;
    BOOLEAN bFound;

    pcr = idleThread = idleProcess = 0;
    bFound = FALSE;
    pMap = NULL;
    mapSize = PROCESS_SEARCH_LIMIT_THREAD_UPPER + gGuest.WordSize - PROCESS_SEARCH_LIMIT_THREAD_LOWER;

    status = IntFindKernelPcr(IG_CURRENT_VCPU, &pcr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntFindKernelPcr failed: 0x%08x\n", status);
        return status;
    }

    TRACE("[INFO] KPCR [%d] @ 0x%016llx\n", gVcpu->Index, pcr);

    // Read the idle thread
    status = IntKernVirtMemRead(pcr + IDLE_THREAD_OFFSET_PCR,
                                gGuest.WordSize,
                                &idleThread,
                                NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    TRACE("[INFO] Idle thread [%d] @ 0x%016llx\n", gVcpu->Index, idleThread);

    status = IntVirtMemMap(idleThread + PROCESS_SEARCH_LIMIT_THREAD_LOWER, mapSize, gGuest.Mm.SystemCr3, 0, &pMap);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed: 0x%08x\n", status);
        pMap = NULL;
        goto cleanup_and_exit;
    }

    // Iterate through the search limit in order to find the idle process.
    for (INT32 procOffset = PROCESS_SEARCH_LIMIT_THREAD_UPPER - PROCESS_SEARCH_LIMIT_THREAD_LOWER;
         procOffset >= 0;
         procOffset -= gGuest.WordSize)
    {
        QWORD supposedCr3 = 0;
        QWORD aux = 0;

        idleProcess = gGuest.Guest64 ? *(PQWORD)(pMap + procOffset) : *(PDWORD)(pMap + procOffset);
        idleProcess = FIX_GUEST_POINTER(gGuest.Guest64, idleProcess);

        // The idle process isn't in the process list and is inside the kernel, not dynamically allocated.
        if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, idleProcess) ||
            (idleProcess < gGuest.KernelVa) || (idleProcess > (gGuest.KernelVa + gGuest.KernelSize)))
        {
            continue;
        }

        TRACE("[INFO] Found a potentially valid idle process at offset 0x%08x -> 0x%016llx\n",
              procOffset + PROCESS_SEARCH_LIMIT_THREAD_LOWER, idleProcess);

        // The way we'll do the check is we read the supposed cr3,
        // translate it's address with it, and see if it matches.
        // THEORETICALLY, it will only work with the cr3, it shouldn't work with junk.

        status = IntKernVirtMemRead(idleProcess + CR3_OFFSET_IN_KPROCESS, gGuest.WordSize, &supposedCr3, NULL);
        if (!INT_SUCCESS(status) || (0 == supposedCr3))
        {
            continue;
        }

        status = IntVirtMemRead(idleProcess + CR3_OFFSET_IN_KPROCESS, gGuest.WordSize, supposedCr3, &aux, NULL);
        if (!INT_SUCCESS(status) || (aux != supposedCr3))
        {
            continue;
        }

        TRACE("[INFO] Found a valid idle process cr3 at offset 0x%08x @ 0x%016llx -> 0x%016llx\n",
              CR3_OFFSET_IN_KPROCESS, idleProcess + CR3_OFFSET_IN_KPROCESS, supposedCr3);

        bFound = TRUE;
        gGuest.Mm.SystemCr3 = supposedCr3;
        break;
    }

cleanup_and_exit:
    if (NULL != pMap)
    {
        IntVirtMemUnmap(&pMap);
    }

    return bFound ? INT_STATUS_SUCCESS : INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntWinGuestNew(
    void
    )
///
/// @brief      Starts the initialization and protection process for a new Windows guest
///
/// This will find the base of the kernel, initiate the #WINDOWS_GUEST.KernelBuffer read, will start to look for
/// relevant kernel objects, variables, and functions and will activate protection when every needed piece of
/// information is known.
/// The initialization depends on the value of the syscall MSR (for 64-bit guests) or the sysenter MSR (for 32-bit
/// guests) as it will point inside the kernel image and we need a valid address that points somewhere inside the
/// kernel image. Parts of the initialization may be done asynchronously.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_INITIALIZED if the sysenter or syscall MSR does not point inside the kernel space
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
///
{
    INTSTATUS status;
    DWORD activeCpuCount;

    WIN_INIT_SWAP *pSwp = NULL;
    void *swapHandle = NULL;
    QWORD msrValue = 0;
    QWORD idtValue = 0;
    QWORD kernelBase = 0;
    QWORD kernelBaseIdt = 0;
    DWORD ntBuildNumber = 0;

    // Uninitialize some things which may have been left here from the previous retry
    if (gWinGuest)
    {
        IntWinGuestCancelKernelRead();

        memzero(gWinGuest, sizeof(*gWinGuest));
    }

    gWinGuest = &gGuest._WindowsGuest;

    // Init this early because if anything fails here, we'll end up calling IntWinGuestCancelKernelRead
    // which will iterate the list, causing intro to crash if it's uninitialized.
    InitializeListHead(&gWinGuest->InitSwapHandles);

    // Initialize the #VE state. We do this here because only Windows guests are supported for #VE.
    status = IntVeInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVeInit failed: 0x%08x; will continue, but will not use #VE.\n", status);
    }
    else
    {
        TRACE("[INTRO-INIT] #VE initialized successfully!\n");
    }

    if (gGuest.Guest64)
    {
        QWORD gsBase = 0;

        status = IntGsRead(IG_CURRENT_VCPU, &gsBase);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntGsRead failed: 0x%08x\n", status);
            return status;
        }

        TRACE("[INTRO-INIT] IA32_GS_BASE_MSR = 0x%016llx \n", gsBase);
    }
    else
    {
        QWORD fsBase = 0;

        status = IntFsRead(IG_CURRENT_VCPU, &fsBase);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntFsRead failed: 0x%08x\n", status);
            return status;
        }

        TRACE("[INTRO-INIT] IA32_FS_BASE_MSR = 0x%016llx \n", fsBase);
    }

    activeCpuCount = IntWinGetActiveCpuCount(gGuest.CpuCount);

    if (gGuest.Guest64)
    {
        status = IntSyscallRead(IG_CURRENT_VCPU, NULL, &msrValue);
    }
    else
    {
        status = IntSysenterRead(IG_CURRENT_VCPU, NULL, &msrValue, NULL);
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading the syscall msr: 0x%08x\n", status);
        return status;
    }
    else if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, msrValue))
    {
        ERROR("[ERROR] SYSCALL MSR 0x%016llx is not valid!\n", msrValue);

        // We can actually try again, no need to say it's not supported
        return INT_STATUS_NOT_INITIALIZED;
    }

    TRACE("[INTRO-INIT] Found SYSCALL handler @ 0x%016llx\n", msrValue);

    status = IntCr3Read(IG_CURRENT_VCPU, &gGuest.Mm.SystemCr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
        return status;
    }

    if (gGuest.KptiActive)
    {
        // With KPTI, we might get here using any cr3 so read the one from PCR
        status = IntWinGuestFindKernelCr3(msrValue);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinGuestFindKernelCr3 failed: 0x%08x\n", status);

            IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);

            // There is no point in retrying the init, as this will always fail if it managed to fail once.
            gGuest.DisableOnReturn = TRUE;

            return status;
        }
    }

    TRACE("[INTRO-INIT] Found a valid cr3 at: 0x%016llx\n", gGuest.Mm.SystemCr3);

    // We have the IDT and cr3, now get the #PF interrupt handler
    status = IntIdtGetEntry(IG_CURRENT_VCPU, VECTOR_PF, &idtValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntIdtGetEntry failed: %08x\n", status);
        return status;
    }

    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, idtValue))
    {
        TRACE("[INTRO-INIT] Found first interrupt handler @ 0x%016llx\n", idtValue);
    }
    else
    {
        WARNING("[WARNING] First interrupt handler @ 0x%016llx is not valid\n", idtValue);
    }

    // Find the kernel. We must have a kernel base from the msr value, and that must be valid, or
    // else the agent injection won't work
    status = IntWinGuestFindKernel(msrValue, &kernelBase);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestFindKernel failed: %08X\n", status);
        kernelBase = 0;
    }
    else
    {
        LOG("[INTRO-INIT] Found the base of the ntoskrnl.exe [SYSCALL] @ VA 0x%016llx\n", kernelBase);
    }

    // Find the kernel using the first interrupt handler as well.
    if (IS_KERNEL_POINTER_WIN(gGuest.Guest64, idtValue))
    {
        status = IntWinGuestFindKernel(idtValue, &kernelBaseIdt);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinGuestFindKernel failed: 0x%08X\n", status);

            IntGuestSetIntroErrorState(intErrGuestKernelNotFound, NULL);

            gGuest.DisableOnReturn = TRUE;

            return status;
        }

        LOG("[INTRO-INIT] Found the base of the ntoskrnl.exe [IDT]     @ VA 0x%016llx\n", kernelBaseIdt);
    }

    if (kernelBaseIdt && kernelBase != kernelBaseIdt)
    {
        WARNING("[WARNING] SYSCALL & IDT handlers point in different drivers (0x%016llx vs 0x%016llx).\n",
                kernelBase, kernelBaseIdt);

        kernelBase = kernelBaseIdt;
    }

    // Find the NtBuildNumber inside the kernel
    status = IntWinGuestFindBuildNumber(kernelBase, gGuest.Guest64, gGuest.KptiInstalled, &ntBuildNumber);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestFindBuildNumber failed: 0x%08X\n", status);

        IntGuestSetIntroErrorState(intErrGuestNotSupported, NULL);

        gGuest.DisableOnReturn = TRUE;

        return status;
    }

    gGuest.ActiveCpuCount = activeCpuCount;
    gGuest.OSType = introGuestWindows;
    gGuest.KernelVa = kernelBase;

    // Set this temporarily
    gGuest.OSVersion = ntBuildNumber & 0xffff;

    // Set this temporarily until we find the real size
    gGuest.KernelSize = KERNEL_SEARCH_LIMIT;

    // We need these early, for agent injection (BP page faults)
    gWinGuest->SyscallAddress = msrValue;

    IntWinAgentInit();

    // We have a kernel cr3 and the OS version so we can query the PCR
    // and find the idle process cr3.
    // We can place hooks on this one since it SHOULDN'T terminate
    status = IntWinGuestFindIdleCr3();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestFindIdleCr3 failed: 0x%08x\n", status);

        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);

        // There is no point in retrying the init, as this will always fail if it managed to fail once.
        gGuest.DisableOnReturn = TRUE;

        return status;
    }

    TRACE("[INTRO-INIT] Found idle process CR3: 0x%016llx\n", gGuest.Mm.SystemCr3);

    // We only search for this here since we don't really need it before...
    status = IntWinGuestFindSelfMapIndex();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestFindSelfMapIndex failed: 0x%08x\n", status);

        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);

        // There is no point in retrying the init, as this will always fail if it managed to fail once.
        gGuest.DisableOnReturn = TRUE;

        return status;
    }

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        status = IntIdtFindBase(i, &gGuest.VcpuArray[i].IdtBase, &gGuest.VcpuArray[i].IdtLimit);
        if (!INT_SUCCESS(status))
        {
            gGuest.VcpuArray[i].IdtBase = 0;
            gGuest.VcpuArray[i].IdtLimit = 0;
        }
    }

    status = IntWinGuestInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinGuestInit failed: 0x%08x\n", status);
        return status;
    }

    // We are done here, now read the headers and go forward
    pSwp = HpAllocWithTag(sizeof(*pSwp), IC_TAG_WSWP);
    if (NULL == pSwp)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pSwp->VirtualAddress = kernelBase;
    pSwp->Size = PAGE_SIZE;

    InsertTailList(&gWinGuest->InitSwapHandles, &pSwp->Link);

    status = IntSwapMemReadData(0,
                                kernelBase,
                                PAGE_SIZE,
                                SWAPMEM_OPT_BP_FAULT,
                                pSwp,
                                0,
                                IntWinGuestKernelHeadersInMemory,
                                NULL,
                                &swapHandle);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading the kernel headers: 0x%08x\n", status);
        return status;
    }

    // The callback will be called async, save the handle in case an uninit will come
    if (NULL != swapHandle)
    {
        pSwp->SwapHandle = swapHandle;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinGetVersionString(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR *FullString,
    _Out_ CHAR *VersionString
    )
///
/// @brief      Gets the version string for a Windows guest
///
/// @param[in]  FullStringSize      The size of the FullString buffer
/// @param[in]  VersionStringSize   The size of the VersionString buffer
/// @param[out] FullString          A NULL-terminated string containing detailed version information
/// @param[out] VersionString       A NULL-terminated string containing human-readable version information
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_NOT_READY if the information is not yet available
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL if any of the buffers is not large enough
///
{
    int count;

    if (NULL == gWinGuest->NtBuildLabString)
    {
        return INT_STATUS_NOT_READY;
    }

    if (NULL == gWinGuest->VersionString)
    {
        return INT_STATUS_NOT_READY;
    }

    if (NULL == gWinGuest->ServerVersionString)
    {
        return INT_STATUS_NOT_READY;
    }

    if (winProductTypeNotYetLoaded == gWinGuest->ProductType)
    {
        return INT_STATUS_NOT_READY;
    }

    if (strlen(gWinGuest->NtBuildLabString) >= FullStringSize)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    strcpy(FullString, gWinGuest->NtBuildLabString);

    if (gWinGuest->ProductType == winProductTypeServer && strlen(gWinGuest->ServerVersionString) != 0)
    {
        count = snprintf(VersionString, VersionStringSize, "%s %s", gWinGuest->ServerVersionString,
                         strcasestr(FullString, "lts") ? "ltsb" : "");
    }
    else
    {
        const char *appendix = gWinGuest->ProductType == winProductTypeUnknown ? "(could not determine if server)" :
                               gWinGuest->ProductType == winProductTypeServer ? "(possible server)" : "";

        count = snprintf(VersionString, VersionStringSize, "%s %s %s", gWinGuest->VersionString,
                         strcasestr(FullString, "lts") ? "ltsb" : "", appendix);
    }

    if (count < 0)
    {
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    if ((DWORD)count >= VersionStringSize)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    return INT_STATUS_SUCCESS;
}
