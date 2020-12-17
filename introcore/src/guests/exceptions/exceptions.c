/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       exceptions.c
/// @ingroup    group_exceptions
///

#include "exceptions.h"
#include "codeblocks.h"
#include "crc32.h"
#include "decoder.h"
#include "hook.h"
#include "winpe.h"
#include "winthread.h"
#include "lixmm.h"
#include "serializers.h"

/// @brief  Cache of RIPs from which code blocks were already dumped.
///
/// Used by #IntExceptDumpSignatures in order to avoid dumping the same code blocks multiple times.
static QWORD gUsedRips[255] = {0};

extern INT_VERSION_INFO IntHviVersion;

/// @brief  Pre-allocated buffer used to match value signatures.
///
/// Used by #IntExceptVerifyValueSig to hold the injected memory contents. This avoids allocating and freeing a
/// temporary buffer each time an #EVENT_MEMCOPY_VIOLATION event is analyzed.
///
/// Allocated in #IntExceptInit and freed in #IntExceptUninit. May be reallocated by #IntExceptVerifyValueSig if
/// needed.
static BYTE *gValueBuffer = NULL;

/// @brief  The size, in bytes, of the #gValueBuffer buffer.
static DWORD gValueBufferSize = 2 * PAGE_SIZE;

/// @brief  The exception log line.
char gExcLogLine[2 * ONE_KILOBYTE];

///
/// @brief Describes a code-blocks cache entry.
///
typedef struct _CB_CACHE
{
    QWORD Rip;                                      ///< The RIP from which the write came from.
    DWORD Count;                                    ///< The number of the code-blocks.
    DWORD CsType;                                   ///< The CS type.
    QWORD Cr3;                                      ///< The CR3 of the process from which the write came from.
    DWORD CodeBlocks[PAGE_SIZE / sizeof(DWORD)];    ///< The code-blocks array.

    QWORD EventId;                                  ///< The current event ID.

} CB_CACHE, *PCB_CACHE;

/// @brief  Cache for code blocks extracted from an originator.
///
/// Used by #IntExceptVerifyCodeBlocksSig. Invalidated every time a new #IntExcept pass is started (if the victim GVA
/// is in the same page as #CB_CACHE.Rip), or when a process is terminated (if the process Cr3 is the same as
/// #CB_CACHE.Cr3).
static CB_CACHE gCodeBlocksOriginalCache = { 0 };
/// @brief  Cache for code blocks extracted from a return originator.
///
/// Used by #IntExceptVerifyCodeBlocksSig. Invalidated every time a new #IntExcept pass is started (if the victim GVA
/// is in the same page as #CB_CACHE.Rip), or when a process is terminated (if the process Cr3 is the same as
/// #CB_CACHE.Cr3).
static CB_CACHE gCodeBlocksReturnCache = {0};

/// @brief  Indicated that the #gCodeBlocksReturnCache cache should be used.
#define CB_CACHE_FLG_RETURN     0x1
/// @brief  Indicates that the #gCodeBlocksOriginalCache should be used.
#define CB_CACHE_FLG_ORIGINAL   0x2


void
IntExceptInvCbCacheByGva(
    _In_ QWORD Gva
    )
///
/// @brief Invalidate the cache used for code blocks for a given guest virtual address.
///
/// The cache must be invalided if a process is terminating or for each exception regardless of the
/// action (because the integrator can over-rule our action).
///
/// @param[in] Gva  The guest virtual address for witch the cache must be invalidated.
///
{
    if (IN_RANGE_LEN(gCodeBlocksOriginalCache.Rip, Gva & PAGE_MASK, PAGE_SIZE))
    {
        memzero(&gCodeBlocksOriginalCache, sizeof(gCodeBlocksOriginalCache));
    }

    if (IN_RANGE_LEN(gCodeBlocksReturnCache.Rip, Gva & PAGE_MASK, PAGE_SIZE))
    {
        memzero(&gCodeBlocksReturnCache, sizeof(gCodeBlocksReturnCache));
    }
}


void
IntExceptInvCbCacheByCr3(
    _In_ QWORD Cr3
    )
///
/// @brief Invalidate the cache used for code blocks for a given CR3.
///
/// The cache must be invalidated if a process is terminating or for each exception regardless of the
/// action (because the integrator can over-rule our action).
///
/// param[in] Cr3   The CR3 for witch the cache must be invalidated.
///
{
    if (gCodeBlocksOriginalCache.Cr3 == Cr3)
    {
        memzero(&gCodeBlocksOriginalCache, sizeof(gCodeBlocksOriginalCache));
    }

    if (gCodeBlocksReturnCache.Cr3 == Cr3)
    {
        memzero(&gCodeBlocksReturnCache, sizeof(gCodeBlocksReturnCache));
    }
}


__nonnull() static DWORD
IntExceptExtendedPatternMatch(
    _In_ const BYTE *Buffer,
    _In_ DWORD Length,
    _In_ const SIG_VALUE_CODE *Sig,
    _In_ DWORD IndexPattern
    )
///
/// @brief Try to match the given buffer with the given signature.
///
/// @param[in] Buffer        The buffer that will be compared with the signature pattern.
/// @param[in] Length        The length of the buffer.
/// @param[in] Sig           The signature that will be compared with the given buffer.
/// @param[in] IndexPattern  The start position from the signature pattern.
///
/// @retval #SIG_NOT_FOUND   If the content of the buffer don't match the content of the signature pattern.
/// @retval #SIG_FOUND       If the content of the buffer matches the content of the signature pattern.
///
{
    DWORD ret = SIG_NOT_FOUND;
    BOOLEAN matched = TRUE;

    if (IndexPattern + Length > Sig->Length)
    {
        return SIG_NOT_FOUND;
    }

    for (DWORD i = 0; i < Length; i++)
    {
        if (Sig->Object[i + IndexPattern] != 0x100 &&
            Sig->Object[i + IndexPattern] != Buffer[i])
        {
            matched = FALSE;
            break;
        }
    }

    if (matched)
    {
        ret = SIG_FOUND;
    }

    return ret;
}


static void
IntExceptRemoveKmListExceptions(
    _In_ LIST_HEAD *ListHead
    )
///
/// @brief This function removes and frees all entries from a kernel-mode exceptions list.
///
/// @param[in] ListHead  A pointer to a kernel-mode exceptions list.
///
{
    LIST_ENTRY *list = ListHead->Flink;
    while (list != ListHead)
    {
        KM_EXCEPTION *pException = CONTAINING_RECORD(list, KM_EXCEPTION, Link);
        list = list->Flink;

        IntExceptErase(pException, IC_TAG_EXKM);
    }
}


static void
IntExceptRemoveKernelUserListExceptions(
    _In_ LIST_HEAD *ListHead
    )
///
/// @brief This function removes and frees all entries from a kernel-user mode exceptions list.
///
/// @param[in] ListHead  A pointer to a kernel-user mode exceptions list.
///
{
    LIST_ENTRY *list = ListHead->Flink;
    while (list != ListHead)
    {
        KUM_EXCEPTION *pException = CONTAINING_RECORD(list, KUM_EXCEPTION, Link);
        list = list->Flink;

        IntExceptErase(pException, IC_TAG_EXKU);
    }
}


static void
IntExceptRemoveUmListExceptions(
    _In_ LIST_HEAD *ListHead
    )
///
/// @brief This function removes and frees all entries from a user-mode exceptions list.
///
/// @param[in] ListHead  A pointer to a user-mode exceptions list.
///
{
    LIST_ENTRY *list = ListHead->Flink;
    while (list != ListHead)
    {
        UM_EXCEPTION *pException = CONTAINING_RECORD(list, UM_EXCEPTION, Link);
        list = list->Flink;

        IntExceptErase(pException, IC_TAG_EXUM);
    }
}


static void
IntExceptRemoveUmGlobListExceptions(
    _In_ LIST_HEAD *ListHead
    )
///
/// @brief This function removes and frees all entries from a user-mode glob exceptions list.
///
/// @param[in] ListHead  A pointer to a user-mode glob exceptions list.
///
{
    LIST_ENTRY *list = ListHead->Flink;
    while (list != ListHead)
    {
        UM_EXCEPTION_GLOB *pException = CONTAINING_RECORD(list, UM_EXCEPTION_GLOB, Link);
        list = list->Flink;

        IntExceptErase(pException, IC_TAG_EXUM);
    }
}


INTSTATUS
IntExceptRemove(
    void
    )
///
/// @brief This function removes and frees all exceptions and signatures that have been added from exception
/// binary file.
///
/// The exceptions that have been added from alerts are not removed or freed.
///
/// @retval #INT_STATUS_SUCCESS          On success.
/// @retval #INT_STATUS_NOT_INITIALIZED  If the exceptions data is not initialized.
///
{
    if (!gGuest.Exceptions)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    IntExceptRemoveKmListExceptions(&gGuest.Exceptions->GenericKernelExceptions);
    IntExceptRemoveKmListExceptions(&gGuest.Exceptions->NoNameKernelExceptions);

    for (DWORD i = 0; i < EXCEPTION_TABLE_SIZE; i++)
    {
        IntExceptRemoveKmListExceptions(&gGuest.Exceptions->KernelExceptions[i]);
    }

    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->GenericUserExceptions);
    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->NoNameUserExceptions);
    IntExceptRemoveUmGlobListExceptions(&gGuest.Exceptions->GlobUserExceptions);

    for (DWORD i = 0; i < EXCEPTION_TABLE_SIZE; i++)
    {
        IntExceptRemoveUmListExceptions(&gGuest.Exceptions->UserExceptions[i]);
    }

    IntExceptRemoveKernelUserListExceptions(&gGuest.Exceptions->GenericKernelUserExceptions);
    IntExceptRemoveKernelUserListExceptions(&gGuest.Exceptions->NoNameKernelUserExceptions);

    for (DWORD i = 0; i < EXCEPTION_TABLE_SIZE; i++)
    {
        IntExceptRemoveKernelUserListExceptions(&gGuest.Exceptions->KernelUserExceptions[i]);
    }

    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->UserFeedbackExceptions);
    IntExceptRemoveKmListExceptions(&gGuest.Exceptions->KernelFeedbackExceptions);
    IntExceptRemoveKernelUserListExceptions(&gGuest.Exceptions->KernelUserFeedbackExceptions);
    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->ProcessCreationFeedbackExceptions);

    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->ProcessCreationExceptions);

    for_each_cb_signature(gGuest.Exceptions->CbSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_export_signature(gGuest.Exceptions->ExportSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_value_signature(gGuest.Exceptions->ValueSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_value_code_signature(gGuest.Exceptions->ValueCodeSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_idt_signature(gGuest.Exceptions->IdtSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_version_os_signature(gGuest.Exceptions->VersionOsSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_version_intro_signature(gGuest.Exceptions->VersionIntroSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_process_creation_signature(gGuest.Exceptions->ProcessCreationSignatures, pSignature)
    {
        if (!pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    gGuest.Exceptions->Version.Build = 0;
    gGuest.Exceptions->Version.Minor = 0;
    gGuest.Exceptions->Version.Major = 0;

    gGuest.Exceptions->Loaded = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptAlertRemove(
    void
    )
///
/// @brief This function removes and frees all exceptions and signatures that have been added from alert.
///
/// The exceptions that have been added from binary file are not removed or freed.
///
/// @retval #INT_STATUS_SUCCESS          On success.
/// @retval #INT_STATUS_NOT_INITIALIZED  If the exceptions data is not initialized.
///
{
    if (!gGuest.Exceptions)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->UserAlertExceptions);
    IntExceptRemoveKmListExceptions(&gGuest.Exceptions->KernelAlertExceptions);
    IntExceptRemoveKernelUserListExceptions(&gGuest.Exceptions->KernelUserAlertExceptions);
    IntExceptRemoveUmListExceptions(&gGuest.Exceptions->ProcessCreationAlertExceptions);

    for_each_cb_signature(gGuest.Exceptions->CbSignatures, pSignature)
    {
        if (pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_export_signature(gGuest.Exceptions->ExportSignatures, pSignature)
    {
        if (pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_idt_signature(gGuest.Exceptions->IdtSignatures, pSignature)
    {
        if (pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    for_each_process_creation_signature(gGuest.Exceptions->ProcessCreationSignatures, pSignature)
    {
        if (pSignature->AlertSignature)
        {
            IntExceptErase(pSignature, IC_TAG_ESIG);
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptInit(
    void
    )
///
/// @brief This function allocates the exceptions data and initialize the exception lists and the signature lists.
///
/// This function also allocates a buffer used by the #SIG_VALUE signatures.
///
/// @retval #INT_STATUS_SUCCESS                  On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES   If not enough memory is available.
///
{
    EXCEPTIONS *pExceptions = HpAllocWithTag(sizeof(*pExceptions), IC_TAG_EXCP);
    if (!pExceptions)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    gValueBuffer = HpAllocWithTag(gValueBufferSize, IC_TAG_EXCP);
    if (!gValueBuffer)
    {
        HpFreeAndNullWithTag(&pExceptions, IC_TAG_EXCP);
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeListHead(&pExceptions->GenericKernelExceptions);
    InitializeListHead(&pExceptions->GenericKernelUserExceptions);
    InitializeListHead(&pExceptions->GenericUserExceptions);

    InitializeListHead(&pExceptions->NoNameKernelExceptions);
    InitializeListHead(&pExceptions->NoNameKernelUserExceptions);
    InitializeListHead(&pExceptions->NoNameUserExceptions);

    InitializeListHead(&pExceptions->GlobUserExceptions);

    for (DWORD i = 0; i < EXCEPTION_TABLE_SIZE; i++)
    {
        InitializeListHead(&pExceptions->KernelExceptions[i]);
        InitializeListHead(&pExceptions->UserExceptions[i]);
        InitializeListHead(&pExceptions->KernelUserExceptions[i]);
    }

    InitializeListHead(&pExceptions->UserFeedbackExceptions);
    InitializeListHead(&pExceptions->KernelFeedbackExceptions);
    InitializeListHead(&pExceptions->KernelUserFeedbackExceptions);
    InitializeListHead(&pExceptions->ProcessCreationFeedbackExceptions);

    InitializeListHead(&pExceptions->ProcessCreationExceptions);
    InitializeListHead(&pExceptions->ProcessCreationAlertExceptions);

    InitializeListHead(&pExceptions->UserAlertExceptions);
    InitializeListHead(&pExceptions->KernelAlertExceptions);
    InitializeListHead(&pExceptions->KernelUserAlertExceptions);

    InitializeListHead(&pExceptions->CbSignatures);
    InitializeListHead(&pExceptions->ExportSignatures);
    InitializeListHead(&pExceptions->ValueSignatures);
    InitializeListHead(&pExceptions->ValueCodeSignatures);
    InitializeListHead(&pExceptions->IdtSignatures);
    InitializeListHead(&pExceptions->VersionOsSignatures);
    InitializeListHead(&pExceptions->VersionIntroSignatures);
    InitializeListHead(&pExceptions->ProcessCreationSignatures);

    pExceptions->Loaded = FALSE;

    gGuest.Exceptions = pExceptions;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptUninit(
    void
    )
///
/// @brief This function removes and frees all exceptions and signatures.
///
/// This function also frees the exception data and the buffer used by the #SIG_VALUE signature. The code blocks
/// cache is invalidated and the buffer used for logged RIP is cleaned.
///
/// @retval #INT_STATUS_SUCCESS                  On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT     If the exceptions data is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (!gGuest.Exceptions)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    status = IntExceptRemove();
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    status = IntExceptAlertRemove();
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    HpFreeAndNullWithTag(&gGuest.Exceptions, IC_TAG_EXCP);

    if (gValueBuffer)
    {
        HpFreeAndNullWithTag(&gValueBuffer, IC_TAG_EXCP);
    }

    memzero(&gCodeBlocksOriginalCache, sizeof(gCodeBlocksOriginalCache));
    memzero(&gCodeBlocksReturnCache, sizeof(gCodeBlocksReturnCache));

    memzero(gUsedRips, sizeof(gUsedRips));

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntExceptWinGetVictimDriver(
    _In_ KERNEL_DRIVER *Driver,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief This function get the information from #KERNEL_DRIVER and fill the information required
/// by #EXCEPTION_VICTIM_ZONE.
///
/// This function assume that the #KERNEL_DRIVER refers a windows driver and must be used only for windows guests.
///
/// @param[in] Driver   The driver that have been modified.
/// @param[out] Victim  The victim structure used by the exceptions mechanism.
///
/// @retval #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    IMAGE_DATA_DIRECTORY dir = {0};
    IMAGE_SECTION_HEADER section;

    Victim->Object.BaseAddress = Driver->BaseVa;
    Victim->ProtectionFlag = Driver->ProtectionFlag;

    if (Driver->BaseVa == gGuest.KernelVa)
    {
        Victim->Object.NameHash = kmExcNameKernel;
    }
    else if (0 == wstrcasecmp(Driver->Name, u"hal.dll") ||
             0 == wstrcasecmp(Driver->Name, u"halmacpi.dll") ||
             0 == wstrcasecmp(Driver->Name, u"halacpi.dll"))
    {
        Victim->Object.NameHash = kmExcNameHal;
    }
    else
    {
        // NOTE: Keep the name hash here (we don't except based on path!)
        Victim->Object.NameHash = Driver->NameHash;
    }

    status = IntPeGetSectionHeaderByRva(Driver->BaseVa,
                                        Driver->Win.MzPeHeaders,
                                        (DWORD)(Victim->Ept.Gva - Driver->BaseVa),
                                        &section);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the section header of the write address 0x%016llx in module 0x%016llx: 0x%08x\n",
              Victim->Ept.Gva, Driver->BaseVa, status);
        TRACE("[EXCEPTIONS] Will continue to check exceptions anyway...\n");
    }
    else
    {
        memcpy(Victim->Object.Module.SectionName, section.Name, 8);

        if ((section.Characteristics & IMAGE_SCN_CNT_CODE) ||
            (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        {
            Victim->ZoneFlags |= ZONE_LIB_CODE;
        }
        else
        {
            Victim->ZoneFlags |= ZONE_LIB_DATA;
        }
    }

    // NOTE: If more types are added, be careful where you put the code. When parsing directories, we exit at
    // the first one found. Hopefully a zone can't be both in the resources section & imports, or in both
    // imports & exports, etc.

    status = IntPeGetDirectory(Driver->BaseVa, Driver->Win.MzPeHeaders, IMAGE_DIRECTORY_ENTRY_IAT, &dir);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] Failed getting IAT from driver 0x%016llx: 0x%08x\n", Driver->BaseVa, status);
    }
    else if (status != INT_STATUS_NOT_FOUND)
    {
        if (Victim->Ept.Gva >= Driver->BaseVa + dir.VirtualAddress &&
            Victim->Ept.Gva < Driver->BaseVa + dir.VirtualAddress + dir.Size)
        {
            Victim->ZoneFlags |= ZONE_LIB_IMPORTS;
            return INT_STATUS_SUCCESS;
        }
    }

    status = IntPeGetDirectory(Driver->BaseVa, Driver->Win.MzPeHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT, &dir);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] Failed getting EAT from driver 0x%016llx: 0x%08x\n", Driver->BaseVa, status);
    }
    else if (status != INT_STATUS_NOT_FOUND)
    {
        if (Victim->Ept.Gva >= Driver->BaseVa + dir.VirtualAddress &&
            Victim->Ept.Gva < Driver->BaseVa + dir.VirtualAddress + dir.Size)
        {
            Victim->ZoneFlags |= ZONE_LIB_EXPORTS;
            return INT_STATUS_SUCCESS;
        }
    }

    status = IntPeGetDirectory(Driver->BaseVa, Driver->Win.MzPeHeaders, IMAGE_DIRECTORY_ENTRY_RESOURCE, &dir);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] Failed getting imports from driver 0x%016llx: 0x%08x\n", Driver->BaseVa, status);
    }
    else if (status != INT_STATUS_NOT_FOUND)
    {
        if (Victim->Ept.Gva >= Driver->BaseVa + dir.VirtualAddress &&
            Victim->Ept.Gva < Driver->BaseVa + dir.VirtualAddress + dir.Size)
        {
            Victim->ZoneFlags |= ZONE_LIB_RESOURCES;
            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntExceptLixGetVictimDriver(
    _In_ KERNEL_DRIVER *Driver,
    _Inout_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief Fills an #EXCEPTION_VICTIM_ZONE with the relevant information from a #KERNEL_DRIVER.
///
/// This function assume that the #KERNEL_DRIVER refers a Linux module and must be used only for Linux guests.
///
/// @param[in] Driver   The driver that have been modified.
/// @param[out] Victim  The victim structure used by the exceptions mechanism.
///
/// @retval #INT_STATUS_SUCCESS  On success.
///
{
    QWORD gva = Victim->Ept.Gva;

    Victim->Object.BaseAddress = Driver->BaseVa;
    Victim->ProtectionFlag = Driver->ProtectionFlag;

    if (Victim->Object.BaseAddress == gGuest.KernelVa)
    {
        Victim->Object.NameHash = kmExcNameKernel;
    }
    else
    {
        // Important: Keep the name hash here (we don't except based on path!)
        Victim->Object.NameHash = Driver->NameHash;
    }

    if (IN_RANGE_LEN(gva, Driver->Lix.CoreLayout.Base, Driver->Lix.CoreLayout.TextSize))
    {
        memcpy(Victim->Object.Module.SectionName, "text", sizeof("text"));
        Victim->ZoneFlags |= ZONE_LIB_CODE;
    }
    else if (IN_RANGE(gva,
                      Driver->Lix.CoreLayout.Base + Driver->Lix.CoreLayout.TextSize,
                      Driver->Lix.CoreLayout.Base + Driver->Lix.CoreLayout.RoSize))
    {
        memcpy(Victim->Object.Module.SectionName, "text_ro", sizeof("text_ro"));
        Victim->ZoneFlags |= ZONE_LIB_DATA;
    }
    else if (!Driver->Lix.Initialized &&
             IN_RANGE_LEN(gva, Driver->Lix.InitLayout.Base, Driver->Lix.InitLayout.TextSize))
    {
        memcpy(Victim->Object.Module.SectionName, "init", sizeof("init"));
        Victim->ZoneFlags |= ZONE_LIB_CODE;
    }
    else if (!Driver->Lix.Initialized &&
             IN_RANGE(gva,
                      Driver->Lix.InitLayout.Base + Driver->Lix.InitLayout.TextSize,
                      Driver->Lix.InitLayout.Base + Driver->Lix.InitLayout.RoSize))
    {
        memcpy(Victim->Object.Module.SectionName, "init_ro", sizeof("init_ro"));
        Victim->ZoneFlags |= ZONE_LIB_DATA;
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntExceptGetVictimEpt(
    _In_opt_ void *Context,
    _In_ QWORD Gpa,
    _In_ QWORD Gva,
    _In_ INTRO_OBJECT_TYPE Type,
    _In_ DWORD ZoneFlags,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    )
///
/// @brief Fills an #EXCEPTION_VICTIM_ZONE with relevant information from an EPT violation.
///
/// This function can be called from both user-mode and kernel-mode objects.
///
/// The type of the Context parameter changes based on the Type value:
///
/// ------------------------------------------------------------------------------
/// | Type value                        | Context type                           |
/// |-----------------------------------|----------------------------------------|
/// | #introObjectTypeSsdt              | #WIN_KERNEL_DRIVER                     |
/// | #introObjectTypeKmModule          | #KERNEL_DRIVER                         |
/// | #introObjectTypeUmModule          | #WIN_PROCESS_MODULE                    |
/// | #introObjectTypeUmGenericNxZone   | #WIN_PROCESS_OBJECT for Windows guests |
/// | #introObjectTypeUmGenericNxZone   | #LIX_TASK_OBJECT for Linux guests      |
/// | #introObjectTypeDriverObject      | #WIN_DRIVER_OBJECT                     |
/// | #introObjectTypeFastIoDispatch    | #WIN_DRIVER_OBJECT                     |
/// | #introObjectTypeHalIntController  | #WIN_KERNEL_DRIVER                     |
/// | #introObjectTypeHalHeap           | not used                               |
/// | #introObjectTypeVeAgent           | #KERNEL_DRIVER                         |
/// | #introObjectTypeVdso              | not used                               |
/// | #introObjectTypeVsyscall          | not used                               |
/// | #introObjectTypeIdt               | not used                               |
/// | #introObjectTypeSelfMapEntry      | #WIN_PROCESS_OBJECT                    |
/// | #introObjectTypeKmLoggerContext   | not used                               |
/// | #introObjectTypeTokenPrivs        | #WIN_PROCESS_OBJECT                    |
/// | #introObjectTypeSudExec           | #WIN_PROCESS_OBJECT if user-mode exec. |
/// ------------------------------------------------------------------------------
///
/// @param[in]  Context     A pointer to a context that depends on the Type value (see the table from above).
/// @param[in]  Gpa         The guest physically address where the read/write/exec violation occurred.
/// @param[in]  Gva         The guest virtual address where the read/write/exec violation occurred.
/// @param[in]  Type        The type of the modified object (#INTRO_OBJECT_TYPE).
/// @param[in]  ZoneFlags   The flags of the modified zone.
/// @param[out] Victim      The victim structure used by the exceptions mechanism.
///
/// @retval #INT_STATUS_SUCCESS              On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_5  If the zone flags are invalid.
/// @retval #INT_STATUS_INVALID_PARAMETER_6  If the pointer to the victim structure is invalid.
/// @retval #INT_STATUS_NOT_SUPPORTED        If the object type is invalid.
///
{
    INTSTATUS status;
    OPERAND_VALUE operandValue = { 0 };

    if (ZoneFlags == 0)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (Victim == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    Victim->Ept.Gva = Gva;
    Victim->Ept.Gpa = Gpa;
    Victim->ZoneType = exceptionZoneEpt;
    Victim->ZoneFlags = ZoneFlags;

    // See if this a SSDT write or a SSDT relocation (first field in KeServiceDescriptorTable),
    // but only on 32 bit systems
    if (!gGuest.Guest64 &&
        gGuest.OSType == introGuestWindows &&
        ((Victim->Ept.Gva >= gWinGuest->Ssdt &&
          Victim->Ept.Gva < gWinGuest->Ssdt + gWinGuest->NumberOfServices * 4ull) ||
         (Victim->Ept.Gva == gWinGuest->KeServiceDescriptorTable)))
    {
        Victim->Object.Type = introObjectTypeSsdt;
    }
    else
    {
        Victim->Object.Type = Type;
    }

    switch (Victim->Object.Type)
    {
    case introObjectTypeSsdt:
        if (gGuest.OSType != introGuestWindows)
        {
            ERROR("[ERROR] Writes of type %d are not supported on guests %d\n",
                  Victim->Object.Type, gGuest.OSType);
            return INT_STATUS_NOT_SUPPORTED;
        }

        Victim->ProtectionFlag = INTRO_OPT_PROT_KM_NT;
        Victim->Object.Module.Module = Context;

        // We are on Windows since we verified before
        IntExceptWinGetVictimDriver(Context, Victim);

        break;

    case introObjectTypeVeAgent:
    case introObjectTypeKmModule:
        Victim->Object.Module.Module = Context;

        if (gGuest.OSType == introGuestWindows)
        {
            IntExceptWinGetVictimDriver(Context, Victim);
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            IntExceptLixGetVictimDriver(Context, Victim);
        }

        break;

    case introObjectTypeFastIoDispatch:
        if (gGuest.OSType != introGuestWindows)
        {
            ERROR("[ERROR] Writes of type %d are not supported on guests %d\n",
                  Victim->Object.Type, gGuest.OSType);
            return INT_STATUS_NOT_SUPPORTED;
        }

        Victim->Object.DriverObject = Context;
        Victim->Object.BaseAddress = ((PWIN_DRIVER_OBJECT)Context)->DriverObjectGva;
        Victim->Object.NameHash = ((PWIN_DRIVER_OBJECT)Context)->NameHash;
        break;

    case introObjectTypeDriverObject:
        if (gGuest.OSType != introGuestWindows)
        {
            ERROR("[ERROR] Writes of type %d are not supported on guests %d\n",
                  Victim->Object.Type, gGuest.OSType);
            return INT_STATUS_NOT_SUPPORTED;
        }

        Victim->Object.DriverObject = Context;
        Victim->Object.BaseAddress = ((WIN_DRIVER_OBJECT *)Context)->DriverObjectGva;
        Victim->Object.NameHash = ((WIN_DRIVER_OBJECT *)Context)->NameHash;

        break;

    case introObjectTypeUmModule:
    {
        WIN_PROCESS_MODULE *pModule = Context;
        IMAGE_SECTION_HEADER section;

        if (gGuest.OSType != introGuestWindows)
        {
            ERROR("[ERROR] Writes of type %d are not supported on guests %d\n",
                  Victim->Object.Type, gGuest.OSType);
            return INT_STATUS_NOT_SUPPORTED;
        }

        Victim->Object.BaseAddress = pModule->VirtualBase;
        Victim->Object.Library.Module = Context;
        Victim->Object.WinProc = pModule->Subsystem->Process;

        if (pModule->Cache && (pModule->Cache->Info.IatRva != 0) && (pModule->Cache->Info.IatSize != 0) &&
            (Gva - pModule->VirtualBase >= pModule->Cache->Info.IatRva) &&
            (Gva - pModule->VirtualBase < (QWORD)pModule->Cache->Info.IatRva + pModule->Cache->Info.IatSize))
        {
            Victim->ZoneFlags |= ZONE_LIB_IMPORTS;
        }

        if (pModule->Cache && (pModule->Cache->Info.EatRva != 0) && (pModule->Cache->Info.EatSize != 0) &&
            (Gva - pModule->VirtualBase >= pModule->Cache->Info.EatRva) &&
            (Gva - pModule->VirtualBase < (QWORD)pModule->Cache->Info.EatRva + pModule->Cache->Info.EatSize))
        {
            Victim->ZoneFlags |= ZONE_LIB_EXPORTS;
        }

        if (pModule->Cache && pModule->Cache->Headers)
        {
            status = IntPeGetSectionHeaderByRva(pModule->VirtualBase, pModule->Cache->Headers,
                                                (DWORD)(Victim->Ept.Gva - pModule->VirtualBase), &section);
            if (INT_SUCCESS(status))
            {
                memcpy(Victim->Object.Library.SectionName, section.Name, 8);

                if ((section.Characteristics & IMAGE_SCN_CNT_CODE) ||
                    (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
                {
                    Victim->ZoneFlags |= ZONE_LIB_CODE;
                }
                else
                {
                    Victim->ZoneFlags |= ZONE_LIB_DATA;
                }
            }
        }

        Victim->Object.NameHash = pModule->Path->NameHash;
        Victim->Object.NameWide = pModule->Path->Name; // Module names are saved as WCHAR

        break;
    }

    case introObjectTypeHalIntController:
    {
        Victim->Object.BaseAddress = Victim->Ept.Gva; // actual written address
        Victim->Object.NameHash = kmExcNameHal;

        break;
    }

    case introObjectTypeHalHeap:
    {
        Victim->Object.NameHash = kmExcNameHal;

        break;
    }

    case introObjectTypeSudExec:
    {
        Victim->Object.BaseAddress = Gva & PAGE_MASK;

        if (NULL == Context)
        {
            break;
        }

        if (gGuest.OSType == introGuestWindows)
        {
            WIN_PROCESS_OBJECT *pProc = (WIN_PROCESS_OBJECT *)Context;

            Victim->Object.NameHash = pProc->NameHash;
            Victim->Object.Name = pProc->Name;

            Victim->Object.Process = pProc;
        }

        break;
    }

    case introObjectTypeUmGenericNxZone:
    {
        Victim->Object.BaseAddress = Gva & PAGE_MASK;

        if (gGuest.OSType == introGuestWindows)
        {
            WIN_PROCESS_OBJECT *pProc = (WIN_PROCESS_OBJECT *)Context;
            QWORD tibBase = 0;

            Victim->ExecInfo.StackBase = 0;
            Victim->ExecInfo.StackLimit = 0;
            Victim->ExecInfo.Rsp = gVcpu->Regs.Rsp;
            Victim->ExecInfo.Length = gVcpu->Instruction.Length;

            status = IntWinThrGetCurrentStackBaseAndLimit(&tibBase, &Victim->ExecInfo.StackBase,
                                                          &Victim->ExecInfo.StackLimit);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntWinThrGetCurrentStackBaseAndLimit failed with status: 0x%08x\n", status);
            }

            Victim->Object.NameHash = pProc->NameHash;
            Victim->Object.Name = pProc->Name;

            Victim->Object.Process = pProc;
        }
        else
        {
            LIX_TASK_OBJECT *pTask = (LIX_TASK_OBJECT *)Context;
            LIX_VMA *pVma = IntLixMmFindVmaByRange(pTask, gVcpu->Regs.Rip);
            if (pVma == NULL)
            {
                Victim->ExecInfo.StackBase = 0;
                Victim->ExecInfo.StackLimit = 0;

                WARNING("[WARNING] IntLixMmFindVmaByRange failed for GVA 0x%016llx\n", gVcpu->Regs.Rip);
            }
            else
            {
                Victim->ExecInfo.StackBase = pVma->Start;
                Victim->ExecInfo.StackLimit = pVma->End;
            }

            Victim->ExecInfo.Rsp = gVcpu->Regs.Rsp;
            Victim->ExecInfo.Length = gVcpu->Instruction.Length;

            Victim->Object.NameHash = pTask->CommHash;

            if (pTask->Path)
            {
                Victim->Object.Name = pTask->Path->Name;
            }
            else
            {
                Victim->Object.Name = pTask->Comm;
            }

            Victim->Object.Process = pTask;
        }

        break;
    }

    case introObjectTypeVdso:
    case introObjectTypeVsyscall:
    {
        if (!IS_KERNEL_POINTER_LIX(Gva))
        {
            Victim->Object.LixProc = IntLixTaskGetCurrent(gVcpu->Index);
        }

        Victim->ZoneFlags |= ZONE_LIB_CODE;
        Victim->Object.BaseAddress = Gva & PAGE_MASK;
        break;
    }

    case introObjectTypeIdt:
    {
        // We send the real IDT base through the context
        Victim->Object.BaseAddress = *(QWORD *)Context;
        Victim->Object.Name = "IDT";

        break;
    }

    case introObjectTypeTokenPrivs:
    case introObjectTypeSecDesc:
    case introObjectTypeAcl:
    case introObjectTypeSelfMapEntry:
    {
        Victim->Object.Process = Context;
        Victim->Object.Name = ((WIN_PROCESS_OBJECT *)Context)->Name;
        Victim->Object.NameHash = ((WIN_PROCESS_OBJECT *)Context)->NameHash;
        Victim->Object.BaseAddress = Gva & PAGE_MASK;

        break;
    }

    case introObjectTypeKmLoggerContext:
    {
        break;
    }

    default:
        WARNING("[WARNING] Shouldn't reach here (for now). Type is %d (original %d)...\n", Victim->Object.Type, Type);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Victim->Object.Type != introObjectTypeUmGenericNxZone &&
        Victim->Object.Type != introObjectTypeHalHeap &&
        Victim->Object.Type != introObjectTypeSudExec &&
        (Victim->Object.Type != introObjectTypeVeAgent || (Victim->ZoneFlags & ZONE_WRITE) != 0))
    {
        if (!(ZONE_READ & Victim->ZoneFlags))
        {
            DWORD writeSize = gVcpu->Instruction.Operands[0].Size;

            if (writeSize > sizeof(Victim->WriteInfo.OldValue) || writeSize == 0)
            {
                ERROR("[ERROR] Accessed size is too large or 0: 0x%x\n", writeSize);
                return INT_STATUS_NOT_SUPPORTED;
            }

            status = IntVirtMemRead(Gva, writeSize, 0, Victim->WriteInfo.OldValue, NULL);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntVirtMemRead failed for GVA 0x%016llx: 0x%08x\n", Gva, status);
                Victim->WriteInfo.OldValue[0] = 0xbaddead;
            }

            status = IntDecGetWrittenValueFromInstruction(&gVcpu->Instruction,
                                                          &gVcpu->Regs,
                                                          NULL,
                                                          &operandValue);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] Failed getting operands for instruction %s: 0x%08x\n",
                        gVcpu->Instruction.Mnemonic, status);
                IntDumpInstruction(&gVcpu->Instruction, gVcpu->Regs.Rip);

                Victim->WriteInfo.NewValue[0] = 0xbaddead;
                Victim->WriteInfo.AccessSize = gVcpu->AccessSize;
            }
            else
            {
                memcpy(Victim->WriteInfo.NewValue, operandValue.Value.QwordValues, operandValue.Size);
                Victim->WriteInfo.AccessSize = operandValue.Size;
            }
        }
        else
        {
            if (gVcpu->AccessSize > sizeof(Victim->ReadInfo.Value) || gVcpu->AccessSize == 0)
            {
                ERROR("[ERROR] Accessed size is too large or 0: 0x%x\n", gVcpu->AccessSize);
                return INT_STATUS_NOT_SUPPORTED;
            }

            status = IntKernVirtMemRead(Gva, gVcpu->AccessSize, &Victim->ReadInfo.Value[0], NULL);
            if (!INT_SUCCESS(status))
            {
                Victim->ReadInfo.Value[0] = 0xbaddead;
            }

            Victim->ReadInfo.AccessSize = gVcpu->AccessSize;
        }
    }

    // At this point, override every status possible
    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntExceptVerifyCodeBlocksSig(
    _In_ void *Exception,
    _In_ void *Originator,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _Inout_ DWORD SignatureCount,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief This function checks if the code blocks from the originator RIP match the code blocks from the given
/// exception.
///
/// A code blocks cache is used to avoid to extract same code blocks for each call. The cache is used if this function
/// is called with the saved #gEventId or is called for the same guest virtual address and the save process.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Signatures          An array of signature IDs.
/// @param[in]  SignatureCount      The number of signature IDs.
/// @param[in]  ExceptionType       The type of the exception #EXCEPTION_TYPE.
///
/// @retval #INT_STATUS_NOT_SUPPORTED           If the exception type is invalid, the code blocks cache is invalid or
///                                             the current mode could not be obtained.
/// @retval #INT_STATUS_SIGNATURE_MATCHED       If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND     If no signature matched
///
{
    INTSTATUS status;

    DWORD lastChecked = 0;

    DWORD startOffset, endOffset, totalSize, csType;
    void *pCode = NULL;

    BOOLEAN requires64BitSig = gGuest.Guest64;
    BOOLEAN execute = FALSE;
    BYTE level = (ExceptionType == exceptionTypeKm || ExceptionType == exceptionTypeKmUm) ? cbLevelNormal : cbLevelMedium;

    QWORD rip, cr3;

    void *pHookObject = NULL;
    CB_CACHE *pCodeBlocksCache;
    BYTE cacheFlags;

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    if ((csType != IG_CS_TYPE_32B) && (csType != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", csType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeKm:
    {
        EXCEPTION_KM_ORIGINATOR *pKmOrig = Originator;

        if (((KM_EXCEPTION *)Exception)->Flags & EXCEPTION_KM_FLG_RETURN_DRV)
        {
            rip = pKmOrig->Return.Rip;
            cacheFlags = CB_CACHE_FLG_RETURN;
        }
        else
        {
            rip = pKmOrig->Original.Rip;
            cacheFlags = CB_CACHE_FLG_ORIGINAL;
        }

        cr3 = gGuest.Mm.SystemCr3;

        break;
    }

    case exceptionTypeKmUm:
    {
        EXCEPTION_KM_ORIGINATOR *pKmOrig = Originator;

        if (((KUM_EXCEPTION *)Exception)->Flags & EXCEPTION_KM_FLG_RETURN_DRV)
        {
            rip = pKmOrig->Return.Rip;
            cacheFlags = CB_CACHE_FLG_RETURN;
        }
        else
        {
            rip = pKmOrig->Original.Rip;
            cacheFlags = CB_CACHE_FLG_ORIGINAL;
        }

        cr3 = gGuest.Mm.SystemCr3;

        break;
    }

    case exceptionTypeUmGlob:
    case exceptionTypeUm:
    {
        EXCEPTION_UM_ORIGINATOR *pUmOrig = Originator;

        rip = pUmOrig->Rip;
        execute = pUmOrig->Execute;
        cacheFlags = CB_CACHE_FLG_ORIGINAL;

        if (gGuest.OSType == introGuestWindows)
        {
            if (pUmOrig->WinLib != NULL)
            {
                pHookObject = pUmOrig->WinLib->HookObject;
            }

            cr3 = pUmOrig->WinProc->Cr3;

            requires64BitSig = requires64BitSig && !pUmOrig->WinProc->Wow64Process;
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            pHookObject = pUmOrig->LixProc->HookObject;
            cr3 = pUmOrig->LixProc->Cr3;
        }
        else
        {
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (cr3 != gVcpu->Regs.Cr3)
        {
            LOG("[INFO] Special case where process cr3 %llx != VCPU cr3 %llx\n", cr3, gVcpu->Regs.Cr3);
            cr3 = gVcpu->Regs.Cr3;

            // Don't use keep a cache for these writes (when should we invalidate it, after all?)
            pHookObject = NULL;
        }

        break;
    }

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // In case we get a invalid RIP, we can't extract any code blocks. This is just a sanity check
    // since it shouldn't happen (we always have the current RIP from the VCPU. And if the return rip is 0, then
    // an exception with EXCEPTION_KM_FLG_RETURN_DRV won't match).
    if (0 == rip)
    {
        return INT_STATUS_SIGNATURE_MATCHED;
    }

    // Make sure the totalSize is 2 * EXCEPTION_CODEBLOCKS_OFFSET, and to remain in the same page. Eg:
    // RipOffset = 0xf31 => [0xc00, 0xfff]
    // RipOffset = 0x123 => [0x000, 0x3ff]
    // RipOffset = 0x523 => [0x323, 0x722]
    //
    // But for a EXECUTE violation, get from here on.

    startOffset = endOffset = rip & PAGE_OFFSET;

    if (!execute)
    {
        if (startOffset > EXCEPTION_CODEBLOCKS_OFFSET)
        {
            if (endOffset + EXCEPTION_CODEBLOCKS_OFFSET < PAGE_SIZE)
            {
                startOffset -= EXCEPTION_CODEBLOCKS_OFFSET;
                endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
            }
            else
            {
                startOffset = PAGE_SIZE - (EXCEPTION_CODEBLOCKS_OFFSET * 2);
                endOffset = PAGE_SIZE - 1;
            }
        }
        else
        {
            startOffset = 0;
            endOffset = (EXCEPTION_CODEBLOCKS_OFFSET * 2) - 1;
        }
    }
    else
    {
        endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
    }

    totalSize = endOffset - startOffset;

    // This shouldn't happen since we only extract from the same page, but let's be sure
    if (totalSize > PAGE_SIZE && !execute)
    {
        totalSize = PAGE_SIZE;
    }

    if (cacheFlags & CB_CACHE_FLG_ORIGINAL)
    {
        pCodeBlocksCache = &gCodeBlocksOriginalCache;
    }
    else if (cacheFlags & CB_CACHE_FLG_RETURN)
    {
        pCodeBlocksCache = &gCodeBlocksReturnCache;
    }
    else
    {
        ERROR("[ERROR] Invalid codeblocks cache flag %d...\n", cacheFlags);
        return INT_STATUS_NOT_SUPPORTED;
    }

    // If the current RIP is from a hooked region, we can re-use the cache because it will remain identically
    // (code blocks) until it's written; when the page is written, we'll invalidate the codeblocks cache. (this
    // cache is valid for multiple exits).
    // If the condition is not met, the 'event-id' cache will be used (this cache is valid for one exit).
    if ((PAGE_FRAME_NUMBER(pCodeBlocksCache->Rip) == PAGE_FRAME_NUMBER(rip)) &&
        my_llabs((long long)(pCodeBlocksCache->Rip) - (long long)(rip)) < 0x50 &&
        NULL != IntHookObjectFindRegion(rip, pHookObject, IG_EPT_HOOK_WRITE))
    {
        if (pCodeBlocksCache->Rip == rip &&
            pCodeBlocksCache->CsType == csType &&
            pCodeBlocksCache->Cr3 == cr3)
        {
            goto _skip_getting_codeblocks;
        }

        pCodeBlocksCache->EventId = gEventId;
        pCodeBlocksCache->Rip = rip;
        pCodeBlocksCache->CsType = csType;
        pCodeBlocksCache->Cr3 = cr3;
        pCodeBlocksCache->Count = totalSize / sizeof(DWORD);
    }
    else
    {
        if (pCodeBlocksCache->EventId == gEventId &&
            pCodeBlocksCache->Rip == rip &&
            pCodeBlocksCache->CsType == csType)
        {
            goto _skip_getting_codeblocks;
        }

        pCodeBlocksCache->EventId = gEventId;
        pCodeBlocksCache->Rip = rip;
        pCodeBlocksCache->CsType = csType;
        pCodeBlocksCache->Cr3 = cr3;
        pCodeBlocksCache->Count = totalSize / sizeof(DWORD);
    }

    status = IntVirtMemMap((rip & PAGE_MASK) + startOffset, totalSize, cr3, 0, &pCode);
    if (!INT_SUCCESS(status))
    {
        if (execute)
        {
            WARNING("[WARNING] Failed to map range [0x%016llx - 0x%016llx], try to map range [0x%016llx - 0x%016llx]\n",
                    (rip & PAGE_MASK) + startOffset, (rip & PAGE_MASK) + startOffset + totalSize,
                    (rip & PAGE_MASK) + startOffset,  (rip & PAGE_MASK) + startOffset + (PAGE_SIZE - startOffset));
            status = IntVirtMemMap((rip & PAGE_MASK) + startOffset, PAGE_SIZE - startOffset, cr3, 0, &pCode);
            if (!INT_SUCCESS(status))
            {
                pCodeBlocksCache->EventId = 0;

                ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", rip & PAGE_MASK, status);

                goto _clean_and_leave;
            }

            totalSize = PAGE_SIZE - startOffset;
        }
        else
        {
            pCodeBlocksCache->EventId = 0;

            ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", rip & PAGE_MASK, status);

            goto _clean_and_leave;
        }
    }

    status = IntFragExtractCodeBlocks(pCode, totalSize, csType, level,
                                      &pCodeBlocksCache->Count, pCodeBlocksCache->CodeBlocks);
    if (!INT_SUCCESS(status) && INT_STATUS_NOT_FOUND != status)
    {
        pCodeBlocksCache->EventId = 0;
        ERROR("[ERROR] Failed extracting blocks from VA 0x%016llx: 0x%08x\n", rip, status);
        goto _clean_and_leave;
    }
    else if (INT_STATUS_NOT_FOUND == status)
    {
        // If we didn't manage to extract codeblocks, we can't verify anything.
        pCodeBlocksCache->Count = 0;
        status = INT_STATUS_SIGNATURE_NOT_FOUND;

        goto _clean_and_leave;
    }

_skip_getting_codeblocks:
    for_each_cb_signature(gGuest.Exceptions->CbSignatures, pSig)
    {
        if ((gGuest.OSType == introGuestWindows && (pSig->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSig->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignatureCount; i++)
        {
            if (Signatures[i].Field.Type != signatureTypeCodeBlocks)
            {
                break;
            }

            if (Signatures[i].Value != pSig->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_64)) ||
                (!requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            if ((pSig->Flags & SIGNATURE_FLG_CB_MEDIUM) && level != cbLevelMedium)
            {
                break;
            }

            status = IntFragMatchSignature(pCodeBlocksCache->CodeBlocks, pCodeBlocksCache->Count, pSig);
            if (status == INT_STATUS_SIGNATURE_MATCHED)
            {
                goto _clean_and_leave;
            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    // if we get here, the we didn't match anything
    status = INT_STATUS_SIGNATURE_NOT_FOUND;

_clean_and_leave:
    if (NULL != pCode)
    {
        IntVirtMemUnmap(&pCode);
    }

    return status;
}


static INTSTATUS
IntExceptVerifyValueCodeSig(
    _In_ void *Exception,
    _In_ void *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief This function checks if the opcodes from the originator's RIP match the opcodes pattern from the given
/// exception.
///
/// For every call of this function the guest virtual address near the RIP is mapped only once.
/// The mapped guest virtual address is freed after all the checks have been made.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Victim              The #EXCEPTION_VICTIM_ZONE structure used by the exceptions mechanism.
/// @param[in]  Signatures          An array of signature IDs.
/// @param[in]  SignaturesCount     The number of signature IDs.
/// @param[in]  ExceptionType       The type of the exception #EXCEPTION_TYPE.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the cs type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    INTSTATUS status;

    DWORD lastChecked = 0;

    DWORD csType;
    BYTE *pCodePattern = NULL;
    BYTE *pCodePatternBuffer = NULL;
    BYTE level = (ExceptionType == exceptionTypeKm) ? cbLevelNormal : cbLevelMedium;

    BOOLEAN requires64BitSig = gGuest.Guest64;
    QWORD rip, cr3;

    QWORD oldGva = 0;

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return status;
    }

    if ((csType != IG_CS_TYPE_32B) && (csType != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", csType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeKm:
    case exceptionTypeKmUm:
    {
        EXCEPTION_KM_ORIGINATOR *pKmOrig = Originator;

        if (((KM_EXCEPTION *)Exception)->Flags & EXCEPTION_KM_FLG_RETURN_DRV)
        {
            rip = pKmOrig->Return.Rip;
        }
        else
        {
            rip = pKmOrig->Original.Rip;
        }

        cr3 = gGuest.Mm.SystemCr3;

        break;
    }

    case exceptionTypeUmGlob:
    case exceptionTypeUm:
    {
        EXCEPTION_UM_ORIGINATOR *pUmOrig = Originator;

        rip = pUmOrig->Rip;

        if (gGuest.OSType == introGuestWindows)
        {
            if (pUmOrig->PcType == INT_PC_VIOLATION_DPI_HEAP_SPRAY ||
                pUmOrig->PcType == INT_PC_VIOLATION_DPI_THREAD_START)
            {
                cr3 = Victim->Object.WinProc->Cr3;
                requires64BitSig = requires64BitSig && !Victim->Object.WinProc->Wow64Process;
                break;
            }

            cr3 = pUmOrig->WinProc->Cr3;

            requires64BitSig = requires64BitSig && !pUmOrig->WinProc->Wow64Process;
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            cr3 = pUmOrig->LixProc->Cr3;
        }
        else
        {
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (cr3 != gVcpu->Regs.Cr3)
        {
            LOG("[INFO] Special case where process cr3 %llx != VCPU cr3 %llx\n", cr3, gVcpu->Regs.Cr3);
            cr3 = gVcpu->Regs.Cr3;
        }

        break;
    }

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (0 == rip)
    {
        return INT_STATUS_SIGNATURE_MATCHED;
    }

    for_each_value_code_signature(gGuest.Exceptions->ValueCodeSignatures, pSig)
    {
        if ((gGuest.OSType == introGuestWindows && (pSig->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSig->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            QWORD gva;
            DWORD pageRemaining;
            QWORD alignedGva;

            if (Signatures[i].Field.Type != signatureTypeValueCode)
            {
                break;
            }

            if (Signatures[i].Value != pSig->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_64)) ||
                (!requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            if ((pSig->Flags & SIGNATURE_FLG_CB_MEDIUM) && level != cbLevelMedium)
            {
                break;
            }

            // Match only the first page
            gva = rip + pSig->Offset;
            pageRemaining = (DWORD)PAGE_REMAINING(gva);
            alignedGva = gva & PAGE_MASK;

            // New map only if the page changes
            if ((oldGva != alignedGva) || NULL == pCodePattern)
            {
                oldGva = alignedGva;

                // Unmap the old page
                if (NULL != pCodePattern)
                {
                    IntVirtMemUnmap(&pCodePattern);
                }

                status = IntVirtMemMap(alignedGva, PAGE_SIZE, cr3, 0, &pCodePattern);
                if (!INT_SUCCESS(status))
                {
                    WARNING("[WARNING] IntVirtMemMap failed for address %llx: 0x%08x\n", alignedGva, status);
                    continue;
                }
            }

            pCodePattern = (BYTE *)(((QWORD)pCodePattern & PAGE_MASK) | gva % PAGE_SIZE);

            if (SIG_NOT_FOUND == IntExceptExtendedPatternMatch(pCodePattern, MIN(pageRemaining, pSig->Length), pSig, 0))
            {
                // so the next time we will search from this signature forward only
                lastChecked = i + 1;

                // no point in searching anymore (only one will match)
                break;
            }

            // Match next pages if is necessary
            if (pageRemaining >= pSig->Length)
            {
                status = INT_STATUS_SIGNATURE_MATCHED;
                goto _clean_and_leave;
            }

            gva += pageRemaining;

            pCodePatternBuffer = HpAllocWithTag(pSig->Length - pageRemaining, IC_TAG_EXCP);
            if (NULL == pCodePatternBuffer)
            {
                status = INT_STATUS_INSUFFICIENT_RESOURCES;
                goto _clean_and_leave;
            }

            status = IntVirtMemRead(gva, pSig->Length - pageRemaining, cr3, pCodePatternBuffer, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemMap failed for address %llx: 0x%08x\n", gva, status);
                continue;
            }

            if (SIG_NOT_FOUND == IntExceptExtendedPatternMatch(pCodePatternBuffer, pSig->Length - pageRemaining,
                                                               pSig, pageRemaining))
            {
                HpFreeAndNullWithTag(&pCodePatternBuffer, IC_TAG_EXCP);

                // so the next time we will search from this signature forward only
                lastChecked = i + 1;

                // no point in searching anymore (only one will match)
                break;
            }

            HpFreeAndNullWithTag(&pCodePatternBuffer, IC_TAG_EXCP);

            status = INT_STATUS_SIGNATURE_MATCHED;
            goto _clean_and_leave;
        }
    }

    // if we get here, the we didn't match anything
    status = INT_STATUS_SIGNATURE_NOT_FOUND;

_clean_and_leave:

    if (NULL != pCodePattern)
    {
        IntVirtMemUnmap(&pCodePattern);
    }

    return status;
}


static INTSTATUS
IntExceptVerifyValueSig(
    _In_ void *Exception,
    _In_ void *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief This function checks if the hash of the modified zone from the originator matches the hash from the
/// given exception.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Victim              The victim structure used by the exceptions mechanism.
/// @param[in]  Signatures          An array of signature IDs.
/// @param[in]  SignaturesCount     The number of signature IDs.
/// @param[in]  ExceptionType       The type of the exception #EXCEPTION_TYPE.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the cs type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EXCEPTION_UM_ORIGINATOR *pOriginator = Originator;
    BYTE *pBuffer = NULL;
    BOOLEAN requires64BitSig = gGuest.Guest64;
    DWORD size = 0;
    DWORD lastChecked = 0;

    UNREFERENCED_PARAMETER(Exception);

    if ((Victim->ZoneType == exceptionZoneEpt) ||
        (Victim->ZoneType == exceptionZoneMsr))
    {
        if (Victim->WriteInfo.AccessSize > sizeof(Victim->WriteInfo.NewValue))
        {
            ERROR("[ERROR] Access size too large or 0: %d\n", Victim->WriteInfo.AccessSize);
            return INT_STATUS_NOT_SUPPORTED;
        }

        pBuffer = (BYTE *)&Victim->WriteInfo.NewValue;
        size = Victim->WriteInfo.AccessSize;
    }
    else if (Victim->ZoneType == exceptionZoneProcess &&
             NULL == Victim->Injection.Buffer)
    {
        QWORD gva = pOriginator->SourceVA;
        QWORD cr3 = 0;

        size = Victim->Injection.Length;

        if (NULL == gValueBuffer || size > gValueBufferSize)
        {
            TRACE("[EXCEPTIONS] Must realloc old buffer %p with size %d to size %d\n",
                  gValueBuffer, gValueBufferSize, size);

            // Maybe it failed at a previous allocation
            if (gValueBuffer)
            {
                HpFreeAndNullWithTag(&gValueBuffer, IC_TAG_EXCP);
            }

            gValueBuffer = HpAllocWithTag(size, IC_TAG_EXCP);
            if (NULL == gValueBuffer)
            {
                return INT_STATUS_INSUFFICIENT_RESOURCES;
            }

            gValueBufferSize = size;
        }

        pBuffer = gValueBuffer;

        if (gGuest.OSType == introGuestWindows)
        {
            cr3 = pOriginator->WinProc->Cr3;
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            cr3 = pOriginator->LixProc->Cr3;
        }
        else
        {
            return INT_STATUS_NOT_SUPPORTED;
        }

        // Safe: buf is allocated dynamically to match the read size.
        status = IntVirtMemRead(gva, size, cr3, pBuffer, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemRead failed for gva %llx, cr3 %llx with size %d: %08x\n", gva, cr3, size, status);
            return status;
        }

        Victim->Injection.Buffer = gValueBuffer;
        Victim->Injection.BufferSize = gValueBufferSize;
    }
    else if (Victim->ZoneType == exceptionZoneProcess &&
             NULL != Victim->Injection.Buffer)
    {
         pBuffer = Victim->Injection.Buffer;
         size = Victim->Injection.BufferSize;
    }
    else if (Victim->ZoneType == exceptionZoneIntegrity)
    {
        if (Victim->Object.Type == introObjectTypeIdt ||
            Victim->Object.Type == introObjectTypeSudIntegrity)
        {
            pBuffer = (BYTE *)&Victim->WriteInfo.NewValue;
            size = Victim->WriteInfo.AccessSize;
        }
        else if (Victim->Object.Type == introObjectTypeSecDesc ||
                 Victim->Object.Type == introObjectTypeAcl)
        {
             pBuffer = Victim->Integrity.Buffer;
             size = Victim->Integrity.BufferSize;
        }
        else
        {
            return INT_STATUS_NOT_SUPPORTED;
        }
    }
    else if (Victim->ZoneType == exceptionZonePc)
    {
        // Nothing to do here ...
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    switch (ExceptionType)
    {
    case exceptionTypeKm:
    case exceptionTypeKmUm:
        break;

    case exceptionTypeUmGlob:
    case exceptionTypeUm:
        if (gGuest.OSType == introGuestWindows && requires64BitSig)
        {
            requires64BitSig = !pOriginator->WinProc->Wow64Process;
        }

        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    for_each_value_signature(gGuest.Exceptions->ValueSignatures, pSig)
    {
        if ((gGuest.OSType == introGuestWindows && (pSig->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSig->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            SIG_VALUE_HASH *pSigHash = NULL;
            DWORD matchedCount = 0;

            if (Signatures[i].Field.Type != signatureTypeValue)
            {
                break;
            }

            if (Signatures[i].Value != pSig->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_64)) ||
                (!requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            pSigHash = (SIG_VALUE_HASH *)pSig->Object;
            for (DWORD j = 0; j < pSig->ListsCount; j++)
            {
                BOOLEAN match = FALSE;

                if (pSig->Flags & SIGNATURE_FLG_VALUE_CLI)
                {
                    char *pCommandLine = NULL;

                    if (gGuest.OSType == introGuestWindows)
                    {
                        pCommandLine = pOriginator->WinProc->CommandLine;
                    }
                    else if (gGuest.OSType == introGuestLinux)
                    {
                        pCommandLine = pOriginator->LixProc->CmdLine;
                    }
                    else
                    {
                        break;
                    }

                    if (pCommandLine == NULL)
                    {
                        return INT_STATUS_EXCEPTION_ALLOW;
                    }

                    // This case will include Offset > wstrlen(pCli) and Size > wstrlen(pCommandLine) because we cast
                    // Offset and Size (WORD -> DWORD) so we'll not have an overflow
                    if (((QWORD)pSigHash[j].Offset + (DWORD)pSigHash[j].Size) > strlen(pCommandLine))
                    {
                        continue;
                    }

                    match = (pSigHash[j].Hash == Crc32Compute(pCommandLine + pSigHash[j].Offset,
                                                              pSigHash[j].Size,
                                                              INITIAL_CRC_VALUE));
                }
                else
                {
                    if (Victim->ZoneType == exceptionZonePc || pBuffer == NULL)
                    {
                        continue;
                    }

                    // This case will include Offset >size and Size > size because we cast Offset and Size
                    // (WORD -> DWORD) so we'll not have an overflow
                    if (((DWORD)pSigHash[j].Offset + (DWORD)pSigHash[j].Size) > size)
                    {
                        continue;
                    }

                    match = (pSigHash[j].Hash == Crc32Compute(pBuffer + pSigHash[j].Offset,
                                                              pSigHash[j].Size,
                                                              INITIAL_CRC_VALUE));
                }

                if (match)
                {
                    matchedCount++;

                    if (matchedCount >= pSig->Score)
                    {
                        return INT_STATUS_SIGNATURE_MATCHED;
                    }
                }

            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    // if we get here, the we didn't match anything
    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


static INTSTATUS
IntExceptVerifyExportSig(
    _In_ void *Exception,
    _In_ void *Originator,
    _Inout_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief Checks if the modified library from the originator matches the library from the given exception.
///
/// A cache is used to store the exports for the protected library. For every call, the function checks if the export
/// match the function name from the exception and if the modified size is in the range of 0 and the given delta
/// from exception.
///
/// @param[in]      Exception           The current exception to check.
/// @param[in]      Originator          The originator structure used by the exceptions mechanism.
/// @param[in, out] Victim              The victim structure used by the exceptions mechanism.
/// @param[in]      Signatures          An array of signature IDs.
/// @param[in, out] SignaturesCount     The number of signature IDs.
/// @param[in]      ExceptionType       The type of the exception #EXCEPTION_TYPE
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the cs type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    WIN_PROCESS_MODULE *pModule;
    DWORD accessSize;
    DWORD lastChecked = 0;
    BOOLEAN requires64BitSig = gGuest.Guest64;
    QWORD gva;

    UNREFERENCED_PARAMETER(Exception);

    switch(ExceptionType)
    {
        case exceptionTypeUm:
        {
            EXCEPTION_UM_ORIGINATOR *pOriginator = Originator;
            if (gGuest.OSType == introGuestWindows && requires64BitSig)
            {
                if (Victim->ZoneType == exceptionZoneProcess)
                {
                    requires64BitSig = !Victim->Object.WinProc->Wow64Process;
                }
                else
                {
                    requires64BitSig = !pOriginator->WinProc->Wow64Process;
                }
            }
            break;
        }

        case exceptionTypeKmUm:
            requires64BitSig = gGuest.Guest64;
            break;

        default:
            WARNING("[WARNING] Unsupported exception type (%d) for export signature\n", ExceptionType);
            return INT_STATUS_SIGNATURE_MATCHED;
    }

    if (Victim->ZoneType == exceptionZoneEpt)
    {
        gva = Victim->Ept.Gva;
        accessSize = Victim->WriteInfo.AccessSize;
    }
    else if (Victim->ZoneType == exceptionZoneProcess)
    {
        gva = Victim->Injection.Gva;
        accessSize = Victim->Injection.Length;
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    pModule = Victim->Object.Library.Module;

    // We must return an error since this injection was for a module-only modification
    if (NULL == pModule)
    {
        return INT_STATUS_SIGNATURE_NOT_FOUND;
    }

    if (NULL == pModule->Cache || !pModule->Cache->ExportDirRead)
    {
        return INT_STATUS_SIGNATURE_MATCHED;
    }

    if (Victim->Object.Library.Export == NULL)
    {
        Victim->Object.Library.Export = IntWinUmCacheGetExportFromRange(pModule, gva, 0x20);
    }

    for_each_export_signature(gGuest.Exceptions->ExportSignatures, pSig)
    {
        if ((gGuest.OSType == introGuestWindows && (pSig->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSig->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        if (pSig->LibraryNameHash != umExcNameAny && pModule->Path->NameHash != pSig->LibraryNameHash)
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            SIG_EXPORT_HASH *pSigHash;

            if (Signatures[i].Field.Type != signatureTypeExport)
            {
                break;
            }

            if (Signatures[i].Value != pSig->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_64)) ||
                (!requires64BitSig && !(pSig->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            pSigHash = (SIG_EXPORT_HASH *)pSig->Object;
            for (DWORD j = 0; j < pSig->ListsCount; j++)
            {
                DWORD offset;
                BOOLEAN found = FALSE;

                if (pSigHash[j].Hash == umExcNameAny)
                {
                    return INT_STATUS_SIGNATURE_MATCHED;
                }

                if (Victim->Object.Library.Export == NULL &&
                    pSigHash[i].Hash == umExcNameNone)
                {
                    return INT_STATUS_SIGNATURE_MATCHED;
                }

                // Only check the exceptions which match any name if we didn't found an export
                if (Victim->Object.Library.Export == NULL)
                {
                    continue;
                }

                for (DWORD export = 0; export < Victim->Object.Library.Export->NumberOfOffsets; export++)
                {
                    if (pSigHash[j].Hash == Victim->Object.Library.Export->NameHashes[export])
                    {
                        found = TRUE;
                        break;
                    }
                }

                if (!found)
                {
                    continue;
                }

                // Verify that the write is inside the allowed zone or that delta is 0 (match any length)
                offset = (DWORD)(gva - pModule->VirtualBase) - Victim->Object.Library.Export->Rva;
                if (pSigHash[j].Delta != 0 &&
                    (offset + accessSize - 1 > pSigHash[j].Delta))
                {
                    continue;
                }

                return INT_STATUS_SIGNATURE_MATCHED;
            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


static INTSTATUS
IntExceptVerifyIdtSignature(
    _In_ void *Exception,
    _In_ void *Originator,
    _Inout_ PEXCEPTION_VICTIM_ZONE Victim,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief This function checks if the modified IDT entry matches the entry from the given exception.
///
/// @param[in]      Exception           The current exception to check,
/// @param[in]      Originator          The originator structure used by the exceptions mechanism.
/// @param[in, out] Victim              The victim structure used by the exceptions mechanism.
/// @param[in]      Signatures          An array of signature IDs.
/// @param[in, out] SignaturesCount     The number of signature IDs.
/// @param[in]      ExceptionType       The type of the exception #EXCEPTION_TYPE.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the cs type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    UNREFERENCED_PARAMETER(Originator);
    UNREFERENCED_PARAMETER(Exception);

    DWORD lastChecked = 0;
    BYTE idtEntry;

    if (ExceptionType != exceptionTypeKm)
    {
        return INT_STATUS_SIGNATURE_NOT_FOUND;
    }
    switch (Victim->Object.Type)
    {
        case introObjectTypeIdt:
            if (Victim->ZoneType == exceptionZoneIntegrity)
            {
                idtEntry = (BYTE)(Victim->Integrity.Offset /
                    (gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32));
            }
            else
            {
                idtEntry = (BYTE)((Victim->Ept.Gva - Victim->Object.BaseAddress) /
                    (gGuest.Guest64 ? DESCRIPTOR_SIZE_64 : DESCRIPTOR_SIZE_32));
            }
            break;

        case introObjectTypeInterruptObject:
            idtEntry = (BYTE)Victim->Integrity.InterruptObjIndex;
            break;

        default:
            return INT_STATUS_NOT_SUPPORTED;
    }

    lastChecked = 0;
    for_each_idt_signature(gGuest.Exceptions->IdtSignatures, pSig)
    {
        if ((gGuest.OSType == introGuestWindows && (pSig->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSig->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            if (Signatures[i].Field.Type != signatureTypeIdt)
            {
                break;
            }

            if (Signatures[i].Value != pSig->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((gGuest.Guest64 && !(pSig->Flags & SIGNATURE_FLG_64)) ||
                (!gGuest.Guest64 && !(pSig->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            if (pSig->Entry == idtEntry)
            {
                return INT_STATUS_SIGNATURE_MATCHED;
            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    // if we get here, the we didn't match anything
    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


static INTSTATUS
IntExceptVerifyProcessCreationSignature(
    _In_ void *Exception,
    _In_ void *Originator,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount,
    _In_ EXCEPTION_TYPE ExceptionType
    )
///
/// @brief Checks if the DPI mask of the newly created process match the DPI mask from the given exception.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Signatures          An array of signature IDs.
/// @param[in]  SignaturesCount     The number of signature IDs.
/// @param[in]  ExceptionType       The type of the exception #EXCEPTION_TYPE.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the CS type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    UNREFERENCED_PARAMETER(Exception);

    EXCEPTION_UM_ORIGINATOR *pOriginator = NULL;
    DWORD mask = 0;
    DWORD lastChecked = 0;

    if (ExceptionType == exceptionTypeKm)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    pOriginator = Originator;

    mask = pOriginator->PcType;

    lastChecked = 0;
    for_each_process_creation_signature(gGuest.Exceptions->ProcessCreationSignatures, pSignature)
    {
        if ((gGuest.OSType == introGuestWindows && (pSignature->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSignature->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            if (Signatures[i].Field.Type != signatureTypeProcessCreation)
            {
                break;
            }

            if (Signatures[i].Value != pSignature->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((gGuest.Guest64 && !(pSignature->Flags & SIGNATURE_FLG_64)) ||
                (!gGuest.Guest64 && !(pSignature->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            if ((~(pSignature->CreateMask) & mask) == 0)
            {
                return INT_STATUS_SIGNATURE_MATCHED;
            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    // if we get here, the we didn't match anything
    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


static INTSTATUS
IntExceptVerifyVersionOsSignature(
    _In_ void *Exception,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount
    )
///
/// @brief This function checks if the version of the guest operating system is in the minimum-maximum range.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Signatures          An array of signature IDs.
/// @param[in]  SignaturesCount     The number of signature IDs.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the cs type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    UNREFERENCED_PARAMETER(Exception);

    DWORD lastChecked = 0;

    lastChecked = 0;
    for_each_version_os_signature(gGuest.Exceptions->VersionOsSignatures, pSignature)
    {
        if ((gGuest.OSType == introGuestWindows && (pSignature->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSignature->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            if (Signatures[i].Field.Type != signatureTypeVersionOs)
            {
                break;
            }

            if (Signatures[i].Value != pSignature->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((gGuest.Guest64 && !(pSignature->Flags & SIGNATURE_FLG_64)) ||
                (!gGuest.Guest64 && !(pSignature->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            if (gGuest.OSType == introGuestWindows)
            {
                if (pSignature->Minimum.Value <= gGuest.OSVersion &&
                    pSignature->Maximum.Value >= gGuest.OSVersion)
                {
                    return INT_STATUS_SIGNATURE_MATCHED;
                }
            }
            else if (gGuest.OSType == introGuestLinux)
            {
                BOOLEAN matchMax = FALSE;
                BOOLEAN matchMin = FALSE;

                if (pSignature->Minimum.Version <= gLixGuest->Version.Version)
                {
                    if (pSignature->Minimum.Version < gLixGuest->Version.Version)
                    {
                        matchMin = TRUE;
                        goto _check_min_os_done;
                    }

                    if (pSignature->Minimum.Patch <= gLixGuest->Version.Patch)
                    {
                        if (pSignature->Minimum.Patch < gLixGuest->Version.Patch)
                        {
                            matchMin = TRUE;
                            goto _check_min_os_done;
                        }

                        if (pSignature->Minimum.Sublevel <= gLixGuest->Version.Sublevel)
                        {
                            if (pSignature->Minimum.Sublevel < gLixGuest->Version.Sublevel)
                            {
                                matchMin = TRUE;
                                goto _check_min_os_done;
                            }

                            if (pSignature->Minimum.Backport <= gLixGuest->Version.Backport)
                            {
                                matchMin = TRUE;
                            }
                        }
                    }
                }

_check_min_os_done:
                if (!matchMin)
                {
                    goto _check_max_os_done;
                }

                if (pSignature->Maximum.Version >= gLixGuest->Version.Version)
                {
                    if (pSignature->Maximum.Version > gLixGuest->Version.Version)
                    {
                        matchMax = TRUE;
                        goto _check_max_os_done;
                    }

                    if (pSignature->Maximum.Patch >= gLixGuest->Version.Patch)
                    {
                        if (pSignature->Maximum.Patch > gLixGuest->Version.Patch)
                        {
                            matchMax = TRUE;
                            goto _check_max_os_done;
                        }

                        if (pSignature->Maximum.Sublevel >= gLixGuest->Version.Sublevel)
                        {
                            if (pSignature->Maximum.Sublevel > gLixGuest->Version.Sublevel)
                            {
                                matchMax = TRUE;
                                goto _check_max_os_done;
                            }

                            if (pSignature->Maximum.Backport >= gLixGuest->Version.Backport)
                            {
                                matchMax = TRUE;
                            }
                        }
                    }
                }

_check_max_os_done:
                if (matchMin && matchMax)
                {
                    return INT_STATUS_SIGNATURE_MATCHED;
                }
            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    // if we get here, the we didn't match anything
    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


static INTSTATUS
IntExceptVerifyVersionIntroSignature(
    _In_ void *Exception,
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD SignaturesCount
    )
///
/// @brief This function checks if the version of the introspection is in the minimum-maximum range.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Signatures          An array of signature IDs.
/// @param[in]  SignaturesCount     The number of signature IDs.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid or the CS type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{
    UNREFERENCED_PARAMETER(Exception);

    DWORD lastChecked = 0;

    lastChecked = 0;
    for_each_version_intro_signature(gGuest.Exceptions->VersionIntroSignatures, pSignature)
    {
        if ((gGuest.OSType == introGuestWindows && (pSignature->Flags & SIGNATURE_FLG_LINUX)) ||
            (gGuest.OSType == introGuestLinux && !(pSignature->Flags & SIGNATURE_FLG_LINUX)))
        {
            continue;
        }

        // Since everything is ordered, it's safely to do it like this
        for (DWORD i = lastChecked; i < SignaturesCount; i++)
        {
            BOOLEAN matchMax;
            BOOLEAN matchMin;

            if (Signatures[i].Field.Type != signatureTypeVersionIntro)
            {
                break;
            }

            if (Signatures[i].Value != pSignature->Id.Value)
            {
                continue;
            }

            // We found a signature. Make sure it matches the architecture & everything else
            if ((gGuest.Guest64 && !(pSignature->Flags & SIGNATURE_FLG_64)) ||
                (!gGuest.Guest64 && !(pSignature->Flags & SIGNATURE_FLG_32)))
            {
                break;
            }

            matchMax = FALSE;
            matchMin = FALSE;

            if (pSignature->Minimum.Major <= IntHviVersion.VersionInfo.Major)
            {
                if (pSignature->Minimum.Major < IntHviVersion.VersionInfo.Major)
                {
                    matchMin = TRUE;
                    goto _check_min_done;
                }

                if (pSignature->Minimum.Minor <= IntHviVersion.VersionInfo.Minor)
                {
                    if (pSignature->Minimum.Minor < IntHviVersion.VersionInfo.Minor)
                    {
                        matchMin = TRUE;
                        goto _check_min_done;
                    }

                    if (pSignature->Minimum.Revision <= IntHviVersion.VersionInfo.Revision)
                    {
                        if (pSignature->Minimum.Revision < IntHviVersion.VersionInfo.Revision)
                        {
                            matchMin = TRUE;
                            goto _check_min_done;
                        }

                        if (pSignature->Minimum.Build <= IntHviVersion.VersionInfo.Build)
                        {
                            matchMin = TRUE;
                        }
                    }
                }
            }

_check_min_done:

            if (!matchMin)
            {
                goto _check_max_done;
            }

            if (pSignature->Maximum.Major >= IntHviVersion.VersionInfo.Major)
            {
                if (pSignature->Maximum.Major > IntHviVersion.VersionInfo.Major)
                {
                    matchMax = TRUE;
                    goto _check_max_done;
                }

                if (pSignature->Maximum.Minor >= IntHviVersion.VersionInfo.Minor)
                {
                    if (pSignature->Maximum.Minor > IntHviVersion.VersionInfo.Minor)
                    {
                        matchMax = TRUE;
                        goto _check_max_done;
                    }

                    if (pSignature->Maximum.Revision >= IntHviVersion.VersionInfo.Revision)
                    {
                        if (pSignature->Maximum.Revision > IntHviVersion.VersionInfo.Revision)
                        {
                            matchMax = TRUE;
                            goto _check_max_done;
                        }

                        if (pSignature->Maximum.Build >= IntHviVersion.VersionInfo.Build)
                        {
                            matchMax = TRUE;
                        }
                    }
                }
            }

_check_max_done:
            if (matchMax && matchMin)
            {
                return INT_STATUS_SIGNATURE_MATCHED;
            }

            // so the next time we will search from this signature forward only
            lastChecked = i + 1;

            // no point in searching anymore (only one will match)
            break;
        }
    }

    // if we get here, the we didn't match anything
    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


static BOOLEAN
IntExceptSignaturesHasType(
    _In_ EXCEPTION_SIGNATURE_ID *Signatures,
    _In_ DWORD Count,
    _In_ EXCEPTION_SIGNATURE_TYPE Type
    )
///
/// @brief This function checks if any signature from an signature-array has the given type.
///
/// @param[in]  Signatures  An array of signature IDs.
/// @param[in]  Count       The number of the signature-array.
/// @param[in]  Type        The type of signature.
///
/// @retval True if any signature from an signature-array has the given type.
///
{
    for (DWORD index = 0; index < Count; index++)
    {
        if ((EXCEPTION_SIGNATURE_TYPE)(Signatures[index].Field.Type) == Type)
        {
            return TRUE;
        }
    }

    return FALSE;
}


static INTSTATUS
IntExceptVerifySignature(
    _In_ void *Exception,
    _In_ void *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_TYPE ExceptionType,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief Iterates all signatures from the given exception and call the suitable function for that signature type.
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Victim              The current victim to check.
/// @param[in]  ExceptionType       The type of the exception #EXCEPTION_TYPE.
/// @param[out] Reason              The reason for which the violation is allowed/blocked.
///
/// @retval #INT_STATUS_NOT_SUPPORTED        If the exception type is invalid.
/// @retval #INT_STATUS_SIGNATURE_MATCHED    If any signature of the exception matched.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND  If no signature matched.
///
{

    INTSTATUS status = INT_STATUS_SUCCESS;
    EXCEPTION_SIGNATURE_ID *pId = NULL;
    DWORD count = 0;
    DWORD index;

    // The caller will set the beta flag if needed.
    *Reason = introReasonAllowed;

    switch (ExceptionType)
    {
    case exceptionTypeKm:
        count = ((KM_EXCEPTION *)Exception)->SigCount;
        pId = ((KM_EXCEPTION *)Exception)->Signatures;

        break;

    case exceptionTypeKmUm:
        count = ((KUM_EXCEPTION *)Exception)->SigCount;
        pId = ((KUM_EXCEPTION *)Exception)->Signatures;

        break;

    case exceptionTypeUm:
        count = ((UM_EXCEPTION *)Exception)->SigCount;
        pId = ((UM_EXCEPTION *)Exception)->Signatures;

        // An injection that modifies a dll MUST have a export signature
        if (NULL != Victim->Object.Library.Module &&
            Victim->ZoneType == exceptionZoneProcess &&
            !IntExceptSignaturesHasType(pId, count, signatureTypeExport) &&
            !(Victim->ZoneFlags & ZONE_MODULE_LOAD))
        {
            *Reason = introReasonExportNotMatched;
            return INT_STATUS_SIGNATURE_NOT_FOUND;
        }

        break;

    case exceptionTypeUmGlob:
        count = ((UM_EXCEPTION_GLOB *)Exception)->SigCount;
        pId = ((UM_EXCEPTION_GLOB *)Exception)->Signatures;


        // An injection that modifies a dll MUST have a export signature
        if (NULL != Victim->Object.Library.Module &&
            Victim->ZoneType == exceptionZoneProcess &&
            !IntExceptSignaturesHasType(pId, count, signatureTypeExport) &&
            !(Victim->ZoneFlags & ZONE_MODULE_LOAD))
        {
            *Reason = introReasonExportNotMatched;
            return INT_STATUS_SIGNATURE_NOT_FOUND;
        }

        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (0 == count)
    {
        return INT_STATUS_SIGNATURE_MATCHED;
    }

    index = 0;
    while (index < count)
    {
        switch (pId[index].Field.Type)
        {
        case signatureTypeVersionOs:
        {
            status = IntExceptVerifyVersionOsSignature(Exception, &pId[index], count - index);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonVersionOsNotMatched;
                return status;
            }

            break;
        }

        case signatureTypeVersionIntro:
        {
            status = IntExceptVerifyVersionIntroSignature(Exception, &pId[index], count - index);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonVersionIntroNotMatched;
                return status;
            }

            break;
        }

        case signatureTypeProcessCreation:
        {
            status = IntExceptVerifyProcessCreationSignature(Exception,
                                                             Originator,
                                                             &pId[index],
                                                             count - index,
                                                             ExceptionType);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonProcessCreationNotMatched;
                return status;
            }

            break;
        }


        case signatureTypeExport:
        {
            status = IntExceptVerifyExportSig(Exception,
                                              Originator,
                                              Victim,
                                              &pId[index],
                                              count - index,
                                              ExceptionType);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonExportNotMatched;
                return status;
            }

            break;
        }

        case signatureTypeValue:
        {
            status = IntExceptVerifyValueSig(Exception,
                                             Originator,
                                             Victim,
                                             &pId[index],
                                             count - index,
                                             ExceptionType);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonValueNotMatched;
                return status;
            }

            break;
        }

        case signatureTypeIdt:
        {
            status = IntExceptVerifyIdtSignature(Exception,
                                                 Originator,
                                                 Victim,
                                                 &pId[index],
                                                 count - index,
                                                 ExceptionType);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonIdtNotMatched;
                return status;
            }

            break;
        }

        case signatureTypeValueCode:
        {
            status = IntExceptVerifyValueCodeSig(Exception,
                                                 Originator,
                                                 Victim,
                                                 &pId[index],
                                                 count - index,
                                                 ExceptionType);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonValueCodeNotMatched;
                return status;
            }

            break;
        }

        case signatureTypeCodeBlocks:
        {
            status = IntExceptVerifyCodeBlocksSig(Exception, Originator, &pId[index], count - index, ExceptionType);
            if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
            {
                *Reason = introReasonSignatureNotMatched;
                return status;
            }

            break;
        }

        default:
        {
            ERROR("[ERROR] Should not reach here. Type is %d ...\n", pId[index].Field.Type);
            return INT_STATUS_NOT_SUPPORTED;
        }

        }

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntExceptVerifySignature failed for signature type %d with status: 0x%08x\n",
                  pId[index].Field.Type, status);
            *Reason = introReasonInternalError;

            return status;
        }

        index++;
        while (index < count && pId[index].Field.Type == pId[index - 1].Field.Type)
        {
            index++;
        }
    }

    return INT_STATUS_SIGNATURE_MATCHED;
}


void
IntExceptDumpSignatures(
    _In_ void *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ BOOLEAN KernelMode,
    _In_ BOOLEAN ReturnDrv
    )
///
/// @brief Dump code blocks from the originator's RIP.
///
/// param[in] Originator    The originator of the current violation.
/// param[in] Victim        The internal structure of the modified zone.
/// param[in] KernelMode    True if the kernel-mode originator is given.
/// param[in] ReturnDrv     True if the kernel-mode originator has a return driver.
///
{
    INTSTATUS status;

    DWORD startOffset, endOffset, totalSize, i, csType;
    BOOLEAN execute = FALSE;
    BYTE *pCode = NULL;

    QWORD rip;

    if (NULL == Originator)
    {
        return;
    }

    status = IntGetCurrentMode(IG_CURRENT_VCPU, &csType);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentMode failed: 0x%08x\n", status);
        return;
    }

    if ((csType != IG_CS_TYPE_32B) && (csType != IG_CS_TYPE_64B))
    {
        ERROR("[ERROR] Unsupported CS type: %d\n", csType);
        return;
    }

    if (KernelMode)
    {
        if (ReturnDrv)
        {
            rip = ((EXCEPTION_KM_ORIGINATOR *)Originator)->Return.Rip;
        }
        else
        {
            rip = ((EXCEPTION_KM_ORIGINATOR *)Originator)->Original.Rip;
        }
    }
    else
    {
        rip = ((EXCEPTION_UM_ORIGINATOR *)Originator)->Rip;
        execute = ((EXCEPTION_UM_ORIGINATOR *)Originator)->Execute;
    }

    if (0 == rip)
    {
        return;
    }

    // See if we dumped this already
    for (i = 0; i < ARRAYSIZE(gUsedRips); i++)
    {
        if (gUsedRips[i] == rip)
        {
            return;
        }
    }

    // Now add it to the list, if we can
    for (i = 0; i < ARRAYSIZE(gUsedRips); i++)
    {
        if (gUsedRips[i] == 0)
        {
            gUsedRips[i] = rip;
            break;
        }
    }

    // Make sure the totalSize is 2 * EXCEPTION_CODEBLOCKS_OFFSET, and to remain in the same page. Eg:
    // RipOffset = 0xf31 => [0xc00, 0xfff]
    // RipOffset = 0x123 => [0x000, 0x3ff]
    // RipOffset = 0x523 => [0x323, 0x722]

    startOffset = endOffset = rip & PAGE_OFFSET;

    if (!execute)
    {
        // endOffset = MIN(endOffset + EXCEPTION_CODEBLOCKS_OFFSET, PAGE_SIZE - 1);
        // startOffset = MIN(0, (int)(endOffset - EXCEPTION_CODEBLOCKS_OFFSET));

        if (startOffset > EXCEPTION_CODEBLOCKS_OFFSET)
        {
            if (endOffset + EXCEPTION_CODEBLOCKS_OFFSET < PAGE_SIZE)
            {
                startOffset -= EXCEPTION_CODEBLOCKS_OFFSET;
                endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
            }
            else
            {
                startOffset = PAGE_SIZE - (EXCEPTION_CODEBLOCKS_OFFSET * 2);
                endOffset = PAGE_SIZE - 1;
            }

        }
        else
        {
            startOffset = 0;
            endOffset = (EXCEPTION_CODEBLOCKS_OFFSET * 2) - 1;
        }
    }
    else
    {
        endOffset += EXCEPTION_CODEBLOCKS_OFFSET - 1;
    }

    totalSize = endOffset - startOffset;

    if (KernelMode)
    {
        status = IntVirtMemMap((rip & PAGE_MASK) + startOffset, totalSize, gGuest.Mm.SystemCr3, 0, &pCode);
    }
    else
    {
        QWORD cr3 = 0;

        if (gGuest.OSType == introGuestWindows)
        {
            cr3 = ((EXCEPTION_UM_ORIGINATOR *)Originator)->WinProc->Cr3;
        }
        else if (gGuest.OSType == introGuestLinux)
        {
            cr3 = ((EXCEPTION_UM_ORIGINATOR *)Originator)->LixProc->Cr3;
        }

        status = IntVirtMemMap((rip & PAGE_MASK) + startOffset, totalSize, cr3, 0, &pCode);
        if (!INT_SUCCESS(status) && execute)
        {
            WARNING("[WARNING] Failed to map range [0x%016llx - 0x%016llx], try to map range [0x%016llx - 0x%016llx]\n",
                    (rip & PAGE_MASK) + startOffset, (rip & PAGE_MASK) + startOffset + totalSize,
                    (rip & PAGE_MASK) + startOffset,  (rip & PAGE_MASK) + startOffset + (PAGE_SIZE - startOffset));

            status = IntVirtMemMap((rip & PAGE_MASK) + startOffset, PAGE_SIZE - startOffset, cr3, 0, &pCode);
            if (INT_SUCCESS(status))
            {
                totalSize = PAGE_SIZE - startOffset;
            }
        }
    }

    if (!INT_SUCCESS(status) && (Victim->ZoneFlags & ZONE_DEP_EXECUTION) == 0)
    {
        ERROR("[ERROR] Failed mapping VA 0x%016llx to host: 0x%08x\n", rip & PAGE_MASK, status);
        goto _clean_and_leave;
    }
    else if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed mapping VA 0x%016llx to host: 0x%08x\n", rip & PAGE_MASK, status);
        goto _clean_and_leave;
    }

    status = IntFragDumpBlocks(pCode,
                               (rip & PAGE_MASK) + startOffset,
                               totalSize,
                               csType,
                               KernelMode ? cbLevelNormal : cbLevelMedium,
                               rip,
                               KernelMode ? ReturnDrv : FALSE);

    IntDumpBuffer(pCode, (rip & PAGE_MASK) + startOffset, totalSize, 16, sizeof(BYTE), TRUE, TRUE);

    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed extracting blocks from VA 0x%016llx: 0x%08x\n", rip, status);
        goto _clean_and_leave;
    }

_clean_and_leave:
    if (NULL != pCode)
    {
        IntVirtMemUnmap(&pCode);
    }
}


INTSTATUS
IntExceptMatchException(
    _In_ void *Victim,
    _In_ void *Originator,
    _In_ void *Exception,
    _In_ EXCEPTION_TYPE ExceptionType,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief This function tries to find a exception for the current violation..
///
/// This mechanism has three steps:
///     1. check the victim flags and the modified object
///     2. check the victim init/child flags
///     3. check if any signature match the originator
///
/// @param[in]  Exception           The current exception to check.
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Victim              The current victim to check.
/// @param[in]  ExceptionType       The type of the exception #EXCEPTION_TYPE.
/// @param[out] Reason              The action that was taken.
/// @param[out] Action              The reason for which Action was taken.
///
/// @retval #INT_STATUS_NOT_SUPPORTED         If the exception type is invalid
/// @retval #INT_STATUS_EXCEPTION_ALLOW       If the exception matched
/// @retval #INT_STATUS_EXCEPTION_NOT_MATCHED If no exception matched
///
{
    INTSTATUS status;
    BOOLEAN feedbackException, linuxException;

    switch (ExceptionType)
    {
    case exceptionTypeKm:
        feedbackException = (((KM_EXCEPTION *)Exception)->Flags & EXCEPTION_FLG_FEEDBACK) != 0;
        linuxException = (((KM_EXCEPTION *)Exception)->Flags & EXCEPTION_FLG_LINUX) != 0;
        break;

    case exceptionTypeUm:
        feedbackException = (((UM_EXCEPTION *)Exception)->Flags & EXCEPTION_FLG_FEEDBACK) != 0;
        linuxException = (((UM_EXCEPTION *)Exception)->Flags & EXCEPTION_FLG_LINUX) != 0;
        break;

    case exceptionTypeUmGlob:
        feedbackException = (((UM_EXCEPTION_GLOB *)Exception)->Flags & EXCEPTION_FLG_FEEDBACK) != 0;
        linuxException = (((UM_EXCEPTION_GLOB *)Exception)->Flags & EXCEPTION_FLG_LINUX) != 0;
        break;

    case exceptionTypeKmUm:
        feedbackException = (((KUM_EXCEPTION *)Exception)->Flags & EXCEPTION_FLG_FEEDBACK) != 0;
        linuxException = (((KUM_EXCEPTION *)Exception)->Flags & EXCEPTION_FLG_LINUX) != 0;
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if ((linuxException && (gGuest.OSType != introGuestLinux)) ||
        (!linuxException && (gGuest.OSType == introGuestLinux)))
    {
        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }

    // 1. Check if the exception is matching at type, flags, and name.
    switch (ExceptionType)
    {
    case exceptionTypeKm:
        status = IntExceptKernelMatchVictim(Victim, Originator, Exception);
        break;

    case exceptionTypeUm:
    case exceptionTypeUmGlob:
        status = IntExceptUserMatchVictim(Victim, Originator, Exception, ExceptionType);
        break;

    case exceptionTypeKmUm:
        status = IntExceptKernelUserMatchVictim(Victim, Originator, Exception);
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (status == INT_STATUS_EXCEPTION_NOT_MATCHED)
    {
        // In this case don't overwrite the Action and Reason. If another exception was found and it failed
        // at extra checks or signature, then return that action&reason. Anyway, if no exception matched, then
        // we can safely return the default values (introGuestNotAllowed, introReasonNoException).
        return status;
    }
    else if (status == INT_STATUS_EXCEPTION_ALLOW)
    {
        *Action = introGuestAllowed;
        *Reason = feedbackException ? introReasonAllowedFeedback : introReasonAllowed;
    }
    else
    {
        ERROR("[ERROR] IntExceptMatchVictim `%d` failed: 0x%08x. Will ignore this exception!\n",
              ExceptionType, status);

        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;

        return status;
    }

    // 2. Do we have any extra thing to verify (like the imports, exports, etc.) ?
    switch (ExceptionType)
    {
    case exceptionTypeKm:
        status = IntExceptKernelVerifyExtra(Victim, Originator, Exception);
        break;

    case exceptionTypeUm:
        status = IntExceptUserVerifyExtra(Victim, Originator, Exception);
        break;

    case exceptionTypeUmGlob:
        status = IntExceptUserVerifyExtraGlobMatch(Victim, Originator, Exception);
        break;

    case exceptionTypeKmUm:
        status = IntExceptKernelUserVerifyExtra(Victim, Originator, Exception);
        break;

    default:
        ERROR("[ERROR] Shouldn't reach here. Type is %d ...\n", ExceptionType);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (status == INT_STATUS_EXCEPTION_CHECKS_FAILED)
    {
        *Action = introGuestNotAllowed;

        // Checks have more priority than exception searching. But not more than signatures!
        if (*Reason != introReasonSignatureNotMatched)
        {
            *Reason = introReasonExtraChecksFailed;
        }

        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }
    else if (status == INT_STATUS_EXCEPTION_CHECKS_OK)
    {
        *Action = introGuestAllowed;
        *Reason = feedbackException ? introReasonAllowedFeedback : introReasonAllowed;
    }
    else
    {
        ERROR("[ERROR] IntExceptVerfiyExtra Type: `%d` failed: 0x%08x. Will ignore this exception!\n",
              ExceptionType, status);

        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;

        return status;
    }

    // 3. Check the signature
    status = IntExceptVerifySignature(Exception, Originator, Victim, ExceptionType, Reason);
    if (status == INT_STATUS_SIGNATURE_NOT_FOUND)
    {
        // Signatures have the most priority. We overwrite the action every time.
        *Action = introGuestNotAllowed;

        return INT_STATUS_EXCEPTION_NOT_MATCHED;
    }
    else if (status == INT_STATUS_SIGNATURE_MATCHED)
    {
        *Action = introGuestAllowed;
        *Reason = feedbackException ? introReasonAllowedFeedback : introReasonAllowed;
    }
    else
    {
        ERROR("[ERROR] IntExceptVerifySignature failed: 0x%08x. Will ignore this exception!\n", status);

        *Action = introGuestNotAllowed;
        *Reason = introReasonInternalError;

        return status;
    }

    // If we get to this point, then allow the action
    return INT_STATUS_EXCEPTION_ALLOW;
}


void
IntExcept(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ void *Originator,
    _In_ EXCEPTION_TYPE Type,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason,
    _In_ INTRO_EVENT_TYPE EventClass
    )
///
/// @brief This function is the entry point for the exception mechanism.
///
/// This will dispatch the exception checking to the appropriate function, depending if we are in user-mode or
/// kernel-mode. It will also serialize the exception.
///
/// @param[in]  Originator          The originator structure used by the exceptions mechanism.
/// @param[in]  Victim              The current victim to check.
/// @param[in]  Type                The exception type.
/// @param[out] Reason              The reason for which Action was taken.
/// @param[out] Action              The action that was taken.
/// @param[in]  EventClass          The event type for which this function is called. This is needed by the serializer.
///
{
    INTSTATUS status;
    static BOOLEAN showNotLoadedWarning = TRUE;

    UNREFERENCED_PARAMETER(EventClass);

    if (Action != NULL)
    {
        *Action = introGuestNotAllowed;
    }

    if (Reason != NULL)
    {
        *Reason = introReasonInternalError;
    }

    if (NULL == Victim)
    {
        ERROR("[ERROR] The 'Victim' argument for exceptions mechanism is invalid!\n");
        return;
    }

    if (NULL == Originator)
    {
        ERROR("[ERROR] The 'Originator' argument for exceptions mechanism is invalid!\n");
        return;
    }

    if (NULL == Action)
    {
        ERROR("[ERROR] The 'Action' argument for exceptions mechanism is invalid!\n");
        return;
    }

    if (NULL == Reason)
    {
        ERROR("[ERROR] The 'Reason' argument for exceptions mechanism is invalid!\n");
        return;
    }

    // Default values. If beta is enabled, let the caller handle that
    *Action = introGuestNotAllowed;
    *Reason = introReasonNoException;

    if (NULL == gGuest.Exceptions || !gGuest.Exceptions->Loaded)
    {
        if (showNotLoadedWarning)
        {
            LOG("**************************************************\n");
            LOG("************Exceptions are not loaded*************\n");
            LOG("**************************************************\n");

            showNotLoadedWarning = FALSE;
        }

        *Action = introGuestAllowed;
        *Reason = introReasonExceptionsNotLoaded;
        return;
    }

    switch(Type)
    {
        case exceptionTypeKm:
            status = IntExceptKernel(Victim, Originator, Action, Reason);
            break;
        case exceptionTypeUm:
            status = IntExceptUser(Victim, Originator, Action, Reason);
            break;
        case exceptionTypeKmUm:
            status = IntExceptKernelUser(Victim, Originator, Action, Reason);
            break;

        default:
            ERROR("[ERROR] Invalid exception type (%d)...\n", Type);
            return;
    }

    if (status != INT_STATUS_EXCEPTION_NOT_MATCHED && !INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExcept failed for type %d with status: 0x%08x . Will ignore this exception!\n", Type, status);
    }

    switch(Type)
    {
        case exceptionTypeKm:
            IntExceptKernelLogInformation(Victim, Originator, *Action, *Reason);
            break;
        case exceptionTypeUm:
            IntExceptUserLogInformation(Victim, Originator, *Action, *Reason);
            break;

        case exceptionTypeKmUm:
            IntExceptKernelUserLogInformation(Victim, Originator, *Action, *Reason);
            break;

        default:
            ERROR("[ERROR] Invalid exception type (%d)...\n", Type);
            break;
    }

    // IntSerializeException(Victim, Originator, Type, *Action, *Reason, EventClass);

    if (Victim->ZoneType == exceptionZoneEpt)
    {
        IntExceptInvCbCacheByGva(Victim->Ept.Gva);
    }
    else if (Victim->ZoneType == exceptionZoneIntegrity)
    {
        IntExceptInvCbCacheByGva(Victim->Integrity.StartVirtualAddress);
    }
}
