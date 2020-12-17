/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       update_guests.c
/// @brief      The CAMI parser.
/// @ingroup    group_guest_support
///

#include "update_guests.h"
#include "introdefs.h"
#include "introstatus.h"
#include "winapi.h"
#include "guests.h"
#include "winprocess.h"
#include "lixprocess.h"
#include "introcrt.h"

/// @brief The version of the loaded update file.
static CAMI_VERSION gCamiVersion = { 0 };

/// @brief The buffer holding the update file.
static const BYTE *gUpdateBuffer = NULL;

/// @brief The size of the update buffer.
static DWORD gUpdateBufferSize = 0;

/// @brief Pointer to the syscall signatures that will be loaded from the update buffer.
extern PATTERN_SIGNATURE *gSysenterSignatures;

/// @brief Holds the number of loaded syscall signatures.
extern DWORD gSysenterSignaturesCount;

/// @brief Pointer to the linux distribution signatures that will be loaded from the update buffer.
extern PATTERN_SIGNATURE *gLinuxDistSigs;

/// @brief Holds the number of loaded linux distribution signatures.
extern DWORD gLinuxDistSigsCount;

/// @brief The HVI version. Used to check for compatibility issues with the cami version.
extern INT_VERSION_INFO IntHviVersion;


/// @brief Check whether a file offset overflows the update buffer.
#define IS_CAMI_FILEOFFSET_OK(FileOffset)   __likely((FileOffset) < gUpdateBufferSize)

/// @brief Check whether a file pointer resides inside the update buffer.
#define IS_CAMI_FILEPOINTER_OK(FilePointer) __likely((const BYTE*)(FilePointer) >= (const BYTE*)gUpdateBuffer) && \
                                                    ((const BYTE*)(FilePointer) < (const BYTE*)gUpdateBuffer + \
                                                                                    gUpdateBufferSize)

/// @brief Check whether a whole structure resides inside the update buffer.
#define IS_CAMI_STRUCTURE_OK(FilePointer)   __likely(IS_CAMI_FILEPOINTER_OK(FilePointer) && \
                                                     IS_CAMI_FILEPOINTER_OK(((const BYTE*)((FilePointer) + 1) - 1)))

/// @brief Check whether a whole array resides inside the update buffer.
#define IS_CAMI_ARRAY_OK(StartPointer, Count)   __likely(IS_CAMI_FILEPOINTER_OK(StartPointer) && \
                                                        ((Count) < CAMI_MAX_ENTRY_COUNT) && \
                                                        (((DWORD)(Count) == 0) || \
                                                        (IS_CAMI_FILEPOINTER_OK((const BYTE*)((StartPointer) + \
                                                                                    (DWORD)(Count)) - 1))))

/// @brief Get a CAMI structure from an update buffer.
///
/// @param[in]  Type    The type of the structure. It should be a pointer to a constant structure.
/// @param[in]  Offset  The offset at which the structure is found.
///
/// @returns    The structure.
#define GET_CAMI_STRUCT(Type, Offset)           ((Type)(const void *)((const BYTE*)gUpdateBuffer + (DWORD)(Offset)))

/// @brief Describe the way we load the guest offsets from the update buffer.
typedef struct _CAMI_STRUCTURE
{
    /// @brief Specifies which opaque field structure to load.
    ///
    /// This can be any of the #WIN_UM_STRUCTURE, #WIN_KM_STRUCTURE, or #LIX_STRUCTURE.
    ///
    DWORD   StructureTag;

    /// @brief Offset of the structure to be loaded inside the OpaqueFields.
    ///
    /// This can be the offset of any #LIX_OPAQUE_FIELDS.OpaqueFields for Linux guests,
    /// an offset inside #WIN_OPAQUE_FIELDS.Km or #WIN_OPAQUE_FIELDS.Um for windows guests.
    ///
    size_t  Offset;

    /// @brief The number of fields to be loaded.
    DWORD   MembersCount;
} CAMI_STRUCTURE;

/// @brief Describe process protection options.
typedef struct _CAMI_PROCESS_PROTECTION_INFO
{
    struct
    {
        union
        {
            WCHAR    Name16[32];        ///< The process name as a wide char string.
            CHAR     Name8[64];         ///< The process name as a char string.
        };

        CAMI_STRING_ENCODING Encoding;  ///< Encoding of the name.
    } Name;                             ///< The process name.

    CAMI_PROT_OPTIONS   Options;        ///< Specifies the process protection.
} CAMI_PROCESS_PROTECTION_INFO, *PCAMI_PROCESS_PROTECTION_INFO;

/// @brief Describe a list of process protection options.
typedef struct _CAMI_PROCESS_PROTECTION_DATA
{
    DWORD                           Count;  ///< The number of elements in #Items.
    CAMI_PROCESS_PROTECTION_INFO    *Items; ///< Array of process protection options.
} CAMI_PROCESS_PROTECTION_DATA, *PCAMI_PROCESS_PROTECTION_DATA;


/// @brief Loaded process protection data from CAMI.
static CAMI_PROCESS_PROTECTION_DATA gCamiProcessProtectionData;

/// @brief Describe the Linux fields to be loaded from the update buffer.
static const CAMI_STRUCTURE gLinuxStructures[lixStructureEnd] =
{
    {.StructureTag = lixStructureInfo,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Info),
     .MembersCount = lixFieldInfoEnd},

    {.StructureTag = lixStructureModule,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Module),
     .MembersCount = lixFieldModuleEnd},

    {.StructureTag = lixStructureBinprm,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Binprm),
     .MembersCount = lixFieldBinprmEnd},

    {.StructureTag = lixStructureVma,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Vma),
     .MembersCount = lixFieldVmaEnd},

    {.StructureTag = lixStructureDentry,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Dentry),
     .MembersCount = lixFieldDentryEnd},

    {.StructureTag = lixStructureMmStruct,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.MmStruct),
     .MembersCount = lixFieldMmStructEnd},

    {.StructureTag = lixStructureTaskStruct,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.TaskStruct),
     .MembersCount = lixFieldTaskStructEnd},

    {.StructureTag = lixStructureFs,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Fs),
     .MembersCount = lixFieldFsEnd},

    {.StructureTag = lixStructureFdTable,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.FdTable),
     .MembersCount = lixFieldFdTableEnd},

    {.StructureTag = lixStructureFiles,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Files),
     .MembersCount = lixFieldFilesEnd},

    {.StructureTag = lixStructureInode,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Inode),
     .MembersCount = lixFieldInodeEnd},

    {.StructureTag = lixStructureSocket,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Socket),
     .MembersCount = lixFieldSocketEnd},

    {.StructureTag = lixStructureSock,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Sock),
     .MembersCount = lixFieldSockEnd},

    {.StructureTag = lixStructureCred,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Cred),
     .MembersCount = lixFieldCredEnd},

    {.StructureTag = lixStructureNsProxy,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.NsProxy),
     .MembersCount = lixFieldNsProxyEnd},

    {.StructureTag = lixStructureUngrouped,
     .Offset = OFFSET_OF(LINUX_GUEST, OsSpecificFields.OpaqueFields.Ungrouped),
     .MembersCount = lixFieldUngroupedEnd},
};

/// @brief Describe the windows km fields to be loaded from the update buffer.
static const CAMI_STRUCTURE gWinKmStructures[winKmStructureEnd] =
{
    {.StructureTag = winKmStructureProcess,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.Process),
     .MembersCount = winKmFieldProcessEnd},

    {.StructureTag = winKmStructureThread,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.Thread),
     .MembersCount = winKmFieldThreadEnd},

    {.StructureTag = winKmStructureDrvObj,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.DrvObj),
     .MembersCount = winKmFieldDrvObjEnd},

    {.StructureTag = winKmStructurePcr,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.Pcr),
     .MembersCount = winKmFieldPcrEnd},

    {.StructureTag = winKmStructurePoolDescriptor,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.PoolDescriptor),
     .MembersCount = winKmFieldPoolDescriptorEnd},

    {.StructureTag = winKmStructureMmpfn,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.Mmpfn),
     .MembersCount = winKmFieldMmpfnEnd},

    {.StructureTag = winKmStructureToken,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.Token),
     .MembersCount = winKmFieldTokenEnd},

    {.StructureTag = winKmStructureUngrouped,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.Ungrouped),
     .MembersCount = winKmFieldUngroupedEnd},

    {.StructureTag = winKmStructureEprocessFlags,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.EprocessFlags),
     .MembersCount = winKmFieldEprocessFlagsEnd},

    {.StructureTag = winKmStructureVadShort,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.VadShort),
     .MembersCount = winKmFieldVadShortEnd},

    {.StructureTag = winKmStructureVadLong,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.VadLong),
     .MembersCount = winKmFieldVadLongEnd},

    {.StructureTag = winKmStructureVadFlags,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.VadFlags),
     .MembersCount = winKmFieldVadFlagsEnd},

    {.StructureTag = winKmStructureSyscallNumbers,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.SyscallNumbers),
     .MembersCount = winKmFieldSyscallNumbersEnd},

    {.StructureTag = winKmStructureFileObject,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Km.FileObject),
     .MembersCount = winKmFieldFileObjectEnd},
};

/// @brief Describe the windows um fields to be loaded from the update buffer.
static const CAMI_STRUCTURE gWinUmStructures[winUmStructureEnd] =
{
    {.StructureTag = winUmStructureDll,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Um.Dll),
     .MembersCount = winUmFieldDllEnd },

    {.StructureTag = winUmStructurePeb,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Um.Peb),
     .MembersCount = winUmFieldPebEnd },

    {.StructureTag = winUmStructureTeb,
     .Offset = OFFSET_OF(WINDOWS_GUEST, OsSpecificFields.Um.Teb),
     .MembersCount = winUmFieldTebEnd },
};


static BOOLEAN
IntCamiCheckIntroVersion(
    _In_ QWORD MinIntroVersion,
    _In_ QWORD MaxIntroVersion
    )
///
/// @brief Check if the CAMI buffer is compatible with the Intro version.
///
/// @returns TRUE if they are compatible, FALSE otherwise.
///
{
    INT_VERSION_INFO minVer, maxVer;

    minVer.Raw = MinIntroVersion;
    maxVer.Raw = MaxIntroVersion;

    // Make sure we don't compare build numbers.
    minVer.VersionInfo.Build = 0;
    maxVer.VersionInfo.Build = WORD_MAX;

    return IntHviVersion.Raw >= minVer.Raw && IntHviVersion.Raw <= maxVer.Raw;
}


static const CAMI_SECTION_HEADER *
IntCamiFindSectionHeaderByHint(
    _In_ const CAMI_HEADER *CamiHeader,
    _In_ DWORD SectionHint
    )
///
/// @brief Iterate through all of the section headers from the update buffer and
/// return the one matching the hint.
///
/// @param[in] CamiHeader   The CAMI header from the update buffer.
/// @param[in] SectionHint  Specifies which section to search for.
///
/// @returns The #CAMI_SECTION_HEADER desired if found, NULL otherwise.
///
{
    const CAMI_SECTION_HEADER *pHeaders;

    pHeaders = GET_CAMI_STRUCT(const CAMI_SECTION_HEADER *, CamiHeader->PointerToSectionsHeaders);
    if (!IS_CAMI_ARRAY_OK(pHeaders, CamiHeader->NumberOfSections))
    {
        ERROR("[ERROR] Sections table entries are outside the update buffer!\n");
        return NULL;
    }

    for (DWORD i = 0; i < CamiHeader->NumberOfSections; i++)
    {
        if ((pHeaders[i].Hint & SectionHint) == SectionHint)
        {
            return (pHeaders + i);
        }
    }

    return NULL;
}


static INTSTATUS
IntCamiLoadOpaqueFields(
    _In_ const CAMI_OPAQUE_STRUCTURE *CamiStructures,
    _In_ const CAMI_STRUCTURE *ToLoad,
    _In_ DWORD Count,
    _In_ INTRO_GUEST_TYPE OsType
    )
///
/// @brief Load a set of opaque filed offsets from the update buffer.
///
/// @param[in] CamiStructures   Pointer to the CAMI structure holding the offsets.
/// @param[in] ToLoad           Specifies which fields to be loaded and how.
/// @param[in] Count            Specifies how may fields to be loaded.
/// @param[in] OsType           Specifies the OS for which these should be loaded.
///
/// @retval #INT_STATUS_SUCCESS             On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_4 If the OsType is not supported.
/// @retval #INT_STATUS_NOT_SUPPORTED       If the number of fields from the update is less
///                                         than the required number of fields.
/// @retval #INT_STATUS_INVALID_DATA_SIZE   If the fields array overflows the buffer.
///
{
    char *pBasePtr = NULL;

    switch (OsType)
    {
    case introGuestLinux:
        pBasePtr = (char *)gLixGuest;
        break;

    case introGuestWindows:
        pBasePtr = (char *)gWinGuest;
        break;

    default:
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    for (DWORD iStruct = 0; iStruct < Count; iStruct++)
    {
        const DWORD *pFields;

        if (CamiStructures->MembersCount < ToLoad->MembersCount)
        {
            ERROR("[ERROR] For structure %d we need at least %d fields, got only %d\n",
                  iStruct, ToLoad->MembersCount, CamiStructures->MembersCount);
            return INT_STATUS_NOT_SUPPORTED;
        }

        pFields = GET_CAMI_STRUCT(const DWORD *, CamiStructures->Members);
        if (!IS_CAMI_ARRAY_OK(pFields, CamiStructures->MembersCount))
        {
            ERROR("[ERROR] Members for structure %d are outside the update buffer!\n", iStruct);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        memcpy(pBasePtr + ToLoad->Offset, pFields, sizeof(DWORD) * ToLoad->MembersCount);

        CamiStructures++;
        ToLoad++;
    }

    return INT_STATUS_SUCCESS;

}


static INTSTATUS
IntCamiLoadPatternSignatures(
    _In_ const CAMI_SECTION_HEADER *SectionHeader,
    _Out_ PATTERN_SIGNATURE **PatternSignatures,
    _Out_ DWORD *PatternSignaturesCount
    )
///
/// @brief Allocate and load pattern signatures.
///
/// @param[in] SectionHeader            Header of the section holding the patterns.
/// @param[out] PatternSignatures       Will hold the newly allocated memory range holding the patterns.
/// @param[out] PatternSignaturesCount  Will hold the number of loaded pattern signatures.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_PATTERN_SIGNATURE *pCamiSignatures;

    pCamiSignatures = GET_CAMI_STRUCT(const CAMI_PATTERN_SIGNATURE *, SectionHeader->DescriptorTable);
    if (!IS_CAMI_ARRAY_OK(pCamiSignatures, SectionHeader->EntryCount))
    {
        LOG("[ERROR] Pattern signature descriptors are outside the update buffer!");
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    if (SectionHeader->EntryCount == 0)
    {
        ERROR("[ERROR] Invalid entry count for the pattern signature array: %u\n", SectionHeader->EntryCount);
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    *PatternSignatures = HpAllocWithTag(sizeof(PATTERN_SIGNATURE) * SectionHeader->EntryCount, IC_TAG_CAMI);
    if (NULL == *PatternSignatures)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    *PatternSignaturesCount = 0;

    for (DWORD i = 0; i < SectionHeader->EntryCount; i++)
    {
        const CAMI_PATTERN_SIGNATURE *pCamiPat;
        PPATTERN_SIGNATURE pPat;
        const WORD *pPatternHash;

        pCamiPat = pCamiSignatures + i;
        pPat = *PatternSignatures + i;

        pPatternHash = GET_CAMI_STRUCT(const WORD *, pCamiPat->PatternOffset);
        if (!IS_CAMI_ARRAY_OK(pPatternHash, pCamiPat->PatternLength))
        {
            ERROR("[ERROR] Hash for signature %d is outside the update buffer!\n", i);

            HpFreeAndNullWithTag(PatternSignatures, IC_TAG_CAMI);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        pPat->SignatureId = pCamiPat->SignatureId;
        pPat->Offset = pCamiPat->Offset;
        pPat->Length = MIN(pCamiPat->PatternLength, ARRAYSIZE(pPat->Pattern));

        memcpy(pPat->Pattern, pPatternHash, pPat->Length * sizeof(pPat->Pattern[0]));
    }

    *PatternSignaturesCount = SectionHeader->EntryCount;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCamiLoadSyscalls(
    _In_ const CAMI_HEADER *CamiHeader
    )
///
/// @brief Loads the syscall signatures from their section.
///
/// @param[in] CamiHeader The CAMI header of the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;

    pSec = IntCamiFindSectionHeaderByHint(CamiHeader, CAMI_SECTION_HINT_SYSCALLS);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find syscalls section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    return IntCamiLoadPatternSignatures(pSec, &gSysenterSignatures, &gSysenterSignaturesCount);
}


static INTSTATUS
IntCamiLoadLixDistSigs(
    _In_ const CAMI_HEADER *CamiHeader
    )
///
/// @brief Loads the Linux distribution signatures from their section.
///
/// @param[in] CamiHeader The CAMI header of the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;

    pSec = IntCamiFindSectionHeaderByHint(CamiHeader, CAMI_SECTION_HINT_LINUX | CAMI_SECTION_HINT_DIST_SIG);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find syscalls section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    return IntCamiLoadPatternSignatures(pSec, &gLinuxDistSigs, &gLinuxDistSigsCount);
}


static void
IntCamiUpdateProtOptions(
    _In_ const CAMI_PROT_OPTIONS *Src,
    _Inout_ INTRO_PROT_OPTIONS *Dst
    )
///
/// @brief  Updates the current protection options.
///
/// @param[in]      Src The new protection options.
/// @param[in, out] Dst The current protection option to be updated.
///
{
    if (Dst->ForceOff != Src->ForceOff)
    {
        LOG("[CAMI] New force off options: 0x%016llx\n", Src->ForceOff);
    }

    Dst->ForceOff = Src->ForceOff;

    if (Dst->Beta != Src->ForceBeta)
    {
        LOG("[CAMI] New force beta options: 0x%016llx\n", Src->ForceBeta);
    }

    Dst->Beta = Src->ForceBeta;

    if (Dst->Feedback != Src->ForceFeedback)
    {
        LOG("[CAMI] New force feedback options: 0x%016llx\n", Src->ForceFeedback);
    }

    Dst->Feedback = Src->ForceFeedback;
}


static INTSTATUS
IntCamiSetCoreOptions(
    _In_ const CAMI_PROT_OPTIONS *Options
    )
///
/// @brief Update the guest protection flags using the ones from CAMI.
///
/// @param[in] Options The options received from the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    LOG("[CAMI] Will set new core options!\n");

    IntCamiUpdateProtOptions(Options, &gGuest.CoreOptions);

    IntGuestUpdateCoreOptions(gGuest.CoreOptions.Original);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCamiSetShemuOptions(
    _In_ const CAMI_PROT_OPTIONS *Options
    )
///
/// @brief Update the shemu flags using the ones from CAMI.
///
/// @param[in] Options The options received from the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    LOG("[CAMI] Will set new shemu options!\n");

    IntCamiUpdateProtOptions(Options, &gGuest.ShemuOptions);

    IntGuestUpdateShemuOptions(gGuest.ShemuOptions.Original);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCamiUpdateProcessProtectionInfoLix(
    _In_ LIX_PROTECTED_PROCESS *ProtectedProcess
    )
///
/// @brief Update a Linux process' protection flags using the ones from CAMI.
///
/// @param[in] ProtectedProcess Process whose protection flags to be updated.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    for (DWORD index = 0; index < gCamiProcessProtectionData.Count; index++)
    {
        BOOLEAN match = FALSE;
        if (gCamiProcessProtectionData.Items[index].Name.Encoding != CAMI_STRING_ENCODING_UTF8)
        {
            WARNING("[WARNING] Unsupported process name encoding: %d. Will skip...\n",
                    gCamiProcessProtectionData.Items[index].Name.Encoding);
        }
        else
        {
            if (IntMatchPatternUtf8(gCamiProcessProtectionData.Items[index].Name.Name8,
                                    ProtectedProcess->CommPattern,
                                    0))
            {
                match = TRUE;
            }
        }

        if (match)
        {
            ProtectedProcess->Protection.Current =
                ProtectedProcess->Protection.Original & ~(gCamiProcessProtectionData.Items[index].Options.ForceOff);
            ProtectedProcess->Protection.Beta = gCamiProcessProtectionData.Items[index].Options.ForceBeta;
            ProtectedProcess->Protection.Feedback = gCamiProcessProtectionData.Items[index].Options.ForceFeedback;

            TRACE("[CAMI] Protection options for '%s': %llx %llx %llx", ProtectedProcess->CommPattern,
                  ProtectedProcess->Protection.Current, ProtectedProcess->Protection.Beta,
                  ProtectedProcess->Protection.Feedback);
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCamiUpdateProcessProtectionInfoWin(
    _In_ PROTECTED_PROCESS_INFO *ProtectedProcess
    )
///
/// @brief Update a windows process' protection flags using the ones from CAMI.
///
/// @param[in] ProtectedProcess Process whose protection flags to be updated.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    for (DWORD index = 0; index < gCamiProcessProtectionData.Count; index++)
    {
        BOOLEAN match = FALSE;
        switch (gCamiProcessProtectionData.Items[index].Name.Encoding)
        {
        case CAMI_STRING_ENCODING_UTF16:
        {
            if (IntMatchPatternUtf16(gCamiProcessProtectionData.Items[index].Name.Name16,
                                     ProtectedProcess->FullNamePattern,
                                     0))
            {
                match = TRUE;
            }
            break;
        }
        case CAMI_STRING_ENCODING_UTF8:
        {
            if (IntMatchPatternUtf8(gCamiProcessProtectionData.Items[index].Name.Name8,
                                    ProtectedProcess->ImageBaseNamePattern,
                                    0))
            {
                match = TRUE;
            }
            break;
        }
        default:
        {
            WARNING("[WARNING] Unsupported process name encoding: %d. Will skip...\n",
                    gCamiProcessProtectionData.Items[index].Name.Encoding);
        }
        }

        if (match)
        {
            ProtectedProcess->Protection.Current =
                ProtectedProcess->Protection.Original & ~(gCamiProcessProtectionData.Items[index].Options.ForceOff);
            ProtectedProcess->Protection.Beta = gCamiProcessProtectionData.Items[index].Options.ForceBeta;
            ProtectedProcess->Protection.Feedback = gCamiProcessProtectionData.Items[index].Options.ForceFeedback;

            TRACE("[CAMI] Protection options for '%s': %x %llx %llx", ProtectedProcess->ImageBaseNamePattern,
                  ProtectedProcess->Protection.Current, ProtectedProcess->Protection.Beta,
                  ProtectedProcess->Protection.Feedback);

        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCamiUpdateProcessProtectionInfo(
    _In_ void *ProtectedProcess
    )
///
/// @brief Update a process' protection flags using the ones from CAMI.
///
/// @param[in] ProtectedProcess Process whose protection flags to be updated. Will be a #PROTECTED_PROCESS_INFO for
/// Windows guests and a #LIX_PROTECTED_PROCESS for Linux Guests.
///
/// @retval #INT_STATUS_SUCCESS         On success.
/// @retval #INT_STATUS_NOT_SUPPORTED   If the current guest is not supported.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        return IntCamiUpdateProcessProtectionInfoWin(ProtectedProcess);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntCamiUpdateProcessProtectionInfoLix(ProtectedProcess);
    }

    return INT_STATUS_NOT_SUPPORTED;
}


void
IntCamiUpdateProcessProtectionItems(
    _In_ void *Name,
    _In_ CAMI_STRING_ENCODING Encoding,
    _In_ CAMI_PROT_OPTIONS *Options
    )
///
/// @brief Update a protected process protection flags.
///
/// @param[in] Name     Name of the process.
/// @param[in] Encoding Encoding of Name. May be utf-8 or utf-16.
/// @param[in] Options  The new protection options.
///
{
    if (gGuest.OSType == introGuestWindows)
    {
        IntWinProcUpdateProtectedProcess(Name, Encoding, Options);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntLixProcUpdateProtectedProcess(Name, Encoding, Options);
    }
}


static INTSTATUS
IntCamiSetProcProtOptions(
    _In_ const CAMI_PROC_PROT_OPTIONS *Table,
    _In_ DWORD TableCount
    )
///
/// @brief Loads all the process protection flags from CAMI.
///
/// @param[in] Table        Array containing the protection options to be loaded.
/// @param[in] TableCount   Size of Table in elements.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    for (DWORD index = 0; index < TableCount; index++)
    {
        const CAMI_PROT_OPTIONS *pOptions = GET_CAMI_STRUCT(const CAMI_PROT_OPTIONS *, Table[index].OptionsOffset);
        if (!IS_CAMI_STRUCTURE_OK(pOptions))
        {
            ERROR("[ERROR] CAMI_PROT_OPTIONS struct is invalid! (%p)", pOptions);
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        memcpy(gCamiProcessProtectionData.Items[index].Name.Name8, Table[index].Name8, 64);
        gCamiProcessProtectionData.Items[index].Name.Encoding = Table[index].Encoding;
        gCamiProcessProtectionData.Items[index].Options = *pOptions;

        TRACE("[CAMI] NameHash : %s -> ForceOff : 0x%llx, ForceBeta: 0x%llx, ForceFeedback: 0x%llx",
              Table[index].Name8, pOptions->ForceOff, pOptions->ForceBeta, pOptions->ForceFeedback);

        IntCamiUpdateProcessProtectionItems(gCamiProcessProtectionData.Items[index].Name.Name8,
                                            gCamiProcessProtectionData.Items[index].Name.Encoding,
                                            &gCamiProcessProtectionData.Items[index].Options);
    }

    if (gGuest.OSType == introGuestWindows)
    {
        IntWinProcUpdateProtection();
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        IntLixTaskUpdateProtection();
    }
    else
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCamiResetCoreOptions(
    void
    )
///
/// Reset the Introcore guest options.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    const CAMI_PROT_OPTIONS defaultOpts = {0};

    return IntCamiSetCoreOptions(&defaultOpts);
}


static INTSTATUS
IntCamiResetShemuOptions(
    void
    )
///
/// Reset the Introcore shemu options.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    const CAMI_PROT_OPTIONS defaultOpts = {0};

    return IntCamiSetShemuOptions(&defaultOpts);
}


static INTSTATUS
IntCamiLoadOsOptions(
    _In_ DWORD OptionsFileOffset
    )
///
/// @brief Load custom protection options for the guest OS or for protected processes.
///
/// @param[in] OptionsFileOffset    File offset of a #CAMI_CUSTOM_OS_PROTECTION.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    INTSTATUS status;
    const CAMI_CUSTOM_OS_PROTECTION *pOsProt;
    const CAMI_PROT_OPTIONS *pCoreProtOpt, *pShemuProtOpt;

    if (0 == OptionsFileOffset)
    {
        IntCamiProtectedProcessFree();

        IntCamiResetCoreOptions();
        IntCamiResetShemuOptions();

        return INT_STATUS_SUCCESS;
    }

    pOsProt = GET_CAMI_STRUCT(const CAMI_CUSTOM_OS_PROTECTION *, OptionsFileOffset);
    if (!IS_CAMI_STRUCTURE_OK(pOsProt))
    {
        ERROR("[ERROR] Invalid file offset: %d / %d\n", OptionsFileOffset, gUpdateBufferSize);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    pCoreProtOpt = GET_CAMI_STRUCT(const CAMI_PROT_OPTIONS *, pOsProt->CoreOptionsOffset);
    if (!IS_CAMI_STRUCTURE_OK(pCoreProtOpt))
    {
        ERROR("[ERROR] Invalid file offset: %d / %d\n", pOsProt->CoreOptionsOffset, gUpdateBufferSize);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    pShemuProtOpt = GET_CAMI_STRUCT(const CAMI_PROT_OPTIONS *, pOsProt->ShemuOptionsOffset);
    if (!IS_CAMI_STRUCTURE_OK(pShemuProtOpt))
    {
        ERROR("[ERROR] Invalid file offset: %d / %d\n", pOsProt->ShemuOptionsOffset, gUpdateBufferSize);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    IntCamiProtectedProcessFree();

    if (pOsProt->ProcOptionsCount > 0)
    {
        const CAMI_PROC_PROT_OPTIONS *pProcProt = GET_CAMI_STRUCT(const CAMI_PROC_PROT_OPTIONS *,
                                                                  pOsProt->ProcOptionsTable);
        if (!IS_CAMI_ARRAY_OK(pProcProt, pOsProt->ProcOptionsCount))
        {
            ERROR("[ERROR] Invalid ProcOptionsTable : 0x%0x / %08x.\n", pOsProt->ProcOptionsTable, gUpdateBufferSize);
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        status = IntCamiProtectedProcessAllocate(pOsProt->ProcOptionsCount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCamiProtectedProcessAllocate failed with status: 0x%08x.", status);
            return status;
        }

        status = IntCamiSetProcProtOptions(pProcProt, pOsProt->ProcOptionsCount);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCamiSetProcProtOptions failed with status: 0x%08x.\n", status);
            return status;
        }
    }

    status = IntCamiSetCoreOptions(pCoreProtOpt);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCamiSetCoreOptions failed with status: 0x%08x.\n", status);
        return status;
    }

    status = IntCamiSetShemuOptions(pShemuProtOpt);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCamiSetShemuOptions failed with status: 0x%08x.\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntCamiLoadLinux(
    _In_ const CAMI_HEADER *CamiHeader
    )
///
/// @brief Loads all of the necessary information about the current windows guest
/// that is needed by intro to support it.
///
/// 1. Find the proper Linux descriptor from the update buffer.
/// 2. Check for Intro compatibility.
/// 3. Load all hookable functions and opaque structures.
/// 4. Load the enforced protection options.
///
/// @param[in] CamiHeader The CAMI header of the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;
    const CAMI_LIX_DESCRIPTOR *pLixOsList;
    INTSTATUS status;

    pSec = IntCamiFindSectionHeaderByHint(CamiHeader, CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_LINUX);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find Linux section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    pLixOsList = GET_CAMI_STRUCT(const CAMI_LIX_DESCRIPTOR *, pSec->DescriptorTable);
    if (!IS_CAMI_ARRAY_OK(pLixOsList, pSec->EntryCount))
    {
        ERROR("[ERROR] Linux supported OS descriptors are outside the update buffer!");
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    for (DWORD i = 0; i < pSec->EntryCount; i++)
    {
        const CAMI_LIX_DESCRIPTOR *pLix;
        const CAMI_LIX_HOOK *pHooks;
        const CAMI_OPAQUE_STRUCTURE *pStructures;

        pLix = pLixOsList + i;

        if (strnlen(pLix->VersionString, MAX_VERSION_STRING_SIZE) == MAX_VERSION_STRING_SIZE)
        {
            ERROR("[ERROR] Version string is not null terminated.");
            return INT_STATUS_CORRUPTED_DATA;
        }

        if (!glob_match_numeric_utf8(pLix->VersionString, gLixGuest->VersionString))
        {
            continue;
        }

        if (!IntCamiCheckIntroVersion(pLix->MinIntroVersion, pLix->MaxIntroVersion))
        {
            LOG("[WARNING] This OS is no longer supported by introcore!\n");
            continue;
        }

        if (lixStructureEnd > pLix->StructuresCount)
        {
            ERROR("[ERROR] Expected %d fields, got %d.", lixStructureEnd, pLix->StructuresCount);
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (pLix->HooksCount > LIX_MAX_HOOKED_FN_COUNT || pLix->HooksCount == 0)
        {
            ERROR("[ERROR] Unsupported number of hooks! Got %d, expected a max of %d!\n",
                  pLix->HooksCount, LIX_MAX_HOOKED_FN_COUNT);
            return INT_STATUS_NOT_SUPPORTED;
        }

        pStructures = GET_CAMI_STRUCT(const CAMI_OPAQUE_STRUCTURE *, pLix->StructuresTable);
        if (!IS_CAMI_ARRAY_OK(pStructures, pLix->StructuresCount))
        {
            ERROR("[ERROR] Fields for OS %s are outside the update buffer.", pLix->VersionString);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        pHooks = GET_CAMI_STRUCT(const CAMI_LIX_HOOK *, pLix->HooksTable);
        if (!IS_CAMI_ARRAY_OK(pHooks, pLix->HooksCount))
        {
            ERROR("[ERROR] Hooks for OS %s are outside the update buffer.", pLix->VersionString);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        status = IntCamiLoadOsOptions(pLix->CustomProtectionOffset);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to load introcore options for this OS. Status: 0x%08x\n", status);
            // Shall we bail out?
        }

        status = IntCamiLoadOpaqueFields(pStructures, gLinuxStructures, lixStructureEnd, introGuestLinux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCamiLoadOpaqueFields failed for linux fields. Status: 0x%08x\n", status);
            return status;
        }

        ASSERT(NULL == gLixGuest->OsSpecificFields.Functions);

        gLixGuest->OsSpecificFields.Functions =
            HpAllocWithTag(pLix->HooksCount * sizeof(gLixGuest->OsSpecificFields.Functions[0]), IC_TAG_CAMI);

        if (NULL == gLixGuest->OsSpecificFields.Functions)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        for (DWORD j = 0; j < pLix->HooksCount; j++)
        {
            LIX_FUNCTION *pFun = &gLixGuest->OsSpecificFields.Functions[j];

            pFun->NameHash = pHooks[j].NameHash;
            pFun->SkipOnBoot = pHooks[j].SkipOnBoot;
            pFun->HookHandler = pHooks[j].HookHandler;
        }

        gLixGuest->OsSpecificFields.FunctionsCount = pLix->HooksCount;

        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_SUPPORTED;
}


static INTSTATUS
IntCamiLoadWindows(
    _In_ const CAMI_HEADER *CamiHeader
    )
///
/// @brief Loads all of the necessary information about the current windows guest
/// that is needed by intro to support it.
///
/// 1. Find the proper windows descriptor from the update buffer.
/// 2. Check for Intro compatibility.
/// 3. Load all functions, opaque fields and version strings.
/// 4. Load the enforced protection options.
/// 5. Load all function patterns sent by CAMI and update the hook descriptors.
///
/// @param[in] CamiHeader The CAMI header of the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;
    const CAMI_WIN_DESCRIPTOR *pWinOsList;
    INTSTATUS status;

    pSec = IntCamiFindSectionHeaderByHint(CamiHeader, CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_WINDOWS);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find Windows section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    pWinOsList = GET_CAMI_STRUCT(const CAMI_WIN_DESCRIPTOR *, pSec->DescriptorTable);
    if (!IS_CAMI_ARRAY_OK(pWinOsList, pSec->EntryCount))
    {
        ERROR("[ERROR] Windows supported OS descriptors are outside the update buffer!");
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    for (DWORD i = 0; i < pSec->EntryCount; i++)
    {
        const CAMI_WIN_DESCRIPTOR *pWin;
        const CAMI_OPAQUE_STRUCTURE *pKmStructures, *pUmStructures;
        const CAMI_WIN_FUNCTION *pFunTable;
        const CAMI_WIN_VERSION_STRING *pCamiVersionString;

        pWin = pWinOsList + i;

        if (gGuest.OSVersion != pWin->BuildNumber ||
            gGuest.Guest64 != pWin->Is64 ||
            gGuest.KptiInstalled != pWin->Kpti)
        {
            continue;
        }

        if (!IntCamiCheckIntroVersion(pWin->MinIntroVersion, pWin->MaxIntroVersion))
        {
            LOG("[WARNING] This OS is no longer supported by introcore!\n");
            continue;
        }

        pFunTable = GET_CAMI_STRUCT(const CAMI_WIN_FUNCTION *, pWin->FunctionTable);
        if (!IS_CAMI_ARRAY_OK(pFunTable, pWin->FunctionCount))
        {
            ERROR("[ERROR] Functions for OS %d KPTI %d is64 %d are outside the update buffer. ",
                  pWin->BuildNumber, pWin->Kpti, pWin->Is64);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        pKmStructures = GET_CAMI_STRUCT(const CAMI_OPAQUE_STRUCTURE *, pWin->KmStructuresTable);
        if (!IS_CAMI_ARRAY_OK(pKmStructures, pWin->KmStructuresCount))
        {
            ERROR("[ERROR] Km Structures for OS %d KPTI %d is64 %d are outside the update buffer. \n",
                  pWin->BuildNumber, pWin->Kpti, pWin->Is64);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        pCamiVersionString = GET_CAMI_STRUCT(const CAMI_WIN_VERSION_STRING *, pWin->VersionStringOffset);
        if (!IS_CAMI_STRUCTURE_OK(pCamiVersionString))
        {
            ERROR("[ERROR] CAMI_WIN_VERSION_STRING struct is invalid! (%p)", pCamiVersionString);
            return INT_STATUS_INVALID_DATA_TYPE;
        }

        if (pCamiVersionString->VersionStringSize > MAX_VERSION_STRING_SIZE ||
            pCamiVersionString->VersionStringSize == 0)
        {
            ERROR("[ERROR] VersionString size is too big (%llx)\n", pCamiVersionString->VersionStringSize);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        gWinGuest->VersionString = HpAllocWithTag(pCamiVersionString->VersionStringSize, IC_TAG_NAME);
        if (NULL == gWinGuest->VersionString)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        strlcpy(gWinGuest->VersionString, pCamiVersionString->VersionString, pCamiVersionString->VersionStringSize);

        if (pCamiVersionString->ServerVersionStringSize > MAX_VERSION_STRING_SIZE ||
            pCamiVersionString->ServerVersionStringSize == 0)
        {
            ERROR("[ERROR] VersionString size is too big (%llx)\n", pCamiVersionString->ServerVersionStringSize);
            return INT_STATUS_INVALID_DATA_SIZE;
        }

        gWinGuest->ServerVersionString = HpAllocWithTag(pCamiVersionString->ServerVersionStringSize, IC_TAG_NAME);
        if (NULL == gWinGuest->ServerVersionString)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }

        strlcpy(gWinGuest->ServerVersionString, pCamiVersionString->ServerVersionString,
                pCamiVersionString->ServerVersionStringSize);

        pUmStructures = GET_CAMI_STRUCT(const CAMI_OPAQUE_STRUCTURE *, pWin->UmStructuresTable);
        if (!IS_CAMI_ARRAY_OK(pUmStructures, pWin->UmStructuresCount))
        {
            ERROR("[ERROR] Um Structures for OS %d KPTI %d is64 %d are outside the update buffer. \n",
                  pWin->BuildNumber, pWin->Kpti, pWin->Is64);
            return INT_STATUS_INVALID_DATA_STATE;
        }

        if (winKmStructureEnd > pWin->KmStructuresCount)
        {
            ERROR("[ERROR] Expected %d structures, got %d.", winKmStructureEnd, pWin->KmStructuresCount);
            return INT_STATUS_NOT_SUPPORTED;
        }

        if (winUmStructureEnd > pWin->UmStructuresCount)
        {
            ERROR("[ERROR] Expected %d structures, got %d.", winUmStructureEnd, pWin->UmStructuresCount);
            return INT_STATUS_NOT_SUPPORTED;
        }

        status = IntCamiLoadOsOptions(pWin->CustomProtectionOffset);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to load introcore options for this OS. Status: 0x%08x\n", status);
            // Shall we bail out?
        }

        status = IntCamiLoadOpaqueFields(pKmStructures, gWinKmStructures, winKmStructureEnd, introGuestWindows);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCamiLoadOpaqueFields failed for win km structures: 0x%08x\n", status);
            return status;
        }

        status = IntCamiLoadOpaqueFields(pUmStructures, gWinUmStructures, winUmStructureEnd, introGuestWindows);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCamiLoadOpaqueFields failed for win um structures: 0x%08x\n", status);
            return status;
        }

        for (DWORD j = 0; j < pWin->FunctionCount; j++)
        {
            PWIN_UNEXPORTED_FUNCTION pWf;
            const CAMI_WIN_FUNCTION_PATTERN *pPatterns;
            const DWORD *pArgs;

            pPatterns = GET_CAMI_STRUCT(const CAMI_WIN_FUNCTION_PATTERN *, pFunTable[j].PatternsTable);
            if (!IS_CAMI_ARRAY_OK(pPatterns, pFunTable[j].PatternsCount))
            {
                ERROR("[ERROR] Function %d has patterns outside the update buffer. \n", j);
                return INT_STATUS_INVALID_DATA_STATE;
            }

            pArgs = GET_CAMI_STRUCT(const DWORD *, pFunTable[j].ArgumentsTable);
            if (!IS_CAMI_ARRAY_OK(pArgs, pFunTable[j].ArgumentsCount))
            {
                ERROR("[ERROR] Function %d has arguments outside the update buffer. Will skip!\n", j);
                continue;
            }

            pWf = HpAllocWithTag(sizeof(*pWf) + pFunTable[j].PatternsCount * sizeof(pWf->Patterns[0]), IC_TAG_CAMI);
            if (NULL == pWf)
            {
                // Bail out if we ran out of memory, we won't be able to
                // load the rest anyway and we'll basically be useless
                // without function hooks...
                return INT_STATUS_INSUFFICIENT_RESOURCES;
            }

            for (DWORD k = 0; k < pFunTable[j].PatternsCount; k++)
            {
                const WORD *pPatHash;

                pPatHash = GET_CAMI_STRUCT(const WORD *, pPatterns[k].HashOffset);
                if (!IS_CAMI_ARRAY_OK(pPatHash, pPatterns[k].HashLength))
                {
                    ERROR("[ERROR] Hash for pattern %d of function 0x%x spills outside the update buffer. Will skip!",
                          k, pFunTable[j].NameHash);

                    status = INT_STATUS_INVALID_DATA_STATE;
                    goto _free_on_err;
                }

                if (pPatterns[k].Extended != 0)
                {
                    const CAMI_WIN_FUNCTION_PATTERN_EXTENSION *pPatEx;
                    const DWORD *pArgs2;

                    pPatEx = GET_CAMI_STRUCT(const CAMI_WIN_FUNCTION_PATTERN_EXTENSION*, pPatterns[k].Extended);
                    if (!IS_CAMI_STRUCTURE_OK(pPatEx))
                    {
                        ERROR("[ERROR] Extension for pattern %d (function 0x%x) spills outside the update buffer.\n",
                              k, pFunTable[j].NameHash);

                        status = INT_STATUS_INVALID_DATA_STATE;
                        goto _free_on_err;
                    }

                    pArgs2 = GET_CAMI_STRUCT(const DWORD *, pPatEx->ArgumentsTable);
                    if (!IS_CAMI_ARRAY_OK(pArgs2, pPatEx->ArgumentsCount))
                    {
                        ERROR("[ERROR] Arguments array for pattern %d (function 0x%x) are outside the update buffer\n",
                              k, pFunTable[j].NameHash);

                        status = INT_STATUS_INVALID_DATA_STATE;
                        goto _free_on_err;
                    }

                    if (pPatEx->ArgumentsCount > ARRAYSIZE(pWf->Patterns[k].Arguments.Argv))
                    {
                        ERROR("[ERROR] Too many arguments for pattern %d (function 0x%x)\n",
                              k, pFunTable[j].NameHash);

                        status = INT_STATUS_INVALID_DATA_STATE;
                        goto _free_on_err;
                    }

                    pWf->Patterns[k].Arguments.Argc = pPatEx->ArgumentsCount;
                    memcpy(pWf->Patterns[k].Arguments.Argv,
                           pArgs2,
                           sizeof(pWf->Patterns[k].Arguments.Argv[0]) * pPatEx->ArgumentsCount);
                }

                memcpy(pWf->Patterns[k].SectionHint, pPatterns[k].SectionHint, 8);

                pWf->Patterns[k].Signature.Length = MIN(SIG_MAX_PATTERN, pPatterns[k].HashLength);
                memcpy(pWf->Patterns[k].Signature.Pattern, pPatHash, 2ull * pWf->Patterns[k].Signature.Length);
            }

            status = INT_STATUS_SUCCESS;

_free_on_err:

            if (!INT_SUCCESS(status))
            {
                if (pWf != NULL)
                {
                    HpFreeAndNullWithTag(&pWf, IC_TAG_CAMI);
                }

                return status;
            }

            pWf->NameHash = pFunTable[j].NameHash;
            pWf->PatternsCount = pFunTable[j].PatternsCount;

            status = IntWinApiUpdateHookDescriptor(pWf, pFunTable[j].ArgumentsCount, pArgs);
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] Failed to add function %d %x to a hook descriptor: 0x%08x\n",
                        j, pFunTable[j].NameHash, status);
                HpFreeAndNullWithTag(&pWf, IC_TAG_CAMI);
            }
        }

        return INT_STATUS_SUCCESS;
    }

    return INT_STATUS_NOT_SUPPORTED;
}


static INTSTATUS
IntCamiLoadProtOptionsLinux(
    _In_ const CAMI_HEADER *CamiHeader
    )
///
/// @brief Load and apply all of the enforced protection options for Linux guests.
///
/// Will load and apply core protection options and process protection options.
///
/// @param[in] CamiHeader The CAMI header of the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;
    const CAMI_LIX_DESCRIPTOR *pLixOsList;
    INTSTATUS status;

    pSec = IntCamiFindSectionHeaderByHint(CamiHeader, CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_LINUX);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find Linux section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    pLixOsList = GET_CAMI_STRUCT(const CAMI_LIX_DESCRIPTOR *, pSec->DescriptorTable);
    if (!IS_CAMI_ARRAY_OK(pLixOsList, pSec->EntryCount))
    {
        ERROR("[ERROR] Linux supported OS descriptors are outside the update buffer!");
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    for (DWORD i = 0; i < pSec->EntryCount; i++)
    {
        const CAMI_LIX_DESCRIPTOR *pLix = pLixOsList + i;

        if (strnlen(pLix->VersionString, MAX_VERSION_STRING_SIZE) == MAX_VERSION_STRING_SIZE)
        {
            ERROR("[ERROR] Version string is not null terminated.");
            return INT_STATUS_CORRUPTED_DATA;
        }

        if (!glob_match_numeric_utf8(pLix->VersionString, gLixGuest->VersionString))
        {
            continue;
        }

        if (!IntCamiCheckIntroVersion(pLix->MinIntroVersion, pLix->MaxIntroVersion))
        {
            continue;
        }

        if (lixStructureEnd > pLix->StructuresCount)
        {
            ERROR("[ERROR] Expected %d fields, got %d.", lixStructureEnd, pLix->StructuresCount);
            return INT_STATUS_NOT_SUPPORTED;
        }

        status = IntCamiLoadOsOptions(pLix->CustomProtectionOffset);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to load introcore options for this OS. Status: 0x%08x\n", status);
        }

        return status;
    }

    return INT_STATUS_NOT_NEEDED_HINT;
}


static INTSTATUS
IntCamiLoadProtOptionsWin(
    _In_ const CAMI_HEADER *CamiHeader
    )
///
/// @brief Load and apply all of the enforced protection options for Windows guests.
///
/// Will load and apply core protection options and process protection options.
///
/// @param[in] CamiHeader The CAMI header of the update buffer.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;
    const CAMI_WIN_DESCRIPTOR *pWinOsList;
    INTSTATUS status;

    pSec = IntCamiFindSectionHeaderByHint(CamiHeader, CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_WINDOWS);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find windows section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    pWinOsList = GET_CAMI_STRUCT(const CAMI_WIN_DESCRIPTOR *, pSec->DescriptorTable);
    if (!IS_CAMI_ARRAY_OK(pWinOsList, pSec->EntryCount))
    {
        ERROR("[ERROR] Windows supported OS descriptors are outside the update buffer!");
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    for (DWORD i = 0; i < pSec->EntryCount; i++)
    {
        const CAMI_WIN_DESCRIPTOR *pWin = pWinOsList + i;

        if ((gGuest.OSVersion != pWin->BuildNumber) ||
            (gGuest.Guest64 != pWin->Is64) ||
            (gGuest.KptiInstalled != pWin->Kpti))
        {
            continue;
        }

        if (!IntCamiCheckIntroVersion(pWin->MinIntroVersion, pWin->MaxIntroVersion))
        {
            continue;
        }

        status = IntCamiLoadOsOptions(pWin->CustomProtectionOffset);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed to load introcore options for this OS: 0x%08x\n", status);
        }

        return status;
    }

    return INT_STATUS_NOT_NEEDED_HINT;
}


INTSTATUS
IntCamiGetWinSupportedList(
    _In_ BOOLEAN KptiInstalled,
    _In_ BOOLEAN Guest64,
    _Out_opt_ DWORD *NtBuildNumberList,
    _Inout_ DWORD *Count
    )
///
/// @brief Return a list of supported Windows NtBuildNumbers.
///
/// If NtBuildNumberList is NULL, Count will hold the number of elements
/// that NtBuildNumberList should be able to hold.
///
/// If it's not NULL, it will be filled with at most Count NtBuildNumbers
/// the list in the update buffer.
///
/// @param[in]     KptiInstalled        Specifies whether to load supported guests with or without KPTI patches.
/// @param[in]     Guest64              Specifies whether to load supported x86_64 guests or x86.
/// @param[out]    NtBuildNumberList    If NULL, ignored.
///                                     If not NULL, will hold a list of supported NtBuildNumbers.
/// @param[in,out] Count                If NtBuildNumberList is NULL, will hold the number of elements NtBuildNumberList
///                                     should hold. If NtBuildNumberList is not null, holds the maximum numbers of
///                                     elements to be loaded in it.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    const CAMI_SECTION_HEADER *pSec;
    const CAMI_WIN_DESCRIPTOR *pWinOsList;
    const CAMI_WIN_DESCRIPTOR *pWin;
    DWORD i, lastNt, cnt;

    if (NULL == Count)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL != NtBuildNumberList && 0 == *Count)
    {
        return INT_STATUS_INVALID_PARAMETER_MIX;
    }

    if (NULL == gUpdateBuffer || 0 == gUpdateBufferSize)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    pSec = IntCamiFindSectionHeaderByHint((const CAMI_HEADER *)gUpdateBuffer,
                                          CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_WINDOWS);
    if (NULL == pSec)
    {
        ERROR("[ERROR] Failed to find windows section header\n");
        return INT_STATUS_NOT_FOUND;
    }

    pWinOsList = GET_CAMI_STRUCT(const CAMI_WIN_DESCRIPTOR *, pSec->DescriptorTable);
    if (!IS_CAMI_ARRAY_OK(pWinOsList, pSec->EntryCount))
    {
        ERROR("[ERROR] Windows supported OS descriptors are outside the update buffer!");
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    lastNt = cnt = 0;
    // the OS list from CAMI is sorted by NtBuildNumber, so it's fine.
    for (i = 0; i < pSec->EntryCount; i++)
    {
        pWin = pWinOsList + i;

        if (!IntCamiCheckIntroVersion(pWin->MinIntroVersion, pWin->MaxIntroVersion) ||
            Guest64 != pWin->Is64 || KptiInstalled != pWin->Kpti)
        {
            continue;
        }

        if (pWin->BuildNumber != lastNt)
        {
            lastNt = pWin->BuildNumber;

            if (NULL != NtBuildNumberList)
            {
                if (cnt >= *Count)
                {
                    return INT_STATUS_SUCCESS;
                }

                NtBuildNumberList[cnt] = lastNt;
            }

            cnt++;
        }
    }

    *Count = cnt;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCamiLoadSection(
    _In_ DWORD CamiSectionHint
    )
///
/// @brief Load CAMI objects from section with given hint.
///
/// @param[in] CamiSectionHint Specifies the section from which to load.
///
/// @returns #INT_STATUS_SUCCESS or an appropriate #INTSTATUS error value.
///
{
    INTSTATUS status;
    const CAMI_HEADER *pCami;

    if (NULL == gUpdateBuffer || 0 == gUpdateBufferSize)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    pCami = (const CAMI_HEADER *)gUpdateBuffer;

    status = INT_STATUS_NOT_FOUND;
    if (CamiSectionHint & CAMI_SECTION_HINT_SUPPORTED_OS)
    {
        if (CamiSectionHint & CAMI_SECTION_HINT_WINDOWS)
        {
            status = IntCamiLoadWindows(pCami);
        }
        else if (CamiSectionHint & CAMI_SECTION_HINT_LINUX)
        {
            status = IntCamiLoadLinux(pCami);
        }
        else
        {
            return INT_STATUS_NOT_SUPPORTED;
        }
    }
    else if (CamiSectionHint & CAMI_SECTION_HINT_SYSCALLS)
    {
        status = IntCamiLoadSyscalls(pCami);
    }
    else if (CamiSectionHint & CAMI_SECTION_HINT_DIST_SIG)
    {
        if (CamiSectionHint & CAMI_SECTION_HINT_LINUX)
        {
            status = IntCamiLoadLixDistSigs(pCami);
        }
        else
        {
            status = INT_STATUS_NOT_SUPPORTED;
        }
    }
    else if (CamiSectionHint & CAMI_SECTION_HINT_PROT_OPTIONS)
    {
        if (CamiSectionHint & CAMI_SECTION_HINT_WINDOWS)
        {
            status = IntCamiLoadProtOptionsWin(pCami);
        }
        else if (CamiSectionHint & CAMI_SECTION_HINT_LINUX)
        {
            status = IntCamiLoadProtOptionsLinux(pCami);
        }
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed loading from hint 0x%08x: 0x%08x\n", CamiSectionHint, status);
    }

    return status;
}


INTSTATUS
IntCamiSetUpdateBuffer(
    _In_ const BYTE *UpdateBuffer,
    _In_ DWORD BufferLength
    )
///
/// @brief Initialize the update buffer with the one from the integrator.
///
/// @param[in] UpdateBuffer The update buffer from the integrator.
/// @param[in] BufferLength The size of the buffer.
///
/// @returns #INT_STATUS_SUCCESS or an appropriate #INTSTATUS error value.
///
{
    const CAMI_HEADER *pHeader;

    if (NULL == UpdateBuffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == BufferLength)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (sizeof(*pHeader) > BufferLength)
    {
        ERROR("[ERROR] BufferLength is smaller than file header (%d vs %zu)\n", BufferLength, sizeof(*pHeader));
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    pHeader = (const CAMI_HEADER *)UpdateBuffer;

    if (pHeader->Magic != CAMI_MAGIC_WORD)
    {
        LOG("[ERROR] Invalid cami magic word! Expected 0x%x, got  0x%x\n", CAMI_MAGIC_WORD, pHeader->Magic);
        return INT_STATUS_INVALID_DATA_TYPE;
    }

    if (BufferLength != pHeader->FileSize)
    {
        LOG("[ERROR] Buffer length is not equal with header file size. (%d vs %d)\n", BufferLength, pHeader->FileSize);
        return INT_STATUS_INVALID_DATA_SIZE;
    }

    LOG("[INFO] Loaded cami version %u.%u build %u\n",
        pHeader->Version.Major, pHeader->Version.Minor, pHeader->Version.BuildNumber);

    memcpy(&gCamiVersion, &pHeader->Version, sizeof(pHeader->Version));

    if (gCamiVersion.Major != UPDATE_CAMI_MIN_VER_MAJOR)
    {
        ERROR("[ERROR] Update's file major (%d.%d) version is different form ours (%d.%d)\n",
              gCamiVersion.Major, gCamiVersion.Minor, UPDATE_CAMI_MIN_VER_MAJOR, UPDATE_CAMI_MIN_VER_MINOR);

        return INT_STATUS_NOT_SUPPORTED;
    }

    if (gCamiVersion.Minor > UPDATE_CAMI_MIN_VER_MINOR)
    {
        WARNING("[WARNING] Update's file minor (%d.%d) version is newer than ours (%d.%d). "
                "Not all features will be available!\n",
                gCamiVersion.Major, gCamiVersion.Minor, UPDATE_CAMI_MIN_VER_MAJOR, UPDATE_CAMI_MIN_VER_MINOR);
    }
    else if (gCamiVersion.Minor < UPDATE_CAMI_MIN_VER_MINOR)
    {
        ERROR("[ERROR] Update's file minor (%d.%d) version is older than ours (%d.%d). Will not load.\n",
              gCamiVersion.Major, gCamiVersion.Minor, UPDATE_CAMI_MIN_VER_MAJOR, UPDATE_CAMI_MIN_VER_MINOR);

        return INT_STATUS_NOT_SUPPORTED;
    }

    gUpdateBuffer = UpdateBuffer;
    gUpdateBufferSize = BufferLength;

    return INT_STATUS_SUCCESS;
}


void
IntCamiClearUpdateBuffer(
    void
    )
///
/// @brief Uninitialize the update buffer and notify the integrator that we don't need it anymore.
///
{
    INTSTATUS status;

    if (NULL == gUpdateBuffer)
    {
        ASSERT( gUpdateBufferSize == 0 );
        return;
    }

#ifdef INT_COMPILER_GNUC
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-qual"
#endif

    status = IntReleaseBuffer((void *)gUpdateBuffer, gUpdateBufferSize);

#ifdef INT_COMPILER_GNUC
# pragma GCC diagnostic pop
#endif

    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntReleaseBuffer failed: 0x%08x\n", status);
    }

    gUpdateBuffer = NULL;
    gUpdateBufferSize = 0;
}


INTSTATUS
IntCamiGetVersion(
    _Out_ DWORD *MajorVersion,
    _Out_ DWORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    )
///
/// @brief Get the version of the loaded CAMI support file.
///
/// @param[out] MajorVersion Will hold the major version.
/// @param[out] MinorVersion Will hold the minor version.
/// @param[out] BuildNumber  Will hold the build number.
///
/// @returns #INT_STATUS_SUCCESS or an appropriate #INTSTATUS error value.
///
{
    if (NULL == MajorVersion)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == MinorVersion)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == BuildNumber)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    *MajorVersion = gCamiVersion.Major;
    *MinorVersion = gCamiVersion.Minor;
    *BuildNumber = gCamiVersion.BuildNumber;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCamiProtectedProcessAllocate(
    _In_ DWORD Items
    )
///
/// @brief Initialize the global variable holding custom process protection options.
///
/// @param[in] Items Number of items the global should hold.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error code.
///
{
    if (gCamiProcessProtectionData.Items != NULL)
    {
        ERROR("[ERROR] Cami protected processes array already allocated!");
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (Items == 0)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    gCamiProcessProtectionData.Items = HpAllocWithTag(Items * sizeof(CAMI_PROCESS_PROTECTION_INFO), IC_TAG_CAMI);
    if (gCamiProcessProtectionData.Items == NULL)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    gCamiProcessProtectionData.Count = Items;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntCamiProtectedProcessFree(
    void
    )
///
/// @brief Uninitialize the global holding custom process protection options.
///
{
    if (gCamiProcessProtectionData.Items == NULL)
    {
        return INT_STATUS_SUCCESS;
    }

    HpFreeAndNullWithTag(&gCamiProcessProtectionData.Items, IC_TAG_CAMI);
    gCamiProcessProtectionData.Items = NULL;
    gCamiProcessProtectionData.Count = 0;

    return INT_STATUS_SUCCESS;
}
