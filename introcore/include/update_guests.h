/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UPDATE_GUESTS_H__
#define _UPDATE_GUESTS_H__

///
/// @defgroup   group_guest_support Guest support mechanism
/// @ingroup    group_internal
/// @brief      Guest support and policy update mechanism.
///
/// CAMI is an Introcore sub module serving mainly as an OS specific info database. However, it may include other
/// features that can control Introspection behavior, such as hooked kernel APIs or enforced options (forcing features
/// to be on or off).
///

///
/// @file       update_guests.h
/// @brief      Exposes the definitions used by the CAMI parser and the functions used to load guest support
///             information or update protection policies.
/// @ingroup    group_guest_support
///

#include "introcore.h"

/// @brief Maximum size of a version string.
#define     MAX_VERSION_STRING_SIZE             64

/// @brief Maximum size of a function name.
#define     MAX_FUNCTION_NAME_SIZE              64

/// @brief Cami header magic number.
#define     CAMI_MAGIC_WORD                     'IMAC'

/// @brief Maximum number of elements for a CAMI array.
#define     CAMI_MAX_ENTRY_COUNT                0x4000

/// @brief CAMI section hints that describe what is to be loaded.
typedef enum _CAMI_SECTION_HINTS
{
    CAMI_SECTION_HINT_SUPPORTED_OS      = 0x0001,   ///< Section will contain information about a supported OS.
    CAMI_SECTION_HINT_SYSCALLS          = 0x0002,   ///< Section will contain syscall signatures.
    CAMI_SECTION_HINT_DIST_SIG          = 0x0004,   ///< Section will contain distribution signatures.
    CAMI_SECTION_HINT_PROT_OPTIONS      = 0x0008,   ///< Section will contain protection flags.

    CAMI_SECTION_HINT_WINDOWS           = 0x0100,   ///< Section will contain windows related information.
    CAMI_SECTION_HINT_LINUX             = 0x0200,   ///< Section will contain linux related information.
} CAMI_SECTION_HINTS;

/// @brief Describes the encoding of a string received from the CAMI file.
typedef enum CAMI_STRING_ENCODING
{
    CAMI_STRING_ENCODING_UTF8           = 0x0000,   ///< String will be encoded in utf-8.
    CAMI_STRING_ENCODING_UTF16          = 0x0001,   ///< String will be encoded in utf-16.
} CAMI_STRING_ENCODING;


#pragma pack(push)
#pragma pack(1)

#define UPDATE_CAMI_MIN_VER_MAJOR                        1
#define UPDATE_CAMI_MIN_VER_MINOR                        4

/// @brief Describe the CAMI version.
typedef struct _CAMI_VERSION
{
    DWORD Minor;                                    ///< Minor version of this file.
    DWORD Major;                                    ///< Major version of this file.

    DWORD BuildNumber;                              ///< Build number.
} CAMI_VERSION, *PCAMI_VERSION;

/// @brief Describe the CAMI file header.
typedef struct _CAMI_HEADER
{
    DWORD Magic;                                    ///< Magic value. Should be #CAMI_MAGIC_WORD.

    CAMI_VERSION Version;                           ///< Version.

    /// @brief  The size of the update file. Should be equal with the value of BufferSize.
    DWORD FileSize;
    DWORD NumberOfSections;                         ///< Number of entries in the table bellow.
    DWORD PointerToSectionsHeaders;                 ///< RVA of a #CAMI_SECTION_HEADER table.

} CAMI_HEADER, *PCAMI_HEADER;

/// @brief Describe a CAMI file section header.
typedef struct _CAMI_SECTION_HEADER
{
    DWORD Hint;                                     ///< Any combination of #CAMI_SECTION_HINTS.
    DWORD EntryCount;                               ///< How many entries of this type are in the DescriptorTable.
    DWORD _Reserved;                                ///< Reserved.
    DWORD DescriptorTable;                          ///< Pointer to a CAMI descriptor table.
} CAMI_SECTION_HEADER, *PCAMI_SECTION_HEADER;

/// @brief Describe a CAMI file Linux descriptor. Load support for a Linux guest.
typedef struct _CAMI_LIX_DESCRIPTOR
{
    CHAR    VersionString[MAX_VERSION_STRING_SIZE]; ///< The versions string used to match this OS.

    QWORD   MinIntroVersion;                        ///< Minimum introcore version which supports this OS.
    QWORD   MaxIntroVersion;                        ///< Maximum introcore version which supports this OS.

    DWORD   StructuresCount;                        ///< Opaque structures count.
    /// @brief  Opaque structures file pointer. (pointer to a #CAMI_OPAQUE_STRUCTURE array).
    DWORD   StructuresTable;

    DWORD   HooksCount;                             ///< Hooked functions count.
    /// @brief  Hooked functions file pointer. (pointer to a #CAMI_LIX_HOOK array).
    DWORD   HooksTable;

    /// @brief  Protection flags for this OS. (pointer to a #CAMI_CUSTOM_OS_PROTECTION).
    DWORD   CustomProtectionOffset;

    DWORD   _Reserved1;                             ///< Reserved for future use.
    DWORD   _Reserved2;                             ///< Reserved for future use.
    DWORD   _Reserved3;                             ///< Reserved for future use.
} CAMI_LIX_DESCRIPTOR, *PCAMI_LIX_DESCRIPTOR;

/// @brief Describe a function to be hooked by introcore.
typedef struct _CAMI_LIX_HOOK
{
    DWORD   NameHash;                               ///< Function name hash.
    BYTE    HookHandler;                            ///< The hook handler index from the #API_HOOK_DESCRIPTOR.
    BYTE    SkipOnBoot;                             ///< TRUE if this function should not be hooked on boot.
    WORD    _Reserved1;                             ///< Reserved for future use.
    DWORD   _Reserved2;                             ///< Reserved for future use.
} CAMI_LIX_HOOK, *PCAMI_LIX_HOOK;

/// @brief Describe windows version strings.
typedef struct _CAMI_WIN_VERSION_STRING
{
    QWORD   VersionStringSize;                              ///< Size of the version string.
    CHAR    VersionString[MAX_VERSION_STRING_SIZE];         ///< The version string.
    QWORD   ServerVersionStringSize;                        ///< Size of the server version string, if exists.
    CHAR    ServerVersionString[MAX_VERSION_STRING_SIZE];   ///< The version string if the OS is a server
} CAMI_WIN_VERSION_STRING, *PCAMI_WIN_VERSION_STRING;

/// @brief Describe a CAMI file windows descriptor. Load support for a windows guest.
typedef struct _CAMI_WIN_DESCRIPTOR
{
    DWORD   BuildNumber;                             ///< Build number for this Windows OS
    BOOLEAN Kpti;                                    ///< If this OS has KPTI support.
    BOOLEAN Is64;                                    ///< If this OS is 64 bits.

    WORD    _Reserved1;                              ///< Alignment mostly, but may become useful.

    QWORD   MinIntroVersion;                         ///< Minimum introcore version which supports this OS
    QWORD   MaxIntroVersion;                         ///< Maximum introcore version which supports this OS

    DWORD   KmStructuresCount;                       ///< KM opaque fields count
    /// @brief  KM opaque fields file pointer. (pointer to a #CAMI_OPAQUE_STRUCTURE array
    DWORD   KmStructuresTable;

    DWORD   UmStructuresCount;                       ///< UM opaque fields count
    /// @brief  UM opaque fields file pointer (pointer to a #CAMI_OPAQUE_STRUCTURE array
    DWORD   UmStructuresTable;

    DWORD   FunctionCount;                           ///< Functions count
    /// @brief  Functions file pointer. (pointer to a #CAMI_WIN_FUNCTION array.
    DWORD   FunctionTable;

    /// @brief  Protection flags for this OS. (pointer to a #CAMI_CUSTOM_OS_PROTECTION struct)
    DWORD   CustomProtectionOffset;

    /// @brief  VersionString pointer (pointer to a #CAMI_WIN_VERSION_STRING struct)
    DWORD   VersionStringOffset;
    DWORD   _Reserved3;                              ///< Reserved for future use.
    DWORD   _Reserved4;                              ///< Reserved for future use.
} CAMI_WIN_DESCRIPTOR, *PCAMI_WIN_DESCRIPTOR;

/// @brief Describe a function to be hooked by introcore.
typedef struct _CAMI_WIN_FUNCTION
{
    DWORD   NameHash;                               ///< Function name hash

    DWORD   PatternsCount;                          ///< Patterns count
    /// @brief  Patterns file offset. (pointer to a #CAMI_WIN_FUNCTION_PATTERN array)
    DWORD   PatternsTable;

    DWORD   ArgumentsCount;                         ///< Arguments count
    DWORD   ArgumentsTable;                         ///< Arguments file offset. (pointer to a DWORD array)

    QWORD   _Reserved1;                             ///< Reserved for future use.
    DWORD   _Reserved2;                             ///< Reserved for future use.
    DWORD   _Reserved3;                             ///< Reserved for future use.
} CAMI_WIN_FUNCTION, *PCAMI_WIN_FUNCTION;

/// @brief Describe the arguments for a function.
typedef struct _CAMI_WIN_FUNCTION_PATTERN_EXTENSION
{
    DWORD   ArgumentsCount;                         ///< Arguments count
    DWORD   ArgumentsTable;                         ///< Arguments file offset. (pointer to a DWORD array)

    QWORD   _Reserved1;                             ///< Reserved for future use.
    QWORD   _Reserved2;                             ///< Reserved for future use.
    QWORD   _Reserved3;                             ///< Reserved for future use.
    QWORD   _Reserved4;                             ///< Reserved for future use.
} CAMI_WIN_FUNCTION_PATTERN_EXTENSION, *PCAMI_WIN_FUNCTION_PATTERN_EXTENSION;

/// @brief Describe a function pattern.
typedef struct _CAMI_WIN_FUNCTION_PATTERN
{
    BYTE    SectionHint[8];                         ///< Section hint where this pattern should be found
    DWORD   HashLength;                             ///< The length (count of DWORDs) of the pattern.
    DWORD   HashOffset;                             ///< Pattern file pointer. (pointer to a DWORD array)

    DWORD   _Reserved1;                             ///< Reserved for future use.
    DWORD   Extended;                               ///< The file pointer of this structure's extension.
} CAMI_WIN_FUNCTION_PATTERN, *PCAMI_WIN_FUNCTION_PATTERN;

/// @brief Describe a pattern signature.
typedef struct _CAMI_PATTERN_SIGNATURE
{
    DWORD       SignatureId;                        ///< The unique ID of the signature
    DWORD       Offset;                             ///< Offset inside the buffer
    DWORD       Flags;                              ///< Auxiliary data
    WORD        _Reserved;
    WORD        PatternLength;                      ///< The length of the pattern. (count of DWORDs)
    DWORD       PatternOffset;                      ///< Pattern file pointer. (pointer to a DWORD array)

    DWORD       _Reserved1;                         ///< Reserved for future use.
    QWORD       _Reserved2;                         ///< Reserved for future use.
} CAMI_PATTERN_SIGNATURE, *PCAMI_PATTERN_SIGNATURE;

/// @brief Describe the members of a guest opaque structure.
typedef struct _CAMI_OPAQUE_STRUCTURE
{
    /// @brief  A file pointer to members of this structure. (pointer to a DWORD array)
    DWORD   Members;
    DWORD   MembersCount;                           ///< How many members are available for this structure
} CAMI_OPAQUE_STRUCTURE, *PCAMI_OPAQUE_STRUCTURE;

/// @brief Describe the introcore protection options.
typedef struct _CAMI_PROT_OPTIONS
{
    QWORD   ForceOff;                               ///< Options which will be disabled
    QWORD   ForceBeta;                              ///< Options beta only
    QWORD   ForceFeedback;                          ///< Options feedback only
    QWORD   ForceOn;                                ///< Options which will be enabled by default
    DWORD  _Reserved2;                              ///< Reserved for future use.
    DWORD  _Reserved3;                              ///< Reserved for future use.
} CAMI_PROT_OPTIONS;

/// @brief Describe the introcore protection options for a process.
typedef struct _CAMI_PROC_PROT_OPTIONS
{
    union
    {
        WCHAR    Name16[32];                        ///< The process name as a utf-16 string.
        CHAR     Name8[64];                         ///< The process name as a utf-8 string.
    };

    DWORD    OptionsOffset;                         ///< File pointer to a #CAMI_PROT_OPTIONS.
    DWORD    Encoding;                              ///< One of the #CAMI_STRING_ENCODING.

    QWORD   _Reserved1;                             ///< Reserved for future use.
    DWORD   _Reserved2;                             ///< Reserved for future use.
    DWORD   _Reserved3;                             ///< Reserved for future use.

} CAMI_PROC_PROT_OPTIONS;

/// @brief Describe the introcore protection options for a guest.
typedef struct _CAMI_CUSTOM_OS_PROTECTION
{
    DWORD CoreOptionsOffset;    ///< Intro core options. File pointer to a #CAMI_PROT_OPTIONS structure.
    DWORD ProcOptionsCount;     ///< The number of entries in the ProcOptionsTable.
    DWORD ProcOptionsTable;     ///< Process protection options. Pointer to a #CAMI_PROC_PROT_OPTIONS array.
    DWORD ShemuOptionsOffset;   ///< Shemu options. File pointer to a #CAMI_PROT_OPTIONS structure.
    QWORD _Reserved2;           ///< Reserved for future use.
} CAMI_CUSTOM_OS_PROTECTION;

#pragma pack(pop)

INTSTATUS
IntCamiLoadSection(
    _In_ DWORD CamiSectionHint
    );

INTSTATUS
IntCamiSetUpdateBuffer(
    _In_ const BYTE *UpdateBuffer,
    _In_ DWORD BufferLength
    );

INTSTATUS
IntCamiGetVersion(
    _Out_ DWORD *MajorVersion,
    _Out_ DWORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    );

INTSTATUS
IntCamiGetWinSupportedList(
    _In_ BOOLEAN KptiInstalled,
    _In_ BOOLEAN Guest64,
    _Out_opt_ DWORD *NtBuildNumberList,
    _Inout_ DWORD *Count
    );

void
IntCamiClearUpdateBuffer(
    void
    );

INTSTATUS
IntCamiProtectedProcessAllocate(
    _In_ DWORD Items
    );

INTSTATUS
IntCamiProtectedProcessFree(
    void
    );

INTSTATUS
IntCamiUpdateProcessProtectionInfo(
    _In_ void *ProtectedProcess
    );

#endif // !_UPDATE_GUESTS_H__
