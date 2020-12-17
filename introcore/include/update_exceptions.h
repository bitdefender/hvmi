/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       update_exceptions.h
/// @ingroup    group_exceptions
///

#ifndef _UPDATE_EXCEPTIONS_H_
#define _UPDATE_EXCEPTIONS_H_

#include "exceptions.h"

//
// These will be shared between Linux & Windows
//

#pragma pack(push)
#pragma pack(1)


///
/// @brief The header of the exceptions binary file.
///
typedef struct _UPDATE_FILE_HEADER
{
    DWORD Magic;                        ///< The magic value; must be UPDATE_MAGIC_WORD

    struct
    {
        WORD Major;                     ///< The major version of the exceptions binary file
        WORD Minor;                     ///< The minor version of the exceptions binary file
    } Version;

    DWORD KernelExceptionsCount;        ///< The number of the kernel-mode exceptions
    DWORD UserExceptionsCount;          ///< The number of the user-mode exceptions
    DWORD SignaturesCount;              ///< The number of the signatures

    DWORD BuildNumber;                  ///< The build number of the exceptions binary file

    DWORD UserExceptionsGlobCount;      ///< The number of the user-mode exceptions that contains glob items
    DWORD KernelUserExceptionsCount;    ///< The number of the kernel-user mode exceptions

    DWORD _Reserved[1];
} UPDATE_FILE_HEADER, *PUPDATE_FILE_HEADER;


///
/// @brief The header of an exception or a signature
///
typedef struct _UPDATE_HEADER
{
    BYTE    Type;                       ///< The type of the exception/signature
    WORD    Size;                       ///< The size of the exception/signature
} UPDATE_HEADER, *PUPDATE_HEADER;


///
/// @brief Describe a kernel-mode exception in binary format
///
typedef struct _UPDATE_KM_EXCEPTION
{
    struct
    {
        DWORD   NameHash;               ///< The name-hash of the originator
        DWORD   PathHash;               ///< Unused
    } Originator;

    DWORD       VictimNameHash;         ///< The name-hash of the victim

    DWORD       Flags;                  ///< The flags of the exception; any flags from \ref _EXCEPTION_FLG

    BYTE        _Reserved;              ///< Alignment purposes
    BYTE        Type;                   ///< The type of the exception; any type from \ref _KM_EXCEPTION_OBJECT
    WORD        SigCount;               ///< The number of the signatures

    _Field_size_(SigCount)
    DWORD       SigIds[];               ///< An array that contains the signature IDs
} UPDATE_KM_EXCEPTION, *PUPDATE_KM_EXCEPTION;


///
/// @brief Describe a user-mode exception in binary format
///
typedef struct _UPDATE_UM_EXCEPTION
{
    DWORD       OriginatorNameHash;     ///< The name-hash of the originator

    struct
    {
        DWORD   NameHash;               ///< The name-hash of the victim
        DWORD   ProcessHash;            ///< The name-hash of the process in which the modification takes place
    } Victim;

    DWORD       Flags;                  ///< The flags of the exception; any flags from \ref _EXCEPTION_FLG

    BYTE        _Reserved;              ///< Alignment purposes
    BYTE        Type;                   ///< The type of the exception; any type from \ref _UM_EXCEPTION_OBJECT
    WORD        SigCount;               ///< The number of the signatures

    _Field_size_(SigCount)
    DWORD       SigIds[];               ///< An array that contains the signature IDs
} UPDATE_UM_EXCEPTION, *PUPDATE_UM_EXCEPTION;


///
/// @brief Describe a user-mode-glob exception in binary format
///
typedef struct _UPDATE_UM_EXCEPTION_GLOB
{
    /// @brief  The flags of the exception; any flags from \ref _EXCEPTION_FLG
    DWORD       Flags;

    BYTE        _Reserved;
    /// @brief  The type of the exception; any type from \ref _UM_EXCEPTION_OBJECT
    BYTE        Type;
    /// @brief  The number of the signatures
    WORD        SigCount;

    /// @brief  The name (a string that can contain glob items) of the originator
    CHAR        OriginatorNameGlob[EXCEPTION_UM_GLOB_LENGTH];

    struct
    {
        /// @brief  The name (a string that can contain glob items) of the victim
        CHAR    NameGlob[EXCEPTION_UM_GLOB_LENGTH];
        /// @brief  The name of the process(a string that can contain glob items)
        CHAR    ProcessGlob[EXCEPTION_UM_GLOB_LENGTH];
    } Victim;

    _Field_size_(SigCount)
    DWORD       SigIds[];   ///< An array that contains the signature IDs
} UPDATE_UM_EXCEPTION_GLOB, *PUPDATE_UM_EXCEPTION_GLOB;


///
/// @brief Describe a kernel-user mode exception in binary format
///
typedef struct _UPDATE_KUM_EXCEPTION
{
    union
    {
        DWORD       NameHash;                   ///< Contains the originator name-hash.
        DWORD       DriverHash;                 ///< Contains the originator driver name-hash.
        DWORD       ProcessHash;                ///< Contains the originator process name-hash.
    } Originator;

    struct
    {
        DWORD   NameHash;               ///< The name-hash of the victim
        DWORD   ProcessHash;            ///< The name-hash of the process in which the modification takes place
    } Victim;

    DWORD       Flags;                  ///< The flags of the exception; any flags from #EXCEPTION_FLG

    BYTE        _Reserved;              ///< Alignment purposes
    BYTE        Type;                   ///< The type of the exception; any type from #KUM_EXCEPTION_OBJECT
    WORD        SigCount;               ///< The number of the signatures

    _Field_size_(SigCount)
    DWORD       SigIds[];               ///< An array that contains the signature IDs
} UPDATE_KUM_EXCEPTION, *PUPDATE_KUM_EXCEPTION;


///
/// @brief Describe a code-blocks hash in binary format
///
typedef struct _UPDATE_CB_HASH
{
    BYTE        Count;              ///< The number of hashes from the list

    _Field_size_(Count)
    DWORD       Hashes[];           ///< The hashes list
} UPDATE_CB_HASH, *PUPDATE_CB_HASH;


///
/// @brief Describe a value hash in binary format
///
typedef struct _UPDATE_VALUE_HASH
{
    WORD            Offset;         ///< The displacement from the beginning of the modified zone
    WORD            Size;           ///< The size of of the modified zone
    BYTE            _Reserved[4];
    DWORD           Hash;           ///< The hash of the modified zone
} UPDATE_VALUE_HASH, *PUPDATE_VALUE_HASH;


///
/// @brief Describe a export hash in binary format
///
typedef struct _UPDATE_EXPORT_HASH
{
    WORD            Delta;          ///< The number of bytes that are modified
    BYTE            _Reserved[2];
    DWORD           Hash;           ///< The hash of the modified function name
} UPDATE_EXPORT_HASH, *PUPDATE_EXPORT_HASH;


///
/// @brief Describe a code-blocks signature in binary format
///
typedef struct _UPDATE_CB_SIGNATURE
{
    DWORD       Id;                 ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;              ///< Contains any flags from \ref _SIGNATURE_FLG

    BYTE        Score;              ///< The number of (minimum) hashes from a list that need to match
    BYTE        ListsCount;         ///< The number of the list of hashes

    char        HashesList[];       ///< Contains lists of (\ref _UPDATE_CB_HASH)
} UPDATE_CB_SIGNATURE, *PUPDATE_CB_SIGNATURE;


///
/// @brief Describe an export signature in binary format
///
typedef struct _UPDATE_EXPORT_SIGNATURE
{
    DWORD       Id;                 ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;              ///< Contains any flags from \ref _SIGNATURE_FLG

    DWORD       LibraryName;        ///< The name-hash of the modified library

    BYTE        ListsCount;         ///< The number of the list of hashes
    BYTE        _Align[3];

    char        HashesList[];       ///< Contains lists of (\ref _UPDATE_EXPORT_HASH)
} UPDATE_EXPORT_SIGNATURE, *PUPDATE_EXPORT_SIGNATURE;


///
/// @brief Describe a value signature in binary format
///
typedef struct _UPDATE_VALUE_SIGNATURE
{
    DWORD       Id;                 ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;              ///< Contains any flags from \ref _SIGNATURE_FLG

    BYTE        Score;              ///< The number of (minimum) hashes from a list that need to match.
    BYTE        ListsCount;         ///< The number of the list of hashes
    BYTE        _Align[2];

    char        HashesList[];       ///< Contains lists of (\ref _SIG_VALUE_HASH)
} UPDATE_VALUE_SIGNATURE, *PUPDATE_VALUE_SIGNATURE;


///
/// @brief Describe an IDT signature in binary format
///
typedef struct _UPDATE_IDT_SIGNATURE
{
    DWORD       Id;                 ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;              ///< Contains any flags from \ref _SIGNATURE_FLG

    BYTE        Entry;              ///< The number of the IDT entry
    BYTE        _Reserved[3];
} UPDATE_IDT_SIGNATURE, *PUPDATE_IDT_SIGNATURE;


///
/// @brief Describe a value-code signature in binary format
///
typedef struct _UPDATE_VALUE_CODE_SIGNATURE
{
    DWORD       Id;                 ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;              ///< Contains any flags from \ref _SIGNATURE_FLG

    INT16       Offset;             ///< The displacement from the beginning of the modified zone
    WORD        Length;             ///< The length of the opcode pattern

    WORD        Pattern[];          ///< Contains list of opcodes
} UPDATE_VALUE_CODE_SIGNATURE, *PUPDATE_VALUE_CODE_SIGNATURE;


///
/// @brief Describe a version OS signature in binary format
///
typedef struct _UPDATE_VERSION_OS_SIGNATURE
{
    DWORD       Id;                 ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;              ///< Contains any flags from \ref _SIGNATURE_FLG

    union
    {
        ///< Contains the minimum version.patch.sublevel-backport of the operating system (used for Linux)
        struct
        {
            BYTE Version;
            BYTE Patch;
            WORD Sublevel;
            WORD Backport;
            BYTE _Reserved[2];
        };
        ///< Contains the minimum build number of the operating system (used for windows)
        QWORD Value;
    } Minimum;

    union
    {
        ///< Contains the maximum version.patch.sublevel-backport of the operating system (used for Linux)
        struct
        {
            BYTE Version;
            BYTE Patch;
            WORD Sublevel;
            WORD Backport;
            BYTE _Reserved[2];
        };
        ///< Contains the maximum build number of the operating system (used for windows)
        QWORD Value;
    } Maximum;

} UPDATE_VERSION_OS_SIGNATURE, *PUPDATE_VERSION_OS_SIGNATURE;


///
/// @brief Describe a version introspection signature in binary format
///
typedef struct _UPDATE_VERSION_INTRO_SIGNATURE
{
    DWORD       Id;             ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;          ///< Contains any flags from \ref _SIGNATURE_FLG

    union
    {
        ///< Contains the minimum version of the introspection
        struct
        {
            WORD    Major;
            WORD    Minor;
            WORD    Revision;
            WORD    Build;
        };

        QWORD Raw;
    } Minimum;

    union
    {
        ///< Contains the maximum version of the introspection
        struct
        {
            WORD    Major;
            WORD    Minor;
            WORD    Revision;
            WORD    Build;
        };

        QWORD Raw;
    } Maximum;

} UPDATE_VERSION_INTRO_SIGNATURE, *PUPDATE_VERSION_INTRO_SIGNATURE;


///
/// @brief Describe a process-creation signature in binary format
///
typedef struct _UPDATE_PROCESS_CREATION_SIGNATURE
{
    DWORD       Id;             ///< An unique id (\ref _EXCEPTION_SIGNATURE_ID)
    DWORD       Flags;          ///< Contains any flags from \ref _SIGNATURE_FLG

    DWORD       CreateMask;     ///< Contains the DPI mask

    DWORD       _Reserved[3];

} UPDATE_PROCESS_CREATION_SIGNATURE, *PUPDATE_PROCESS_CREATION_SIGNATURE;

#pragma pack(pop)


#define UPDATE_MAGIC_WORD                           'ANXE'

#define UPDATE_TYPE_KM_EXCEPTION                    1
#define UPDATE_TYPE_UM_EXCEPTION                    2
#define UPDATE_TYPE_UM_EXCEPTION_GLOB_MATCH         6
#define UPDATE_TYPE_APC_UM_EXCEPTION                9

#define UPDATE_TYPE_CB_SIGNATURE                    3
#define UPDATE_TYPE_EXPORT_SIGNATURE                4
#define UPDATE_TYPE_VALUE_SIGNATURE                 5
#define UPDATE_TYPE_RESERVED                        7
#define UPDATE_TYPE_VALUE_CODE_SIGNATURE            8
#define UPDATE_TYPE_IDT_SIGNATURE                   10
#define UPDATE_TYPE_VERSION_OS_SIGNATURE            11
#define UPDATE_TYPE_VERSION_INTRO_SIGNATURE         12
#define UPDATE_TYPE_PROCESS_CREATION_SIGNATURE      13
#define UPDATE_TYPE_KUM_EXCEPTION                   14

#define UPDATE_EXCEPTIONS_MIN_VER_MAJOR             2
#define UPDATE_EXCEPTIONS_MIN_VER_MINOR             2


INTSTATUS
IntUpdateGetVersion(
    _Out_ WORD *MajorVersion,
    _Out_ WORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    );

INTSTATUS
IntUpdateLoadExceptions(
    _In_ void *Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
    );

INTSTATUS
IntUpdateAddExceptionFromAlert(
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
    );

INTSTATUS
IntUpdateFlushAlertExceptions(
    void
    );

INTSTATUS
IntUpdateRemoveException(
    _In_opt_ QWORD Context
    );

#endif // _UPDATE_EXCEPTIONS_H_
