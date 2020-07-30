/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef LIX_FILES_H_
#define LIX_FILES_H_

#include "lixprocess.h"

///
/// @brief Describes a string used for paths by the linux kernel (quick string).
///
typedef struct _LIX_QSTR
{
    union
    {
        struct
        {
            DWORD   Hash;       ///< Unused by introcore.
            DWORD   Length;     ///< The length of the string.
        };

        QWORD       HashLen;    ///< The union between the Hash and the Length.
    };

    QWORD           Name;       ///< A pointer to the string.
} LIX_QSTR, *PLIX_QSTR;


///
/// @brief The maximum length of a dentry-path.
///
#define LIX_MAX_PATH            256u

///
/// @brief The maximum entries to be parsed.
///
#define LIX_MAX_DENTRY_DEPTH    30

///
/// @brief Checks if a file has the SU rights.
///
#ifdef INT_COMPILER_MSVC
#define LIX_FILE_HAS_SUID(mode) ((mode & S_ISUID) || ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)))
#else
#define LIX_FILE_HAS_SUID(mode)                                         \
    ({ __auto_type mode_suid_ = (mode);                                 \
        ((mode_suid_ & S_ISUID) || ((mode_suid_ & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP))); })
#endif

INTSTATUS
IntLixFileGetDentry(
    _In_ QWORD File,
    _Out_ QWORD *Dentry
    );

INTSTATUS
IntLixDentryGetName(
    _In_ QWORD Dentry,
    _Outptr_ char **FileName,
    _Out_opt_ DWORD *NameLength
    );

INTSTATUS
IntLixGetFileName(
    _In_ QWORD FileStruct,
    _Outptr_ char **FileName,
    _Out_opt_ DWORD *NameLength,
    _Out_opt_ QWORD *DentryGva
    );

INTSTATUS
IntLixFileGetPath(
    _In_ QWORD FileStructGva,
    _Out_ char **Path,
    _Out_opt_ DWORD *Length
    );

void
IntLixFilesCacheUninit(
    void
    );

#endif // LIX_FILES_H_
