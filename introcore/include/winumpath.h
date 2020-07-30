/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINUMPATH_H_
#define _WINUMPATH_H_

#include "introcrt.h"

///
/// An object representing a user-mode module path.
///
typedef struct _WINUM_PATH
{
    RBNODE      RbNode;             ///< The node which is inserted into #gPaths tree.

    WCHAR       *Path;              ///< The string which represents the user-mode module path.
    WCHAR       *Name;              ///< The name of the module contained in the path.

    DWORD       PathSize;           ///< The number of bytes in the path string.
    DWORD       NameSize;           ///< The number of bytes in the name string.

    DWORD       NameHash;           ///< The CRC32 hash of the name. Used for fast matching.

    /// @brief  The reference count of the current object. When reaching 0, the path will be freed.
    INT32       RefCount;

    /// @brief  The subsection guest virtual address from where the path was read. Serves as an unique identifier.
    QWORD       SubsectionGva;

} WINUM_PATH, *PWINUM_PATH;


WINUM_PATH *
IntWinUmPathCreate(
    _In_ const WCHAR *Path,
    _In_ DWORD PathSize,
    _In_ QWORD SubsectionGva
    );

WINUM_PATH *
IntWinUmPathReference(
    _In_ WINUM_PATH *Path
    );

void
IntWinUmPathDereference(
    _Inout_ WINUM_PATH **Path
    );

WINUM_PATH *
IntWinUmPathFetchAndReferenceBySubsection(
    _In_ QWORD SubsectionGva
    );

#endif // _WINUMPATH_H_

