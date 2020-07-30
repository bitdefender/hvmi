/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LOADER_H_
#define _LOADER_H_

#include "introtypes.h"


#define LDR_FLAG_FIX_RELOCATIONS        0x00000001  ///< If flag is set, the relocations will be applied.
#define LDR_FLAG_FIX_IMPORTS            0x00000002  ///< If flag is set, the imports will be fixed.


//
// API
//
INTSTATUS
IntLdrGetImageSizeAndEntryPoint(
    _In_ PBYTE RawPe,
    _In_ DWORD RawSize,
    _Out_ DWORD *VirtualSize,
    _Out_ DWORD *EntryPoint
    );

INTSTATUS
IntLdrLoadPEImage(
    _In_ PBYTE RawPe,
    _In_ DWORD RawPeSize,
    _In_ QWORD GuestVirtualAddress,
    _Inout_ PBYTE LoadedPe,
    _In_ DWORD VirtualPeSize,
    _In_ DWORD Flags
    );

#endif // _LOADER_H
