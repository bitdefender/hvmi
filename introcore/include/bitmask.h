/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _BITMASK_H_
#define _BITMASK_H_

#include "introtypes.h"

///
/// @brief  Represents a bit mask.
///
/// Note that this structure has a variable size.
///
typedef struct _BITMASK
{
    size_t      Length; ///< The number of bits included.
    BYTE        Bits[]; ///< The bit array.
} BITMASK;


BITMASK *
BitMaskAlloc(
    _In_ size_t Size
    );

void
BitMaskFree(
    _Inout_ BITMASK **BitMask
    );

void
BitMaskSet(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    );

void
BitMaskClear(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    );

BYTE
BitMaskTest(
    _In_ BITMASK *BitMask,
    _In_ DWORD BitPos
    );

BYTE
BitMaskTestAndSet(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    );

BYTE
BitMaskTestAndReset(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    );

DWORD
BitMaskScanForward(
    _In_ BITMASK *BitMask
    );


#endif // _BITMASK_H_
