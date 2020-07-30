/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _KERNVM_H_
#define _KERNVM_H_

#include "introcore.h"

/// A MPX bound structure.
typedef struct _MPX_BOUND
{
    QWORD               LowerBound;     ///< Lower bound.
    QWORD               UpperBound;     ///< Upper bound.
    QWORD               PointerValue;   ///< Pointer value.
    QWORD               Reserved;       ///< Reserved for future use/alignment.
} MPX_BOUND, *PMPX_BOUND;

/// A MPX translation structure.
typedef struct _MPX_TRANSLATION
{
    QWORD               LinearAddressToPointer; ///< Linear address to pointer (LoPA)
    QWORD               BoundDirectory;         ///< The bound directory address.
    QWORD               BoundDirectoryEntry;    ///< The bound directory entry.
    QWORD               BoundTable;             ///< The bound table address.
    MPX_BOUND           BoundTableEntry;        ///< The bound table entry.
} MPX_TRANSLATION, *PMPX_TRANSLATION;


//
// API
//
INTSTATUS
IntSplitVirtualAddress(
    _In_ QWORD VirtualAddress,
    _Out_ DWORD *OffsetsCount,
    _Out_writes_(MAX_TRANSLATION_DEPTH) QWORD *OffsetsTrace
    );

INTSTATUS
IntIterateVirtualAddressSpace(
    _In_ QWORD Cr3,
    _In_ PFUNC_VirtualAddressSpaceCallback Callback
    );

INTSTATUS
IntValidateRangeForWrite(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ DWORD Size,
    _In_ DWORD Ring
    );

INTSTATUS
IntVirtMemSafeWrite(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ DWORD Size,
    _In_reads_bytes_(Size) void *Buffer,
    _In_ DWORD Ring
    );

#endif // _KERNVM_H_
