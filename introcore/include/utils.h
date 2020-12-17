/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UTILS_H_
#define _UTILS_H_

#include "introtypes.h"

size_t
UtilBinarySearch(
    _In_bytecount_(Length) void *Buffer,
    _In_ size_t Length,                         // Length in bytes!
    _In_ size_t SizeOfElements,
    _In_bytecount_(SizeOfElements) void *Target
    );

size_t
UtilInsertOrdered(
    _In_bytecount_(Length) void *Buffer,
    _In_ size_t Length,
    _In_ size_t MaximumLength,
    _In_ size_t SizeOfElements,
    _In_bytecount_(SizeOfElements) void *Target
    );

size_t
UtilBinarySearchStructure(
    _In_bytecount_(Count *SizeOfElements) void *Buffer,
    _In_ size_t Count,              // Number of structures
    _In_ size_t SizeOfElements,     // Elements size
    _In_ DWORD CompareFieldOffset,  // The offset of the compare field
    _In_bytecount_(TargetSize) void *Target,
    _In_ DWORD TargetSize
    );

void
UtilQuickSort(
    _Inout_updates_bytes_(NumberOfElements *ElementSize) void *Array,
    _In_ const DWORD NumberOfElements,
    _In_ const BYTE ElementSize
    );

void
UtilSortQwords(
    _Inout_updates_(NumberOfElements) PQWORD Array,
    _In_ const DWORD NumberOfElements
    );

BOOLEAN
UtilIsBufferZero(
    _In_bytecount_(BufferSize) void *Buffer,
    _In_ size_t BufferSize
    );

#endif // _UTILS_H_
