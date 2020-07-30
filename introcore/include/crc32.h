/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CRC32_H_
#define _CRC32_H_

#include "introtypes.h"

__nonnull() DWORD
Crc32Compute(
    _In_ const void *Buffer,
    _In_ size_t Size,
    _In_ DWORD InitialCrc
    );

__nonnull() DWORD
Crc32ComputeFast(
    _In_ const void *Buffer,
    _In_ size_t Size,
    _In_ DWORD InitialCrc
    );

__nonnull() DWORD
Crc32String(
    _In_ const char *String,
    _In_ DWORD InitialCrc
    );

__nonnull() DWORD
Crc32Wstring(
    _In_ const WCHAR *String,
    _In_ DWORD InitialCrc
    );

DWORD
Crc32WstringLen(
    _In_ const WCHAR *String,
    _In_ DWORD InitialCrc,
    _In_ size_t MaxLength,
    _Out_ BOOLEAN *Valid
    );

DWORD
Crc32StringLen(
    _In_ const char *String,
    _In_ DWORD InitialCrc,
    _In_ size_t MaxLength,
    _Out_ BOOLEAN *Valid
    );

#endif // _CRC32_H_
