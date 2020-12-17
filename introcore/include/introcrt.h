/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTROCRT_H_
#define _INTROCRT_H_

#include "rbtree.h"

//
// CRT stuff
//
#ifndef INT_COMPILER_MSVC

#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#else
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#endif // INT_COMPILER_MSVC

#include "introtypes.h"
#include "pgtable.h"


#define strlen_s(s, n)          strnlen(s, n)
#define memzero(a, s)           memset(a, 0, s)

#ifdef INT_COMPILER_MSVC
size_t
strnlen(
    _In_reads_or_z_ (maxlen)const char *s,
    _In_ size_t maxlen
    );
#endif

__nonnull() int
strlower_utf16(
    _Inout_updates_(len) WCHAR *buf,
    _In_ size_t len
    );

__nonnull() int
strlower_utf8(
    _Inout_updates_(len) char *buf,
    _In_ size_t len
    );

__nonnull() int
wstrcmp(
    _In_z_ const WCHAR *buf1,
    _In_z_ const WCHAR *buf2
    );

__nonnull() int
wstrcasecmp(
    _In_z_ const WCHAR *buf1,
    _In_z_ const WCHAR *buf2
    );

__nonnull() int
wstrncasecmp(
    _In_reads_z_(len) const WCHAR *buf1,
    _In_reads_z_(len) const WCHAR *buf2,
    _In_ size_t len
    );

__nonnull() const WCHAR *
strstr_utf16(
    _In_z_ const WCHAR *buf1,
    _In_z_ const WCHAR *buf2
    );

#ifdef INT_COMPILER_MSVC

const CHAR *
strcasestr(
    _In_z_ const CHAR *buf1,
    _In_z_ const CHAR *buf2
    );

#endif

#ifdef INT_COMPILER_MSVC

int
strncasecmp(
    _In_reads_z_(len) const char *buf1,
    _In_reads_z_(len) const char *buf2,
    _In_ size_t len
    );

int
strcasecmp(
    _In_z_ const char *buf1,
    _In_z_ const char *buf2
    );

#endif


__nonnull() int
strcasecmp_utf8_utf16(
    _In_reads_z_(len) const char *buf1,
    _In_reads_z_(len) const WCHAR *buf2,
    _In_ size_t len
    );

__nonnull() char *
utf16toutf8(
    _Out_writes_z_(DestinationMaxLength) char *Destination,
    _In_z_ const WCHAR *Source,
    _In_ DWORD DestinationMaxLength
    );

char *
utf16tolowerutf8(
    _Out_writes_z_(DestinationMaxLength) char *Destination,
    _In_z_ const WCHAR *Source,
    _In_ DWORD DestinationMaxLength
    );

__nonnull() WCHAR *
utf8toutf16(
    _Out_writes_bytes_(DestinationMaxLength) WCHAR *Destination,
    _In_z_ const char *Source,
    _In_ DWORD DestinationMaxLength
    );

__nonnull() int
is_str_ansi(
    _In_reads_z_(MaxBufferSize) const char *Buffer,
    _In_ size_t MaxBufferSize,
    _In_ size_t MinSize
    );

__nonnull() void
memcpy_end(
    _Out_writes_bytes_(DestinationSize) void *Destination,
    _In_reads_bytes_(SourceSize) const void *Source,
    _In_ size_t DestinationSize,
    _In_ size_t SourceSize
    );

long long
my_llabs(
    _In_  long long value
    );

__nonnull() BOOLEAN
glob_match_utf8(
    _In_z_ char const *Pattern,
    _In_z_ char const *String,
    _In_opt_ BOOLEAN IgnoreCase,
    _In_opt_ BOOLEAN Truncated
    );

__nonnull() BOOLEAN
glob_match_numeric_utf8(
    _In_z_ char const *Pattern,
    _In_z_ char const *String
    );

__nonnull() BOOLEAN
glob_match_utf16(
    _In_z_ char const *Pattern,
    _In_z_ WCHAR const *String,
    _In_opt_ BOOLEAN IgnoreCase,
    _In_opt_ BOOLEAN Truncated
    );

__nonnull() size_t
wstrnlen(
    _In_reads_or_z_(maxlen) const WCHAR *s,
    _In_ size_t maxlen
    );

__nonnull() size_t
wstrlen(
    _In_z_ const WCHAR *str
    );

__nonnull() size_t
strlcpy(
    char *dst,
    const char *src,
    size_t dest_size
    );

__nonnull() size_t
wstrlcpy(
    WCHAR *dst,
    const WCHAR *src,
    size_t dest_size
    );

__nonnull() size_t
strlcat(
    char *dst,
    const char *src,
    size_t size
    );

int
nd_vsnprintf_s(char *str, size_t sizeOfBuffer, size_t count, const char *format, va_list args);


//
// wstrncasecmp_len is a wrapper over the original mycmp_utf16
// This wrapper should be used if one of the buffers could be ONLY a substring of the other.
//
__nonnull()
static inline int wstrncasecmp_len(const WCHAR *buf1, const WCHAR *buf2, size_t len_buf1, size_t len_buf2)
{
    if (len_buf1 < len_buf2)
    {
        return -1;
    }

    if (len_buf1 > len_buf2)
    {
        return 1;
    }

    return wstrncasecmp(buf1, buf2, len_buf1);
}

//
// strncasecmp_len is a wrapper over the original mycmp_utf8
// This wrapper should be used if one of the buffers could be ONLY a substring of the other.
//
__nonnull()
static inline int strncasecmp_len(const char *buf1, const char *buf2, size_t len_buf1, size_t len_buf2)
{
    if (len_buf1 < len_buf2)
    {
        return -1;
    }

    if (len_buf1 > len_buf2)
    {
        return 1;
    }

    return strncasecmp(buf1, buf2, len_buf1);
}

//
// strcasecmp_utf8_utf16_len is a wrapper over the original strcasecmp_utf8_utf16
// This wrapper should be used if one of the buffers could be ONLY a substring of the other.
//
__nonnull()
static inline int strcasecmp_utf8_utf16_len(const char *buf1, const WCHAR *buf2, size_t len_buf1, size_t len_buf2)
{
    if (len_buf1 < len_buf2)
    {
        return -1;
    }

    if (len_buf1 > len_buf2)
    {
        return 1;
    }

    return strcasecmp_utf8_utf16(buf1, buf2, len_buf1);
}


//
// memcmp_len is a wrapper over the original memcmp
// This wrapper should be used if one of the buffers could be ONLY a substring of the other.
//
__nonnull()
static inline int memcmp_len(const void *buf1, const void *buf2, size_t len_buf1, size_t len_buf2)
{
    if (len_buf1 < len_buf2)
    {
        return -1;
    }

    if (len_buf1 > len_buf2)
    {
        return 1;
    }

    return memcmp(buf1, buf2, len_buf1);
}


#endif // _INTROCRT_H_
