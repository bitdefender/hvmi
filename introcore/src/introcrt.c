/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcrt.h"
#include "glue.h"


#ifdef INT_COMPILER_MSVC
size_t
strnlen(
    _In_reads_or_z_(maxlen) const char *s,
    _In_ size_t maxlen
    )
{
    size_t len = 0;
    while (len < maxlen && s[len])
    {
        ++len;
    }

    return len;
}
#endif


int
strlower_utf16(
    _Inout_updates_(len) WCHAR *buf,
    _In_ size_t len
    )
//
// Converts a wide string to lower-case (dumb version: only ASCII A-Z handled).
//
// Returns the number of characters in the string (without NULL-terminator).
//
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        if (buf[i] >= u'A' && buf[i] <= u'Z')
        {
            buf[i] |= 0x20;
        }
        else if (buf[i] == u'\0')
        {
            break;
        }
    }

    return (int)i;
}


int
strlower_utf8(
    _Inout_updates_(len) char *buf,
    _In_ size_t len
    )
//
// Converts a string to lower-case (dumb version: only ASCII A-Z handled).
//
// Returns the number of characters in the string (without NULL-terminator).
//
{
    size_t i;

    for (i = 0; i < len; i++)
    {
        if (buf[i] >= 'A' && buf[i] <= 'Z')
        {
            buf[i] |= 0x20;
        }
        else if (buf[i] == '\0')
        {
            break;
        }
    }

    return (int)i;
}


int
wstrcmp(
    _In_z_ const WCHAR *buf1,
    _In_z_ const WCHAR *buf2
    )
{
    for (; *buf1 == *buf2 && *buf1 && *buf2; buf1++, buf2++) {}

    return *buf1 - *buf2;
}


int
wstrcasecmp(
    _In_z_ const WCHAR *buf1,
    _In_z_ const WCHAR *buf2
    )
//
// Compares the given buffers as wide-char strings. Buf1 is considered to be
// the same as buf2 (equal) if every 2 characters located at the same index
// are the same. Buf1 is considered less than buf2 if the first unequal
// character from the 2 buffers is smaller in buf1 than buf2. Otherwise, buf1
// is considered greater than buf2. The strings must both be NULL terminated.
//
// \ret -1                              If the buf1 < buf2.
// \ret 0                               If buf1 == buf2.
// \ret 1                               If buf1 > buf2.
//
{
    for (size_t i = 0; buf1[i] || buf2[i]; i++)
    {
        WCHAR c1, c2;

        c1 = buf1[i];
        c2 = buf2[i];

        if (c1 >= u'A' && c1 <= u'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= u'A' && c2 <= u'Z')
        {
            c2 |= 0x20;
        }

        if (c1 < c2)
        {
            return -1;
        }
        else if (c1 > c2)
        {
            return 1;
        }
    }

    return 0;
}


int
wstrncasecmp(
    _In_reads_z_(len) const WCHAR *buf1,
    _In_reads_z_(len) const WCHAR *buf2,
    _In_ size_t len
    )
//
// Compares the given buffers as wide-char strings. Buf1 is considered to be
// the same as buf2 (equal) if every 2 characters located at the same index
// are the same. Buf1 is considered less than buf2 if the first unequal
// character from the 2 buffers is smaller in buf1 than buf2. Otherwise, buf1
// is considered greater than buf2.
//
// \ret -1                              If the buf1 < buf2.
// \ret 0                               If buf1 == buf2.
// \ret 1                               If buf1 > buf2.
//
{
    for (size_t i = 0; i < len; i++)
    {
        WCHAR c1, c2;

        c1 = buf1[i];
        c2 = buf2[i];

        if (c1 >= u'A' && c1 <= u'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= u'A' && c2 <= u'Z')
        {
            c2 |= 0x20;
        }

        if (c1 < c2)
        {
            return -1;
        }
        else if (c1 > c2)
        {
            return 1;
        }
    }

    return 0;
}


const WCHAR *
strstr_utf16(
    _In_z_ const WCHAR *buf1,
    _In_z_ const WCHAR *buf2
    )
//
// Checks if buf2 is a substring of buf1 (case insensitive).
//
{
    size_t i = 0, j = 0;

    while (buf1[i] && buf2[j])
    {
        WCHAR c1 = buf1[i];
        WCHAR c2 = buf2[j];

        if (c1 >= u'A' && c1 <= u'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= u'A' && c2 <= u'Z')
        {
            c2 |= 0x20;
        }

        if (c1 == c2)
        {
            j++;
        }
        else
        {
            j = 0;
        }

        i++;
    }

    if ((buf2[j] == 0) && (j > 0))
    {
        return &buf1[i - j];
    }

    return NULL;
}

#ifdef INT_COMPILER_MSVC

const CHAR *
strcasestr(
    _In_z_ const CHAR *buf1,
    _In_z_ const CHAR *buf2
    )
//
// Checks if buf2 is a substring of buf1 (case insensitive).
//
{
    size_t i, j;

    if ((NULL == buf1) || (NULL == buf2))
    {
        return 0;
    }

    i = j = 0;

    while (buf1[i] && buf2[j])
    {
        CHAR c1 = buf1[i];
        CHAR c2 = buf2[j];

        if (c1 >= 'A' && c1 <= 'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= 'A' && c2 <= 'Z')
        {
            c2 |= 0x20;
        }

        if (c1 == c2)
        {
            j++;
        }
        else
        {
            j = 0;
        }

        i++;
    }

    if ((buf2[j] == 0) && (j > 0))
    {
        return &buf1[i - j];
    }

    return NULL;
}

#endif

#ifdef INT_COMPILER_MSVC

int
strncasecmp(
    _In_reads_z_(len) const char *buf1,
    _In_reads_z_(len) const char *buf2,
    _In_ size_t len
    )
//
// Compares the given buffers as ANSI strings. buf1 is considered to be
// the same as buf2 (equal) if every character located at the same index
// are the same. buf1 is considered less than buf2 if the first unequal
// character from the 2 buffers is smaller in buf1 than buf2. Otherwise, buf1
// is considered greater than buf2.
//
// \ret -1                              If the buf1 < buf2.
// \ret 0                               If buf1 == buf2.
// \ret 1                               If buf1 > buf2.
//
{
    size_t i;

    if ((NULL == buf1) || (NULL == buf2))
    {
        return 0;
    }

    for (i = 0; i < len; i++)
    {
        char c1, c2;

        c1 = (char)buf1[i];
        c2 = (char)buf2[i];

        if (c1 >= 'A' && c1 <= 'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= 'A' && c2 <= 'Z')
        {
            c2 |= 0x20;
        }

        if (c1 < c2)
        {
            return -1;
        }
        else if (c1 > c2)
        {
            return 1;
        }
    }

    return 0;
}


int
strcasecmp(
    _In_z_ const char *buf1,
    _In_z_ const char *buf2
    )
//
// Compares the given buffers as ANSI strings. buf1 is considered to be
// the same as buf2 (equal) if every character located at the same index
// are the same. buf1 is considered less than buf2 if the first unequal
// character from the 2 buffers is smaller in buf1 than buf2. Otherwise, buf1
// is considered greater than buf2.
//
// \ret -1                              If the buf1 < buf2.
// \ret 0                               If buf1 == buf2.
// \ret 1                               If buf1 > buf2.
//
{
    size_t i;

    if ((NULL == buf1) || (NULL == buf2))
    {
        return 0;
    }

    for (i = 0; buf1[i] || buf2[i]; i++)
    {
        char c1, c2;

        c1 = (char)buf1[i];
        c2 = (char)buf2[i];

        if (c1 >= 'A' && c1 <= 'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= 'A' && c2 <= 'Z')
        {
            c2 |= 0x20;
        }

        if (c1 < c2)
        {
            return -1;
        }
        else if (c1 > c2)
        {
            return 1;
        }
    }

    return 0;
}

#endif


int
strcasecmp_utf8_utf16(
    _In_reads_z_(len) const char *buf1,
    _In_reads_z_(len) const WCHAR *buf2,
    _In_ size_t len
    )
//
// Compares the given buffers as wide-char strings. Buf1 is considered to be
// the same as buf2 (equal) if every 2 characters located at the same index
// are the same. Buf1 is considered less than buf2 if the first unequal
// character from the 2 buffers is smaller in buf1 than buf2. Otherwise, buf1
// is considered greater than buf2.
//
// \ret -1                              If the buf1 < buf2.
// \ret 0                               If buf1 == buf2.
// \ret 1                               If buf1 > buf2.
//
{
    for (size_t i = 0; i < len; i++)
    {
        char c1 = buf1[i];
        WCHAR c2 = buf2[i];

        if (c1 >= 'A' && c1 <= 'Z')
        {
            c1 |= 0x20;
        }

        if (c2 >= u'A' && c2 <= u'Z')
        {
            c2 |= 0x20;
        }

        if (c1 < c2)
        {
            return -1;
        }
        else if (c1 > c2)
        {
            return 1;
        }
    }

    return 0;
}


char *
utf16toutf8(
    _Out_writes_z_(DestinationMaxLength) char *Destination,
    _In_z_ const WCHAR *Source,
    _In_ DWORD DestinationMaxLength
    )
{
    DWORD i;

    for (i = 0; (i < DestinationMaxLength - 1) && (Source[i] != 0); i++)
    {
        Destination[i] = (CHAR)Source[i];
    }

    Destination[i] = 0;

    return Destination;
}


char *
utf16tolowerutf8(
    _Out_writes_z_(DestinationMaxLength) char *Destination,
    _In_z_ const WCHAR *Source,
    _In_ DWORD DestinationMaxLength
    )
{
    DWORD i;

    for (i = 0; (i < DestinationMaxLength - 1) && (Source[i] != 0); i++)
    {
        char c = (char)Source[i];

        if (c >= 'A' && c <= 'Z')
        {
            c |= 0x20;
        }

        Destination[i] = c;
    }

    Destination[i] = 0;

    return Destination;
}


WCHAR *
utf8toutf16(
    _Out_writes_bytes_(DestinationMaxLength) WCHAR *Destination,
    _In_z_ const char *Source,
    _In_ DWORD DestinationMaxLength
    )
{
    DWORD i;

    for (i = 0; (i < DestinationMaxLength - 1) && (Source[i] != 0); i++)
    {
        Destination[i] = (WCHAR)Source[i];
    }

    Destination[i] = 0;

    return Destination;
}


int
is_str_ansi(
    _In_reads_z_(MaxBufferSize) const char *Buffer,
    _In_ size_t MaxBufferSize,
    _In_ size_t MinSize
    )
//
// Checks that the given Buffer is a string having at least MinSize.
// Used to verify that a given region is a buffer (there are some "corrupt" or missing
// strings in linux structures, and we must check that).
//
// \ret 0 if the string doesn't have the minimum size
// \ret -1 if there isn't a string at that address
// \ret strlen(Buffer) if it's a string (does not include the NULL!)
//
{
    DWORD i = 0;

    while (i < MaxBufferSize)
    {
        // found the end
        if (Buffer[i] == 0)
        {
            break;
        }

        // Linux convention...
        if (Buffer[i] < 0x20 && Buffer[i] != '\n' && Buffer[i] != '\t')
        {
            return -1;
        }

        if ((UCHAR)Buffer[i] >= 0x7f)
        {
            return -1;
        }

        i++;
    }

    if (i < MinSize)
    {
        return 0;
    }

    return i;
}


void
memcpy_end(
    _Out_writes_bytes_(DestinationSize) void *Destination,
    _In_reads_bytes_(SourceSize) const void *Source,
    _In_ size_t DestinationSize,
    _In_ size_t SourceSize
    )
//
// If the Destination buffer is large enough to hold the entire Source buffer, the entire buffer is copied
// Else, only the last DestinationSize bytes are copied
//
{
    if (DestinationSize >= SourceSize)
    {
        memcpy(Destination, Source, DestinationSize);
    }
    else
    {
        // copy the last DestinationSize bytes
        memcpy(Destination, (void *)((size_t)Source + SourceSize - DestinationSize), DestinationSize);
    }
}


long long
my_llabs(
    _In_ long long value
    )
{
    return value > 0 ? value : -value;
}


BOOLEAN
glob_match_utf8(
    _In_z_ char const *Pattern,
    _In_z_ char const *String,
    _In_opt_ BOOLEAN IgnoreCase,
    _In_opt_ BOOLEAN Truncated
    )
//
// See 'glob_match' inside Linux kernel sources. License: MIT, so we can change it freely.
//
{
    //
    // Backtrack to previous '*' on mismatch and retry starting one
    // character later in the string.  Because '*' matches all characters
    // (no exception for /), it can be easily proved that there's
    // never a need to backtrack multiple levels.
    //
    char const *backPattern = NULL, *back_str = NULL;

    DWORD tries = 1024;

    //
    // Loop over each token (character or class) in Pattern, matching
    // it against the remaining unmatched tail of String.  Return false
    // on mismatch, or true after matching the trailing NULL bytes.
    //
    while (--tries)
    {
        unsigned char strChar = *String++;
        unsigned char patChar = *Pattern++;

        if (IgnoreCase)
        {
            strChar = (unsigned char)tolower(strChar);
            patChar = (unsigned char)tolower(patChar);
        }

        switch (patChar)
        {
        case '?': // Anything but nul
            if (strChar == '\0')
            {
                // "winguest?" doesn't match "winguest"
                return FALSE;
            }

            break;

        case '*': // Any-length wildcard
            // Trailing '*': "winguest*" matches "winguest"
            if (*Pattern == '\0')
            {
                return TRUE;
            }

            backPattern = Pattern;
            back_str = --String; // Allow zero-length match
            break;

        case '[': // Character class
        {
            int match = 0, inverted = (*Pattern == '!');
            char const *class = Pattern + inverted;
            unsigned char startChar = *class ++;

            //
            // Iterate over each span in the character class. A span is either a single character 'a',
            // or a range 'a-b'. The first span may begin with ']'.
            //
            do
            {
                unsigned char endChar = startChar;

                // Malformed input, treat as literal
                if (startChar == '\0')
                {
                    goto literal;
                }

                if (class[0] == '-' && class[1] != ']')
                {
                    endChar = class[1];

                    if (endChar == '\0')
                    {
                        goto literal;
                    }

                    class += 2;
                }

                if (IgnoreCase)
                {
                    startChar = (unsigned char)tolower(startChar);
                    endChar = (unsigned char)tolower(endChar);
                }

                match |= (startChar <= strChar && strChar <= endChar);
            } while ((startChar = *class ++) != ']');

            if (match == inverted)
            {
                goto backtrack;
            }

            Pattern = class;
        }
        break;

        case '\\':
            patChar = *Pattern++;

            if (IgnoreCase)
            {
                patChar = (unsigned char)tolower(patChar);
            }

        // FALLTHROUGH
        default: // Literal character
literal:
            if (strChar == patChar)
            {
                if (patChar == '\0')
                {
                    return TRUE;
                }

                break;
            }

backtrack:
            if (patChar == '\0' && Truncated && !backPattern)
            {
                // Got to the end of our string, and we requested a truncated match
                return TRUE;
            }

            if (strChar == '\0' || !backPattern)
            {
                // Got to the end of our string, and we don't backtrack
                return FALSE;
            }

            // Try again from last *, one character later in String.
            Pattern = backPattern;
            String = ++back_str;
            break;
        }
    }

    return FALSE;
}


//
// glob_match_numeric_utf8
//
BOOLEAN
glob_match_numeric_utf8(
    _In_z_ char const *Pattern,
    _In_z_ char const *String
    )
// Basically my_glob_match_utf8, but treat the [x-y] pattern as a closed interval and ignore truncated & case
// insensitive flags assuming both are false.
{
    //
    // Backtrack to previous '*' on mismatch and retry starting one
    // character later in the string.  Because '*' matches all characters
    // (no exception for /), it can be easily proved that there's
    // never a need to backtrack multiple levels.
    //
    char const *backPattern = NULL, *back_str = NULL;

    DWORD tries = 1024;

    //
    // Loop over each token (character or class) in Pattern, matching
    // it against the remaining unmatched tail of String.  Return false
    // on mismatch, or true after matching the trailing nul bytes.
    //
    while (--tries)
    {
        unsigned char strChar = *String++;
        unsigned char patChar = *Pattern++;

        switch (patChar)
        {
        case '?': // Anything but nul
            if (strChar == '\0')
            {
                // "winguest?" doesn't match "winguest"
                return FALSE;
            }

            break;

        case '*': // Any-length wildcard
            // Trailing '*': "winguest*" matches "winguest"
            if (*Pattern == '\0')
            {
                return TRUE;
            }

            backPattern = Pattern;
            back_str = --String; // Allow zero-length match
            break;

        case '[': // Character class
        {
            QWORD first, last, nr;
            char *next;

            int match = 0, inverted = (*Pattern == '!');
            char const *class = Pattern + inverted;


            if (*class == '-')
            {
                first = 0;
            }
            else
            {
                first = strtoul(class, &next, 0);
                // Malformed pattern
                if (class == next || *next != '-')
                {
                    goto literal;
                }
                class = next;
            }

            class ++;

            if (*class == ']')
            {
                last = QWORD_MAX;
            }
            else
            {
                last = strtoul(class, &next, 0);
                // Again, malformed pattern
                if (class == next || *next != ']')
                {
                    goto literal;
                }
                class = next;
            }


            // String - 1 because it was incremented already
            nr = strtoul(String - 1, &next, 0);
            if (String - 1 == next)
            {
                goto literal;
            }

            match = (first <= nr && nr <= last);
            if (match == inverted)
            {
                goto backtrack;
            }

            Pattern = class + 1;
            String = next;
        }
        break;

        case '\\':
            patChar = *Pattern++;

        // FALLTHROUGH
        default: // Literal character
literal:
            if (strChar == patChar)
            {
                if (patChar == '\0')
                {
                    return TRUE;
                }
                break;
            }

backtrack:
            if (strChar == '\0' || !backPattern)
            {
                // Got to the end of our string, and we don't backtrack
                return FALSE;
            }

            // Try again from last *, one character later in String.
            Pattern = backPattern;
            String = ++back_str;
            break;
        }
    }

    return FALSE;
}


BOOLEAN
glob_match_utf16(
    _In_z_ char const *Pattern,
    _In_z_ WCHAR const *String,
    _In_opt_ BOOLEAN IgnoreCase,
    _In_opt_ BOOLEAN Truncated
    )
//
// See 'glob_match' inside linux kernel sources. License: MIT, so we can change it freely.
//
{
    //
    // Backtrack to previous '*' on mismatch and retry starting one
    // character later in the string.  Because '*' matches all characters
    // (no exception for /), it can be easily proved that there's
    // never a need to backtrack multiple levels.
    //
    char const *backPattern = NULL;
    WCHAR const *back_str = NULL;

    DWORD tries = 1024;

    //
    // Loop over each token (character or class) in Pattern, matching
    // it against the remaining unmatched tail of String.  Return false
    // on mismatch, or true after matching the trailing nul bytes.
    //
    while (--tries)
    {
        unsigned char strChar = (unsigned char) * String++;
        unsigned char patChar = *Pattern++;

        if (IgnoreCase)
        {
            strChar = (unsigned char)tolower(strChar);
            patChar = (unsigned char)tolower(patChar);
        }

        switch (patChar)
        {
        case '?': // Anything but nul
            if (strChar == '\0')
            {
                // "winguest?" doesn't match "winguest"
                return FALSE;
            }

            break;

        case '*': // Any-length wildcard
            // Trailing '*': "winguest*" matches "winguest"
            if (*Pattern == '\0')
            {
                return TRUE;
            }

            backPattern = Pattern;
            back_str = --String; // Allow zero-length match
            break;

        case '[': // Character class
        {
            int match = 0, inverted = (*Pattern == '!');
            char const *class = Pattern + inverted;
            unsigned char startChar = *class ++;

            //
            // Iterate over each span in the character class. A span is either a single character 'a',
            // or a range 'a-b'. The first span may begin with ']'.
            //
            do
            {
                unsigned char endChar = startChar;

                // Malformed input, treat as literal
                if (startChar == '\0')
                {
                    goto literal;
                }

                if (class[0] == '-' && class[1] != ']')
                {
                    endChar = class[1];

                    if (endChar == '\0')
                    {
                        goto literal;
                    }

                    class += 2;
                }

                if (IgnoreCase)
                {
                    startChar = (unsigned char)tolower(startChar);
                    endChar = (unsigned char)tolower(endChar);
                }

                match |= (startChar <= strChar && strChar <= endChar);
            } while ((startChar = *class ++) != ']');

            if (match == inverted)
            {
                goto backtrack;
            }

            Pattern = class;
        }
        break;

        case '\\':
            patChar = *Pattern++;

            if (IgnoreCase)
            {
                patChar = (unsigned char)tolower(patChar);
            }

        // FALLTHROUGH
        default: // Literal character
literal:
            if (strChar == patChar)
            {
                if (patChar == '\0')
                {
                    return TRUE;
                }

                break;
            }

backtrack:
            if (patChar == '\0' && Truncated && !backPattern)
            {
                // Got to the end of our string, and we requested a truncated match
                return TRUE;
            }

            if (strChar == '\0' || !backPattern)
            {
                // Got to the end of our string, and we don't backtrack
                return FALSE;
            }

            // Try again from last *, one character later in String.
            Pattern = backPattern;
            String = ++back_str;
            break;
        }
    }

    return FALSE;
}


size_t
wstrnlen(
    _In_reads_or_z_(maxlen) const WCHAR *s,
    _In_ size_t maxlen
    )
{
    size_t len = 0;
    while (len < maxlen && s[len])
    {
        ++len;
    }

    return len;
}


size_t
wstrlen(
    _In_z_ const WCHAR *str
    )
{
    size_t i;

    for (i = 0; str[i] != 0; i++) {}

    return i;
}


size_t
strlcpy(
    char *dst,
    const char *src,
    size_t dest_size
    )
{
    const char *orig_src = src;

    if (dest_size < 1)
    {
#ifdef DEBUG
        IntBugCheck();
#else
        return 0;
#endif // DEBUG
    }

    while (--dest_size != 0)
    {
        if (0 == (*dst++ = *src))
        {
            break;
        }

        src++;
    }

    // destination size wasn't enough, add the null terminator and parse the rest of the src
    if (dest_size == 0)
    {
        *dst = 0;
    }

    return src - orig_src;
}


size_t
wstrlcpy(
    WCHAR *dst,
    const WCHAR *src,
    size_t dest_size
    )
{
    const WCHAR *orig_src = src;

    if (dest_size < 1)
    {
#ifdef DEBUG
        IntBugCheck();
#else
        return 0;
#endif // DEBUG
    }

    while (--dest_size != 0)
    {
        if (0 == (*dst++ = *src))
        {
            break;
        }

        src++;
    }

    // destination size wasn't enough, add the null terminator and parse the rest of the src
    if (dest_size == 0)
    {
        *dst = 0;
    }

    return src - orig_src;
}


size_t
strlcat(
    char *dst,
    const char *src,
    size_t size
    )
{
    char *d = dst;
    const char *s = src;
    size_t n = size;
    size_t dest_len;

    if (size < 1)
    {
#ifdef DEBUG
        IntBugCheck();
#else
        return 0;
#endif // DEBUG
    }

    // Find the end of dst
    while ((n-- != 0) && (*d != 0))
    {
        d++;
    }

    dest_len = d - dst;
    n = size - dest_len;

    if (n == 0)
    {
        return dest_len + strlen(s);
    }

    while (*s)
    {
        if (n != 1)
        {
            *d++ = *s;
            n--;
        }

        s++;
    }

    *d = 0;

    return dest_len + (s - src);
}


//
// nd_vsnprintf_s
// This function must be implemented as the disassembler makes use if it. Since Napoca also uses the disassembler,
// it will also define this function; therefore, we only need to implement it in introcore when building for Xen.
//
int
nd_vsnprintf_s(char *str, size_t sizeOfBuffer, size_t count, const char *format, va_list args)
{
    UNREFERENCED_PARAMETER(sizeOfBuffer);

    //
    // It's safe to use vsnprintf instead of rpl_vsnprintf since on linux it
    // exists in stdlib and it's #defined to rpl_vsnprintf
    //
    return vsnprintf(str, count, format, args);
}

//
// nd_memset
// Implemented by the integrator, used by disasm. Easy way to make sure platform specific memset is used, not
// something implemented by the disasm.
//
void *nd_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}


#ifdef INT_COMPILER_MSVC

#    pragma function(memcpy)
void *
memcpy(void *dest, const void *src, size_t n)
{
    __movsb(dest, src, n);
    return dest;
}

#    pragma function(memset)
void *
memset(void *s, int c, size_t n)
{
    __stosb(s, c, n);
    return s;
}

#    pragma function(memcmp)
int
memcmp(const void *vl, const void *vr, size_t n)
{
    const unsigned char *l = vl, *r = vr;
    for (; n && *l == *r; n--, l++, r++)
        ;
    return n ? *l - *r : 0;
}

#    pragma function(strcmp)
int
strcmp(const char *l, const char *r)
{
    for (; *l == *r && *l; l++, r++)
        ;
    return *(unsigned char *)l - *(unsigned char *)r;
}

#    pragma function(strlen)
size_t
strlen(const char *s)
{
    size_t l = 0;
    while (*s++)
        l++;
    return l;
}

int
strncmp(const char *_l, const char *_r, size_t n)
{
    const unsigned char *l = (void *)_l, *r = (void *)_r;
    if (!n--)
        return 0;
    for (; *l && *r && n && *l == *r; l++, r++, n--)
        ;
    return *l - *r;
}


char *
strstr(
    _In_z_ const char *str1,
    _In_z_ const char *str2
    )
{
    const char *cp = str1;
    const char *s1, *s2;

    while (*cp)
    {
        s1 = cp;
        s2 = str2;

        while (*s1 && *s2 && !(*s1 - *s2))
        {
            s1++;
            s2++;
        }

        if (!*s2)
        {
            return (char *)cp;
        }

        cp++;
    }

    return NULL;
}

char *
strchr(
    _In_z_ const char *str,
    _In_ INT32 c
    )
{
    while (*str && *str != (char)c)
    {
        str++;
    }

    if (*str == (char)c)
    {
        return (char *)str;
    }

    return NULL;
}

char *
strrchr(
    _In_z_ const char *str,
    _In_ INT32 c
    )
{
    const char *start = str;

    while (*str++)
        ;

    // Search towards front
    while (--str != start && *str != (char)c)
    {
        ;
    }

    if (*str == (char)c)
    {
        return (char *)str;
    }

    return NULL;
}

#    pragma function(strcpy)
char *
strcpy(
    _Out_writes_z_(_String_length_(src) + 1) char *dst,
    _In_z_ const char *src
    )
{
    char *cp = dst;

#pragma warning(push)
#pragma warning(suppress : 4127)

    while ((*cp++ = *src++) != '\0')
        ; /* Copy src over dst */

#pragma warning(pop)

    return dst;
}

#endif // INT_COMPILER_MSVC
