/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introtypes.h"

//
// ANSI character macros
//
#define crt_tolower(c) ((((c) >= 'A') && ((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c))
#define crt_toupper(c) ((((c) >= 'a') && ((c) <= 'z')) ? ((c) - 'a' + 'A') : (c))

int
tolower(int c)
{
    return crt_tolower(c);
}

int
toupper(int c)
{
    return crt_toupper(c);
}

#define isalpha(c)  (((((c) >= 'A') && ((c) <= 'Z')) || (((c) >= 'a') && ((c) <= 'z'))) ? 1 : 0)

#define isdigit(c)  ((((c) >= '0') && ((c) <= '9')) ? 1 : 0)

#define isxdigit(c) (((((c) >= 'A') && ((c) <= 'F')) || (((c) >= 'a') && \
                    ((c) <= 'f')) || (((c) >= '0') && ((c) <= '9'))) ? 1 : 0)

#define isprint(c)  (((c) >= ' ' && (c) <= '~') ? 1 : 0)
#define isspace(c)  (((c) == ' ') || ((c) == '\t') || ((c) == '\n') || ((c) == '\v') || ((c) == '\f') || ((c) == '\r'))

//
// helper routines
//

static UINT64
quick_convert(
    const char *Ptr,
    const char **EndPtr
    )
{
    UINT64 result = 0;
    bool neg = false, hex = false;
    size_t i = 0;

    while (Ptr[i] == ' ')
    {
        i++;
    }

    if (Ptr[i] == '-')
    {
        neg = true, i++;
    }
    else if (Ptr[i] == '+')
    {
        neg = false, i++;
    }
    
    if (Ptr[i] == '0' && (Ptr[i + 1] == 'x' || Ptr[i + 1] == 'X'))
    {
        hex = true, i += 2;
    }

    for (; Ptr[i]; i++)
    {
        if (Ptr[i] >= '0' && Ptr[i] <= '9')
        {
            result = result * (hex ? 16 : 10) + Ptr[i] - '0';
        }
        else if (hex && Ptr[i] >= 'A' && Ptr[i] <= 'F')
        {
            result = result * 16 + Ptr[i] - 'A' + 10;
        }
        else if (hex && Ptr[i] >= 'a' && Ptr[i] <= 'f')
        {
            result = result * 16 + Ptr[i] - 'a' + 10;
        }
        else
        {
            break;
        }
    }

    if (EndPtr)
    {
        *EndPtr = Ptr + i;
    }

    if (neg && result != 0)
    {
        result = ~result + 1;
    }

    return result;
}


//
// crt_strtol
//
INT32 __cdecl
strtol(
    _In_z_ const INT8 *nptr,
    _Out_opt_ INT8 **endptr,
    _In_ INT32 ibase
    )
{
    ibase;

    return (INT32)quick_convert(nptr, (const INT8 **)endptr);
}


//
// crt_strtoul
//
UINT32 __cdecl
strtoul(
    _In_z_ const INT8 *nptr,
    _Out_opt_ INT8 **endptr,
    _In_ INT32 ibase
    )
{
    ibase;

    return (UINT32)quick_convert(nptr, (const INT8 **)endptr);
}


//
// crt_strtoll
//
INT64 __cdecl
strtoll(
    _In_z_ const INT8 *nptr,
    _Out_opt_ INT8 **endptr,
    _In_ INT32 ibase
    )
{
    ibase;

    return (INT64)quick_convert(nptr, (const INT8 **)endptr);
}


//
// crt_strtoull
//
UINT64 __cdecl
strtoull(
    _In_z_ const INT8 *nptr,
    _Out_opt_ INT8 **endptr,
    _In_ INT32 ibase
    )
{
    ibase;

    return quick_convert(nptr, (const INT8 **)endptr);
}
