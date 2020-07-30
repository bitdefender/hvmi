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

/***
*crt_strtol, crt_strtoul(nptr,endptr,ibase) - Convert ascii string to INT32 un/INT32
*       INT32.
*
*Purpose:
*       Convert an ascii string to a INT32 32-bit value.  The base
*       used for the caculations is supplied by the caller.  The base
*       must be in the range 0, 2-36.  If a base of 0 is supplied, the
*       ascii string must be examined to determine the base of the
*       number:
*               (a) First INT8 = '0', second INT8 = 'x' or 'X',
*                   use base 16.
*               (b) First INT8 = '0', use base 8
*               (c) First INT8 in range '1' - '9', use base 10.
*
*       If the 'endptr' value is non-NULL, then crt_strtol/crt_strtoul places
*       a pointer to the terminating character in this value.
*       See ANSI standard for details
*
*Entry:
*       nptr == NEAR/FAR pointer to the start of string.
*       endptr == NEAR/FAR pointer to the end of the string.
*       ibase == integer base to use for the calculations.
*
*       string format: [whitespace] [sign] [0] [x] [digits/letters]
*
*Exit:
*       Good return:
*               result
*
*       Overflow return:
*               crt_strtol -- INT32_MAX or INT32_MIN
*               crt_strtoul -- UINT32_MAX
*               crt_strtol/crt_strtoul -- errno == ERANGE
*
*       No digits or bad base return:
*               0
*               endptr = nptr*
*
*Exceptions:
*       Input parameters are validated. Refer to the validation section of the function.
*
*******************************************************************************/

/* flag values */
#define FL_UNSIGNED  1 /* crt_strtoul called */
#define FL_NEG       2 /* negative sign found */
#define FL_OVERFLOW  4 /* overflow occurred */
#define FL_READDIGIT 8 /* we've read at least one correct digit */

static UINT32 __cdecl
crt_strtoxl(
    const INT8 *nptr,
    const INT8 **endptr,
    INT32 ibase,
    INT32 flags
    )
{
    const INT8 *p;
    INT8 c;
    UINT32 number;
    UINT32 digval;
    UINT32 maxval;

    /* validation section */
    if (endptr != NULL)
    {
        /* store beginning of string in endptr */
        *endptr = (INT8 *)nptr;
    }

    /// TO-DO: reimplement validation
    ///_VALIDATE_RETURN(nptr != NULL, EINVAL, 0L);
    ///_VALIDATE_RETURN(ibase == 0 || (2 <= ibase && ibase <= 36), EINVAL, 0L);

    p = nptr;   /* p is our scanning pointer */
    number = 0; /* start with zero */

    c = *p++; /* read INT8 */
    ///while ( _isspace_l((INT32)(UINT8)c, _loc_update.GetLocaleT()) )
    while (' ' == (INT32)(UINT8)c)
        c = *p++; /* skip whitespace */

    if (c == '-')
    {
        flags |= FL_NEG; /* remember minus sign */
        c = *p++;
    }
    else if (c == '+')
        c = *p++; /* skip sign */

    if (ibase < 0 || ibase == 1 || ibase > 36)
    {
        /* bad base! */
        if (endptr)
            /* store beginning of string in endptr */
            *endptr = nptr;
        return 0L; /* return 0 */
    }
    else if (ibase == 0)
    {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 0)
    {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 16)
    {
        /* we might have 0x in front of number; remove if there */
        if (c == '0' && (*p == 'x' || *p == 'X'))
        {
            ++p;
            c = *p++; /* advance past prefix */
        }
    }

    /* if our number exceeds this, we will overflow on multiply */
    maxval = INT32_MAX / ibase;


    for (;;)
    {
        /* exit in middle of loop */
        /* convert c to value */
        ///if ( __ascii_isdigit_l((INT32)(UINT8)c, _loc_update.GetLocaleT()) )
        if (isdigit((INT32)(UINT8)c))
            digval = c - '0';
        ///else if ( __ascii_isalpha_l((INT32)(UINT8)c, _loc_update.GetLocaleT()) )
        else if (isalpha((INT32)(UINT8)c))
            ///digval = __ascii_toupper(c) - 'A' + 10;
            digval = toupper(c) - 'A' + 10;
        else
            break;
        if (digval >= (UINT32)ibase)
            break; /* exit loop if bad digit found */

        /* record the fact we have read one digit */
        flags |= FL_READDIGIT;

        /* we now need to compute number = number * base + digval,
           but we need to know if overflow occurred.  This requires
           a tricky pre-check. */

        if (number < maxval || (number == maxval && (UINT32)digval <= UINT32_MAX % ibase))
        {
            /* we won't overflow, go ahead and multiply */
            number = number * ibase + digval;
        }
        else
        {
            /* we would have overflowed -- set the overflow flag */
            flags |= FL_OVERFLOW;
            if (endptr == NULL)
            {
                /* no need to keep on parsing if we
                   don't have to return the endptr. */
                break;
            }
        }

        c = *p++; /* read next digit */
    }

    --p; /* point to place that stopped scan */

    if (!(flags & FL_READDIGIT))
    {
        /* no number there; return 0 and point to beginning of
           string */
        if (endptr)
            /* store beginning of string in endptr later on */
            p = nptr;
        number = 0L; /* return 0 */
    }
    else if ((flags & FL_OVERFLOW) || (!(flags & FL_UNSIGNED) && (((flags & FL_NEG) && (number > -INT32_MIN)) ||
                                                                  (!(flags & FL_NEG) && (number > INT32_MAX)))))
    {
        /* overflow or INT32 overflow occurred */
        ///errno = ERANGE;
        if (flags & FL_UNSIGNED)
            number = INT32_MAX;
        else if (flags & FL_NEG)
            number = (UINT32)(-INT32_MIN);
        else
            number = INT32_MAX;
    }

    if (endptr != NULL)
        /* store pointer to INT8 that stopped the scan */
        *endptr = p;

    if (flags & FL_NEG)
        /* negate result if there was a neg sign */
        number = (UINT32)(-(INT32)number);

    return number; /* done. */
}

static UINT64 __cdecl
crt_strtoxll(
    const INT8 *nptr,
    const INT8 **endptr,
    INT32 ibase,
    INT32 flags
    )
{
    const INT8 *p;
    INT8 c;
    UINT64 number;
    UINT32 digval;
    UINT64 maxval;

    /* validation section */
    if (endptr != NULL)
    {
        /* store beginning of string in endptr */
        *endptr = (INT8 *)nptr;
    }

    /// TO-DO: reimplement validation
    ///_VALIDATE_RETURN(nptr != NULL, EINVAL, 0L);
    ///_VALIDATE_RETURN(ibase == 0 || (2 <= ibase && ibase <= 36), EINVAL, 0L);

    p = nptr;   /* p is our scanning pointer */
    number = 0; /* start with zero */

    c = *p++; /* read INT8 */
    ///while ( _isspace_l((INT32)(UINT8)c, _loc_update.GetLocaleT()) )
    while (' ' == (INT32)(UINT8)c)
        c = *p++; /* skip whitespace */

    if (c == '-')
    {
        flags |= FL_NEG; /* remember minus sign */
        c = *p++;
    }
    else if (c == '+')
        c = *p++; /* skip sign */

    if (ibase < 0 || ibase == 1 || ibase > 36)
    {
        /* bad base! */
        if (endptr)
            /* store beginning of string in endptr */
            *endptr = nptr;
        return 0L; /* return 0 */
    }
    else if (ibase == 0)
    {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 0)
    {
        /* determine base free-lance, based on first two chars of
           string */
        if (c != '0')
            ibase = 10;
        else if (*p == 'x' || *p == 'X')
            ibase = 16;
        else
            ibase = 8;
    }

    if (ibase == 16)
    {
        /* we might have 0x in front of number; remove if there */
        if (c == '0' && (*p == 'x' || *p == 'X'))
        {
            ++p;
            c = *p++; /* advance past prefix */
        }
    }

    /* if our number exceeds this, we will overflow on multiply */
    maxval = UINT64_MAX / ibase;


    for (;;)
    {
        /* exit in middle of loop */
        /* convert c to value */
        ///if ( __ascii_isdigit_l((INT32)(UINT8)c, _loc_update.GetLocaleT()) )
        if (isdigit((INT32)(UINT8)c))
            digval = c - '0';
        ///else if ( __ascii_isalpha_l((INT32)(UINT8)c, _loc_update.GetLocaleT()) )
        else if (isalpha((INT32)(UINT8)c))
            ///digval = __ascii_toupper(c) - 'A' + 10;
            digval = toupper(c) - 'A' + 10;
        else
            break;
        if (digval >= (UINT32)ibase)
            break; /* exit loop if bad digit found */

        /* record the fact we have read one digit */
        flags |= FL_READDIGIT;

        /* we now need to compute number = number * base + digval,
           but we need to know if overflow occurred.  This requires
           a tricky pre-check. */

        if (number < maxval || (number == maxval && (UINT64)digval <= UINT64_MAX % ibase))
        {
            /* we won't overflow, go ahead and multiply */
            number = number * ibase + digval;
        }
        else
        {
            /* we would have overflowed -- set the overflow flag */
            flags |= FL_OVERFLOW;
            if (endptr == NULL)
            {
                /* no need to keep on parsing if we
                   don't have to return the endptr. */
                break;
            }
        }

        c = *p++; /* read next digit */
    }

    --p; /* point to place that stopped scan */

    if (!(flags & FL_READDIGIT))
    {
        /* no number there; return 0 and point to beginning of
           string */
        if (endptr)
            /* store beginning of string in endptr later on */
            p = nptr;
        number = 0L; /* return 0 */
    }
    else if ((flags & FL_OVERFLOW) || (!(flags & FL_UNSIGNED) && (((flags & FL_NEG) && (number > -INT64_MIN)) ||
                                                                  (!(flags & FL_NEG) && (number > INT64_MAX)))))
    {
        /* overflow or INT32 overflow occurred */
        ///errno = ERANGE;
        if (flags & FL_UNSIGNED)
            number = UINT64_MAX;
        else if (flags & FL_NEG)
            number = (UINT64)(-INT64_MIN);
        else
            number = INT64_MAX;
    }

    if (endptr != NULL)
        /* store pointer to INT8 that stopped the scan */
        *endptr = p;

    if (flags & FL_NEG)
        /* negate result if there was a neg sign */
        number = (UINT64)(-(INT64)number);

    return number; /* done. */
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
    return (INT32)crt_strtoxl(nptr, (const INT8 **)endptr, ibase, 0);
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
    return crt_strtoxl(nptr, (const INT8 **)endptr, ibase, FL_UNSIGNED);
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
    return (INT64)crt_strtoxll(nptr, (const INT8 **)endptr, ibase, 0);
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
    return crt_strtoxll(nptr, (const INT8 **)endptr, ibase, FL_UNSIGNED);
}
