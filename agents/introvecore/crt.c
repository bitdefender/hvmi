/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "vecorebase.h"

#ifdef memcpy
#undef memcpy
#endif

#ifdef memcmp
#undef memcmp
#endif

#ifdef memset
#undef memset
#endif

//
// memcpy
//
CX_VOID* __cdecl
memcpy(
    _cx_out_bcount_full_opt(Size) CX_VOID *Dest,
    _cx_in_bcount_opt(Size) const CX_VOID *Source,
    _cx_in CX_SIZE_T Size
)
{
    CX_VOID *ret = Dest;

    crt_assert(CX_NULL != Dest);
    crt_assert(CX_NULL != Source);

    if ((CX_NULL == Dest) || (CX_NULL == Source))
    {
        return CX_NULL;        // On release crt_assert doesn't build
    }

    // copy from lower addresses to higher addresses
    while (Size--)
    {
        *(CX_INT8 *)Dest = *(CX_INT8 *)Source;
        Dest = (CX_INT8 *)Dest + 1;
        Source = (CX_INT8 *)Source + 1;
    }

    return(ret);
}


//
// memcmp
//
CX_INT32 __cdecl
memcmp(
    _cx_in_bcount_opt(Size) const CX_VOID *Source1,
    _cx_in_bcount_opt(Size) const CX_VOID *Source2,
    _cx_in CX_SIZE_T Size
)
{
    crt_assert(CX_NULL != Source1);
    crt_assert(CX_NULL != Source2);
    crt_assert(Size > 0);

    if ((CX_NULL == Source1) || (CX_NULL == Source2) || (Size <= 0))
    {
        return 0;           // There's no better return value, even if 0 might be confusing.
                            // We must return a value for release builds, because crt_assert builds only for debug.
    }

    while (--Size && *(CX_INT8 *)Source1 == *(CX_INT8 *)Source2)
    {
        Source1 = (CX_INT8 *)Source1 + 1;
        Source2 = (CX_INT8 *)Source2 + 1;
    }

    return(*((CX_UINT8 *)Source1) - *((CX_UINT8 *)Source2));
}


//
// memset
//
CX_VOID* __cdecl
memset(
    _cx_out_bcount_full_opt(Size) CX_VOID *Dest,
    _cx_in CX_INT32 Value,
    _cx_in CX_SIZE_T Size
)
{
    CX_VOID *start = Dest;

    crt_assert(CX_NULL != Dest);

    if (CX_NULL == Dest)
    {
        return CX_NULL;
    }

    while (Size--)
    {
        *(CX_INT8 *)Dest = (CX_INT8)Value;
        Dest = (CX_INT8 *)Dest + 1;
    }

    return(start);
}


//
// memcpy_s
//
CX_VOID* __cdecl
memcpy_s(
    _cx_out_bcount_full_opt(Size) CX_VOID *Dest,
    _cx_in CX_SIZE_T SizeInBytes,
    _cx_in_bcount_opt(Size) const CX_VOID *Source,
    _cx_in CX_SIZE_T Size)
{
    if (0 == Size)
    {
        return CX_NULL;
    }

    if ((CX_NULL == Source) || (SizeInBytes < Size))
    {
        memzero(Dest, Size);
        return CX_NULL;
    }

    memcpy(Dest, Source, Size);

    return Dest;
}


//
// memzero
//
CX_VOID* __cdecl
memzero(
    _cx_out_bcount_full_opt(Size) CX_VOID *Dest,
    _cx_in CX_SIZE_T Size
    )
{
#if defined(CX_DEBUG_BUILD) && defined(CX_MSVC)
    CX_VOID *start = Dest;

    crt_assert(CX_NULL != Dest);

    if (CX_NULL == Dest)
    {
        return CX_NULL;
    }

    while (Size--)
    {
        *(CX_INT8 *)Dest = 0;
        Dest = (CX_INT8 *)Dest + 1;
    }

    return(start);
#else
    // this is faster on release builds, uses intrinsic
    return memset(Dest, 0, Size);
#endif
}
