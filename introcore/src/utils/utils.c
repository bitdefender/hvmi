/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "utils.h"
#include "introcrt.h"

// This assumes that S1 <= E1 AND S2 <= E2; If one range ends before the other starts, the ranges don't overlap
#define RANGES_OVERLAP(S1, E1, S2, E2)   (!((E1) < (S2) || (S1) > (E2)))


size_t
UtilBinarySearch(
    _In_bytecount_(Length) void *Buffer,
    _In_ size_t Length,
    _In_ size_t SizeOfElements,
    _In_bytecount_(SizeOfElements) void *Target
    )
//
// Will do a binary search inside the sorted array Buffer, with each element SizeOfElements bytes in size.
//
// \ret The position where the element has been found, or -1, if the element is not in the array.
//
{
    size_t left, right;
    QWORD dst, src;

    if (NULL == Buffer)
    {
        return (size_t) -1;
    }

    if (NULL == Target)
    {
        return (size_t) -1;
    }

    left = 0;
    right = (Length / SizeOfElements);

    switch (SizeOfElements)
    {
    case 1:
        dst = *((BYTE *)Target);
        break;
    case 2:
        dst = *((WORD *)Target);
        break;
    case 4:
        dst = *((DWORD *)Target);
        break;
    case 8:
        dst = *((QWORD *)Target);
        break;
    default:
        return (size_t) -1;
    }

    while (left < right)
    {
        size_t midd = (left + right) / 2;

        switch (SizeOfElements)
        {
        case 1:
            src = *((BYTE *)Buffer + midd * SizeOfElements);
            break;
        case 2:
            src = *((WORD *)((BYTE *)Buffer + midd * SizeOfElements));
            break;
        case 4:
            src = *((DWORD *)((BYTE *)Buffer + midd * SizeOfElements));
            break;
        case 8:
            src = *((QWORD *)((BYTE *)Buffer + midd * SizeOfElements));
            break;
        default:
            return (size_t) -1;
        }

        if (dst == src)
        {
            return midd;
        }
        else if (dst < src)
        {
            // We must continue the search to the left.
            right = midd;
        }
        else
        {
            // We must continue the search to the right.
            left = midd + 1;
        }
    }

    return (size_t) -1;
}


size_t
UtilInsertOrdered(
    _In_bytecount_(Length) void *Buffer,
    _In_ size_t Length,
    _In_ size_t MaximumLength,
    _In_ size_t SizeOfElements,
    _In_bytecount_(SizeOfElements) void *Target
    )
{
    size_t i;
    QWORD src, dst;

    if (NULL == Buffer)
    {
        return (size_t) -1;
    }

    if (NULL == Target)
    {
        return (size_t) -1;
    }

    if (MaximumLength < Length + SizeOfElements)
    {
        return (size_t) -1;
    }

    switch (SizeOfElements)
    {
    case 1:
        dst = *((BYTE *)Target);
        break;
    case 2:
        dst = *((WORD *)Target);
        break;
    case 4:
        dst = *((DWORD *)Target);
        break;
    case 8:
        dst = *((QWORD *)Target);
        break;
    default:
        return (size_t) -1;
    }

    for (i = Length; i > 0; i -= SizeOfElements)
    {
        switch (SizeOfElements)
        {
        case 1:
            src = *((BYTE *)Buffer + i - SizeOfElements);
            break;
        case 2:
            src = *((WORD *)((BYTE *)Buffer + i - SizeOfElements));
            break;
        case 4:
            src = *((DWORD *)((BYTE *)Buffer + i - SizeOfElements));
            break;
        case 8:
            src = *((QWORD *)((BYTE *)Buffer + i - SizeOfElements));
            break;
        default:
            return (size_t) -1;
        }

        if (dst > src)
        {
            memcpy((BYTE *)Buffer + i, &dst, SizeOfElements);
            return i / SizeOfElements;
        }
        else
        {
            memcpy((BYTE *)Buffer + i, &src, SizeOfElements);
        }
    }

    // We must put it on position 0.
    memcpy(Buffer, Target, SizeOfElements);

    return 0;
}


//
// Using a if-else/switch by ElementSize to do indexing of Array, slows this down by 30-50%
// This macro is only needed for `pivot` type, and for direct indexing.
// Names generated: _QuickSort<TypeOfArray>, eg: _QuickSortQWORD, _QuickSortBYTE, etc.
//
#define QUICKSORT_FUNCTION(Array, TypeOfArray)                          \
static void                                                             \
_QuickSort##TypeOfArray(                                                \
    _Inout_updates_all_(NumberOfElements) TypeOfArray *Array,           \
    _In_ const DWORD NumberOfElements                                   \
    )                                                                   \
{                                                                       \
    DWORD begin[64] = {0}, end[64] = {0};                               \
    TypeOfArray pivot;                                                  \
    int i = 0;                                                          \
    int swap;                                                           \
                                                                        \
    end[0] = NumberOfElements;                                          \
                                                                        \
    while (i >= 0)                                                      \
    {                                                                   \
        int left = begin[i];                                            \
        int right = end[i] - 1;                                         \
                                                                        \
        if (left < right)                                               \
        {                                                               \
            pivot = Array[left];                                        \
                                                                        \
            while (left < right)                                        \
            {                                                           \
                while (Array[right] >= pivot && left < right)           \
                {                                                       \
                    right--;                                            \
                }                                                       \
                                                                        \
                if (left < right)                                       \
                {                                                       \
                    Array[left++] = Array[right];                       \
                }                                                       \
                                                                        \
                while (Array[left] <= pivot && left < right)            \
                {                                                       \
                    left++;                                             \
                }                                                       \
                                                                        \
                if (left < right)                                       \
                {                                                       \
                    Array[right--] = Array[left];                       \
                }                                                       \
            }                                                           \
                                                                        \
            Array[left] = pivot;                                        \
                                                                        \
            begin[i + 1] = left + 1;                                    \
            end[i + 1] = end[i];                                        \
            end[i++] = left;                                            \
                                                                        \
            if (end[i] - begin[i] > end[i - 1] - begin[i - 1])          \
            {                                                           \
                swap = begin[i];                                        \
                begin[i] = begin[i - 1];                                \
                begin[i - 1] = swap;                                    \
                                                                        \
                swap = end[i];                                          \
                end[i] = end[i - 1];                                    \
                end[i - 1] = swap;                                      \
            }                                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            i--;                                                        \
        }                                                               \
    }                                                                   \
}


QUICKSORT_FUNCTION(Array, QWORD);
QUICKSORT_FUNCTION(Array, DWORD);
QUICKSORT_FUNCTION(Array, WORD);
QUICKSORT_FUNCTION(Array, BYTE);


void
UtilQuickSort(
    _Inout_updates_bytes_(NumberOfElements *ElementSize) void *Array,
    _In_ const DWORD NumberOfElements,
    _In_ const BYTE ElementSize
    )
{
    switch (ElementSize)
    {
    case 1:
        _QuickSortBYTE(Array, NumberOfElements);
        break;
    case 2:
        _QuickSortWORD(Array, NumberOfElements);
        break;
    case 4:
        _QuickSortDWORD(Array, NumberOfElements);
        break;
    case 8:
        _QuickSortQWORD(Array, NumberOfElements);
        break;
    }
}


size_t
UtilBinarySearchStructure(
    _In_bytecount_(Count *SizeOfElements) void *Buffer,
    _In_ size_t Count,              // Number of structures
    _In_ size_t SizeOfElements,     // Elements size
    _In_ DWORD CompareFieldOffset,  // The offset of the compare field
    _In_bytecount_(TargetSize) void *Target,
    _In_ DWORD TargetSize
    )
//
// Will do a binary search inside the sorted array of structures Buffer, with each element SizeOfElements bytes in size.
// Will compare the Element at CompareFieldOffset with the element at Target, both of size TargetSize.
//
// \ret The position where the element has been found, or -1, if the element is not in the array.
//
{
    size_t left, right;
    QWORD dst, src;

    if (NULL == Buffer)
    {
        return (size_t) -1;
    }

    if (NULL == Target)
    {
        return (size_t) -1;
    }

    left = 0;
    right = Count;

    switch (TargetSize)
    {
    case 1:
        dst = *((BYTE *)Target);
        break;
    case 2:
        dst = *((WORD *)Target);
        break;
    case 4:
        dst = *((DWORD *)Target);
        break;
    case 8:
        dst = *((QWORD *)Target);
        break;
    default:
        return (size_t) -1;
    }

    while (left < right)
    {
        size_t midd = (left + right) / 2;

        switch (TargetSize)
        {
        case 1:
            src = *((BYTE *)Buffer + midd * SizeOfElements + CompareFieldOffset);
            break;
        case 2:
            src = *((WORD *)((BYTE *)Buffer + midd * SizeOfElements + CompareFieldOffset));
            break;
        case 4:
            src = *((DWORD *)((BYTE *)Buffer + midd * SizeOfElements + CompareFieldOffset));
            break;
        case 8:
            src = *((QWORD *)((BYTE *)Buffer + midd * SizeOfElements + CompareFieldOffset));
            break;
        default:
            return (size_t) -1;
        }

        if (dst == src)
        {
            return midd;
        }
        else if (dst < src)
        {
            // We must continue the search to the left.
            right = midd;
        }
        else
        {
            // We must continue the search to the right.
            left = midd + 1;
        }
    }

    return (size_t) -1;
}


void
UtilSortQwords(
    _Inout_updates_(NumberOfElements) QWORD *Array,
    _In_ const DWORD NumberOfElements
    )
{
    BOOLEAN swapped = TRUE;
    size_t j = 0;

    while (swapped)
    {
        swapped = FALSE;
        j++;

        for (size_t i = 0; i < NumberOfElements - j; i++)
        {
            if (Array[i] > Array[i + 1])
            {
                QWORD tmp = Array[i];
                Array[i] = Array[i + 1];
                Array[i + 1] = tmp;

                swapped = TRUE;
            }
        }
    }
}


BOOLEAN
UtilIsBufferZero(
    _In_bytecount_(BufferSize) void *Buffer,
    _In_ size_t BufferSize
    ) 
{
    static const char zeroPage[PAGE_SIZE] = { 0 };

    if (BufferSize > PAGE_SIZE || NULL == Buffer)
    {
        return FALSE;
    }

    return memcmp(Buffer, zeroPage, BufferSize) == 0;
}
