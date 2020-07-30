/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "bitmask.h"
#include "glue.h"
#include "introcrt.h"


static inline
UINT64 *
BitMaskGetBaseAndBit(
    _In_ BITMASK *BitMask,
    _Inout_ DWORD *BitPos
    )
///
/// @brief  Return the base and the position of a bit relative to that base.
///
/// @param[in]      BitMask The bit mask.
/// @param[in, out] BitPos  As input, the position of the bit in the bitmask. After this function returns, it will
///                         contain the bit position relative to the bit base.
///
/// @returns        The bit base for the given bit position. This is the #BITMASK.Bits entry in which the given bit is
///                 found.
///
{
    UINT64 *b = (UINT64 *)BitMask->Bits + (*BitPos / 64);

    *BitPos %= 64;

    return b;
}


static inline
UINT64 *
BitMaskGetBase(
    _In_ BITMASK *BitMask,
    _In_ DWORD BitPos
    )
///
/// @brief  Returns the bit base for a given bit position.
///
/// @param[in]  BitMask The bit mask.
/// @param[in]  BitPos  As input, the position of the bit in the bitmask.
///
/// @returns    The bit base for the given bit position. This is the #BITMASK.Bits entry in which the given bit is
///             found.
///
{
    return (UINT64 *)BitMask->Bits + (BitPos / 64);
}


BITMASK *
BitMaskAlloc(
    _In_ size_t Size
    )
///
/// @brief  Creates a new #BITMASK.
///
/// The actual size of the #BITMASK.Bits array will be (Size / 8) is Size is divisible by 8, otherwise (Size / 8) + 1.
///
/// @param[in]  Size    The number of bits in the bit mask.
///
/// @returns    On success, a pointer to the newly created #BITMASK. The caller must free this using #BitMaskFree. On
///             failure, NULL. All bits will be set to 0.
///
{
    BITMASK *bitmask = HpAllocWithTag(sizeof(*bitmask) + (Size / 8) + (Size % 8 != 0), IC_TAG_ALLOC);
    if (NULL == bitmask)
    {
        return NULL;
    }

    bitmask->Length = Size;

    return bitmask;
}


void
BitMaskFree(
    _Inout_ BITMASK **BitMask
    )
///
/// @brief  Frees a #BITMASK allocated by #BitMaskAlloc.
///
/// @param[in, out] BitMask     Pointer to the #BITMASK pointer to be freed. Upon return will point to NULL.
///
{
    HpFreeAndNullWithTag(BitMask, IC_TAG_ALLOC);
}


void
BitMaskSet(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    )
///
/// @brief  Sets a bit in a #BITMASK.
///
/// If the given bit is not a member of the #BITMASK this function does nothing.
///
/// @param[in, out] BitMask The bit mask in which to set the bit.
/// @param[in]      BitPos  The position of the bit.
///
{
    if (BitPos > BitMask->Length)
    {
        ERROR("[ERROR] Trying to set bit %u which is outside of the bitmask (%zu length)\n",
              BitPos, BitMask->Length);
        return;
    }

    UINT64 *bitBase = BitMaskGetBaseAndBit(BitMask, &BitPos);

    *bitBase |= (1ull << BitPos);
}


void
BitMaskClear(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    )
///
/// @brief  Clears a bit in a #BITMASK.
///
/// If the given bit is not a member of the #BITMASK this function does nothing.
///
/// @param[in, out] BitMask The bit mask in which to clear the bit.
/// @param[in]      BitPos  The position of the bit.
///
{
    if (BitPos > BitMask->Length)
    {
        ERROR("[ERROR] Trying to set bit %u which is outside of the bitmask (%zu length)\n",
              BitPos, BitMask->Length);
        return;
    }

    UINT64 *bitBase = BitMaskGetBaseAndBit(BitMask, &BitPos);

    *bitBase &= ~(1ull << BitPos);
}


BYTE
BitMaskTest(
    _In_ BITMASK *BitMask,
    _In_ DWORD BitPos
    )
///
/// @brief  Tests a bit in a #BITMASK.
///
/// If the given bit is not a member of the #BITMASK this function does nothing.
///
/// @param[in, out] BitMask The bit mask in which to test the bit.
/// @param[in]      BitPos  The position of the bit.
///
/// @returns        1 if the bit is set, 0 if the bit is not set.
///
{
    if (BitPos > BitMask->Length)
    {
        ERROR("[ERROR] Trying to set bit %u which is outside of the bitmask (%zu length)\n",
              BitPos, BitMask->Length);
        return 0;
    }

    UINT64 *bitBase = BitMaskGetBaseAndBit(BitMask, &BitPos);

    return (*bitBase >> BitPos) & 1;
}


BYTE
BitMaskTestAndSet(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    )
///
/// @brief  Tests and sets a bit in a #BITMASK.
///
/// If the given bit is not a member of the #BITMASK this function does nothing.
///
/// @param[in, out] BitMask The bit mask in which to test and set the bit. After this function returns, the bit at
///                         BitPos will be set.
/// @param[in]      BitPos  The position of the bit.
///
/// @returns        THe old value of the bit at BitPos (1 if it was set, 0 if it was not set).
///
{
    if (BitPos > BitMask->Length)
    {
        ERROR("[ERROR] Trying to set bit %u which is outside of the bitmask (%zu length)\n",
              BitPos, BitMask->Length);
        return 0;
    }

    UINT64 *bitBase = BitMaskGetBaseAndBit(BitMask, &BitPos);

    BYTE old = (*bitBase >> BitPos) & 1;

    *bitBase |= (1ull << BitPos);

    return old;
}


BYTE
BitMaskTestAndReset(
    _Inout_ BITMASK *BitMask,
    _In_ DWORD BitPos
    )
///
/// @brief  Tests and clears a bit in a #BITMASK.
///
/// If the given bit is not a member of the #BITMASK this function does nothing.
///
/// @param[in, out] BitMask The bit mask in which to test and clear the bit. After this function returns, the bit at
///                         BitPos will be cleared.
/// @param[in]      BitPos  The position of the bit.
///
/// @returns        THe old value of the bit at BitPos (1 if it was set, 0 if it was not set).
///
{
    if (BitPos > BitMask->Length)
    {
        ERROR("[ERROR] Trying to set bit %u which is outside of the bitmask (%zu length)\n",
              BitPos, BitMask->Length);

        return 0;
    }

    UINT64 *bitBase = BitMaskGetBaseAndBit(BitMask, &BitPos);

    BYTE old = (*bitBase >> BitPos) & 1;

    *bitBase &= ~(1ull << BitPos);

    return old;
}


DWORD
BitMaskScanForward(
    _In_ BITMASK *BitMask
    )
///
/// @brief  Search for a set bit starting from the least significant bit.
///
/// @param[in]  BitMask The bit mask in which to search the bit.
///
/// @returns    The position of the first set (1) bit found. If no bit is found, the returned value is -1.
{
    DWORD index = 0;

    for (DWORD i = 0; i < BitMask->Length; i += 64)
    {
        UINT64 base = *BitMaskGetBase(BitMask, i);

        if (!_BitScanForward64(&index, ~base))
        {
            continue;
        }

        return i + index;
    }

    return (DWORD) -1;
}
