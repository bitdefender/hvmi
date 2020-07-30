/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "patsig.h"


DWORD
IntPatternMatch(
    _In_ const BYTE *Buffer,
    _In_ DWORD SigCount,
    _In_ const PATTERN_SIGNATURE *Sigs
    )
///
/// @brief  Matches one of the given signatures on the given buffer.
///
/// @param[in]  Buffer      The buffer to be checked. The caller must ensure that the buffer is large enough to
///                         properly check all the signatures.
/// @param[in]  SigCount    The number of entries in the Sigs array.
/// @param[in]  Sigs        The array of signatures to check.
///
/// @returns    The index in the Sigs array of the first matching signature, or #SIG_NOT_FOUND if no signature is
///             matched or the Buffer or Sigs pointers are NULL.
///
{
    if (Buffer == NULL || Sigs == NULL)
    {
        return SIG_NOT_FOUND;
    }

    for (DWORD i = 0; i < SigCount; i++)
    {
        BOOLEAN matched = TRUE;

        for (DWORD j = 0; j < Sigs[i].Length; j++)
        {
            if (Sigs[i].Pattern[j] != 0x100 &&
                Sigs[i].Pattern[j] != Buffer[Sigs[i].Offset + j])
            {
                matched = FALSE;
                break;
            }
        }

        if (matched)
        {
            return i;
        }
    }

    return SIG_NOT_FOUND;
}


DWORD
IntPatternMatchAllOffsets(
    _In_ const BYTE *Buffer,
    _In_ const DWORD BufferSize,
    _In_ DWORD SigCount,
    _In_ const PATTERN_SIGNATURE *Sigs
    )
///
/// @brief  Matches one of the given signatures on the given buffer at any offset inside the given buffer.
///
/// @param[in]  Buffer      The buffer to be checked.
/// @param[in]  BufferSize  The size of the buffer.
/// @param[in]  SigCount    The number of entries in the Sigs array.
/// @param[in]  Sigs        The array of signatures to check.
///
/// @returns    The index in the Sigs array of the first matching signature, or #SIG_NOT_FOUND if no signature is
///             matched or the Buffer or Sigs pointers are NULL.
///
{
    if (Buffer == NULL || Sigs == NULL)
    {
        return SIG_NOT_FOUND;
    }

    for (DWORD i = 0; i < SigCount; i++)
    {
        // check at each offset of buffer
        for (DWORD bufferOffset = 0; bufferOffset + Sigs[i].Length <= BufferSize; bufferOffset++)
        {
            DWORD foundSigId = IntPatternMatch(Buffer + bufferOffset, 1, &Sigs[i]);
            if (0 == foundSigId) // only one element, can be SIG_NOT_FOUND or 0
            {
                return i;
            }
        }
    }

    return SIG_NOT_FOUND;
}
