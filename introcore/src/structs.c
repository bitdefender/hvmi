/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "structs.h"

INTSTATUS
IntStructFill(
    _In_reads_bytes_(Size) const void *Buffer,
    _In_ size_t Size,
    _Inout_updates_(Count) INT_STRUCT_INVARIANT *Invariants,
    _In_ size_t Count,
    _In_ BOOLEAN LogErrors,
    _Inout_opt_ void *Context
    )
///
/// @brief         Fill an internal structure with information gathered from the guest by applying
/// a list of invariants on buffer.
///
/// Will simply iterate through the buffer, letting the invariants increment the offsets
/// where they are applied and set each invariants' known offset to the one where it was 
/// successful, then go to the next one.
///
/// @param[in]      Buffer      The buffer in which to perform the search.
/// @param[in]      Size        The size of the buffer.
/// @param[in,out]  Invariants  List of invariants that are to be applied on the buffer.
/// @param[in]      Count       The number of invariants to be applied.
/// @param[in]      LogErrors   Set to TRUE if this function should log any errors on failure.
/// @param[in,out]  Context     Context to be given to each invariant callback, can be anything.
///
/// @returns  #INT_STATUS_SUCCESS if successful, or an appropriate #INTSTATUS error value.
///
{
    size_t inv = 0;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Size || Size > INT_STRUCT_MAX_SEARCH_SIZE)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Invariants)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (0 == Count || Count > INT_STRUCT_MAX_INVARIANT_CNT)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    for (size_t lastOffset = 0; inv < Count; inv++)
    {
        INTSTATUS status = INT_STATUS_NOT_FOUND;

        if (Invariants[inv].Offset == INT_OFFSET_NOT_INITIALIZED)
        {
            for (size_t i = lastOffset; i < Size; )
            {
                lastOffset = i;
                status = Invariants[inv].Getter(Buffer, Size, &i, Context);
                if (INT_SUCCESS(status))
                {
                    Invariants[inv].Offset = lastOffset;
                    lastOffset = i;
                    break;
                }
            }
        }
        else
        {
            lastOffset = Invariants[inv].Offset;
            status = Invariants[inv].Getter(Buffer, Size, &lastOffset, Context);
        }

        if (!INT_SUCCESS(status))
        {
            if (LogErrors)
            {
                ERROR("[ERROR] Failed applying invariant %zu @ 0x%zx\n", inv, lastOffset);
            }

            return status;
        }
    }

    return inv == Count ? INT_STATUS_SUCCESS : INT_STATUS_NOT_INITIALIZED;
}

