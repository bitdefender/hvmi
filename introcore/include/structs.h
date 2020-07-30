/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTSTRUCTS_H_
#define _INTSTRUCTS_H_

#include "introcore.h"

///
/// @brief Structure getter callback.
///
/// Structure getter callback. Will be called on each offset inside a map
/// in order to fill an internal structure with elements from a guest structure.
/// Responsible for incrementing the offsets with which the guest structure
/// is iterated and performing any sanity checks.
///
/// @param[in] Buffer       Buffer in which the search is performed.
/// @param[in] Size         The size of the buffer.
/// @param[in,out] Offset   Offset in the buffer where the current search is begin performed.
///                         The callback should increment this offset accordingly.
/// @param[in,out] Context  Context given by the caller, can be anything.
///
typedef _Function_class_(PFUNC_IntStructGetter)
INTSTATUS (*PFUNC_IntStructGetter)(
    _In_reads_bytes_(Size) const void *Buffer,
    _In_ size_t Size,
    _Inout_ size_t *Offset,
    _Inout_opt_ void *Context
    );


///
/// Describe an invariant with which a guest structure/field is extracted from the guest
///
typedef struct _INT_STRUCT_INVARIANT
{
    /// @brief Offset from where the field/structure is to be extracted.
    ///
    /// Will be #INT_OFFSET_NOT_INITIALIZED if the offset is to be searched for,
    /// or any other value if it's known.
    size_t Offset;

    /// @brief Callback function that is responsible for searching for the offset and
    /// extracting a field/structure from the guest.
    PFUNC_IntStructGetter Getter;
} INT_STRUCT_INVARIANT;

/// @brief  Specifies that an offset value is yet to be searched for.
#define INT_OFFSET_NOT_INITIALIZED      ((size_t) -1)

/// @brief  Maximum size of a buffer in which to search for fields/structures.
#define INT_STRUCT_MAX_SEARCH_SIZE      ((size_t) PAGE_SIZE) // for now, just page size

/// @brief  Upper limit of the number of invariants to be applied to a bufffer.
#define INT_STRUCT_MAX_INVARIANT_CNT    ((size_t) 64)        // needed?

INTSTATUS
IntStructFill(
    _In_reads_bytes_(Size) const void *Buffer,
    _In_ size_t Size,
    _Inout_updates_(Count) INT_STRUCT_INVARIANT *Invariants,
    _In_ size_t Count,
    _In_ BOOLEAN LogErrors,
    _Inout_opt_ void *Context
    );

#endif // !_INTSTRUCTS_H_
