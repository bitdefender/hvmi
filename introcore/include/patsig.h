/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PATSIG_H_
#define _PATSIG_H_

#include "introtypes.h"

/// The maximum size of a pattern.
#define SIG_MAX_PATTERN             128u
/// Signals that a signature was not matched.
#define SIG_NOT_FOUND               0xFFFFFFFF
/// Signals that a signature matched.
#define SIG_FOUND                   0

#pragma pack(push)
#pragma pack(1)

///
/// @brief  Describes a signature that can be used for searching or matching guest contents.
///
typedef struct _PATTERN_SIGNATURE
{
    DWORD       Length;         ///< The valid size of the Pattern array.
    DWORD       SignatureId;    ///< Signature ID.
    DWORD       Offset;         ///< Offset inside the tested buffer at which the pattern should be found.
    INT64       AuxData;        ///< Signature specific auxiliary data.
    /// The pattern that must be matched.
    ///
    /// Each entry is a byte that must be matched. 0x100 can be used as a wild card for matching anything.
    WORD        Pattern[SIG_MAX_PATTERN];
} PATTERN_SIGNATURE, *PPATTERN_SIGNATURE;

#pragma pack(pop)

DWORD
IntPatternMatch(
    _In_ const BYTE *Buffer,
    _In_ DWORD SigCount,
    _In_ const PATTERN_SIGNATURE *Sigs
    );

DWORD
IntPatternMatchAllOffsets(
    _In_ const BYTE *Buffer,
    _In_ const DWORD BufferSize,
    _In_ DWORD SigCount,
    _In_ const PATTERN_SIGNATURE *Sigs
    );

#endif // _PATSIG_H_
