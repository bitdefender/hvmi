/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HOOK_PTWH_H_
#define _HOOK_PTWH_H_

#include "introtypes.h"


#define LAST_WRITE_RIP_MASK     ((1ULL << 23) - 1)  ///< We keep only the low 32 bits from the RIP.

///
/// Page Table Entry Write State. Whenever processing a page-table write, this structure keeps the intermediate state,
/// as a page-table write may only modify a partial chunk of the entry. We call the swap callbacks only when the entire
/// page-table entry has been written.
///
typedef struct _HOOK_PTEWS
{
    QWORD               CurEntry;           ///< Current page-table entry value.
    QWORD               IntEntry;           ///< Intermediate page-table entry value.
    /// @brief  Bit mask indicating which bytes inside the page-table entry have been written.
    DWORD               WrittenMask : 8;
    DWORD               LastWriteRip : 23;  ///< Last RIP that wrote this entry (low 23 bits only).
    DWORD               LastWriteSize : 1;  ///< The size of the last write (1 == 8 bytes, 0 == 4 bytes).
} HOOK_PTEWS, *PHOOK_PTEWS;


//
// API
//
INTSTATUS
IntHookPtwEmulateWrite(
    _In_ QWORD Address
    );

_Success_(return == INT_STATUS_SUCCESS)
INTSTATUS
IntHookPtwProcessWrite(
    _Inout_ PHOOK_PTEWS WriteState,
    _In_ QWORD Address,
    _In_ BYTE EntrySize,
    _Out_ QWORD *OldValue,
    _Out_ QWORD *NewValue
    );


#endif // _HOOK_PTWH_H_
