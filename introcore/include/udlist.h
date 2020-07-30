/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UDLIST_H_
#define _UDLIST_H_

#include "introtypes.h"


///
/// One pending UD injection.
///
typedef struct _INFO_UD_PENDING
{
    LIST_ENTRY  Link;   ///< List entry element.
    QWORD       Cr3;    ///< Target virtual address space.
    QWORD       Rip;    ///< The Rip.
    QWORD       Thread; ///< Software thread ID.
} INFO_UD_PENDING, *PINFO_UD_PENDING;


//
// API.
//
INTSTATUS
IntUDAddToPendingList(
    _In_ const QWORD Cr3,
    _In_ const QWORD Rip,
    _In_ const QWORD Thread,
    _Out_ INFO_UD_PENDING **CurrentPendingUD
    );

void
IntUDRemoveEntry(
    _Inout_ INFO_UD_PENDING **InfoUD
    );

void
IntUDRemoveAllEntriesForCr3(
    _In_ const QWORD Cr3
    );

INFO_UD_PENDING *
IntUDGetEntry(
    _In_ const QWORD Cr3,
    _In_ const QWORD Rip,
    _In_ const QWORD Thread
    );

#endif // _UDLIST_H_
