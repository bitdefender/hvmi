/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINSELFMAP_H_
#define _WINSELFMAP_H_

#include "guests.h"

typedef struct _WIN_PROCESS_OBJECT WIN_PROCESS_OBJECT, *PWIN_PROCESS_OBJECT;

///
/// @brief      Computes the self map entry physical address based on a given Cr3
///
/// This is done using the self map index value used by the guest for the self mapping mechanism.
///
/// @param[in]  Cr3 The Cr3 for which the self map entry physical address is calculated
///
/// @returns     The physical address of the self map entry for the given Cr3
///
#define SELF_MAP_ENTRY(Cr3)                     (CLEAN_PHYS_ADDRESS64(((QWORD)(Cr3))) + gGuest.Mm.SelfMapIndex * 8ull)

///
/// @brief      Decides if a self map entry value is malicious or not
///
/// If the entry is present and has the user/supervisor bit set, it is considered to be malicious, as it can be accessed
/// from user mode code
///
/// @param[in]  entry   The self map entry value
///
/// @retval     True if the value of the entry is suspicious
/// @retval     False if the value of the entry is not suspicious
///
#define SELF_MAP_ENTRY_IS_DETECTION(entry)      (((entry) & PT_P) != 0 && ((entry) & PT_US) != 0)

/// @brief      Computes the virtual address at which the self map entry is mapped for this guest
///
/// This is done using the self map index value used by the guest for the self mapping mechanism
#define SELF_MAP_ENTRY_VA   (0xFFFF800000000000 | ((QWORD)gGuest.Mm.SelfMapIndex << 39) | \
                            ((QWORD)gGuest.Mm.SelfMapIndex << 30) | ((QWORD)gGuest.Mm.SelfMapIndex << 21) | \
                            ((QWORD)gGuest.Mm.SelfMapIndex << 12) | ((QWORD)gGuest.Mm.SelfMapIndex * 8))


INTSTATUS
IntWinSelfMapValidateSelfMapEntries(
    void
    );

INTSTATUS
IntWinSelfMapUnprotectSelfMapIndex(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinSelfMapProtectSelfMapIndex(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinSelfMapDisableSelfMapEntryProtection(
    void
    );

INTSTATUS
IntWinSelfMapEnableSelfMapEntryProtection(
    void
    );

INTSTATUS
IntWinSelfMapGetAndCheckSelfMapEntry(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

#endif
