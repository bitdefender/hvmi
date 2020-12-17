/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINSUD_H_
#define _WINSUD_H_

#include "guests.h"

 /// @brief  The address where the SharedUserData is mapped in the Windows kernel.
#define WIN_SHARED_USER_DATA_PTR            (gGuest.Guest64 ? 0xFFFFF78000000000 : 0xFFDF0000)

INTSTATUS
IntWinSudProtectSudExec(
    void
    );

INTSTATUS
IntWinSudUnprotectSudExec(
    void
    );

TIMER_FRIENDLY INTSTATUS
IntWinSudCheckIntegrity(
    void
    );

INTSTATUS
IntWinSudProtectIntegrity(
    void
    );

INTSTATUS
IntWinSudUnprotectIntegrity(
    void
    );

#endif //_WINSUD_H_
