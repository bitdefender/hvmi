/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HVIFACE_H_
#define _HVIFACE_H_

#include "vetypes.h"
#include "vecommon.h"

//
// API
//
DWORD
HvRaiseEpt(
    void
    );

DWORD
HvBreak(
    QWORD Reason,
    QWORD Argument
    );

DWORD
HvTrace(
    QWORD Reason,
    QWORD Argument
    );

#endif // _HVIFACE_H_
