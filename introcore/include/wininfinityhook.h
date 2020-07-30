/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WIN_INFINITY_HOOK_H_
#define _WIN_INFINITY_HOOK_H_

#include "introtypes.h"

//
// API
//
INTSTATUS
IntWinInfHookProtect(
    void
    );

INTSTATUS
IntWinInfHookUnprotect(
    void
    );

#endif // !_WIN_INFINITY_HOOK_H_
