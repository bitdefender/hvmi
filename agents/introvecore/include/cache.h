/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CACHE_H_
#define _CACHE_H_

#include "cpu.h"
#include "vetypes.h"
#include "vecommon.h"

BOOLEAN
VeCacheIsEntryHooked(
    QWORD Address
    );

#endif // _CACHE_H_
