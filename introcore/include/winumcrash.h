/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINUMCRASH_H_
#define _WINUMCRASH_H_

#include "introtypes.h"

INTSTATUS
IntWinHandleException(
    _In_ void *Detour
    );

#endif // !_WINUMCRASH_H_
