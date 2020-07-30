/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINPOOL_H_
#define _WINPOOL_H_

#include "introtypes.h"
#include "wddefs.h"


// Note: On windows 7, it seems that the most significant bit is used to mark the allocation
// as "Protected", thus the tags may or may not have the most significant bit set.
#define WIN_POOL_TAG_DRIV       0x76697244
#define WIN_POOL_TAG_DRIV2      0xF6697244
#define WIN_POOL_TAG_FMFI       0x69664d46
#define WIN_POOL_TAG_TOKE       0x656b6f54
#define WIN_POOL_TAG_TOKE2      0xe56b6f54

INTSTATUS
IntWinPoolHandleAlloc(
    _In_ void *Detour
    );

INTSTATUS
IntWinPoolHandleFree(
    _In_ void *Detour
    );

const POOL_HEADER*
IntWinPoolGetPoolHeaderInPage(
    _In_ const void* Page,
    _In_ DWORD StartOffset,
    _In_ DWORD Tag
    );

#endif // _WINPOOL_H_
