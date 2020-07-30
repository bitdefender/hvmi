/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINOBJ_H_
#define _WINOBJ_H_

#include "wddefs.h"

INTSTATUS
IntWinObjIsTypeObject(
    _In_ QWORD Gva
    );

INTSTATUS
IntWinObjGetPoolHeaderForObject(
    _In_ QWORD ObjectGva,
    _Out_ POOL_HEADER *PoolHeader
    );

INTSTATUS
IntWinGuestFindDriversNamespace(
    void
    );

void
IntWinObjCleanup(
    void
    );

#endif // !_WINOBJ_H_
