/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WININTOBJ_H_
#define _WININTOBJ_H_

#include "guests.h"

INTSTATUS
IntWinIntObjUnprotect(
    void
    );

INTSTATUS
IntWinIntObjProtect(
    void
    );

#endif //_WININTOBJ_H_
