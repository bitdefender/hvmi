/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DTR_PROTECTION_H_
#define _DTR_PROTECTION_H_

#include "introtypes.h"


INTSTATUS
IntIdtrProtect(
    void
    );

INTSTATUS
IntGdtrProtect(
    void
    );

INTSTATUS
IntIdtrUnprotect(
    void
    );

INTSTATUS
IntGdtrUnprotect(
    void
    );

#endif // _DTR_PROTECTION_H_
