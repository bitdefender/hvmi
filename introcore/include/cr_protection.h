/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CR_PROTECTION_H_
#define _CR_PROTECTION_H_

#include "introtypes.h"

INTSTATUS
IntCr4Protect(
    void
    );

INTSTATUS
IntCr4Unprotect(
    void
    );

#endif // _CR_PROTECTION_H_
