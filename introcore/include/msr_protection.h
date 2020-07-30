/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _MSR_PROTECTION_H_
#define _MSR_PROTECTION_H_

#include "introtypes.h"

INTSTATUS
IntMsrSyscallProtect(
    void
    );

INTSTATUS
IntMsrSyscallUnprotect(
    void
    );

#endif // _MSR_PROTECTION_H_
