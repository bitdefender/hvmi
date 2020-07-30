/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXKERNEL_H_
#define _LIXKERNEL_H_

#include "introtypes.h"

INTSTATUS
IntLixKernelReadProtect(
    void
    );

INTSTATUS
IntLixKernelWriteProtect(
    void
    );

void
IntLixKernelReadUnprotect(
    void
    );

void
IntLixKernelWriteUnprotect(
    void
    );

#endif // _LIXKERNEL_H_
