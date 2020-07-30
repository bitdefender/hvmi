/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HANDLER_H_
#define _HANDLER_H_

#include "vetypes.h"
#include "vecommon.h"
#include "cpu.h"

void
VirtualizationExceptionHandler(
    PVECPU Cpu
    );

#endif // _HANDLER_H_
