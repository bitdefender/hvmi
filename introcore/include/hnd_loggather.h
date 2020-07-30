/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HND_LOGGATHER_H_
#define _HND_LOGGATHER_H_

#include "introtypes.h"

INTSTATUS
IntAgentHandleLogGatherVmcall(
    _In_opt_ void *Reserved,
    _In_ PIG_ARCH_REGS Registers
    );

#endif // _HND_LOGGATHER_H_
