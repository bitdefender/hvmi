/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _EMU_H_
#define _EMU_H_

#include "vetypes.h"
#include "vecommon.h"
#include "cpu.h"
#include "bddisasm.h"

VESTATUS
VeHandlePtWrite(
    PVECPU Cpu
    );

VESTATUS
VeHandlePageWalk(
    PVECPU Cpu
    );

#endif // _EMU_H_
