/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINIDT_H_
#define _WINIDT_H_

#include "introtypes.h"

INTSTATUS
IntWinIdtProtectOnCpu(
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntWinIdtUnprotectOnCpu(
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntWinIdtProtectAll(
    void
    );

INTSTATUS
IntWinIdtUnprotectAll(
    void
    );

#endif // _WINIDT_H_
