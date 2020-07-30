/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXIDT_H_
#define _LIXIDT_H_

#include "introtypes.h"

INTSTATUS
IntLixIdtProtectOnCpu(
    _In_ DWORD CpuNumber
    );

INTSTATUS
IntLixIdtProtectAll(
    void
    );

INTSTATUS
IntLixIdtUnprotectAll(
    void
    );

#endif // !_LIXIDT_H_
