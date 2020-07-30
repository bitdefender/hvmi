/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HYPERCALL_H_
#define _HYPERCALL_H_

#include "introbootdrv_types.h"

#include "../../../introcore/include/aghcall.h"

#define HYPERCALL_EXCEPTION     (SIZE_T)-1

SIZE_T
Hypercall(
    _In_ DWORD MaxOutputSize,
    _In_ PBYTE Buffer,
    _In_ DWORD Number
    );

#endif // !_HYPERCALL_H_
