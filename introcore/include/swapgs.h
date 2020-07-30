/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SWAPGS_H_
#define _SWAPGS_H_

#include "thread_safeness.h"

INTSTATUS
IntSwapgsStartMitigation(
    void
    );

void
IntSwapgsUninit(
    void
    );

void
IntSwapgsDisable(
    void
    );

BOOLEAN
IntSwapgsIsPtrInHandler(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type,
    _Out_opt_ QWORD *Gadget
    );

QWORD
IntSwapgsRelocatePtrIfNeeded(
    _In_ QWORD Ptr
    );

#endif // _SWAPGS_H_
