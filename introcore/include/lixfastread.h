/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXFASTREAD_H_
#define _LIXFASTREAD_H_

#include "introcore.h"

INTSTATUS
IntLixFsrInitMap(
    _In_ QWORD Gva
    );

void
IntLixFsrUninitMap(
    void
    );

INTSTATUS
IntLixFsrRead(
    _In_ QWORD Gva,
    _In_ DWORD Offset,
    _In_ DWORD Size,
    _Out_ void *Buffer
    );

#endif
