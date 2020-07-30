/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXKSYM_H_
#define _LIXKSYM_H_

#include "introcore.h"


INTSTATUS
IntKsymInit(
    void
    );

QWORD
IntKsymFindByName(
    _In_ const char *Name,
    _Out_opt_ QWORD *SymEnd
    );

INTSTATUS
IntKsymFindByAddress(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _Out_ char *SymName,
    _Out_opt_ QWORD *SymStart,
    _Out_opt_ QWORD *SymEnd
    );

void
IntKsymUninit(
    void
    );

#endif
