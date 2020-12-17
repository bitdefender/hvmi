/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIX_VDSO_H_
#define _LIX_VDSO_H_

#include "introtypes.h"

typedef struct _LIX_TASK_OBJECT LIX_TASK_OBJECT, *PLIX_TASK_OBJECT;

#define LIX_VDSO_FIXED          0xffffffffff600000ULL

INTSTATUS
IntLixVdsoProtect(
    void
    );

void
IntLixVdsoUnprotect(
    void
    );

INTSTATUS
IntLixVdsoFetchAddress(
    _In_ LIX_TASK_OBJECT *Task,
    _Out_ QWORD *Address
    );

INTSTATUS
IntLixVdsoDynamicProtect(
    void
    );

#endif // !_LIX_VDSO_H_
