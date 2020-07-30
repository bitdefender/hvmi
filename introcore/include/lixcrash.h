/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXCRASH_H_
#define _LIXCRASH_H_

#include "introtypes.h"

typedef struct _LIX_TASK_OBJECT LIX_TASK_OBJECT, *PLIX_TASK_OBJECT;

INTSTATUS
IntLixTaskSendExceptionEvent(
    _In_ DWORD Signal,
    _In_ LIX_TASK_OBJECT *Task
    );

INTSTATUS
IntLixCrashHandle(
    _In_ void *Detour
    );

INTSTATUS
IntLixCrashPanicHandler(
    _In_ void *Detour
    );

void
IntLixCrashDumpDmesg(
    void
    );

#endif  // !_LIXCRASH_H_

