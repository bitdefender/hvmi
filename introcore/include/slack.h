/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SLACK_H_
#define _SLACK_H_

#include "introtypes.h"


INTSTATUS
IntSlackAlloc(
    _In_opt_ QWORD ModuleBase,
    _In_ BOOLEAN Pageable,
    _In_ DWORD Size,
    _Out_ QWORD *Buffer,
    _In_opt_ QWORD SecHint
    );

INTSTATUS
IntSlackFree(
    _In_ QWORD Buffer
    );

void
IntSlackUninit(
    void
    );


#endif // _SLACK_H_
