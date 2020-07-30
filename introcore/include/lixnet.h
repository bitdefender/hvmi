/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIX_NET_H_
#define _LIX_NET_H_

#include "lixprocess.h"

INTSTATUS
IntLixNetSendTaskConnections(
    _In_ LIX_TASK_OBJECT *Task
    );

INTSTATUS
IntLixNetSendGuestConnections(
    void
    );

#endif // _LIX_NET_H_
