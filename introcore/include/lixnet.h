/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIX_NET_H_
#define _LIX_NET_H_

#include "intronet.h"
#include "lixprocess.h"


typedef void
(*PFUNC_IterateConnectionsCallback)(
    _In_ INTRONET_ENDPOINT *Endpoint
    );

INTSTATUS
IntLixNetIterateTaskConnections(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ PFUNC_IterateConnectionsCallback Callback
    );

INTSTATUS
IntLixNetSendTaskConnections(
    _In_ LIX_TASK_OBJECT *Task
    );

INTSTATUS
IntLixNetSendGuestConnections(
    void
    );

#endif // _LIX_NET_H_
