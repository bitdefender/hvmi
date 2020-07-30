/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WIN_NET_H_
#define _WIN_NET_H_

#include "intronet.h"

typedef
_Function_class_(PFUNC_IntWinNetCallback) INTSTATUS
(*PFUNC_IntWinNetCallback)(
    _In_ const INTRONET_ENDPOINT *Connection,
    _Inout_opt_ void *Context
    );

INTSTATUS
IntWinNetSendProcessConnections(
    _In_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinNetDumpConnections(
    void
    );

#endif // !_WIN_NET_SCAN_H_
