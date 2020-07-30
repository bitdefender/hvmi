/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   wincmdline.h
///
/// @brief  Exposes the functions used to schedule an asynchronous
/// command line scan and receives its result.
///

#ifndef _WINCMDLINE_H_
#define _WINCMDLINE_H_

#include "winprocess.h"

INTSTATUS
IntWinInspectCommandLine(
    _In_ PWIN_PROCESS_OBJECT Process
    );

INTSTATUS
IntWinHandleCmdLineCallback(
    _In_ PENG_NOTIFICATION_CMD_LINE EngineNotification
    );

#endif // _WINCMDLINE_H_
