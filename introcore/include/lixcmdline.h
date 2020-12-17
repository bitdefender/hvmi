/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   lixcmdline.h
///
/// @brief  Exposes the functions used to schedule an asynchronous
/// command line scan and receives its result.
///

#ifndef _LIXCMDLINE_H_
#define _LIXCMDLINE_H_

#include "lixprocess.h"

INTSTATUS
IntLixCmdLineInspect(
    _In_ LIX_TASK_OBJECT *Task
    );

INTSTATUS
IntLixHandleCmdLineCallback(
    _In_ ENG_NOTIFICATION_CMD_LINE *EngineNotification
    );

#endif // _LIXCMDLINE_H_
