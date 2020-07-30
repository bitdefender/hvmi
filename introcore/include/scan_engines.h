/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   scan_engines.h
///
/// @brief  Exposes the functions used to schedule an asynchronous
/// code execution scan and receives its result.
///

#ifndef _SCAN_ENGINES_H_
#define _SCAN_ENGINES_H_

#include "winprocess.h"
#include "lixprocess.h"

INTSTATUS
IntLixEngExecSendNotification(
    _In_ LIX_TASK_OBJECT *Task,
    _In_ PIG_ARCH_REGS Registers,
    _In_ PINTRO_EXEC_INFO ExecInfo
    );

INTSTATUS
IntWinEngExecSendNotification(
    _In_ PWIN_PROCESS_OBJECT Process,
    _In_ PIG_ARCH_REGS Registers,
    _In_ PINTRO_EXEC_INFO ExecInfo
    );

INTSTATUS
IntHandleExecCallback(
    _In_ PENG_NOTIFICATION_CODE_EXEC ExecNotification
    );

#endif //_SCAN_ENGINES_H_
