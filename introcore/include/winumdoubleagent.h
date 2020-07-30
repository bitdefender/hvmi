/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINUMDOUBLEAGENT_H_
#define _WINUMDOUBLEAGENT_H_

#include "introcrt.h"

typedef struct _WIN_PROCESS_MODULE WIN_PROCSSS_MODULE;

INTSTATUS
IntWinDagentCheckSuspiciousDllLoad(
    _In_ WIN_PROCESS_MODULE *Module
    );

#endif // _WINUMDOUBLEAGENT_H_
