/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WIN_DEPLOYER_H_
#define _WIN_DEPLOYER_H_

#include "introtypes.h"

INTSTATUS
IntWinDepInjectProcess(
    _In_ DWORD AgentTag,
    _In_opt_ PBYTE AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_ const CHAR *Name,
    _In_opt_ const CHAR *Args
    );

INTSTATUS
IntWinDepInjectFile(
    _In_ PBYTE FileContent,
    _In_ DWORD FileSize,
    _In_ const CHAR *Name
    );

#endif // _WIN_DEPLOYER_H_
