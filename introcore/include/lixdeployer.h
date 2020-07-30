/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIX_DEPLOYER_H_
#define _LIX_DEPLOYER_H_

#include "introtypes.h"

INTSTATUS
IntLixDepInjectFile(
    _In_ BYTE *Content,
    _In_ DWORD Size,
    _In_ const CHAR *Name
    );

INTSTATUS
IntLixDepInjectProcess(
    _In_ DWORD AgentTag,
    _In_opt_ BYTE *Content,
    _In_ DWORD Size,
    _In_ const char *Name,
    _In_opt_ const char *Args
    );

INTSTATUS
IntLixDepRunCommand(
    _In_ const CHAR *CommandLine
    );

#endif // !_LIX_DEPLOYER_H_
