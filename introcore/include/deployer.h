/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DEPLOYER_H_
#define _DEPLOYER_H_

#include "introtypes.h"

INTSTATUS
IntDepInjectProcess(
    _In_ DWORD AgentTag,
    _In_opt_ BYTE *AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_ const CHAR *Name,
    _In_opt_ const CHAR *Args
    );

INTSTATUS
IntDepInjectFile(
    _In_ BYTE *FileContent,
    _In_ DWORD FileSize,
    _In_ const CHAR *Name
    );

INTSTATUS
IntDepRunCommand(
    _In_ const CHAR *CommandLine
    );

#endif // _DEPLOYER_H_
