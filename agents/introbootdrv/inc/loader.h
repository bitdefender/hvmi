/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LOADER_H_
#define _LOADER_H_

#include "introbootdrv_types.h"

void *
LdrFindModuleByName(
    _In_z_ const CHAR *ModuleName
    );

void *
LdrFindExportByName(
    _In_ PBYTE ModuleBase,
    _In_z_ const CHAR *ExportName
    );

BOOLEAN
LdrFixMyImports(
    void
    );

#endif // !_LOADER_H_
