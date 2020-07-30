/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

#include "introtypes.h"


//#define DEBUG_MEM_ALLOCS
//#define DEBUG_EPT_VIOLATIONS
//#define DEBUG_CHECK_HOOKS

#ifdef DEBUG_MEM_ALLOCS
#define HpAllocWithTag(Add, Len, Tag)       IntDbgAllocMem(Len, Tag, __FILENAME__, __LINE__)
#define HpFreeAndNullWithTag(Add, Tag)      IntDbgFreeMem(Add, Tag, __LINE__)
#endif

INTSTATUS
IntDbgProcessCommand(
    _In_ DWORD Argc,
    _In_ const char *Argv[]
    );

#ifdef DEBUG_MEM_ALLOCS

__attribute__((malloc))
__attribute__ ((alloc_size (1)))
__must_check void *
IntDbgAllocMem(
    _In_ size_t Size,
    _In_ DWORD Tag,
    _In_ const char *FileName,
    _In_ DWORD Line
    );

INTSTATUS
IntDbgFreeMem(
    _In_ void **Address,
    _In_ DWORD Tag,
    _In_ DWORD Line
    );

INTSTATUS
IntDbgDumpAllocs(
    _In_opt_ DWORD Tag
    );

INTSTATUS
IntDbgCheckAllocs(
    void
    );

#endif // DEBUG_MEM_ALLOCS

#ifdef DEBUG_CHECK_HOOKS

static void
IntDbgCheckHooks(
    void
    );

#endif // DEBUG_CHECK_HOOKS

#endif // _DEBUGGER_H_
