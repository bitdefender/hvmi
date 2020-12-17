/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINPROCESSHP_H_
#define _WINPROCESSHP_H_

#include "winprocess.h"

PWIN_PROCESS_OBJECT
IntWinProcFindObjectByCr3(
    _In_ QWORD Cr3
    );

PWIN_PROCESS_OBJECT
IntWinProcFindObjectByUserCr3(
    _In_ QWORD Cr3
    );

#define IntWinGetCurrentProcess() IntWinProcFindObjectByCr3(gVcpu->Regs.Cr3)

PWIN_PROCESS_OBJECT
IntWinProcFindObjectByEprocess(
    _In_ QWORD Eprocess
    );

PWIN_PROCESS_OBJECT
IntWinProcFindObjectByPid(
    _In_ DWORD Pid
    );

PWIN_PROCESS_OBJECT
IntWinProcFindObjectByName(
    _In_ CHAR const *Name,
    _In_ BOOLEAN MustBeSystem);

INTSTATUS
IntWinProcAdd(
    _In_ QWORD Eprocess,
    _In_ QWORD Aux
    );

INTSTATUS
IntWinProcIsPsActiveProcessHead(
    _In_ QWORD Gva);

INTSTATUS
IntWinProcIterateGuestProcesses(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    );

INTSTATUS
IntWinProcGetNameFromEprocess(
    _In_ QWORD Eprocess,
    _Out_writes_z_(IMAGE_BASE_NAME_LEN) CHAR *Name
    );

INTSTATUS
IntWinProcGetNameFromInternalEprocess(
    _In_ QWORD Eprocess,
    _Out_writes_z_(IMAGE_BASE_NAME_LEN) CHAR *Name
    );

BOOLEAN
IntWinProcIsEnoughHeapAvailable(
    void
    );

_Function_class_(FUNC_RbTreeNodeFree) void
IntWinProcRbTreeNodeFree(
    _Inout_ RBNODE *Node
    );

_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinProcRbTreeNodeCompareCr3(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right
    );

_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinProcRbTreeNodeCompareUserCr3(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right
    );

_Function_class_(FUNC_RbTreeNodeCompare) int
IntWinProcRbTreeNodeCompareEproc(
    _In_ RBNODE const *Left,
    _In_ RBNODE const *Right
    );

INTSTATUS
IntWinProcGetAgentsAsCli(
    _Out_writes_bytes_(Length) PCHAR CommandLine,
    _In_ DWORD Length
    );

void
IntWinProcDump(
    void
    );

void
IntWinProcDumpVads(
    _In_opt_ const char *ProcessName
    );

void
IntWinProcDumpEgFlags(
    void
    );

INTSTATUS
IntWinProcMapEprocess(
    _In_ QWORD Eprocess,
    _Outptr_ void **Ptr
    );

void
IntWinProcLstUnsafeReInit(void);

void
IntWinProcLstInsertProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    );

void
IntWinProcLstRemoveProcess(
    _In_ WIN_PROCESS_OBJECT *Process
    );

#endif // _WINPROCESSHP_H_
