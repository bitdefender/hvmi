/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SWAPMEM_H_
#define _SWAPMEM_H_

#include "introtypes.h"

/// This means that the callback was invoked after a PF injection. Otherwise, the callback has been invoked
/// before returning from the IntSwapMemRead function.
#define SWAPMEM_FLAG_ASYNC_CALL         0x00000001
/// If set, than the newly mounted entry is installed as XD. This will be set if any page inside the read
/// area is XD.
#define SWAPMEM_FLAG_ENTRY_XD           0x00000002


/// If set, no PF will be injected. Introcore will wait for the pages to be naturally swapped in.
#define SWAPMEM_OPT_NO_FAULT            0x00000001
/// If set, the PF must be injected only while in user-mode. Use it when reading user-mode memory.
#define SWAPMEM_OPT_UM_FAULT            0x00000002
/// If set, the PF must be injected only while in kernel-mode. Use it when reading kernel-mode memory.
/// Note, however, that the PF will be injected as soon as possible, and may result in a bug-check. It is
/// recommended to use SWAPMEM_OPT_BP_FAULT instead.
#define SWAPMEM_OPT_KM_FAULT            0x00000004
/// If set, the \#PF will be generated from an int3 detour. Use this when injecting kernel PFs.
#define SWAPMEM_OPT_BP_FAULT            0x00000010
/// If set, the PF will be generated with write access. Useful when CoW must be done.
#define SWAPMEM_OPT_RW_FAULT            0x00000020
/// If set, will make sure that a single PF is scheduled for this page.
#define SWAPMEM_OPT_NO_DUPS             0x80000000



///
/// @brief Called when all the required data is available.
///
/// This callback is called as soon as all the data has been read from guest memory. The callback may be called even
/// before returning from #IntSwapMemReadData, if all the pages are present in physical memory. If at least one page
/// is missing, the callback will be called later, after the pages have been swapped in, and all the data has been
/// read.
///
/// @param[in]  Context         Optional context, as passed to the #IntSwapMemReadData function.
/// @param[in]  Cr3             The virtual address space.
/// @param[in]  VirtualAddress  The base virtual address read.
/// @param[in]  PhysicalAddress The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data            Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize        Size of the Data buffer. Will normally be equal to the Length passed to read function.
/// @param[in]  Flags           Swap flags. Check out SWAPMEM_FLG* for more info.
///
typedef INTSTATUS
(*PFUNC_PagesReadCallback)(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    );


///
/// @brief Called before injecting a PF inside the guest.
///
/// This callback is called before injecting a PF inside the guest. If it returns #INT_STATUS_NOT_NEEDED_HINT,
/// the PF will no longer be injected. This may be useful if the caller wishes to inhibit PF injection in
/// certain cases (for example, you may want to check the existence of a VAD before injecting a PF for a
/// newly loaded module).
/// NOTE: This callback is optional. If it is not used, the PF will be injected as soon as possible, when
/// the scheduler decides it is safe.
///
/// @param[in]  Context         Context, as passed to the #IntSwapMemReadData function.
/// @param[in]  Cr3             The virtual address space.
/// @param[in]  VirtualAddress  The address the PF is about to be injected for.
///
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the PF should not be injected.
///
typedef INTSTATUS
(*PFUNC_PreInjectCallback)(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress
    );


//
// API
//
INTSTATUS
IntSwapMemReadData(
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_ DWORD Options,
    _In_opt_ void *Context,
    _In_opt_ DWORD ContextTag,
    _In_opt_ PFUNC_PagesReadCallback Callback,
    _In_opt_ PFUNC_PreInjectCallback PreInject,
    _Out_opt_ void **SwapHandle
    );

INTSTATUS
IntSwapMemInjectPendingPF(
    void
    );

void
IntSwapMemCancelPendingPF(
    _In_ QWORD VirtualAddress
    );

void
IntSwapMemReinjectFailedPF(
    void
    );

INTSTATUS
IntSwapMemRemoveTransaction(
    _In_ void *Transaction
    );

INTSTATUS
IntSwapMemRemoveTransactionsForVaSpace(
    _In_ QWORD Cr3
    );

INTSTATUS
IntSwapMemInit(
    void
    );

INTSTATUS
IntSwapMemUnInit(
    void
    );

void
IntSwapMemDump(
    void
    );

#endif // _SWAPMEM_H_
