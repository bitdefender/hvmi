/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINHAL_H_
#define _WINHAL_H_

#include "introtypes.h"

///
/// @brief      Hal information.
///
typedef struct _WIN_HAL_DATA
{
    /// @brief  The guest virtual address of the HAL heap.
    QWORD           HalHeapAddress;
    /// @brief  The guest virtual address of the HAL interrupt controller.
    QWORD           HalIntCtrlAddress;
    /// @brief  The size of the HAL heap.
    DWORD           HalHeapSize;

    /// @brief  The guest virtual address of the HAL dispatch table.
    QWORD           HalDispatchTableAddress;
    /// @brief  The size of the HAL dispatch table.
    DWORD           HalDispatchTableSize;

    /// @brief  The hal.dll kernel module or ntoskrnl.exe.
    KERNEL_DRIVER   *OwnerHalModule;

    /// @brief  The HAL heap execution hook object.
    void            *HalHeapExecHook;
    /// @brief  The HAL interrupt controller write hook object.
    void            *HalIntCtrlWriteHook;
    /// @brief  The HAL dispatch table integrity hook object.
    void            *HalDispatchIntegrityHook;
} WIN_HAL_DATA, *PWIN_HAL_DATA;


INTSTATUS
IntWinHalCreateHalData(
    void
    );

void
IntWinHalUninit(
    void
    );

INTSTATUS
IntWinHalUpdateProtection(
    void
    );

INTSTATUS
IntWinHalProtectHalHeapExecs(
    void
    );

INTSTATUS
IntWinHalProtectHalIntCtrl(
    void
    );

INTSTATUS
IntWinHalProtectHalDispatchTable(
    void
    );

INTSTATUS
IntWinHalUnprotectHalHeapExecs(
    void
    );

INTSTATUS
IntWinHalUnprotectHalIntCtrl(
    void
    );

INTSTATUS
IntWinHalUnprotectHalDispatchTable(
    void
    );

#endif // _WINHAL_H_
