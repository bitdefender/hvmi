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
    /// @brief  The guest virtual address of the HAL performance counter.
    QWORD           HalPerfCounterAddress;
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

    /// @brief  A buffer containing the whole HAL image.
    ///
    /// This can be used when there is a need to fetch values
    /// from the HAL image, such as exports, code, etc. Note that
    /// this buffer should be valid only after #IntWinHalFinishRead
    /// is called.
    BYTE            *HalBuffer;

    /// @brief  The size of HAL buffer.
    DWORD           HalBufferSize;

    /// @brief  The number of sections which are not yet read into HAL buffer.
    DWORD           RemainingSections;

    /// @brief  A list containing the swap handles for the swapped out sections
    ///         which should be read in HalBuffer.
    LIST_ENTRY      InitSwapHandles;

    /// @brief  The HAL Performance Counter integrity hook object.
    void            *HalPerfIntegrityObj;
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

INTSTATUS
IntWinHalProtectHalPerfCounter(
    void
    );

INTSTATUS
IntWinHalUnprotectHalPerfCounter(
    void
    );

#endif // _WINHAL_H_
