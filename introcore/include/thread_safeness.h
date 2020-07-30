/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _THREAD_SAFENESS_H_
#define _THREAD_SAFENESS_H_

#include "introtypes.h"

///
/// @defgroup   group_thread_safeness_options Thread safeness options
/// @brief      Options that control the thread safeness mechanism
/// @ingroup    group_internal
/// @{
///

#define THS_CHECK_ONLY          0x00000001  ///< Will check for safeness, without moving any RIP or stack value.
#define THS_CHECK_DETOURS       0x00000010  ///< Will check if any RIP is inside detours.
#define THS_CHECK_MEMTABLES     0x00000020  ///< Will check if any RIP is inside memtables.
#define THS_CHECK_TRAMPOLINE    0x00000040  ///< Will check if any RIP is inside the agent loader.
#define THS_CHECK_PTFILTER      0x00000080  ///< Will check if any RIP is inside the PT filter agent.
#define THS_CHECK_VEFILTER      0x00000100  ///< Will check if any RIP is inside the VE filter agent.
#define THS_CHECK_SWAPGS        0x00000200  ///< Will check if any RIP is inside a mitigated SWAPGS gadget.

/// @}

/// @brief  The type of pointer to be checked.
typedef enum
{
    ptrLiveRip,     ///< The RIP of a thread.
    ptrStackValue   ///< A stack value.
} THS_PTR_TYPE;

INTSTATUS
IntThrSafeCheckThreads(
    _In_ QWORD Options
    );

#endif // _THREAD_SAFENESS_H_

