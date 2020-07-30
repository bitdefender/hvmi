/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   winbugcheck.h
///
/// @brief  Information about Windows kernel crashes
///
/// For more information about a specific bug check code see
/// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
///
/// The codes defined in this file are the ones for which introcore tries to do some handling (usually, obtaining
/// more information about the crash).
///

#ifndef _WINBUGCHECK_H_
#define _WINBUGCHECK_H_

#include "introtypes.h"

#define BUGCHECK_IRQL_NOT_LESS_OR_EQUAL                 0x0000000A
#define BUGCHECK_BAD_POOL_HEADER                        0x00000019
#define BUGCHECK_MEMORY_MANAGEMENT                      0x0000001A
#define BUGCHECK_KMODE_EXCEPTION_NOT_HANDLED            0x0000001E
#define BUGCHECK_SYSTEM_SERVICE_EXCEPTION               0x0000003B
#define BUGCHECK_PFN_LIST_CORRUPT                       0x0000004E
#define BUGCHECK_PAGE_FAULT_IN_NONPAGED_AREA            0x00000050
#define BUGCHECK_PROCESS_INITIALIZATION_FAILED          0x00000060
#define BUGCHECK_KERNEL_STACK_INPAGE_ERROR              0x00000077
#define BUGCHECK_KERNEL_DATA_INPAGE_ERROR               0x0000007A
#define BUGCHECK_INACCESSIBLE_BOOT_DEVICE               0x0000007C
#define BUGCHECK_SYSTEM_THREAD_EXCEPTION_NOT_HANDLED    0x0000007E
#define BUGCHECK_UNEXPECTED_KERNEL_MODE_TRAP            0x0000007F
#define BUGCHECK_KERNEL_MODE_EXCEPTION_NOT_HANDLED      0x0000008E
#define BUGCHECK_CRITICAL_PROCESS_DIED                  0x000000EF
#define BUGCHEDCK_CRITICAL_STRUCTURE_CORRUPTION         0x00000109

///
/// @brief  The layout of the EFLAGS register
///
typedef union _EFLAGS
{
    DWORD Raw;  ///< Raw register value
    struct
    {
        DWORD CF        : 1;
        DWORD Unused5   : 1;
        DWORD PF        : 1;
        DWORD Unused4   : 1;
        DWORD AF        : 1;
        DWORD Unused3   : 1;
        DWORD ZF        : 1;
        DWORD SF        : 1;
        DWORD TF        : 1;
        DWORD IF        : 1;
        DWORD DF        : 1;
        DWORD OF        : 1;
        DWORD IOPL      : 2;
        DWORD NT        : 1;
        DWORD Unused2   : 1;
        DWORD RF        : 1;
        DWORD VF        : 1;
        DWORD AC        : 1;
        DWORD VIF       : 1;
        DWORD VIP       : 1;
        DWORD ID        : 1;
        DWORD Unused1   : 10;
    };
} EFLAGS, *PEFLAGS;

INTSTATUS
IntWinBcHandleBugCheck(
    _In_ void const *Detour
    );

#endif
