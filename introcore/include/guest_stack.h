/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GUEST_STACK_H_
#define _GUEST_STACK_H_

#include "introtypes.h"

/// @brief Flag used to tell that the ReturnAddress in a #STACK_ELEMENT is not inside any function.
#define STACK_ADDR_NOT_INSIDE_FUNCTION          0x00000001
/// @brief Flag used to tell that the CalledAddress in a #STACK_ELEMENT is not precise (it's an approximation).
#define STACK_CALL_ADDRESS_IMPRECISE            0x00000002
/// @brief Flag used to tell that the ReturnAddress in a #STACK_ELEMENT is an interrupt routine.
#define STACK_INTERRUPT_ROUTINE                 0x00000004
/// @brief Flag used to tell that the ReturnAddress in a #STACK_ELEMENT is an exception routine.
#define STACK_EXCEPTION_ROUTINE                 0x00000008

/// @brief Flag that tells to only get addresses inside drivers.
#define STACK_FLG_ONLY_DRIVER_ADDRS             0x00000001
/// @brief Flag that tells to only get return addresses (no drivers).
#define STACK_FLG_FAST_GET                      0x00000002

/// @brief Structure that describes a stack trace element.
typedef struct _STACK_ELEMENT
{
    /// @brief Describe what each of the following fields mean.
    ///
    /// Can be any combination of #STACK_ADDR_NOT_INSIDE_FUNCTION, #STACK_CALL_ADDRESS_IMPRECISE,
    /// #STACK_INTERRUPT_ROUTINE, #STACK_EXCEPTION_ROUTINE.
    ///
    DWORD   Flags;
    void    *ReturnModule;                  ///< The module to which the function belongs
    QWORD   ReturnAddress;                  ///< The address where the current stack frame will return (@ ret)

    QWORD   CalledAddress;                  ///< The start address of the function called
    QWORD   CurrentRip;                     ///< The RIP where we are now (pointing to the instruction next to the CALL)
    QWORD   RetAddrPointer;                 ///< Where we found the return address
} STACK_ELEMENT, *PSTACK_ELEMENT;

/// @brief Structure that describes a stack trace.
typedef struct _STACK_TRACE
{
    DWORD           NumberOfTraces; ///< Number of elements inside Traces.
    QWORD           StartRip;       ///< The RIP where we were initially
    STACK_ELEMENT   *Traces;        ///< Array describing the stack trace elements.

    BOOLEAN         Bits64;         ///< TRUE if we got the stack frame in 64-bit mode (RBP) or 32 (EBP)
} STACK_TRACE, *PSTACK_TRACE;

#endif //_GUEST_STACK_H_
