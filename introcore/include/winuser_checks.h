/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   winuser_checks.h
///
/// @brief  Exposes the function used to perform initialization checks on Windows processes.
///

#ifndef _WINUSER_CHECKS_H_
#define _WINUSER_CHECKS_H_

#include "exceptions.h"

INTSTATUS
IntWinUmCheckInitializationInjection(
    _In_ PEXCEPTION_VICTIM_ZONE Victim,
    _In_ PEXCEPTION_UM_ORIGINATOR Originator
    );


#endif  // _WINUSER_CHECKS_H_
