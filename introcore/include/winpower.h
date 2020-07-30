/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINPOWER_H_
#define _WINPOWER_H_

#include "introtypes.h"

///
/// @brief  Detected guest power states.
///
typedef enum _INTRO_POWER_STATE
{
    /// @brief  The state is not among the known combinations or it is unused by the introspection engine.
    intPowStateUnknown = 0,
    intPowStateSleeping,                    ///< The guest is about to enter a sleep state (S1, S2, S3).
    intPowStateHibernate,                   ///< The guest is about to enter hibernate (S4).
    intPowStateReboot,                      ///< The guest is about to reboot.
    intPowStateShutdown,                    ///< The guest is about to shutdown.
    /// @brief  The maximum state, should never be used as it is just an indicator for sanity checks.
    intPowStateMaxState
} INTRO_POWER_STATE, *PINTRO_POWER_STATE;


//
// API
//
INTSTATUS
IntWinPowHandlePowerStateChange(
    _In_ void *Detour
    );

INTSTATUS
IntWinPowEnableSpinWait(
    void
    );

INTSTATUS
IntWinPowDisableSpinWait(
    void
    );

#endif
