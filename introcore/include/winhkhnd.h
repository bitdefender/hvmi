/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file      winhkhnd.h
/// @ingroup   group_detours
/// @brief     Windows detour descriptors
///
/// This file exposes the global variables describing the detours that Introcore will set on Windows kernel functions. Please see winhkhnd.c for more information.
///

#ifndef _WINHKHND_H_
#define _WINHKHND_H_

#include "detours.h"

extern API_HOOK_DESCRIPTOR gHookableApisX86[];
extern const size_t gHookableApisX86Size;

extern API_HOOK_DESCRIPTOR gHookableApisX64[];
extern const size_t gHookableApisX64Size;

#endif // !_WINHKHND_H_

