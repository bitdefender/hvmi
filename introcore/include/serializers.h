/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _SERIALIZERS_H_
#define _SERIALIZERS_H_

#include "introtypes.h"


void
IntSerializeException(
    _In_ void *Victim,
    _In_ void *Originator,
    _In_ DWORD Type,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason,
    _In_ INTRO_EVENT_TYPE EventClass
    );

#endif // !_SERIALIZERS_H_
