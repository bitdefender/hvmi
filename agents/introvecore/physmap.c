/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "core.h"
#include "physmap.h"




VOID
PmPreinit(
    VOID
    );

NTSTATUS
PmInit(
    VOID
    );

NTSTATUS
PmBuildPhysMemMap(
    VOID
    );

NTSTATUS
PmUninit(
    VOID
    );

NTSTATUS
PmGetPhysMemType(
    __in QWORD PhysicalAddress,
    __out BYTE *Caching
    );