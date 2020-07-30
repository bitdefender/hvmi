/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTROBOOTDRV_TYPES_H_
#define _INTROBOOTDRV_TYPES_H_

#include <basetsd.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <sal.h>

typedef UINT8   BYTE, * PBYTE;
typedef UINT16  WORD, * PWORD;
typedef UINT32  DWORD, * PDWORD;
typedef UINT64  QWORD, * PQWORD;

#define IREM_TAG_DEPL_BUFFER     'DEPL'
#define IREM_TAG_VE_AGENT        'VEVE'
#define IREM_TAG_PT_AGENT        'PTFL'

#endif // !_INTROBOOTDRV_TYPES_H_
