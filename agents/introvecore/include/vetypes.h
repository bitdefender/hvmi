/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VETYPES_H_
#define _VETYPES_H_

typedef char CHAR;
typedef char *PCHAR;
typedef unsigned char BOOLEAN;
typedef unsigned char BYTE;
typedef unsigned char *PBYTE;
typedef unsigned short WORD;
typedef unsigned short *PWORD;
typedef unsigned int DWORD;
typedef unsigned int *PDWORD;
typedef unsigned long long QWORD;
typedef unsigned long long *PQWORD;

#define TRUE    (1)
#define FALSE   (0)
#define NULL    ((void*)0)

#define UNREFERENCED_PARAMETER(x)       (x)

// Intrinsics
void _enable(void);
void _disable(void);

#pragma intrinsic(_enable)
#pragma intrinsic(_disable)

#include "disasmtypes.h"

#endif _VETYPES_H_ // _VETYPES_H_
