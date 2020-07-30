/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXCRED_H_
#define _LIXCRED_H_

#include "introtypes.h"

///
/// @brief Describes one set of credentials.
///
typedef struct _LIX_CREDS
{
    LIST_ENTRY  Link;     ///< Linked list entry.
    QWORD       Gva;      ///< Guest virtual address of the protected cred structure.
    DWORD       RefCount; ///< Number of processes referring this credentials set.
    DWORD       Checksum; ///< The CRC32 checksum.
} LIX_CREDS;

typedef struct _LIX_TASK_OBJECT LIX_TASK_OBJECT;

INTSTATUS
IntLixCredAdd(
    _In_ QWORD CredsGva,
    _Out_ LIX_CREDS **Creds
    );

void
IntLixCredRemove(
    _In_ LIX_CREDS **Creds
    );

void
IntLixCredsVerify(
    _In_ LIX_TASK_OBJECT *Task
    );

INTSTATUS
IntLixCommitCredsHandle(
    _In_ void *Detour
    );

#endif // _LIXCRED_H_
