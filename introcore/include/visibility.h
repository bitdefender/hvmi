/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VISIBILITY_H_
#define _VISIBILITY_H_

#include "introcore.h"

INTSTATUS
IntWinGetStartUpTime(
    _Out_ QWORD *StartUpTime);

//
// Privileges bit in _TOKEN_PRIVILEGES bitmap (obtained from WinDbg);
// bits who are not defined here are not used (marked as Unknown in WinDbg)
//

#define PRIV_CREATE_TOKEN               BIT(2)
#define PRIV_ASSIGN_PRIMARY_TOKEN       BIT(3)
#define PRIV_LOCK_MEMORY                BIT(4)
#define PRIV_INCREASE_QUOTA             BIT(5)
#define PRIV_MACHINE_ACCOUNT            BIT(6)
#define PRIV_TCB                        BIT(7)
#define PRIV_SECURITY                   BIT(8)
#define PRIV_TAKE_OWNERSHIP             BIT(9)
#define PRIV_LOAD_DRIVER                BIT(10)
#define PRIV_SYSTEM_PROFILE             BIT(11)
#define PRIV_SYSTEM_TIME                BIT(12)
#define PRIV_PROFILE_SINGLE_PROCESS     BIT(13)
#define PRIV_INCREASE_BASE_PRIORITY     BIT(14)
#define PRIV_CREATE_PAGEFILE            BIT(15)
#define PRIV_CREATE_PERMANENT           BIT(16)
#define PRIV_BACKUP                     BIT(17)
#define PRIV_RESTORE                    BIT(18)
#define PRIV_SHUTDOWN                   BIT(19)
#define PRIV_DEBUG                      BIT(20)
#define PRIV_AUDOT                      BIT(21)
#define PRIV_SYSTEM_ENVIRONMENT         BIT(22)
#define PRIV_CHANGE_NOTIFY              BIT(23)
#define PRIV_REMOTE_SHUTDOWN            BIT(24)
#define PRIV_UNDOCK                     BIT(25)
#define PRIV_SYNC_AGENT                 BIT(26)
#define PRIV_ENABLE_DELEGATION          BIT(27)
#define PRIV_MANAGE_VOLUME              BIT(28)
#define PRIV_IMPERSONATE                BIT(29)
#define PRIV_CREATE_GLOBAL              BIT(30)
#define PRIV_TRUSTED_CRED_MAN_ACCESS    BIT(31)
#define PRIV_RELABLE                    BIT(32)
#define PRIV_INCREASE_WORKING_SET       BIT(33)
#define PRIV_TIMEZONE                   BIT(34)
#define PRIV_CREATE_SYMBOLIC_LINK       BIT(35)

#define FIRST_KNOWN_PRIVILEGE               02
#define LAST_KNOWN_PRIVILEGE                35

INTSTATUS
IntWinDumpPrivileges(
    _In_ INTRO_TOKEN_PRIVILEGES const *Privileges
    );

INTSTATUS
IntWinReadSid(
    _In_ QWORD SidAndAttributesGva,
    _Out_ INTRO_SID_ATTRIBUTES *Sid
    );

INTSTATUS
IntWinReadToken(
    _In_ QWORD TokenGva,
    _Out_ INTRO_WIN_TOKEN *Token
    );

INTSTATUS
IntWinGetAccessTokenFromProcess(
    _In_ DWORD ProcessId,
    _In_ QWORD EprocessGva,
    _Out_ INTRO_WIN_TOKEN *Token
    );

INTSTATUS
IntWinGetAccesTokenFromThread(
    _In_ QWORD EthreadGva,
    _Out_ INTRO_WIN_TOKEN *Token
    );

void
IntWinDumpToken(
    _In_ INTRO_WIN_TOKEN const *Token
    );

void
IntWinDumpSid(
    _In_ INTRO_SID_ATTRIBUTES const *Sid
    );

#endif // _VISIBILITY_H_
