/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "visibility.h"
#include "guests.h"
#include "winprocesshp.h"


//
// IntWinGetStartUpTime
//
INTSTATUS
IntWinGetStartUpTime(
    _Out_ QWORD *StartUpTime
    )
///
/// @brief      Gets the system startup time
///
/// This will return the creation time of the system process, which is a Windows
/// FILETIME structure (see https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).
/// This remains unchanged on sleep/hibernate events, as the system process remains the same.
/// Note that the CreationTime field in _EPROCESS seems to not have the same meaning for other processes.
///
/// @param[out] StartUpTime     The startup time as a FILETIME value
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if StartUpTime is NULL
/// @retval     #INT_STATUS_NOT_INITIALIZED if the system process is not yet started
///
{
    INTSTATUS status;
    PWIN_PROCESS_OBJECT systemProc;

    if (NULL == StartUpTime)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    systemProc = IntWinProcFindObjectByPid(4);
    if (NULL == systemProc)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    // CreateTime is represented as a FILETIME on both x86 and x64
    status = IntKernVirtMemFetchQword(systemProc->EprocessAddress + WIN_KM_FIELD(Process, CreateTime),
                                      StartUpTime);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


//
// A lot of this is based on http://www.alex-ionescu.com/?p=196
//
//     * From a EPROCESS we read a pointer to a _HANDLE_TABLE struct (Eprocess.ObjectTable)
//     * From that HandleTable we can get the handles array assigned to our process from the TableCode field. TableCode
//     can be interpreted in different ways. If the lower 3 bits are cleared, tableCode is a pointer to the start of
//     the handle table. If tableCode[0-2] = 1, we have a 2-level or a 3-level handle table. When the maximum valid
//     handle value is reached, it is reseted and we use it to index the next handle table.
//     * A Handle value is used as an index inside this table. The lower 2 bits of a handle value are ignored and 0x0
//     is not a valid handle value, so the lowest valid handle value is 0x4. The first (possible) valid handle
//     is HandleTable[4 * sizeof _HANDLE_TABLE_ENTRY]
//     * HandleCount is equal to the number of open handles. A free handle can be found between two open handles. In
//     order to make sure we return all the open handles we need to determine the free ones. We can use
//     HandleTable.FirstFreeHandleEntry, HandleTable.LastFreeHandleEntry and HandleTableEntry.NextFreeHandleEntry.
//     Starting with Windows 8, FirstFreeHandleEntry and NextFreeHandleEntry point directly to the handle table entry
//     structure. On Windows 7 it is equal to the handle value of the free handle. LastFreeHandleEntry is always a
//     pointer to a handle table entry.
//     Or we could do a little trick: a valid handle will point to a object header. This means that the pointer must be
//     a valid kernel pointer. It seems that free handles don't have a valid kernel address in ObjectPtr.
//     If this method backfires we will use the first.
//     * Starting with Windows 8, the first field of the _HANDLE_TABLE_ENTRY (DWORD on x86, QWORD on x64) is actually
//     a pointer to a _OBJECT_HEADER that describes the object related to this handle. The lowest 3 bits are used to
//     store additional info about the object (Audit, Inherited, Protected for x64 and Lock, Audit, Inherited for x86,
//     see the above link for additional details.
//     * the Object we search for is always stored after the ObjectHeader structure so we can get to it by simply adding
//     the offset at which Quad is in _OBJECT_HEADER.
//     * user mode sockets (WSA) are nothing more than file objects. File objects that represent sockets have the file
//     name "\Endpoint" and have a pointer to a Afd.sys object list in FsContext (AfdEndpointListHead is the start of
//     this list). Also FileObject.DeviceObject points to a device from Afd.sys
//


static void
IntWinDumpPrivilegesMask(
    _In_ QWORD Mask
    )
///
/// @brief      Prints the name of the privileges available
///
/// See https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
///
/// @param[in]  Mask        Bitfield of privileges. This is one of the #INTRO_TOKEN_PRIVILEGES fields
///
{
    const CHAR *privs2str[] =
    {
        /* 00 */ NULL,
        /* 01 */ NULL,
        /* 02 */ "SeCreateTokenPrivilege",
        /* 03 */ "SeAssignPrimaryTokenPrivilege",
        /* 04 */ "SeLockMemoryPrivilege",
        /* 05 */ "SeIncreaseQuotaPrivilege",
        /* 06 */ "SeMachineAccountPrivilege",
        /* 07 */ "SeTcbPrivilege",
        /* 08 */ "SeSecurityPrivilege",
        /* 09 */ "SeTakeOwnershipPrivilege",
        /* 10 */ "SeLoadDriverPrivilege",
        /* 11 */ "SeSystemProfilePrivilege",
        /* 12 */ "SeSystemtimePrivilege",
        /* 13 */ "SeProfileSingleProcessPrivilege",
        /* 14 */ "SeIncreaseBasePriorityPrivilege",
        /* 15 */ "SeCreatePagefilePrivilege",
        /* 16 */ "SeCreatePermanentPrivilege",
        /* 17 */ "SeBackupPrivilege",
        /* 18 */ "SeRestorePrivilege",
        /* 19 */ "SeShutdownPrivilege",
        /* 20 */ "SeDebugPrivilege",
        /* 21 */ "SeAuditPrivilege",
        /* 22 */ "SeSystemEnvironmentPrivilege",
        /* 23 */ "SeChangeNotifyPrivilege",
        /* 24 */ "SeRemoteShutdownPrivilege",
        /* 25 */ "SeUndockPrivilege",
        /* 26 */ "SeSyncAgentPrivilege",
        /* 27 */ "SeEnableDelegationPrivilege",
        /* 28 */ "SeManageVolumePrivilege",
        /* 29 */ "SeImpersonatePrivilege",
        /* 30 */ "SeCreateGlobalPrivilege",
        /* 31 */ "SeTrustedCredManAccessPrivilege",
        /* 32 */ "SeRelabelPrivilege",
        /* 33 */ "SeIncreaseWorkingSetPrivilege",
        /* 34 */ "SeTimeZonePrivilege",
        /* 35 */ "SeCreateSymbolicLinkPrivilege",
    };

    for (DWORD i = 0; i < 63; i++)
    {
        if (BIT(i) & Mask)
        {
            if (i >= ARRAYSIZE(privs2str) || privs2str[i] == NULL)
            {
                LOG("%d Unknown Privilege\n", i);
            }
            else
            {
                LOG("%d %s\n", i, privs2str[i]);
            }
        }
    }
}


//
// IntWinDumpPrivileges
//
INTSTATUS
IntWinDumpPrivileges(
    _In_ INTRO_TOKEN_PRIVILEGES const *Privileges
    )
///
/// @brief      Prints a #INTRO_TOKEN_PRIVILEGES structure.
///
/// @param[in]  Privileges  Pointer to a structure to dump. This is obtained from a #INTRO_WIN_TOKEN structure.
///
/// @retval     #INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Privileges is NULL.
///
{
    if (NULL == Privileges)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    LOG("Present: \n");
    IntWinDumpPrivilegesMask(Privileges->Present);

    LOG("Enabled: \n");
    IntWinDumpPrivilegesMask(Privileges->Enabled);

    LOG("Enabled By Default: \n");
    IntWinDumpPrivilegesMask(Privileges->EnabledByDefault);

    return INT_STATUS_SUCCESS;
}

//
// IntWinReadSid
//
INTSTATUS
IntWinReadSid(
    _In_ QWORD SidAndAttributesGva,
    _Out_ INTRO_SID_ATTRIBUTES *Sid
    )
///
/// @brief      Reads the contents of a _SID_AND_ATTRIBUTES Windows structure.
///
/// If the SubAuthority array inside the guest structure contains more than #INTRO_WIN_SID_MAX_SUB_AUTHORITIES entries,
/// only the first #INTRO_WIN_SID_MAX_SUB_AUTHORITIES entries will be read.
///
/// @param[in]  SidAndAttributesGva     Guest virtual address of the _SID_AND_ATTRIBUTES structure.
/// @param[out] Sid                     On success, will contain the _SID_AND_ATTRIBUTES structure.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if SidAndAttributesGva is not a kernel pointer.
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Sid is NULL.
/// @retval     #INT_STATUS_INVALID_DATA_VALUE if pointers inside the guest _SID_AND_ATTRIBUTES structure are not valid
///             kernel pointers.
///
{
    INTSTATUS status;
    QWORD sidGva;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, SidAndAttributesGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Sid)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (gGuest.Guest64)
    {
        SID_AND_ATTRIBUTES64 sa = {0};

        status = IntKernVirtMemRead(SidAndAttributesGva, sizeof(sa), &sa, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        Sid->Attributes = sa.Attributes;
        sidGva = sa.Sid;
    }
    else
    {
        SID_AND_ATTRIBUTES32 sa = {0};

        status = IntKernVirtMemRead(SidAndAttributesGva, sizeof(sa), &sa, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        Sid->Attributes = sa.Attributes;
        sidGva = sa.Sid;
    }

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, sidGva))
    {
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    status = IntKernVirtMemRead(sidGva, sizeof(INTRO_WIN_SID), &Sid->Sid, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    Sid->Sid.SubAuthorityCount = MIN(Sid->Sid.SubAuthorityCount, INTRO_WIN_SID_MAX_SUB_AUTHORITIES);

    return IntKernVirtMemRead(sidGva + FIELD_OFFSET(INTRO_WIN_SID, SubAuthority),
                              sizeof(DWORD) * Sid->Sid.SubAuthorityCount, &Sid->Sid.SubAuthority, NULL);
}


//
// IntWinReadToken
//
INTSTATUS
IntWinReadToken(
    _In_ QWORD TokenGva,
    _Out_ INTRO_WIN_TOKEN *Token
    )
///
/// @brief      Reads the contents of a _TOKEN Windows structure.
///
/// If the Sid or RestrictedSid arrays inside the guest have more than #INTRO_SIDS_MAX_COUNT entries, only the first
/// #INTRO_SIDS_MAX_COUNT will be read and the SidsBufferTooSmall or RestrictedSidsBufferTooSmall will be set to True.
///
/// @param[in]  TokenGva    Guest virtual address from which to read the _TOKEN structure.
/// @param[out] Token       On success, will contain the _TOKEN structure.
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if TokenGva is not a valid kernel pointer
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Token is NULL
/// @retval     #INT_STATUS_NOT_FOUND if parts of the structure could not be read
///
{
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, TokenGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Token)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // read the privileges
    status = IntKernVirtMemRead(TokenGva + WIN_KM_FIELD(Token, Privs),
                                sizeof(INTRO_TOKEN_PRIVILEGES), &Token->Privileges, NULL);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // read User and Groups SIDs
    status = IntKernVirtMemFetchDword(TokenGva + WIN_KM_FIELD(Token, UserCount),
                                      &Token->SidCount);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    // assume that the buffers are large enough
    Token->SidsBufferTooSmall = Token->RestrictedSIdsBufferTooSmall = FALSE;

    if (0 != Token->SidCount)
    {
        QWORD gva = 0;
        size_t incrementSize;

        if (Token->SidCount > INTRO_SIDS_MAX_COUNT)
        {
            Token->SidCount = INTRO_SIDS_MAX_COUNT;
            Token->SidsBufferTooSmall = TRUE;
        }

        if (gGuest.Guest64)
        {
            incrementSize = sizeof(SID_AND_ATTRIBUTES64);
            status = IntKernVirtMemFetchQword(TokenGva + WIN_KM_FIELD(Token, Users), &gva);
        }
        else
        {
            incrementSize = sizeof(SID_AND_ATTRIBUTES32);
            status = IntKernVirtMemFetchDword(TokenGva + WIN_KM_FIELD(Token, Users), (PDWORD)&gva);
            gva &= 0xFFFFFFFF;
        }
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Failed to read Token.UserAndGroups: 0x%08x\n", status);
            return status;
        }

        for (DWORD i = 0; i < Token->SidCount; i++)
        {
            status = IntWinReadSid(gva + i * incrementSize, &Token->SidsAndAttributes[i]);
            if (!INT_SUCCESS(status))
            {
                return status;
            }

            Token->SidsAndAttributes[i].IsRestricted = FALSE;
        }
    }

    // read Restricted SIDs
    status = IntKernVirtMemFetchDword(TokenGva + WIN_KM_FIELD(Token, RestrictedCount),
                                      &Token->RestrictedSidCount);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (0 != Token->RestrictedSidCount)
    {
        QWORD gva = 0;
        size_t incrementSize;

        if (Token->RestrictedSidCount > INTRO_SIDS_MAX_COUNT)
        {
            Token->RestrictedSidCount = INTRO_SIDS_MAX_COUNT;
            Token->RestrictedSIdsBufferTooSmall = TRUE;
        }

        if (gGuest.Guest64)
        {
            incrementSize = sizeof(SID_AND_ATTRIBUTES64);
            status = IntKernVirtMemFetchQword(TokenGva + WIN_KM_FIELD(Token, RestrictedSids), &gva);
        }
        else
        {
            incrementSize = sizeof(SID_AND_ATTRIBUTES32);
            status = IntKernVirtMemFetchDword(TokenGva + WIN_KM_FIELD(Token, RestrictedSids), (PDWORD)&gva);
            gva &= 0xFFFFFFFF;
        }
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        for (DWORD i = 0; i < Token->RestrictedSidCount; i++)
        {
            status = IntWinReadSid(gva + i * incrementSize, &Token->RestrictedSids[i]);
            if (!INT_SUCCESS(status))
            {
                return status;
            }

            Token->RestrictedSids[i].IsRestricted = TRUE;
        }
    }

    // this might not be a valid Token
    if (0 == Token->SidCount && 0 == Token->RestrictedSidCount)
    {
        QWORD gva = 0;

        // try to read UserAndGroups
        if (gGuest.Guest64)
        {
            status = IntKernVirtMemFetchQword(TokenGva + WIN_KM_FIELD(Token, Users), &gva);
        }
        else
        {
            status = IntKernVirtMemFetchDword(TokenGva + WIN_KM_FIELD(Token, Users), (PDWORD)&gva);
        }
        if (!INT_SUCCESS(status) || !IS_KERNEL_POINTER_WIN(gGuest.Guest64, gva))
        {
            return INT_STATUS_NOT_FOUND;
        }

        // try to read restricted SIDs (the pointer can be null)
        if (gGuest.Guest64)
        {
            status = IntKernVirtMemFetchQword(TokenGva + WIN_KM_FIELD(Token, RestrictedCount), &gva);
        }
        else
        {
            status = IntKernVirtMemFetchDword(TokenGva + WIN_KM_FIELD(Token, RestrictedCount), (PDWORD)&gva);
        }
        if (!INT_SUCCESS(status) || !IS_KERNEL_POINTER_WIN(gGuest.Guest64, gva))
        {
            return INT_STATUS_NOT_FOUND;
        }
    }

    return status;
}


//
// IntWinGetAccessTokenFromProcess
//
INTSTATUS
IntWinGetAccessTokenFromProcess(
    _In_ DWORD ProcessId,
    _In_ QWORD EprocessGva,
    _Out_ INTRO_WIN_TOKEN *Token
    )
///
/// @brief      Reads the contents of a _TOKEN Windows structure assigned to a process.
///
/// This function obtains the address of the _TOKEN structure associated with the given process and then uses
/// #IntWinReadToken to read it. Note that the pointer saved inside _EPROCESS is a _EX_FAST_REF (see
/// #EX_FAST_REF_TO_PTR).
///
/// @param[in]  ProcessId   The ID of the process. If EprocessGva is 0 will search the process by this ID; ignored
///                         if EprocessGva is not 0.
/// @param[in]  EprocessGva The guest virtual address of the _EPROCESS structure from which to obtain the token. If
///                         0 will use ProcessId to find the process.
/// @param[out] Token       On success, will contain the _TOKEN structure.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    QWORD tokenGva = 0;
    PWIN_PROCESS_OBJECT pProcess = NULL;

    if (NULL == Token)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (0 == EprocessGva)
    {
        status = IntWinProcGetObjectByPid(ProcessId, &pProcess);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinProcGetObjectByPid failed for %d: 0x%x\n", ProcessId, status);
            return status;
        }

        EprocessGva = pProcess->EprocessAddress;
    }

    // the Token pointer is stored as EX_FAST_REF, we have to clear the lower bits before using it
    if (gGuest.Guest64)
    {
        status = IntKernVirtMemFetchQword(EprocessGva + WIN_KM_FIELD(Process, Token), &tokenGva);
    }
    else
    {
        status = IntKernVirtMemFetchDword(EprocessGva + WIN_KM_FIELD(Process, Token), (PDWORD)&tokenGva);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read Token from Eprocess 0x%016llx: 0x%08x\n", EprocessGva, status);
        return status;
    }

    tokenGva = EX_FAST_REF_TO_PTR(gGuest.Guest64, tokenGva);
    return IntWinReadToken(tokenGva, Token);
}


//
// IntWinGetAccesTokenFromThread
//
INTSTATUS
IntWinGetAccesTokenFromThread(
    _In_ QWORD EthreadGva,
    _Out_ INTRO_WIN_TOKEN *Token
    )
///
/// @brief      Reads the contents of a _TOKEN Windows structure assigned to a thread.
///
/// This function obtains the address of the _TOKEN structure associated with the given thread and then uses
/// #IntWinReadToken to read it. Note that the pointer saved inside _ETHREAD is a _PS_CLIENT_SECURITY_CONTEXT, bits
/// [0:2] must be cleared before using it as a pointer.
///
/// @param[in]  EthreadGva  The guest virtual address of the _ETHREAD structure from which to obtain the token.
/// @param[out] Token       On success, will contain the _TOKEN structure.
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
    QWORD tokenGva = 0;

    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, EthreadGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Token)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (gGuest.Guest64)
    {
        status = IntKernVirtMemFetchQword(EthreadGva + WIN_KM_FIELD(Thread, ClientSecurity), &tokenGva);
    }
    else
    {
        status = IntKernVirtMemFetchDword(EthreadGva + WIN_KM_FIELD(Thread, ClientSecurity), (PDWORD)&tokenGva);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to read Token from Ethread 0x%016llx: 0x%08x\n", EthreadGva, status);
        return status;
    }

    // Ethread.ClientSecurity is of type _PS_CLIENT_SECURITY_CONTEXT, clear bits 0-2
    tokenGva &= ~((QWORD)0x7);
    if (!IS_KERNEL_POINTER_WIN(gGuest.Guest64, tokenGva))
    {
        return INT_STATUS_NOT_FOUND;
    }

    return IntWinReadToken(tokenGva, Token);
}


//
// IntWinDumpSid
//
void
IntWinDumpSid(
    _In_ INTRO_SID_ATTRIBUTES const *Sid
    )
///
/// @brief      Prints a #INTRO_SID_ATTRIBUTES structure.
///
/// @param[in]  Sid     Pointer to a #INTRO_SID_ATTRIBUTES structure to print.
///
{
    if (NULL == Sid)
    {
        return;
    }

    if (Sid->IsRestricted)
    {
        LOG("Restricted SID\n");
    }

    LOG("Attributes: 0x%x\n", Sid->Attributes);

    LOG("Revision: %d\n", Sid->Sid.Revision);

    LOG("Identifier Authority: ");
    for (DWORD i = 0; i < 6; i++)
    {
        NLOG("%d ", Sid->Sid.IdentifierAuthority[i]);
    }
    NLOG("\n");

    LOG("Sub authority: ");
    for (DWORD i = 0; i < Sid->Sid.SubAuthorityCount; i++)
    {
        NLOG("%d ", Sid->Sid.SubAuthority[i]);
    }
    NLOG("\n");
}


//
// IntWinDumpToken
//
void
IntWinDumpToken(
    _In_ INTRO_WIN_TOKEN const *Token
    )
///
/// @brief      Prints a #INTRO_WIN_TOKEN structure.
///
/// @param[in]  Token   Pointer to a #INTRO_WIN_TOKEN structure to print.
///
{
    if (NULL == Token)
    {
        return;
    }

    if (Token->ImpersonationToken)
    {
        LOG("Impersonation token\n");
    }

    LOG("Privileges: \n");
    IntWinDumpPrivileges(&Token->Privileges);

    LOG("User and Groups: \n");
    for (DWORD i = 0; i < Token->SidCount; i++)
    {
        IntWinDumpSid(&Token->SidsAndAttributes[i]);
    }

    LOG("Restricted SIDs: \n");
    for (DWORD i = 0; i < Token->RestrictedSidCount; i++)
    {
        IntWinDumpSid(&Token->RestrictedSids[i]);
    }
}
