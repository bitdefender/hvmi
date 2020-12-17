/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcore.h"
#include "winsecdesc.h"
#include "guests.h"
#include "hook.h"
#include "alerts.h"
#include "gpacache.h"
#include "kernvm.h"
#include "crc32.h"

// Please note that the SECURITY_DESCRIPTOR structure is not the one described on MSDN
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor
// Below, there is windbg dump showing how the actual SECURITY_DESCRIPTOR looks like.
//
//  1) Let`s get the _EPROCESS for system process
//      0: kd > !process 0 0 system
//      PROCESS ffffa103dd2652c0
//      SessionId : none  Cid : 0004    Peb : 00000000  ParentCid : 0000
//      DirBase : 001ad002  ObjectTable : ffff8b8278c06e40  HandleCount : 2334.
//      Image : System
//
//  2) The security descriptor address is located word size (#gGuest.WordSize) before the _EPROCESS (part of
//  the _OBJECT_HEADER structure).
//      0 : kd > dq ffffa103dd2652c0 - 8 l 1
//      ffffa103`dd2652b8  ffff8b82`78c094ec
//
//  3) Now we have the address (ffff8b82`78c094ec). Let`s zero out the last 4 bits (see #EX_FAST_REF_TO_PTR) and dump
//  the security descriptor.
//      0: kd > !sd ffff8b82`78c094e0
//      ->Revision: 0x1
//      ->Sbz1 : 0x0
//      ->Control : 0x8814
//      SE_DACL_PRESENT
//      SE_SACL_PRESENT
//      SE_SACL_AUTO_INHERITED
//      SE_SELF_RELATIVE
//      ->Owner : S - 1 - 5 - 32 - 544
//      ->Group : S - 1 - 5 - 18
//      ->Dacl :
//      ->Dacl : ->AclRevision : 0x2 ________________________________________________________________________
//      ->Dacl : ->Sbz1 : 0x0                                                                                |
//      ->Dacl : ->AclSize : 0x3c                                                                            |
//      ->Dacl : ->AceCount : 0x2                                                                            |
//      ->Dacl : ->Sbz2 : 0x0                                                                                |
//      ->Dacl : ->Ace[0] : ->AceType : ACCESS_ALLOWED_ACE_TYPE                                              |
//      ->Dacl : ->Ace[0] : ->AceFlags : 0x0                                                                 |
//      ->Dacl : ->Ace[0] : ->AceSize : 0x14                                                                 |
//      ->Dacl : ->Ace[0] : ->Mask : 0x001fffff                                                              |
//      ->Dacl : ->Ace[0] : ->SID : S - 1 - 5 - 18                                                           |
//                                                                                                           |
//      ->Dacl : ->Ace[1] : ->AceType : ACCESS_ALLOWED_ACE_TYPE                                              |
//      ->Dacl : ->Ace[1] : ->AceFlags : 0x0                                                                 |
//      ->Dacl : ->Ace[1] : ->AceSize : 0x18                                                                 |
//      ->Dacl : ->Ace[1] : ->Mask : 0x00121411                                                              |
//      ->Dacl : ->Ace[1] : ->SID : S - 1 - 5 - 32 - 544                                                     |
//                                                                                                           |
//      ->Sacl :                                                                                             |
//      ->Sacl : ->AclRevision : 0x2 _____________________________________________________                   |
//      ->Sacl : ->Sbz1 : 0x0                                                             |                  |
//      ->Sacl : ->AclSize : 0x1c                                                         |                  |
//      ->Sacl : ->AceCount : 0x1                                                         |                  |
//      ->Sacl : ->Sbz2 : 0x0                                                             |                  |
//      ->Sacl : ->Ace[0] : ->AceType : SYSTEM_MANDATORY_LABEL_ACE_TYPE                   |                  |
//      ->Sacl : ->Ace[0] : ->AceFlags : 0x0                                              |                  |
//      ->Sacl : ->Ace[0] : ->AceSize : 0x14                                              |                  |
//      ->Sacl : ->Ace[0] : ->Mask : 0x00000003                                           |                  |
//      ->Sacl : ->Ace[0] : ->SID : S - 1 - 16 - 16384                                    |                  |
//                                                                                        |                  |
//      0 : kd > db ffff8b82`78c094e0 l 100                                               |                  |
//                                                                                        |                  |
//                                         _______________________________________________|                  |
//                                         |                                                                 |
//      ffff8b82`78c094e0     01 00 14 88  |  6c 00 00 00 - 7c 00 00 00 14 00 00 00  ....l... | .......      |
//      ffff8b82`78c094f0     30 00 00 00  |->02 00 1c 00 - 01 00 00 00 11 00 14 00  0...............        |
//      ffff8b82`78c09500     03 00 00 00     01 01 00 00 - 00 00 00 10 00 40 00 00  .............@..        |
//                         __________________________________________________________________________________|
//                         |
//      ffff8b82`78c09510  |->02 00 3c 00     02 00 00 00 - 00 00 14 00 ff ff 1f 00  .. < .............
//      ffff8b82`78c09520     01 01 00 00     00 00 00 05 - 12 00 00 00 00 00 18 00  ................
//      ffff8b82`78c09530     11 14 12 00     01 02 00 00 - 00 00 00 05 20 00 00 00  ............ ...
//      ffff8b82`78c09540     20 02 00 00     00 00 00 00 - 00 00 00 00 01 02 00 00   ...............
//      ffff8b82`78c09550     00 00 00 05     20 00 00 00 - 20 02 00 00 01 01 00 00  .... ... .......
//      ffff8b82`78c09560     00 00 00 05     12 00 00 00 - 00 00 00 00 00 00 00 00  ................
//      ffff8b82`78c09570     00 00 00 00     00 00 00 00 - 00 00 00 00 00 00 00 00  ................
//      ffff8b82`78c09580     00 00 00 00     00 00 00 00 - 00 00 00 00 00 00 00 00  ................
//      ffff8b82`78c09590     a7 47 db 42     f4 bb 9b c6 - 00 00 00 00 00 00 00 00. G.B............
//
// 4) Please note that the AclSize also takes into account the "header", not only the contents (ACEs). For example,
// SACL starts at ffff8b82`78c094f4 and ends at ffff8b82`78c09510 (the difference is exactly 1c, as the AclSize).
//
// 5) Same goes for DACL.

extern LIST_HEAD gWinProcesses;

/// @brief  We are using the #EXCEPTION_VICTIM_ZONE.WriteInfo to send the New/Old SACL/DACL.
STATIC_ASSERT(sizeof(ACL) == sizeof(QWORD), "Sizeof of ACL is not a QWORD");

/// @brief  Make sure the buffer is big enough - at least for the headers.
STATIC_ASSERT(INTRO_SECURITY_DESCRIPTOR_SIZE > (sizeof(SECURITY_DESCRIPTOR) + 2 * sizeof(ACL)),
              "INTRO_SECURITY_DESCRIPTOR_SIZE is too small");

/// @brief  The maximum number of ACEs that are allowed within a single ACL. "The maximum size of an ACL is 64
/// kilobytes (KB), or approximately 1,820 ACEs."
/// https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/error-add-user-to-security-permissions
#define INT_MAX_ACE_COUNT   1820

static char *
IntWinSDGetAceTypeName(
    _In_ BYTE AceTypeValue
    )
///
/// @brief      This function obtains the printable name for a given ACE type.
///
/// @param[in]  AceTypeValue    The ACE type - found within the Security Descriptor.
///
/// @retval     A valid ACE type name       On success.
/// @retval     NULL                        If the given ACE type value is invalid.
///
{
    char *aceType;

    switch (AceTypeValue)
    {
    case ACCESS_ALLOWED_ACE_TYPE:
        aceType = ACCESS_ALLOWED_ACE_TYPE_STRING;
        break;
    case ACCESS_DENIED_ACE_TYPE:
        aceType = ACCESS_DENIED_ACE_TYPE_STRING;
        break;
    case SYSTEM_AUDIT_ACE_TYPE:
        aceType = SYSTEM_AUDIT_ACE_TYPE_STRING;
        break;
    case SYSTEM_ALARM_ACE_TYPE:
        aceType = SYSTEM_ALARM_ACE_TYPES_STRING;
        break;
    case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
        aceType = ACCESS_ALLOWED_COMPOUND_ACE_TYPE_STRING;
        break;
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        aceType = ACCESS_ALLOWED_OBJECT_ACE_TYPE_STRING;
        break;
    case ACCESS_DENIED_OBJECT_ACE_TYPE:
        aceType = ACCESS_DENIED_OBJECT_ACE_TYPE_STRING;
        break;
    case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
        aceType = SYSTEM_AUDIT_OBJECT_ACE_TYPE_STRING;
        break;
    case SYSTEM_ALARM_OBJECT_ACE_TYPE:
        aceType = SYSTEM_ALARM_OBJECT_ACE_TYPE_STRING;
        break;
    case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        aceType = ACCESS_ALLOWED_CALLBACK_ACE_TYPE_STRING;
        break;
    case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        aceType = ACCESS_DENIED_CALLBACK_ACE_TYPE_STRING;
        break;
    case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
        aceType = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE_STRING;
        break;
    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
        aceType = ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE_STRING;
        break;
    case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
        aceType = SYSTEM_AUDIT_CALLBACK_ACE_TYPE_STRING;
        break;
    case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
        aceType = SYSTEM_ALARM_CALLBACK_ACE_TYPE_STRING;
        break;
    case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
        aceType = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE_STRING;
        break;
    case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
        aceType = SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE_STRING;
        break;
    case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        aceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE_STRING;
        break;
    case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
        aceType = SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE_STRING;
        break;
    case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
        aceType = SYSTEM_SCOPED_POLICY_ID_ACE_TYPE_STRING;
        break;
    case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
        aceType = SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE_STRING;
        break;
    case SYSTEM_ACCESS_FILTER_ACE_TYPE:
        aceType = SYSTEM_ACCESS_FILTER_ACE_TYPE_STRING;
        break;
    default:
        aceType = NULL;
    }

    return aceType;
}


INTSTATUS
IntWinSDFindAcls(
    _In_ DWORD BufferSize,
    _In_ BYTE *SecurityDescriptorBuffer,
    _Inout_ DWORD *ReadSize,
    _Out_ ACL **Sacl,
    _Out_ ACL **Dacl
    )
///
/// @brief      This function looks for the Sacl/Dacl within the SecurityDescriptorBuffer and makes sure they are within
/// the buffer range.
///
/// @param[in]  BufferSize                  The size in bytes of the given buffer (SecurityDescriptorBuffer).
/// @param[in]  SecurityDescriptorBuffer    The buffer where the ACLs (along with the ACEs) are stored.
/// @param[out] ReadSize                    The size in bytes of the returned security descriptor.
/// @param[out] Sacl                        Points to the SACL header inside the SecurityDescriptorBuffer.
/// @param[out] Dacl                        Points to the DACL header inside the SecurityDescriptorBuffer.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL   If the Sacl/Dacl do not fit within the buffer.
///
{
    ACL *sacl = NULL;
    ACL *dacl = NULL;

    *Sacl = NULL;
    *Dacl = NULL;

    if (BufferSize < sizeof(SECURITY_DESCRIPTOR) ||
        BufferSize < sizeof(ACL) ||
        BufferSize < sizeof(SECURITY_DESCRIPTOR) + sizeof(ACL))
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }
    
    sacl = (ACL *)((QWORD)SecurityDescriptorBuffer + sizeof(SECURITY_DESCRIPTOR));

    // Please note that the sacl->AclSize also takes into account the ACL structure.
    // Here we bail out even if (QWORD)sacl + sizeof(ACL) = (QWORD)SecurityDescriptorBuffer + BufferSize because we
    // expect at least one ACE entry for the given ACL.
    if ((QWORD)sacl >= (QWORD)SecurityDescriptorBuffer + BufferSize ||
        (QWORD)sacl + sizeof(ACL) >= (QWORD)SecurityDescriptorBuffer + BufferSize ||
        sacl->AclSize > BufferSize ||
        sacl->AclSize < sizeof(ACL) ||
        sacl->AclSize + sizeof(SECURITY_DESCRIPTOR) > BufferSize ||
        sacl->AclSize + sizeof(SECURITY_DESCRIPTOR) + sizeof(ACL) > BufferSize ||
        sacl->AclRevision > MAX_ACL_REVISION ||
        sacl->AclSize < sacl->AceCount * sizeof(ACE_HEADER) ||
        sacl->Sbz1 != 0 ||
        sacl->Sbz2 != 0)
    {
        WARNING("[WARNING] It seems that the SaclSize is unexpected\n");

        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    *Sacl = sacl;
    *ReadSize += sacl->AclSize;

    dacl = (ACL *)((QWORD)sacl + sacl->AclSize);

    // Please note that the dacl->AclSize also takes into account the ACL structure.
    // Here we bail out even if (QWORD)dacl + sizeof(ACL) = (QWORD)SecurityDescriptorBuffer + BufferSize because we
    // expect at least one ACE entry for the given ACL.
    if ((QWORD)dacl >= (QWORD)SecurityDescriptorBuffer + BufferSize ||
        (QWORD)dacl + sizeof(ACL) >= (QWORD)SecurityDescriptorBuffer + BufferSize ||
        dacl->AclSize > BufferSize ||
        dacl->AclSize < sizeof(ACL) ||
        dacl->AclSize + sizeof(SECURITY_DESCRIPTOR) > BufferSize ||
        ((QWORD)sacl->AclSize + dacl->AclSize + sizeof(SECURITY_DESCRIPTOR)) > BufferSize ||
        dacl->AclRevision > MAX_ACL_REVISION ||
        dacl->AclSize < dacl->AceCount * sizeof(ACE_HEADER) ||
        dacl->Sbz1 != 0 ||
        dacl->Sbz2 != 0)
    {
        WARNING("[WARNING] It seems that the DaclSize is unexpected\n");

        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    *Dacl = dacl;
    *ReadSize += dacl->AclSize;

    return INT_STATUS_SUCCESS;
}


static BOOLEAN
IntWinSDIsAceInsideAcl(
    _In_ ACL *Acl,
    _In_ ACE_HEADER *Ace
    )
///
/// @brief      This function checks whether the ACE fits inside the ACL (the ACL structure must be obtained using
/// IntWinSDFindAcls).
///
/// @param[in]  Acl     The Access Control List.
/// @param[in]  Ace     The Access Control Entry.
///
/// @retval     #TRUE   The Ace fits inside the Acl.
/// @retval     #FALSE  The Ace does NOT fit inside the Acl.
///
{
    // IntWinSDFindAcls may return a NULL Sacl/Dacl.
    if (NULL == Acl || NULL == Ace)
    {
        return FALSE;
    }

    // Please note that in IntWinSDReadSecDesc, we make sure that #ACL::AclSize is inside the Security Descriptor
    // buffer - otherwise the returned ACL (Sacl/Dacl) will be NULL.
    if ((QWORD)Ace >= (QWORD)Acl + Acl->AclSize ||
        (QWORD)Ace + sizeof(ACE_HEADER) > (QWORD)Acl + Acl->AclSize ||
        (QWORD)Ace + Ace->AceSize > (QWORD)Acl + Acl->AclSize ||
        Ace->AceSize >= Acl->AclSize ||
        Ace->AceSize < sizeof(ACE_HEADER))
    {
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN
IntWinSDIsAceInsideBuffer(
    _In_ BYTE *Buffer,
    _In_ DWORD BufferSize,
    _In_ ACE_HEADER *Ace
)
///
/// @brief      This function checks whether the ACE fits inside the given buffer.
///
/// @param[in]  Buffer      The buffer.
/// @param[in]  BufferSize  The size of the buffer.
/// @param[in]  Ace         The Access Control Entry.
///
/// @retval     #TRUE   The Ace fits inside the buffer.
/// @retval     #FALSE  The Ace does NOT fit inside the buffer.
///
{
    if (NULL == Buffer || NULL == Ace)
    {
        return FALSE;
    }

    if ((QWORD)Ace >= (QWORD)Buffer + BufferSize ||
        (QWORD)Ace + sizeof(ACL) > (QWORD)Buffer + BufferSize ||
        (QWORD)Ace + sizeof(ACE_HEADER) > (QWORD)Buffer + BufferSize ||
        (QWORD)Ace + sizeof(ACE_HEADER) + sizeof(ACE_BODY) > (QWORD)Buffer + BufferSize ||
        Ace->AceSize > BufferSize ||
        Ace->AceSize < sizeof(ACE_HEADER))
    {
        return FALSE;
    }

    return TRUE;
}


INTSTATUS
IntWinSDReadSecDesc(
    _In_ QWORD SecurityDescriptorGva,
    _In_ DWORD BufferSize,
    _Out_writes_bytes_ (BufferSize) BYTE *SecurityDescriptorBuffer,
    _Out_ DWORD *ReadSize,
    _Out_ ACL **Sacl,
    _Out_ ACL **Dacl
    )
///
/// @brief      This function reads the ACLs (along with the ACEs) from the given GVA and returns the data using
/// the provided buffer and the Sacl/Dacl pointers. This function will read the #SECURITY_DESCRIPTOR structure that
/// acts as a header, the SACL header and then use the SACL size to find the DACL. If an attacker were to alter the
/// SACL/DACL size such that it will not fit in the given buffer, the function will fail with
/// #INT_STATUS_DATA_BUFFER_TOO_SMALL - check the returned Sacl/Dacl values.
///
/// @param[in]  SecurityDescriptorGva       The GVA of the security descriptor.
/// @param[in]  BufferSize                  The size in bytes of the given buffer (SecurityDescriptorBuffer).
/// @param[out] SecurityDescriptorBuffer    The buffer where the ACLs (along with the ACEs) will be stored.
/// @param[out] ReadSize                    The size in bytes of the returned security descriptor.
/// @param[out] Sacl                        Points to the SACL header inside the SecurityDescriptorBuffer.
/// @param[out] Dacl                        Points to the DACL header inside the SecurityDescriptorBuffer.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_PAGE_NOT_PRESENT        If the given GVA is not mapped.
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL   If the security descriptor is larger than the provided buffer.
///
{
    INTSTATUS status;
    VA_TRANSLATION tr = { 0 };

    if (0 == SecurityDescriptorGva || NULL == SecurityDescriptorBuffer ||
        NULL == ReadSize || NULL == Sacl || NULL == Dacl)
    {
        return INT_STATUS_INVALID_PARAMETER;
    }

    *ReadSize = 0;
    *Sacl = NULL;
    *Dacl = NULL;

    if (BufferSize < INTRO_SECURITY_DESCRIPTOR_SIZE)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    status = IntTranslateVirtualAddressEx(SecurityDescriptorGva, gGuest.Mm.SystemCr3, TRFLG_PG_MODE, &tr);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
        return status;
    }

    if (0 == (tr.Flags & PT_P))
    {
        return INT_STATUS_PAGE_NOT_PRESENT;
    }

    status = IntGpaCacheFetchAndAdd(gGuest.GpaCache,
                                    tr.PhysicalAddress,
                                    BufferSize,
                                    (BYTE *)SecurityDescriptorBuffer);
    if (INT_STATUS_NOT_SUPPORTED == status)
    {
        // This happens if the buffer is spread on more than one page.
        status = IntKernVirtMemRead(SecurityDescriptorGva, BufferSize, SecurityDescriptorBuffer, NULL);
        if (!INT_SUCCESS(status))
        {
            if (INT_STATUS_PAGE_NOT_PRESENT != status && INT_STATUS_NO_MAPPING_STRUCTURES != status)
            {
                ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            }
            return status;
        }
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheFetchAndAdd failed: 0x%08x\n", status);
        return status;
    }

    *ReadSize = sizeof(SECURITY_DESCRIPTOR);
    
    status = IntWinSDFindAcls(BufferSize,
                              SecurityDescriptorBuffer,
                              ReadSize,
                              Sacl,
                              Dacl);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinSDFindAcls failed: 0x%08x\n", status);
    }

    return status;
}


static void
IntWinSDDumpAclEntries(
    _In_ ACL *Acl,
    _In_ BOOLEAN IsSacl,
    _In_ BYTE *SecurityDescriptorBuffer,
    _In_ DWORD BufferSize
    )
///
/// @brief      This function dumps the access control entries (ACE) for a given access control list (ACL).
///
/// @param[in]  Acl                         The ACL to dump the entries for.
/// @param[in]  IsSacl                      TRUE is the ACL is Sacl, FALSE otherwise (Dacl) - used for logging.
/// @param[in]  SecurityDescriptorBuffer    The security descriptor buffer.
/// @param[in]  BufferSize                  The size of the security descriptor buffer.
///
{
/// @brief  The size of the printable SID buffer.
#define INT_SID_CHAR_SIZE 512
/// @brief  The maximum number of sub authorities - empirically chosen value.
#define INT_MAX_SUB_AUTHORITY_COUT 30

    ACE_HEADER *aceHeader;
    ACE_BODY *aceBody;
    DWORD *subAuthority;
    int writtenBytes;
    char *aclName = IsSacl ? "Sacl" : "Dacl";
    char *aceType = NULL;
    static char sidChar[INT_SID_CHAR_SIZE];

    LOG("->%s :\n", aclName);
    LOG("->%s : ->AclRevision : 0x%x\n", aclName, Acl->AclRevision);
    LOG("->%s : ->Sbz1 : 0x%x\n", aclName, Acl->Sbz1);
    LOG("->%s : ->AclSize : 0x%x\n", aclName, Acl->AclSize);
    LOG("->%s : ->AceCount : 0x%x\n", aclName, Acl->AceCount);
    LOG("->%s : ->Sbz2 : 0x%x\n", aclName, Acl->Sbz2);

    if (__unlikely(Acl->AceCount > INT_MAX_ACE_COUNT))
    {
        WARNING("[WARNING] The maximum number of ACEs has been exceeded:0x%x\n", Acl->AceCount);
        return;
    }

    aceHeader = (ACE_HEADER *)((QWORD)Acl + sizeof(ACL));

    for (DWORD i = 0; i < Acl->AceCount; i++)
    {
        if (!IntWinSDIsAceInsideBuffer(SecurityDescriptorBuffer, BufferSize, aceHeader))
        {
            return;
        }

        aceBody = (ACE_BODY*)((QWORD)aceHeader + sizeof(ACE_HEADER));

        memset(sidChar, 0, INT_SID_CHAR_SIZE);

        writtenBytes = snprintf(sidChar, INT_SID_CHAR_SIZE, "->%s : ->Ace[%d] : ->SID: S-%u-%u",
                                aclName, i, (BYTE)aceBody->Sid.Revision,
                                (BYTE)aceBody->Sid.IdentifierAuthority.Value[5]);
        if (writtenBytes < 0 || writtenBytes >= INT_SID_CHAR_SIZE)
        {
            ERROR("[ERROR] snprintf failed with return value: %d, buffer size: %d\n", writtenBytes, INT_SID_CHAR_SIZE);
            return;
        }

        aceType = IntWinSDGetAceTypeName(aceHeader->AceType);
        if (aceType)
        {
            LOG("->%s : ->Ace[%d] : ->AceType: %s\n", aclName, i, aceType);
        }
        else
        {
            LOG("->%s : ->Ace[%d] : ->AceType: UNKNOWN(0x%x)\n", aclName, i, (BYTE)aceHeader->AceType);
        }
        
        LOG("->%s : ->Ace[%d] : ->AceFlags: 0x%x\n", aclName, i, (BYTE)aceHeader->AceFlags);
        LOG("->%s : ->Ace[%d] : ->AceSize: 0x0%x\n", aclName, i, (WORD)aceHeader->AceSize);
        LOG("->%s : ->Ace[%d] : ->Mask: 0x%08x\n", aclName, i, (DWORD)aceBody->Mask);

        subAuthority = (DWORD *)((QWORD)aceBody + sizeof(ACE_BODY));

        for (DWORD j = 0; j < aceBody->Sid.SubAuthorityCount; j++)
        {
            if (__unlikely(j > INT_MAX_SUB_AUTHORITY_COUT))
            {
                WARNING("[WARNING] The maximum number of sub authorities has been exceeded:0x%x\n",
                        (UCHAR)aceBody->Sid.SubAuthorityCount);
                break;
            }

            if ((QWORD)&subAuthority[j] >= (QWORD)SecurityDescriptorBuffer + BufferSize ||
                (QWORD)&subAuthority[j] + sizeof(DWORD) > (QWORD)SecurityDescriptorBuffer + BufferSize)
            {
                break;
            }

            int ret = snprintf(&sidChar[writtenBytes], (QWORD)INT_SID_CHAR_SIZE - writtenBytes,
                                     "-%u", subAuthority[j]);
            if (ret < 0 || ret >= INT_SID_CHAR_SIZE - writtenBytes)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, INT_SID_CHAR_SIZE - writtenBytes);
            }
            else
            {
                writtenBytes += ret;
            }
        }

        LOG("%s\n", sidChar);
        LOG("->%s :\n", aclName);

        aceHeader = (ACE_HEADER *)((QWORD)aceHeader + aceHeader->AceSize);
    }

#undef INT_SID_CHAR_SIZE
#undef INT_MAX_SUB_AUTHORITY_COUT
}


static void
IntWinSDDumpSecDesc(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BYTE *SecurityDescriptorBuffer,
    _In_ DWORD BufferSize,
    _In_ BOOLEAN Original
    )
///
/// @brief      This function dumps the security descriptor for a given process.
///
/// @param[in]  Process                     The process to dump the security descriptor for.
/// @param[in]  SecurityDescriptorBuffer    The security descriptor to be dumped.
/// @param[in]  BufferSize                  The size of the security descriptor buffer.
/// @param[in]  Original                    TRUE is the given security descriptor is the original one, FALSE otherwise
///                                         (used only for logging).
///
{
    SECURITY_DESCRIPTOR *secDesc = (SECURITY_DESCRIPTOR *)SecurityDescriptorBuffer;
    DWORD readSize = sizeof(SECURITY_DESCRIPTOR);
    INTSTATUS status;
    ACL *sacl;
    ACL *dacl;

    if (NULL != Process)
    {
        LOG("[ACL] Dumping %s security descriptor for process 0x%llx (%d / %s)\n",
            Original ? "OLD" : "NEW",
            Process->EprocessAddress, Process->Pid, Process->Name);
    }

    if (BufferSize < sizeof(SECURITY_DESCRIPTOR))
    {
        return;
    }

    LOG("->Revision: 0x%x\n", secDesc->Revision);
    LOG("->Sbz1: 0x%x\n", secDesc->Sbz1);
    LOG("->Control: 0x%x\n", secDesc->Control);
    LOG("->Owner: 0x%llx\n", secDesc->Owner);
    LOG("->Group: 0x%llx\n", secDesc->Group);

    status = IntWinSDFindAcls(BufferSize,
                              SecurityDescriptorBuffer,
                              &readSize,
                              &sacl,
                              &dacl);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinSDFindAcls failed: 0x%08x\n", status);
        return;
    }

    IntWinSDDumpAclEntries(dacl, FALSE, SecurityDescriptorBuffer, BufferSize);
    IntWinSDDumpAclEntries(sacl, TRUE, SecurityDescriptorBuffer, BufferSize);
}


static INTSTATUS
IntWinSDGatherAcl(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      This function gathers the 2 ACLs (SACL/DACL) and stores them in the #WIN_PROCESS_OBJECT
/// structure of the given process (the data will later be used for integrity checks and DPI).
///
/// @param[in, out]  Process       The process to gather the ACLs for.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If the SecurityDescriptor GVA is NULL.
///
{
    INTSTATUS status;
    DWORD totalSize = 0;
    ACL *sacl = NULL;
    ACL *dacl = NULL;
    static BYTE securityDescriptorBuffer[INTRO_SECURITY_DESCRIPTOR_SIZE];

    if (0 == Process->SecurityDescriptor.SecurityDescriptorGva)
    {
        // When a new process is created, the security descriptor pointer seems to be NULL.
        // We`ll try again at the next integrity check.
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    memset(securityDescriptorBuffer, 0, INTRO_SECURITY_DESCRIPTOR_SIZE);

    status = IntWinSDReadSecDesc(Process->SecurityDescriptor.SecurityDescriptorGva,
                                 INTRO_SECURITY_DESCRIPTOR_SIZE,
                                 securityDescriptorBuffer,
                                 &totalSize,
                                 &sacl,
                                 &dacl);
    if (INT_STATUS_PAGE_NOT_PRESENT == status || INT_STATUS_NO_MAPPING_STRUCTURES == status)
    {
        return status;
    }
    else if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntWinSDReadSecDesc failed for process 0x%llx (%d / %s) with status : 0x%08x\n",
                Process->EprocessAddress, Process->Pid, Process->Name, status);

        return status;
    }

    TRACE("[ACL] SACL/DACL for process 0x%llx (%d / %s) have been found: SD:0x%llx SACL AclSize:0x%x, AceCount:0x%x "
          "AclRevision:0x%x - DACL AclSize:0x%x, AceCount:0x%x, AclRevision:0x%x - Total size 0x%x\n",
          Process->EprocessAddress, Process->Pid, Process->Name,
          Process->SecurityDescriptor.SecurityDescriptorGva,
          sacl->AclSize, sacl->AceCount, sacl->AclRevision,
          dacl->AclSize, dacl->AceCount, dacl->AclRevision, totalSize);

    Process->SecurityDescriptor.RawBufferSize = totalSize;
    memcpy(&Process->SecurityDescriptor.RawBuffer[0], securityDescriptorBuffer, totalSize);
    memcpy(&Process->SecurityDescriptor.Sacl, sacl, sizeof(ACL));
    memcpy(&Process->SecurityDescriptor.Dacl, dacl, sizeof(ACL));

    return status;
}


static INTSTATUS
IntWinSDFetchSecDescAddress(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Out_ QWORD *SecurityDescriptorAddressGva
    )
///
/// @brief      This function reads the security descriptor address for the given process using the GPA cache.
///
/// @param[in]  Process                             The process to read the security descriptor for.
/// @param[in]  SecurityDescriptorAddressGva        The security descriptor GVA.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_PAGE_NOT_PRESENT        If the GVA is not mapped/present using guest PTEs.
///
{
    INTSTATUS status;
    VA_TRANSLATION tr = { 0 };

    *SecurityDescriptorAddressGva = 0;

    // The security descriptor address is the last element of the OBJECT_HEADER structure that is always located just
    // before the start of the start of the _EPROCESS.
    status = IntTranslateVirtualAddressEx(Process->EprocessAddress - gGuest.WordSize,
                                          gGuest.Mm.SystemCr3,
                                          TRFLG_PG_MODE,
                                          &tr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed: 0x%08x\n", status);
        return status;
    }

    if (0 == (tr.Flags & PT_P))
    {
        return INT_STATUS_PAGE_NOT_PRESENT;
    }

    status = IntGpaCacheFetchAndAdd(gGuest.GpaCache,
                                    tr.PhysicalAddress,
                                    gGuest.WordSize,
                                    (PBYTE)SecurityDescriptorAddressGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGpaCacheFetchAndAdd failed: 0x%08x\n", status);
        return status;
    }

    *SecurityDescriptorAddressGva = EX_FAST_REF_TO_PTR(gGuest.Guest64, *SecurityDescriptorAddressGva);

    return status;
}


INTSTATUS
IntWinSDProtectSecDesc(
    _Inout_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      This function saves the security descriptor address and ACLs into the #WIN_PROCESS_OBJECT structure.
///
/// @param[in]  Process     The process to save the security descriptor for.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1     If the given Process is NULL.
///
{
    INTSTATUS status;
    QWORD securityDescriptor = 0;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntWinSDFetchSecDescAddress(Process, &securityDescriptor);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinSDFetchSecDescAddress failed: 0x%08x\n", status);
        return status;
    }

    Process->SecurityDescriptor.SecurityDescriptorGva = securityDescriptor;

    status = IntWinSDGatherAcl(Process);
    if (!INT_SUCCESS(status))
    {
        // Sometimes we might have an invalid security descriptor pointer - try again next time on integrity.
        Process->SecurityDescriptor.SecurityDescriptorGva = 0;

        WARNING("[WARNING] IntWinSDGatherAcl failed: 0x%08x\n", status);
    }

    return status;
}


static INTSTATUS
IntWinSDFetchSecDescValues(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Out_ QWORD *OldValue,
    _Out_ QWORD *NewValue
    )
///
/// @brief      This function obtains the original security descriptor value (from the #WIN_PROCESS_OBJECT structure)
/// and the current value (by reading the guest memory using GPA cache).
///
/// @param[in]      Process     The process to query the information for.
/// @param[out]     OldValue    The original security descriptor value.
/// @param[out]     NewValue    The current security descriptor value.
///
/// @retval     #INT_STATUS_SUCCESS             On success.
/// @retval     #INT_STATUS_PAGE_NOT_PRESENT    If the GVA is not mapped/present using guest PTEs.
///
{
    INTSTATUS status;
    QWORD newValue = 0;

    status = IntWinSDFetchSecDescAddress(Process, &newValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinSDFetchSecDescAddress failed: 0x%08x\n", status);
        return status;
    }

    *OldValue = Process->SecurityDescriptor.SecurityDescriptorGva;
    *NewValue = newValue;

    return INT_STATUS_SUCCESS;
}


_Success_(return == TRUE)
BOOLEAN
IntWinSDIsSecDescPtrAltered(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Inout_opt_ WIN_PROCESS_OBJECT **VictimProcess,
    _Out_opt_ QWORD *OldValue,
    _Out_opt_ QWORD *NewValue
    )
///
/// @brief      This function checks if the security descriptor pointer of a process has been altered or not.
///
/// @param[in]      Process         The process to query the information for.
/// @param[out]     VictimProcess   The process where the security descriptor has been stolen from (it can be NULL
///                                 if the security descriptor was not altered or it was altered but the source is not
///                                 the security descriptor of a known process).
/// 
/// @param[out]     OldValue        The original security descriptor value.
/// @param[out]     NewValue        The current security descriptor value.
///
/// @retval     #TRUE   The security descriptor has been altered.
/// @retval     #FALSE  The security descriptor has NOT been altered.
///
{
    INTSTATUS status;
    WIN_PROCESS_OBJECT *victimProcess = NULL;
    QWORD oldValue = 0;
    QWORD newValue = 0;

    if (NULL == Process)
    {
        ERROR("[ERROR] Process is NULL\n");
        return FALSE;
    }

    status = IntWinSDFetchSecDescValues(Process, &oldValue, &newValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinSDFetchSecDescAddress failed: 0x%08x\n", status);
        return FALSE;
    }

    if (OldValue)
    {
        *OldValue = oldValue;
    }

    if (NewValue)
    {
        *NewValue = newValue;
    }

    if (0 == oldValue && 0 != newValue)
    {
        // When a new process is created, the security descriptor pointer seems to be NULL.
        Process->SecurityDescriptor.SecurityDescriptorGva = newValue;
        status = IntWinSDGatherAcl(Process);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinSDGatherAcl failed: 0x%08x\n", status);
        }

        return FALSE;
    }

    if (oldValue == newValue)
    {
        return FALSE;
    }

    list_for_each(gWinProcesses, WIN_PROCESS_OBJECT, pProcess)
    {
        if (pProcess->SecurityDescriptor.SecurityDescriptorGva == newValue &&
            pProcess->EprocessAddress != Process->EprocessAddress)
        {
            victimProcess = pProcess;
        }
    }

    if (VictimProcess)
    {
        *VictimProcess = victimProcess;
    }

    return TRUE;
}


_Success_(return == TRUE)
BOOLEAN
IntWinSDIsAclEdited(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ DWORD BufferSize,
    _Out_writes_bytes_(BufferSize) BYTE *SecurityDescriptorBuffer,
    _Out_ DWORD *ReadSize,
    _Out_ ACL **NewSacl,
    _Out_ ACL **NewDacl
    )
///
/// @brief      This function reads the ACLs for the given process (returning the data using the provided buffer
/// and the Sacl/Dacl pointers) and then compares the read data with the one stored within the
/// #WIN_PROCESS_OBJECT structure.
///
/// @param[in]  Process                     The process the check the ACLs integrity for.
/// @param[in]  BufferSize                  The size in bytes of the given buffer (SecurityDescriptorBuffer).
/// @param[out] SecurityDescriptorBuffer    The buffer where the ACLs (along with the ACEs) will be stored.
/// @param[out] ReadSize                    The size in bytes of the returned security descriptor.
/// @param[out] NewSacl                     The current SACL header.
/// @param[out] NewDacl                     The current DACL header.
///
/// @retval     #TRUE                       If the ACLs have been modified.
/// @retval     #FALSE                      If the ACLs have NOT been modified.
///
{
    INTSTATUS status;
    ACL *sacl = NULL;
    ACL *dacl = NULL;
    BOOLEAN securityDescriptorAltered = FALSE;
    BOOLEAN updateSecurityDescriptorInfo = FALSE;

    if (NULL == Process || 0 == Process->SecurityDescriptor.SecurityDescriptorGva || 0 == BufferSize ||
        NULL == SecurityDescriptorBuffer || NULL == ReadSize || NULL == NewSacl || NULL == NewDacl)
    {
        goto cleanup_and_exit;
    }

    *NewDacl = NULL;
    *NewSacl = NULL;

    status = IntWinSDReadSecDesc(Process->SecurityDescriptor.SecurityDescriptorGva,
                                 BufferSize,
                                 SecurityDescriptorBuffer,
                                 ReadSize,
                                 &sacl,
                                 &dacl);
    if (INT_STATUS_PAGE_NOT_PRESENT == status || INT_STATUS_NO_MAPPING_STRUCTURES == status)
    {
        goto cleanup_and_exit;
    }
    else if (!INT_SUCCESS(status) && INT_STATUS_DATA_BUFFER_TOO_SMALL != status)
    {
        WARNING("[WARNING] IntWinSDReadSecDesc failed for process 0x%llx (%d / %s): 0x%08x\n",
                Process->EprocessAddress, Process->Pid, Process->Name, status);

        goto cleanup_and_exit;
    }

    // If an attacker modifies the AceSize we may end up failing the read function and thus, allowing the modification.
    if (NULL != sacl)
    {
        *NewSacl = sacl;

        if (0 != sacl->AclSize && 0 == Process->SecurityDescriptor.Sacl.AclSize)
        {
            // Some processes start with an incomplete SACL (taskhost.exe, etc.) - we allow the modification.
            updateSecurityDescriptorInfo = TRUE;
            goto cleanup_and_exit;
        }

        if (sacl->AclSize != Process->SecurityDescriptor.Sacl.AclSize)
        {
            securityDescriptorAltered = TRUE;
            goto cleanup_and_exit;
        }
    }

    if (NULL != dacl)
    {
        *NewDacl = dacl;

        if (0 != dacl->AclSize && 0 == Process->SecurityDescriptor.Dacl.AclSize)
        {
            // Some processes start with an incomplete DACL (msmpeng.exe, etc.) - we allow the modification.
            updateSecurityDescriptorInfo = TRUE;
            goto cleanup_and_exit;
        }

        if (dacl->AclSize != Process->SecurityDescriptor.Dacl.AclSize)
        {
            securityDescriptorAltered = TRUE;
            goto cleanup_and_exit;
        }
    }

    if (*ReadSize != Process->SecurityDescriptor.RawBufferSize)
    {
        securityDescriptorAltered = TRUE;
        goto cleanup_and_exit;
    }

    if (memcmp_len(SecurityDescriptorBuffer,
                   Process->SecurityDescriptor.RawBuffer,
                   *ReadSize,
                   Process->SecurityDescriptor.RawBufferSize))
    {
        securityDescriptorAltered = TRUE;
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (updateSecurityDescriptorInfo)
    {
        Process->SecurityDescriptor.RawBufferSize = *ReadSize;

        memcpy(&Process->SecurityDescriptor.RawBuffer[0], SecurityDescriptorBuffer, *ReadSize);

        if (sacl)
        {
            memcpy(&Process->SecurityDescriptor.Sacl, sacl, sizeof(ACL));
        }

        if (dacl)
        {
            memcpy(&Process->SecurityDescriptor.Dacl, dacl, sizeof(ACL));
        }
    }

    return securityDescriptorAltered;
}


static INTSTATUS
IntWinSDSendSecDescIntViolation(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_opt_ WIN_PROCESS_OBJECT *Victim,
    _In_ QWORD OldValue,
    _In_ QWORD NewValue,
    _In_ BYTE *SecDescBuffer,
    _In_ DWORD SecDescSize,
    _In_ DWORD SecDescHash,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      This function sends an integrity violation caused by a modified security descriptor pointer.
///
/// @param[in]  Process         The process that was found to have a different security descriptor.
/// @param[in]  Victim          The process from where the security descriptor pointer was stolen from (it can be NULL).
/// @param[in]  OldValue        The old value of the security descriptor.
/// @param[in]  NewValue        The new value of the security descriptor.
/// @param[in]  SecDescBuffer   The new security descriptor buffer.
/// @param[in]  SecDescSize     The new security descriptor buffer size.
/// @param[in]  SecDescHash     The new security descriptor hash (computer after IntWinSDProcessAcl). 
/// @param[in]  Action          The taken action (#INTRO_ACTION).
/// @param[in]  Reason          The reason for the taken action (#INTRO_ACTION_REASON).
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    EVENT_INTEGRITY_VIOLATION *pIntViolation;
    INTSTATUS status;

    pIntViolation = &gAlert.Integrity;
    memzero(pIntViolation, sizeof(*pIntViolation));

    pIntViolation->Header.Action = Action;
    pIntViolation->Header.Reason = Reason;
    pIntViolation->Header.MitreID = idAccessToken;

    pIntViolation->Header.CpuContext.Valid = FALSE;
    pIntViolation->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_SD_ACL, Reason);

    IntAlertFillWinProcess(Process, &pIntViolation->Header.CurrentProcess);
    IntAlertFillWinProcess(Process, &pIntViolation->Victim.Process);
    if (Victim)
    {
        // In this case we have 2 "Victims".
        IntAlertFillWinProcess(Victim, &pIntViolation->Originator.Process);
    }

    pIntViolation->Victim.Type = introObjectTypeSecDesc;
    memcpy(pIntViolation->Victim.Name, VICTIM_PROCESS_SECURITY_DESCRIPTOR, sizeof(VICTIM_PROCESS_SECURITY_DESCRIPTOR));

    pIntViolation->Size = SecDescSize;
    pIntViolation->BaseAddress = Process->SecurityDescriptor.SecurityDescriptorGva;
    pIntViolation->VirtualAddress = Process->SecurityDescriptor.SecurityDescriptorGva;

    pIntViolation->SecDescWriteInfo.OldAddress = OldValue;
    pIntViolation->SecDescWriteInfo.NewAddress = NewValue;

    pIntViolation->SecDescWriteInfo.NewSecDescHash = SecDescHash;

    memcpy(&pIntViolation->SecDescWriteInfo.OldSecDesc[0], Process->SecurityDescriptor.RawBuffer,
           MIN(sizeof(pIntViolation->SecDescWriteInfo.OldSecDesc), Process->SecurityDescriptor.RawBufferSize));

    pIntViolation->SecDescWriteInfo.OldSecDescSize = Process->SecurityDescriptor.RawBufferSize;

    memcpy(&pIntViolation->SecDescWriteInfo.NewSecDesc[0], SecDescBuffer,
           MIN(sizeof(pIntViolation->SecDescWriteInfo.NewSecDesc), SecDescSize));

    pIntViolation->SecDescWriteInfo.NewSecDescSize = SecDescSize;
    
    IntAlertFillVersionInfo(&pIntViolation->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViolation, sizeof(*pIntViolation));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinSDSendAclIntegrityViolation(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ BYTE *SecDescBuffer,
    _In_ DWORD SecDescSize,
    _In_ DWORD SecDescHash,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief      This function sends an integrity violation caused by a modified ACL (SACL/DACL).
///
/// @param[in]  Process             The process that was found to have a modified security descriptor.
/// @param[in]  SecDescBuffer       The new security descriptor buffer.
/// @param[in]  SecDescSize         The new security descriptor buffer size.
/// @param[in]  SecDescHash     The new security descriptor hash (computer after IntWinSDProcessAcl). 
/// @param[in]  Action              The taken action (#INTRO_ACTION).
/// @param[in]  Reason              The reason for the taken action (#INTRO_ACTION_REASON).
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    EVENT_INTEGRITY_VIOLATION *pIntViolation;
    INTSTATUS status;

    pIntViolation = &gAlert.Integrity;
    memzero(pIntViolation, sizeof(*pIntViolation));

    pIntViolation->Header.Action = Action;
    pIntViolation->Header.Reason = Reason;
    pIntViolation->Header.MitreID = idAccessToken;

    pIntViolation->Header.CpuContext.Valid = FALSE;
    pIntViolation->Header.Flags = IntAlertCoreGetFlags(INTRO_OPT_PROT_KM_SD_ACL, Reason);

    IntAlertFillWinProcess(Process, &pIntViolation->Header.CurrentProcess);
    IntAlertFillWinProcess(Process, &pIntViolation->Victim.Process);

    pIntViolation->Victim.Type = introObjectTypeAcl;
    memcpy(pIntViolation->Victim.Name, VICTIM_PROCESS_ACL, sizeof(VICTIM_PROCESS_ACL));

    pIntViolation->Size = SecDescSize;
    pIntViolation->BaseAddress = Process->SecurityDescriptor.SecurityDescriptorGva;
    pIntViolation->VirtualAddress = Process->SecurityDescriptor.SecurityDescriptorGva;

    // The address has not been changed in this case.
    pIntViolation->SecDescWriteInfo.OldAddress = Process->SecurityDescriptor.SecurityDescriptorGva;
    pIntViolation->SecDescWriteInfo.NewAddress = Process->SecurityDescriptor.SecurityDescriptorGva;

    pIntViolation->SecDescWriteInfo.NewSecDescHash = SecDescHash;

    memcpy(&pIntViolation->SecDescWriteInfo.OldSecDesc[0], Process->SecurityDescriptor.RawBuffer,
           MIN(sizeof(pIntViolation->SecDescWriteInfo.OldSecDesc), Process->SecurityDescriptor.RawBufferSize));

    pIntViolation->SecDescWriteInfo.OldSecDescSize = Process->SecurityDescriptor.RawBufferSize;

    memcpy(&pIntViolation->SecDescWriteInfo.NewSecDesc[0], SecDescBuffer,
           MIN(sizeof(pIntViolation->SecDescWriteInfo.NewSecDesc), SecDescSize));

    pIntViolation->SecDescWriteInfo.NewSecDescSize = SecDescSize;

    IntAlertFillVersionInfo(&pIntViolation->Header);

    IntAlertFillVersionInfo(&pIntViolation->Header);

    status = IntNotifyIntroEvent(introEventIntegrityViolation, pIntViolation, sizeof(*pIntViolation));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static void
IntWinSDClearAclEnd(
    _Inout_ ACL *Acl,
    _In_ WORD CalculatedSize
    )
///
/// @brief      This function clears the last bytes of the ACL in case the ACL size is greater than the sum of its ACEs.
///
/// @param[in, out] Acl             The access control entry to be cleared (SACL/DACL).
/// @param[in]      CalculatedSize  The calculated size of the ACEs contained within the ACL.
///
{
    BYTE *aclEnd;
    WORD sizeToClear;

    aclEnd = (BYTE *)((QWORD)Acl + CalculatedSize);
    sizeToClear = Acl->AclSize - CalculatedSize;

    if (Acl->AclSize <= CalculatedSize ||
        (QWORD)aclEnd + sizeToClear > (QWORD)Acl + Acl->AclSize)
    {
        return;
    }

    memset(aclEnd, 0, sizeToClear);
}


static void
IntWinSDProcessAcl(
    _Inout_ ACL *Acl
    )
///
/// @brief      This function clears the SIDs that have more than one sub authority for a given ACL.
///
/// @param[in, out]  Acl     The access control entry to be processed (SACL/DACL).
///
{
    // We have 2 types of SIDs: "well-known" and "custom".
    //
    // 1) "well-known" SIDs https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
    //     Example: SID: S-1-5-19 	NT Authority	Local Service
    //     Only one sub-authority (19).
    //
    // 2) "custom" SIDs
    //     Example: SID: S-1-15-3-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194
    //     8 sub-authorities (3, 3624051433, 2125758914, etc.).
    //
    // Our problem is that the "custom" ACEs are allocated dynamically (each time the security descriptor pointer is
    // being replaced, at least one or two bytes are different in "custom" SIDs which means we can`t use a hash to sign
    // these changes). One relatively easy fix is to clear the SID if it exceeds a threshold (#INT_STD_ACE_MAX_SIZE)
    // before sending the buffer to the exception mechanism. Please note that we are not going to clear the #ACE_HEADER.

    ACE_HEADER *ace = (ACE_HEADER *)((QWORD)Acl + sizeof(ACL));
    WORD totalSize = sizeof(ACL);

    if (__unlikely(Acl->AceCount > INT_MAX_ACE_COUNT))
    {
        WARNING("[WARNING] The maximum number of ACEs has been exceeded:0x%x\n", Acl->AceCount);
        return;
    }

    for (DWORD i = 0; i < Acl->AceCount; i++)
    {
        if (!IntWinSDIsAceInsideAcl(Acl, ace))
        {
            return;
        }

        if (ace->AceSize > INT_STD_ACE_MAX_SIZE)
        {
            BYTE *aceContents = (BYTE *)((QWORD)ace + sizeof(ACE_HEADER));
            memset(aceContents, 0, ace->AceSize - sizeof(ACE_HEADER));
        }

        totalSize += ace->AceSize;

        ace = (ACE_HEADER *)((QWORD)ace + ace->AceSize);
    }

    if (Acl->AclSize != totalSize)
    {
        IntWinSDClearAclEnd(Acl, totalSize);
    }
}


static INTSTATUS
IntWinSDCheckSecDescIntegrity(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      This function checks the integrity of the security descriptor for the given process. In case the
/// security descriptor pointer has been altered, the VCPUs will be paused in order to restore the original value,
/// the victim process will be found (in case there is one) and an alert will be sent.
///
/// @param[in]  Process     The process to be saved.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_SKIP_OTHER_CALLBACKS    If the security descriptor has been patched and there is no need
///                                                 for the ACL checks.
///
{
    static BYTE securityDescriptorBuffer[INTRO_SECURITY_DESCRIPTOR_SIZE];
    INTSTATUS status;
    QWORD newValue = 0;
    QWORD oldValue = 0;
    DWORD processedSecDescHash = 0;
    WIN_PROCESS_OBJECT *victimProcess = NULL;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION action;
    INTRO_ACTION_REASON reason;
    DWORD totalSize = 0;
    ACL *newSacl = NULL;
    ACL *newDacl = NULL;

    if (NULL == Process)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!IntWinSDIsSecDescPtrAltered(Process, &victimProcess, &oldValue, &newValue))
    {
        return INT_STATUS_SUCCESS;
    }

    memset(securityDescriptorBuffer, 0, INTRO_SECURITY_DESCRIPTOR_SIZE);

    // From: https://www.matteomalvica.com/blog/2019/07/06/windows-kernel-shellcode/
    // The original paper from Cesar Cerrudo from 2012 shows how we can find the SecurityDescriptor of a privileged
    // process and override it with NULL.If a process has not SecurityDescriptor, the kernel assumes that has been
    // created with a NULL DACL which means that everyone(every other process) can access it.However, Microsoft has
    // introduced a patch on Windows10 1607 Redstone 1, where it now maps a table of pointers to object structures,
    // and if a pointer to the SecurityDescriptor is set to NULL, it will trigger a Blue Screen Of Death(BSOD).
    if (0 == newValue)
    {
        goto check_exceptions;
    }

    status = IntWinSDReadSecDesc(newValue,
                                 INTRO_SECURITY_DESCRIPTOR_SIZE,
                                 securityDescriptorBuffer,
                                 &totalSize,
                                 &newSacl,
                                 &newDacl);
    if (INT_STATUS_PAGE_NOT_PRESENT == status || INT_STATUS_NO_MAPPING_STRUCTURES == status)
    {
        return INT_STATUS_SUCCESS;
    }
    else if (!INT_SUCCESS(status) && INT_STATUS_DATA_BUFFER_TOO_SMALL != status)
    {
        WARNING("[WARNING] IntWinSDReadSecDesc failed for process 0x%llx (%d / %s): 0x%08x\n",
                Process->EprocessAddress, Process->Pid, Process->Name, status);

        return INT_STATUS_SUCCESS;
    }

    // There are some cases in which the security descriptor pointer is being swapped but the contents are not
    // initialized yet.
    if (NULL == newSacl || NULL == newDacl)
    {
        Process->SecurityDescriptor.SecurityDescriptorGva = newValue;
        status = IntWinSDGatherAcl(Process);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinSDGatherAcl failed: 0x%08x\n", status);
        }

        return INT_STATUS_SKIP_OTHER_CALLBACKS;
    }

    if (newSacl)
    {
        IntWinSDProcessAcl(newSacl);
    }

    if (newDacl)
    {
        IntWinSDProcessAcl(newDacl);
    }

check_exceptions:
    // The originator is only dummy. Complete just the elements so that we can go through exceptions.
    originator.Original.NameHash = INITIAL_CRC_VALUE;
    originator.Return.NameHash = INITIAL_CRC_VALUE;
    
    // Since we don't have an INTEGRITY_REGION associated, we'll complete the victim in-place.
    victim.Object.Process = Process;
    victim.Object.NameHash = Process->NameHash;
    victim.Object.Type = introObjectTypeSecDesc;
    victim.ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;
    victim.ZoneType = exceptionZoneIntegrity;

    // We are going to provide the new security descriptor buffer pointer to the exception mechanism (a hash will be
    // generated and used to check the available signatures).
    victim.Integrity.Buffer = securityDescriptorBuffer;
    victim.Integrity.BufferSize = totalSize;

    processedSecDescHash = Crc32Compute(securityDescriptorBuffer, totalSize, INITIAL_CRC_VALUE);

    memcpy(&victim.WriteInfo.OldValue[0], &Process->SecurityDescriptor.Sacl, sizeof(ACL));
    if (newSacl)
    {
        memcpy(&victim.WriteInfo.NewValue[0], newSacl, sizeof(ACL));
    }

    memcpy(&victim.WriteInfo.OldValue[1], &Process->SecurityDescriptor.Dacl, sizeof(ACL));
    if (newDacl)
    {
        memcpy(&victim.WriteInfo.NewValue[1], newDacl, sizeof(ACL));
    }

    victim.WriteInfo.OldValue[2] = oldValue;
    victim.WriteInfo.NewValue[2] = newValue;

    IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

    if (introGuestNotAllowed == action || introReasonAllowedFeedback == reason)
    {
        // Read the security descriptor again because we used IntWinSDProcessAcl before IntExcept to
        // clear "specific" SIDs.
        status = IntWinSDReadSecDesc(newValue,
                                     INTRO_SECURITY_DESCRIPTOR_SIZE,
                                     securityDescriptorBuffer,
                                     &totalSize,
                                     &newSacl,
                                     &newDacl);
        if (INT_SUCCESS(status))
        {
            IntWinSDDumpSecDesc(Process,
                                Process->SecurityDescriptor.RawBuffer,
                                Process->SecurityDescriptor.RawBufferSize,
                                TRUE);

            IntWinSDDumpSecDesc(Process, securityDescriptorBuffer, totalSize, FALSE);

            status = IntWinSDSendSecDescIntViolation(Process, victimProcess, oldValue, newValue,
                                                     securityDescriptorBuffer, totalSize, processedSecDescHash,
                                                     action, reason);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinSDSendSecDescIntViolation failed: 0x%08x\n", status);
            }
        }
    }

    if (introGuestNotAllowed != action)
    {
        Process->SecurityDescriptor.SecurityDescriptorGva = newValue;
        status = IntWinSDGatherAcl(Process);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinSDGatherAcl failed: 0x%08x\n", status);
        }
    }
    else
    {
        IntPauseVcpus();

        // The security descriptor address is the last element of the OBJECT_HEADER structure that is always located
        // just before the start of the start of the _EPROCESS.
        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                     Process->EprocessAddress - gGuest.WordSize,
                                     gGuest.WordSize,
                                     &oldValue,
                                     0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinSDCheckAclIntegrity(
    _In_ WIN_PROCESS_OBJECT *Process
    )
///
/// @brief      This function checks the integrity of the ACLs (SACL/DACL) for the given process. In case the
/// ACLs have been altered, the VCPUs will be paused in order to restore the original value and an alert will be sent.
///
/// @param[in]  Process     The process to be saved.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_INITIALIZED_HINT    If the SecurityDescriptor GVA is NULL.
///
{
    INTSTATUS status;
    ACL *newSacl = NULL;
    ACL *newDacl = NULL;
    DWORD processedSecDescHash = 0;
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    INTRO_ACTION action = introGuestNotAllowed;
    INTRO_ACTION_REASON reason = introReasonNoException;
    INTRO_ACTION bestAction = introGuestNotAllowed;
    INTRO_ACTION_REASON bestReason = introReasonNoException;
    DWORD totalSize = 0;
    static BYTE securityDescriptorBuffer[INTRO_SECURITY_DESCRIPTOR_SIZE];

    if (0 == Process->SecurityDescriptor.SecurityDescriptorGva)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    memset(securityDescriptorBuffer, 0, INTRO_SECURITY_DESCRIPTOR_SIZE);

    if (!IntWinSDIsAclEdited(Process, INTRO_SECURITY_DESCRIPTOR_SIZE, securityDescriptorBuffer,
                             &totalSize, &newSacl, &newDacl))
    {
        return INT_STATUS_SUCCESS;
    }

    // There are some cases in which the security descriptor pointer is being swapped but the contents are not
    // initialized yet.
    if (NULL == newSacl || NULL == newDacl)
    {
        LOG("[WARNING] SACL or DACL is NULL for process process 0x%llx (%d / %s)\n",
            Process->EprocessAddress, Process->Pid, Process->Name);

        return INT_STATUS_SUCCESS;
    }

    if (newSacl)
    {
        IntWinSDProcessAcl(newSacl);
    }

    if (newDacl)
    {
        IntWinSDProcessAcl(newDacl);
    }

    // The originator is only dummy. Complete just the elements so that we can go through exceptions.
    originator.Original.NameHash = INITIAL_CRC_VALUE;
    originator.Return.NameHash = INITIAL_CRC_VALUE;

    // Since we don't have an INTEGRITY_REGION associated, we'll complete the victim in-place.
    victim.Object.Type = introObjectTypeAcl;
    victim.ZoneFlags |= ZONE_WRITE | ZONE_INTEGRITY;
    victim.ZoneType = exceptionZoneIntegrity;

    // We are going to provide the new security descriptor buffer pointer to the exception mechanism (a hash will be
    // generated and used to check the available signatures).
    victim.Integrity.Buffer = securityDescriptorBuffer;
    victim.Integrity.BufferSize = totalSize;

    processedSecDescHash = Crc32Compute(securityDescriptorBuffer, totalSize, INITIAL_CRC_VALUE);

    memcpy(&victim.WriteInfo.OldValue[0], &Process->SecurityDescriptor.Sacl, sizeof(ACL));
    if (newSacl)
    {
        memcpy(&victim.WriteInfo.NewValue[0], newSacl, sizeof(ACL));
    }

    memcpy(&victim.WriteInfo.OldValue[1], &Process->SecurityDescriptor.Dacl, sizeof(ACL));
    if (newDacl)
    {
        memcpy(&victim.WriteInfo.NewValue[1], newDacl, sizeof(ACL));
    }

    // There are some cases in which multiple processes share the same Security Descriptor pointer, so depending upon
    // the order in which they are stored within our #gWinProcesses, we may find an exception only after iterating the
    // entire process list.
    list_for_each(gWinProcesses, WIN_PROCESS_OBJECT, pProcess)
    {
        if (pProcess->SecurityDescriptor.SecurityDescriptorGva == Process->SecurityDescriptor.SecurityDescriptorGva)
        {
            victim.Object.Process = pProcess;
            victim.Object.NameHash = pProcess->NameHash;

            IntExcept(&victim, &originator, exceptionTypeKm, &action, &reason, introEventIntegrityViolation);

            if (introGuestAllowed == action)
            {
                bestAction = action;
                bestReason = reason;
            }

            if (introReasonAllowed == reason)
            {
                goto found_exception;
            }
        }
    }

found_exception:
    if (introGuestNotAllowed == bestAction || introReasonAllowedFeedback == bestReason)
    {
        // Read the security descriptor again because we used IntWinSDProcessAcl before IntExcept to
        // clear "specific" SIDs.
        status = IntWinSDReadSecDesc(Process->SecurityDescriptor.SecurityDescriptorGva,
                                     INTRO_SECURITY_DESCRIPTOR_SIZE,
                                     securityDescriptorBuffer,
                                     &totalSize,
                                     &newSacl,
                                     &newDacl);
        if (INT_SUCCESS(status))
        {
            IntWinSDDumpSecDesc(Process,
                                Process->SecurityDescriptor.RawBuffer,
                                Process->SecurityDescriptor.RawBufferSize,
                                TRUE);

            IntWinSDDumpSecDesc(Process, securityDescriptorBuffer, totalSize, FALSE);

            status = IntWinSDSendAclIntegrityViolation(Process, securityDescriptorBuffer, totalSize,
                                                       processedSecDescHash, bestAction, bestReason);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinSDSendAclIntegrityViolation failed: 0x%08x\n", status);
            }
        }
    }

    if (introGuestNotAllowed != bestAction)
    {
        status = IntWinSDGatherAcl(Process);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntWinSDGatherAcl failed: 0x%08x\n", status);
        }
    }
    else
    {
        IntPauseVcpus();

        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3,
                                     Process->SecurityDescriptor.SecurityDescriptorGva,
                                     Process->SecurityDescriptor.RawBufferSize,
                                     Process->SecurityDescriptor.RawBuffer,
                                     0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        }

        IntResumeVcpus();
    }

    return INT_STATUS_SUCCESS;
}


TIMER_FRIENDLY INTSTATUS
IntWinSDCheckIntegrity(
    void
    )
///
/// @brief      This function checks the integrity of the security descriptor for all the processes
/// inside #gWinProcesses.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status;

    if (!gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (!gGuest.ProtectionActivated)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if ((introGuestWindows != gGuest.OSType) || (0 == (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_SD_ACL)))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    STATS_ENTER(statsSecDesc);

    list_for_each(gWinProcesses, WIN_PROCESS_OBJECT, pProcess)
    {
        status = IntWinSDCheckSecDescIntegrity(pProcess);
        if (!INT_SUCCESS(status) &&
            INT_STATUS_PAGE_NOT_PRESENT != status && INT_STATUS_NO_MAPPING_STRUCTURES != status)
        {
            ERROR("[ERROR] IntWinSDCheckSecDescIntegrity failed for process 0x%llx (%d / %s) "
                   "status:0x%08x\n",
                  pProcess->EprocessAddress, pProcess->Pid, pProcess->Name, status);
        }

        if (INT_STATUS_SKIP_OTHER_CALLBACKS != status)
        {
            status = IntWinSDCheckAclIntegrity(pProcess);
            if (!INT_SUCCESS(status) &&
                INT_STATUS_PAGE_NOT_PRESENT != status && INT_STATUS_NO_MAPPING_STRUCTURES != status)
            {
                ERROR("[ERROR] IntWinSDCheckAclIntegrity failed for process 0x%llx (%d / %s) "
                    "status:0x%08x\n",
                    pProcess->EprocessAddress, pProcess->Pid, pProcess->Name, status);
            }
        }
    }

    STATS_EXIT(statsSecDesc);

    return INT_STATUS_SUCCESS;
}

