/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _WINSECDESC_H_
#define _WINSECDESC_H_

#include "intro_types.h"

/// @brief      The maximum size of a standard access control entry (empirically chosen value).
#define INT_STD_ACE_MAX_SIZE    0x14

 /// @brief      Converts an #ACL to an #INTRO_ACL
 ///
 /// Internally, Windows uses a structure called Access Control List (#ACL) which has some 0 padding fields.
 /// Since we want to provide the integrator with the information contained within the #ACL structure, we implemented
 /// another structure #INTRO_ACL that only has the relevant fields. This macro converts an #ACL to an #INTRO_ACL.
 ///
 /// @param[in]  Acl        The #ACL structure
 /// @param[out] IntroAcl   The #INTRO_ACL structure
#define COPY_ACL_TO_INTRO_ACL(Acl, IntroAcl) do {                                           \
                                                 IntroAcl.AclRevision = Acl.AclRevision;    \
                                                 IntroAcl.AclSize = Acl.AclSize;            \
                                                 IntroAcl.AceCount = Acl.AceCount;          \
                                             } while(0);

typedef struct _WIN_PROCESS_OBJECT WIN_PROCESS_OBJECT, *PWIN_PROCESS_OBJECT;

/// @brief  The internal representation of the SID structure.
typedef struct _SID_INTERNAL
{
    /// @brief  S-1-5-32-554 - The SID revision (in this case 1).
    UCHAR                       Revision;
    /// @brief  S-1-5-32-554 - The number of sub authorities (in this case 2 -> sub-authority 32 and sub-authority 544).
    UCHAR                       SubAuthorityCount;
    /// @brief  S-1-5-32-554 - The authority (in this case 5).
    SID_IDENTIFIER_AUTHORITY    IdentifierAuthority;
} SID_INTERNAL, *PSID_INTERNAL;

/// @brief  The internal representation of an Access Control Entry body.
typedef struct _ACE_BODY
{
    /// @brief The access mask of the given SID (https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask).
    DWORD           Mask;
    /// @brief The containing SID.
    SID_INTERNAL    Sid;
} ACE_BODY, *PACE_BODY;

INTSTATUS
IntWinSDProtectSecDesc(
    _Inout_ WIN_PROCESS_OBJECT *Process
    );

INTSTATUS
IntWinSDCheckIntegrity(
    void
    );

_Success_(return == TRUE)
BOOLEAN
IntWinSDIsSecDescPtrAltered(
    _In_ WIN_PROCESS_OBJECT *Process,
    _Inout_opt_ WIN_PROCESS_OBJECT **VictimProcess,
    _Out_opt_ QWORD *OldValue,
    _Out_opt_ QWORD *NewValue
    );

_Success_(return == TRUE)
BOOLEAN
IntWinSDIsAclEdited(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ DWORD BufferSize,
    _Out_writes_bytes_(BufferSize) BYTE *SecurityDescriptorBuffer,
    _Out_ DWORD *ReadSize,
    _Out_ ACL **NewSacl,
    _Out_ ACL **NewDacl
    );

INTSTATUS
IntWinSDReadSecDesc(
    _In_ QWORD SecurityDescriptorGva,
    _In_ DWORD BufferSize,
    _Out_writes_bytes_(BufferSize) BYTE *SecurityDescriptorBuffer,
    _Out_ DWORD *ReadSize,
    _Out_ ACL **Sacl,
    _Out_ ACL **Dacl
    );

#endif //_WINSECDESC_H_
