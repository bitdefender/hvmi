/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTROAPI_H_
#define _INTROAPI_H_

#include "glue.h"

//
// Introspection API - exposed to the HV/other 3rd party integrators.
//
INTSTATUS
IntNewGuestNotification(
    _In_ void *GuestHandle,
    _In_ QWORD Options,
    _In_reads_(BufferLength) PBYTE UpdateBuffer,
    _In_ DWORD BufferLength
    );

INTSTATUS
IntDisableIntro(
    _In_ void *GuestHandle,
    _In_ QWORD Flags
    );

INTSTATUS
IntNotifyGuestPowerStateChange(
    _In_ void *GuestHandle,
    _In_ IG_GUEST_POWER_STATE PowerState
    );

INTSTATUS
IntInjectProcessAgentInGuest(
    _In_ void *GuestHandle,
    _In_ DWORD AgentTag,
    _In_opt_ PBYTE AgentContent,
    _In_opt_ DWORD AgentSize,
    _In_z_ const CHAR *Name,
    _In_opt_ const CHAR *Args
    );

INTSTATUS
IntInjectFileAgentInGuest(
    _In_ void *GuestHandle,
    _In_ PBYTE AgentContent,
    _In_ DWORD AgentSize,
    _In_z_ const CHAR *Name
    );

INTSTATUS
IntAddRemoveProtectedProcessUtf8(
    _In_ void *GuestHandle,
    _In_z_ const CHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
    );

INTSTATUS
IntAddRemoveProtectedProcessUtf16(
    _In_ void *GuestHandle,
    _In_z_ const WCHAR *FullPath,
    _In_ DWORD ProtectionMask,
    _In_ BOOLEAN Add,
    _In_ QWORD Context
    );

INTSTATUS
IntRemoveAllProtectedProcesses(
    _In_ void *GuestHandle
    );

INTSTATUS
IntGetCurrentInstructionLength(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ BYTE *Length
    );

INTSTATUS
IntGetCurrentInstructionMnemonic(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _Out_ CHAR *Mnemonic
    );

INTSTATUS
IntIterateVaSpace(
    _In_ void *GuestHandle,
    _In_ QWORD Cr3,
    _In_ PFUNC_VirtualAddressSpaceCallback Callback
    );

INTSTATUS
IntGetGuestInfo(
    _In_ void *GuestHandle,
    _Out_ GUEST_INFO *GuestInfo
    );

INTSTATUS
IntModifyDynamicOptions(
    _In_ void *GuestHandle,
    _In_ QWORD NewOptions
    );

INTSTATUS
IntFlushGpaCache(
    _In_ void *GuestHandle
    );

INTSTATUS
IntGetCurrentIntroOptions(
    _In_  void *GuestHandle,
    _Out_ QWORD *IntroOptions
    );

INTSTATUS
IntProcessDebugCommand(
    _In_ void *GuestHandle,
    _In_ DWORD CpuNumber,
    _In_ DWORD Argc,
    _In_ CHAR *Argv[]
    );


//
// Exceptions related.
//
INTSTATUS
IntGetExceptionsVersion(
    _In_ void *GuestHandle,
    _Out_ WORD *MajorVersion,
    _Out_ WORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    );

INTSTATUS
IntUpdateExceptions(
    _In_ void *GuestHandle,
    _In_reads_bytes_(Length) PBYTE Buffer,
    _In_ DWORD Length,
    _In_ DWORD Flags
    );

INTSTATUS
IntUpdateSupport(
    _In_ void *GuestHandle,
    _In_reads_bytes_(Length) PBYTE Buffer,
    _In_ DWORD Length
    );

INTSTATUS
IntGetSupportVersion(
    _In_ void *GuestHandle,
    _Out_ DWORD *MajorVersion,
    _Out_ DWORD *MinorVersion,
    _Out_ DWORD *BuildNumber
    );


INTSTATUS
IntAddExceptionFromAlert(
    _In_ void *GuestHandle,
    _In_ const void *Event,
    _In_ INTRO_EVENT_TYPE Type,
    _In_ BOOLEAN Exception,
    _In_ QWORD Context
    );

INTSTATUS
IntFlushAlertExceptions(
    _In_ void *GuestHandle
    );

INTSTATUS
IntRemoveException(
    _In_ void *GuestHandle,
    _In_opt_ QWORD Context
    );

INTSTATUS
IntAbortEnableIntro(
    _In_ void *GuestHandle,
    _In_ BOOLEAN Abort
    );

INTSTATUS
IntSetLogLevel(
    _In_ void *GuestHandle,
    _In_ IG_LOG_LEVEL LogLevel
    );

INTSTATUS
IntGetVersionString(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR *FullString,
    _Out_ CHAR *VersionString
    );

#endif // _INTROAPI_H_
