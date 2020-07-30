/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _GLUE_H_
#define _GLUE_H_

#include "introtypes.h"
#include "memtags.h"

#ifndef INT_COMPILER_MSVC
#include <stdlib.h>
#include <string.h>
#endif

extern DWORD gCurLogBuffer;

extern PFUNC_IntTracePrint GlueTracePrint;
extern PFUNC_IntEnterDebugger GlueEnterDebugger;

extern IG_LOG_LEVEL gLogLevel;

#ifdef INT_COMPILER_MSVC
#define INT_LOG(loglevel, fmt, ...)                             \
    do {                                                        \
        if ((loglevel) < gLogLevel) break;                      \
        GlueTracePrint(__FILE__, __LINE__, (fmt), __VA_ARGS__); \
        gCurLogBuffer = 0;                                      \
    } while (0)
#define NLOG(fmt, ...)                                  \
    do {                                                \
        GlueTracePrint(NULL, 0, (fmt), __VA_ARGS__);    \
        gCurLogBuffer = 0;                              \
    } while (0)
#else
#define INT_LOG(loglevel, fmt, ...)                                     \
    do {                                                                \
        if ((loglevel) < gLogLevel) break;                              \
        GlueTracePrint(__FILENAME__, __LINE__, (fmt), ##__VA_ARGS__);   \
        gCurLogBuffer = 0;                                              \
    } while (0)

#define NLOG(fmt, ...)                                  \
    do {                                                \
        GlueTracePrint(NULL, 0, (fmt), ##__VA_ARGS__);  \
        gCurLogBuffer = 0;                              \
    } while (0)
#endif

#ifdef INT_COMPILER_MSVC
#define TRACE(fmt, ...)                 INT_LOG(intLogLevelDebug, fmt, __VA_ARGS__)
#define INFO(fmt, ...)                  INT_LOG(intLogLevelInfo, fmt, __VA_ARGS__)
#define WARNING(fmt, ...)               INT_LOG(intLogLevelWarning, fmt, __VA_ARGS__)
#define LOG(fmt, ...)                   INT_LOG(intLogLevelError, fmt, __VA_ARGS__)
#define ERROR(fmt, ...)                 INT_LOG(intLogLevelError, fmt, __VA_ARGS__)
#define CRITICAL(fmt, ...)              INT_LOG(intLogLevelCritical, fmt, __VA_ARGS__)
#else
#define TRACE(fmt, ...)                 INT_LOG(intLogLevelDebug, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...)                  INT_LOG(intLogLevelInfo, fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)               INT_LOG(intLogLevelWarning, fmt, ##__VA_ARGS__)
#define LOG(fmt, ...)                   INT_LOG(intLogLevelError, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)                 INT_LOG(intLogLevelError, fmt, ##__VA_ARGS__)
#define CRITICAL(fmt, ...)              INT_LOG(intLogLevelCritical, fmt, ##__VA_ARGS__)
#endif

#define INVALID_EPTP_INDEX      0xFFFFFFFF

/// @brief      Indicates that #IntPhysMemMap should not use the fast memory mapping mechanism
///
/// This is always true for hypervisors that are not Napoca
#define PHYS_MAP_FLG_NO_FASTMAP     0x80000000


void
IntGlueReset(
    void
    );

__nonnull() INTSTATUS
IntGlueInit(
    _In_ GLUE_IFACE const *GlueInterface,
    _In_ UPPER_IFACE const *UpperInterface
    );

__nonnull((3)) INTSTATUS
IntQueryGuestInfo(
    _In_ DWORD InfoClass,
    _In_opt_ void *InfoParam,
    _When_(InfoClass == IG_QUERY_INFO_CLASS_SET_REGISTERS, _In_reads_bytes_(BufferLength))
    _When_(InfoClass != IG_QUERY_INFO_CLASS_SET_REGISTERS, _Out_writes_bytes_(BufferLength))
    void *Buffer,
    _In_ DWORD BufferLength
    );

__nonnull() INTSTATUS
IntGpaToHpa(
    _In_ QWORD Gpa,
    _Out_ QWORD *Hpa
    );

__must_check
__nonnull()  INTSTATUS
IntPhysMemMap(
    _In_ QWORD PhysAddress,
    _In_ DWORD Length,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) void **HostPtr
    );

__nonnull() INTSTATUS
IntPhysMemUnmap(
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    );

__nonnull() INTSTATUS
IntReserveVaSpaceWithPt(
    _Outptr_ void **FirstPageBase,
    _Out_ DWORD *PagesCount,
    _Outptr_ void **PtBase
    );

INTSTATUS
GluePauseVcpus(
    void
    );

INTSTATUS
GlueResumeVcpus(
    void
    );

__nonnull() INTSTATUS
IntEnableMsrExit(
    _In_ DWORD Msr,
    _Out_ BOOLEAN *OldValue
    );

__nonnull() INTSTATUS
IntDisableMsrExit(
    _In_ DWORD Msr,
    _Out_ BOOLEAN *OldValue
    );

__nonnull() INTSTATUS
IntRegisterMSRHandler(
    _In_ PFUNC_IntMSRViolationCallback Callback
    );

INTSTATUS
IntUnregisterMSRHandler(
    void
    );

__nonnull() INTSTATUS
IntPhysMemGetTypeFromMtrrs(
    _In_ QWORD Gpa,
    _Out_ IG_MEMTYPE *MemType
    );

INTSTATUS
IntEnableCrWriteExit(
    _In_ DWORD Cr
    );

INTSTATUS
IntDisableCrWriteExit(
    _In_ DWORD Cr
    );

__nonnull() INTSTATUS
IntRegisterCrWriteHandler(
    _In_ PFUNC_IntCrWriteCallback Callback
    );

INTSTATUS
IntUnregisterCrWriteHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterBreakpointHandler(
    _In_ PFUNC_IntBreakpointCallback Callback
    );

INTSTATUS
IntUnregisterBreakpointHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterEventInjectionHandler(
    _In_ PFUNC_IntEventInjectionCallback Callback
    );

INTSTATUS
IntUnregisterEventInjectionHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterEnginesResultCallback(
    _In_ PFUNC_IntEventEnginesResultCallback Callback
    );

INTSTATUS
IntUnregisterEnginesResultCalback(
    void
    );

__nonnull() INTSTATUS
IntGetEPTPageProtection(
    _In_ DWORD EptIndex,
    _In_ QWORD Gpa,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    );

INTSTATUS
IntSetEPTPageProtection(
    _In_ DWORD EptIndex,
    _In_ QWORD Gpa,
    _In_ BYTE Read,
    _In_ BYTE Write,
    _In_ BYTE Execute
    );

__nonnull() INTSTATUS
IntGetSPPPageProtection(
    _In_ QWORD Gpa,
    _Out_ QWORD *Spp
    );

INTSTATUS
IntSetSPPPageProtection(
    _In_ QWORD Gpa,
    _In_ QWORD Spp
    );

BOOLEAN
GlueIsSppApiAvailable(
    void
    );

__nonnull() INTSTATUS
IntRegisterEPTHandler(
    _In_ PFUNC_IntEPTViolationCallback Callback
    );

INTSTATUS
IntUnregisterEPTHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterIntroCallHandler(
    _In_ PFUNC_IntIntroCallCallback Callback
    );

INTSTATUS
IntUnregisterIntroCallHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterVmxTimerHandler(
    _In_ PFUNC_IntIntroTimerCallback Callback
    );

INTSTATUS
IntUnregisterVmxTimerHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterDtrHandler(
    _In_ PFUNC_IntIntroDescriptorTableCallback Callback
    );

INTSTATUS
IntUnregisterDtrHandler(
    void
    );

__nonnull() INTSTATUS
IntRegisterXcrWriteHandler(
    _In_ PFUNC_IntXcrWriteCallback Callback
    );

INTSTATUS
IntUnregisterXcrWriteHandler(
    void
    );

__nonnull() INTSTATUS
IntSpinLockInit(
    _Outptr_ void **SpinLock,
    _In_z_ char *Name
    );

__nonnull() INTSTATUS
IntSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) void **SpinLock
    );

_Acquires_lock_(SpinLock)
__nonnull() void
IntSpinLockAcquire(
    _In_ void *SpinLock
    );

_Releases_lock_(SpinLock)
__nonnull() void
IntSpinLockRelease(
    _In_ void *SpinLock
    );

__nonnull() INTSTATUS
IntRwSpinLockInit(
    _Outptr_ void **SpinLock,
    _In_z_ char *Name
    );

__nonnull() INTSTATUS
IntRwSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) void **SpinLock
    );

__nonnull() INTSTATUS
IntRwSpinLockAcquireShared(
    _In_ void *SpinLock
    );

__nonnull() INTSTATUS
IntRwSpinLockAcquireExclusive(
    _In_ void *SpinLock
    );

__nonnull() INTSTATUS
IntRwSpinLockReleaseShared(
    _In_ void *SpinLock
    );

__nonnull() INTSTATUS
IntRwSpinLockReleaseExclusive(
    _In_ void *SpinLock
    );

__noreturn void
IntBugCheck(
    void
    );

INTSTATUS
IntNotifyIntroActive(
    void
    );

INTSTATUS
IntNotifyIntroInactive(
    void
    );

INTSTATUS
IntNotifyIntroDetectedOs(
    _In_ INTRO_GUEST_TYPE OsType,
    _In_ DWORD OsVersion,
    _In_ BOOLEAN Is64
    );

INTSTATUS
IntNotifyIntroErrorState(
    _In_ INTRO_ERROR_STATE State,
    _In_opt_ INTRO_ERROR_CONTEXT *Context
    );

__nonnull() INTSTATUS
IntNotifyEngines(
    _Inout_ void *Parameters
    );

__nonnull() INTSTATUS
IntSetIntroEmulatorContext(
    _In_ DWORD CpuNumber,
    _In_ QWORD VirtualAddress,
    _In_ DWORD BufferSize,
    _In_reads_bytes_(BufferSize) BYTE *Buffer
    );

INTSTATUS
IntInjectTrap(
    _In_ DWORD CpuNumber,
    _In_ BYTE TrapNumber,
    _In_ DWORD ErrorCode,
    _In_opt_ QWORD Cr2
    );

__nonnull() INTSTATUS
IntNotifyIntroEvent(
    _In_ INTRO_EVENT_TYPE EventClass,
    _In_ void *Param,
    _In_ size_t EventSize
    );

__nonnull() INTSTATUS
IntGetAgentContent(
    _In_ DWORD AgentTag,
    _In_ BOOLEAN Is64,
    _Out_ DWORD *Size,
    _Outptr_ BYTE **Content
    );

__nonnull() INTSTATUS
IntReleaseBuffer(
    _In_ void *Buffer,
    _In_ DWORD Size
    );

INTSTATUS
IntToggleRepOptimization(
    _In_ BOOLEAN Enable
    );

__nonnull() INTSTATUS
IntQueryHeapSize(
    _Out_ size_t *TotalHeapSize,
    _Out_ size_t *FreeHeapSize
    );

__nonnull() INTSTATUS
IntSendMessage(
    _In_ char const *Message
    );

INTSTATUS
IntSetVEInfoPage(
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoGpa
    );

__nonnull() INTSTATUS
IntCreateEPT(
    _Out_ DWORD *EptIndex
    );

INTSTATUS
IntDestroyEPT(
    _In_ DWORD EptIndex
    );

INTSTATUS
IntSwitchEPT(
    _In_ DWORD NewEptIndex
    );

__nonnull() INTSTATUS
IntGetEPTPageConvertible(
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BOOLEAN *Convertible
    );

INTSTATUS
IntSetEPTPageConvertible(
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _In_ BOOLEAN Convertible
    );

INTSTATUS
IntFlushEPTPermissions(
    void
    );

BOOLEAN
GlueIsVeApiAvailable(
    void
    );

BOOLEAN
GlueIsScanEnginesApiAvailable(
    void
    );

#ifdef INT_COMPILER_MSVC

__attribute__((malloc))
__attribute__ ((alloc_size (1)))
__must_check
void *
IntAllocWithTag(
    _In_ size_t Length,
    _In_ DWORD Tag,
    _In_ const char *FileName,
    _In_ DWORD FileLine
    );

INTSTATUS
IntFreeWithTag(
    _In_ void *Address,
    _In_ DWORD Tag
    );

#endif // INT_COMPILER_MSVC

#ifndef DEBUG_MEM_ALLOCS

# ifdef INT_COMPILER_MSVC
#  define HpAllocWithTag(Len, Tag)            IntAllocWithTag((Len), (Tag), __FILENAME__, __LINE__)
#  define HpFreeAndNullWithTag(Add, Tag)        \
    do {                                        \
        IntFreeWithTag(*(Add), (Tag));          \
        *(Add) = NULL;                          \
    } while (0)
# else
#  define HpAllocWithTag(Len, Tag)            (int)(Len) <= 0 ? NULL : calloc(1, (Len))
#  define HpFreeAndNullWithTag(Add, Tag)        \
    do {                                        \
        free(*(Add));                           \
        *(Add) = NULL;                          \
    } while (0)
# endif // INT_COMPILER_MSVC

#endif // DEBUG_MEM_ALLOCS

#endif // _GLUE_H_
